//! What the packet forwarder protocol's JSON carries (`datagram.rs`): an
//! [`Rxpk`], one packet a gateway heard, which `PUSH_DATA` carries in its
//! `rxpk` array; a [`Txpk`], one packet a gateway is to send, which
//! `PULL_RESP` carries; and the `txpk_ack` a gateway answers with in
//! `TX_ACK`. The fields are `PROTOCOL.TXT`'s, sections 4 and 6, read and
//! written with `serde_json`, the PHY payload in base 64 by the estate's
//! one codec. A field this crate does not read — a `PUSH_DATA`'s `stat`, a
//! packet's `time` — is left as it came.

use serde_json::{Map, Value, json};
use transport::error::{Result, protocol_error};

/// A packet's CRC checked and found good (`stat`).
const CRC_GOOD: i64 = 1;

/// One packet a gateway heard.
#[derive(Clone, Debug, PartialEq)]
pub struct Rxpk {
    /// The concentrator's clock as the packet ended, in microseconds: what
    /// an answer in the device's receive window is timed from.
    pub tmst: u32,
    /// The frequency it was heard on, in MHz.
    pub freq: f64,
    /// Its modulation: `LORA` or `FSK`.
    pub modu: String,
    /// Its data rate: `SF7BW125` for `LoRa`, bits a second for FSK.
    pub datr: Value,
    /// Its coding rate, `LoRa`'s alone: `4/5`.
    pub codr: Option<String>,
    /// Whether its CRC was good: 1, bad -1, none 0.
    pub stat: i64,
    /// The PHY payload: a frame as the air carried it.
    pub data: Vec<u8>,
}

impl Rxpk {
    /// A `LoRa` packet heard on `freq` at `rate`, its CRC good, ending at
    /// `tmst`: what a gateway forwards of a device's frame.
    #[must_use]
    pub fn lora(tmst: u32, freq: f64, rate: &str, data: &[u8]) -> Self {
        Self {
            tmst,
            freq,
            modu: "LORA".to_string(),
            datr: Value::from(rate),
            codr: Some("4/5".to_string()),
            stat: CRC_GOOD,
            data: data.to_vec(),
        }
    }

    /// Whether its CRC was checked and good: the packets a network server
    /// takes, as Semtech's packet forwarder forwards by default
    /// (`forward_crc_valid`).
    #[must_use]
    pub const fn whole(&self) -> bool {
        self.stat == CRC_GOOD
    }

    fn read(value: &Value) -> Result<Self> {
        let number = |name: &str| value.get(name).and_then(Value::as_f64);
        let wanting = |name: &str| protocol_error(format!("an rxpk without its \"{name}\""));
        Ok(Self {
            tmst: value
                .get("tmst")
                .and_then(Value::as_u64)
                .and_then(|tmst| u32::try_from(tmst).ok())
                .ok_or_else(|| wanting("tmst"))?,
            freq: number("freq").ok_or_else(|| wanting("freq"))?,
            modu: text(value, "modu").ok_or_else(|| wanting("modu"))?,
            datr: value.get("datr").cloned().ok_or_else(|| wanting("datr"))?,
            codr: text(value, "codr"),
            stat: value
                .get("stat")
                .and_then(Value::as_i64)
                .ok_or_else(|| wanting("stat"))?,
            data: payload(value)?,
        })
    }

    fn written(&self) -> Value {
        let mut packet = json!({
            "tmst": self.tmst,
            "chan": 0,
            "rfch": 0,
            "freq": self.freq,
            "stat": self.stat,
            "modu": self.modu,
            "datr": self.datr,
            "rssi": -35,
            "lsnr": 5.0,
            "size": self.data.len(),
            "data": codec::base64::encode(&self.data),
        });
        if let (Some(codr), Some(object)) = (&self.codr, packet.as_object_mut()) {
            object.insert("codr".to_string(), Value::from(codr.as_str()));
        }
        packet
    }
}

/// The packets a `PUSH_DATA`'s JSON carries in `rxpk`: none where it carries
/// only the gateway's `stat`.
///
/// # Errors
/// JSON that is not an object, or a packet without what this crate reads.
pub fn heard(json: &[u8]) -> Result<Vec<Rxpk>> {
    let root = object(json, "PUSH_DATA")?;
    root.get("rxpk").and_then(Value::as_array).map_or_else(
        || Ok(Vec::new()),
        |packets| packets.iter().map(Rxpk::read).collect(),
    )
}

/// The JSON of a `PUSH_DATA` carrying `packets`.
#[must_use]
pub fn pushed(packets: &[Rxpk]) -> Vec<u8> {
    let packets: Vec<Value> = packets.iter().map(Rxpk::written).collect();
    json!({ "rxpk": packets }).to_string().into_bytes()
}

/// One packet a gateway is to send.
#[derive(Clone, Debug, PartialEq)]
pub struct Txpk {
    /// Sent at once, where it is not timed by `tmst`.
    pub imme: bool,
    /// When to send it, on the concentrator's clock, in microseconds.
    pub tmst: Option<u32>,
    /// The frequency to send it on, in MHz.
    pub freq: f64,
    /// The power to send it at, in dBm.
    pub powe: i64,
    pub modu: String,
    pub datr: Value,
    pub codr: Option<String>,
    /// `LoRa`'s polarity inverted, as a device listens for a downlink.
    pub ipol: bool,
    /// The PHY payload: a frame as the air is to carry it.
    pub data: Vec<u8>,
}

impl Txpk {
    /// `data` sent `delay` microseconds after `heard` ended, on its
    /// frequency, data rate and coding rate, polarity inverted: an answer in
    /// the device's first receive window, which EU868 opens on the channel
    /// and data rate the device sent on (`RX1DROffset` 0).
    #[must_use]
    pub fn answering(heard: &Rxpk, delay: u32, powe: i64, data: Vec<u8>) -> Self {
        Self {
            imme: false,
            tmst: Some(heard.tmst.wrapping_add(delay)),
            freq: heard.freq,
            powe,
            modu: heard.modu.clone(),
            datr: heard.datr.clone(),
            codr: heard.codr.clone(),
            ipol: true,
            data,
        }
    }

    /// `data` sent at once on `freq` at the `LoRa` data rate `rate`, polarity
    /// inverted: a downlink to a device listening there.
    #[must_use]
    pub fn now(freq: f64, rate: &str, powe: i64, data: Vec<u8>) -> Self {
        Self {
            imme: true,
            tmst: None,
            freq,
            powe,
            modu: "LORA".to_string(),
            datr: Value::from(rate),
            codr: Some("4/5".to_string()),
            ipol: true,
            data,
        }
    }

    /// The JSON of a `PULL_RESP` carrying it.
    #[must_use]
    pub fn written(&self) -> Vec<u8> {
        let mut packet = Map::new();
        packet.insert("imme".into(), Value::from(self.imme));
        if let Some(tmst) = self.tmst {
            packet.insert("tmst".into(), Value::from(tmst));
        }
        packet.insert("freq".into(), Value::from(self.freq));
        packet.insert("rfch".into(), Value::from(0));
        packet.insert("powe".into(), Value::from(self.powe));
        packet.insert("modu".into(), Value::from(self.modu.as_str()));
        packet.insert("datr".into(), self.datr.clone());
        if let Some(codr) = &self.codr {
            packet.insert("codr".into(), Value::from(codr.as_str()));
        }
        packet.insert("ipol".into(), Value::from(self.ipol));
        packet.insert("size".into(), Value::from(self.data.len()));
        packet.insert(
            "data".into(),
            Value::from(codec::base64::encode(&self.data)),
        );
        json!({ "txpk": packet }).to_string().into_bytes()
    }

    /// The packet a `PULL_RESP`'s JSON carries.
    ///
    /// # Errors
    /// JSON without a `txpk`, or one without what this crate reads.
    pub fn read(json: &[u8]) -> Result<Self> {
        let root = object(json, "PULL_RESP")?;
        let packet = root
            .get("txpk")
            .ok_or_else(|| protocol_error("a PULL_RESP without its txpk"))?;
        let wanting = |name: &str| protocol_error(format!("a txpk without its \"{name}\""));
        Ok(Self {
            imme: packet.get("imme").and_then(Value::as_bool).unwrap_or(false),
            tmst: packet
                .get("tmst")
                .and_then(Value::as_u64)
                .and_then(|tmst| u32::try_from(tmst).ok()),
            freq: packet
                .get("freq")
                .and_then(Value::as_f64)
                .ok_or_else(|| wanting("freq"))?,
            powe: packet.get("powe").and_then(Value::as_i64).unwrap_or(0),
            modu: text(packet, "modu").ok_or_else(|| wanting("modu"))?,
            datr: packet.get("datr").cloned().ok_or_else(|| wanting("datr"))?,
            codr: text(packet, "codr"),
            ipol: packet.get("ipol").and_then(Value::as_bool).unwrap_or(false),
            data: payload(packet)?,
        })
    }
}

/// What a `TX_ACK`'s JSON says of the `PULL_RESP` it answers: `None` where
/// the gateway took it — no JSON, or `"error":"NONE"` — and the error it
/// names where it did not, `TOO_LATE`, `COLLISION_PACKET` and the rest. A
/// warning, which revision 1.5 of `PROTOCOL.md` moved `TX_POWER` to, is no
/// refusal.
///
/// # Errors
/// JSON that is there and is not an object.
pub fn refusal(json: &[u8]) -> Result<Option<String>> {
    if json
        .iter()
        .all(|byte| byte.is_ascii_whitespace() || *byte == 0)
    {
        return Ok(None);
    }
    let root = object(json, "TX_ACK")?;
    Ok(root
        .get("txpk_ack")
        .and_then(|ack| text(ack, "error"))
        .filter(|error| error != "NONE"))
}

/// The JSON of a `TX_ACK` saying the gateway took what it was sent.
#[must_use]
pub fn taken() -> Vec<u8> {
    json!({ "txpk_ack": { "error": "NONE" } })
        .to_string()
        .into_bytes()
}

/// The root object `json` is, which `datagram` carries.
fn object(json: &[u8], datagram: &str) -> Result<Map<String, Value>> {
    match serde_json::from_slice(json) {
        Ok(Value::Object(root)) => Ok(root),
        _ => Err(protocol_error(format!(
            "a {datagram} whose JSON is not an object"
        ))),
    }
}

/// The text field `name` of `value`.
fn text(value: &Value, name: &str) -> Option<String> {
    value.get(name).and_then(Value::as_str).map(str::to_string)
}

/// The PHY payload a packet carries in `data`, base 64 padded or not.
fn payload(value: &Value) -> Result<Vec<u8>> {
    let data = value
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| protocol_error("a packet without its \"data\""))?;
    codec::base64::decode(data).map_err(|e| protocol_error(e.message))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first packet of `PROTOCOL.TXT`'s example in section 4, but its
    /// `data`: the example's holds a `-`, which base 64 has not, so it is
    /// 32 bytes that are, as the example's `size` says.
    const EXAMPLE: &str = r#"{"rxpk":[{"time":"2013-03-31T16:21:17.528002Z","tmst":3512348611,
        "chan":2,"rfch":0,"freq":866.349812,"stat":1,"modu":"LORA","datr":"SF7BW125",
        "codr":"4/6","rssi":-35,"lsnr":5.1,"size":32,
        "data":"QDDaAAGAAQABlAyYcg8kdnRE/ArVa3zW1Ag4htD2Ac8="}]}"#;

    #[test]
    fn the_protocols_own_example_is_read() {
        let packets = heard(EXAMPLE.as_bytes()).expect("read");
        assert_eq!(packets.len(), 1);
        let packet = &packets[0];
        assert_eq!((packet.tmst, packet.freq), (3_512_348_611, 866.349_812));
        assert_eq!(
            (packet.modu.as_str(), packet.datr.as_str()),
            ("LORA", Some("SF7BW125"))
        );
        assert_eq!(packet.codr.as_deref(), Some("4/6"));
        assert!(packet.whole());
        assert_eq!(packet.data.len(), 32);
        let stat = heard(br#"{"stat":{"rxnb":2}}"#).expect("stat alone");
        assert!(stat.is_empty(), "{stat:?}");
        assert!(heard(b"[]").is_err(), "not an object");
        assert!(heard(br#"{"rxpk":[{"tmst":1}]}"#).is_err(), "no freq");
    }

    #[test]
    fn what_a_gateway_pushes_is_read_back_and_an_answer_is_timed_from_it() {
        let packet = Rxpk::lora(4_294_000_000, 868.1, "SF9BW125", b"frame");
        let back = heard(&pushed(std::slice::from_ref(&packet))).expect("read");
        assert_eq!(back, std::slice::from_ref(&packet));
        let answer = Txpk::answering(&packet, 1_000_000, 14, b"ack".to_vec());
        assert_eq!(
            answer.tmst,
            Some(4_294_000_000_u32.wrapping_add(1_000_000)),
            "wraps"
        );
        assert!(!answer.imme && answer.ipol);
        assert_eq!(
            (answer.freq, answer.datr.as_str()),
            (868.1, Some("SF9BW125"))
        );
        let read = Txpk::read(&answer.written()).expect("read");
        assert_eq!(read, answer);
        let now = Txpk::now(869.525, "SF12BW125", 14, Vec::new());
        let written = String::from_utf8(now.written()).expect("text");
        assert!(
            written.contains(r#""imme":true"#) && !written.contains("tmst"),
            "{written}"
        );
        assert_eq!(Txpk::read(&now.written()).expect("read"), now);
        assert!(Txpk::read(br#"{"txpk":{"freq":1}}"#).is_err(), "no modu");
    }

    #[test]
    fn a_tx_ack_says_none_taken_and_names_its_error() {
        assert_eq!(refusal(b"").expect("empty"), None);
        assert_eq!(refusal(&taken()).expect("NONE"), None);
        let late = br#"{"txpk_ack":{"error":"TOO_LATE"}}"#;
        assert_eq!(refusal(late).expect("late").as_deref(), Some("TOO_LATE"));
        let warned = br#"{"txpk_ack":{"warn":"TX_POWER","value":14}}"#;
        assert_eq!(refusal(warned).expect("a warning"), None);
        assert!(refusal(b"no").is_err());
    }
}
