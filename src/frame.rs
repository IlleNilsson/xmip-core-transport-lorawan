//! The `LoRaWAN` MAC frame as the air carries it: a MAC header naming the
//! message type, the frame header — device address, frame control, frame
//! counter, frame options — a port, the `FRMPayload` under a session key,
//! and the four-byte MIC under the network session key.
//!
//! What a real device sends is opened whole: a frame with no `FRMPayload`
//! carries no port, its options — MAC commands, which this crate answers
//! none of — are skipped under the MIC that covers them, and a payload on
//! port 0, MAC commands too, is under the network session key, as the
//! specification has it (`LoRaWAN` L2 1.0.4, section 4.3).

use transport::error::{Result, TransportError, protocol_error};

use crate::aes::{self, BLOCK};

/// The most `FRMPayload` one frame carries: N for the fastest EU868 data rate
/// (DR5, 230 bytes of `MACPayload` less the frame header and port). A slower
/// data rate carries less; the specification's tables say how much.
pub const MAX_FRM_PAYLOAD: usize = 222;

/// The ACK bit in frame control.
const ACK: u8 = 0x20;
/// The frame-options length is the low four bits of frame control.
const FOPTS_LEN: u8 = 0x0f;
/// The MAC header and the frame header without its options: what every
/// data frame opens with.
const HEAD: usize = 8;
/// The MIC every frame ends with.
const MIC: usize = 4;

/// The session keys a device and its network share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Keys {
    pub nwk_s_key: [u8; BLOCK],
    pub app_s_key: [u8; BLOCK],
}

impl Keys {
    /// The keys `text` holds: 64 hexadecimal digits, the network session
    /// key's 32 and then the application session key's, each most
    /// significant byte first, as a network server shows them — what the
    /// secret a Location names holds (ADR-0051, amendment 2026-11-27).
    ///
    /// # Errors
    /// Permanent where `text` is not 64 hexadecimal digits, saying what
    /// it is to hold.
    pub fn from_hex(text: &str) -> Result<Self> {
        let refused = || {
            TransportError::permanent(
                "a LoRaWAN session's keys are 64 hexadecimal digits, the network session key's \
                 32 and then the application session key's, in the secret its Location names",
            )
        };
        let bytes = codec::hex::decode(text.trim()).map_err(|_| refused())?;
        let (nwk, app) = bytes.split_at_checked(BLOCK).ok_or_else(refused)?;
        Ok(Self {
            nwk_s_key: nwk.try_into().map_err(|_| refused())?,
            app_s_key: app.try_into().map_err(|_| refused())?,
        })
    }

    /// The keys as [`Keys::from_hex`] reads them.
    #[must_use]
    pub fn to_hex(&self) -> String {
        codec::hex::encode(&[self.nwk_s_key, self.app_s_key].concat())
    }
}

/// The message type in the MAC header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MType {
    UnconfirmedUp,
    UnconfirmedDown,
    ConfirmedUp,
    ConfirmedDown,
}

impl MType {
    const fn bits(self) -> u8 {
        match self {
            Self::UnconfirmedUp => 2,
            Self::UnconfirmedDown => 3,
            Self::ConfirmedUp => 4,
            Self::ConfirmedDown => 5,
        }
    }

    fn from_bits(bits: u8) -> Result<Self> {
        match bits {
            2 => Ok(Self::UnconfirmedUp),
            3 => Ok(Self::UnconfirmedDown),
            4 => Ok(Self::ConfirmedUp),
            5 => Ok(Self::ConfirmedDown),
            other => Err(protocol_error(format!(
                "a message type this crate does not carry: {other}"
            ))),
        }
    }

    /// Whether the frame goes up, from the device.
    #[must_use]
    pub const fn is_uplink(self) -> bool {
        matches!(self, Self::UnconfirmedUp | Self::ConfirmedUp)
    }

    /// Whether the frame asks to be acknowledged.
    #[must_use]
    pub const fn is_confirmed(self) -> bool {
        matches!(self, Self::ConfirmedUp | Self::ConfirmedDown)
    }
}

/// One data frame, its `FRMPayload` in the clear.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Frame {
    pub mtype: MType,
    pub dev_addr: u32,
    pub ack: bool,
    /// The full 32-bit counter; the air carries its low sixteen bits.
    pub fcnt: u32,
    /// The port, 0 where the frame carries none.
    pub port: u8,
    pub payload: Vec<u8>,
}

impl Frame {
    /// A frame, refusing more `FRMPayload` than the data rate carries.
    ///
    /// # Errors
    /// A payload over [`MAX_FRM_PAYLOAD`].
    pub fn new(mtype: MType, dev_addr: u32, fcnt: u32, port: u8, payload: &[u8]) -> Result<Self> {
        if payload.len() > MAX_FRM_PAYLOAD {
            return Err(protocol_error("more FRMPayload than one frame carries"));
        }
        Ok(Self {
            mtype,
            dev_addr,
            ack: false,
            fcnt,
            port,
            payload: payload.to_vec(),
        })
    }

    #[must_use]
    pub const fn acknowledging(mut self) -> Self {
        self.ack = true;
        self
    }

    /// Whether the frame carries no port: nothing on port 0, which the air
    /// carries as no port and no payload — a bare acknowledgement.
    fn bare(&self) -> bool {
        self.port == 0 && self.payload.is_empty()
    }

    /// The key its `FRMPayload` is under: the network session key on port
    /// 0, MAC commands, and the application session key on every other.
    const fn payload_key(&self, keys: &Keys) -> [u8; BLOCK] {
        if self.port == 0 {
            keys.nwk_s_key
        } else {
            keys.app_s_key
        }
    }

    /// The block every MIC and key stream opens with: a leading byte, four
    /// zeros, the direction, the device address, the full counter, a zero.
    fn block(&self, leading: u8, last: u8) -> [u8; BLOCK] {
        let mut block = [0u8; BLOCK];
        block[0] = leading;
        block[5] = u8::from(!self.mtype.is_uplink());
        block[6..10].copy_from_slice(&self.dev_addr.to_le_bytes());
        block[10..14].copy_from_slice(&self.fcnt.to_le_bytes());
        block[15] = last;
        block
    }

    /// MHDR, FHDR and `FPort`: what the MIC covers before the payload.
    fn head(&self) -> Vec<u8> {
        let mut out = vec![self.mtype.bits() << 5];
        out.extend_from_slice(&self.dev_addr.to_le_bytes());
        out.push(if self.ack { ACK } else { 0 });
        out.extend_from_slice(&u16::try_from(self.fcnt & 0xffff).unwrap_or(0).to_le_bytes());
        if !self.bare() {
            out.push(self.port);
        }
        out
    }

    /// What the MIC is the CMAC of: its block, then `body`, what precedes
    /// the MIC on the air.
    fn covered(&self, body: &[u8]) -> Vec<u8> {
        let mut covered = self
            .block(0x49, u8::try_from(body.len()).unwrap_or(u8::MAX))
            .to_vec();
        covered.extend_from_slice(body);
        covered
    }

    /// The frame as the air carries it: payload encrypted, MIC appended.
    #[must_use]
    pub fn seal(&self, keys: &Keys) -> Vec<u8> {
        let mut out = self.head();
        out.extend(aes::counter(
            &self.payload_key(keys),
            &self.block(0x01, 0),
            &self.payload,
        ));
        let covered = self.covered(&out);
        out.extend_from_slice(&aes::cmac(&keys.nwk_s_key, &covered)[..MIC]);
        out
    }

    /// The frame `bytes` carry, MIC checked and payload decrypted, given the
    /// high sixteen bits of the counter the air does not carry; its options
    /// skipped.
    ///
    /// # Errors
    /// A frame cut off, a message type this crate does not carry, or a MIC
    /// that does not check — a frame under another key, or tampered with.
    pub fn open(bytes: &[u8], keys: &Keys, fcnt_high: u16) -> Result<Self> {
        if bytes.len() < HEAD + MIC {
            return Err(protocol_error("a frame cut off before its MIC"));
        }
        let (body, mic) = bytes.split_at(bytes.len() - MIC);
        let mtype = MType::from_bits(body[0] >> 5)?;
        let fctrl = body[5];
        let options = HEAD + usize::from(fctrl & FOPTS_LEN);
        if body.len() < options {
            return Err(protocol_error("a frame cut off inside its options"));
        }
        let fcnt = u32::from(fcnt_high) << 16 | u32::from(u16::from_le_bytes([body[6], body[7]]));
        let mut frame = Self {
            mtype,
            dev_addr: u32::from_le_bytes([body[1], body[2], body[3], body[4]]),
            ack: fctrl & ACK != 0,
            fcnt,
            port: body.get(options).copied().unwrap_or(0),
            payload: Vec::new(),
        };
        if !aes::verifies(&keys.nwk_s_key, &frame.covered(body), mic) {
            return Err(protocol_error("a MIC that does not check"));
        }
        if let Some(sealed) = body.get(options + 1..) {
            frame.payload = aes::counter(&frame.payload_key(keys), &frame.block(0x01, 0), sealed);
        }
        Ok(frame)
    }
}

/// The device a data frame names, read before it is opened: how a network
/// server tells whose session opens what a gateway heard. `None` for what
/// is no data frame this crate carries.
#[must_use]
pub fn dev_addr_of(bytes: &[u8]) -> Option<u32> {
    if bytes.len() < HEAD + MIC {
        return None;
    }
    MType::from_bits(bytes[0] >> 5).ok()?;
    Some(u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> Keys {
        Keys {
            nwk_s_key: [0x11; BLOCK],
            app_s_key: [0x22; BLOCK],
        }
    }

    #[test]
    fn a_sealed_frame_opens_under_the_same_keys_and_counter() {
        let frame =
            Frame::new(MType::ConfirmedUp, 0x2601_1b2c, 0x0001_0007, 1, b"21.5 C").expect("frame");
        let bytes = frame.seal(&keys());
        assert_eq!(bytes[0], 0x80, "confirmed up");
        assert_eq!(
            &bytes[1..5],
            &[0x2c, 0x1b, 0x01, 0x26],
            "DevAddr little-endian"
        );
        assert_eq!(&bytes[6..8], &[7, 0], "the low sixteen bits of the counter");
        assert_eq!(bytes.len(), 9 + 6 + 4);
        assert_ne!(&bytes[9..15], b"21.5 C", "encrypted");
        assert_eq!(Frame::open(&bytes, &keys(), 1).expect("open"), frame);
        assert_eq!(dev_addr_of(&bytes), Some(0x2601_1b2c));
        assert!(
            Frame::open(&bytes, &keys(), 0).is_err(),
            "the wrong high bits"
        );
        let other = Keys {
            nwk_s_key: [0x33; BLOCK],
            ..keys()
        };
        assert!(
            Frame::open(&bytes, &other, 1).is_err(),
            "another network's key"
        );
    }

    #[test]
    fn what_is_not_a_frame_is_refused() {
        let frame = Frame::new(MType::UnconfirmedDown, 1, 0, 1, b"").expect("frame");
        let bytes = frame.acknowledging().seal(&keys());
        assert_eq!(bytes[5], ACK);
        assert!(Frame::open(&bytes, &keys(), 0).expect("open").ack);
        assert!(Frame::open(&bytes[..11], &keys(), 0).is_err(), "cut off");
        let mut bad = bytes.clone();
        bad[bytes.len() - 1] ^= 1;
        assert!(Frame::open(&bad, &keys(), 0).is_err(), "MIC");
        let mut join = bytes;
        join[0] = 0x00;
        assert!(Frame::open(&join, &keys(), 0).is_err(), "a join request");
        assert_eq!(dev_addr_of(&join), None, "no data frame");
        assert!(Frame::new(MType::UnconfirmedUp, 1, 0, 1, &[0; 223]).is_err());
        assert!(Frame::new(MType::UnconfirmedUp, 1, 0, 1, &[0; 222]).is_ok());
    }

    #[test]
    fn a_bare_acknowledgement_carries_no_port_and_options_are_skipped() {
        let bare = Frame::new(MType::UnconfirmedUp, 9, 3, 0, b"")
            .expect("frame")
            .acknowledging();
        let bytes = bare.seal(&keys());
        assert_eq!(bytes.len(), HEAD + MIC, "no port, no payload");
        assert_eq!(Frame::open(&bytes, &keys(), 0).expect("open"), bare);

        // A device's frame with two bytes of options, a LinkCheckReq and a
        // DeviceTimeReq, and three of payload on port 5, sealed as a device
        // seals it: the options are covered by the MIC and skipped.
        let sent = Frame::new(MType::UnconfirmedUp, 9, 4, 5, b"abc").expect("frame");
        let mut body = sent.head();
        body[5] |= 2;
        let port = body.split_off(HEAD);
        body.extend([0x02, 0x0d]);
        body.extend(port);
        body.extend(aes::counter(
            &keys().app_s_key,
            &sent.block(0x01, 0),
            b"abc",
        ));
        let covered = sent.covered(&body);
        body.extend_from_slice(&aes::cmac(&keys().nwk_s_key, &covered)[..MIC]);
        let opened = Frame::open(&body, &keys(), 0).expect("options skipped");
        assert_eq!((opened.port, opened.payload.as_slice()), (5, &b"abc"[..]));
        let cut = Frame::open(&body[..HEAD + MIC], &keys(), 0).expect_err("cut");
        assert!(cut.message.contains("options"), "{cut}");
    }

    #[test]
    fn port_zero_is_under_the_network_key() {
        let commands = Frame::new(MType::UnconfirmedDown, 9, 0, 0, &[0x02]).expect("frame");
        let bytes = commands.seal(&keys());
        let under_app = aes::counter(&keys().app_s_key, &commands.block(0x01, 0), &[0x02]);
        assert_ne!(bytes[9..10], under_app[..], "not the application key");
        assert_eq!(Frame::open(&bytes, &keys(), 0).expect("open"), commands);
    }

    #[test]
    fn the_keys_read_from_and_write_to_64_hexadecimal_digits() {
        let text = format!("{}{}", "11".repeat(16), "22".repeat(16));
        let read = Keys::from_hex(&text).expect("keys");
        assert_eq!(read, keys());
        assert_eq!(read.to_hex(), text);
        assert_eq!(
            Keys::from_hex(&format!(" {text}\n")).expect("trimmed"),
            keys()
        );
        for wrong in [
            "",
            "11",
            &text[..62],
            &format!("{text}00"),
            &text.replace('1', "g"),
        ] {
            let refused = Keys::from_hex(wrong).expect_err(wrong);
            assert!(
                !refused.retryable && refused.message.contains("64"),
                "{refused}"
            );
        }
    }
}
