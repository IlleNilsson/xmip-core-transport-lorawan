#![forbid(unsafe_code)]

//! Streams that arrive over `LoRaWAN`, the long-range, low-power radio of
//! the meter in the basement and the sensor in the field: a device talks up
//! to any gateway that hears it, the gateways forward to one network server,
//! and the server talks down through a gateway as the device listens.
//!
//! **A node is the network server.** A Location's address is where the node
//! listens for the gateways pointed at it, over Semtech's UDP packet
//! forwarder protocol, version 2 (`datagram.rs`, `packet.rs`): a gateway
//! running Semtech's packet forwarder names the node as its server, and
//! `lorawan://0.0.0.0` listens on port 1700, where the address names none.
//! The Locations of a node at one address share its socket and each
//! device's session (`gateways.rs`, `server.rs`). A Receive Location takes
//! what one device sends up, whole; a Send Location sends a Stream down to
//! it. The origin names the gateway that heard the device last and the
//! device: `lorawan://aa555a0000000000/26011b2c?port=1&fcnt=0`.
//!
//! What is carried is the MAC frame (`frame.rs`) — message type, device
//! address, frame control and counter, port, the `FRMPayload` under the
//! application session key and the MIC under the network session key,
//! AES-128 as the specification uses it — confirmed and unconfirmed data
//! both ways, and a Stream longer than a frame in fragments on a port of
//! its own (`fragment.rs`). A device's session is activated by
//! personalization: its address is a setting and its keys the secret its
//! Location names. Joining over the air is not built.
//!
//! **A confirmed frame up is answered in the device's first receive
//! window**, a second after it ended on its gateway's clock, before the
//! receive cycle has ended, since the window does not wait for it:
//! acceptance is at-most-once here (`AT_MOST_ONCE_UP`). **A Send Location
//! sends at once**, on the frequency and at the data rate it says, where a
//! Class C device listens; a confirmed one waits for the device's
//! acknowledgement in its next frame up.
//!
//! The far end is a device behind a gateway (`device.rs`), the gateway a
//! packet forwarder of this crate's own (`forwarder.rs`), which needs no
//! radio: the loopback stands both ends on this machine, over UDP.
//!
//! **Built with its `declaration` feature alone** the crate is `declaration`.
//! It is the same wherever it is built. The wait a Location takes unless it
//! says, `DEFAULT_TIMEOUT`, and the port an address that names none listens
//! on, `PORT`, are declared there with it.

#[cfg(feature = "default")]
pub mod aes;
#[cfg(feature = "default")]
mod configured;
#[cfg(feature = "default")]
pub mod datagram;
#[cfg(feature = "default")]
pub mod deadline;
#[cfg(feature = "declaration")]
pub mod declaration;
#[cfg(feature = "default")]
pub mod device;
#[cfg(feature = "default")]
pub mod forwarder;
#[cfg(feature = "default")]
pub mod fragment;
#[cfg(feature = "default")]
pub mod frame;
#[cfg(feature = "default")]
pub mod gateways;
#[cfg(feature = "default")]
pub mod packet;
#[cfg(feature = "default")]
mod radio;
#[cfg(feature = "default")]
pub mod server;

#[cfg(feature = "default")]
use std::sync::{Arc, Mutex};
#[cfg(feature = "default")]
use std::time::Duration;
#[cfg(feature = "default")]
use xcore::lock::Locked;

#[cfg(feature = "default")]
use deadline::Deadline;
#[cfg(feature = "default")]
use declaration::{DEFAULT_DATA_RATE, DEFAULT_FREQUENCY, DEFAULT_TIMEOUT};
#[cfg(feature = "default")]
pub use device::{BehindGateway, Device, EndDevice};
#[cfg(feature = "default")]
pub use forwarder::Forwarder;
#[cfg(feature = "default")]
pub use frame::{Frame, Keys, MType};
#[cfg(feature = "default")]
pub use gateways::Gateways;
#[cfg(feature = "default")]
pub use radio::Radio;
#[cfg(feature = "default")]
pub use server::NetworkServer;
#[cfg(feature = "default")]
use transport::error::{Result, TransportError, protocol_error};
#[cfg(feature = "default")]
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
#[cfg(feature = "default")]
use transport::{Acknowledgement, ArrivalIdentity, Arrived, Configured, Directions};
#[cfg(feature = "default")]
use transport::{Secured, Transport, secured};

/// Why a frame up cannot be acknowledged after the receive cycle.
#[cfg(feature = "default")]
pub const AT_MOST_ONCE_UP: &str = "a confirmed LoRaWAN frame up is answered in the device's \
                                   first receive window, a second after it, which does not wait \
                                   for the receive cycle to end";

/// How long after its frame up ends a device opens its first receive
/// window, in microseconds on its gateway's clock: `RECEIVE_DELAY1`, one
/// second, in the `LoRaWAN` Regional Parameters.
#[cfg(feature = "default")]
const RECEIVE_DELAY1: u32 = 1_000_000;

/// The power a downlink is sent at, in dBm: within what EU868 permits on
/// every one of its channels.
#[cfg(feature = "default")]
const POWER: i64 = 14;

/// The device a loopback is the network server of.
#[cfg(feature = "default")]
const LOOPBACK_DEVICE: u32 = 0x2601_1b2c;

/// The session keys of a loopback's device.
#[cfg(feature = "default")]
const LOOPBACK_KEYS: Keys = Keys {
    nwk_s_key: [0x2b; 16],
    app_s_key: [0x7e; 16],
};

/// The gateway a loopback's far end is behind: the identifier Semtech's
/// packet forwarder ships with, `AA555A0000000000`.
#[cfg(feature = "default")]
const LOOPBACK_GATEWAY: datagram::Eui = [0xaa, 0x55, 0x5a, 0, 0, 0, 0, 0];

/// The network server's side of one device, behind the gateways pointed at
/// one address of the node.
#[cfg(feature = "default")]
#[derive(Clone)]
pub struct LorawanTransport {
    gateways: Arc<Gateways>,
    session: Arc<Mutex<NetworkServer>>,
    dev_addr: u32,
    /// The session keys it was built with, as `Keys::to_hex` writes them,
    /// where its Location names no secret: a loopback's.
    kept: String,
    secured: Option<Secured>,
    confirmed: bool,
    /// Where a downlink is sent: in hertz, and at which data rate.
    frequency: u32,
    data_rate: String,
    timeout: Duration,
    /// What its waits are counted on: its node's Clock, the operating
    /// system's until it is handed one (`Configured::timed_by`).
    clock: Arc<dyn xcore::Clock>,
}

#[cfg(feature = "default")]
impl LorawanTransport {
    /// The network server's side of `dev_addr`, behind the gateways pointed
    /// at `address`, a host and port — `declaration::PORT` where it names
    /// none — sending unconfirmed. Nothing is bound until it is listened on
    /// or sent from.
    #[must_use]
    pub fn listening_at(address: &str, dev_addr: u32) -> Self {
        let bind = net::authority::with_default_port(address, declaration::PORT);
        Self {
            gateways: Arc::new(Gateways::new(&bind)),
            session: Arc::new(Mutex::new(NetworkServer::new(dev_addr))),
            dev_addr,
            kept: String::new(),
            secured: None,
            confirmed: false,
            frequency: u32::try_from(DEFAULT_FREQUENCY).unwrap_or(u32::MAX),
            data_rate: DEFAULT_DATA_RATE.to_string(),
            timeout: DEFAULT_TIMEOUT,
            clock: Arc::new(xcore::SystemClock),
        }
    }

    /// With the session keys `keys`, where its Location names no secret.
    #[must_use]
    pub fn keyed(mut self, keys: Keys) -> Self {
        self.kept = keys.to_hex();
        self
    }

    /// Send confirmed: every Stream down waits for the device's ACK up.
    #[must_use]
    pub const fn confirmed(mut self) -> Self {
        self.confirmed = true;
        self
    }

    /// The session keys, read now from the secret its Location names, or
    /// those it was built with.
    fn keys(&self) -> Result<Keys> {
        let held = secured::presented(self.secured.as_ref(), &self.kept, "lorawan")?;
        Keys::from_hex(&held)
    }

    /// `lorawan://<gateway>/<device address>?port=<port>&fcnt=<counter>`,
    /// the gateway the one that heard the device last.
    fn origin(&self, port: u8, fcnt: u32) -> String {
        let gateway = self
            .gateways
            .heard_by(self.dev_addr)
            .map_or_else(|| "unheard".to_string(), |eui| datagram::shown(&eui));
        format!(
            "lorawan://{gateway}/{:08x}?port={port}&fcnt={fcnt}",
            self.dev_addr
        )
    }

    /// One uplink taken into the device's session, a confirmed one answered
    /// in its first receive window through the gateway that heard it:
    /// whether it acknowledged the last confirmed frame down.
    fn took(&self, uplink: &gateways::Uplink, keys: &Keys, until: &Deadline) -> Result<bool> {
        let Some(heard) = self.session.locked().uplink(&uplink.rxpk.data, keys)? else {
            return Ok(false);
        };
        if let Some(answer) = heard.answer {
            let txpk = packet::Txpk::answering(&uplink.rxpk, RECEIVE_DELAY1, POWER, answer);
            self.gateways.transmit(Some(uplink.gateway), &txpk, until)?;
        }
        Ok(heard.ack)
    }

    /// The next Stream the device sent up, whole, or `None` where none was
    /// whole within the timeout. Acceptance is at-most-once
    /// ([`AT_MOST_ONCE_UP`]).
    ///
    /// # Errors
    /// Where the gateways' socket could not be read, the session's keys
    /// not, or a frame of the session's is refused: a counter that did not
    /// advance, a port this crate does not carry. A frame that does not open
    /// under its keys is not the session's, and is read past.
    pub fn receive_one(&self) -> Result<Option<Arrived>> {
        let until = Deadline::after(&self.clock, self.timeout);
        let mut keys = None;
        loop {
            if let Some(whole) = self.session.locked().take() {
                let origin = self.origin(whole.port, whole.fcnt);
                let acknowledgement = Acknowledgement::at_most_once(AT_MOST_ONCE_UP);
                return Ok(Some(Arrived::whole(origin, whole.bytes, acknowledgement)));
            }
            let Some(uplink) = self.gateways.uplink(self.dev_addr, &until)? else {
                return Ok(None);
            };
            if keys.is_none() {
                keys = Some(self.keys()?);
            }
            if let Some(keys) = &keys {
                self.took(&uplink, keys, &until)?;
            }
        }
    }

    /// `bytes` sent down to the device, in one frame or in fragments, each
    /// at once through the gateway that heard it last; confirmed, its last
    /// frame confirmed and the device's acknowledgement waited for.
    ///
    /// # Errors
    /// Where the session's keys could not be read, no gateway took a frame,
    /// or a confirmed Stream went unacknowledged.
    pub fn send_stream(&self, bytes: &[u8]) -> Result<()> {
        let keys = self.keys()?;
        if self.confirmed {
            // Its acknowledgement may come up the moment the last frame is
            // down, before this thread looks for it.
            self.gateways.expecting(self.dev_addr);
        }
        let until = Deadline::after(&self.clock, self.timeout);
        let payloads = fragment::payloads(bytes);
        let last = payloads.len() - 1;
        let freq = f64::from(self.frequency) / 1_000_000.0;
        for (index, (port, payload)) in payloads.into_iter().enumerate() {
            let mtype = if self.confirmed && index == last {
                MType::ConfirmedDown
            } else {
                MType::UnconfirmedDown
            };
            let sealed = self
                .session
                .locked()
                .downlink(mtype, port, &payload, &keys)?;
            let txpk = packet::Txpk::now(freq, &self.data_rate, POWER, sealed);
            let gateway = self.gateways.heard_by(self.dev_addr);
            self.gateways.transmit(gateway, &txpk, &until)?;
        }
        if self.confirmed {
            return self.acknowledged(&keys, &until);
        }
        Ok(())
    }

    /// The device's acknowledgement, in a frame up before `until`; what any
    /// frame up carries meanwhile kept for a receive.
    fn acknowledged(&self, keys: &Keys, until: &Deadline) -> Result<()> {
        while let Some(uplink) = self.gateways.uplink(self.dev_addr, until)? {
            if self.took(&uplink, keys, until)? {
                return Ok(());
            }
        }
        Err(TransportError::retryable(format!(
            "device {:08x} did not acknowledge the Stream in time",
            self.dev_addr
        )))
    }
}

#[cfg(feature = "default")]
impl Transport for LorawanTransport {
    fn name(&self) -> &'static str {
        "lorawan"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn arrivals(&self) -> transport::Arrivals {
        transport::Arrivals::Ordered("one device's frames, in the order of its frame counter")
    }

    fn waiting(&self) -> transport::Waiting {
        transport::Waiting::Waits("a read of the gateways' socket waits for an uplink")
    }

    /// A timeout with nothing whole is not an error: an empty vector.
    /// Acceptance is at-most-once ([`AT_MOST_ONCE_UP`]).
    fn receive_up_to(&self, _most: usize) -> Result<Vec<Arrived>> {
        Ok(self.receive_one()?.into_iter().collect())
    }

    fn sending(&self) -> transport::Sending {
        transport::Sending::Gathered("a Stream is sealed into frames, each one downlink")
    }

    /// The target is the device the Location names, through its gateway.
    fn send_from(&self, _target: &str, outgoing: transport::Outgoing<'_>) -> Result<()> {
        let bytes: &[u8] = &outgoing.gather()?;
        self.send_stream(bytes)
    }
}

#[cfg(feature = "default")]
impl LorawanTransport {
    /// Both ends on this machine: the network server on an ephemeral port
    /// of loopback with a device's session and its keys, and the loopback
    /// timeout on every wait.
    #[must_use]
    pub fn loopback() -> Self {
        Self::listening_at("127.0.0.1:0", LOOPBACK_DEVICE)
            .keyed(LOOPBACK_KEYS)
            .timing_out_after(LOOPBACK_TIMEOUT)
    }
}

#[cfg(feature = "default")]
impl Loopback for LorawanTransport {
    fn arrival_identity(&self) -> ArrivalIdentity {
        ArrivalIdentity::Unnamed(
            "a frame names its device by its address alone, which its MIC under the session \
             key vouches for",
        )
    }

    /// The device, behind a gateway pointed at this transport's socket,
    /// which it binds.
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        self.gateways.expecting(self.dev_addr);
        let address = self
            .gateways
            .listening()?
            .ok_or_else(|| protocol_error("the gateways' socket is bound nowhere"))?
            .to_string();
        let gateway = Forwarder::pointed_at(&address, LOOPBACK_GATEWAY, self.timeout)?;
        let device = Arc::new(Device::new(self.dev_addr, self.keys()?));
        let device = EndDevice::new(Arc::new(gateway), device).waiting(self.timeout);
        Ok(Box::new(BehindGateway::new(address, device)))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        self.send(address, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use datagram::Datagram;
    use std::net::UdpSocket;
    use transport::payload::edge_payloads;

    /// The shapes a protocol breaks on, as the System Tests list them.
    fn payloads() -> Vec<(&'static str, Vec<u8>)> {
        let mut payloads = edge_payloads();
        payloads.extend([(
            "sixty-four kibibytes plus one",
            (0..65_537u32)
                .map(|n| u8::try_from(n * 31 % 256).unwrap_or(0))
                .collect(),
        )]);
        payloads
    }

    /// A device behind a gateway pointed at `node`, which listens.
    fn behind(node: &LorawanTransport) -> EndDevice {
        node.gateways.expecting(node.dev_addr);
        let address = node
            .gateways
            .listening()
            .expect("bound")
            .expect("an address");
        let gateway =
            Forwarder::pointed_at(address, LOOPBACK_GATEWAY, LOOPBACK_TIMEOUT).expect("a gateway");
        let device = Arc::new(Device::new(node.dev_addr, LOOPBACK_KEYS));
        EndDevice::new(Arc::new(gateway), device).waiting(LOOPBACK_TIMEOUT)
    }

    #[test]
    fn a_loopback_round_carries_a_stream_down_to_a_device_behind_a_gateway() {
        let loopback = LorawanTransport::loopback();
        let arrived = loopback.round(b"21.5 C").expect("round");
        assert_eq!(arrived.bytes, b"21.5 C");
        assert!(
            arrived.origin_uri.starts_with("lorawan://127.0.0.1:"),
            "{}",
            arrived.origin_uri
        );
        assert!(
            arrived.origin_uri.ends_with("/26011b2c?port=1&fcnt=0"),
            "{}",
            arrived.origin_uri
        );
        let long = vec![7; 1000];
        let arrived = loopback.round(&long).expect("fragments");
        assert_eq!(arrived.bytes, long);
        assert!(
            arrived.origin_uri.contains("?port=2&"),
            "{}",
            arrived.origin_uri
        );
        assert!(loopback.ceiling().is_none());
        assert!(loopback.refuses(b"anything").is_none());
        assert_eq!(loopback.name(), "lorawan");
        assert!(loopback.directions().receives() && loopback.directions().sends());
        assert!(loopback.claims().is_none());
    }

    #[test]
    fn the_loopback_returns_the_edges_whole() {
        let loopback = LorawanTransport::loopback();
        for (name, bytes) in payloads() {
            let arrived = loopback
                .round(&bytes)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(arrived.bytes, bytes, "{name}");
        }
    }

    #[test]
    fn a_device_sends_streams_up_and_each_confirmed_frame_is_answered_in_its_window() {
        let node = LorawanTransport::loopback();
        let device = behind(&node).confirmed();
        let long = vec![9u8; 500];
        std::thread::scope(|scope| {
            let sending = scope.spawn(|| {
                device.send_stream(b"21.5 C")?;
                device.send_stream(&long)
            });
            let first = node.receive_one().expect("first").expect("a Stream");
            assert_eq!(
                first.origin_uri,
                "lorawan://aa555a0000000000/26011b2c?port=1&fcnt=0"
            );
            assert!(!first.defers(), "an uplink is at-most-once");
            assert_eq!(first.taken().expect("taken").bytes, b"21.5 C");
            let second = node.receive_one().expect("second").expect("a Stream");
            assert!(
                second.origin_uri.ends_with("?port=2&fcnt=3"),
                "{}",
                second.origin_uri
            );
            assert_eq!(second.taken().expect("taken").bytes, long);
            sending
                .join()
                .expect("the device's thread")
                .expect("every confirmed frame acknowledged");
        });
        let quiet = node.timing_out_after(Duration::from_millis(20));
        assert!(quiet.receive().expect("quiet").is_empty(), "nothing more");
    }

    #[test]
    fn a_confirmed_stream_down_waits_for_the_device_to_acknowledge_it() {
        let node = LorawanTransport::loopback().confirmed();
        let device = behind(&node);
        std::thread::scope(|scope| {
            let answering = scope.spawn(|| {
                let arrived = device.receive_one()?.expect("a Stream");
                assert!(arrived.defers(), "a confirmed Stream waits for its verdict");
                let taken = arrived.taken()?;
                device.send_stream(b"done")?;
                Ok::<_, TransportError>(taken.bytes)
            });
            node.send_stream(b"set 20").expect("acknowledged");
            assert_eq!(
                answering.join().expect("the device").expect("taken"),
                b"set 20"
            );
        });
        let kept = node
            .receive_one()
            .expect("kept")
            .expect("the device's frame");
        assert_eq!(kept.taken().expect("taken").bytes, b"done");
    }

    #[test]
    fn a_receive_and_a_send_of_one_device_share_the_socket_each_told_what_the_other_read() {
        let sharing: Arc<dyn transport::Sharing> = Arc::new(transport::Shared::default());
        let receiving = LorawanTransport::loopback().shared_by(&sharing);
        let sending = LorawanTransport::loopback().shared_by(&sharing);
        receiving.listening().expect("bound");
        let device = behind(&receiving);
        std::thread::scope(|scope| {
            let received = scope.spawn(|| receiving.receive_one());
            let answering = scope.spawn(|| {
                let down = device.receive_one()?.expect("a Stream down").taken()?;
                device.send_stream(b"up")?;
                Ok::<_, TransportError>(down.bytes)
            });
            // Whichever Location reads the socket, the other is woken by
            // the PULL_DATA and the TX_ACK it reads.
            sending
                .send_stream(b"down")
                .expect("sent through the shared socket");
            assert_eq!(
                answering.join().expect("the device").expect("took"),
                b"down"
            );
            let up = received.join().expect("the receive").expect("read");
            assert_eq!(
                up.expect("a Stream up").taken().expect("taken").bytes,
                b"up"
            );
        });
    }

    #[test]
    fn a_gateway_that_refuses_a_downlink_is_named_and_none_asking_is_said() {
        let quiet = LorawanTransport::loopback().timing_out_after(Duration::from_millis(50));
        let unheard = quiet.send_stream(b"x").expect_err("no gateway");
        assert!(
            unheard.retryable && unheard.message.contains("keepalive"),
            "{unheard}"
        );

        let node = LorawanTransport::loopback();
        let address = node
            .gateways
            .listening()
            .expect("bound")
            .expect("an address");
        let gateway = UdpSocket::bind("127.0.0.1:0").expect("a gateway's socket");
        let pull = Datagram::PullData {
            token: 1,
            gateway: LOOPBACK_GATEWAY,
        };
        gateway.send_to(&pull.encode(), address).expect("pulled");
        std::thread::scope(|scope| {
            let refusing = scope.spawn(|| {
                let until = Deadline::after(&node.clock, LOOPBACK_TIMEOUT);
                while let Some((bytes, peer)) = datagram::received(&gateway, &until)? {
                    if let Datagram::PullResp { token, json } = Datagram::decode(&bytes)? {
                        let late = Datagram::TxAck {
                            token,
                            gateway: LOOPBACK_GATEWAY,
                            json: br#"{"txpk_ack":{"error":"TOO_LATE"}}"#.to_vec(),
                        };
                        datagram::sent(&gateway, &late, peer)?;
                        return packet::Txpk::read(&json);
                    }
                }
                Err(protocol_error("no PULL_RESP"))
            });
            let refused = node.send_stream(b"x").expect_err("too late");
            assert!(
                refused.retryable && refused.message.contains("TOO_LATE"),
                "{refused}"
            );
            assert!(refused.message.contains("aa555a0000000000"), "{refused}");
            let txpk = refusing.join().expect("the gateway").expect("a txpk");
            assert!(txpk.imme && txpk.ipol);
            assert_eq!(
                (txpk.freq, txpk.datr.as_str()),
                (869.525, Some("SF12BW125"))
            );
            let frame = Frame::open(&txpk.data, &LOOPBACK_KEYS, 0).expect("the device's");
            assert_eq!(
                (frame.mtype, frame.port, frame.payload),
                (MType::UnconfirmedDown, 1, b"x".to_vec())
            );
        });
    }
}
