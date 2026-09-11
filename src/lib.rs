#![forbid(unsafe_code)]

//! Streams that arrive over `LoRaWAN`. One frame's `FRMPayload` is one Stream
//! where it fits; a longer Stream travels as flagged fragments on a port of
//! its own and arrives whole at the network server.
//!
//! `LoRaWAN` is the long-range, low-power radio of the meter in the basement
//! and the sensor in the field: a device talks up to any gateway that hears
//! it, the gateways forward to one network server, and the server talks
//! down in the device's receive windows. What is here is the MAC frame —
//! message type, device address, frame control and counter, port, the
//! `FRMPayload` under the application session key and the MIC under the
//! network session key, AES-128 as the specification uses it — confirmed
//! and unconfirmed data in both directions, and a fragmented Stream. A Send
//! Location is the device sending up; a Receive Location is the device
//! taking what comes down.
//!
//! The radio is a trait: [`LoopbackRadio`] is a gateway and network server
//! in-process, which every test and every box without a concentrator
//! drives, the way hart drives its loopback line. The origin URI names the
//! radio, the device and the port: `lorawan://loopback/26011b2c?port=2`.

pub mod aes;
pub mod frame;
pub mod server;

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

pub use frame::{Frame, Keys, MType};
pub use server::NetworkServer;
use transport::error::{Result, TransportError, protocol_error};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::{Arrived, Directions, Transport};

/// Where frames go and come from: the air, as one device hears it.
pub trait Radio: Send + Sync {
    /// The radio's name, for the origin URI.
    fn name(&self) -> &str;
    /// Send a sealed frame up.
    ///
    /// # Errors
    /// Where the radio refused it.
    fn transmit(&self, frame: &[u8]) -> Result<()>;
    /// The next sealed frame down, or `None` when nothing came within
    /// `timeout` — the receive windows closed empty.
    ///
    /// # Errors
    /// Where the radio could not be read.
    fn receive(&self, timeout: Duration) -> Result<Option<Vec<u8>>>;
}

/// A gateway and network server in-process: what the device sends up the
/// server opens, and what the server queues down the device receives next.
pub struct LoopbackRadio {
    server: Mutex<NetworkServer>,
}

impl LoopbackRadio {
    #[must_use]
    pub const fn new(server: NetworkServer) -> Self {
        Self {
            server: Mutex::new(server),
        }
    }

    /// The network server, to queue a downlink or take what arrived.
    pub fn server(&self) -> std::sync::MutexGuard<'_, NetworkServer> {
        self.server.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Radio for LoopbackRadio {
    fn name(&self) -> &'static str {
        "loopback"
    }

    fn transmit(&self, frame: &[u8]) -> Result<()> {
        self.server().uplink(frame)
    }

    fn receive(&self, _timeout: Duration) -> Result<Option<Vec<u8>>> {
        Ok(self.server().next_downlink())
    }
}

/// The device's session: its address, its keys and where its counter is.
/// Shared by every clone of a transport, because the network refuses a
/// counter that goes back.
#[derive(Debug)]
pub struct Device {
    pub dev_addr: u32,
    pub keys: Keys,
    fcnt_up: Mutex<u32>,
    fcnt_down: Mutex<Option<u32>>,
    /// Frames down that carried data as well as an ACK, kept for the next
    /// receive.
    held: Mutex<VecDeque<Frame>>,
}

impl Device {
    #[must_use]
    pub const fn new(dev_addr: u32, keys: Keys) -> Self {
        Self {
            dev_addr,
            keys,
            fcnt_up: Mutex::new(0),
            fcnt_down: Mutex::new(None),
            held: Mutex::new(VecDeque::new()),
        }
    }

    fn next_fcnt_up(&self) -> u32 {
        let mut fcnt = self.fcnt_up.lock().unwrap_or_else(PoisonError::into_inner);
        let next = *fcnt;
        *fcnt += 1;
        next
    }
}

/// One device on one radio.
#[derive(Clone)]
pub struct LorawanTransport {
    radio: Arc<dyn Radio>,
    device: Arc<Device>,
    confirmed: bool,
    timeout: Duration,
    /// Set on a loopback: the radio holds the network server.
    loopback: Option<Arc<LoopbackRadio>>,
}

impl LorawanTransport {
    /// `device` on `radio`, sending unconfirmed.
    #[must_use]
    pub fn new(radio: Arc<dyn Radio>, device: Arc<Device>) -> Self {
        Self {
            radio,
            device,
            confirmed: false,
            timeout: Duration::from_secs(5),
            loopback: None,
        }
    }

    /// Send confirmed: every frame up waits for the ACK down.
    #[must_use]
    pub const fn confirmed(mut self) -> Self {
        self.confirmed = true;
        self
    }

    /// Give up on a receive window that stays empty for `timeout`.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// `lorawan://<radio>/<device address>`.
    #[must_use]
    pub fn origin(&self) -> String {
        format!(
            "lorawan://{}/{:08x}",
            self.radio.name(),
            self.device.dev_addr
        )
    }

    /// The next frame down, opened, or `None` when the window closed empty.
    fn next_down(&self) -> Result<Option<Frame>> {
        let Some(bytes) = self.radio.receive(self.timeout)? else {
            return Ok(None);
        };
        let mut last = self
            .device
            .fcnt_down
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        let expected = last.map_or(0, |n| n + 1);
        let frame = Frame::open(
            &bytes,
            &self.device.keys,
            u16::try_from(expected >> 16).unwrap_or(0),
        )?;
        if frame.mtype.is_uplink() || frame.dev_addr != self.device.dev_addr {
            return Err(protocol_error("a frame down that is not for this device"));
        }
        *last = Some(frame.fcnt);
        Ok(Some(frame))
    }

    /// Send `bytes` up as one frame, or as fragments, confirmed as
    /// configured.
    ///
    /// # Errors
    /// Where the radio refused a frame, or a confirmed frame went
    /// unacknowledged.
    pub fn send_stream(&self, bytes: &[u8]) -> Result<()> {
        let mtype = if self.confirmed {
            MType::ConfirmedUp
        } else {
            MType::UnconfirmedUp
        };
        for (port, payload) in frame::payloads(bytes) {
            let fcnt = self.device.next_fcnt_up();
            let frame = Frame::new(mtype, self.device.dev_addr, fcnt, port, &payload)?;
            self.radio.transmit(&frame.seal(&self.device.keys))?;
            if self.confirmed {
                let down = self
                    .next_down()?
                    .ok_or_else(|| TransportError::retryable("no ACK in the receive windows"))?;
                if !down.ack {
                    return Err(protocol_error("a frame down without the ACK bit"));
                }
                if !Self::is_bare_ack(&down) {
                    self.device
                        .held
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .push_back(down);
                }
            }
        }
        Ok(())
    }

    /// Whether a frame down carries nothing but its ACK bit.
    fn is_bare_ack(frame: &Frame) -> bool {
        frame.port == 0 && frame.payload.is_empty()
    }

    /// The next Stream down with a payload — one held from a confirmed send,
    /// else the next off the radio — or `None` when the windows closed
    /// empty. A bare ACK carries nothing and is not a Stream.
    ///
    /// # Errors
    /// Where the radio could not be read or the frame does not open.
    pub fn receive_one(&self) -> Result<Option<Arrived>> {
        let held = self
            .device
            .held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop_front();
        let mut next = match held {
            Some(frame) => Some(frame),
            None => self.next_down()?,
        };
        while let Some(frame) = next {
            if Self::is_bare_ack(&frame) {
                next = self.next_down()?;
                continue;
            }
            let origin = format!("{}?port={}&fcnt={}", self.origin(), frame.port, frame.fcnt);
            return Ok(Some(Arrived::new(origin, frame.payload)));
        }
        Ok(None)
    }
}

impl Transport for LorawanTransport {
    fn name(&self) -> &'static str {
        "lorawan"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    /// An empty receive window is not an error: an empty vector.
    fn receive(&self) -> Result<Vec<Arrived>> {
        Ok(self.receive_one()?.into_iter().collect())
    }

    /// The target is the network: a device sends to whoever hears it.
    fn send(&self, _target: &str, bytes: &[u8]) -> Result<()> {
        self.send_stream(bytes)
    }
}

impl LorawanTransport {
    /// Both ends on one in-process radio: a device sending confirmed, and
    /// the network server that opens and acknowledges what it sends, the
    /// loopback timeout on the receive windows.
    #[must_use]
    pub fn loopback() -> Self {
        let keys = Keys {
            nwk_s_key: [0x2b; 16],
            app_s_key: [0x7e; 16],
        };
        let dev_addr = 0x2601_1b2c;
        let radio = Arc::new(LoopbackRadio::new(NetworkServer::new(dev_addr, keys)));
        let mut transport = Self::new(
            Arc::clone(&radio) as Arc<dyn Radio>,
            Arc::new(Device::new(dev_addr, keys)),
        )
        .confirmed()
        .timing_out_after(LOOPBACK_TIMEOUT);
        transport.loopback = Some(radio);
        transport
    }
}

/// The network server, holding what arrived whole.
struct Served {
    radio: Arc<LoopbackRadio>,
    origin: String,
}

impl FarEnd for Served {
    fn address(&self) -> &str {
        &self.origin
    }

    fn take_one(self: Box<Self>) -> Result<Arrived> {
        let (port, bytes) = self
            .radio
            .server()
            .take()
            .ok_or_else(|| protocol_error("nothing arrived at the network server"))?;
        Ok(Arrived::new(format!("{}?port={port}", self.origin), bytes))
    }
}

impl Loopback for LorawanTransport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let radio = self
            .loopback
            .as_ref()
            .ok_or_else(|| protocol_error("a concentrator, not a loopback radio"))?;
        Ok(Box::new(Served {
            radio: Arc::clone(radio),
            origin: self.origin(),
        }))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        self.clone().send(address, payload)
    }

    fn unblock(&self, _address: &str) {
        // The air is in-process; nothing listens on a socket.
    }

    /// In order on one thread: the network server lives in the radio and
    /// opens each frame as it is sent, so the send goes first and the take
    /// finds the Stream whole.
    fn round(&self, payload: &[u8]) -> Result<Arrived> {
        let far = self.far_end()?;
        self.send_to(far.address(), payload)?;
        let arrived = far.take_one()?;
        if arrived.bytes != payload {
            return Err(protocol_error("sent, but what the server took differs"));
        }
        Ok(arrived)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shapes a protocol breaks on, as the Playground lists them.
    fn edge_payloads() -> Vec<(&'static str, Vec<u8>)> {
        vec![
            ("empty", Vec::new()),
            ("one byte", vec![0x2a]),
            ("every byte", (0..=255).collect()),
            ("nul run", vec![0; 512]),
            ("high bytes", vec![0xff; 512]),
            ("crlf storm", b"\r\n".repeat(400)),
            (
                "sixty-four kibibytes plus one",
                (0..65_537u32)
                    .map(|n| u8::try_from(n * 31 % 256).unwrap_or(0))
                    .collect(),
            ),
        ]
    }

    #[test]
    fn a_loopback_round_carries_a_stream_up_to_the_network_server() {
        let loopback = LorawanTransport::loopback();
        let arrived = loopback.round(b"21.5 C").expect("round");
        assert_eq!(arrived.bytes, b"21.5 C");
        assert_eq!(arrived.origin_uri, "lorawan://loopback/26011b2c?port=1");
        let long = vec![7; 1000];
        let arrived = loopback.round(&long).expect("fragments");
        assert_eq!(arrived.bytes, long);
        assert_eq!(arrived.origin_uri, "lorawan://loopback/26011b2c?port=2");
        assert!(loopback.ceiling().is_none());
        assert!(loopback.refuses(b"anything").is_none());
        assert_eq!(loopback.name(), "lorawan");
        assert!(loopback.directions().receives() && loopback.directions().sends());
        assert!(loopback.claims().is_none());
    }

    #[test]
    fn the_loopback_returns_the_edges_whole() {
        let loopback = LorawanTransport::loopback();
        for (name, bytes) in edge_payloads() {
            let arrived = loopback
                .round(&bytes)
                .unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(arrived.bytes, bytes, "{name}");
        }
    }

    #[test]
    fn a_downlink_arrives_as_a_stream_and_a_bare_ack_does_not() {
        let loopback = LorawanTransport::loopback();
        assert!(
            loopback.receive().expect("quiet").is_empty(),
            "empty is not an error"
        );
        let radio = loopback.loopback.as_ref().expect("loopback");
        radio.server().downlink(3, b"set 20").expect("queued");
        loopback
            .send("lorawan://loopback", b"confirmed")
            .expect("sending");
        let arrived = loopback.receive().expect("receiving");
        assert_eq!(arrived.len(), 1);
        assert_eq!(arrived[0].bytes, b"set 20");
        assert_eq!(
            arrived[0].origin_uri,
            "lorawan://loopback/26011b2c?port=3&fcnt=0"
        );
        assert!(
            loopback.receive().expect("quiet again").is_empty(),
            "the ACK rode on the downlink; no bare ACK follows"
        );
    }

    #[test]
    fn a_confirmed_frame_nobody_acknowledges_is_worth_trying_again() {
        struct Silence;
        impl Radio for Silence {
            fn name(&self) -> &'static str {
                "silence"
            }
            fn transmit(&self, _frame: &[u8]) -> Result<()> {
                Ok(())
            }
            fn receive(&self, _timeout: Duration) -> Result<Option<Vec<u8>>> {
                Ok(None)
            }
        }
        let keys = Keys {
            nwk_s_key: [1; 16],
            app_s_key: [2; 16],
        };
        let device = Arc::new(Device::new(7, keys));
        let quiet = LorawanTransport::new(Arc::new(Silence), device).confirmed();
        let error = quiet
            .send("lorawan://silence", b"anyone?")
            .expect_err("no ack");
        assert!(error.retryable, "{error}");
        assert!(
            quiet.far_end().is_err(),
            "a real radio has no server inside"
        );
        assert_eq!(quiet.origin(), "lorawan://silence/00000007");
    }
}
