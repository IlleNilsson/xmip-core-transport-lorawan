//! A device's side of `LoRaWAN`: its session — address, keys, counters — and
//! what it does on the air it hears, a [`Radio`]: send a Stream up in one
//! frame or in fragments, confirmed or not, and take what comes down, put
//! back together. It is what stands behind a gateway as a node's far end,
//! the device a node's network server talks to, written with the frame, the
//! keys and the fragments the node's side is written with.
//!
//! **A confirmed frame down is acknowledged after the whole receive
//! cycle**: on [`transport::Verdict::Accepted`] the device's next frame up
//! carries its ACK bit; on [`transport::Verdict::Failed`] it does not, and
//! the network server sends the frame again. `LoRaWAN` has no negative
//! acknowledgement — the ACK bit is the only answer (`LoRaWAN` L2 1.0.4,
//! section 4.3.1.2, message acknowledgement) — so nothing tells a network
//! server *refused, do not send again*: on [`transport::Verdict::Refused`]
//! the ACK bit rides up too, the frame taken and not sent again, and the
//! refusal is what the runtime audited. An unconfirmed frame down asks for
//! no ACK: acceptance is at-most-once there ([`AT_MOST_ONCE`]).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use transport::error::{Result, TransportError, protocol_error};
use transport::loopback::FarEnd;
use transport::{Acknowledgement, Arrived, Taken, Verdict};
use xcore::lock::Locked;

use crate::declaration::DEFAULT_TIMEOUT;
use crate::fragment::{self, Reassembly};
use crate::frame::{Frame, Keys, MType};
use crate::radio::Radio;

/// Why an unconfirmed frame down cannot be acknowledged after the receive
/// cycle.
pub const AT_MOST_ONCE: &str = "an unconfirmed LoRaWAN frame down asks for no ACK: the network \
                                server sent it once, in the receive window";

/// The device's session: its address, its keys and where its counters are.
/// Shared by every clone of a device, because the network refuses a
/// counter that goes back.
#[derive(Debug)]
pub struct Device {
    pub dev_addr: u32,
    pub keys: Keys,
    fcnt_up: Mutex<u32>,
    fcnt_down: Mutex<Option<u32>>,
    /// Frames down that came while a confirmed frame up waited for its
    /// ACK, kept for the next receive.
    held: Mutex<VecDeque<Frame>>,
    /// The fragments of a Stream coming down.
    arriving: Mutex<Reassembly>,
    /// A confirmed frame down was accepted: the next frame up carries its
    /// ACK bit.
    ack_due: AtomicBool,
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
            arriving: Mutex::new(Reassembly::new()),
            ack_due: AtomicBool::new(false),
        }
    }

    fn next_fcnt_up(&self) -> u32 {
        let mut fcnt = self.fcnt_up.locked();
        let next = *fcnt;
        *fcnt += 1;
        next
    }
}

/// One device on one radio.
#[derive(Clone)]
pub struct EndDevice {
    radio: Arc<dyn Radio>,
    device: Arc<Device>,
    confirmed: bool,
    timeout: Duration,
}

impl EndDevice {
    /// `device` on `radio`, sending unconfirmed and waiting
    /// [`DEFAULT_TIMEOUT`] on its receive windows.
    #[must_use]
    pub fn new(radio: Arc<dyn Radio>, device: Arc<Device>) -> Self {
        Self {
            radio,
            device,
            confirmed: false,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Send confirmed: every frame up waits for the ACK down.
    #[must_use]
    pub const fn confirmed(mut self) -> Self {
        self.confirmed = true;
        self
    }

    /// Waiting `timeout` on its receive windows.
    #[must_use]
    pub const fn waiting(mut self, timeout: Duration) -> Self {
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
        let mut last = self.device.fcnt_down.locked();
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
        for (port, payload) in fragment::payloads(bytes) {
            let fcnt = self.device.next_fcnt_up();
            let mut frame = Frame::new(mtype, self.device.dev_addr, fcnt, port, &payload)?;
            if self.device.ack_due.swap(false, Ordering::Relaxed) {
                frame = frame.acknowledging();
            }
            self.radio.transmit(&frame.seal(&self.device.keys))?;
            if self.confirmed {
                let down = self
                    .next_down()?
                    .ok_or_else(|| TransportError::retryable("no ACK in the receive windows"))?;
                if !down.ack {
                    return Err(protocol_error("a frame down without the ACK bit"));
                }
                self.device.held.locked().push_back(down);
            }
        }
        Ok(())
    }

    /// The next Stream down, whole — put back together from frames held
    /// from a confirmed send and those off the radio — or `None` when the
    /// windows closed before it was. A frame carrying no Stream, a bare
    /// ACK, is read past. A Stream whose last frame was confirmed is
    /// acknowledged by its arrival's verdict: accepted or refused, the
    /// device's next frame up carries its ACK bit; failed, it does not, and
    /// the network server sends it again. An unconfirmed one is
    /// at-most-once ([`AT_MOST_ONCE`]).
    ///
    /// # Errors
    /// Where the radio could not be read or a frame does not open.
    pub fn receive_one(&self) -> Result<Option<Arrived>> {
        loop {
            let held = self.device.held.locked().pop_front();
            let Some(frame) = held.map_or_else(|| self.next_down(), |frame| Ok(Some(frame)))?
            else {
                return Ok(None);
            };
            let (mtype, port, fcnt) = (frame.mtype, frame.port, frame.fcnt);
            let Some(bytes) = self.device.arriving.locked().arrived(port, frame.payload)? else {
                continue;
            };
            let origin = format!("{}?port={port}&fcnt={fcnt}", self.origin());
            let acknowledgement = if mtype == MType::ConfirmedDown {
                let device = Arc::clone(&self.device);
                Acknowledgement::deferred(move |verdict| {
                    // LoRaWAN has no negative acknowledgement: a refused
                    // frame is acknowledged, taken for good.
                    let acknowledged = !matches!(verdict, Verdict::Failed);
                    device.ack_due.store(acknowledged, Ordering::Relaxed);
                    Ok(())
                })
            } else {
                Acknowledgement::at_most_once(AT_MOST_ONCE)
            };
            return Ok(Some(Arrived::whole(origin, bytes, acknowledgement)));
        }
    }
}

/// A device behind a gateway pointed at a network server: the far end of a
/// node's `LoRaWAN` Send Location, taking the one Stream the node sends it
/// and accepting it.
pub struct BehindGateway {
    address: String,
    device: EndDevice,
}

impl BehindGateway {
    /// `device`, whose radio is a gateway pointed at the node listening at
    /// `address`.
    #[must_use]
    pub const fn new(address: String, device: EndDevice) -> Self {
        Self { address, device }
    }
}

impl FarEnd for BehindGateway {
    /// Where the node listens for the gateway.
    fn address(&self) -> &str {
        &self.address
    }

    /// The gateway reads a datagram socket with its own timeout.
    fn datagram(&self) -> bool {
        true
    }

    /// The one Stream, accepted: a receive ends once no frame came down
    /// within the device's wait.
    fn take_one(self: Box<Self>) -> Result<Taken> {
        let Some(arrived) = self.device.receive_one()? else {
            return Err(TransportError::retryable(format!(
                "{}: no Stream came down to the device",
                self.device.origin()
            )));
        };
        arrived.taken()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A radio whose frames down are queued by the test and whose frames up
    /// are kept for it to read.
    #[derive(Default)]
    struct Scripted {
        down: Mutex<VecDeque<Vec<u8>>>,
        up: Mutex<Vec<Vec<u8>>>,
    }

    impl Radio for Scripted {
        fn name(&self) -> &'static str {
            "scripted"
        }
        fn transmit(&self, frame: &[u8]) -> Result<()> {
            self.up.lock().expect("up").push(frame.to_vec());
            Ok(())
        }
        fn receive(&self, _timeout: Duration) -> Result<Option<Vec<u8>>> {
            Ok(self.down.lock().expect("down").pop_front())
        }
    }

    const KEYS: Keys = Keys {
        nwk_s_key: [3; 16],
        app_s_key: [4; 16],
    };

    #[test]
    fn a_confirmed_frame_down_is_acknowledged_by_the_next_frame_up_only_when_accepted() {
        let radio = Arc::new(Scripted::default());
        let device = EndDevice::new(
            Arc::clone(&radio) as Arc<dyn Radio>,
            Arc::new(Device::new(9, KEYS)),
        );
        let down = |fcnt, mtype| {
            let frame = Frame::new(mtype, 9, fcnt, 1, b"set 20").expect("frame");
            radio
                .down
                .lock()
                .expect("down")
                .push_back(frame.seal(&KEYS));
        };
        let last_up_acknowledges = || {
            let up = radio.up.lock().expect("up").pop().expect("a frame up");
            Frame::open(&up, &KEYS, 0).expect("open").ack
        };
        // Failed: the next frame up carries no ACK, so it is sent again.
        down(0, MType::ConfirmedDown);
        let first = device.receive_one().expect("first").expect("a Stream");
        assert!(first.defers(), "a confirmed frame down waits for its ACK");
        first.failed().expect("failed");
        device.send_stream(b"C1").expect("up");
        assert!(!last_up_acknowledges(), "failed: no ACK");
        // Refused: the ACK rides up, so it is not sent again.
        down(1, MType::ConfirmedDown);
        let refused = device.receive_one().expect("refused").expect("a Stream");
        refused
            .refused(transport::Refusal::Unacceptable)
            .expect("acknowledged");
        device.send_stream(b"R1").expect("up");
        assert!(last_up_acknowledges(), "refused: taken for good");
        // Accepted: the next frame up carries the ACK bit.
        down(2, MType::ConfirmedDown);
        let again = device.receive_one().expect("again").expect("a Stream");
        assert_eq!(again.taken().expect("accepted").bytes, b"set 20");
        device.send_stream(b"C2").expect("up");
        assert!(last_up_acknowledges(), "accepted: the ACK rides up");
        // Unconfirmed: nobody waits.
        down(3, MType::UnconfirmedDown);
        let unconfirmed = device
            .receive_one()
            .expect("unconfirmed")
            .expect("a Stream");
        assert!(
            !unconfirmed.defers(),
            "an unconfirmed frame down is at-most-once"
        );
        assert!(device.receive_one().expect("quiet").is_none(), "empty");
    }

    #[test]
    fn fragments_down_arrive_as_one_stream_and_a_bare_ack_as_none() {
        let radio = Arc::new(Scripted::default());
        let device = EndDevice::new(
            Arc::clone(&radio) as Arc<dyn Radio>,
            Arc::new(Device::new(9, KEYS)),
        );
        let long = vec![5; 500];
        let bare = Frame::new(MType::UnconfirmedDown, 9, 0, 0, b"").expect("bare");
        radio
            .down
            .lock()
            .expect("down")
            .push_back(bare.acknowledging().seal(&KEYS));
        for (fcnt, (port, payload)) in fragment::payloads(&long).into_iter().enumerate() {
            let fcnt = u32::try_from(fcnt + 1).unwrap_or(0);
            let frame = Frame::new(MType::UnconfirmedDown, 9, fcnt, port, &payload).expect("frame");
            radio
                .down
                .lock()
                .expect("down")
                .push_back(frame.seal(&KEYS));
        }
        let arrived = device.receive_one().expect("whole").expect("a Stream");
        assert_eq!(
            arrived.origin_uri,
            "lorawan://scripted/00000009?port=2&fcnt=3"
        );
        assert_eq!(arrived.taken().expect("taken").bytes, long);
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
        let device = Arc::new(Device::new(7, KEYS));
        let quiet = EndDevice::new(Arc::new(Silence), device).confirmed();
        let error = quiet.send_stream(b"anyone?").expect_err("no ack");
        assert!(error.retryable, "{error}");
        assert_eq!(quiet.origin(), "lorawan://silence/00000007");
        let far = Box::new(BehindGateway::new(
            "node".into(),
            quiet.waiting(Duration::ZERO),
        ));
        assert!(far.datagram() && far.address() == "node");
        assert!(far.take_one().expect_err("nothing").retryable);
    }
}
