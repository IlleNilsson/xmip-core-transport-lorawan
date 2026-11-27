//! The network server's side of one device: it opens each uplink under the
//! device's session keys, takes the same frame heard by a second gateway
//! once, refuses a counter that does not advance, puts the fragments of a
//! Stream back together, answers a confirmed uplink with a frame carrying
//! the ACK bit, and seals each downlink with its own counter. A node is it
//! behind the gateways that point at it (`gateways.rs`); the keys are handed
//! in at each use, as the secret holding them is read then.

use std::collections::VecDeque;

use transport::error::{Result, protocol_error};

use crate::fragment::{PORT_COMMANDS, Reassembly};
use crate::frame::{Frame, Keys, MType};

/// One device as its network server knows it.
#[derive(Debug)]
pub struct NetworkServer {
    dev_addr: u32,
    /// The last uplink counter taken, or `None` before the first.
    fcnt_up: Option<u32>,
    /// The last uplink taken, as the air carried it: the same frame another
    /// gateway heard is not taken again.
    last_up: Vec<u8>,
    fcnt_down: u32,
    arriving: Reassembly,
    complete: VecDeque<Whole>,
}

/// A Stream that arrived whole: the port and the counter of its last frame.
#[derive(Debug, PartialEq, Eq)]
pub struct Whole {
    pub port: u8,
    pub fcnt: u32,
    pub bytes: Vec<u8>,
}

/// What one uplink was, beyond the Stream it may have made whole.
#[derive(Debug, PartialEq, Eq)]
pub struct Uplink {
    /// It acknowledged the last confirmed frame down.
    pub ack: bool,
    /// The frame acknowledging it, sealed, where it was confirmed: for the
    /// device's first receive window.
    pub answer: Option<Vec<u8>>,
}

impl NetworkServer {
    #[must_use]
    pub const fn new(dev_addr: u32) -> Self {
        Self {
            dev_addr,
            fcnt_up: None,
            last_up: Vec::new(),
            fcnt_down: 0,
            arriving: Reassembly::new(),
            complete: VecDeque::new(),
        }
    }

    /// One uplink as a gateway forwarded it, opened under `keys`: `None`
    /// where it is the frame taken last, heard again by another gateway, or
    /// no frame of this session's — one that does not open under its keys,
    /// as another network's device at the same address sends, for a device
    /// address is unique within one network alone.
    ///
    /// # Errors
    /// A frame from another device, going the wrong way, with a counter
    /// that does not advance, or on a port this crate does not carry.
    pub fn uplink(&mut self, bytes: &[u8], keys: &Keys) -> Result<Option<Uplink>> {
        if bytes == self.last_up.as_slice() {
            return Ok(None);
        }
        let expected = self.fcnt_up.map_or(0, |last| last + 1);
        let high = u16::try_from(expected >> 16).unwrap_or(0);
        let Ok(frame) = Frame::open(bytes, keys, high) else {
            return Ok(None);
        };
        if frame.dev_addr != self.dev_addr {
            return Err(protocol_error("an uplink from another device"));
        }
        if !frame.mtype.is_uplink() {
            return Err(protocol_error("a downlink where an uplink was due"));
        }
        if self.fcnt_up.is_some_and(|last| frame.fcnt <= last) {
            return Err(protocol_error("a frame counter that did not advance"));
        }
        let (port, fcnt, ack) = (frame.port, frame.fcnt, frame.ack);
        if let Some(bytes) = self.arriving.arrived(port, frame.payload)? {
            self.complete.push_back(Whole { port, fcnt, bytes });
        }
        self.fcnt_up = Some(fcnt);
        self.last_up = bytes.to_vec();
        let answer = if frame.mtype.is_confirmed() {
            let ack = Frame::new(
                MType::UnconfirmedDown,
                self.dev_addr,
                self.fcnt_down,
                PORT_COMMANDS,
                &[],
            )?;
            Some(self.sealed(&ack.acknowledging(), keys))
        } else {
            None
        };
        Ok(Some(Uplink { ack, answer }))
    }

    /// `bytes` on `port` as a frame down of type `mtype`, sealed under
    /// `keys` with the next counter down.
    ///
    /// # Errors
    /// More than one frame carries.
    pub fn downlink(
        &mut self,
        mtype: MType,
        port: u8,
        bytes: &[u8],
        keys: &Keys,
    ) -> Result<Vec<u8>> {
        let frame = Frame::new(mtype, self.dev_addr, self.fcnt_down, port, bytes)?;
        Ok(self.sealed(&frame, keys))
    }

    /// `frame` sealed, its counter spent.
    fn sealed(&mut self, frame: &Frame, keys: &Keys) -> Vec<u8> {
        self.fcnt_down += 1;
        frame.seal(keys)
    }

    /// The next Stream that arrived whole.
    pub fn take(&mut self) -> Option<Whole> {
        self.complete.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fragment::{self, PORT_FRAGMENT, PORT_STREAM};

    const DEV_ADDR: u32 = 0x2601_1b2c;

    fn keys() -> Keys {
        Keys {
            nwk_s_key: [0x11; 16],
            app_s_key: [0x22; 16],
        }
    }

    fn uplink(mtype: MType, fcnt: u32, port: u8, payload: &[u8]) -> Vec<u8> {
        Frame::new(mtype, DEV_ADDR, fcnt, port, payload)
            .expect("frame")
            .seal(&keys())
    }

    #[test]
    fn fragments_come_back_together_and_a_confirmed_uplink_is_answered() {
        let mut server = NetworkServer::new(DEV_ADDR);
        let long: Vec<u8> = (0..300u32)
            .map(|n| u8::try_from(n % 256).unwrap_or(0))
            .collect();
        let mut answers = Vec::new();
        for (fcnt, (port, payload)) in fragment::payloads(&long).into_iter().enumerate() {
            let mtype = if fcnt == 1 {
                MType::ConfirmedUp
            } else {
                MType::UnconfirmedUp
            };
            let fcnt = u32::try_from(fcnt).unwrap_or(0);
            let heard = server
                .uplink(&uplink(mtype, fcnt, port, &payload), &keys())
                .expect("uplink")
                .expect("not heard before");
            answers.extend(heard.answer);
        }
        let whole = server.take().expect("whole");
        assert_eq!(
            (whole.port, whole.fcnt, whole.bytes),
            (PORT_FRAGMENT, 1, long)
        );
        assert!(server.take().is_none());
        assert_eq!(answers.len(), 1, "one answer for one confirmed frame");
        let ack = Frame::open(&answers[0], &keys(), 0).expect("open");
        assert!(ack.ack && ack.mtype == MType::UnconfirmedDown && ack.fcnt == 0);
        assert_eq!(
            (ack.port, ack.payload.len()),
            (0, 0),
            "a bare acknowledgement"
        );
        server
            .uplink(&uplink(MType::UnconfirmedUp, 2, 1, b""), &keys())
            .expect("empty");
        let empty = server.take().expect("an empty Stream");
        assert_eq!((empty.port, empty.bytes), (PORT_STREAM, Vec::new()));
    }

    #[test]
    fn a_second_gateways_copy_is_taken_once_and_a_counter_must_advance() {
        let mut server = NetworkServer::new(DEV_ADDR);
        let first = uplink(MType::UnconfirmedUp, 5, 1, b"a");
        assert!(server.uplink(&first, &keys()).expect("first").is_some());
        assert_eq!(
            server.uplink(&first, &keys()).expect("again"),
            None,
            "a copy"
        );
        let elsewhere = Keys {
            nwk_s_key: [0x33; 16],
            ..keys()
        };
        let foreign = Frame::new(MType::UnconfirmedUp, DEV_ADDR, 6, 1, b"z")
            .expect("frame")
            .seal(&elsewhere);
        let heard = server
            .uplink(&foreign, &keys())
            .expect("not this session's");
        assert_eq!(heard, None, "another network's device at the same address");
        let replayed = uplink(MType::UnconfirmedUp, 5, 1, b"x");
        assert!(server.uplink(&replayed, &keys()).is_err(), "replay");
        let backwards = uplink(MType::UnconfirmedUp, 4, 1, b"a");
        assert!(server.uplink(&backwards, &keys()).is_err(), "backwards");
        let port = uplink(MType::UnconfirmedUp, 6, 9, b"a");
        assert!(server.uplink(&port, &keys()).is_err(), "port");
        let down = uplink(MType::UnconfirmedDown, 6, 1, b"a");
        assert!(server.uplink(&down, &keys()).is_err(), "down");
        let flagless = uplink(MType::UnconfirmedUp, 6, 2, b"");
        assert!(server.uplink(&flagless, &keys()).is_err(), "no flags");
        let stranger = Frame::new(MType::UnconfirmedUp, 7, 6, 1, b"a")
            .expect("frame")
            .seal(&keys());
        assert!(server.uplink(&stranger, &keys()).is_err(), "another device");
        let next = uplink(MType::UnconfirmedUp, 6, 1, b"b");
        let heard = server
            .uplink(&next, &keys())
            .expect("advances")
            .expect("new");
        assert_eq!(
            heard,
            Uplink {
                ack: false,
                answer: None
            }
        );
        assert_eq!(server.take().map(|whole| whole.bytes), Some(b"a".to_vec()));
        assert_eq!(server.take().map(|whole| whole.bytes), Some(b"b".to_vec()));
    }

    #[test]
    fn a_downlink_is_sealed_for_the_device_with_its_own_counter() {
        let mut server = NetworkServer::new(DEV_ADDR);
        let first = server
            .downlink(MType::UnconfirmedDown, 3, b"set 20", &keys())
            .expect("downlink");
        let second = server
            .downlink(MType::ConfirmedDown, 3, b"set 21", &keys())
            .expect("downlink");
        assert_eq!(Frame::open(&first, &keys(), 0).expect("open").fcnt, 0);
        let frame = Frame::open(&second, &keys(), 0).expect("open");
        assert_eq!(
            (
                frame.mtype,
                frame.port,
                frame.payload.as_slice(),
                frame.fcnt
            ),
            (MType::ConfirmedDown, 3, &b"set 21"[..], 1)
        );
        assert!(
            server
                .downlink(MType::UnconfirmedDown, 3, &[0; 223], &keys())
                .is_err()
        );
        let acknowledging = Frame::new(MType::UnconfirmedUp, DEV_ADDR, 0, 0, b"")
            .expect("frame")
            .acknowledging()
            .seal(&keys());
        let heard = server
            .uplink(&acknowledging, &keys())
            .expect("ack")
            .expect("new");
        assert!(heard.ack, "the device acknowledged");
        assert!(
            server.take().is_none(),
            "a bare acknowledgement is no Stream"
        );
    }
}
