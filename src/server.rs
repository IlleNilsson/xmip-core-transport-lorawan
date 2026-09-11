//! The network server's side of one device: it opens each uplink under the
//! device's session keys, refuses a counter that does not advance, puts the
//! fragments of a Stream back together, and answers a confirmed uplink with
//! a downlink carrying the ACK bit. The same server runs inside the loopback
//! radio; behind a real gateway it is the operator's.

use std::collections::VecDeque;

use transport::error::{Result, protocol_error};

use crate::frame::{self, Frame, Keys, MType};

/// One device as its network server knows it.
#[derive(Debug)]
pub struct NetworkServer {
    dev_addr: u32,
    keys: Keys,
    /// The last uplink counter accepted, or `None` before the first.
    fcnt_up: Option<u32>,
    fcnt_down: u32,
    arriving: Vec<u8>,
    complete: VecDeque<(u8, Vec<u8>)>,
    /// Queued for the device's receive windows, sealed when they open: a
    /// confirmed uplink puts its ACK on the first of them.
    downlinks: VecDeque<Frame>,
}

impl NetworkServer {
    #[must_use]
    pub const fn new(dev_addr: u32, keys: Keys) -> Self {
        Self {
            dev_addr,
            keys,
            fcnt_up: None,
            fcnt_down: 0,
            arriving: Vec::new(),
            complete: VecDeque::new(),
            downlinks: VecDeque::new(),
        }
    }

    /// One uplink as the gateway forwarded it.
    ///
    /// # Errors
    /// A frame that does not open, from another device, going the wrong way,
    /// with a counter that does not advance, or on a port this crate does
    /// not carry.
    pub fn uplink(&mut self, bytes: &[u8]) -> Result<()> {
        let expected = self.fcnt_up.map_or(0, |last| last + 1);
        let frame = Frame::open(
            bytes,
            &self.keys,
            u16::try_from(expected >> 16).unwrap_or(0),
        )?;
        if frame.dev_addr != self.dev_addr {
            return Err(protocol_error("an uplink from another device"));
        }
        if !frame.mtype.is_uplink() {
            return Err(protocol_error("a downlink where an uplink was due"));
        }
        if self.fcnt_up.is_some_and(|last| frame.fcnt <= last) {
            return Err(protocol_error("a frame counter that did not advance"));
        }
        match frame.port {
            frame::PORT_STREAM => self.complete.push_back((frame.port, frame.payload.clone())),
            frame::PORT_FRAGMENT => self.fragment(&frame.payload)?,
            other => {
                return Err(protocol_error(format!(
                    "port {other}, which nothing listens on"
                )));
            }
        }
        self.fcnt_up = Some(frame.fcnt);
        if frame.mtype.is_confirmed() {
            if let Some(pending) = self.downlinks.front_mut() {
                pending.ack = true;
            } else {
                let ack = Frame::new(
                    MType::UnconfirmedDown,
                    self.dev_addr,
                    self.fcnt_down,
                    0,
                    &[],
                )?;
                self.fcnt_down += 1;
                self.downlinks.push_back(ack.acknowledging());
            }
        }
        Ok(())
    }

    fn fragment(&mut self, payload: &[u8]) -> Result<()> {
        let (flags, chunk) = payload
            .split_first()
            .ok_or_else(|| protocol_error("a fragment without its flags"))?;
        if flags & frame::FIRST != 0 {
            self.arriving.clear();
        }
        self.arriving.extend_from_slice(chunk);
        if flags & frame::LAST != 0 {
            let whole = std::mem::take(&mut self.arriving);
            self.complete.push_back((frame::PORT_FRAGMENT, whole));
        }
        Ok(())
    }

    /// Queue a downlink carrying `bytes` on `port` for the device's next
    /// receive window.
    ///
    /// # Errors
    /// More than one frame carries.
    pub fn downlink(&mut self, port: u8, bytes: &[u8]) -> Result<()> {
        let frame = Frame::new(
            MType::UnconfirmedDown,
            self.dev_addr,
            self.fcnt_down,
            port,
            bytes,
        )?;
        self.fcnt_down += 1;
        self.downlinks.push_back(frame);
        Ok(())
    }

    /// The next downlink for the device, sealed.
    pub fn next_downlink(&mut self) -> Option<Vec<u8>> {
        self.downlinks
            .pop_front()
            .map(|frame| frame.seal(&self.keys))
    }

    /// The next Stream that arrived whole: the port it came on and its bytes.
    pub fn take(&mut self) -> Option<(u8, Vec<u8>)> {
        self.complete.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn fragments_come_back_together_and_a_confirmed_uplink_is_acknowledged() {
        let mut server = NetworkServer::new(DEV_ADDR, keys());
        let long: Vec<u8> = (0..300u32)
            .map(|n| u8::try_from(n % 256).unwrap_or(0))
            .collect();
        for (fcnt, (port, payload)) in frame::payloads(&long).into_iter().enumerate() {
            let mtype = if fcnt == 1 {
                MType::ConfirmedUp
            } else {
                MType::UnconfirmedUp
            };
            let fcnt = u32::try_from(fcnt).unwrap_or(0);
            server
                .uplink(&uplink(mtype, fcnt, port, &payload))
                .expect("uplink");
        }
        assert_eq!(server.take(), Some((frame::PORT_FRAGMENT, long)));
        assert!(server.take().is_none());
        let ack = server.next_downlink().expect("an ack");
        let ack = Frame::open(&ack, &keys(), 0).expect("open");
        assert!(ack.ack && ack.mtype == MType::UnconfirmedDown && ack.fcnt == 0);
        assert!(
            server.next_downlink().is_none(),
            "one ack for one confirmed frame"
        );
        server
            .uplink(&uplink(MType::UnconfirmedUp, 2, 1, b""))
            .expect("empty");
        assert_eq!(server.take(), Some((frame::PORT_STREAM, Vec::new())));
    }

    #[test]
    fn a_counter_that_does_not_advance_is_refused_as_are_strangers() {
        let mut server = NetworkServer::new(DEV_ADDR, keys());
        server
            .uplink(&uplink(MType::UnconfirmedUp, 5, 1, b"a"))
            .expect("first");
        assert!(
            server
                .uplink(&uplink(MType::UnconfirmedUp, 5, 1, b"a"))
                .is_err(),
            "replay"
        );
        assert!(
            server
                .uplink(&uplink(MType::UnconfirmedUp, 4, 1, b"a"))
                .is_err(),
            "backwards"
        );
        assert!(
            server
                .uplink(&uplink(MType::UnconfirmedUp, 6, 9, b"a"))
                .is_err(),
            "port"
        );
        assert!(
            server
                .uplink(&uplink(MType::UnconfirmedDown, 6, 1, b"a"))
                .is_err(),
            "down"
        );
        assert!(
            server
                .uplink(&uplink(MType::UnconfirmedUp, 6, 2, b""))
                .is_err(),
            "no flags"
        );
        let stranger = Frame::new(MType::UnconfirmedUp, 7, 6, 1, b"a")
            .expect("frame")
            .seal(&keys());
        assert!(server.uplink(&stranger).is_err(), "another device");
        server
            .uplink(&uplink(MType::UnconfirmedUp, 6, 1, b"b"))
            .expect("advances");
        assert_eq!(server.take(), Some((1, b"a".to_vec())));
        assert_eq!(server.take(), Some((1, b"b".to_vec())));
    }

    #[test]
    fn a_downlink_is_sealed_for_the_device_with_its_own_counter() {
        let mut server = NetworkServer::new(DEV_ADDR, keys());
        server.downlink(3, b"set 20").expect("downlink");
        server.downlink(3, b"set 21").expect("downlink");
        let second = server.next_downlink().and_then(|_| server.next_downlink());
        let frame = Frame::open(&second.expect("second"), &keys(), 0).expect("open");
        assert_eq!(
            (frame.port, frame.payload.as_slice(), frame.fcnt),
            (3, &b"set 21"[..], 1)
        );
        assert!(server.downlink(3, &[0; 223]).is_err());
    }
}
