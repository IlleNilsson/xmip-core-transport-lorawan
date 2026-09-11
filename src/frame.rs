//! The `LoRaWAN` MAC frame as the air carries it: a MAC header naming the
//! message type, the frame header — device address, frame control, frame
//! counter — a port, the `FRMPayload` under the application session key, and
//! the four-byte MIC under the network session key.

use transport::error::{Result, protocol_error};

use crate::aes::{self, BLOCK};

/// The most `FRMPayload` one frame carries: N for the fastest EU868 data rate
/// (DR5, 230 bytes of `MACPayload` less the frame header and port). A slower
/// data rate carries less; the specification's tables say how much.
pub const MAX_FRM_PAYLOAD: usize = 222;

/// A Stream that fits one frame travels whole on this port.
pub const PORT_STREAM: u8 = 1;
/// A Stream longer than one frame travels in fragments on this port, each
/// opening with a flags byte: [`FIRST`], [`LAST`], both or neither.
pub const PORT_FRAGMENT: u8 = 2;
/// The fragment is the Stream's first.
pub const FIRST: u8 = 0x40;
/// The fragment is the Stream's last.
pub const LAST: u8 = 0x80;
/// What a fragment carries past its flags byte.
pub const MAX_FRAGMENT: usize = MAX_FRM_PAYLOAD - 1;

/// The ACK bit in frame control.
const ACK: u8 = 0x20;
/// The frame-options length is the low four bits of frame control.
const FOPTS_LEN: u8 = 0x0f;

/// The session keys a device and its network share.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Keys {
    pub nwk_s_key: [u8; BLOCK],
    pub app_s_key: [u8; BLOCK],
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
        out.push(self.port);
        out
    }

    /// The frame as the air carries it: payload encrypted, MIC appended.
    #[must_use]
    pub fn seal(&self, keys: &Keys) -> Vec<u8> {
        let mut out = self.head();
        out.extend(aes::counter(
            &keys.app_s_key,
            &self.block(0x01, 0),
            &self.payload,
        ));
        let mut covered = self
            .block(0x49, u8::try_from(out.len()).unwrap_or(u8::MAX))
            .to_vec();
        covered.extend_from_slice(&out);
        out.extend_from_slice(&aes::cmac(&keys.nwk_s_key, &covered)[..4]);
        out
    }

    /// The frame `bytes` carry, MIC checked and payload decrypted, given the
    /// high sixteen bits of the counter the air does not carry.
    ///
    /// # Errors
    /// A frame cut off, a message type this crate does not carry, frame
    /// options (which this crate does not carry), or a MIC that does not
    /// check — a frame under another key, or tampered with.
    pub fn open(bytes: &[u8], keys: &Keys, fcnt_high: u16) -> Result<Self> {
        let cut = || protocol_error("a frame cut off before its MIC");
        if bytes.len() < 13 {
            return Err(cut());
        }
        let (body, mic) = bytes.split_at(bytes.len() - 4);
        let mtype = MType::from_bits(body[0] >> 5)?;
        let fctrl = body[5];
        if fctrl & FOPTS_LEN != 0 {
            return Err(protocol_error("frame options this crate does not carry"));
        }
        let fcnt = u32::from(fcnt_high) << 16 | u32::from(u16::from_le_bytes([body[6], body[7]]));
        let mut frame = Self {
            mtype,
            dev_addr: u32::from_le_bytes([body[1], body[2], body[3], body[4]]),
            ack: fctrl & ACK != 0,
            fcnt,
            port: body[8],
            payload: Vec::new(),
        };
        let mut covered = frame
            .block(0x49, u8::try_from(body.len()).unwrap_or(u8::MAX))
            .to_vec();
        covered.extend_from_slice(body);
        if aes::cmac(&keys.nwk_s_key, &covered)[..4] != *mic {
            return Err(protocol_error("a MIC that does not check"));
        }
        frame.payload = aes::counter(&keys.app_s_key, &frame.block(0x01, 0), &body[9..]);
        Ok(frame)
    }
}

/// `bytes` as the frame payloads that carry it: one on [`PORT_STREAM`] where it
/// fits, else fragments on [`PORT_FRAGMENT`], each flagged first, last, both
/// or neither.
#[must_use]
pub fn payloads(bytes: &[u8]) -> Vec<(u8, Vec<u8>)> {
    if bytes.len() <= MAX_FRM_PAYLOAD {
        return vec![(PORT_STREAM, bytes.to_vec())];
    }
    let count = bytes.len().div_ceil(MAX_FRAGMENT);
    bytes
        .chunks(MAX_FRAGMENT)
        .enumerate()
        .map(|(index, chunk)| {
            let flags =
                if index == 0 { FIRST } else { 0 } | if index + 1 == count { LAST } else { 0 };
            let mut out = Vec::with_capacity(chunk.len() + 1);
            out.push(flags);
            out.extend_from_slice(chunk);
            (PORT_FRAGMENT, out)
        })
        .collect()
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
        assert!(Frame::open(&bytes[..12], &keys(), 0).is_err(), "cut off");
        let mut bad = bytes.clone();
        bad[bytes.len() - 1] ^= 1;
        assert!(Frame::open(&bad, &keys(), 0).is_err(), "MIC");
        let mut join = bytes.clone();
        join[0] = 0x00;
        assert!(Frame::open(&join, &keys(), 0).is_err(), "a join request");
        let mut options = bytes;
        options[5] |= 2;
        assert!(Frame::open(&options, &keys(), 0).is_err(), "frame options");
        assert!(Frame::new(MType::UnconfirmedUp, 1, 0, 1, &[0; 223]).is_err());
        assert!(Frame::new(MType::UnconfirmedUp, 1, 0, 1, &[0; 222]).is_ok());
    }

    #[test]
    fn a_stream_travels_whole_where_it_fits_and_in_flagged_fragments_beyond() {
        let short = payloads(&[7; 222]);
        assert_eq!(short, vec![(PORT_STREAM, vec![7; 222])]);
        assert_eq!(payloads(&[]), vec![(PORT_STREAM, Vec::new())]);
        let long: Vec<u8> = (0..500u32)
            .map(|n| u8::try_from(n % 256).unwrap_or(0))
            .collect();
        let fragments = payloads(&long);
        assert_eq!(fragments.len(), 3);
        assert_eq!(fragments[0].0, PORT_FRAGMENT);
        assert_eq!(fragments[0].1[0], FIRST);
        assert_eq!(fragments[1].1[0], 0);
        assert_eq!(fragments[2].1[0], LAST);
        assert_eq!(fragments[2].1.len(), 1 + 500 - 2 * MAX_FRAGMENT);
        let joined: Vec<u8> = fragments
            .iter()
            .flat_map(|(_, f)| f[1..].to_vec())
            .collect();
        assert_eq!(joined, long);
        assert!(MType::ConfirmedDown.is_confirmed() && !MType::ConfirmedDown.is_uplink());
    }
}
