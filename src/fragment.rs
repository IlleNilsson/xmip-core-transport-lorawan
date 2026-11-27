//! A Stream longer than one frame carries travels as fragments on a port
//! of its own, and is put back together where it arrives: by the network
//! server going up, by the device coming down, through the one
//! [`Reassembly`].

use transport::error::{Result, protocol_error};

use crate::frame::MAX_FRM_PAYLOAD;

/// A frame on this port carries nothing of a Stream: MAC commands, which
/// this crate answers none of, or no payload, a bare acknowledgement.
pub const PORT_COMMANDS: u8 = 0;
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
const MAX_FRAGMENT: usize = MAX_FRM_PAYLOAD - 1;

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

/// The fragments of one Stream come so far.
#[derive(Debug, Default)]
pub struct Reassembly {
    arriving: Vec<u8>,
}

impl Reassembly {
    /// Nothing come yet.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            arriving: Vec::new(),
        }
    }

    /// What a frame on `port` carrying `payload` makes of its Stream: the
    /// Stream whole where it fits the frame or the frame is its last
    /// fragment, and `None` while fragments are still to come or the frame
    /// carries no Stream.
    ///
    /// # Errors
    /// A fragment without its flags, or a port this crate does not carry.
    pub fn arrived(&mut self, port: u8, payload: Vec<u8>) -> Result<Option<Vec<u8>>> {
        match port {
            PORT_COMMANDS => Ok(None),
            PORT_STREAM => Ok(Some(payload)),
            PORT_FRAGMENT => {
                let (flags, chunk) = payload
                    .split_first()
                    .ok_or_else(|| protocol_error("a fragment without its flags"))?;
                if flags & FIRST != 0 {
                    self.arriving.clear();
                }
                self.arriving.extend_from_slice(chunk);
                Ok((flags & LAST != 0).then(|| std::mem::take(&mut self.arriving)))
            }
            other => Err(protocol_error(format!(
                "port {other}, which nothing listens on"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let mut reassembly = Reassembly::default();
        let mut whole = None;
        for (port, payload) in fragments {
            assert!(whole.is_none(), "whole only at the last");
            whole = reassembly.arrived(port, payload).expect("fragment");
        }
        assert_eq!(whole, Some(long));
    }

    #[test]
    fn a_first_fragment_starts_again_and_what_is_no_stream_is_said() {
        let mut reassembly = Reassembly::default();
        assert_eq!(
            reassembly
                .arrived(PORT_FRAGMENT, vec![FIRST, 1, 2])
                .expect("first"),
            None
        );
        let again = reassembly.arrived(PORT_FRAGMENT, vec![FIRST | LAST, 3]);
        assert_eq!(again.expect("again"), Some(vec![3]), "the lost Stream left");
        assert_eq!(
            reassembly
                .arrived(PORT_COMMANDS, vec![0x02])
                .expect("commands"),
            None
        );
        assert_eq!(
            reassembly.arrived(PORT_STREAM, Vec::new()).expect("empty"),
            Some(Vec::new())
        );
        assert!(
            reassembly.arrived(PORT_FRAGMENT, Vec::new()).is_err(),
            "no flags"
        );
        assert!(reassembly.arrived(9, vec![1]).is_err(), "port 9");
    }
}
