//! The datagrams a gateway and its network server exchange over UDP, as
//! Semtech's packet forwarder speaks them: protocol version 2, which
//! `PROTOCOL.TXT` in Lora-net/packet_forwarder describes since its revision
//! 1.3, which added `TX_ACK`, and `PROTOCOL.md` in Lora-net/sx1302_hal
//! still describes, at its revision 1.6. Each opens with the version, a
//! random token its answer echoes, and its identifier; a gateway's own
//! datagrams name it by its unique identifier, eight bytes, and those that
//! carry JSON carry it after their header (`packet.rs`).
//!
//! | Identifier | Datagram | Sent by | After the token |
//! | --- | --- | --- | --- |
//! | 0x00 | `PUSH_DATA` | the gateway | its identifier, JSON: `rxpk`, `stat` |
//! | 0x01 | `PUSH_ACK` | the server | nothing |
//! | 0x02 | `PULL_DATA` | the gateway | its identifier |
//! | 0x03 | `PULL_RESP` | the server | JSON: `txpk` |
//! | 0x04 | `PULL_ACK` | the server | nothing |
//! | 0x05 | `TX_ACK` | the gateway | its identifier, JSON: `txpk_ack`, or none |
//!
//! Both ends are written here once: the network server a node is, behind
//! its gateways (`gateways.rs`), and the packet forwarder that stands in for
//! a gateway where none is (`forwarder.rs`).

use std::io::ErrorKind;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use transport::error::{Result, classify, protocol_error};

use crate::deadline::Deadline;

/// The protocol version every datagram opens with.
pub const VERSION: u8 = 2;

/// A gateway's unique identifier, its EUI-64, as the datagram carries it.
pub type Eui = [u8; 8];

const PUSH_DATA: u8 = 0x00;
const PUSH_ACK: u8 = 0x01;
const PULL_DATA: u8 = 0x02;
const PULL_RESP: u8 = 0x03;
const PULL_ACK: u8 = 0x04;
const TX_ACK: u8 = 0x05;

/// The version, the token and the identifier.
const HEADER: usize = 4;
/// The header and a gateway's identifier.
const NAMED: usize = HEADER + 8;
/// The most a datagram holds: one UDP payload over IPv4 (RFC 768, RFC 791).
const MAX_DATAGRAM: usize = 65_507;

/// One datagram, the JSON it carries as its bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Datagram {
    /// What the gateway heard: `rxpk`, and its `stat`.
    PushData {
        token: u16,
        gateway: Eui,
        json: Vec<u8>,
    },
    /// The server took a `PUSH_DATA`.
    PushAck { token: u16 },
    /// The gateway asks for what to send, keeping its way down open.
    PullData { token: u16, gateway: Eui },
    /// What the gateway is to send: `txpk`.
    PullResp { token: u16, json: Vec<u8> },
    /// The server heard a `PULL_DATA`.
    PullAck { token: u16 },
    /// Whether the gateway took a `PULL_RESP`: `txpk_ack`, or nothing where
    /// it took it.
    TxAck {
        token: u16,
        gateway: Eui,
        json: Vec<u8>,
    },
}

impl Datagram {
    /// The datagram as UDP carries it.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let (token, identifier, gateway, json): (u16, u8, Option<&Eui>, &[u8]) = match self {
            Self::PushData {
                token,
                gateway,
                json,
            } => (*token, PUSH_DATA, Some(gateway), json),
            Self::PushAck { token } => (*token, PUSH_ACK, None, &[]),
            Self::PullData { token, gateway } => (*token, PULL_DATA, Some(gateway), &[]),
            Self::PullResp { token, json } => (*token, PULL_RESP, None, json),
            Self::PullAck { token } => (*token, PULL_ACK, None, &[]),
            Self::TxAck {
                token,
                gateway,
                json,
            } => (*token, TX_ACK, Some(gateway), json),
        };
        let [high, low] = token.to_be_bytes();
        let mut out = Vec::with_capacity(NAMED + json.len());
        out.extend_from_slice(&[VERSION, high, low, identifier]);
        out.extend_from_slice(gateway.map_or(&[][..], |eui| &eui[..]));
        out.extend_from_slice(json);
        out
    }

    /// The datagram `bytes` are.
    ///
    /// # Errors
    /// Another version, an identifier the protocol does not have, or a
    /// datagram cut off before the gateway it names.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let [version, high, low, identifier, ..] = *bytes else {
            return Err(protocol_error("a datagram shorter than its header"));
        };
        if version != VERSION {
            return Err(protocol_error(format!(
                "a packet forwarder speaking version {version}; Xmip speaks version {VERSION}"
            )));
        }
        let token = u16::from_be_bytes([high, low]);
        let named = || -> Result<(Eui, Vec<u8>)> {
            let gateway = bytes
                .get(HEADER..NAMED)
                .and_then(|eui| Eui::try_from(eui).ok())
                .ok_or_else(|| protocol_error("a datagram cut off before its gateway"))?;
            Ok((gateway, bytes[NAMED..].to_vec()))
        };
        Ok(match identifier {
            PUSH_DATA => {
                let (gateway, json) = named()?;
                Self::PushData {
                    token,
                    gateway,
                    json,
                }
            }
            PUSH_ACK => Self::PushAck { token },
            PULL_DATA => Self::PullData {
                token,
                gateway: named()?.0,
            },
            PULL_RESP => Self::PullResp {
                token,
                json: bytes[HEADER..].to_vec(),
            },
            PULL_ACK => Self::PullAck { token },
            TX_ACK => {
                let (gateway, json) = named()?;
                Self::TxAck {
                    token,
                    gateway,
                    json,
                }
            }
            other => {
                return Err(protocol_error(format!(
                    "a datagram identifier the protocol does not have: {other:#04x}"
                )));
            }
        })
    }
}

/// A gateway's identifier as a network server shows it: sixteen
/// hexadecimal digits, most significant first.
#[must_use]
pub fn shown(gateway: &Eui) -> String {
    codec::hex::encode(gateway)
}

/// `datagram` sent to `peer` from `socket`.
///
/// # Errors
/// Where the socket refused it.
pub fn sent(socket: &UdpSocket, datagram: &Datagram, peer: SocketAddr) -> Result<()> {
    socket
        .send_to(&datagram.encode(), peer)
        .map(drop)
        .map_err(|e| classify("sending to a packet forwarder's peer", &e))
}

/// The next datagram `socket` reads before `until`, with where it came
/// from, or `None` where none came. A peer that went away is not this
/// socket's failure: Windows reads its ICMP message as a reset of the
/// next read, Linux as a refusal, and each is read past.
///
/// # Errors
/// Where the socket could not be read.
pub fn received(socket: &UdpSocket, until: &Deadline) -> Result<Option<(Vec<u8>, SocketAddr)>> {
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    loop {
        let left = until.left();
        if left.is_zero() {
            return Ok(None);
        }
        // A read timeout of zero is refused: a microsecond is the least.
        socket
            .set_read_timeout(Some(left.max(Duration::from_micros(1))))
            .map_err(|e| classify("setting the read timeout", &e))?;
        match socket.recv_from(&mut buffer) {
            Ok((read, peer)) => {
                buffer.truncate(read);
                return Ok(Some((buffer, peer)));
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::ConnectionReset | ErrorKind::ConnectionRefused
                ) => {}
            Err(e) => return Err(classify("reading a packet forwarder's datagram", &e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GATEWAY: Eui = [0xaa, 0x55, 0x5a, 0, 0, 0, 0, 0];

    #[test]
    fn every_datagram_is_written_as_the_protocol_lays_it_out_and_read_back() {
        let push = Datagram::PushData {
            token: 0x1234,
            gateway: GATEWAY,
            json: br#"{"rxpk":[]}"#.to_vec(),
        };
        let bytes = push.encode();
        assert_eq!(
            &bytes[..4],
            &[2, 0x12, 0x34, 0x00],
            "version, token, PUSH_DATA"
        );
        assert_eq!(&bytes[4..12], &GATEWAY, "the gateway");
        assert_eq!(&bytes[12..], br#"{"rxpk":[]}"#, "the JSON after it");
        let pull = Datagram::PullData {
            token: 7,
            gateway: GATEWAY,
        };
        assert_eq!(pull.encode().len(), 12);
        let resp = Datagram::PullResp {
            token: 9,
            json: br#"{"txpk":{}}"#.to_vec(),
        };
        assert_eq!(
            &resp.encode()[3..5],
            &[0x03, b'{'],
            "the JSON after the header"
        );
        for datagram in [
            push,
            Datagram::PushAck { token: 1 },
            pull,
            resp,
            Datagram::PullAck { token: 2 },
            Datagram::TxAck {
                token: 3,
                gateway: GATEWAY,
                json: Vec::new(),
            },
        ] {
            assert_eq!(
                Datagram::decode(&datagram.encode()).expect("read"),
                datagram
            );
        }
        assert_eq!(shown(&GATEWAY), "aa555a0000000000");
    }

    #[test]
    fn what_is_not_this_protocol_is_refused() {
        let version = Datagram::decode(&[1, 0, 0, 0]).expect_err("version 1");
        assert!(version.message.contains("version 1"), "{version}");
        assert!(Datagram::decode(&[2, 0, 0]).is_err(), "no identifier");
        assert!(
            Datagram::decode(&[2, 0, 0, 0x06]).is_err(),
            "no such identifier"
        );
        let cut = Datagram::decode(&[2, 0, 0, PULL_DATA, 1, 2]).expect_err("cut");
        assert!(cut.message.contains("gateway"), "{cut}");
    }

    #[test]
    fn a_read_ends_at_its_due_time_and_takes_what_comes_before() {
        let clock: std::sync::Arc<dyn xcore::Clock> = std::sync::Arc::new(xcore::SystemClock);
        let (socket, address) = transport::socket::bind_udp("127.0.0.1:0", None).expect("bind");
        let quiet = received(&socket, &Deadline::after(&clock, Duration::from_millis(20)));
        assert!(quiet.expect("read").is_none(), "nothing came");
        let peer = UdpSocket::bind("127.0.0.1:0").expect("peer");
        peer.send_to(&Datagram::PullAck { token: 5 }.encode(), &address)
            .expect("sent");
        let (bytes, from) = received(&socket, &Deadline::after(&clock, Duration::from_secs(2)))
            .expect("read")
            .expect("one");
        assert_eq!(
            Datagram::decode(&bytes).expect("read"),
            Datagram::PullAck { token: 5 }
        );
        assert_eq!(from, peer.local_addr().expect("its address"));
    }
}
