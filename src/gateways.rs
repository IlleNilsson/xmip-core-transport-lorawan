//! Where the gateways pointed at a node reach it: one UDP socket, the
//! network server's end of Semtech's packet forwarder protocol
//! (`datagram.rs`). Each `PUSH_DATA` is answered `PUSH_ACK` as it is read,
//! and each packet in it with a good CRC kept for the device its frame
//! names, where a Location of that device listens; each `PULL_DATA` is
//! answered `PULL_ACK`, and where it came from is the way down to its
//! gateway; a downlink goes that way in a `PULL_RESP`, and the gateway's
//! `TX_ACK` says whether it took it.
//!
//! The Locations of a node naming one address share it
//! (`transport::sharing`), as a gateway sends to one address whichever
//! device it hears: one socket, and one of them reading it at a time,
//! keeping what it read for the others and waking them, which wait
//! meanwhile (`xcore::wake`). Bound where a Receive Location opens, as
//! every listener is (*Bind at open*), and otherwise as a Send Location
//! first sends: it then waits for its gateway's next `PULL_DATA`.

use std::collections::{BTreeMap, VecDeque};
use std::net::{SocketAddr, UdpSocket};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU16, Ordering};

use transport::error::{Result, TransportError};
use transport::kept::Kept;
use xcore::lock::Locked;
use xcore::wake::Wake;

use crate::datagram::{self, Datagram, Eui};
use crate::deadline::Deadline;
use crate::frame;
use crate::packet::{self, Rxpk, Txpk};

/// The uplinks kept for one device before the oldest is let go: a
/// Location that stopped taking them holds no more than this.
const KEPT: usize = 1024;

/// A packet a gateway heard, kept for the device its frame names.
#[derive(Clone, Debug)]
pub struct Uplink {
    /// The gateway that heard it, which an answer in the device's receive
    /// window goes through.
    pub gateway: Eui,
    pub rxpk: Rxpk,
}

/// What the gateways said, as the socket's reader keeps it.
#[derive(Debug, Default)]
struct Said {
    /// One Location reads the socket; the others wait to be woken.
    reading: bool,
    /// Where each gateway's `PULL_DATA` came from: its way down.
    routes: BTreeMap<Eui, SocketAddr>,
    /// The gateway that asked for downlinks last.
    pulled: Option<Eui>,
    /// The uplinks of each device a Location of this node listens for.
    devices: BTreeMap<u32, VecDeque<Uplink>>,
    /// The gateway that heard each device last.
    heard_by: BTreeMap<u32, Eui>,
    /// The `PULL_RESP`s sent, by token, until their `TX_ACK` is taken.
    answers: BTreeMap<u16, Pending>,
}

/// One `PULL_RESP` sent, and what its gateway said of it.
#[derive(Debug)]
struct Pending {
    gateway: Eui,
    /// Sent again the new way where the gateway asks from another address
    /// before it answered: a packet forwarder that started again.
    resp: Datagram,
    answer: Answer,
}

/// What a gateway said of one `PULL_RESP`.
#[derive(Debug, PartialEq, Eq)]
enum Answer {
    /// Its `TX_ACK` has not come.
    Waiting,
    /// It took the packet.
    Taken,
    /// It refused the packet, saying why: `TOO_LATE`, `COLLISION_PACKET`.
    Refused(String),
}

impl Said {
    /// The way down to `gateway`, or to the one that asked last.
    fn route(&self, gateway: Option<Eui>) -> Option<(Eui, SocketAddr)> {
        let gateway = gateway.or(self.pulled)?;
        self.routes.get(&gateway).map(|peer| (gateway, *peer))
    }
}

/// The gateways one address of a node hears.
#[derive(Debug)]
pub struct Gateways {
    bind: String,
    socket: Kept<UdpSocket>,
    said: Mutex<Said>,
    woken: Wake,
    tokens: AtomicU16,
}

impl Gateways {
    /// The gateways pointed at `bind`, a host and port; nothing bound yet.
    #[must_use]
    pub fn new(bind: &str) -> Self {
        Self {
            bind: bind.to_string(),
            socket: Kept::new(),
            said: Mutex::new(Said::default()),
            woken: Wake::new(),
            tokens: AtomicU16::new(1),
        }
    }

    /// Where it listens, as the Location named it.
    #[must_use]
    pub fn bind(&self) -> &str {
        &self.bind
    }

    fn bound(&self) -> Result<&UdpSocket> {
        self.socket
            .bound(|| transport::socket::bind_udp(&self.bind, None))
    }

    /// Bind the socket where it is not yet, and say where it is bound.
    ///
    /// # Errors
    /// Where the address is taken or not this machine's.
    pub fn listening(&self) -> Result<Option<&str>> {
        self.bound()?;
        Ok(self.socket.address())
    }

    /// Keep what the gateways hear of `dev_addr` from now on.
    pub fn expecting(&self, dev_addr: u32) {
        self.said.locked().devices.entry(dev_addr).or_default();
    }

    /// The gateway that heard `dev_addr` last, where one has.
    #[must_use]
    pub fn heard_by(&self, dev_addr: u32) -> Option<Eui> {
        self.said.locked().heard_by.get(&dev_addr).copied()
    }

    /// The next uplink of `dev_addr`, kept since [`Gateways::expecting`],
    /// or `None` where none comes before `until`.
    ///
    /// # Errors
    /// Where the socket could not be bound or read.
    pub fn uplink(&self, dev_addr: u32, until: &Deadline) -> Result<Option<Uplink>> {
        self.expecting(dev_addr);
        self.until(until, |heard| heard.devices.get_mut(&dev_addr)?.pop_front())
    }

    /// `txpk` sent through `gateway`, or through the one that asked for
    /// downlinks last, once its way down is known, and its `TX_ACK` waited
    /// for, all before `until`.
    ///
    /// # Errors
    /// Retryable where no gateway asked for downlinks in time, its
    /// `TX_ACK` did not come, or it refused the packet, naming why.
    pub fn transmit(&self, gateway: Option<Eui>, txpk: &Txpk, until: &Deadline) -> Result<()> {
        let (gateway, peer) = self
            .until(until, |heard| heard.route(gateway))?
            .ok_or_else(|| {
                TransportError::retryable(format!(
                    "{}: no gateway asked for downlinks in time — a packet forwarder asks each \
                     keepalive_interval",
                    self.bind
                ))
            })?;
        let token = self.tokens.fetch_add(1, Ordering::Relaxed);
        let resp = Datagram::PullResp {
            token,
            json: txpk.written(),
        };
        let socket = self.bound()?;
        // Kept before it is sent, so a TX_ACK read on another Location's
        // thread the moment it comes finds what it answers.
        let pending = Pending {
            gateway,
            resp: resp.clone(),
            answer: Answer::Waiting,
        };
        self.said.locked().answers.insert(token, pending);
        let answered = datagram::sent(socket, &resp, peer).and_then(|()| {
            self.until(until, |heard| match heard.answers.get(&token)?.answer {
                Answer::Waiting => None,
                Answer::Taken | Answer::Refused(_) => heard.answers.remove(&token),
            })
        });
        self.said.locked().answers.remove(&token);
        let shown = datagram::shown(&gateway);
        match answered?.map(|pending| pending.answer) {
            Some(Answer::Taken) => Ok(()),
            Some(Answer::Refused(error)) => Err(TransportError::retryable(format!(
                "gateway {shown} refused the downlink: {error}"
            ))),
            Some(Answer::Waiting) | None => Err(TransportError::retryable(format!(
                "gateway {shown} sent no TX_ACK for the downlink in time"
            ))),
        }
    }

    /// What `found` finds in what the gateways said, reading the socket
    /// until it finds it or `until` comes: one reader at a time, the rest
    /// woken as each datagram is taken in.
    fn until<T>(
        &self,
        until: &Deadline,
        mut found: impl FnMut(&mut Said) -> Option<T>,
    ) -> Result<Option<T>> {
        let socket = self.bound()?;
        let mut heard = self.said.locked();
        loop {
            if let Some(found) = found(&mut heard) {
                return Ok(Some(found));
            }
            if until.passed() {
                return Ok(None);
            }
            if heard.reading {
                heard = self.woken.wait_timeout(&self.said, heard, until.left()).0;
                continue;
            }
            heard.reading = true;
            drop(heard);
            let read = datagram::received(socket, until);
            heard = self.said.locked();
            heard.reading = false;
            let taken = match read {
                Ok(Some((bytes, peer))) => Self::taken_in(&mut heard, socket, &bytes, peer),
                Ok(None) => Ok(()),
                Err(error) => Err(error),
            };
            self.woken.notify_all();
            taken?;
        }
    }

    /// One datagram from `peer` taken into `heard`, answered as the
    /// protocol answers it. What is not the protocol's, or no gateway's to
    /// send, is read past: a stray datagram is no Location's failure.
    fn taken_in(
        heard: &mut Said,
        socket: &UdpSocket,
        bytes: &[u8],
        peer: SocketAddr,
    ) -> Result<()> {
        match Datagram::decode(bytes) {
            Ok(Datagram::PushData {
                token,
                gateway,
                json,
            }) => {
                datagram::sent(socket, &Datagram::PushAck { token }, peer)?;
                for rxpk in packet::heard(&json).unwrap_or_default() {
                    let Some(dev_addr) = frame::dev_addr_of(&rxpk.data).filter(|_| rxpk.whole())
                    else {
                        continue;
                    };
                    let Some(kept) = heard.devices.get_mut(&dev_addr) else {
                        continue;
                    };
                    if kept.len() == KEPT {
                        kept.pop_front();
                    }
                    kept.push_back(Uplink { gateway, rxpk });
                    heard.heard_by.insert(dev_addr, gateway);
                }
                Ok(())
            }
            Ok(Datagram::PullData { token, gateway }) => {
                let moved = heard
                    .routes
                    .insert(gateway, peer)
                    .is_some_and(|was| was != peer);
                heard.pulled = Some(gateway);
                datagram::sent(socket, &Datagram::PullAck { token }, peer)?;
                let mut again = heard.answers.values().filter(|pending| {
                    moved && pending.gateway == gateway && pending.answer == Answer::Waiting
                });
                again.try_for_each(|pending| datagram::sent(socket, &pending.resp, peer))
            }
            Ok(Datagram::TxAck { token, json, .. }) => {
                if let Some(Pending { answer, .. }) = heard.answers.get_mut(&token) {
                    *answer = match packet::refusal(&json) {
                        Ok(None) => Answer::Taken,
                        Ok(Some(error)) => Answer::Refused(error),
                        Err(error) => Answer::Refused(error.message),
                    };
                }
                Ok(())
            }
            Ok(_) | Err(_) => Ok(()),
        }
    }
}
