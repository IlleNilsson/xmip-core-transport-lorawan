//! A gateway's packet forwarder, as Semtech's speaks to its network server
//! over UDP (`datagram.rs`): the air a device hears where no concentrator
//! is, a [`Radio`]. What the device sends up goes in a `PUSH_DATA`, which
//! the server answers `PUSH_ACK`; a `PULL_DATA` as it starts and again each
//! keepalive keeps the way down open, answered `PULL_ACK`; and what the
//! server sends down comes in a `PULL_RESP`, answered `TX_ACK`. A frame is
//! forwarded as it is sent and a downlink handed to the device as it comes,
//! whatever moment its `tmst` names: there is no air to wait for.

use std::collections::VecDeque;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use transport::error::{Result, TransportError, classify, protocol_error};
use xcore::clock::between;
use xcore::lock::Locked;
use xcore::{Clock, SystemClock};

use crate::datagram::{self, Datagram, Eui};
use crate::deadline::Deadline;
use crate::packet::{self, Rxpk, Txpk};
use crate::radio::Radio;

/// How often a packet forwarder asks for downlinks unless told otherwise:
/// Semtech's `keepalive_interval`, ten seconds as it ships.
pub const KEEPALIVE: Duration = Duration::from_secs(10);

/// The channel a device's frame is heard on: EU868's first, 868.1 MHz.
const HEARD_ON: f64 = 868.1;
/// The data rate it is heard at: EU868's DR5, whose frame carries the most.
const HEARD_AT: &str = "SF7BW125";

/// One gateway pointed at one network server.
pub struct Forwarder {
    socket: UdpSocket,
    server: SocketAddr,
    named: String,
    gateway: Eui,
    /// The operating system's clock, which a gateway's concentrator runs on.
    clock: Arc<dyn Clock>,
    /// What the concentrator's clock, `tmst`, counts microseconds from: a
    /// reading of `clock`.
    started: i128,
    tokens: AtomicU16,
    keepalive: Duration,
    /// How long an answer of the server's is waited on.
    wait: Duration,
    /// When the last `PULL_DATA` went, a reading of `clock`.
    pulled: Mutex<i128>,
    /// Downlinks that came while a `PUSH_ACK` was waited on, for the next
    /// receive.
    held: Mutex<VecDeque<Vec<u8>>>,
}

impl Forwarder {
    /// The gateway `gateway` pointed at the network server at `server`,
    /// waiting `wait` for each of its answers, and asking it for downlinks
    /// at once, as a packet forwarder does as it starts. Its socket is on
    /// loopback where the server is, so a test's gateway listens on
    /// nothing outside the machine.
    ///
    /// # Errors
    /// Where `server` is no address, or the gateway's socket could not be
    /// bound or send.
    pub fn pointed_at(server: &str, gateway: Eui, wait: Duration) -> Result<Self> {
        let address = server
            .to_socket_addrs()
            .map_err(|e| classify("naming the network server", &e))?
            .next()
            .ok_or_else(|| protocol_error(format!("{server}: no address")))?;
        let local = match (address.is_ipv4(), address.ip().is_loopback()) {
            (true, true) => "127.0.0.1:0",
            (true, false) => "0.0.0.0:0",
            (false, true) => "[::1]:0",
            (false, false) => "[::]:0",
        };
        let (socket, _) = transport::socket::bind_udp(local, None)?;
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let now = clock.monotonic_nanos();
        let forwarder = Self {
            socket,
            server: address,
            named: server.to_string(),
            gateway,
            clock,
            started: now,
            tokens: AtomicU16::new(1),
            keepalive: KEEPALIVE,
            wait,
            pulled: Mutex::new(now),
            held: Mutex::new(VecDeque::new()),
        };
        forwarder.pull()?;
        Ok(forwarder)
    }

    /// Asking for downlinks every `every` in place of [`KEEPALIVE`].
    #[must_use]
    pub const fn keeping_alive(mut self, every: Duration) -> Self {
        self.keepalive = every;
        self
    }

    fn token(&self) -> u16 {
        self.tokens.fetch_add(1, Ordering::Relaxed)
    }

    /// The concentrator's clock: microseconds since it started, as the
    /// protocol's 32 bits hold them, wrapping.
    fn tmst(&self) -> u32 {
        let since = between(self.started, self.clock.monotonic_nanos());
        let micros = since.as_micros() % (u128::from(u32::MAX) + 1);
        u32::try_from(micros).unwrap_or(0)
    }

    fn send(&self, datagram: &Datagram) -> Result<()> {
        datagram::sent(&self.socket, datagram, self.server)
    }

    /// A `PULL_DATA`, and when it went.
    fn pull(&self) -> Result<()> {
        let pull = Datagram::PullData {
            token: self.token(),
            gateway: self.gateway,
        };
        self.send(&pull)?;
        *self.pulled.locked() = self.clock.monotonic_nanos();
        Ok(())
    }

    /// The next datagram from the server before `until`, or `None`; what
    /// another peer sends, or what is not the protocol's, is read past.
    fn next(&self, until: &Deadline) -> Result<Option<Datagram>> {
        while let Some((bytes, peer)) = datagram::received(&self.socket, until)? {
            if peer == self.server
                && let Ok(datagram) = Datagram::decode(&bytes)
            {
                return Ok(Some(datagram));
            }
        }
        Ok(None)
    }

    /// What a `PULL_RESP` carried down, answered `TX_ACK` as taken.
    fn delivered(&self, token: u16, json: &[u8]) -> Result<Vec<u8>> {
        let txpk = Txpk::read(json)?;
        self.send(&Datagram::TxAck {
            token,
            gateway: self.gateway,
            json: packet::taken(),
        })?;
        Ok(txpk.data)
    }
}

impl Radio for Forwarder {
    /// The network server it points at.
    fn name(&self) -> &str {
        &self.named
    }

    /// The frame in a `PUSH_DATA`, sent once its `PUSH_ACK` comes.
    fn transmit(&self, frame: &[u8]) -> Result<()> {
        let token = self.token();
        let heard = Rxpk::lora(self.tmst(), HEARD_ON, HEARD_AT, frame);
        self.send(&Datagram::PushData {
            token,
            gateway: self.gateway,
            json: packet::pushed(&[heard]),
        })?;
        let until = Deadline::after(&self.clock, self.wait);
        while let Some(datagram) = self.next(&until)? {
            match datagram {
                Datagram::PushAck { token: acked } if acked == token => return Ok(()),
                Datagram::PullResp { token, json } => {
                    let data = self.delivered(token, &json)?;
                    self.held.locked().push_back(data);
                }
                _ => {}
            }
        }
        Err(TransportError::retryable(format!(
            "{}: no PUSH_ACK for the frame within {:?}",
            self.named, self.wait
        )))
    }

    /// The next `PULL_RESP`'s frame, asking again each keepalive.
    fn receive(&self, timeout: Duration) -> Result<Option<Vec<u8>>> {
        if let Some(data) = self.held.locked().pop_front() {
            return Ok(Some(data));
        }
        let until = Deadline::after(&self.clock, timeout);
        loop {
            let since = between(*self.pulled.locked(), self.clock.monotonic_nanos());
            let Some(due) = self
                .keepalive
                .checked_sub(since)
                .filter(|due| !due.is_zero())
            else {
                self.pull()?;
                continue;
            };
            match self.next(&until.within(due))? {
                Some(Datagram::PullResp { token, json }) => {
                    return self.delivered(token, &json).map(Some);
                }
                None if until.passed() => return Ok(None),
                Some(_) | None => {}
            }
        }
    }
}
