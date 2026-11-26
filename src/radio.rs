//! Where a device's frames go and come from: the [`Radio`], the air as one
//! device hears it, and [`LoopbackRadio`], a gateway and network server
//! in-process, which every test and every box without a concentrator
//! drives.

use std::sync::Mutex;
use std::time::Duration;

use transport::error::Result;
use xcore::lock::Locked;

use crate::server::NetworkServer;

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
        self.server.locked()
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
