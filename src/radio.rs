//! Where a device's frames go and come from: the [`Radio`], the air as one
//! device hears it. A gateway's packet forwarder speaking to its network
//! server over UDP is one (`forwarder.rs`), which every test and every far
//! end with no concentrator drives.

use std::time::Duration;

use transport::error::Result;

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
