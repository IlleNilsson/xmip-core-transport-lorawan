//! When a wait of this technology ends — for an uplink, a gateway's way
//! down, its `TX_ACK`, a server's `PUSH_ACK` — counted on the monotonic
//! reading of the Clock it was handed (ADR-0068, amendment 2026-11-15), so
//! a node's Locations wait by the node's Clock and no wait here reads std's
//! `Instant` of its own.

use std::sync::Arc;
use std::time::Duration;

use xcore::Clock;
use xcore::clock::{between, nanos};

/// A moment on one Clock's monotonic reading.
#[derive(Clone)]
pub struct Deadline {
    clock: Arc<dyn Clock>,
    at: i128,
}

impl Deadline {
    /// `span` from now, on `clock`.
    #[must_use]
    pub fn after(clock: &Arc<dyn Clock>, span: Duration) -> Self {
        Self {
            clock: Arc::clone(clock),
            at: clock.monotonic_nanos().saturating_add(nanos(span)),
        }
    }

    /// What is left of it: nothing once it passed.
    #[must_use]
    pub fn left(&self) -> Duration {
        between(self.clock.monotonic_nanos(), self.at)
    }

    /// Whether it passed.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.left().is_zero()
    }

    /// The sooner of it and `span` from now.
    #[must_use]
    pub fn within(&self, span: Duration) -> Self {
        let at = self.clock.monotonic_nanos().saturating_add(nanos(span));
        Self {
            clock: Arc::clone(&self.clock),
            at: at.min(self.at),
        }
    }

    /// The Clock it is counted on.
    #[must_use]
    pub const fn clock(&self) -> &Arc<dyn Clock> {
        &self.clock
    }
}

impl std::fmt::Debug for Deadline {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Deadline")
            .field("at", &self.at)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xcore::clock::Stepped;

    #[test]
    fn a_deadline_passes_as_its_clock_is_stepped_past_it() {
        let stepped = Arc::new(Stepped::at(0));
        let clock: Arc<dyn Clock> = Arc::clone(&stepped) as Arc<dyn Clock>;
        let due = Deadline::after(&clock, Duration::from_secs(5));
        assert_eq!(due.left(), Duration::from_secs(5));
        let sooner = due.within(Duration::from_secs(2));
        assert_eq!(sooner.left(), Duration::from_secs(2));
        assert_eq!(
            due.within(Duration::from_secs(9)).left(),
            Duration::from_secs(5)
        );
        stepped.pass(Duration::from_secs(3));
        assert!(sooner.passed() && !due.passed());
        stepped.pass(Duration::from_secs(2));
        assert!(due.passed() && due.left().is_zero());
    }
}
