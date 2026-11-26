//! What a Location of this technology is configured with: its declaration,
//! which `Configured` reads, built with the crate's `declaration` feature
//! alone and the code behind the default (ADR-0064, amendments 2026-10-22
//! and 2026-11-26), for the library the surfaces load to carry (open
//! problem 48). It is the same wherever it is built, a box with no
//! concentrator included: a Location's settings are suggested and checked
//! wherever it is designed.

use std::time::Duration;

use xcore::settings::{Applies, Kind, Presence, Setting, Settings};

/// How long the receive windows are waited on before they close empty
/// unless a Location says.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Every setting a Location takes beyond its address, the radio the device
/// is heard through, a concentrator: the device's session and how it sends.
/// The session keys are secrets and come through the Location's
/// `credentials`, never a setting.
pub const SETTINGS: &Settings = &Settings {
    technology: env!("CARGO_PKG_NAME"),
    settings: &[
        Setting {
            name: "dev_addr",
            kind: Kind::Integer {
                minimum: 0,
                maximum: u32::MAX as i64,
            },
            presence: Presence::Required,
            meaning: "The device address the network gave this device's session.",
            applies: Applies::Both,
        },
        Setting {
            name: "confirmed",
            kind: Kind::Boolean,
            presence: Presence::Optional,
            meaning: "Whether every frame up waits for its acknowledgement down.",
            applies: Applies::Send,
        },
        transport::configured::timeout(
            Applies::Both,
            Some(DEFAULT_TIMEOUT),
            "How long the receive windows are waited on before they close empty.",
        ),
    ],
};

/// The schemes a Location's address is entered with to choose this technology.
pub const SCHEMES: &[&str] = &["lorawan"];
