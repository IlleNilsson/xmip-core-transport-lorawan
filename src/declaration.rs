//! What a Location of this technology is configured with: its declaration,
//! which `Configured` reads, built with the crate's `declaration` feature
//! alone and the code behind the default (ADR-0064, amendments 2026-10-22
//! and 2026-11-26), for the library the surfaces load to carry (open
//! problem 48). It is the same wherever it is built, a box with no
//! gateway in reach included: a Location's settings are suggested and
//! checked wherever it is designed.

use std::time::Duration;

use xcore::settings::{Applies, Fixed, Kind, Presence, Setting, Settings};

/// How long a receive waits for an uplink, and a send for its gateway's
/// answers, unless a Location says.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// The UDP port a Location's address listens on where it names none:
/// where the network servers a packet forwarder is pointed at listen, The
/// Things Stack's and `ChirpStack`'s gateway bridge, so a gateway set up for
/// either reaches a node with its server's address changed alone.
/// Semtech's packet forwarder ships `serv_port_up` and `serv_port_down` at
/// 1680, and `sx1302_hal`'s at 1730: a gateway's own file names the port it
/// sends to (ADR-0051, amendment 2026-11-27).
pub const PORT: u16 = 1700;

/// The frequency a downlink is sent on unless a Location says, in hertz:
/// EU868's second receive window, 869.525 MHz, where a Class C device
/// listens between its uplinks (`LoRaWAN` Regional Parameters, EU863-870).
pub const DEFAULT_FREQUENCY: i64 = 869_525_000;

/// The data rate a downlink is sent at unless a Location says: EU868's
/// second receive window's, DR0, spreading factor 12 over 125 kHz.
pub const DEFAULT_DATA_RATE: &str = "SF12BW125";

/// The data rates a gateway's concentrator sends `LoRa` at, as the packet
/// forwarder protocol writes them: a spreading factor and a bandwidth.
pub const DATA_RATES: &[&str] = &[
    "SF7BW125",
    "SF8BW125",
    "SF9BW125",
    "SF10BW125",
    "SF11BW125",
    "SF12BW125",
    "SF7BW250",
    "SF8BW250",
    "SF9BW250",
    "SF10BW250",
    "SF11BW250",
    "SF12BW250",
    "SF7BW500",
    "SF8BW500",
    "SF9BW500",
    "SF10BW500",
    "SF11BW500",
    "SF12BW500",
];

/// Every setting a Location takes beyond its address, where the node
/// listens for the gateways that point at it: the device whose session it
/// is the network server's side of, and how a downlink reaches it. The
/// session keys are secrets and come through the Location's `secret`,
/// never a setting.
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
            meaning: "Whether every Stream sent down waits for the device's acknowledgement up.",
            applies: Applies::Send,
        },
        Setting {
            name: "frequency",
            kind: Kind::Integer {
                minimum: 1,
                maximum: u32::MAX as i64,
            },
            presence: Presence::Default(Fixed::Integer(DEFAULT_FREQUENCY)),
            meaning: "The frequency in hertz a downlink is sent on, where the device listens.",
            applies: Applies::Send,
        },
        Setting {
            name: "data_rate",
            kind: Kind::Choice {
                choices: DATA_RATES,
            },
            presence: Presence::Default(Fixed::Text(DEFAULT_DATA_RATE)),
            meaning: "The spreading factor and bandwidth a downlink is sent at.",
            applies: Applies::Send,
        },
        transport::configured::timeout(
            Applies::Both,
            Some(DEFAULT_TIMEOUT),
            "How long a receive waits for an uplink, and a send for its gateway's answers.",
        ),
    ],
};

/// The schemes a Location's address is entered with to choose this technology.
pub const SCHEMES: &[&str] = &["lorawan"];
