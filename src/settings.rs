//! What a `LoRaWAN` Location says beyond its address, declared once and read
//! through (ADR-0064, amendment 2026-09-26).

use std::sync::Arc;

use transport::Configured;
use transport::error::{Result, TransportError};
use xcore::settings::{Applies, Kind, Presence, Read, Setting, Settings};

use crate::{Device, Keys, LorawanTransport, Radio};

impl Configured for LorawanTransport {
    /// The address is the radio the device is heard through, a concentrator;
    /// the settings are the device's session and how it sends. The session
    /// keys are secrets and come through the Location's `credentials`.
    const SETTINGS: &'static Settings = &Settings {
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
            Setting {
                name: "timeout",
                kind: Kind::Duration,
                presence: Presence::Optional,
                meaning: "How long the receive windows are waited on before they close empty.",
                applies: Applies::Both,
            },
        ],
    };

    /// No radio is opened from an address yet: the only one is the loopback,
    /// and the session keys a device needs come through the Location's
    /// `credentials`, which this does not read.
    fn configured(address: &str, _settings: &Read) -> Result<Self> {
        Err(TransportError::permanent(format!(
            "{address}: this build drives no concentrator, only the loopback radio"
        )))
    }
}

impl LorawanTransport {
    /// The device with `keys` on `radio`, as the settings read say: what
    /// [`Configured::configured`] builds once a radio opens from an address
    /// and the keys come through the Location's `credentials`.
    #[must_use]
    pub fn on(radio: Arc<dyn Radio>, keys: Keys, settings: &Read) -> Self {
        // The declaration holds it within 32 bits.
        let dev_addr = u32::try_from(settings.integer("dev_addr")).unwrap_or(0);
        let mut transport = Self::new(radio, Arc::new(Device::new(dev_addr, keys)));
        if settings.optional_boolean("confirmed") == Some(true) {
            transport = transport.confirmed();
        }
        match settings.optional_duration("timeout") {
            Some(timeout) => transport.timing_out_after(timeout),
            None => transport,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{LoopbackRadio, NetworkServer};
    use std::time::Duration;
    use xcore::settings::Given;

    #[test]
    fn lorawan_declares_its_settings_and_reads_through_them() {
        let declared = LorawanTransport::SETTINGS;
        assert!(declared.problems().is_empty(), "{:?}", declared.problems());

        let given = [
            ("dev_addr".to_string(), Given::Integer(0x2601_1b2c)),
            ("confirmed".to_string(), Given::Boolean(true)),
            ("timeout".to_string(), Given::Text("3s".to_string())),
        ];
        let keys = Keys {
            nwk_s_key: [1; 16],
            app_s_key: [2; 16],
        };
        let radio = Arc::new(LoopbackRadio::new(NetworkServer::new(0x2601_1b2c, keys)));
        let read = declared.read(Applies::Send, &given).expect("read");
        let device = LorawanTransport::on(radio, keys, &read);
        assert_eq!(device.device.dev_addr, 0x2601_1b2c);
        assert!(device.confirmed);
        assert_eq!(device.timeout, Duration::from_secs(3));

        let Err(refused) = LorawanTransport::open("gateway", Applies::Receive, &given) else {
            panic!("a Receive Location sends nothing confirmed");
        };
        assert!(refused.message.contains("\"confirmed\""), "{refused}");
    }
}
