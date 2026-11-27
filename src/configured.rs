//! How a `LoRaWAN` Location is configured: `Configured`, reading what it
//! says beyond its address, which its [`declaration`](crate::declaration)
//! declares once (ADR-0064, amendments 2026-09-26 and 2026-11-26); the
//! gateways and the device's session the Locations of a node share
//! (`transport::sharing`); and the secret holding the session's keys.

use std::sync::{Arc, Mutex};

use transport::error::Result;
use transport::{Configured, Secured, Sharing};
use xcore::settings::{Read, Settings};

use crate::{Gateways, LorawanTransport, NetworkServer, declaration};

impl Configured for LorawanTransport {
    const SETTINGS: &'static Settings = declaration::SETTINGS;
    const SCHEMES: &'static [&'static str] = declaration::SCHEMES;

    fn timeout_kept(&mut self) -> Option<&mut dyn transport::configured::TimeoutKept> {
        Some(&mut self.timeout)
    }

    /// The network server's side of the device `dev_addr` names, behind the
    /// gateways pointed at `address`; nothing bound.
    fn configured(address: &str, settings: &Read) -> Result<Self> {
        // The declaration holds each within 32 bits.
        let dev_addr = u32::try_from(settings.integer("dev_addr")).unwrap_or(0);
        let mut transport = Self::listening_at(address, dev_addr);
        if settings.optional_boolean("confirmed") == Some(true) {
            transport = transport.confirmed();
        }
        if let Some(hertz) = settings.optional_integer("frequency") {
            transport.frequency = u32::try_from(hertz).unwrap_or(u32::MAX);
        }
        if let Some(rate) = settings.optional_text("data_rate") {
            transport.data_rate = rate.to_string();
        }
        Ok(transport)
    }

    /// The node's one socket for this address, and its one session for
    /// this device: a Receive Location and a Send Location of one device
    /// count its frames together, and every Location at the address reads
    /// the gateways through one socket.
    fn shared_by(mut self, sharing: &Arc<dyn Sharing>) -> Self {
        let bind = self.gateways.bind().to_string();
        let dev_addr = self.dev_addr;
        self.gateways = sharing.one(&bind, || Gateways::new(&bind));
        let session = format!("{bind} {dev_addr:08x}");
        self.session = sharing.one(&session, || Mutex::new(NetworkServer::new(dev_addr)));
        self
    }

    /// Its waits counted on its node's Clock (ADR-0068, amendment
    /// 2026-11-15).
    fn timed_by(mut self, clock: &Arc<dyn xcore::Clock>) -> Self {
        self.clock = Arc::clone(clock);
        self
    }

    /// The secret holding the session's keys, read as each Stream is sent
    /// and as each receive opens the first frame it takes.
    fn secured_by(mut self, secured: Secured) -> Result<Self> {
        self.secured = Some(secured);
        Ok(self)
    }

    /// The gateways' socket, bound as a Receive Location opens, its
    /// device's uplinks kept from then on.
    fn listening(&self) -> Result<Option<&str>> {
        self.gateways.expecting(self.dev_addr);
        self.gateways.listening()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Keys;
    use crate::declaration::{DEFAULT_DATA_RATE, DEFAULT_TIMEOUT, PORT};
    use std::time::Duration;
    use transport::secured::Kept;
    use transport::{Shared, Transport};
    use xcore::SecretKind;
    use xcore::settings::{Applies, Given};

    fn given(more: &[(&str, Given)]) -> Vec<(String, Given)> {
        let device = ("dev_addr".to_string(), Given::Integer(0x2601_1b2c));
        let more = more
            .iter()
            .map(|(name, value)| (name.to_string(), value.clone()));
        std::iter::once(device).chain(more).collect()
    }

    #[test]
    fn lorawan_declares_its_settings_and_reads_through_them() {
        let declared = LorawanTransport::SETTINGS;
        assert!(declared.problems().is_empty(), "{:?}", declared.problems());

        let sent = given(&[
            ("confirmed", Given::Boolean(true)),
            ("frequency", Given::Integer(868_100_000)),
            ("data_rate", Given::Text("SF9BW125".to_string())),
            ("timeout", Given::Text("3s".to_string())),
        ]);
        let device = LorawanTransport::open("lorawan://0.0.0.0", Applies::Send, &sent)
            .expect("a Send Location");
        assert_eq!(device.dev_addr, 0x2601_1b2c);
        assert!(device.confirmed);
        assert_eq!(
            (device.frequency, device.data_rate.as_str()),
            (868_100_000, "SF9BW125")
        );
        assert_eq!(device.timeout, Duration::from_secs(3));
        assert_eq!(
            device.gateways.bind(),
            format!("0.0.0.0:{PORT}"),
            "the port it names none"
        );

        let received =
            LorawanTransport::open("lorawan://127.0.0.1:1702", Applies::Receive, &given(&[]))
                .expect("a Receive Location");
        assert_eq!(received.gateways.bind(), "127.0.0.1:1702");
        assert_eq!(received.timeout, DEFAULT_TIMEOUT, "the default it declares");
        assert_eq!(received.data_rate, DEFAULT_DATA_RATE);
        assert!(matches!(received.waiting(), transport::Waiting::Waits(_)));

        let Err(refused) = LorawanTransport::open("gateway", Applies::Receive, &sent) else {
            panic!("a Receive Location sends nothing confirmed");
        };
        assert!(refused.message.contains("\"confirmed\""), "{refused}");
        let wrong = given(&[("data_rate", Given::Text("SF6BW125".to_string()))]);
        assert!(
            LorawanTransport::open("gateway", Applies::Send, &wrong).is_err(),
            "no SF6"
        );
    }

    #[test]
    fn the_locations_of_a_node_at_one_address_share_its_socket_and_a_devices_session() {
        let sharing: Arc<dyn Sharing> = Arc::new(Shared::default());
        let open = |side, dev_addr: i64| {
            let given = [("dev_addr".to_string(), Given::Integer(dev_addr))];
            LorawanTransport::open("127.0.0.1:0", side, &given)
                .expect("opened")
                .shared_by(&sharing)
        };
        let receiving = open(Applies::Receive, 1);
        let sending = open(Applies::Send, 1);
        let another = open(Applies::Receive, 2);
        assert!(
            Arc::ptr_eq(&receiving.gateways, &sending.gateways),
            "one socket"
        );
        assert!(
            Arc::ptr_eq(&receiving.gateways, &another.gateways),
            "one socket"
        );
        assert!(
            Arc::ptr_eq(&receiving.session, &sending.session),
            "one session"
        );
        assert!(
            !Arc::ptr_eq(&receiving.session, &another.session),
            "its own"
        );
        let bound = receiving
            .listening()
            .expect("bound")
            .expect("an address")
            .to_string();
        assert_eq!(
            another.listening().expect("bound").expect("the same"),
            bound
        );
    }

    #[test]
    fn the_session_keys_are_the_secret_a_location_names_read_as_it_sends() {
        let kept = Arc::new(Kept::default());
        let secured = kept.secured("partner-x.sensor");
        let node = LorawanTransport::loopback()
            .secured_by(secured)
            .expect("presents its keys")
            .timing_out_after(Duration::from_millis(50));
        let unset = node.send_stream(b"x").expect_err("not set");
        assert!(
            unset.retryable && unset.message.contains("is not set"),
            "{unset}"
        );
        kept.set("partner-x.sensor", SecretKind::Password, "not hexadecimal");
        let wrong = node.send_stream(b"x").expect_err("not keys");
        assert!(!wrong.retryable && wrong.message.contains("64"), "{wrong}");
        let keys = Keys {
            nwk_s_key: [1; 16],
            app_s_key: [2; 16],
        };
        kept.set("partner-x.sensor", SecretKind::Password, &keys.to_hex());
        assert_eq!(node.keys().expect("read now"), keys);
        let quiet = node.send_stream(b"x").expect_err("no gateway yet");
        assert!(quiet.message.contains("keepalive"), "{quiet}");
    }
}
