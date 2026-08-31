//! Dialling another relay, so a circuit can continue past this one.
//!
//! The transport asks for this through a trait and never learns how it is done,
//! for the same reason it asks for the opening that way: a key, a resolver and a
//! TLS configuration are the operator's, not the protocol's.
//!
//! # What this exposes, said plainly
//!
//! A relay that chains can be told by a stranger to open a connection to a host
//! of the stranger's choosing. The address arrives inside a sealed descriptor,
//! so this relay is the first thing that reads it, and nothing has vouched for
//! it. That is why chaining is off unless the operator turns it on, and why an
//! operator may also name the relays theirs will chain to and refuse the rest.

use rotelyx_net::SecretKey;
use rotelyx_relay_proto::server::links::{DialError, DialFuture, KeyFuture, RelayDialer};

/// Dials other relays on this relay's behalf.
pub struct Dialer {
    /// This relay's own transport key. The far relay authenticates the link
    /// with it, which is what stops the link being anonymous transit.
    secret: SecretKey,
    /// The relays this one will chain to, or none for any.
    allowed: Option<Vec<String>>,
}

/// Says nothing about the key.
impl std::fmt::Debug for Dialer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.allowed {
            Some(urls) => write!(f, "Dialer({} relays allowed)", urls.len()),
            None => write!(f, "Dialer(any relay)"),
        }
    }
}

impl Dialer {
    pub fn new(secret: SecretKey, allowed: Option<Vec<String>>) -> Self {
        Self { secret, allowed }
    }

    /// Whether this relay is willing to dial that address at all.
    ///
    /// Checked before anything is resolved or connected, so a refused address
    /// costs no lookup and reaches no network.
    fn permitted(&self, url: &str) -> bool {
        match &self.allowed {
            None => true,
            Some(urls) => urls.iter().any(|allowed| allowed == url),
        }
    }
}

impl RelayDialer for Dialer {
    /// Reads another relay's published circuit key over HTTP.
    ///
    /// The same allowlist as `dial`, because it is the same outward connection
    /// to the same stranger-chosen address. A caller learns nothing about why
    /// this failed, which is the point: the shape of the answer must not say
    /// which relays this one will reach.
    fn fetch_circuit_key(&self, url: String) -> KeyFuture {
        if !self.permitted(&url) {
            return Box::pin(async move { None });
        }

        Box::pin(async move {
            let at = format!(
                "{}{}",
                url.trim_end_matches('/'),
                rotelyx_relay_proto::http::CIRCUIT_KEY_PATH
            );
            let client = reqwest::Client::builder()
                // A relay that hung here would hold a task per ask, and the
                // caller cannot tell a slow answer from none anyway.
                .timeout(std::time::Duration::from_secs(10))
                // The address came from a stranger. Following redirects would
                // let it point this relay at somewhere else after the
                // allowlist had already said yes.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .ok()?;

            let response = client.get(&at).send().await.ok()?;
            if !response.status().is_success() {
                return None;
            }
            let body = response.text().await.ok()?;
            // `<endpoint id> <key>`. The id is the caller's to know, from the
            // invitation; what this relay fetches on their behalf is the key.
            let key = body.trim().rsplit(' ').next()?;

            // Checked here rather than trusted onward: this came from a machine
            // nobody has vouched for, and what the caller does with it is seal
            // a circuit. A key that does not decode is not a key.
            let bytes = data_encoding::BASE64URL_NOPAD.decode(key.as_bytes()).ok()?;
            rotelyx_crypto::hybrid::HybridPublicKey::from_bytes(&bytes).ok()?;
            Some(key.to_owned())
        })
    }

    fn dial(&self, url: String) -> DialFuture {
        if !self.permitted(&url) {
            // Not logged with the address. An operator who wants to know which
            // addresses are being asked for can turn the transport's own
            // logging up; putting it here would write a stranger's chosen
            // string into this relay's log on demand.
            return Box::pin(
                async move { Err(DialError("not a relay this one chains to".to_owned())) },
            );
        }

        let secret = self.secret.clone();
        Box::pin(async move {
            let parsed: rotelyx_net::RelayUrl = url
                .parse()
                .map_err(|_| DialError("not a relay address".to_owned()))?;

            // The provider the transport was built with, not whatever happens
            // to be installed as the process default. Nothing installs a
            // process default here, so asking for one returned nothing and
            // every dial failed before a two relay test found it.
            let tls = rotelyx_relay_proto::tls::CaTlsConfig::default()
                .client_config(rotelyx_relay_proto::tls::default_provider())
                .map_err(|err| DialError(format!("tls: {err}")))?;

            rotelyx_relay_proto::client::ClientBuilder::new(
                parsed,
                secret,
                rotelyx_discovery::dns::DnsResolver::new(),
            )
            .tls_client_config(tls)
            .connect()
            .await
            .map_err(|err| DialError(format!("{err}")))
        })
    }
}

/// This relay's transport identity, made on first use.
///
/// Separate from the circuit key and doing a different job: this one says who
/// this relay is when it dials another, and it is the name descriptors are
/// sealed to. Both come from files the operator keeps; neither says anything
/// about anybody's messages.
pub fn load_or_create_identity(path: &std::path::Path) -> anyhow::Result<SecretKey> {
    use anyhow::Context;

    match std::fs::read(path) {
        Ok(bytes) => {
            let bytes: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .with_context(|| format!("{} is not a 32 byte key", path.display()))?;
            Ok(SecretKey::from_bytes(&bytes))
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let secret = SecretKey::generate();
            crate::circuit::write_private(path, &secret.to_bytes())
                .with_context(|| format!("writing {}", path.display()))?;
            tracing::info!(path = %path.display(), "made a transport identity");
            Ok(secret)
        }
        Err(err) => Err(anyhow::anyhow!("reading {}: {err}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dialer(allowed: Option<Vec<String>>) -> Dialer {
        Dialer::new(SecretKey::from_bytes(&[1u8; 32]), allowed)
    }

    /// With no list, any address a descriptor names is dialled.
    ///
    /// This is the setting the flag warns about, and the test is here so that
    /// what it does is written down rather than inferred from the absence of a
    /// check.
    #[test]
    fn without_a_list_any_relay_is_dialled() {
        let d = dialer(None);
        assert!(d.permitted("https://relay.example.invalid"));
        assert!(d.permitted("https://somewhere.else.invalid"));
    }

    /// With a list, only what is on it.
    #[test]
    fn with_a_list_only_what_is_on_it() {
        let d = dialer(Some(vec!["https://relay.example.invalid".to_owned()]));
        assert!(d.permitted("https://relay.example.invalid"));
        assert!(!d.permitted("https://somewhere.else.invalid"));
    }

    /// The comparison is exact.
    ///
    /// Not a prefix or a suffix: `https://relay.example.invalid.attacker.test`
    /// ends with a permitted name and is a different host, and
    /// `https://relay.example.invalid` with anything appended is a different
    /// address. A check that matched loosely here would be a way past the list.
    #[test]
    fn a_near_miss_is_not_a_match() {
        let d = dialer(Some(vec!["https://relay.example.invalid".to_owned()]));
        for near in [
            "https://relay.example.invalid.attacker.test",
            "https://relay.example.invalid/../elsewhere",
            "https://relay.example.invalid:8443",
            "http://relay.example.invalid",
            "https://relay.example.invalid ",
            "https://sub.relay.example.invalid",
            "",
        ] {
            assert!(
                !d.permitted(near),
                "{near} was treated as the allowed relay"
            );
        }
    }

    /// A refused address is refused before anything is resolved or connected.
    #[tokio::test]
    async fn a_refused_address_reaches_no_network() {
        let d = dialer(Some(vec!["https://relay.example.invalid".to_owned()]));
        // If this reached the network it would take a DNS timeout rather than
        // returning at once, so the timeout is the assertion.
        let refused = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            d.dial("https://somewhere.else.invalid".to_owned()),
        )
        .await
        .expect("a refused address should not reach a resolver");
        assert!(refused.is_err(), "a refused address was dialled");
    }

    /// Something that is not an address is refused rather than dialled.
    #[tokio::test]
    async fn what_is_not_an_address_is_refused() {
        let d = dialer(None);
        for nonsense in ["", "not a url", "relay.example.invalid", "://"] {
            let out = tokio::time::timeout(
                std::time::Duration::from_millis(500),
                d.dial(nonsense.to_owned()),
            )
            .await
            .expect("parsing should not take a network round trip");
            assert!(out.is_err(), "{nonsense:?} was treated as a relay address");
        }
    }

    /// The dialler never prints the key or the address it was given.
    ///
    /// The address arrived from a stranger, and a `Debug` that echoed it would
    /// put a chosen string into this relay's log on demand.
    #[test]
    fn debug_says_nothing_it_was_given() {
        let shown = format!(
            "{:?}",
            dialer(Some(vec!["https://secret.invalid".to_owned()]))
        );
        assert!(!shown.contains("secret.invalid"), "{shown}");
        assert!(shown.contains('1'), "the count should be there: {shown}");

        let shown = format!("{:?}", dialer(None));
        assert!(shown.contains("any relay"), "{shown}");
    }
}
