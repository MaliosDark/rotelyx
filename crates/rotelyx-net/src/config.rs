//! Transport configuration.
//!
//! The single design rule in this module: **there is no default that reaches
//! infrastructure we do not operate.** Every type here is constructed by naming
//! the infrastructure explicitly, and no `Default` impl exists that could
//! silently reintroduce someone else's servers.
//!
//! This is a structural guarantee rather than a configuration one. A wrong
//! config value is a bug you find in production; a missing constructor is a bug
//! you find at compile time.

pub use rotelyx_path::PathPolicy;

use std::fmt;

use rotelyx_transport::RelayUrl;

/// Which relays this deployment is willing to use when hole punching fails.
///
/// There is deliberately no variant meaning "the library's defaults". Upstream
/// iroh ships `RelayMode::Default` and `RelayMode::Staging`, both of which point
/// at servers operated by Number 0. Neither is reachable through this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayPolicy {
    /// No relay, ever. Direct hole-punched paths only.
    ///
    /// The strongest metadata posture available. No third party, including us,
    /// observes that two identities are in contact. The cost is real, and it is
    /// connection failure, not degradation. Roughly 10-20% of NAT pairs on the
    /// public internet cannot be punched through, and for those peers this
    /// policy means the session simply does not happen.
    DirectOnly,

    /// Fall back to these relays, all of which the deployment operates.
    ///
    /// A relay in this list still sees which endpoint id talks to which: it
    /// cannot read content, but it observes the social graph. That is ADV-3 in
    /// the threat model and it is why this list must never contain a host
    /// somebody else runs.
    SelfHosted(Vec<RelayUrl>),
}

impl RelayPolicy {
    /// Relays this policy will contact. Empty for [`RelayPolicy::DirectOnly`].
    pub fn urls(&self) -> &[RelayUrl] {
        match self {
            Self::DirectOnly => &[],
            Self::SelfHosted(urls) => urls,
        }
    }

    pub fn uses_relays(&self) -> bool {
        !self.urls().is_empty()
    }
}

/// Whether the endpoint publishes its address anywhere discoverable.
///
/// Upstream's default publishes the endpoint's public key and reachability to
/// a pkarr relay and DNS zone operated by Number 0. For Rotelyx that is a
/// disclosure of existence and presence to a third party on every startup, so
/// there is one variant and it publishes nothing. A rendezvous of our own would
/// belong here if it ever existed; it does not, and this comment used to say it
/// did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressLookup {
    /// Publish nothing, resolve nothing. Peer addresses arrive out of band,
    /// from an invitation, or through the blind mailbox.
    ///
    /// This is the correct setting for Rotelyx: rendezvous belongs at L3 where it
    /// can be sealed, not at L0 where it is a public record.
    Disabled,
}

/// A complete transport configuration.
///
/// Built through [`NetConfig::new`], which requires naming both policies. There
/// is no `Default`, and that is the point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetConfig {
    relays: RelayPolicy,
    paths: PathPolicy,
    lookup: AddressLookup,
}

impl NetConfig {
    pub fn new(relays: RelayPolicy, paths: PathPolicy) -> Self {
        Self {
            relays,
            paths,
            lookup: AddressLookup::Disabled,
        }
    }

    /// Direct-only, no relays, no discovery. The maximum-privacy posture, and
    /// the one to use in tests so a test can never reach the network.
    pub fn direct_only() -> Self {
        Self::new(RelayPolicy::DirectOnly, PathPolicy::PreferDirect)
    }

    pub fn relays(&self) -> &RelayPolicy {
        &self.relays
    }

    pub fn paths(&self) -> PathPolicy {
        self.paths
    }

    pub fn address_lookup(&self) -> &AddressLookup {
        &self.lookup
    }

    /// Every host this configuration is permitted to contact.
    ///
    /// The guard test asserts this is a subset of hosts the deployment
    /// operates. If a future change reintroduces an upstream default, this is
    /// where it becomes visible.
    pub fn permitted_hosts(&self) -> Vec<String> {
        self.relays
            .urls()
            .iter()
            .filter_map(|u| u.host_str().map(str::to_owned))
            .collect()
    }
}

impl fmt::Display for NetConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let relays = match &self.relays {
            RelayPolicy::DirectOnly => "direct-only".to_string(),
            RelayPolicy::SelfHosted(urls) => format!("{} self-hosted relay(s)", urls.len()),
        };
        write!(f, "{relays}, {:?} paths, lookup disabled", self.paths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_only_permits_no_hosts() {
        let cfg = NetConfig::direct_only();
        assert!(cfg.permitted_hosts().is_empty());
        assert!(!cfg.relays().uses_relays());
    }

    #[test]
    fn self_hosted_relays_are_the_only_permitted_hosts() {
        let url: RelayUrl = "https://relay.example.internal".parse().unwrap();
        let cfg = NetConfig::new(RelayPolicy::SelfHosted(vec![url]), PathPolicy::PreferDirect);
        assert_eq!(cfg.permitted_hosts(), vec!["relay.example.internal"]);
    }

    #[test]
    fn only_fastest_tolerates_relay_beside_direct() {
        assert!(PathPolicy::Fastest.tolerates_relay_alongside_direct());
        assert!(!PathPolicy::PreferDirect.tolerates_relay_alongside_direct());
        assert!(!PathPolicy::DirectOnceAvailable.tolerates_relay_alongside_direct());
    }
}
