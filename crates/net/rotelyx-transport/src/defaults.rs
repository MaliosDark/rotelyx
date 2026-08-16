//! Default values used in [`rotelyx_transport`][`crate`]

/// The default QUIC port used by the Relay server to accept QUIC connections
/// for QUIC address discovery
///
/// The port is "QUIC" typed on a phone keypad.
pub use rotelyx_relay_proto::defaults::DEFAULT_RELAY_QUIC_PORT;


/// The default HTTP port used by the Relay server.
pub const DEFAULT_HTTP_PORT: u16 = 80;

/// The default HTTPS port used by the Relay server.
pub const DEFAULT_HTTPS_PORT: u16 = 443;

/// The default metrics port used by the Relay server.
pub const DEFAULT_METRICS_PORT: u16 = 9090;

/// Production configuration.
// Rotelyx: the `prod` and `staging` relay maps are deleted. They named relay
// servers operated by a third party, and `RelayMode::Default` existed only to
// return them. Rotelyx names its own relays explicitly through
// `rotelyx_net::RelayPolicy`; there is deliberately no constant here that
// anything could fall back to.
/// Contains all timeouts that we use in `rotelyx_transport`.
pub(crate) mod timeouts {
    use rotelyx_future::time::Duration;

    // Timeouts for net_report

    /// Maximum duration to wait for a net_report.
    pub(crate) const NET_REPORT_TIMEOUT: Duration = Duration::from_secs(10);
}

#[cfg(test)]
pub(crate) mod tests {
    use std::time::Duration;

    use n0_tracing_test::traced_test;

    use super::staging::NA_EAST_RELAY_HOSTNAME;
    use crate::dns::DnsResolver;

    const TIMEOUT: Duration = Duration::from_secs(5);
    const STAGGERING_DELAYS: &[u64] = &[200, 300];

    #[tokio::test]
    #[traced_test]
    async fn test_dns_lookup_ipv4_ipv6() {
        let resolver = DnsResolver::new();
        let res: Vec<_> = resolver
            .lookup_ipv4_ipv6_staggered(NA_EAST_RELAY_HOSTNAME, TIMEOUT, STAGGERING_DELAYS)
            .await
            .unwrap()
            .collect();
        assert!(!res.is_empty());
        dbg!(res);
    }
}
