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

// Rotelyx: upstream's one test here is deleted rather than repaired.
//
// It resolved `NA_EAST_RELAY_HOSTNAME`, a hostname belonging to the operator
// whose relays and presets this tree has already removed, and asserted the
// lookup returned something. So it tested that somebody else's DNS was up, over
// the network, from a unit test, against infrastructure this project
// deliberately does not use.
//
// The staging module it read that name from went with the presets, which is why
// this stopped compiling and why every other test in this crate stopped
// compiling with it. See `endpoint/presets.rs`.
