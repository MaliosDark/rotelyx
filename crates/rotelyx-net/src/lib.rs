//! # rotelyx-net
//!
//! Rotelyx's transport layer (L0/L1): QUIC over hole-punched direct paths, with
//! relay fallback only to infrastructure the deployment operates.
//!
//! ## The guarantee this crate exists to make
//!
//! **No code path here contacts infrastructure Rotelyx does not operate.**
//!
//! That is not a configuration default: it is structural. [`RelayPolicy`] has
//! no variant meaning "the library's defaults", [`AddressLookup`] has no
//! variant that publishes anywhere, and [`NetConfig`] has no `Default` impl.
//! The upstream transport ships defaults that register a pkarr publisher and
//! resolver against `dns.iroh.link` and load a relay map of Number 0's
//! servers; none of those are reachable through this API.
//!
//! `tests/no_foreign_infrastructure.rs` asserts the guarantee against a live
//! endpoint, and fails the build if it ever stops holding.
//!
//! ## Where this crate diverges from upstream on purpose
//!
//! Upstream optimises path selection for latency. Rotelyx optimises it for
//! metadata resistance, and those objectives genuinely conflict: given a fast
//! relayed path and a slower direct one, latency-first hands the social graph
//! to a relay operator to save a few milliseconds. [`PathPolicy`] encodes the
//! other choice.
//!
//! ## Provenance
//!
//! The transport stack is vendored into this repository under `crates/net/`,
//! Rotelyx downloads no upstream transport package. That code is derived from
//! iroh (MIT/Apache-2.0), whose socket layer is in turn derived from Tailscale
//! (BSD-3) and whose QUIC layer is a fork of quinn. See `VENDORING.md` for the
//! licence obligations, the per-subsystem replacement plan, and the wording of
//! the authorship claim that is actually defensible.

#![forbid(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod config;
pub mod endpoint;
pub mod path;

pub use config::{AddressLookup, NetConfig, PathPolicy, RelayPolicy};
pub use endpoint::{NetEndpoint, NetSession};
pub use path::MetadataResistantSelector;

// Re-exported so nothing above this crate names the transport crate directly.
// `rotelyx-net` is the single seam between Rotelyx and the machinery in
// `crates/net/`, which keeps subsystem replacement to one file at a time.
pub use rotelyx_transport::endpoint::{Connection, RecvStream, SendStream};
pub use rotelyx_transport::{EndpointAddr, EndpointId, RelayUrl, SecretKey};
