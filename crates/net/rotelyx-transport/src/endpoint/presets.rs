//! Presets allow configuring an endpoint quickly with a chosen set of defaults.
//!
//! # Example
//!
//! ```no_run
//! # #[cfg(with_crypto_provider)]
//! # {
//! # async fn wrapper() -> rotelyx_error::Result {
//! use rotelyx_transport::{Endpoint, RelayMode, Watcher, endpoint::presets};
//!
//! let endpoint = Endpoint::builder(presets::Minimal).bind().await?;
//! # let _ = endpoint;
//! # Ok(())
//! # }
//! # }
//! ```

use crate::endpoint::Builder;

/// A reusable bundle of endpoint [`Builder`] configuration.
pub trait Preset {
    /// Applies the configuration to the passed in [`Builder`].
    fn apply(self, builder: Builder) -> Builder;
}

/// An empty preset that doesn't set anything on the builder.
///
/// This doesn't set mandatory builder options, so using this in
/// `Endpoint::bind(presets::Empty)` will always fail.
///
/// However, it can be useful, if you want control over all mandatory options
/// yourself, by using `Endpoint::builder(presets::Empty)`.
///
/// If you prefer a minimal version that is guaranteed to work, see the
/// [`Minimal`] preset.
#[derive(Debug, Copy, Clone, Default)]
pub struct Empty;

impl Preset for Empty {
    fn apply(self, builder: Builder) -> Builder {
        builder
    }
}

/// A preset that is almost empty, besides setting mandatory options.
///
/// At the moment the only mandatory option to set on the endpoint builder is
/// [`Builder::crypto_provider`]. This preset makes a choice for that based on
/// the current set of enabled features in rotelyx_transport, which is why it's only available
/// with the `tls-ring` or `tls-aws-lc-rs` feature flag.
///
/// It uses either [ring] or [aws-lc-rs], depending on which feature is enabled
/// on rotelyx_transport (preferring ring if both are enabled).
///
/// [ring]: rustls::crypto::ring::default_provider
/// [aws-lc-rs]: rustls::crypto::aws_lc_rs::default_provider
#[cfg(with_crypto_provider)]
#[derive(Debug, Copy, Clone, Default)]
pub struct Minimal;

#[cfg(with_crypto_provider)]
impl Preset for Minimal {
    fn apply(self, mut builder: Builder) -> Builder {
        use std::sync::Arc;

        #[cfg(feature = "tls-ring")]
        {
            builder = builder.crypto_provider(Arc::new(rustls::crypto::ring::default_provider()));
        }

        #[cfg(all(feature = "tls-aws-lc-rs", not(feature = "tls-ring")))]
        {
            builder =
                builder.crypto_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()));
        }

        builder
    }
}

// Rotelyx: the `N0` and `N0DisableRelay` presets are deleted. Their entire
// purpose was to register a pkarr publisher, a pkarr resolver and a DNS address
// lookup against infrastructure operated by Number 0, and to load that
// operator's relay map. Rotelyx names its own infrastructure explicitly through
// `rotelyx_net::NetConfig`; there is deliberately no preset that could reach
// somebody else's servers.
