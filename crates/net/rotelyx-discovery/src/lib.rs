//! DNS resolution for Rotelyx.
//!
//! **Rotelyx modification.** This crate previously also published endpoint
//! public keys to a third party pkarr relay and DNS zone, and resolved peers
//! from them. That machinery, 1,327 lines across `endpoint_info`, `pkarr` and
//! `attrs`, is deleted: announcing an identity's existence to somebody else's
//! server on every startup is precisely what Rotelyx is designed not to do.
//!
//! What remains is a generic DNS resolver, used to translate our own relay
//! hostnames into addresses and by network condition probing. It publishes
//! nothing about anybody.

#![deny(missing_docs, rustdoc::broken_intra_doc_links, unreachable_pub)]
#![cfg_attr(not(test), deny(clippy::unwrap_used))]

#[cfg(any(target_os = "android", doc))]
mod android;
#[cfg(not(wasm_browser))]
mod attrs;
pub mod dns;
pub mod endpoint_info;

#[cfg(any(target_os = "android", doc))]
pub use android::install_android_jni_context;
pub use attrs::{EncodingError, IROH_TXT_NAME, ParseError};
