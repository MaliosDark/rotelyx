//! DNS resolution for Rotelyx.
//!
//! **Rotelyx modification.** This crate used to publish endpoint public keys to
//! a third party pkarr relay and DNS zone, and resolve peers from them.
//! Announcing `identity X is at address Y` to somebody else's server, where
//! anybody can query it, is precisely what Rotelyx is designed not to do: a
//! message being encrypted is worth little if the fact of the conversation sits
//! in a public directory.
//!
//! An earlier pass deleted the pkarr module and wrote here that the whole
//! machinery was gone. It was not: `endpoint_info` and `attrs` still declared
//! the `_iroh` TXT record name, the parser for it, and every conversion between
//! an address and a DNS record. They were unreachable, because
//! `rotelyx_net::AddressLookup` has one variant and it is `Disabled`, but
//! unreachable is not absent, and a claim in a comment is not a deletion.
//!
//! **620 lines are now actually gone**, across this crate and the transport's
//! test harness for standing up a DNS server and a pkarr relay. What remains is
//! a generic DNS resolver, used to turn our own relay hostnames into addresses,
//! and the address types the transport keeps its in-process address book in.
//! Neither publishes anything about anybody.

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
pub use attrs::{EncodingError, ParseError};
