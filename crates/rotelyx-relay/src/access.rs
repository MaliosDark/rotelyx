//! Who may use this relay.
//!
//! An open relay forwards for anyone who finds it. That is fine for a public
//! utility and wrong for a community's own infrastructure: it turns a machine
//! you run for your friends into a machine strangers use for free, and it means
//! your relay's connection log covers people you have no relationship with.
//!
//! An allowlist gives you the opposite: the only endpoint IDs in your logs are
//! ones you chose to serve.
//!
//! ## What this is not
//!
//! Not confidentiality. A relay forwards ciphertext it cannot read either way,
//! so admitting a stranger does not expose anyone's messages. What it exposes
//! is *your* capacity and *your* logs. Restricting access is an operational and
//! metadata decision, not a cryptographic one.

use std::collections::HashSet;

use rotelyx_net::EndpointId;
use rotelyx_relay_proto::server::{Access, AccessControl, ClientRequest, ConnectionId};

/// Admits only endpoint IDs on a fixed list.
#[derive(Debug)]
pub struct Allowlist {
    allowed: HashSet<EndpointId>,
}

impl Allowlist {
    // Used by tests and by callers embedding the relay as a library; the binary
    // itself only calls `permits`.
    pub fn new(allowed: impl IntoIterator<Item = EndpointId>) -> Self {
        Self {
            allowed: allowed.into_iter().collect(),
        }
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.allowed.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.allowed.is_empty()
    }

    pub fn permits(&self, id: &EndpointId) -> bool {
        self.allowed.contains(id)
    }
}

impl AccessControl for Allowlist {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        if self.permits(&request.endpoint_id()) {
            Access::Allow
        } else {
            // The reason is deliberately vague. Telling a caller *why* it was
            // refused turns the relay into an oracle for which identities the
            // operator serves — which is the membership of a community.
            Access::Deny {
                reason: Some("not permitted".into()),
            }
        }
    }

    fn on_disconnect(&self, _endpoint_id: EndpointId, _connection_id: ConnectionId) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use rotelyx_net::SecretKey;

    fn id(seed: u8) -> EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    #[test]
    fn an_allowlisted_id_is_permitted() {
        let list = Allowlist::new([id(1), id(2)]);
        assert!(list.permits(&id(1)));
        assert!(list.permits(&id(2)));
    }

    #[test]
    fn an_unknown_id_is_refused() {
        let list = Allowlist::new([id(1)]);
        assert!(!list.permits(&id(9)));
    }

    /// An empty allowlist must refuse everyone rather than falling open. A
    /// misconfigured relay that serves the whole internet is a worse failure
    /// than one that serves nobody, because only the second is noticed.
    #[test]
    fn an_empty_allowlist_refuses_everyone() {
        let list = Allowlist::new([]);
        assert!(list.is_empty());
        assert!(!list.permits(&id(1)));
    }

    #[test]
    fn duplicates_do_not_inflate_the_list() {
        let list = Allowlist::new([id(1), id(1), id(2)]);
        assert_eq!(list.len(), 2);
    }
}
