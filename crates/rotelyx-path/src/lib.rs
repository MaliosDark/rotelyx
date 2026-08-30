//! How a path is chosen once more than one is available.
//!
//! # Why this is a crate of its own
//!
//! It is four variants and two methods that match on themselves, and it has no
//! dependencies. That is not an accident, it is the requirement: this is read
//! by the transport, which is native only, and by the media layer, which is
//! not.
//!
//! It lived in `rotelyx-net` because that is where a path is chosen. But
//! `rotelyx-media` reads it for one decision and got the whole transport with
//! it, `ring` included, which does not build for `wasm32`. The media layer
//! therefore could not reach a browser at all, on account of an enum.
//!
//! `rotelyx-net` re-exports it, so nothing that used it from there had to
//! change.

/// How a path is chosen once more than one is available.
///
/// Upstream optimises for latency, which is the right objective for a general
/// transport and the wrong one for a private messenger: given a fast relayed
/// path and a slow direct one, latency-first hands your social graph to the
/// relay operator to save 20ms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathPolicy {
    /// Lowest latency wins, relayed or not. Matches upstream behaviour.
    ///
    /// Provided for benchmarking against the privacy-preserving policies. Not
    /// a sensible production choice for Rotelyx.
    Fastest,

    /// Prefer any direct path over any relayed path, regardless of latency.
    ///
    /// Falls back to relay when no direct path exists. The default: it keeps
    /// the system usable while ensuring a relay only ever carries traffic that
    /// had nowhere else to go.
    PreferDirect,

    /// Use a relay only until a direct path is available, then never again for
    /// this session, and surface the transition to the user.
    ///
    /// Costs a visible reconnect. Buys a bounded window of relay exposure
    /// rather than an open-ended one.
    DirectOnceAvailable,

    /// Never take a direct path. Relay or nothing.
    ///
    /// # Why a policy exists whose whole purpose is to be slower
    ///
    /// The other three trade latency for keeping a relay operator out of your
    /// social graph, because for a message the alternative exposure is to an
    /// operator. **A call inverts that.** On a direct path the other party
    /// learns your address, and in a group call every participant does, so the
    /// exposure that matters is to whoever is on the call rather than to a
    /// server.
    ///
    /// A messenger whose call feature hands your address to whoever rings you
    /// cannot claim to protect anybody, so this is what media uses and there is
    /// no switch to turn it off.
    ///
    /// If no relay is reachable the connection fails, which is the honest
    /// outcome for a policy whose entire promise is that a direct path is never
    /// taken.
    RelayOnly,

    /// Relay only, and through two relays rather than one.
    ///
    /// # What it buys
    ///
    /// One relay learns who is talking to whom, and that is ADV-3 in the threat
    /// model: inherent to relayed transport, not a defect. Two relays split it.
    /// The first learns the caller and that a circuit was opened through the
    /// second; the second learns the destination and that traffic arrives from
    /// the first. Neither alone holds the pair.
    ///
    /// # What it does not buy, which the interface has to say out loud
    ///
    /// **Two relays run by one operator buy nothing.** Colluding operators hold
    /// exactly what one operator holds today, and no software here can check
    /// whether two relays are run by the same person: they are two addresses
    /// and two keys, and that is all a client can see. Whoever chooses this has
    /// to know that the property depends on a fact about the world rather than
    /// about the protocol.
    ///
    /// It is also not a mixnet. Somebody watching both relays learns from
    /// volume and timing what the circuit does not hide, and the threat model
    /// says resisting a global passive adversary is a non-goal.
    ///
    /// # What it costs
    ///
    /// A round trip to set up, a second relay's latency on every packet after
    /// that, and a fetch of the exit relay's key the first time. If no chain
    /// can be built the connection fails, for the reason `RelayOnly` fails:
    /// a policy whose promise is that something never happens has to keep it.
    Chained,
}

impl PathPolicy {
    /// Whether a relayed path is acceptable when a direct one exists.
    pub fn tolerates_relay_alongside_direct(&self) -> bool {
        matches!(self, Self::Fastest | Self::RelayOnly | Self::Chained)
    }

    /// Whether a direct path may ever be used.
    pub fn permits_direct(&self) -> bool {
        !matches!(self, Self::RelayOnly | Self::Chained)
    }

    /// Whether one relay is enough, or a chain of two is required.
    ///
    /// Required rather than preferred: a policy that quietly fell back to one
    /// relay would be a policy somebody chose for a property it then did not
    /// have, and they would have no way to tell.
    pub fn requires_chain(&self) -> bool {
        matches!(self, Self::Chained)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Chaining forbids a direct path, like the policy it extends.
    ///
    /// A chained policy that took a direct path would be one somebody chose for
    /// a property it then did not have.
    #[test]
    fn chaining_forbids_a_direct_path_too() {
        assert!(!PathPolicy::Chained.permits_direct());
        assert!(PathPolicy::Chained.tolerates_relay_alongside_direct());
    }

    /// Only the chained policy requires a chain.
    ///
    /// The others must not quietly gain a second relay, and this one must not
    /// quietly lose it: a fallback to one relay would leave somebody believing
    /// in a split that is not there, with no way to tell.
    #[test]
    fn only_the_chained_policy_requires_a_chain() {
        assert!(PathPolicy::Chained.requires_chain());
        for single in [
            PathPolicy::Fastest,
            PathPolicy::PreferDirect,
            PathPolicy::DirectOnceAvailable,
            PathPolicy::RelayOnly,
        ] {
            assert!(
                !single.requires_chain(),
                "{single:?} would have required a chain"
            );
        }
    }

    #[test]
    fn the_relayed_policies_forbid_a_direct_path_and_the_others_permit_it() {
        // The property the media layer depends on. `MediaOut` refuses to be
        // constructed on a connection whose policy permits a direct path, and
        // this is the answer it asks for.
        for relayed in [PathPolicy::RelayOnly, PathPolicy::Chained] {
            assert!(
                !relayed.permits_direct(),
                "{relayed:?} would have taken a direct path"
            );
        }

        for permissive in [
            PathPolicy::Fastest,
            PathPolicy::PreferDirect,
            PathPolicy::DirectOnceAvailable,
        ] {
            assert!(permissive.permits_direct());
        }
    }

    #[test]
    fn the_two_that_tolerate_a_relay_beside_a_direct_path() {
        // Fastest, because it does not care. RelayOnly, because it never has a
        // direct path to prefer. The two middle policies exist to avoid this.
        assert!(PathPolicy::Fastest.tolerates_relay_alongside_direct());
        assert!(PathPolicy::RelayOnly.tolerates_relay_alongside_direct());
        assert!(!PathPolicy::PreferDirect.tolerates_relay_alongside_direct());
        assert!(!PathPolicy::DirectOnceAvailable.tolerates_relay_alongside_direct());
    }
}
