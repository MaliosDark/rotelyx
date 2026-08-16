//! Metadata-resistant path selection.
//!
//! This is where Rotelyx genuinely diverges from the transport it derives from,
//! and the divergence is a different objective function rather than a different
//! algorithm.
//!
//! The upstream selector sorts paths by `(tier, biased RTT)`. It treats relayed
//! paths as a backup tier, which is close to what we want — but "close" is not
//! a guarantee, and the tie-breaking underneath it is latency. Given a relayed
//! path that is 20ms faster, latency-first hands the social graph to a relay
//! operator to save 20ms.
//!
//! Rotelyx inverts the priority: **any direct path beats any relayed path, at any
//! latency.** A relay carries traffic only when there is nothing else, and
//! [`PathPolicy::DirectOnceAvailable`] additionally refuses to fall back once a
//! direct path has been established.
//!
//! ## What this costs
//!
//! Real latency, sometimes. A direct path across the world can be slower than a
//! relay two hops away, and Rotelyx will take the slow one. That is the trade
//! being made deliberately: a relay operator learns which endpoint talks to
//! which, and no amount of speed is worth handing that over by default.

use std::sync::Arc;

use rotelyx_transport::path_selection::{
    FourTuple, PathSelection, PathSelectionContext, PathSelectionData, PathSelector,
};

use crate::config::PathPolicy;

/// Selects network paths by metadata resistance rather than latency.
#[derive(Debug, Clone)]
pub struct MetadataResistantSelector {
    policy: PathPolicy,
}

impl MetadataResistantSelector {
    pub fn new(policy: PathPolicy) -> Self {
        Self { policy }
    }

    pub fn shared(policy: PathPolicy) -> Arc<dyn PathSelector> {
        Arc::new(Self::new(policy))
    }

    /// Rank within a group of equally-acceptable paths.
    ///
    /// Latency is the tie-breaker, never the primary key. `None` stats mean the
    /// path closed underneath us, so it sorts last rather than being trusted.
    fn rtt_nanos(psd: &PathSelectionData<'_>) -> u128 {
        psd.stats().map(|s| s.rtt.as_nanos()).unwrap_or(u128::MAX)
    }
}

fn is_direct(path: &FourTuple) -> bool {
    path.is_ip()
}

/// Which candidate a policy picks.
///
/// The selector's real logic, lifted out of the transport types so it can be
/// tested without sockets or a relay server. Everything around it is plumbing:
/// find the best direct path, find the best relayed one, ask this.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Choice {
    /// Switch to the best direct path.
    Direct,
    /// Switch to the best relayed path.
    Relayed,
    /// Change nothing. Keeps whatever is currently carrying traffic.
    KeepCurrent,
}

/// Decide, given the best candidate of each kind and what is in use now.
///
/// RTTs are in nanoseconds; `None` means no candidate of that kind exists.
pub fn decide(
    policy: PathPolicy,
    best_direct: Option<u128>,
    best_relayed: Option<u128>,
    currently_direct: bool,
) -> Choice {
    match policy {
        // Upstream's objective, kept so the privacy-preserving policies have
        // something to be measured against.
        PathPolicy::Fastest => match (best_direct, best_relayed) {
            (Some(d), Some(r)) => {
                if d <= r {
                    Choice::Direct
                } else {
                    Choice::Relayed
                }
            }
            (Some(_), None) => Choice::Direct,
            (None, Some(_)) => Choice::Relayed,
            (None, None) => Choice::KeepCurrent,
        },

        // Any direct path beats any relayed path, whatever the latency.
        PathPolicy::PreferDirect => match (best_direct, best_relayed) {
            (Some(_), _) => Choice::Direct,
            (None, Some(_)) => Choice::Relayed,
            (None, None) => Choice::KeepCurrent,
        },

        // As above, but never move back onto a relay once direct.
        PathPolicy::DirectOnceAvailable => match (best_direct, best_relayed) {
            (Some(_), _) => Choice::Direct,
            // Already direct and only relays on offer: hold. If the current
            // path is genuinely dead the connection fails, which is the honest
            // outcome for a policy whose whole promise is "no relay after this".
            (None, Some(_)) if currently_direct => Choice::KeepCurrent,
            (None, Some(_)) => Choice::Relayed,
            (None, None) => Choice::KeepCurrent,
        },
    }
}

impl PathSelector for MetadataResistantSelector {
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
        let mut best_direct: Option<(PathSelectionData<'_>, u128)> = None;
        let mut best_relayed: Option<(PathSelectionData<'_>, u128)> = None;

        for psd in ctx.paths() {
            let rtt = Self::rtt_nanos(&psd);
            let slot = if is_direct(psd.network_path()) {
                &mut best_direct
            } else {
                &mut best_relayed
            };
            if slot.as_ref().is_none_or(|(_, best)| rtt < *best) {
                *slot = Some((psd, rtt));
            }
        }

        let mut selection = PathSelection::none();

        // Whether the path currently carrying traffic is already direct. This
        // is what makes `DirectOnceAvailable` stateless: the context reports
        // the current path *for this remote*, so no per-peer bookkeeping is
        // needed — and per-peer state would be wrong anyway, since one selector
        // serves every peer on the endpoint.
        let currently_direct = ctx.current().is_some_and(is_direct);

        match decide(
            self.policy,
            best_direct.as_ref().map(|(_, rtt)| *rtt),
            best_relayed.as_ref().map(|(_, rtt)| *rtt),
            currently_direct,
        ) {
            Choice::Direct => {
                if let Some((psd, _)) = &best_direct {
                    selection.set(psd);
                }
            }
            Choice::Relayed => {
                if let Some((psd, _)) = &best_relayed {
                    selection.set(psd);
                }
            }
            // An empty selection keeps the current path.
            Choice::KeepCurrent => {}
        }

        selection
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: u128 = 10;
    const SLOW: u128 = 10_000;

    /// The headline property. A relay that is a thousand times faster still
    /// loses, because latency is not what this policy optimises.
    #[test]
    fn prefer_direct_takes_a_slow_direct_path_over_a_fast_relay() {
        assert_eq!(
            decide(PathPolicy::PreferDirect, Some(SLOW), Some(FAST), false),
            Choice::Direct
        );
    }

    /// The behaviour Rotelyx is diverging *from*, kept honest: upstream's
    /// objective really would take the relay here.
    #[test]
    fn fastest_takes_the_relay_when_the_relay_is_faster() {
        assert_eq!(
            decide(PathPolicy::Fastest, Some(SLOW), Some(FAST), false),
            Choice::Relayed
        );
    }

    #[test]
    fn fastest_takes_direct_when_direct_is_faster() {
        assert_eq!(
            decide(PathPolicy::Fastest, Some(FAST), Some(SLOW), false),
            Choice::Direct
        );
    }

    /// A relay is acceptable only when there is genuinely nothing else.
    #[test]
    fn prefer_direct_falls_back_to_a_relay_when_no_direct_path_exists() {
        assert_eq!(
            decide(PathPolicy::PreferDirect, None, Some(FAST), false),
            Choice::Relayed
        );
    }

    /// The promise of `DirectOnceAvailable`: having been direct, it does not go
    /// back, even if that means the connection dies.
    #[test]
    fn direct_once_available_refuses_to_fall_back_to_a_relay() {
        assert_eq!(
            decide(PathPolicy::DirectOnceAvailable, None, Some(FAST), true),
            Choice::KeepCurrent
        );
    }

    /// Before a direct path has ever been established, a relay is how the
    /// connection gets off the ground at all.
    #[test]
    fn direct_once_available_accepts_a_relay_before_going_direct() {
        assert_eq!(
            decide(PathPolicy::DirectOnceAvailable, None, Some(FAST), false),
            Choice::Relayed
        );
    }

    #[test]
    fn direct_once_available_upgrades_to_direct_as_soon_as_one_appears() {
        assert_eq!(
            decide(PathPolicy::DirectOnceAvailable, Some(SLOW), Some(FAST), false),
            Choice::Direct
        );
    }

    /// No candidates at all must never mean "drop the working path".
    #[test]
    fn no_candidates_keeps_the_current_path_under_every_policy() {
        for policy in [
            PathPolicy::Fastest,
            PathPolicy::PreferDirect,
            PathPolicy::DirectOnceAvailable,
        ] {
            assert_eq!(
                decide(policy, None, None, true),
                Choice::KeepCurrent,
                "{policy:?} dropped a working path"
            );
        }
    }

    /// Equal RTTs must not be a coin flip: direct wins ties everywhere.
    #[test]
    fn a_tie_goes_to_the_direct_path() {
        for policy in [
            PathPolicy::Fastest,
            PathPolicy::PreferDirect,
            PathPolicy::DirectOnceAvailable,
        ] {
            assert_eq!(
                decide(policy, Some(FAST), Some(FAST), false),
                Choice::Direct,
                "{policy:?} preferred a relay on a tie"
            );
        }
    }

    #[test]
    fn a_selector_can_be_built_for_every_policy() {
        for policy in [
            PathPolicy::Fastest,
            PathPolicy::PreferDirect,
            PathPolicy::DirectOnceAvailable,
        ] {
            assert_eq!(MetadataResistantSelector::new(policy).policy, policy);
        }
    }
}
