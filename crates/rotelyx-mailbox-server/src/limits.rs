//! Per-address admission control, because nothing in front is doing it.
//!
//! # Why this is not in the reverse proxy
//!
//! It was meant to be. `docs/nginx-relay.conf` carries `limit_conn` and
//! `limit_req`, the control panel rejected both, and they were removed from the
//! live configuration while the documents went on claiming them. Measured on
//! 18 August 2026 and again on 23 August: dozens of requests in a few seconds,
//! dozens of answers, not one refusal.
//!
//! The deeper reason is that a proxy is not always there. Somebody running this
//! server on their own machine has no nginx, no control panel and no Cloudflare,
//! and a limit that only exists in a configuration file most operators will
//! never write is a limit most deployments do not have. So it lives here, in the
//! only place that is present in every deployment.
//!
//! # Why the address, when the relay uses an identity
//!
//! `rotelyx-relay::limits` keys on the endpoint identity, which the relay
//! handshake proves before access control is asked. This server has no such
//! thing at the moment a socket opens, and that is the whole point: the caller
//! this bounds is the one that opens sockets and deposits nothing, so it never
//! presents a token and never gets metered. The address is what exists.
//!
//! It is keyed on the **address**, not the address and port. A fresh connection
//! gets a fresh source port, so keying on the pair would give every connection
//! its own bucket and limit nothing at all.
//!
//! # What an address is worth, said plainly
//!
//! Less than an identity. Addresses are shared by everyone behind one NAT and
//! they are cheap for an attacker with a subnet. This does not stop a determined
//! attacker and is not meant to; it stops one host holding sockets open until
//! the server runs out, and it makes the loud case cost something. The total cap
//! is what bounds the patient one.
//!
//! # Behind a proxy
//!
//! If something forwards to this server, every connection arrives from that
//! something, and keying on the address would put every user in the world in one
//! bucket. Then the first abuser locks out everybody, which is worse than having
//! no limit.
//!
//! So a forwarded address is used only when the operator has named the proxy it
//! must come from, with `--trusted-proxy`. Without that the header is ignored,
//! because a header is written by whoever is talking to us and trusting it by
//! default would let any caller claim a fresh address per connection and walk
//! straight through this file.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Concurrent connections one address may hold.
///
/// A client needs one. A household behind one address might need a handful.
/// Beyond that it is either something retrying without backing off or somebody
/// holding sockets to consume memory, and both deserve the same answer.
pub const PER_ADDRESS_CONNECTIONS: usize = 16;

/// New connections one address may open per minute, sustained.
pub const PER_ADDRESS_PER_MINUTE: f64 = 60.0;

/// How many it may open at once before the sustained rate applies.
///
/// A client reconnecting after a network change legitimately produces a short
/// burst, so a limit with no burst allowance punishes the ordinary case.
pub const PER_ADDRESS_BURST: f64 = 20.0;

/// Concurrent connections this server will hold in total, by default.
///
/// The number that stops ten thousand addresses doing what one address cannot.
/// Refusing at a ceiling is the honest failure; running out of descriptors is
/// the same denial arriving later and taking the accepted connections with it.
///
/// This is a default, not a wall. A connection costs about 16 KB of memory and
/// one file descriptor, measured, so a machine with a few gigabytes and a
/// raised descriptor limit holds hundreds of thousands. The earlier default of
/// 4096 was a conservative floor from before that was measured; it capped a
/// mailbox at a few hundred devices for no reason the hardware required. An
/// operator sets `--max-connections` to their machine's real capacity, and a
/// small machine such as a relay host sets it low. See `docs/DEPLOYMENT.md`.
pub const TOTAL_CONNECTIONS: usize = 131_072;

/// Idle buckets are forgotten after this, so the table cannot grow without
/// bound from addresses that connected once.
const FORGET_AFTER: Duration = Duration::from_secs(600);

/// Why a connection was refused. Never told to the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// Too many connections open from this address.
    Concurrent,
    /// This address is opening them too fast.
    Rate,
    /// The server is full, whoever is asking.
    Total,
}

struct Bucket {
    /// Tokens remaining, in connections.
    tokens: f64,
    /// When the tokens were last refilled.
    refilled: Instant,
    /// Connections currently open from this address.
    open: usize,
}

#[derive(Default)]
struct State {
    buckets: HashMap<IpAddr, Bucket>,
    total_open: usize,
    /// Refusals, for the operator to see. Not per address: a count of who was
    /// refused is a list of who tried.
    refused_rate: u64,
    refused_concurrent: u64,
    refused_total: u64,
}

/// Per-address limits, shared across every connection.
#[derive(Clone)]
pub struct Limits {
    state: Arc<Mutex<State>>,
    /// The total this server will hold, from `--max-connections` or the
    /// default. Kept here rather than read from the constant so a small
    /// machine can be told a small number.
    max_total: usize,
    /// Addresses the per-address limits do not apply to. The total still does.
    ///
    /// For a load test run from one machine, which is one address opening
    /// hundreds of sockets on purpose, and for nothing else: an exemption is
    /// exactly the hole this file exists to close, so it is named on the
    /// command line by the operator, per address, and it is expected to be
    /// taken away again. Nothing here makes it permanent or discoverable.
    exempt: Arc<Vec<IpAddr>>,
}

/// A slot held for as long as a connection is open.
///
/// Released on drop rather than by the handler calling something, because a
/// handler that returns early, panics, or is cancelled mid-await still has to
/// give the slot back. Every one of those happens on a websocket.
pub struct Slot {
    limits: Limits,
    address: IpAddr,
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut state = self.limits.lock();
        state.total_open = state.total_open.saturating_sub(1);
        if let Some(bucket) = state.buckets.get_mut(&self.address) {
            bucket.open = bucket.open.saturating_sub(1);
        }
    }
}

impl Limits {
    #[cfg(test)]
    pub fn new() -> Self {
        Self::with_max(Vec::new(), TOTAL_CONNECTIONS)
    }

    /// The limits, with these addresses excused from the per-address ones and
    /// the total this server will hold named explicitly.
    pub fn with_max(addresses: Vec<IpAddr>, max_total: usize) -> Self {
        Self {
            state: Arc::default(),
            exempt: Arc::new(addresses),
            max_total: max_total.max(1),
        }
    }

    /// A poisoned lock means a previous call panicked while holding it.
    ///
    /// Recovered rather than propagated, because the alternative is that one
    /// panic makes the server refuse every connection for the rest of its life.
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Take a slot for a connection from `address`, or say why not.
    pub fn admit(&self, address: IpAddr) -> Result<Slot, Refusal> {
        let now = Instant::now();
        let mut state = self.lock();

        if state.total_open >= self.max_total {
            state.refused_total += 1;
            return Err(Refusal::Total);
        }
        // Excused from the per-address limits, and counted against the total
        // like everybody, because the total is what protects the server.
        if self.exempt.contains(&address) {
            state.total_open += 1;
            return Ok(Slot {
                limits: self.clone(),
                address,
            });
        }

        // Swept here rather than on a timer: the table only grows when somebody
        // connects, so that is the only moment it can need shrinking.
        state
            .buckets
            .retain(|_, b| b.open > 0 || now.duration_since(b.refilled) < FORGET_AFTER);

        let bucket = state.buckets.entry(address).or_insert(Bucket {
            tokens: PER_ADDRESS_BURST,
            refilled: now,
            open: 0,
        });

        let elapsed = now.duration_since(bucket.refilled).as_secs_f64();
        bucket.tokens =
            (bucket.tokens + elapsed * PER_ADDRESS_PER_MINUTE / 60.0).min(PER_ADDRESS_BURST);
        bucket.refilled = now;

        if bucket.open >= PER_ADDRESS_CONNECTIONS {
            state.refused_concurrent += 1;
            return Err(Refusal::Concurrent);
        }
        if bucket.tokens < 1.0 {
            state.refused_rate += 1;
            return Err(Refusal::Rate);
        }

        bucket.tokens -= 1.0;
        bucket.open += 1;
        state.total_open += 1;

        Ok(Slot {
            limits: self.clone(),
            address,
        })
    }

    /// Refusals so far, by kind: rate, concurrent, total.
    pub fn refusals(&self) -> (u64, u64, u64) {
        let state = self.lock();
        (
            state.refused_rate,
            state.refused_concurrent,
            state.refused_total,
        )
    }

    // Deliberately no public `open()`. The server already keeps that count, with
    // a guard that decrements it on drop, and two counters for one quantity is
    // how they come to disagree. This one exists for the admission decision and
    // stays inside.
}

/// Which address to hold a connection against.
///
/// The socket's peer, unless it is a proxy the operator named, in which case the
/// address that proxy says it is forwarding for. Never the header on its own:
/// see the module note.
pub fn client_address(peer: IpAddr, trusted_proxies: &[IpAddr], forwarded: Option<&str>) -> IpAddr {
    if !trusted_proxies.contains(&peer) {
        return peer;
    }

    // `X-Forwarded-For` is a list, appended to by each hop. The right-most entry
    // is the one our trusted proxy wrote; everything to its left was written by
    // somebody further out and can say anything.
    forwarded
        .and_then(|value| value.rsplit(',').next())
        .map(str::trim)
        .and_then(|s| s.parse().ok())
        .unwrap_or(peer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(last: u8) -> IpAddr {
        IpAddr::from([203, 0, 113, last])
    }

    #[test]
    fn one_address_cannot_hold_every_socket() {
        let limits = Limits::new();
        let mut held = Vec::new();
        for _ in 0..PER_ADDRESS_CONNECTIONS {
            held.push(limits.admit(address(1)).expect("under the limit"));
        }
        assert_eq!(
            limits.admit(address(1)).err(),
            Some(Refusal::Concurrent),
            "one address held more sockets than the limit allows"
        );
        assert_eq!(held.len(), PER_ADDRESS_CONNECTIONS);
    }

    #[test]
    fn a_slot_comes_back_when_the_connection_closes() {
        let limits = Limits::new();
        let held: Vec<Slot> = (0..PER_ADDRESS_CONNECTIONS)
            .map(|_| limits.admit(address(2)).expect("under the limit"))
            .collect();
        assert!(limits.admit(address(2)).is_err());

        drop(held);
        assert!(
            limits.admit(address(2)).is_ok(),
            "an address stayed refused after its connections closed"
        );
    }

    /// The property the whole file exists for, and the one a per-socket key
    /// would silently fail: one address must not spend everybody's budget.
    #[test]
    fn an_exempt_address_is_held_to_the_total_and_nothing_else() {
        let tester: IpAddr = "10.0.0.9".parse().unwrap();
        let limits = Limits::with_max(vec![tester], TOTAL_CONNECTIONS);
        let mut held = Vec::new();
        // Well past both per-address limits, in one burst.
        for _ in 0..(PER_ADDRESS_CONNECTIONS * 4) {
            held.push(limits.admit(tester).expect("exempt, so admitted"));
        }
        // And somebody else is still limited exactly as before.
        let other: IpAddr = "10.0.0.10".parse().unwrap();
        let mut theirs = Vec::new();
        for _ in 0..PER_ADDRESS_CONNECTIONS {
            theirs.push(limits.admit(other).expect("within the limit"));
        }
        assert!(matches!(limits.admit(other), Err(Refusal::Concurrent)));
        // Letting go counts down for the exempt address too.
        drop(held);
        assert_eq!(limits.lock().total_open, PER_ADDRESS_CONNECTIONS);
    }

    #[test]
    fn one_address_running_out_does_not_refuse_another() {
        let limits = Limits::new();
        let _held: Vec<Slot> = (0..PER_ADDRESS_CONNECTIONS)
            .map(|_| limits.admit(address(3)).expect("under the limit"))
            .collect();
        assert!(limits.admit(address(3)).is_err());
        assert!(
            limits.admit(address(4)).is_ok(),
            "a second address was refused for the first one's spending"
        );
    }

    #[test]
    fn opening_and_closing_in_a_loop_is_still_a_rate() {
        let limits = Limits::new();
        // Each connection is closed immediately, so the concurrent limit never
        // bites and only the rate can refuse this.
        let mut admitted = 0;
        for _ in 0..(PER_ADDRESS_BURST as usize + 10) {
            match limits.admit(address(5)) {
                Ok(slot) => {
                    drop(slot);
                    admitted += 1;
                }
                Err(Refusal::Rate) => break,
                Err(other) => panic!("refused for {other:?} rather than the rate"),
            }
        }
        assert_eq!(
            admitted, PER_ADDRESS_BURST as usize,
            "the burst allowance is not the number of connections it allows"
        );
    }

    #[test]
    fn a_header_is_ignored_unless_the_proxy_is_named() {
        let peer: IpAddr = "198.51.100.7".parse().unwrap();
        let claimed = Some("203.0.113.9");

        assert_eq!(
            client_address(peer, &[], claimed),
            peer,
            "an untrusted caller renamed itself by writing a header"
        );
        assert_eq!(
            client_address(peer, &[peer], claimed),
            "203.0.113.9".parse::<IpAddr>().unwrap(),
        );
    }

    /// Only the hop our own proxy wrote can be believed.
    #[test]
    fn only_the_last_hop_in_a_forwarded_chain_counts() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        // The left entry is whatever the caller sent; the right is what the
        // trusted proxy appended.
        let chain = Some("10.0.0.1, 203.0.113.9");
        assert_eq!(
            client_address(peer, &[peer], chain),
            "203.0.113.9".parse::<IpAddr>().unwrap(),
        );
    }

    #[test]
    fn a_malformed_header_falls_back_to_the_socket() {
        let peer: IpAddr = "127.0.0.1".parse().unwrap();
        assert_eq!(client_address(peer, &[peer], Some("not-an-address")), peer);
        assert_eq!(client_address(peer, &[peer], None), peer);
    }
}
