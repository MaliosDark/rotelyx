//! Admission control, because nothing else was doing it.
//!
//! # What was missing
//!
//! The relay had no rate limit of any kind. `docs/nginx-relay.conf` carries
//! `limit_conn` and `limit_req`, the control panel rejected both, and they were
//! removed from the live configuration while the documents kept claiming them.
//! Measured on 18 August 2026: **35 unique requests in a few seconds, 35
//! answers, not one refusal.** The vendored server declares `accept_conn_limit`
//! and `accept_conn_burst` and says in a comment that neither is implemented.
//!
//! So this is the only place a limit can live, and it lives here rather than in
//! the vendored tree so that re-vendoring cannot silently remove it.
//!
//! # Why this is keyed on identity and not on address
//!
//! The obvious key is the source address, which is what nginx would have used.
//! It is the wrong one: an address is free to change and a relay is exactly the
//! service somebody reaches from many of them.
//!
//! `ClientRequest::endpoint_id` is **proven by the relay handshake** before
//! access control is asked, so a client cannot claim an identity it does not
//! hold the key for. Limiting per identity means an attacker has to generate a
//! new keypair for every slot rather than a new source port.
//!
//! Generating a keypair is also cheap, which is why the global cap below exists
//! and is not decoration: per-identity limits alone are a speed bump for
//! somebody willing to make ten thousand identities. Together they bound both
//! the patient attacker and the loud one.
//!
//! # What this deliberately does not do
//!
//! It does not tell a refused client why. A relay that distinguishes "you are
//! over your limit" from "you are not on the list" is an oracle for the
//! operator's membership, and that membership is a community.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use rotelyx_relay_proto::server::{Access, AccessControl, ClientRequest, ConnectionId};
use rotelyx_net::EndpointId;

/// Concurrent connections one identity may hold.
///
/// A client needs one. More than a handful means either something is retrying
/// without backing off, or somebody is holding sockets open to consume the
/// relay's memory, and both deserve the same answer.
pub const PER_ENDPOINT_CONNECTIONS: usize = 8;

/// New connections one identity may open per minute, sustained.
pub const PER_ENDPOINT_PER_MINUTE: f64 = 30.0;

/// How many it may open at once before the sustained rate applies.
///
/// A client reconnecting after a network change legitimately produces a short
/// burst, so a limit with no burst allowance punishes the ordinary case.
pub const PER_ENDPOINT_BURST: f64 = 10.0;

/// Concurrent connections the relay will hold in total.
///
/// The number that stops ten thousand fresh identities from doing what one
/// identity cannot. Chosen to be far above any plausible real load and far
/// below what would exhaust the machine.
pub const TOTAL_CONNECTIONS: usize = 4096;

/// Idle buckets are forgotten after this, so the table cannot grow without
/// bound from identities that connected once.
const FORGET_AFTER: Duration = Duration::from_secs(600);

#[derive(Debug)]
struct Bucket {
    /// Tokens remaining, in connections.
    tokens: f64,
    /// When the tokens were last refilled.
    refilled: Instant,
    /// Connections currently open for this identity.
    open: usize,
}

#[derive(Debug, Default)]
struct State {
    buckets: HashMap<EndpointId, Bucket>,
    total_open: usize,
    /// Refusals, for the operator to see. Not per identity: a count of who was
    /// refused is a list of who tried.
    refused_rate: u64,
    refused_concurrent: u64,
    refused_total: u64,
}

/// Wraps any access control with limits.
///
/// Composes rather than replaces, so the allowlist and the open relay get the
/// same protection and neither has to know about it. The inner decision runs
/// **first**: an identity that is not permitted should be refused for that
/// reason and should not consume a rate limit slot on the way.
#[derive(Debug)]
pub struct Limited<A> {
    inner: A,
    state: Arc<Mutex<State>>,
}

/// A read-only handle on the counters, separate from the limiter itself.
///
/// The limiter goes into an `Arc<dyn DynAccessControl>` the moment it is
/// installed, and a trait object has no `refusals()` on it. Without a handle
/// taken beforehand the counters are unreachable for the life of the process,
/// which is exactly what happened: they were incremented on every refusal and
/// read by nobody.
///
/// Cloneable and cheap, so an operator-facing task can hold one without
/// affecting admission.
#[derive(Debug, Clone)]
pub struct Counters {
    state: Arc<Mutex<State>>,
}

impl Counters {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Refusals so far, by kind: rate, concurrent, total.
    pub fn refusals(&self) -> (u64, u64, u64) {
        let s = self.lock();
        (s.refused_rate, s.refused_concurrent, s.refused_total)
    }

    /// Connections currently open.
    pub fn open(&self) -> usize {
        self.lock().total_open
    }
}

impl<A> Limited<A> {
    pub fn new(inner: A) -> Self {
        Self {
            inner,
            state: Arc::new(Mutex::new(State::default())),
        }
    }

    /// Take a handle on the counters before installing the limiter.
    ///
    /// Must be called before the limiter is moved into the access-control
    /// trait object, because afterwards there is no way back to this type.
    pub fn counters(&self) -> Counters {
        Counters {
            state: Arc::clone(&self.state),
        }
    }

    /// A poisoned lock means a previous call panicked while holding it.
    ///
    /// Recovered rather than propagated. The alternative is that one panic
    /// makes the relay refuse every connection for the rest of its life, which
    /// turns a bug into an outage. The state behind it is counters and a map.
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        match self.state.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Decide, and record. Split out so it can be tested without a server.
    fn admit(&self, endpoint: EndpointId, now: Instant) -> bool {
        let mut s = self.lock();

        if s.total_open >= TOTAL_CONNECTIONS {
            s.refused_total += 1;
            return false;
        }

        // Forget identities that have been idle and are not holding anything.
        // Done here rather than on a timer: a relay with no traffic does not
        // need to wake up to tidy, and one with traffic tidies as it goes.
        if s.buckets.len() > 1024 {
            s.buckets
                .retain(|_, b| b.open > 0 || now.duration_since(b.refilled) < FORGET_AFTER);
        }

        let bucket = s.buckets.entry(endpoint).or_insert(Bucket {
            tokens: PER_ENDPOINT_BURST,
            refilled: now,
            open: 0,
        });

        // Refill for the time that has passed, capped at the burst size.
        let elapsed = now.duration_since(bucket.refilled).as_secs_f64();
        bucket.tokens =
            (bucket.tokens + elapsed * PER_ENDPOINT_PER_MINUTE / 60.0).min(PER_ENDPOINT_BURST);
        bucket.refilled = now;

        if bucket.open >= PER_ENDPOINT_CONNECTIONS {
            s.refused_concurrent += 1;
            return false;
        }
        if bucket.tokens < 1.0 {
            s.refused_rate += 1;
            return false;
        }

        bucket.tokens -= 1.0;
        bucket.open += 1;
        s.total_open += 1;
        true
    }

    fn released(&self, endpoint: EndpointId) {
        let mut s = self.lock();
        s.total_open = s.total_open.saturating_sub(1);
        if let Some(b) = s.buckets.get_mut(&endpoint) {
            b.open = b.open.saturating_sub(1);
        }
    }
}

impl<A: AccessControl> AccessControl for Limited<A> {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        // The inner decision first. Somebody who is not permitted at all should
        // not be able to exhaust a rate limit slot by being refused.
        let inner = self.inner.on_connect(request).await;
        if !matches!(inner, Access::Allow) {
            return inner;
        }

        if self.admit(request.endpoint_id(), Instant::now()) {
            Access::Allow
        } else {
            // Same vague reason the allowlist gives, and for the same purpose:
            // distinguishing "over your limit" from "not on the list" tells a
            // caller which identities the operator serves.
            Access::Deny {
                reason: Some("not permitted".into()),
            }
        }
    }

    fn on_disconnect(&self, endpoint_id: EndpointId, _connection_id: ConnectionId) {
        self.released(endpoint_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rotelyx_net::SecretKey;

    #[derive(Debug)]
    struct Yes;
    impl AccessControl for Yes {
        async fn on_connect(&self, _: &ClientRequest) -> Access {
            Access::Allow
        }
        fn on_disconnect(&self, _: EndpointId, _: ConnectionId) {}
    }

    fn id(seed: u8) -> EndpointId {
        SecretKey::from_bytes(&[seed; 32]).public()
    }

    /// The burst is allowed, and then the sustained rate applies.
    #[test]
    fn a_burst_is_allowed_and_then_it_is_not() {
        let limiter = Limited::new(Yes);
        let who = id(1);
        let now = Instant::now();

        for n in 0..PER_ENDPOINT_BURST as usize {
            assert!(limiter.admit(who, now), "connection {n} within the burst");
            limiter.released(who);
        }
        assert!(
            !limiter.admit(who, now),
            "the burst is spent and no time has passed"
        );
        assert_eq!(limiter.counters().refusals().0, 1, "refused for rate");
    }

    /// Tokens come back with time, or a client that hits the limit once is
    /// locked out for ever.
    #[test]
    fn tokens_refill() {
        let limiter = Limited::new(Yes);
        let who = id(2);
        let start = Instant::now();

        for _ in 0..PER_ENDPOINT_BURST as usize {
            limiter.admit(who, start);
            limiter.released(who);
        }
        assert!(!limiter.admit(who, start));

        // Two seconds at 30 a minute is one token.
        let later = start + Duration::from_secs(2);
        assert!(limiter.admit(who, later), "a token should have refilled");
    }

    /// Holding connections open is limited separately from opening them, or an
    /// attacker with patience gets around the rate by going slowly.
    #[test]
    fn concurrent_connections_are_capped() {
        let limiter = Limited::new(Yes);
        let who = id(3);
        let mut now = Instant::now();

        for n in 0..PER_ENDPOINT_CONNECTIONS {
            // Spread out in time so the rate limit is never the thing refusing.
            now += Duration::from_secs(10);
            assert!(limiter.admit(who, now), "connection {n} held open");
        }
        now += Duration::from_secs(60);
        assert!(
            !limiter.admit(who, now),
            "the ninth concurrent connection, with rate to spare"
        );
        assert_eq!(limiter.counters().refusals().1, 1, "refused for concurrency");

        limiter.released(who);
        assert!(limiter.admit(who, now), "a slot freed is a slot usable");
    }

    /// One identity's limit must not be another's.
    #[test]
    fn identities_are_independent() {
        let limiter = Limited::new(Yes);
        let now = Instant::now();

        for _ in 0..PER_ENDPOINT_BURST as usize {
            limiter.admit(id(4), now);
            limiter.released(id(4));
        }
        assert!(!limiter.admit(id(4), now));
        assert!(limiter.admit(id(5), now), "a different identity is unaffected");
    }

    /// The global cap is what stops ten thousand fresh identities.
    ///
    /// A keypair costs nothing to generate, so a per-identity limit alone is a
    /// speed bump. This is the part that bounds the attacker who is willing to
    /// make as many as it takes.
    #[test]
    fn the_total_cap_stops_what_per_identity_limits_cannot() {
        let limiter = Limited::new(Yes);
        let now = Instant::now();

        // Every one of these is a distinct identity holding a single
        // connection, so no per-identity limit is ever reached.
        for n in 0..TOTAL_CONNECTIONS {
            let who = SecretKey::from_bytes(&{
                let mut b = [0u8; 32];
                b[..8].copy_from_slice(&(n as u64).to_le_bytes());
                b
            })
            .public();
            assert!(limiter.admit(who, now), "identity {n} of the cap");
        }
        assert_eq!(limiter.counters().open(), TOTAL_CONNECTIONS);

        let one_more = SecretKey::from_bytes(&[0xff; 32]).public();
        assert!(!limiter.admit(one_more, now), "the cap must hold");
        assert_eq!(limiter.counters().refusals().2, 1, "refused for the total");
    }

    /// Through `on_connect` and `on_disconnect`, which is what the server calls.
    ///
    /// Every other test here drives `admit` directly, so all of them would pass
    /// with the limiter wired to nothing. This is the one that fails if the
    /// trait implementation forgets to consult it, or if `on_disconnect` never
    /// gives the slot back.
    #[tokio::test]
    async fn the_trait_the_server_uses_is_actually_wired() {
        use rotelyx_relay_proto::http::ProtocolVersion;

        let limiter = Limited::new(Yes);
        let who = id(7);

        let request = || {
            let (parts, _) = http::Request::builder()
                .uri("/relay")
                .body(())
                .expect("a request")
                .into_parts();
            ClientRequest::new(who, ProtocolVersion::V2, parts)
        };

        // Opened and held, so the concurrency cap is what bites rather than the
        // rate: 8 held open against a burst allowance of 10. Which limit fires
        // first depends on whether the client hangs up, and both are meant to.
        let mut ids = Vec::new();
        for n in 0..PER_ENDPOINT_CONNECTIONS {
            let r = request();
            let connection = r.connection_id();
            assert!(
                matches!(limiter.on_connect(&r).await, Access::Allow),
                "connection {n} was refused before the cap"
            );
            ids.push(connection);
        }
        assert_eq!(limiter.counters().open(), PER_ENDPOINT_CONNECTIONS);

        // And one past it.
        assert!(
            matches!(limiter.on_connect(&request()).await, Access::Deny { .. }),
            "the cap is reached and the limiter was not consulted"
        );
        assert_eq!(limiter.counters().refusals().1, 1, "refused for concurrency, not rate");

        // Disconnecting must return the slot. If it does not, a busy relay
        // refuses everybody for ever after a few minutes of ordinary use, which
        // is a worse outage than having no limit at all.
        for connection in ids {
            limiter.on_disconnect(who, connection);
        }
        assert_eq!(limiter.counters().open(), 0, "every slot must come back");
    }

    /// An identity the inner control refuses must not consume a rate slot.
    ///
    /// Otherwise anybody can exhaust an allowlisted user's budget by connecting
    /// as them, which they can do because an endpoint id is public.
    #[tokio::test]
    async fn a_refused_identity_costs_nothing() {
        use rotelyx_relay_proto::http::ProtocolVersion;

        #[derive(Debug)]
        struct No;
        impl AccessControl for No {
            async fn on_connect(&self, _: &ClientRequest) -> Access {
                Access::Deny { reason: None }
            }
            fn on_disconnect(&self, _: EndpointId, _: ConnectionId) {}
        }

        let limiter = Limited::new(No);
        for _ in 0..(PER_ENDPOINT_BURST as usize * 3) {
            let (parts, _) = http::Request::builder().uri("/relay").body(()).unwrap().into_parts();
            let r = ClientRequest::new(id(8), ProtocolVersion::V2, parts);
            assert!(matches!(limiter.on_connect(&r).await, Access::Deny { .. }));
        }
        assert_eq!(limiter.counters().open(), 0, "nothing was admitted");
        assert_eq!(
            limiter.counters().refusals(),
            (0, 0, 0),
            "a refusal by the inner control must not be counted as a limit"
        );
    }

    /// The table must not grow for ever from identities that connected once.
    #[test]
    fn idle_identities_are_forgotten() {
        let limiter = Limited::new(Yes);
        let start = Instant::now();

        for n in 0..1200u64 {
            let who = SecretKey::from_bytes(&{
                let mut b = [0u8; 32];
                b[..8].copy_from_slice(&n.to_le_bytes());
                b
            })
            .public();
            limiter.admit(who, start);
            limiter.released(who);
        }
        assert!(limiter.lock().buckets.len() > 1000, "they are all recorded");

        // Long enough later that everything idle is forgotten, and one more
        // connection to trigger the sweep.
        let later = start + FORGET_AFTER + Duration::from_secs(1);
        limiter.admit(id(9), later);
        assert!(
            limiter.lock().buckets.len() < 100,
            "idle buckets should have been swept, {} remain",
            limiter.lock().buckets.len()
        );
    }
}
