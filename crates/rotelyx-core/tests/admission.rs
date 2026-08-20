//! Admission control over a live connection.
//!
//! The unit tests prove the gate's decisions are right. They do not prove the
//! gate is *consulted*: a policy that is never reached on the accept path is
//! decoration, and this codebase has already shipped that mistake twice. These
//! tests use real sockets so the wiring is what is under test.

use std::time::Duration;

use rotelyx_core::{Admission, Gate, Identity, Invitation, ReachabilityPolicy, RotelyxEndpoint, RotelyxId};
use rotelyx_net::NetConfig;

const EPOCH: u64 = 100;

async fn with_timeout<F, T>(f: F) -> T
where
    F: std::future::Future<Output = T>,
{
    tokio::time::timeout(Duration::from_secs(30), f)
        .await
        .expect("timed out")
}

/// A holder of a live invitation gets in.
#[tokio::test(flavor = "multi_thread")]
async fn an_invited_caller_is_admitted() {
    with_timeout(async {
        let host_id = Identity::generate();
        let caller_id = Identity::generate();

        let invitation = Invitation::issue(EPOCH + 10);
        let proof = invitation.prove(&caller_id.id(), EPOCH);

        let mut gate = Gate::invitation_only();
        gate.add_invitation(invitation);

        let host = RotelyxEndpoint::bind(&host_id, NetConfig::direct_only())
            .await
            .expect("bind host");
        let caller = RotelyxEndpoint::bind(&caller_id, NetConfig::direct_only())
            .await
            .expect("bind caller");

        let addr = host.addr();
        let accept = tokio::spawn(async move {
            let session = host.accept_with(&gate, EPOCH).await;
            let ok = session.is_ok();
            host.close().await;
            ok
        });

        let session = caller
            .connect_with(addr, &Admission::Invitation { proof, epoch: EPOCH })
            .await
            .expect("connect");
        session.close().await;

        assert!(accept.await.expect("join"), "a valid invitation was refused");
        caller.close().await;
    })
    .await;
}

/// The property the whole default rests on: without evidence, a stranger does
/// not get a session. If this ever passes, Rotelyx is an open messenger.
#[tokio::test(flavor = "multi_thread")]
async fn an_uninvited_caller_is_refused() {
    with_timeout(async {
        let host_id = Identity::generate();
        let caller_id = Identity::generate();

        let mut gate = Gate::invitation_only();
        gate.add_invitation(Invitation::issue(EPOCH + 10));

        let host = RotelyxEndpoint::bind(&host_id, NetConfig::direct_only())
            .await
            .expect("bind host");
        let caller = RotelyxEndpoint::bind(&caller_id, NetConfig::direct_only())
            .await
            .expect("bind caller");

        let addr = host.addr();
        let accept = tokio::spawn(async move {
            let refused = host.accept_with(&gate, EPOCH).await.is_err();
            host.close().await;
            refused
        });

        // Present nothing, which is what an uninvited stranger has.
        let session = caller
            .connect_with(addr, &Admission::None)
            .await
            .expect("connect");
        session.close().await;

        assert!(
            accept.await.expect("join"),
            "an uninvited caller reached a session"
        );
        caller.close().await;
    })
    .await;
}

/// A blocked identity is refused even holding a valid invitation, and refused
/// before any verification work happens.
#[tokio::test(flavor = "multi_thread")]
async fn a_blocked_caller_is_refused_over_the_wire() {
    with_timeout(async {
        let host_id = Identity::generate();
        let caller_id = Identity::generate();

        let invitation = Invitation::issue(EPOCH + 10);
        let proof = invitation.prove(&caller_id.id(), EPOCH);

        let mut gate = Gate::invitation_only();
        gate.add_invitation(invitation);
        gate.block(caller_id.id());

        let host = RotelyxEndpoint::bind(&host_id, NetConfig::direct_only())
            .await
            .expect("bind host");
        let caller = RotelyxEndpoint::bind(&caller_id, NetConfig::direct_only())
            .await
            .expect("bind caller");

        let addr = host.addr();
        let accept = tokio::spawn(async move {
            let refused = host.accept_with(&gate, EPOCH).await.is_err();
            host.close().await;
            refused
        });

        let session = caller
            .connect_with(addr, &Admission::Invitation { proof, epoch: EPOCH })
            .await
            .expect("connect");
        session.close().await;

        assert!(
            accept.await.expect("join"),
            "a blocked caller reached a session"
        );
        caller.close().await;
    })
    .await;
}

/// A publicly reachable identity admits a stranger who paid the work.
#[tokio::test(flavor = "multi_thread")]
async fn a_stranger_who_paid_the_work_is_admitted() {
    with_timeout(async {
        let host_id = Identity::generate();
        let caller_id = Identity::generate();

        // Low difficulty: this test measures the wiring, not the CPU.
        let gate = Gate::new(ReachabilityPolicy::ProofOfWork { difficulty: 8 });
        let work = rotelyx_core::solve(&caller_id.id(), &host_id.id(), EPOCH, 8);

        let host = RotelyxEndpoint::bind(&host_id, NetConfig::direct_only())
            .await
            .expect("bind host");
        let caller = RotelyxEndpoint::bind(&caller_id, NetConfig::direct_only())
            .await
            .expect("bind caller");

        let addr = host.addr();
        let accept = tokio::spawn(async move {
            let ok = host.accept_with(&gate, EPOCH).await.is_ok();
            host.close().await;
            ok
        });

        let session = caller
            .connect_with(addr, &Admission::ProofOfWork(work))
            .await
            .expect("connect");
        session.close().await;

        assert!(accept.await.expect("join"), "paid work was refused");
        caller.close().await;
    })
    .await;
}

/// Work solved for one recipient must not open a session with another.
#[tokio::test(flavor = "multi_thread")]
async fn work_solved_for_someone_else_is_refused() {
    with_timeout(async {
        let host_id = Identity::generate();
        let caller_id = Identity::generate();
        let other = Identity::generate();

        let gate = Gate::new(ReachabilityPolicy::ProofOfWork { difficulty: 12 });
        // Solved against a different target.
        let work = rotelyx_core::solve(&caller_id.id(), &other.id(), EPOCH, 12);

        let host = RotelyxEndpoint::bind(&host_id, NetConfig::direct_only())
            .await
            .expect("bind host");
        let caller = RotelyxEndpoint::bind(&caller_id, NetConfig::direct_only())
            .await
            .expect("bind caller");

        let addr = host.addr();
        let accept = tokio::spawn(async move {
            let refused = host.accept_with(&gate, EPOCH).await.is_err();
            host.close().await;
            refused
        });

        let session = caller
            .connect_with(addr, &Admission::ProofOfWork(work))
            .await
            .expect("connect");
        session.close().await;

        assert!(
            accept.await.expect("join"),
            "work solved for another recipient was accepted"
        );
        caller.close().await;
    })
    .await;
}

/// A caller reachable under a key that is not their identity.
///
/// # What this pins
///
/// The relay's disclosure, that it learns which endpoint talks to which, holds
/// only while the transport key and the identity key are the same key. They do
/// not have to be. This binds a caller under a key generated for the session
/// and shows two things at once: the peer the host authenticates is that key
/// and not the caller's identity, and the invitation still admits them.
///
/// # Why the invitation still works
///
/// The proof is a MAC over the caller's transport identity, which is what stops
/// a proof captured on the wire being replayed by somebody else. That argument
/// never needed the key to be permanent. It is computed over the ephemeral key
/// here, and an attacker replaying it would present a different key and fail in
/// exactly the same way.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_can_be_admitted_under_a_key_that_is_not_their_identity() {
    with_timeout(async {
        let host_id = Identity::generate();
        let caller_id = Identity::generate();

        // The key the relay and the host would see. It belongs to nobody.
        let transport = RotelyxEndpoint::ephemeral_transport_key();
        let transport_id: RotelyxId = transport.public().into();

        assert_ne!(
            transport_id,
            caller_id.id(),
            "the ephemeral key is the identity, which defeats the point"
        );

        let invitation = Invitation::issue(EPOCH + 10);
        let proof = invitation.prove(&transport_id, EPOCH);

        let mut gate = Gate::invitation_only();
        gate.add_invitation(invitation);

        let host = RotelyxEndpoint::bind(&host_id, NetConfig::direct_only())
            .await
            .expect("bind host");
        let caller = RotelyxEndpoint::bind_as(&caller_id, transport, NetConfig::direct_only())
            .await
            .expect("bind caller");

        let addr = host.addr();
        let accept = tokio::spawn(async move {
            let session = host.accept_with(&gate, EPOCH).await;
            // What the host authenticated is the transport key, not the identity.
            let seen = session.as_ref().ok().map(|s| s.peer());
            host.close().await;
            seen
        });

        let session = caller
            .connect_with(addr, &Admission::Invitation { proof, epoch: EPOCH })
            .await
            .expect("an invitation proved over the transport key was refused");
        session.close().await;

        let seen = accept.await.expect("join").expect("the host refused");
        assert_eq!(seen, transport_id, "the host saw something other than the key used");
        assert_ne!(seen, caller_id.id(), "the caller's identity reached the wire");

        caller.close().await;
    })
    .await
}
