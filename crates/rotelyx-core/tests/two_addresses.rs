//! End-to-end: does one listener really answer at several addresses?
//!
//! An invitation carries an address of its own so that two people invited by
//! the same host cannot be told they were invited by the same host. That claim
//! is only worth something if a caller dialling one invitation's address never
//! learns the address of any other, and if the host can still answer all of
//! them at once.
//!
//! These tests assert those properties rather than that a connection happened.
//! "It connected" says nothing about who could see what.

use std::time::Duration;

use rotelyx_core::{Frame, FrameKind, Identity, RotelyxEndpoint};
use rotelyx_net::{EndpointAddr, NetConfig};

/// The host, its primary address, and a second address it also answers on.
async fn host_with_two_addresses() -> (RotelyxEndpoint, EndpointAddr, EndpointAddr) {
    let identity = Identity::generate();

    // Two unrelated transport keys. Nothing derives one from the other, so
    // neither is evidence about the other even to somebody holding both.
    let first = RotelyxEndpoint::ephemeral_transport_key();
    let second = RotelyxEndpoint::ephemeral_transport_key();

    let host = RotelyxEndpoint::bind_as(&identity, first, NetConfig::direct_only())
        .await
        .expect("binding the host");
    // Direct only, so there is no relay to ask: the answering half is what is
    // under test here, and the reachability half is the relay's, tested there.
    let _ = host.also_answer_as(&second);

    let primary = host.addr();
    // The same socket, a different name for it.
    let alias = EndpointAddr::from_parts(second.public(), primary.addrs.iter().cloned());
    (host, primary, alias)
}

#[tokio::test]
async fn a_caller_dialling_the_second_address_is_answered_there() {
    let (host, _primary, alias) = host_with_two_addresses().await;
    let expected = alias.id;

    let accepting = tokio::spawn(async move {
        let session = host.accept().await.expect("accepting");
        session.peer()
    });

    let caller = RotelyxEndpoint::bind(&Identity::generate(), NetConfig::direct_only())
        .await
        .expect("binding the caller");
    let session = tokio::time::timeout(Duration::from_secs(20), caller.connect(alias))
        .await
        .expect("connecting timed out")
        .expect("connecting");

    // The TLS half: the host produced a key for the name that was dialled.
    // Had the resolver fallen back to its primary key, authentication would
    // have failed here, because a caller pins the id it dialled.
    assert_eq!(
        session.peer().as_bytes(),
        expected.as_bytes(),
        "the caller must be talking to the address it dialled, not to the host's primary key",
    );

    session.close().await;
    accepting.await.expect("the host task panicked");
}

#[tokio::test]
async fn neither_caller_learns_the_other_address() {
    let (host, primary, alias) = host_with_two_addresses().await;
    let (first_id, second_id) = (primary.id, alias.id);
    assert_ne!(
        first_id.as_bytes(),
        second_id.as_bytes(),
        "the two invitations must not share an address, or there is nothing to test",
    );

    // Callers are served one at a time on purpose.
    //
    // `accept` waits for the caller's first stream before returning, so a host
    // sitting in one accept does not take the next connection off the queue.
    // Answering at several addresses makes the host *reachable* at all of them;
    // serving several conversations at once is a separate thing this endpoint
    // does not do, and a test that pretended otherwise would deadlock rather
    // than tell the truth about it.
    let mut seen = Vec::new();
    for addr in [primary, alias] {
        let expected = addr.id;
        let caller = RotelyxEndpoint::bind(&Identity::generate(), NetConfig::direct_only())
            .await
            .expect("binding the caller");
        // Both sides have to run at once: a dial does not finish until the
        // host takes the connection off its queue, and the host does not
        // finish accepting until the caller opens a stream on it.
        let calling = async {
            let mut session = caller.connect(addr).await.expect("connecting");
            session
                .send(&Frame::new(FrameKind::Admission, b"hello".to_vec()))
                .await
                .expect("sending");
            session
        };
        let answering = async {
            let mut served = host.accept().await.expect("accepting");
            let frame = served.recv().await.expect("reading the frame");
            (served, frame)
        };
        let (session, (served, frame)) = tokio::time::timeout(
            Duration::from_secs(20),
            futures_lite::future::zip(calling, answering),
        )
        .await
        .expect("the call did not complete in time");

        // Each caller's whole view of the far side is the address it was given.
        assert_eq!(
            session.peer().as_bytes(),
            expected.as_bytes(),
            "a caller must see the address it dialled and nothing else",
        );
        assert_eq!(frame.payload, b"hello");

        seen.push(served.peer());
        session.close().await;
        served.close().await;
    }

    // The host really did serve both addresses on one endpoint, and it saw two
    // different callers rather than one counted twice.
    assert_eq!(seen.len(), 2);
    assert_ne!(seen[0].as_bytes(), seen[1].as_bytes());
}
