//! Fails the build if the phone accepts a call the way it accepts a message.
//!
//! # The defect this exists for
//!
//! `NetEndpoint` offers two ways to take an inbound connection, and the
//! difference is written out at `accept_media`: `accept` waits for a
//! bidirectional stream after the handshake, and a call never opens one,
//! because its audio is datagrams.
//!
//! A stream is invisible until it carries a byte. So the dialling phone opened
//! one, wrote nothing into it, completed its own handshake, reported itself
//! connected and started sending audio; and the answering phone sat inside
//! `accept` waiting for a byte that had no reason to come, polled for ten
//! seconds, and told the person that nobody had arrived. Both ends believed
//! something different and neither heard anything.
//!
//! The desktop hit this and `accept_media` was written for it. The phone ABI
//! was never moved across, and nothing failed when it was not: every test of
//! this ABI opens a stream, because every test was written around the
//! messaging path, which is the path where waiting for a stream is right.
//!
//! Measured on two phones before it was fixed: the dialling side reported a
//! connection 3.2 s in, and the accepting side gave up 10 s later having seen
//! nothing, on both sides of two calls in each direction.
//!
//! Read as text rather than exercised, because exercising it needs two
//! endpoints and a relay between them, and this is the kind of fault that gets
//! reintroduced by somebody tidying a call site rather than by somebody
//! rewriting the transport.

use std::fs;

fn net() -> String {
    fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/net.rs"))
        .expect("crates/rotelyx-mobile/src/net.rs")
}

/// The body of `rotelyx_net_accept`, up to its closing brace at column zero.
fn accept_body(source: &str) -> String {
    let start = source
        .find("pub extern \"C\" fn rotelyx_net_accept")
        .expect("rotelyx_net_accept is gone. If accepting moved, this test moves with it.");
    let rest = &source[start..];
    let end = rest.find("\n}\n").map(|i| i + 3).unwrap_or(rest.len());
    rest[..end].to_string()
}

#[test]
fn accepting_waits_for_a_connection_and_not_for_a_stream() {
    let body = accept_body(&net());

    assert!(
        body.contains("accept_media"),
        "rotelyx_net_accept no longer uses accept_media.\n\n\
         The plain `accept` waits for a bidirectional stream, and a call never \
         opens one: its audio is datagrams. The dialler will report itself \
         connected and start sending, this side will wait for a byte that is \
         not coming, and the person will be told the connection did not \
         arrive. See the reasoning at NetEndpoint::accept_media.\n\n\
         What was found in the body:\n{body}"
    );

    // `accept_media` contains `accept`, so a substring test is not enough to
    // catch the plain one coming back beside it.
    let plain = body.matches("transport.accept()").count();
    assert_eq!(
        plain, 0,
        "rotelyx_net_accept calls transport.accept() as well as, or instead \
         of, accept_media. Accepting twice is not a fallback: the first one \
         that waits for a stream holds this side until it times out."
    );
}

#[test]
fn nothing_else_in_this_abi_accepts_for_a_call() {
    let source = net();

    // The ABI has one accept. If a second appears, it has the same decision to
    // make and this test should be told about it rather than pass silently.
    let accepts = source
        .matches("pub extern \"C\" fn rotelyx_net_accept")
        .count();
    assert_eq!(
        accepts, 1,
        "There is now more than one accept in this ABI. Each one has to choose \
         between a stream and a datagram connection, and the wrong choice is \
         silent on both sides."
    );
}
