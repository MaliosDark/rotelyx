//! Two people pair and talk, entirely through the C boundary.
//!
//! Not through the Rust API underneath it: every call in this file goes out as
//! a JSON string through `rotelyx_call` and comes back as a JSON string, which
//! is the exact path a Flutter app takes. A test that used the Rust types
//! directly would pass while the boundary was broken, and the boundary is the
//! only new thing in this crate.

use serde_json::{json, Value};
use std::ffi::{CStr, CString};

/// One request through the real FFI entry point.
fn call(request: Value) -> Result<Value, String> {
    let text = CString::new(request.to_string()).expect("no NUL in JSON");
    let mut response: *mut std::ffi::c_char = std::ptr::null_mut();

    let code = unsafe { rotelyx_mobile::rotelyx_call(text.as_ptr(), &mut response) };
    assert!(!response.is_null(), "a response is always returned");

    let reply: Value = unsafe {
        let s = CStr::from_ptr(response).to_str().expect("UTF-8").to_string();
        rotelyx_mobile::rotelyx_string_free(response);
        serde_json::from_str(&s).expect("the reply is JSON")
    };

    // The status code and the body must agree. A wrapper that trusts one and
    // not the other is a wrapper that will eventually read a result out of an
    // error, so this is asserted on every single call rather than once.
    let ok = reply["ok"].as_bool().expect("`ok` is a bool");
    assert_eq!(
        ok,
        code == 0,
        "return code {code} disagrees with the body: {reply}"
    );

    if ok {
        Ok(reply["result"].clone())
    } else {
        Err(reply["error"].as_str().unwrap_or("?").to_string())
    }
}

fn ok(request: Value) -> Value {
    call(request).expect("call failed")
}

fn text(request: Value) -> String {
    ok(request).as_str().expect("a string").to_string()
}

fn handle(request: Value) -> u64 {
    ok(request).as_u64().expect("a handle")
}

#[test]
fn two_people_pair_and_talk() {
    assert_eq!(text(json!({"op": "abi.version"})), "1");
    assert!(!text(json!({"op": "protocol.version"})).is_empty());

    let ana = handle(json!({"op": "session.new", "label": "ana"}));
    let beto = handle(json!({"op": "session.new", "label": "beto"}));
    assert_ne!(ana, beto, "handles must be distinct");

    // Ana starts a conversation; Beto offers a key package; Ana invites him.
    ok(json!({"op": "session.found", "handle": ana}));
    let package = text(json!({"op": "session.keyPackage", "handle": beto}));

    let invitation = ok(json!({
        "op": "session.invite", "handle": ana, "keyPackage": package
    }));
    let welcome = invitation["welcome"].as_str().expect("welcome").to_string();
    let tree = invitation["ratchetTree"].as_str().expect("tree").to_string();

    ok(json!({
        "op": "session.join", "handle": beto,
        "welcome": welcome, "ratchetTree": tree
    }));

    // The post-quantum secret, which is the part that makes this hybrid rather
    // than merely modern.
    let beto_pk = text(json!({"op": "session.hybridPublicKey", "handle": beto}));
    let ciphertext = text(json!({
        "op": "session.encapsulateTo", "handle": ana, "hybridPublicKey": beto_pk
    }));
    ok(json!({"op": "session.openPq", "handle": beto, "ciphertext": ciphertext}));

    let commit = text(json!({"op": "session.commitPq", "handle": ana}));
    let applied = ok(json!({"op": "session.receive", "handle": beto, "message": commit}));
    // A commit says which of three things it was, not "not a message".
    //
    // This asserted null, which the boundary returned for a member joining, a
    // routine rekey and a message the group did not recognise alike. An
    // application on the other side of this boundary cannot warn about a third
    // party arriving if it is handed the same value for all three, and warning
    // about it is a security control rather than a nicety: see ADV-7.
    assert_eq!(
        applied["kind"], "nothing",
        "mixing in a post-quantum secret moved nobody in or out, and was \
         reported as {applied}"
    );

    // Both sides agree on who is present and on which epoch they are in. If
    // these differ, everything below would still appear to work and the
    // messages would be unreadable, which is the failure this catches.
    let (ana_epoch, beto_epoch) = (
        ok(json!({"op": "session.epoch", "handle": ana})),
        ok(json!({"op": "session.epoch", "handle": beto})),
    );
    assert_eq!(ana_epoch, beto_epoch, "the two sides are in different epochs");
    assert_eq!(ok(json!({"op": "session.memberCount", "handle": ana})), json!(2));
    assert_eq!(ok(json!({"op": "session.memberCount", "handle": beto})), json!(2));

    // The safety number is what a person reads aloud to check for a middle.
    let ana_safety = text(json!({"op": "session.safetyNumber", "handle": ana}));
    let beto_safety = text(json!({"op": "session.safetyNumber", "handle": beto}));
    assert_eq!(ana_safety, beto_safety, "safety numbers must match");
    assert!(!ana_safety.is_empty());

    // A message each way.
    let sealed = text(json!({"op": "session.send", "handle": ana, "text": "hello from ana"}));
    let heard = ok(json!({"op": "session.receive", "handle": beto, "message": sealed}));
    assert_eq!(heard["kind"], "message");
    assert_eq!(heard["text"], "hello from ana");

    let sealed = text(json!({"op": "session.send", "handle": beto, "text": "hello back"}));
    let heard = ok(json!({"op": "session.receive", "handle": ana, "message": sealed}));
    assert_eq!(heard["kind"], "message");
    assert_eq!(heard["text"], "hello back");

    // And the mailbox layer: tags, sealing, opening.
    let bucket = 1_000_000u64;
    let tags = ok(json!({
        "op": "session.recipientTags", "handle": ana, "timeBucket": bucket
    }));
    assert!(!tags.as_array().expect("array").is_empty());

    ok(json!({"op": "session.free", "handle": ana}));
    ok(json!({"op": "session.free", "handle": beto}));
}

#[test]
fn a_session_survives_being_sealed_and_reopened() {
    let key = handle(json!({"op": "key.create", "passphrase": "a long enough passphrase"}));
    let session = handle(json!({"op": "session.new", "label": "ana"}));
    ok(json!({"op": "session.found", "handle": session}));

    let blob = text(json!({"op": "session.sealSession", "handle": session, "key": key}));
    let reopened = handle(json!({"op": "session.unseal", "blob": blob, "key": key}));

    assert_eq!(
        ok(json!({"op": "session.epoch", "handle": session})),
        ok(json!({"op": "session.epoch", "handle": reopened})),
        "a reopened session must be where it was"
    );

    ok(json!({"op": "key.free", "handle": key}));
}

#[test]
fn the_rendezvous_path_works_through_the_boundary() {
    let tag = text(json!({"op": "rendezvous.tag", "passphrase": "the shared passphrase"}));
    assert_eq!(tag.len(), 64, "a tag is 32 bytes as hex");

    // The same passphrase must reach the same place, or two people who agreed
    // on a phrase end up in different mailboxes.
    let again = text(json!({"op": "rendezvous.tag", "passphrase": "the shared passphrase"}));
    assert_eq!(tag, again);

    let envelope = text(json!({
        "op": "rendezvous.seal", "tag": tag, "payload": "aGVsbG8="
    }));
    let payload = text(json!({
        "op": "rendezvous.open", "envelope": envelope, "tag": tag
    }));
    assert_eq!(payload, "aGVsbG8=");
}

/// Nothing a wrapper can send may crash the library.
///
/// A wrapper is written by somebody in another language against a JSON schema
/// in a comment, so it will send the wrong shape, and it will do it in
/// production. Every one of these must come back as an error.
#[test]
fn a_wrapper_cannot_crash_this() {
    for bad in [
        json!({}),
        json!({"op": 5}),
        json!({"op": "nonsense"}),
        json!({"op": "session.send"}),
        json!({"op": "session.send", "handle": 99999, "text": "x"}),
        json!({"op": "session.new"}),
        json!({"op": "session.free", "handle": 0}),
        json!({"op": "key.unlock", "passphrase": "x", "blob": "not base64!!"}),
        json!({"op": "rendezvous.tag", "passphrase": ""}),
        json!({"op": "session.invite", "handle": 1, "keyPackage": "////"}),
        json!({"op": "session.beginGroupPq", "handle": 1, "hybridPublicKeys": [1, 2]}),
        json!([1, 2, 3]),
        json!("a bare string"),
        json!(null),
    ] {
        // `call` asserts the code and the body agree, so an inconsistent
        // failure fails here rather than being tolerated.
        let _ = call(bad);
    }

    // Not JSON at all, and not UTF-8 at all.
    for raw in [b"{".to_vec(), b"".to_vec(), vec![0xff, 0xfe, 0x00]] {
        let c = CString::new(raw.into_iter().filter(|b| *b != 0).collect::<Vec<u8>>())
            .expect("no interior NUL");
        let mut response = std::ptr::null_mut();
        let code = unsafe { rotelyx_mobile::rotelyx_call(c.as_ptr(), &mut response) };
        assert_eq!(code, -1, "malformed input must fail");
        assert!(!response.is_null(), "even a failure returns a string to free");
        unsafe { rotelyx_mobile::rotelyx_string_free(response) };
    }

    // A null request, and a null response slot.
    let mut response = std::ptr::null_mut();
    assert_eq!(
        unsafe { rotelyx_mobile::rotelyx_call(std::ptr::null(), &mut response) },
        -1
    );
    unsafe { rotelyx_mobile::rotelyx_string_free(response) };
    assert_eq!(
        unsafe { rotelyx_mobile::rotelyx_call(std::ptr::null(), std::ptr::null_mut()) },
        -1,
        "a null response slot must be refused, not written to"
    );
}

// ---------------------------------------------------------------------------
// The audio path, through the C boundary
// ---------------------------------------------------------------------------

/// A call between two paired sessions, PCM in and PCM out.
///
/// Goes through the raw entry points rather than the JSON ones, because that is
/// the path an audio callback takes and it is the only path where a buffer
/// length can be wrong.
#[test]
fn a_call_carries_audio_between_two_sessions() {
    use rotelyx_mobile::{
        rotelyx_call_capture, rotelyx_call_close, rotelyx_call_deliver, rotelyx_call_open,
        rotelyx_call_playback, ROTELYX_FRAME_SAMPLES,
    };

    // Pair first: a call needs a conversation, because its keys come from the
    // MLS exporter rather than from anywhere a caller could supply.
    let ana = handle(json!({"op": "session.new", "label": "ana"}));
    let beto = handle(json!({"op": "session.new", "label": "beto"}));
    ok(json!({"op": "session.found", "handle": ana}));
    let package = text(json!({"op": "session.keyPackage", "handle": beto}));
    let invite = ok(json!({"op": "session.invite", "handle": ana, "keyPackage": package}));
    ok(json!({
        "op": "session.join", "handle": beto,
        "welcome": invite["welcome"], "ratchetTree": invite["ratchetTree"]
    }));

    // The identifier both ends agreed on for this call. Without it the media
    // keys would be a function of the MLS epoch alone and a second call would
    // repeat the first one's nonces, which is why the argument is not optional.
    let call = b"a-call-identifier";
    let open = |session: u64| unsafe {
        rotelyx_call_open(session, 60, 0, call.as_ptr(), call.len() as i32)
    };

    // Opening a call before there is a conversation must fail rather than
    // produce a call with a key derived from nothing.
    let orphan = handle(json!({"op": "session.new", "label": "nobody"}));
    assert!(
        open(orphan) < 0,
        "a session with no conversation must not open a call"
    );

    // And a call with no binding, or one too short to be worth having, must be
    // refused rather than quietly keyed from the epoch.
    assert!(
        unsafe { rotelyx_call_open(ana, 60, 0, std::ptr::null(), 0) } < 0,
        "a call with no binding must be refused"
    );
    let short = b"tiny";
    assert!(
        unsafe { rotelyx_call_open(ana, 60, 0, short.as_ptr(), short.len() as i32) } < 0,
        "a call with a binding too short must be refused"
    );

    let speaking = open(ana);
    assert!(speaking > 0, "opening a call failed with {speaking}");
    let listening = open(beto);
    assert!(listening > 0, "opening a call failed with {listening}");
    assert!(open(999_999) < 0, "a bad session handle");

    // 20 ms of a tone, which is what the app would hand over.
    let frame: Vec<i16> = (0..ROTELYX_FRAME_SAMPLES)
        .map(|i| {
            let t = i as f32 / 48_000.0;
            ((2.0 * std::f32::consts::PI * 440.0 * t).sin() * 8000.0) as i16
        })
        .collect();

    let mut datagram = vec![0u8; 1200];
    let mut sent = 0;
    let mut now = 0u64;

    for tick in 0..40 {
        let n = unsafe {
            rotelyx_call_capture(
                speaking,
                frame.as_ptr(),
                ROTELYX_FRAME_SAMPLES,
                datagram.as_mut_ptr(),
                datagram.len() as i32,
            )
        };
        // The first frame only primes the 40 ms window, so it produces nothing.
        if tick == 0 {
            assert_eq!(n, 0, "the first frame primes the window");
        } else {
            assert!(n > 0, "frame {tick} produced {n}");
            sent += 1;
            // To the other party, not back to ourselves.
            //
            // An earlier version of this looped the datagram back into the same
            // call and passed, which it could only do because every receiver
            // was keyed with its own sender index instead of the sender's. That
            // is exactly backwards: a receiver authenticates with the key of
            // whoever it is listening to. The bug made a loopback work and a
            // real call silent, which is the worst way round for a test to be
            // wrong.
            assert_eq!(
                unsafe { rotelyx_call_deliver(listening, datagram.as_ptr(), n, now) },
                0
            );
        }
        now += 20;
    }
    assert!(sent > 30, "only {sent} frames were produced");

    // Collect, and check that real audio comes out rather than silence.
    let mut out = vec![0i16; ROTELYX_FRAME_SAMPLES as usize];
    let mut loudest = 0i16;
    for _ in 0..40 {
        let n = unsafe { rotelyx_call_playback(listening, out.as_mut_ptr(), out.len() as i32) };
        assert_eq!(n, ROTELYX_FRAME_SAMPLES, "a full frame is always returned");
        loudest = loudest.max(out.iter().map(|s| s.abs()).max().unwrap_or(0));
    }
    assert!(
        loudest > 1000,
        "the loudest sample out was {loudest}; nothing came through"
    );

    let stats = ok(json!({"op": "abi.version"}));
    assert_eq!(stats, json!("1"));

    assert_eq!(rotelyx_call_close(speaking), 0);
    assert_eq!(rotelyx_call_close(listening), 0);
    assert_eq!(
        rotelyx_call_close(speaking),
        -1,
        "closing twice must fail rather than corrupt anything"
    );
    ok(json!({"op": "session.free", "handle": ana}));
    ok(json!({"op": "session.free", "handle": beto}));
    ok(json!({"op": "session.free", "handle": orphan}));
}

/// Wrong buffer sizes and null pointers must be refused, not trusted.
///
/// These come from an audio callback in another language, so they will be wrong
/// eventually, and being wrong there means a crash in the middle of a call.
#[test]
fn the_audio_path_refuses_bad_buffers() {
    use rotelyx_mobile::{
        rotelyx_call_capture, rotelyx_call_deliver, rotelyx_call_playback, ROTELYX_FRAME_SAMPLES,
    };

    let mut pcm = vec![0i16; ROTELYX_FRAME_SAMPLES as usize];
    let mut buf = vec![0u8; 1200];

    unsafe {
        // A call that does not exist.
        assert!(
            rotelyx_call_capture(1, pcm.as_ptr(), ROTELYX_FRAME_SAMPLES, buf.as_mut_ptr(), 1200)
                < 0
        );
        assert!(rotelyx_call_deliver(1, buf.as_ptr(), 10, 0) < 0);
        assert!(rotelyx_call_playback(1, pcm.as_mut_ptr(), ROTELYX_FRAME_SAMPLES) < 0);

        // Null pointers and wrong lengths, on a handle that also does not exist:
        // the argument checks must happen before the lookup, or a valid handle
        // with a null buffer would dereference it.
        assert!(rotelyx_call_capture(1, std::ptr::null(), ROTELYX_FRAME_SAMPLES, buf.as_mut_ptr(), 1200) < 0);
        assert!(rotelyx_call_capture(1, pcm.as_ptr(), 480, buf.as_mut_ptr(), 1200) < 0);
        assert!(rotelyx_call_capture(1, pcm.as_ptr(), ROTELYX_FRAME_SAMPLES, std::ptr::null_mut(), 1200) < 0);
        assert!(rotelyx_call_deliver(1, std::ptr::null(), 10, 0) < 0);
        assert!(rotelyx_call_playback(1, std::ptr::null_mut(), ROTELYX_FRAME_SAMPLES) < 0);
        assert!(rotelyx_call_playback(1, pcm.as_mut_ptr(), 100) < 0, "too small a buffer");
    }
}
