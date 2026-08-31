//! A call, through the C boundary, with no Rust types crossing it.
//!
//! The messaging test beside this one goes through `rotelyx_call` with JSON.
//! This goes through the raw entry points, because the audio path exists
//! precisely so that JSON is not on it: a wrapper calls these from an audio
//! callback fifty times a second, and anything that allocates there is a defect
//! the caller hears rather than sees.

use serde_json::{json, Value};
use std::ffi::{CStr, CString};

/// Open a call with a binding, which is not optional: the media keys are fixed
/// for an MLS epoch and only this value keeps two calls off the same nonces.
fn open_call(session: u64) -> i64 {
    let call = b"a-test-call-0001";
    unsafe { rotelyx_mobile::rotelyx_call_open(session, 60, 0, call.as_ptr(), call.len() as i32) }
}

fn control(request: Value) -> Value {
    let text = CString::new(request.to_string()).expect("no NUL");
    let mut response = std::ptr::null_mut();
    unsafe { rotelyx_mobile::rotelyx_call(text.as_ptr(), &mut response) };
    assert!(!response.is_null());
    let reply: Value = unsafe {
        let s = CStr::from_ptr(response)
            .to_str()
            .expect("UTF-8")
            .to_string();
        rotelyx_mobile::rotelyx_string_free(response);
        serde_json::from_str(&s).expect("JSON")
    };
    assert_eq!(reply["ok"], json!(true), "control call failed: {reply}");
    reply["result"].clone()
}

/// Two sessions in one conversation, which is what a call needs before it can
/// derive a key at all.
fn paired() -> (u64, u64) {
    let ana = control(json!({"op": "session.new", "label": "ana"}))
        .as_u64()
        .unwrap();
    let beto = control(json!({"op": "session.new", "label": "beto"}))
        .as_u64()
        .unwrap();

    control(json!({"op": "session.found", "handle": ana}));
    let package = control(json!({"op": "session.keyPackage", "handle": beto}));
    let invite = control(json!({
        "op": "session.invite", "handle": ana, "keyPackage": package
    }));
    control(json!({
        "op": "session.join", "handle": beto,
        "welcome": invite["welcome"], "ratchetTree": invite["ratchetTree"]
    }));

    let pk = control(json!({"op": "session.hybridPublicKey", "handle": beto}));
    let ct = control(json!({
        "op": "session.encapsulateTo", "handle": ana, "hybridPublicKey": pk
    }));
    control(json!({"op": "session.openPq", "handle": beto, "ciphertext": ct}));
    let commit = control(json!({"op": "session.commitPq", "handle": ana}));
    control(json!({"op": "session.receive", "handle": beto, "message": commit}));

    (ana, beto)
}

/// 20 ms of a tone, as the app would hand it over.
fn frame(t0: usize) -> Vec<i16> {
    (0..rotelyx_mobile::ROTELYX_FRAME_SAMPLES as usize)
        .map(|i| {
            let t = (t0 + i) as f32 / 48_000.0;
            let v = 0.4 * (2.0 * std::f32::consts::PI * 440.0 * t).sin();
            (v * 32767.0) as i16
        })
        .collect()
}

#[test]
fn one_person_speaks_and_the_other_hears() {
    let (ana, beto) = paired();

    let speaking = open_call(ana);
    assert!(speaking > 0, "opening a call failed with {speaking}");
    let listening = open_call(beto);
    assert!(listening > 0, "opening a call failed with {listening}");

    let samples = rotelyx_mobile::ROTELYX_FRAME_SAMPLES;
    let mut datagram = vec![0u8; rotelyx_mobile::ROTELYX_MAX_DATAGRAM as usize];
    let mut speaker = vec![0i16; samples as usize];

    let mut sent = 0;
    let mut heard_energy = 0.0f64;

    for tick in 0..60 {
        let pcm = frame(tick * samples as usize);

        let len = unsafe {
            rotelyx_mobile::rotelyx_call_capture(
                speaking,
                pcm.as_ptr(),
                samples,
                datagram.as_mut_ptr(),
                datagram.len() as i32,
            )
        };
        assert!(len >= 0, "capture failed with {len} on tick {tick}");

        // The first frame only primes the 40 ms window, which is the cost of
        // the long window and is worth asserting rather than discovering.
        if tick == 0 {
            assert_eq!(len, 0, "the first frame cannot produce a datagram");
        } else {
            assert!(len > 0, "tick {tick} produced nothing");
            sent += 1;

            let code = unsafe {
                rotelyx_mobile::rotelyx_call_deliver(
                    listening,
                    datagram.as_ptr(),
                    len,
                    tick as u64 * 20,
                )
            };
            assert_eq!(code, 0, "delivery failed on tick {tick}");
        }

        let got = unsafe {
            rotelyx_mobile::rotelyx_call_playback(
                listening,
                speaker.as_mut_ptr(),
                speaker.len() as i32,
            )
        };
        // Always a full frame, even across a gap: an audio callback handed
        // fewer samples than it asked for produces a click.
        assert_eq!(got, samples, "playback must always fill the buffer");
        heard_energy += speaker.iter().map(|s| (*s as f64).powi(2)).sum::<f64>();
    }

    assert!(sent > 50, "only {sent} datagrams for 60 frames");
    assert!(
        heard_energy > 0.0,
        "the listener heard nothing at all across {sent} frames"
    );

    let stats = {
        let mut response = std::ptr::null_mut();
        let code = unsafe { rotelyx_mobile::rotelyx_call_stats(speaking, &mut response) };
        assert_eq!(code, 0);
        let v: Value = unsafe {
            let s = CStr::from_ptr(response).to_str().unwrap().to_string();
            rotelyx_mobile::rotelyx_string_free(response);
            serde_json::from_str(&s).unwrap()
        };
        v["result"].clone()
    };
    assert_eq!(stats["framesSent"], json!(sent));

    assert_eq!(rotelyx_mobile::rotelyx_call_close(speaking), 0);
    assert_eq!(rotelyx_mobile::rotelyx_call_close(listening), 0);
    assert_eq!(
        rotelyx_mobile::rotelyx_call_close(speaking),
        -1,
        "closing twice must fail rather than corrupt anything"
    );
}

/// A call cannot be opened on a session that has no conversation.
///
/// The key comes from an MLS exporter, so there is nothing to derive from until
/// two people have agreed on something. Failing here with a reason is much
/// better than deriving a key from zeroes.
#[test]
fn a_call_needs_a_conversation() {
    let alone = control(json!({"op": "session.new", "label": "alone"}))
        .as_u64()
        .unwrap();
    assert_eq!(
        open_call(alone),
        -2,
        "a session with no conversation has no media key"
    );
    assert_eq!(open_call(999_999), -1, "an unknown session handle");
}

/// Nothing a wrapper passes may crash the audio path.
///
/// These run on an audio thread in another language against a comment. Null
/// pointers, wrong frame sizes and undersized buffers will all happen.
#[test]
fn the_audio_path_refuses_rubbish_rather_than_crashing() {
    let (ana, _beto) = paired();
    let call = open_call(ana);
    assert!(call > 0);

    let samples = rotelyx_mobile::ROTELYX_FRAME_SAMPLES;
    let pcm = frame(0);
    let mut out = vec![0u8; rotelyx_mobile::ROTELYX_MAX_DATAGRAM as usize];

    unsafe {
        // Null in, null out.
        assert!(
            rotelyx_mobile::rotelyx_call_capture(
                call,
                std::ptr::null(),
                samples,
                out.as_mut_ptr(),
                out.len() as i32
            ) < 0
        );
        assert!(
            rotelyx_mobile::rotelyx_call_capture(
                call,
                pcm.as_ptr(),
                samples,
                std::ptr::null_mut(),
                16
            ) < 0
        );

        // A frame that is not 20 ms. The engine's window is fixed, so a caller
        // resampling badly must be told rather than quietly mixed.
        for wrong in [0, 1, samples - 1, samples + 1, samples * 2] {
            assert!(
                rotelyx_mobile::rotelyx_call_capture(
                    call,
                    pcm.as_ptr(),
                    wrong,
                    out.as_mut_ptr(),
                    out.len() as i32
                ) < 0,
                "a {wrong} sample frame was accepted"
            );
        }

        // An output buffer too small for the datagram.
        rotelyx_mobile::rotelyx_call_capture(
            call,
            pcm.as_ptr(),
            samples,
            out.as_mut_ptr(),
            out.len() as i32,
        );
        assert!(
            rotelyx_mobile::rotelyx_call_capture(call, pcm.as_ptr(), samples, out.as_mut_ptr(), 4)
                < 0,
            "a four byte buffer cannot hold a frame and must be refused"
        );

        // Delivery of nonsense: never authenticates, never crashes.
        for junk in [vec![], vec![0u8; 1], vec![0xffu8; 64], vec![0u8; 1199]] {
            assert_eq!(
                rotelyx_mobile::rotelyx_call_deliver(call, junk.as_ptr(), junk.len() as i32, 0),
                0,
                "a datagram that fails to authenticate is dropped, not an error"
            );
        }
        assert!(rotelyx_mobile::rotelyx_call_deliver(call, std::ptr::null(), 5, 0) < 0);

        // Playback into nothing, and into a buffer too small.
        let mut speaker = vec![0i16; samples as usize];
        assert!(rotelyx_mobile::rotelyx_call_playback(call, std::ptr::null_mut(), samples) < 0);
        assert!(rotelyx_mobile::rotelyx_call_playback(call, speaker.as_mut_ptr(), samples - 1) < 0);
        assert_eq!(
            rotelyx_mobile::rotelyx_call_playback(call, speaker.as_mut_ptr(), samples),
            samples
        );

        // An unknown call handle, on every entry point.
        assert!(
            rotelyx_mobile::rotelyx_call_capture(
                -5,
                pcm.as_ptr(),
                samples,
                out.as_mut_ptr(),
                out.len() as i32
            ) < 0
        );
        assert!(rotelyx_mobile::rotelyx_call_deliver(-5, out.as_ptr(), 1, 0) < 0);
        assert!(rotelyx_mobile::rotelyx_call_playback(-5, speaker.as_mut_ptr(), samples) < 0);
        assert!(rotelyx_mobile::rotelyx_call_stats(-5, std::ptr::null_mut()) < 0);
    }

    rotelyx_mobile::rotelyx_call_close(call);
}
