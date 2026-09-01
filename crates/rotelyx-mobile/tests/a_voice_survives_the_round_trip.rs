//! A voice, not a tone, and measured for what it is rather than that it exists.
//!
//! # Why this test exists
//!
//! `audio_path.rs` already sends audio through this ABI and reads it out the
//! other side, and it passed the entire time a real call carried its keypad
//! and not its voices. Two things let it.
//!
//! Its signal is `0.4 * sin(2 pi 440 t)`: a pure tone, held for the length of
//! the test. Every frame of a held tone is the same as the frame before it, so
//! a tone is the one signal that survives having its frames mishandled. It is
//! also, exactly, what a touch tone is, and touch tones were the part of the
//! call that worked.
//!
//! And its assertion is `heard_energy > 0.0`: that something came out. Noise
//! passes that. So does a hum. So does the previous frame played twice.
//!
//! This one speaks instead. The signal changes pitch and loudness the way
//! speech does, so a frame is never the frame before it, and the check is how
//! much of what went in can be found in what came out.
//!
//! # What it holds
//!
//! Two things, and the second is the one a phone does.
//!
//! Every frame delivered, in order: the codec must return something that
//! correlates with what was said. That is the floor, and nothing was asserting
//! it.
//!
//! And frames delivered with gaps, because that is what the capture side
//! produces under load: `CallAudio.kt` keeps a backlog of ten and drops the
//! oldest when Dart does not collect in time, so the encoder is handed audio
//! with holes in it. The encoder has a forty millisecond window over a twenty
//! millisecond hop, which means every frame is built on the one before it, and
//! across a hole the overlap is against audio that was never adjacent. This
//! measures what that costs rather than assuming it.

use std::ffi::{CStr, CString};

use serde_json::{json, Value};

const SAMPLES: usize = rotelyx_mobile::ROTELYX_FRAME_SAMPLES as usize;

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

fn open_call(session: u64) -> i64 {
    let id = b"a-call-that-is-named";
    unsafe { rotelyx_mobile::rotelyx_call_open(session, 60, 0, id.as_ptr(), id.len() as i32) }
}

/// Something with the shape of a voice.
///
/// A fundamental that slides, two harmonics above it, and an envelope that
/// opens and closes about four times a second. None of that is speech, and it
/// does not have to be: what matters is that no frame equals the frame before
/// it, which is the property a held tone lacks and the property that makes
/// mishandled frames audible.
fn voice(t0: usize) -> Vec<i16> {
    (0..SAMPLES)
        .map(|i| {
            let t = (t0 + i) as f32 / 48_000.0;
            let pitch = 140.0 + 40.0 * (2.0 * std::f32::consts::PI * 0.7 * t).sin();
            let tone = (2.0 * std::f32::consts::PI * pitch * t).sin()
                + 0.5 * (2.0 * std::f32::consts::PI * pitch * 2.0 * t).sin()
                + 0.25 * (2.0 * std::f32::consts::PI * pitch * 3.0 * t).sin();
            let syllables = 0.5 + 0.5 * (2.0 * std::f32::consts::PI * 4.0 * t).sin();
            ((tone / 1.75) * syllables * 0.5 * 32767.0) as i16
        })
        .collect()
}

/// The most of `spoken` that can be found in `heard`, at any delay.
///
/// Normalised, so it is between zero and one whatever the levels are: a codec
/// is allowed to change the loudness and is not allowed to change the sound.
/// Searched across a hundred milliseconds of delay, which covers the window
/// and any buffering under it.
fn best_match(spoken: &[i16], heard: &[i16]) -> f64 {
    let energy = |x: &[i16]| x.iter().map(|s| (*s as f64).powi(2)).sum::<f64>().sqrt();

    let width = SAMPLES * 8;
    if spoken.len() < width || heard.len() < width {
        return 0.0;
    }

    let reference = &spoken[..width];
    let reference_energy = energy(reference);
    if reference_energy == 0.0 {
        return 0.0;
    }

    let mut best: f64 = 0.0;
    for delay in 0..(48_000 / 10) {
        if delay + width > heard.len() {
            break;
        }
        let window = &heard[delay..delay + width];
        let window_energy = energy(window);
        if window_energy == 0.0 {
            continue;
        }
        let dot: f64 = reference
            .iter()
            .zip(window)
            .map(|(a, b)| *a as f64 * *b as f64)
            .sum();
        best = best.max(dot / (reference_energy * window_energy));
    }
    best
}

/// Run a call, delivering every `keep`th frame out of `of`, and return what was
/// said and what was heard.
fn through(keep: usize, of: usize) -> (Vec<i16>, Vec<i16>) {
    let (ana, beto) = paired();
    let speaking = open_call(ana);
    let listening = open_call(beto);
    assert!(speaking > 0 && listening > 0, "a call would not open");

    let mut datagram = vec![0u8; rotelyx_mobile::ROTELYX_MAX_DATAGRAM as usize];
    let mut out = vec![0i16; SAMPLES];

    let mut spoken = Vec::new();
    let mut heard = Vec::new();

    for tick in 0..150usize {
        let pcm = voice(tick * SAMPLES);
        spoken.extend_from_slice(&pcm);

        let len = unsafe {
            rotelyx_mobile::rotelyx_call_capture(
                speaking,
                pcm.as_ptr(),
                SAMPLES as i32,
                datagram.as_mut_ptr(),
                datagram.len() as i32,
            )
        };
        assert!(len >= 0, "capture failed with {len}");

        if len > 0 && tick % of < keep {
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
                out.as_mut_ptr(),
                out.len() as i32,
            )
        };
        assert_eq!(got, SAMPLES as i32, "playback must always fill the buffer");
        heard.extend_from_slice(&out);
    }

    (spoken, heard)
}

#[test]
fn a_voice_delivered_whole_comes_out_a_voice() {
    let (spoken, heard) = through(1, 1);
    let matched = best_match(&spoken, &heard);

    println!("every frame delivered: match {matched:.3}");
    assert!(
        matched > 0.5,
        "a voice sent through this ABI with nothing dropped came back matching \
         what was said by only {matched:.3}. Energy came out, which is all the \
         older test asked for, but it is not the same sound. Whatever is wrong \
         here is wrong on every call."
    );
}

#[test]
fn what_a_gap_in_the_capture_costs() {
    // Nine frames in every ten, which is a light version of what a phone under
    // load produces when the capture backlog overflows.
    let (spoken, heard) = through(9, 10);
    let matched = best_match(&spoken, &heard);

    println!("one frame in ten dropped: match {matched:.3}");
    assert!(
        matched > 0.3,
        "losing one captured frame in ten took the match down to {matched:.3}. \
         The encoder builds each frame on the one before it across a forty \
         millisecond window, so a frame that never arrives makes the next one \
         overlap audio it was never adjacent to. If this is where a call stops \
         carrying a voice, the fix is that the capture side must not silently \
         drop: see the backlog in CallAudio.kt."
    );
}
