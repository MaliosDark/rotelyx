//! One encode, several bandwidths.
//!
//! The layered codec's headline claim is that the rate is a decision the
//! network makes rather than the encoder: encode once, and send as much of the
//! result as the link will carry. Until this test existed the claim was
//! untested, because nothing carried a layered frame over the transport at all.
//!
//! What is checked here is the whole path and not any one piece of it: encode,
//! trim to a budget the transport reports, protect, cross a wire, authenticate,
//! parse, decode.

use rotelyx_codec::layered::{LayeredDecoder, LayeredEncoder, LayeredFrame};
use rotelyx_codec::mdct::{self, FRAME, WINDOW};
use rotelyx_media::transport::{MediaIn, MediaOut};
use rotelyx_media::SenderKeys;
use rotelyx_path::PathPolicy;
use std::f32::consts::PI;

const BYTES_PER_FRAME: usize = 60;

fn voice_like(samples: usize) -> Vec<f32> {
    (0..samples)
        .map(|n| {
            let t = n as f32 / mdct::SAMPLE_RATE as f32;
            let pitch = 120.0 + 20.0 * (2.0 * PI * 3.0 * t).sin();

            let mut s = 0.0;
            for harmonic in 1..=12 {
                let f = pitch * harmonic as f32;
                if f > 8_000.0 {
                    break;
                }
                let gain = 1.0 / harmonic as f32 * (1.0 + 2.0 * (-(f - 700.0).abs() / 500.0).exp());
                s += gain * (2.0 * PI * f * t).sin();
            }
            // 0.25 rather than 0.3: at 0.3 this peaked at 1.113, which is
            // not audio. No device can represent a sample past full scale, and
            // measuring a codec on a signal that clips measures the clipping.
            s * 0.25 * (0.5 + 0.5 * (2.0 * PI * 4.0 * t).sin())
        })
        .collect()
}

fn pair() -> (MediaOut, MediaIn) {
    let base = [7u8; 32];
    (
        MediaOut::new(PathPolicy::RelayOnly, SenderKeys::derive(&base, 0)).expect("sender"),
        MediaIn::new(PathPolicy::RelayOnly, SenderKeys::derive(&base, 0)).expect("receiver"),
    )
}

fn rms(x: &[f32]) -> f32 {
    if x.is_empty() {
        return 0.0;
    }
    (x.iter().map(|s| s * s).sum::<f32>() / x.len() as f32).sqrt()
}

/// Encode once, send the same frames at two budgets, decode both.
///
/// The encoder is run a single time and its output is borrowed by both links,
/// which is the property under test: a second listener on a worse connection
/// costs no second encode and no second copy.
///
/// # How much this actually saves, which is less than it sounds
///
/// Measured here, the narrow link carries 89 percent of the wide link's bytes.
/// That is not a bug in the trimming, it is the shape of the frame: the base
/// layer is 86 percent of it, so dropping every refinement can save at most
/// fourteen. And 44 percent of the base is the energy envelope.
///
/// So layered delivery is worth what the base costs, and the way to make it
/// worth more is to shrink the base rather than to trim harder. Coding the
/// energies across a group of frames does exactly that, 20.3 bytes a frame down
/// to 12.4, but it needs 200 ms of batching: available to the mailbox, not to a
/// call. The honest position is that this mechanism is built, correct, and
/// currently buys about a tenth.
#[test]
fn one_encode_serves_two_bandwidths() {
    let signal = voice_like(FRAME * 60);
    let mut encoder = LayeredEncoder::new(BYTES_PER_FRAME);

    let frames: Vec<LayeredFrame> = (0..signal.len() - WINDOW)
        .step_by(FRAME)
        .map(|s| encoder.encode(&signal[s..s + WINDOW]).expect("encode"))
        .collect();

    // Two links: one with room for everything, one that can carry about half a
    // datagram. Neither triggers a re-encode.
    let mut results = Vec::new();

    for datagram in [96usize, 40] {
        let (mut out, mut inbound) = pair();
        let mut decoder = LayeredDecoder::new(BYTES_PER_FRAME);
        let mut audio = Vec::new();
        let mut sent_bytes = 0usize;
        let mut refinements_sent = 0usize;

        for frame in &frames {
            let budget = out.payload_budget(datagram);
            let trimmed = frame.within(budget);
            refinements_sent += trimmed.refinements.iter().filter(|r| !r.is_empty()).count();

            let datagram = out.frame(&trimmed.to_bytes()).expect("protect");
            sent_bytes += datagram.len();

            let payload = inbound.frame(&datagram).expect("authenticate");
            let received = LayeredFrame::from_bytes(&payload).expect("parse");
            audio.extend(decoder.decode(&received).expect("decode"));
        }

        results.push((datagram, sent_bytes, refinements_sent, audio));
    }

    let (wide_size, wide_bytes, wide_refinements, wide_audio) = {
        let r = &results[0];
        (r.0, r.1, r.2, r.3.clone())
    };
    let (narrow_size, narrow_bytes, narrow_refinements, narrow_audio) = {
        let r = &results[1];
        (r.0, r.1, r.2, r.3.clone())
    };

    println!(
        "\n  wide  ({wide_size} byte datagrams): {wide_bytes} bytes, {wide_refinements} refinements\n  \
         narrow ({narrow_size} byte datagrams): {narrow_bytes} bytes, {narrow_refinements} refinements\n  \
         one encode, {:.0}% of the traffic",
        100.0 * narrow_bytes as f32 / wide_bytes as f32
    );

    assert!(
        narrow_bytes < wide_bytes,
        "the narrow link sent {narrow_bytes} bytes against {wide_bytes} for the \
         wide one, so the budget did nothing"
    );
    assert!(
        narrow_refinements < wide_refinements,
        "the narrow link sent {narrow_refinements} refinements against \
         {wide_refinements}; trimming is not reaching the refinements"
    );

    // Both produced audio, and both produced the same amount of it: a listener
    // on a poor link hears a rougher rendering, not a shorter one.
    assert_eq!(wide_audio.len(), narrow_audio.len());
    assert_eq!(wide_audio.len(), frames.len() * FRAME);

    let reference = rms(&signal[FRAME..FRAME + wide_audio.len() - FRAME]);
    for (name, decoded, size) in [
        ("wide", &wide_audio, wide_size),
        ("narrow", &narrow_audio, narrow_size),
    ] {
        let level = rms(&decoded[FRAME..]);
        assert!(
            (0.4..2.5).contains(&(level / reference)),
            "the {name} link ({size} byte datagrams) decoded at {:.2} times the \
             original level, which is not a rougher rendering but a broken one",
            level / reference
        );
    }
}

/// A budget too small for even the base still sends the base.
///
/// The alternative is sending nothing, and a frame that is not sent is a gap
/// the listener hears. A frame sent over budget is a packet the network may
/// drop, which is the same outcome at worst and better at best.
#[test]
fn the_base_is_never_trimmed_away() {
    let signal = voice_like(FRAME * 8);
    let mut encoder = LayeredEncoder::new(BYTES_PER_FRAME);
    let (mut out, mut inbound) = pair();
    let mut decoder = LayeredDecoder::new(BYTES_PER_FRAME);

    for start in (0..signal.len() - WINDOW).step_by(FRAME) {
        let frame = encoder.encode(&signal[start..start + WINDOW]).expect("encode");

        // One byte of payload, which does not fit a base and is not meant to.
        let trimmed = frame.within(1);
        assert!(!trimmed.base.is_empty(), "the base was trimmed away");
        assert!(
            trimmed.refinements.iter().all(|r| r.is_empty()),
            "a one byte budget kept a refinement"
        );

        let datagram = out.frame(&trimmed.to_bytes()).expect("protect");
        let payload = inbound.frame(&datagram).expect("authenticate");
        let received = LayeredFrame::from_bytes(&payload).expect("parse");
        decoder.decode(&received).expect("decode");
    }
}

/// A datagram that has been altered must not reach the parser at all.
///
/// The layer lengths are inside the authenticated payload rather than in the
/// header, which is deliberate: it means a flipped bit in a length field is a
/// failed tag rather than a parse of attacker-chosen structure.
#[test]
fn a_tampered_datagram_never_reaches_the_parser() {
    let signal = voice_like(FRAME * 4);
    let mut encoder = LayeredEncoder::new(BYTES_PER_FRAME);
    let (mut out, mut inbound) = pair();

    let frame = encoder.encode(&signal[..WINDOW]).expect("encode");
    let mut datagram = out.frame(&frame.to_bytes()).expect("protect");

    // The first payload byte is the layer count, the one field that decides how
    // the rest is read.
    let header = 2;
    datagram[header] ^= 0x0f;

    assert!(
        inbound.frame(&datagram).is_none(),
        "a datagram with an altered layer count authenticated"
    );
}
