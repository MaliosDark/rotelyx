#!/usr/bin/env python3
"""What the calls did to the speech, as numbers a codec can be judged by.

    python3 bot-examples/town/measure_calls.py ~/.local/state/rotelyx-town/recordings/2026-09-14-001122

A run started with `--record` leaves, per member:

    said-0001.wav   exactly what was handed to the encoder
    said-0001.json  what it was meant to say, and when
    heard.f32       what the decoder gave back, the whole call in one track
    calls.jsonl     what each call reported when it started and ended

This reads that and prints one row per utterance: where it was found in the
listener's track, how much of it arrived, and how far what arrived is from what
was sent. It writes the same rows as CSV beside the run, which is the thing to
keep: a codec change is worth making when these numbers move, and worth
reverting when they move the other way.

# Why the measures are the ones below and not "SNR"

The codec is an MDCT transform coder with concealment. It does not preserve a
waveform and was never meant to: a frame that arrives is reconstructed from
bands, and a frame that does not is invented from the last one. Subtracting the
decoded samples from the reference therefore reports a large error for audio
that sounds identical, and that number would make every real improvement look
like a regression.

So what is reported is spectral:

  **level**            how loud what arrived is against what was sent, in dB.
                       Near zero is right. A codec that quietly attenuates is
                       a codec that sounds far away.

  **spectral distance** the root mean square difference of the log spectrum
                       over 20 ms frames, in dB, taken over twenty four
                       logarithmically spaced bands rather than raw FFT bins.
                       Bands, because that is what a transform coder allocates
                       bits to and roughly what the ear resolves; bin for bin,
                       a synthetic probe with three harmonics compares "empty"
                       against "quantisation noise forty dB down" across
                       hundreds of bins and reports twenty dB for a call that
                       sounds fine. Under about 1 dB is transparent, 1-3 dB is
                       good, past 6 dB is audible as roughness.

  **gaps**             the share of 20 ms frames in the aligned span whose
                       energy is far below the reference's: audio that did not
                       arrive at all, which is a network measure rather than a
                       codec one and is why it is reported separately.

And from `calls.jsonl`, per call: frames sent, frames received, frames
concealed, and the milliseconds the jitter buffer dropped -- the numbers that
say whether a bad row above is the codec's fault or the network's.
"""

import array
import csv
import json
import os
import sys
import wave

import numpy as np

RATE = 48000
#: The codec's frame. Every measure below is per frame of this length.
FRAME = 960  # 20 ms


def read_wav(path: str) -> np.ndarray:
    with wave.open(path) as f:
        width, channels, rate = f.getsampwidth(), f.getnchannels(), f.getframerate()
        raw = f.readframes(f.getnframes())
    if width == 2:
        samples = np.frombuffer(raw, dtype="<i2").astype(np.float32) / 32768.0
    elif width == 4:
        samples = np.frombuffer(raw, dtype="<f4").astype(np.float32)
    else:
        raise SystemExit(f"{path}: {width * 8} bit audio is not something this reads")
    if channels > 1:
        samples = samples.reshape(-1, channels).mean(axis=1)
    if rate != RATE:
        # The references are written at the codec's rate by `voice.py`; this is
        # here so a file from somewhere else is resampled rather than measured
        # against the wrong clock.
        want = int(len(samples) * RATE / rate)
        samples = np.interp(np.linspace(0, len(samples), want), np.arange(len(samples)), samples)
    return samples.astype(np.float32)


def read_track(path: str) -> np.ndarray:
    with open(path, "rb") as f:
        return np.frombuffer(f.read(), dtype="<f4").astype(np.float32)


def envelope(samples: np.ndarray) -> np.ndarray:
    """One energy value per frame: what alignment is done on.

    Correlating whole waveforms would be both slow and wrong -- the decoded
    copy does not line up sample for sample with the reference. Energy over 20
    ms does line up, because that is the scale at which speech has shape.
    """
    frames = len(samples) // FRAME
    if frames == 0:
        return np.zeros(0, dtype=np.float32)
    block = samples[: frames * FRAME].reshape(frames, FRAME)
    return np.sqrt((block.astype(np.float64) ** 2).mean(axis=1)).astype(np.float32)


#: How many bands a frame is reduced to for alignment. Eight is enough to tell
#: one voice from another and one pitch from another, and few enough that the
#: correlation below is a small matrix multiply rather than a spectrogram
#: comparison.
BANDS = 8


def fingerprint(samples: np.ndarray) -> np.ndarray:
    """Per frame, where its energy sits: what alignment is done on.

    # Why not the envelope

    The first version correlated loudness over time, which is the obvious
    thing and works for speech, whose envelope is distinctive. It failed
    completely on the tones the load test uses when there is no speech
    service: a tone with a steady tremolo has the same envelope everywhere, so
    every offset scored about the same and nothing was ever found -- three
    utterances that plainly arrived were reported as lost.

    Where the energy sits does distinguish them: two tones at different
    pitches look different in bands, and so do two words. It is the same
    measure for both, which is what a test running with and without a speech
    service needs.
    """
    power = 10 ** (spectra(samples) / 10)
    if len(power) == 0:
        return np.zeros((0, BANDS))
    # Logarithmic bands: voices live in the bottom of the range and a linear
    # split would spend six of eight bands above 6 kHz, where there is nothing.
    edges = np.unique(
        np.geomspace(1, power.shape[1] - 1, BANDS + 1).astype(int)
    )
    bands = np.stack(
        [power[:, edges[i] : edges[i + 1]].mean(axis=1) for i in range(len(edges) - 1)],
        axis=1,
    )
    bands = np.log10(np.maximum(bands, 1e-10))
    # Per frame, so loudness is not what is matched: a quiet copy of the same
    # sound is the same sound, and level is reported separately.
    bands -= bands.mean(axis=1, keepdims=True)
    norms = np.sqrt((bands**2).sum(axis=1, keepdims=True))
    return bands / np.maximum(norms, 1e-9)


def find(reference: np.ndarray, track: np.ndarray) -> tuple[int, float]:
    """Where in `track` the reference sits, in frames, and how sure that is.

    The score is the mean per-frame similarity at the best offset: 1 is the
    same sound frame for frame, and under about 0.5 means the utterance was
    not found -- it never arrived, or nothing recognisable of it did.
    """
    a, b = fingerprint(reference), fingerprint(track)
    if len(a) < 2 or len(b) < len(a):
        return -1, 0.0

    # The similarity of every frame of the track to every frame of the
    # reference is one matrix multiply; the score at an offset is the mean of
    # its diagonal. Summing the diagonals of the product is what the loop
    # below does, one offset at a time, which for a track of minutes is still
    # a few thousand cheap steps.
    similarity = b @ a.T
    offsets = len(b) - len(a) + 1
    scores = np.empty(offsets)
    rows = np.arange(len(a))
    for at in range(offsets):
        scores[at] = similarity[rows + at, rows].mean()
    best = int(np.argmax(scores))
    return best, float(scores[best])


def refine(reference: np.ndarray, track: np.ndarray, at: int) -> int:
    """The offset again, in samples rather than frames.

    Frame accuracy is 20 ms, and 20 ms is a tenth of a syllable: comparing two
    spectra that far apart reports a difference that is the shift and not the
    codec. So the waveform is correlated over a frame either side of where the
    fingerprint landed, and the peak of that is where the copy really starts.

    `np.correlate` rather than a window view: the first version built every
    candidate window as a row of a matrix, half a gigabyte per utterance, and
    the kernel killed it. This is the same arithmetic in a loop written in C.
    """
    start = max(0, at * FRAME - FRAME)
    end = min(len(track), at * FRAME + FRAME + len(reference))
    window = track[start:end].astype(np.float64)

    # The first second is correlated: enough to place the start unambiguously
    # -- half a second was one burst of the probe, and one burst looks like
    # the next -- and the whole utterance would cost more for no more accuracy.
    head = reference[: min(len(reference), RATE)].astype(np.float64)
    if head.size == 0 or len(window) < len(head) + 1:
        return at * FRAME

    scores = np.correlate(window, head, mode="valid")
    # Normalised by the energy under each window, or a loud stretch of the
    # wrong sound outscores the quiet start of the right one.
    squares = np.convolve(window**2, np.ones(len(head)), mode="valid")
    scores = scores / np.sqrt(np.maximum(squares, 1e-12))
    return start + int(np.argmax(scores))


def spectra(samples: np.ndarray) -> np.ndarray:
    """Log power spectrum per frame, in dB, which is what is compared."""
    frames = len(samples) // FRAME
    if frames == 0:
        return np.zeros((0, FRAME // 2 + 1))
    block = samples[: frames * FRAME].reshape(frames, FRAME).astype(np.float64)
    window = np.hanning(FRAME)
    power = np.abs(np.fft.rfft(block * window, axis=1)) ** 2
    # A floor, so silence does not produce minus infinity and dominate the
    # mean. -100 dB is below anything a 16 bit recording carries.
    return 10 * np.log10(np.maximum(power, 1e-10))


#: Bands the distance is taken over. Twenty four log-spaced bands from 50 Hz
#: to the top of the range is close to the Bark scale, which is the resolution
#: the ear has and the one every transform codec is designed around.
DISTANCE_BANDS = 24


def banded(log_power: np.ndarray) -> np.ndarray:
    """Log power per band, from log power per bin."""
    bins = log_power.shape[1]
    low = max(1, int(50 / (RATE / 2) * bins))
    edges = np.unique(np.geomspace(low, bins - 1, DISTANCE_BANDS + 1).astype(int))
    power = 10 ** (log_power / 10)
    bands = np.stack(
        [power[:, edges[i] : edges[i + 1]].mean(axis=1) for i in range(len(edges) - 1)],
        axis=1,
    )
    return 10 * np.log10(np.maximum(bands, 1e-10))


def compare(reference: np.ndarray, heard: np.ndarray) -> dict:
    """The three numbers, for one utterance against what was heard of it."""
    length = min(len(reference), len(heard))
    reference, heard = reference[:length], heard[:length]

    rms_in = float(np.sqrt((reference.astype(np.float64) ** 2).mean()))
    rms_out = float(np.sqrt((heard.astype(np.float64) ** 2).mean()))
    level = 20 * np.log10(rms_out / rms_in) if rms_in > 0 and rms_out > 0 else float("nan")

    # Levels matched before the spectra are compared: a quiet copy of the same
    # sound is a level fault, already reported above, and counting it twice
    # would hide a spectral one.
    if rms_out > 0:
        heard = heard * (rms_in / rms_out)

    a, b = spectra(reference), spectra(heard)
    frames = min(len(a), len(b))
    if frames == 0:
        return {"level_db": level, "spectral_db": float("nan"), "gaps": float("nan")}
    a, b = a[:frames], b[:frames]

    energy_in = envelope(reference)[:frames]
    energy_out = envelope(heard)[:frames]
    speaking = (
        energy_in > energy_in.max() * 0.05 if energy_in.size else np.zeros(0, bool)
    )

    # Only the frames somebody was speaking in, and only the part of each
    # spectrum that carries the sound.
    #
    # The first version compared every frame and every bin against a fixed
    # floor, and reported forty six dB for a call that was plainly working.
    # Silence is why: a silent frame is the floor in one copy and the room in
    # the other, and the difference between two kinds of nothing dominated
    # everything that was actually said. A distance is only meaningful where
    # there is something to compare, so: frames with speech in them, and bins
    # within sixty dB of that frame's own peak, which is the convention for
    # log-spectral distance and the reason it is quoted in the units it is.
    if not speaking.any():
        return {"level_db": level, "spectral_db": float("nan"), "gaps": 1.0}

    said, got = banded(a[speaking]), banded(b[speaking])
    ceiling = said.max(axis=1, keepdims=True)
    # Bands more than sixty dB under the frame's loudest are the floor in
    # both copies, and the difference between two floors is not distortion.
    loud = said > ceiling - 60
    said = np.maximum(said, ceiling - 60)
    got = np.maximum(got, ceiling - 60)
    difference = (said - got) * loud
    distance = float(np.sqrt((difference**2).sum() / max(1, loud.sum())))

    # A frame of the reference that has energy and whose copy has almost none:
    # audio that did not arrive, rather than audio that arrived changed.
    missing = speaking & (energy_out < energy_in * 0.1)
    gaps = float(missing.sum() / max(1, speaking.sum()))

    return {"level_db": level, "spectral_db": distance, "gaps": gaps}


def member_rows(folder: str, track: np.ndarray) -> list[dict]:
    rows = []
    for name in sorted(os.listdir(folder)):
        if not name.startswith("said-") or not name.endswith(".wav"):
            continue
        said = read_wav(os.path.join(folder, name))
        meta_path = os.path.join(folder, name[:-4] + ".json")
        meta = {}
        if os.path.exists(meta_path):
            with open(meta_path) as f:
                meta = json.load(f)

        at, score = find(said, track)
        row = {
            "member": os.path.basename(folder),
            "utterance": name,
            "seconds": round(len(said) / RATE, 2),
            "found_at": round(at * FRAME / RATE, 2) if at >= 0 else "",
            "match": round(score, 3),
            "text": (meta.get("said") or "")[:120],
            "synthetic": meta.get("synthetic", ""),
        }
        if at >= 0 and score >= 0.5:
            start = refine(said, track, at)
            row.update(
                {
                    k: (round(v, 3) if isinstance(v, float) else v)
                    for k, v in compare(said, track[start : start + len(said)]).items()
                }
            )
        else:
            # Said and never heard. Reported as a row rather than dropped: an
            # utterance that vanished is the most important thing on this page.
            row.update({"level_db": "", "spectral_db": "", "gaps": 1.0})
        rows.append(row)
    return rows


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit(__doc__.strip().splitlines()[2].strip())
    run = sys.argv[1]
    if not os.path.isdir(run):
        raise SystemExit(f"{run} is not a folder from a `--record` run")

    listeners = [
        os.path.join(run, name)
        for name in sorted(os.listdir(run))
        if os.path.exists(os.path.join(run, name, "heard.f32"))
    ]
    if not listeners:
        raise SystemExit(
            f"nothing in {run} kept a decoded track: was the run started with --record?"
        )

    rows: list[dict] = []
    for listener in listeners:
        track = read_track(os.path.join(listener, "heard.f32"))
        print(
            f"{os.path.basename(listener)} heard {len(track) / RATE:.0f} seconds",
            file=sys.stderr,
        )
        # Everything anybody in the run said, measured against this listener's
        # track. A member that was in another group simply will not be found,
        # which the match column says.
        for name in sorted(os.listdir(run)):
            folder = os.path.join(run, name)
            if not os.path.isdir(folder):
                continue
            for row in member_rows(folder, track):
                row["heard_by"] = os.path.basename(listener)
                rows.append(row)

    found = [r for r in rows if r.get("spectral_db") not in ("", None)]
    out = os.path.join(run, "measures.csv")
    if rows:
        with open(out, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    print(f"{len(rows)} utterances measured, {len(found)} of them arrived")
    if found:
        level = np.mean([r["level_db"] for r in found])
        spectral = np.mean([r["spectral_db"] for r in found])
        gaps = np.mean([r["gaps"] for r in found])
        print(f"  level        {level:+.2f} dB   (0 is right)")
        print(f"  spectral     {spectral:.2f} dB   (under 1 is transparent, over 4 is rough)")
        print(f"  gaps         {gaps * 100:.1f}%     of speaking frames that did not arrive")
    print(f"  written to   {out}")

    for listener in listeners:
        calls = os.path.join(listener, "calls.jsonl")
        if not os.path.exists(calls):
            continue
        with open(calls) as f:
            for line in f:
                row = json.loads(line)
                if row.get("what") == "ended":
                    print(
                        f"  call         sent {row.get('frames_sent', 0)} "
                        f"received {row.get('frames_received', 0)} "
                        f"concealed {row.get('frames_concealed', 0)} "
                        f"dropped {row.get('dropped_ms', 0)} ms"
                    )


if __name__ == "__main__":
    main()
