"""A voice for a member that is not a person, and ears for it.

Every member of a Rotelyx conversation is a person with a microphone, except
the ones in the load test, which are programs. This is what a program uses
instead: text goes to a speech service and comes back as samples the call
sends; what the call heard goes back to the same service and comes back as
text the model can answer.

    ROTELYX_TTS_URL   e.g. https://192.168.68.109:8443/api/tts
    ROTELYX_STT_URL   e.g. https://192.168.68.109:8443/api/stt
    ROTELYX_VOICE_KEY the token both need, from the environment, never a file

**Where the speech service runs decides whether the call is still private.**
The same rule as `llm.py`, and it bites harder here: a call is the most
personal thing this application carries. A service on a machine you control
keeps it yours. Everything sent to one you do not control has left the
conversation, whatever the terms say -- which is why nothing in the
application itself speaks to one of these, and only the simulated people do.

# The samples

The call speaks 32 bit float, mono, at 48 kHz, because that is the codec's
rate and resampling anywhere in the path would colour every measurement taken
of the codec afterwards. Speech services answer in WAV at whatever rate they
like, so the one conversion that has to happen happens here, in `_resample`,
and it is linear interpolation: good enough for a voice and not pretending to
be anything else.

# Without a service

With no URL or no key, `speak` returns a short tone rather than nothing. That
is deliberate and it is for the load test: the thing under test is whether the
mailbox and the relay carry a group call of forty people, and that is
measurable with tones. Words need the service; frames do not.
"""

import array
import io
import json
import math
import os
import random
import struct
import urllib.error
import urllib.request
import wave
import zlib

#: What the codec speaks. See `rotelyx_codec::mdct::SAMPLE_RATE`.
RATE = 48000

TTS_URL = os.environ.get("ROTELYX_TTS_URL", "").rstrip("/")
STT_URL = os.environ.get("ROTELYX_STT_URL", "").rstrip("/")
KEY = os.environ.get("ROTELYX_VOICE_KEY", "")

#: How long a tone stands in for a sentence, in seconds per word, when there is
#: no speech service. Roughly the pace of somebody talking.
SECONDS_PER_WORD = 0.38


def available() -> bool:
    """Whether real speech is possible, rather than tones."""
    return bool(TTS_URL and KEY)


def _headers() -> dict:
    headers = {"Accept": "*/*"}
    if KEY:
        # Both shapes, because a service that wants one ignores the other and
        # this is a private endpoint on somebody's own network, not a place to
        # discover an authentication scheme by trial.
        headers["Authorization"] = f"Bearer {KEY}"
        headers["X-API-Key"] = KEY
    return headers


def speak(text: str, voice: str = "") -> array.array:
    """`text` as samples the call can send: float32, mono, 48 kHz."""
    if not available():
        return tone(text)
    body = json.dumps({"text": text, "voice": voice} if voice else {"text": text}).encode()
    request = urllib.request.Request(
        TTS_URL, data=body, headers={**_headers(), "Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as answer:
            kind = answer.headers.get("Content-Type", "")
            payload = answer.read()
    except (urllib.error.URLError, OSError) as e:
        # A voice service that is down is not a reason to leave the call. The
        # member says something the length of what it meant to say, and the
        # measurement carries on.
        print(f"[voice] {TTS_URL}: {e}")
        return tone(text)

    if "json" in kind:
        payload = _audio_in(json.loads(payload))
    return from_wav(payload)


def hear(samples, voice_hint: str = "") -> str:
    """What was said in `samples` (float32, mono, 48 kHz), or an empty string."""
    if not (STT_URL and KEY):
        return ""
    wav = to_wav(samples)
    request = urllib.request.Request(
        STT_URL, data=wav, headers={**_headers(), "Content-Type": "audio/wav"}
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as answer:
            payload = answer.read()
    except (urllib.error.URLError, OSError) as e:
        print(f"[voice] {STT_URL}: {e}")
        return ""
    try:
        out = json.loads(payload)
    except ValueError:
        return payload.decode("utf-8", "replace").strip()
    for field in ("text", "transcript", "transcription", "result"):
        if isinstance(out.get(field), str):
            return out[field].strip()
    return ""


def _audio_in(out: dict) -> bytes:
    """The audio inside a JSON answer, whatever the service calls the field."""
    import base64

    for field in ("audio", "audio_base64", "data", "wav", "content"):
        value = out.get(field)
        if isinstance(value, str) and value:
            return base64.b64decode(value)
    raise RuntimeError(f"no audio in the answer: {list(out)}")


def tone(text: str) -> array.array:
    """A sound the length of the sentence, for a test with no speech service.

    Not silence: silence sends no frames, and a call that sends no frames
    measures nothing. Not noise either -- a voice is roughly periodic and the
    codec is built for that, so noise would measure the codec's worst case
    rather than a call.
    """
    words = text.split()
    # A stable hash, not Python's: that one is seeded per process, so the same
    # sentence would come out different on every run and a recording could not
    # be repeated.
    seed = zlib.crc32(text.encode())
    base = 110 + (seed % 120)

    # One burst per word, at its own pitch, with a gap after it.
    #
    # The first version was a steady tone under a steady tremolo, and it was
    # useless for the thing this exists for: every part of it looked like
    # every other part, so a copy could not be lined up against the original,
    # and being a few milliseconds out made a working call measure as a fifth
    # of the audio missing. Speech is not like that -- it has edges -- and a
    # stand-in for speech has to have them too.
    out = array.array("f")
    # Its own generator, seeded from the text, so the breath below is the same
    # breath every run: what is measured has to be what was measured before.
    rng = random.Random(seed)
    for n, word in enumerate(words[:40] or [""]):
        length = int(RATE * min(0.45, 0.08 + 0.035 * len(word)))
        pitch = base * (1 + 0.12 * math.sin(n * 1.7 + (seed % 7)))
        # A voice is not three lines on a spectrum. Between the harmonics
        # there is breath, and consonants are nothing else: a spectrum that
        # is dense everywhere, which is what a speech codec is built to code
        # and what a measurement of one has to be fed. Without it the probe
        # was three harmonics over silence, and the codec's own noise floor,
        # forty dB down and inaudible, measured as twenty dB of distortion.
        breath = 0.0
        for i in range(length):
            t = i / RATE
            harmonics = (math.sin(2 * math.pi * pitch * t)
                         + 0.5 * math.sin(4 * math.pi * pitch * t)
                         + 0.3 * math.sin(6 * math.pi * pitch * t)
                         + 0.2 * math.sin(8 * math.pi * pitch * t)
                         + 0.12 * math.sin(10 * math.pi * pitch * t))
            # Shaped noise: one pole, so it falls off the way breath does.
            breath += 0.25 * (rng.uniform(-1, 1) - breath)
            rise = min(1.0, t / 0.01)
            fall = min(1.0, (length - i) / RATE / 0.03)
            out.append((0.16 * harmonics + 0.35 * breath) * rise * fall)
        for _ in range(int(RATE * (0.06 + 0.02 * ((seed >> n) & 3)))):
            out.append(0.0)
    return out


def from_wav(payload: bytes) -> array.array:
    """WAV bytes as float32 mono at the codec's rate."""
    with wave.open(io.BytesIO(payload)) as f:
        channels = f.getnchannels()
        width = f.getsampwidth()
        rate = f.getframerate()
        frames = f.readframes(f.getnframes())

    if width == 2:
        raw = array.array("h")
        raw.frombytes(frames)
        mono = [s / 32768.0 for s in raw]
    elif width == 4:
        raw = array.array("f")
        raw.frombytes(frames)
        mono = list(raw)
    else:
        raise RuntimeError(f"{width * 8} bit audio is not something this reads")

    if channels > 1:
        mono = [sum(mono[i : i + channels]) / channels for i in range(0, len(mono), channels)]
    return _resample(mono, rate, RATE)


def to_wav(samples) -> bytes:
    """Float32 mono at the codec's rate, as a 16 bit WAV a service will take."""
    out = io.BytesIO()
    with wave.open(out, "wb") as f:
        f.setnchannels(1)
        f.setsampwidth(2)
        f.setframerate(RATE)
        f.writeframes(
            b"".join(
                struct.pack("<h", max(-32768, min(32767, int(s * 32767)))) for s in samples
            )
        )
    return out.getvalue()


def _resample(samples, have: int, want: int) -> array.array:
    """Linear interpolation, and honest about being that.

    A voice call at 48 kHz from a service that answered at 22 050 needs the
    rates to meet somewhere. A proper resampler is a filter and a filter is a
    design decision; this is the smallest thing that works and it is here
    rather than in the codec's path so nothing measured of the codec is
    measuring this.
    """
    if have == want or not samples:
        return array.array("f", samples)
    ratio = have / want
    out = array.array("f", bytes(4 * int(len(samples) / ratio)))
    for i in range(len(out)):
        at = i * ratio
        left = int(at)
        right = min(left + 1, len(samples) - 1)
        gap = at - left
        out[i] = samples[left] * (1 - gap) + samples[right] * gap
    return out


def write(path: str, samples) -> None:
    """Hand samples to a call through the file it reads its microphone from.

    See `ROTELYX_CALL_FEED` in `rotelyx-audio`: 32 bit float, little endian,
    mono, at the codec's rate. Opening blocks until the call is reading, which
    is what keeps a member quiet until it is actually in a call.
    """
    with open(path, "wb") as fifo:
        fifo.write(array.array("f", samples).tobytes())
