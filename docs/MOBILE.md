# Rotelyx on a phone

The engine as a native library, for Android, iOS and desktop. The same crate the
browser gets, behind a C ABI instead of `wasm_bindgen`.

**This document is the contract.** The consuming project writes the binding
against it; nothing in this repository knows what a Flutter plugin is, and it
should not learn. If a signature here changes incompatibly, `abi.version`
changes with it.

## Why this exists

`rotelyx-wasm` runs in a browser and nowhere else, because `dart:js_interop`
does not exist off the web. Anything native, a Flutter Android build, a Flutter
desktop build, a Tauri app, needs the engine as a library it can link. That is
this crate.

It reimplements nothing: it depends on `rotelyx-wasm` as an `rlib` and calls its
public API. Two implementations of one handshake diverge, and the divergence is a
security bug that presents as an interoperability bug.

## The control ABI

Three symbols. The audio path adds six more, below, for a total of nine.

```c
int32_t     rotelyx_call(const char *request_json, char **response_json);
void        rotelyx_string_free(char *s);
const char *rotelyx_abi_version(void);
```

`rotelyx_call` returns 0 on success and -1 on failure. **`response_json` is
always set**, on success and failure alike, so a wrapper has one cleanup path
rather than two. Free it with `rotelyx_string_free`.

```json
{"ok": true,  "result": <anything>}
{"ok": false, "error": "a sentence a person could act on"}
```

The return code and `ok` always agree. A wrapper may check either.

### Why one function and not forty two

The engine's surface is 42 calls, every one of which takes and returns base64 or
hex strings. As typed C functions that is around fifteen hundred lines of
`unsafe` marshalling here, all of which has to be correct, and a matching
fifteen hundred on the consuming side. As one function it is a hundred lines of
Dart, adding an operation does not change the ABI, and there is exactly one
place where a string crosses the boundary.

**This is right for messaging and will be wrong for audio.** These calls happen
when a person taps something, so a JSON encode costs nothing measurable. A voice
call moves fifty frames a second in each direction and will need raw buffers with
no allocation per frame. That is a second entry point, and it is **not built**.

### Handles, not pointers

A session is an integer into a registry held inside the library. A wrapper
cannot free one twice, use one after freeing, or invent one: the worst a bad
handle produces is an error. The alternative is raw pointers in a language with
a garbage collector.

Call `session.free` and `key.free` when done. Forgetting leaks until the process
exits, which on a phone is a real leak, not a theoretical one.

## Dart, end to end

```dart
import 'dart:convert';
import 'dart:ffi';
import 'package:ffi/ffi.dart';

typedef _CallNative = Int32 Function(Pointer<Utf8>, Pointer<Pointer<Utf8>>);
typedef _Call = int Function(Pointer<Utf8>, Pointer<Pointer<Utf8>>);
typedef _FreeNative = Void Function(Pointer<Utf8>);
typedef _Free = void Function(Pointer<Utf8>);

class Rotelyx {
  final _Call _call;
  final _Free _free;

  Rotelyx(DynamicLibrary lib)
      : _call = lib.lookupFunction<_CallNative, _Call>('rotelyx_call'),
        _free = lib.lookupFunction<_FreeNative, _Free>('rotelyx_string_free');

  /// Android: DynamicLibrary.open('librotelyx_mobile.so')
  /// iOS:     DynamicLibrary.process()   (statically linked)
  /// Linux:   DynamicLibrary.open('librotelyx_mobile.so')
  factory Rotelyx.open() => Rotelyx(
        Platform.isIOS ? DynamicLibrary.process()
                       : DynamicLibrary.open('librotelyx_mobile.so'),
      );

  Map<String, dynamic> call(Map<String, dynamic> request) {
    final req = jsonEncode(request).toNativeUtf8();
    final slot = calloc<Pointer<Utf8>>();
    try {
      _call(req, slot);
      // Always set, so it is always read and always freed.
      final reply = jsonDecode(slot.value.toDartString()) as Map<String, dynamic>;
      _free(slot.value);
      if (reply['ok'] != true) throw RotelyxError(reply['error'] as String);
      return reply;
    } finally {
      calloc.free(req);
      calloc.free(slot);
    }
  }

  dynamic result(Map<String, dynamic> request) => call(request)['result'];
}

class RotelyxError implements Exception {
  final String message;
  RotelyxError(this.message);
  @override
  String toString() => 'Rotelyx: $message';
}
```

Pairing, which is the flow that matters:

```dart
final r = Rotelyx.open();
final ana = r.result({'op': 'session.new', 'label': 'ana'}) as int;
r.call({'op': 'session.found', 'handle': ana});

// Beto, on the other device, over whatever channel carries the pairing.
final package = r.result({'op': 'session.keyPackage', 'handle': beto}) as String;

final invite = r.result({'op': 'session.invite', 'handle': ana,
                         'keyPackage': package}) as Map;
r.call({'op': 'session.join', 'handle': beto,
        'welcome': invite['welcome'], 'ratchetTree': invite['ratchetTree']});

// The post-quantum half, which is not optional.
final betoPk = r.result({'op': 'session.hybridPublicKey', 'handle': beto});
final ct = r.result({'op': 'session.encapsulateTo', 'handle': ana,
                     'hybridPublicKey': betoPk});
r.call({'op': 'session.openPq', 'handle': beto, 'ciphertext': ct});
final commit = r.result({'op': 'session.commitPq', 'handle': ana});
r.call({'op': 'session.receive', 'handle': beto, 'message': commit});

// Check before trusting: these must match on both devices.
assert(r.result({'op': 'session.safetyNumber', 'handle': ana}) ==
       r.result({'op': 'session.safetyNumber', 'handle': beto}));
```

## Operations

`handle` is a session handle unless stated. Every string is base64 unless the
name says hex. Times are hour buckets, the same ones the browser uses.

### No handle needed

| op | arguments | result |
|---|---|---|
| `abi.version` | | `"1"` |
| `protocol.version` | | version string |
| `protocol.maxMembers` | | integer |
| `session.new` | `label` | new handle |
| `session.unseal` | `blob`, `key` | new handle |
| `session.free` | `handle` | bool |
| `key.create` | `passphrase` | key handle |
| `key.unlock` | `passphrase`, `blob` | key handle |
| `key.fromPlatformKey` | `key` | key handle |
| `key.unlockWithPlatformKey` | `key`, `blob` | key handle |
| `key.free` | `handle` | bool |
| `key.sealBlob` | `key`, `data` | sealed |
| `key.openBlob` | `key`, `blob` | data |
| `rendezvous.tag` | `passphrase` | tag, hex |
| `rendezvous.seal` | `tag` hex, `payload` | envelope |
| `rendezvous.open` | `envelope`, `tag` hex | payload |

### On a session

| op | arguments | result |
|---|---|---|
| `session.found` | | null |
| `session.keyPackage` | | key package |
| `session.hybridPublicKey` | | public key |
| `session.invite` | `keyPackage` | `{commit, welcome, ratchetTree}` |
| `session.join` | `welcome`, `ratchetTree` | null |
| `session.encapsulateTo` | `hybridPublicKey` | ciphertext |
| `session.openPq` | `ciphertext` | null |
| `session.beginGroupPq` | `hybridPublicKeys` (array) | array |
| `session.openGroupPq` | `wrapped` | null |
| `session.commitPq` | | commit |
| `session.send` | `text` | sealed message |
| `session.receive` | `message` | text, or null for a commit |
| `session.rekeyAfterRestore` | | commit, to be delivered |
| `session.seal` | `ciphertext`, `timeBucket` | envelope |
| `session.open` | `envelope`, `timeBucket`, `lookback` | ciphertext |
| `session.sealForGroup` | `ciphertext`, `timeBucket` | array of envelopes |
| `session.sealCommitForGroup` | `ciphertext`, `timeBucket` | array |
| `session.openMine` | `envelope`, `timeBucket`, `lookback` | ciphertext |
| `session.paddedPayload` | `ciphertext` | padded |
| `mailbox.receiptFor` | `envelope` | digest, hex. Needs no handle |
| `session.myTag` | `timeBucket` | tag, hex |
| `session.myPollingTags` | `timeBucket`, `lookback` | array of hex |
| `session.recipientTags` | `timeBucket` | array of hex |
| `session.commitRecipientTags` | `timeBucket` | array of hex |
| `session.tagFor` | `timeBucket` | tag, hex |

`session.removeMember` takes the **signature key**, which `session.rosterDetail`
carries and `session.roster` does not. That is not an oversight of the smaller
call: a label is a claim, two members can make the same one, and removing by
label would eventually remove the wrong person. Removal returns a commit, and
the caller delivers it with `session.sealCommitForGroup`, addressed at the epoch
the others are still on, exactly as an invitation's commit is. A removal nobody
receives is not a removal.

`mailbox.receiptFor` is how an envelope is named when telling the mailbox it
arrived. Delivery peeks and removal waits for that receipt, so an envelope
nobody acknowledges sits until its seven-day TTL and the tag fills at 256, after
which the server refuses deposits and messages are lost with nothing said. Send
it after the envelope is opened and written down, never on arrival: not
acknowledging costs re-delivery, acknowledging something unstored loses it.

`session.rekeyAfterRestore` is the one an application forgets and then cannot
explain. A conversation read back from storage believes it is at a generation
the group has already spent, so everything it sends is refused by the far side
and nothing tells the person holding the phone: to them, messages simply stop
arriving. `session.send` returns `RestoredAndNotRekeyed` rather than sending,
and this call moves the epoch and hands back a commit the caller has to
deliver. It cannot happen inside the restore, because a restore has no way to
send anything, and a rekey nobody receives is the same failure from the other
side.
| `session.pollingTags` | `timeBucket`, `lookback` | array of hex |
| `session.roster` | | array of labels |
| `session.rosterDetail` | | JSON `[{"label":…,"key":…}]` |
| `session.removeMember` | `signatureKey` | commit, to be delivered |
| `session.epoch` | | integer |
| `session.memberCount` | | integer |
| `session.safetyNumber` | | digits |
| `session.sealSession` | `key` | sealed blob |

`lookback` defaults to 0 when omitted.

## Building

```sh
scripts/build-mobile              # this machine, for tests and desktop
scripts/build-mobile android      # arm64-v8a, armeabi-v7a, x86_64
scripts/build-mobile ios          # device and simulator slices
```

Android needs `cargo install cargo-ndk` and `ANDROID_NDK_HOME`.

### iOS needs a Mac for all of it, not just the last step

This said the slices build anywhere and the Mac was only needed for
`xcframework`. That is wrong, and the first thing anybody tries proves it:

```
$ cargo check -p rotelyx-mobile --target aarch64-apple-ios
error: failed to run custom build command for `ring v0.17.14`
  Compiler family detection failed: failed to find tool "clang"
  error occurred in cc-rs: failed to find tool "xcrun"
```

`ring` compiles C, and for an Apple target `cc-rs` asks `xcrun` for the SDK.
`xcrun` is macOS only. Nothing gets as far as compiling our own code.

**What has been checked from Linux**, so the Mac session is not a discovery
exercise:

- The three iOS targets install with `rustup` and are present.
- The Android-only dependencies, `jni` and `ndk-context`, are behind
  `[target.'cfg(target_os = "android")'.dependencies]` and will not be built for
  iOS.
- The one Android-only function, `Java_com_rotelyx_app_Native_initAndroidContext`,
  is behind `#[cfg(target_os = "android")]`.
- Nothing in the mobile, media, audio or wasm crates enumerates operating
  systems in a way that omits iOS. `cpal` reaches CoreAudio on iOS the same way
  it reaches oboe on Android.

**What is unknown until it runs on a Mac:** whether the engine itself compiles
for `aarch64-apple-ios`. It never has. Expect the first attempt to find things,
and expect them to be in the dependency graph rather than in this crate, because
this crate is the part that has been checked.

On the Mac, `scripts/build-mobile ios` builds all three slices and the
`xcframework` in one go. Xcode command line tools are enough; a full Xcode
install is not needed for `lipo`, though `xcodebuild -create-xcframework` is.

The script **refuses to finish** if a build path from the machine reaches the
binary, for the reason in `THREAT-MODEL.md` section 7: an artifact users install
must not carry the build machine's username.

Copy `target/mobile/jniLibs` into the app's
`android/app/src/main/jniLibs`, and Flutter packages it.

## A key the platform holds

`key.create` and `key.unlock` derive the sealing key from a passphrase with
Argon2id at 64 MiB. That is right in a browser, which has nothing better, and it
is not right on a phone: Android has a keystore and iOS a secure enclave, and a
key held there is protected by hardware and by the device unlock rather than by
something a person can be made to say.

Neither is reachable from this engine, so the application fetches the key and
passes it:

```json
{"op": "key.fromPlatformKey", "key": "<32 bytes, base64url>"}
{"op": "key.unlockWithPlatformKey", "key": "<same>", "blob": "<sealed>"}
```

**What goes in has to be a key.** Nothing here stretches it, so anything typed
is worth *less* on this path than it would have been on the passphrase one.
Exactly 32 bytes, refused rather than padded. Give it what the keystore
returned.

A blob sealed this way looks like any other, salt included, so the two are not
told apart on disk. Nothing is derived from that salt here; it is carried
because the format has a slot for it, and a blob with an empty one would
announce which kind of key opens it.

## Saying an envelope arrived

The mailbox does not remove an envelope when it hands it over. It **peeks**, and
removes on an acknowledgement, so that a delivery that never reached anybody is
still there to try again. That means an application which does not acknowledge
leaves everything it has already read sitting in the mailbox.

```json
{"op": "collected", "digests": ["<hex>", ...]}
```

The digest comes from the engine: `mailbox.receiptFor` with the envelope, which
needs no handle. It is a hash of what arrived, not a capability: the server
refuses a receipt for a tag the connection is not listening on.

### What it costs to skip, which is not obvious

An application that reads and never acknowledges works perfectly. Nothing fails,
nothing is shown twice, and three things go wrong out of sight:

- **Retention.** Every envelope stays for the full seven-day TTL. A seized disk
  yields seven days of ciphertext rather than only what was never delivered.
  The content stays unreadable either way; what leaks is who had post waiting.
- **Delivery stops.** A tag holds 256 envelopes. Once it fills, the server
  refuses further deposits and the **sender is not told**, so messages are lost
  silently. That is the one a user meets.
- **Battery.** Every reconnect re-downloads the whole backlog. MLS refuses the
  replays so nothing appears twice, which is exactly why this is invisible from
  the screen.

## Waking a phone that is not running

A device that is asleep collects nothing, so the mailbox wakes it. What the
application has to do is register its push token once, and the one field that
matters is **which service**, because getting it wrong on Android means no
notifications and no error.

```json
{"op": "registerWake", "token": "<the platform token>",
 "kind": "apns" | "fcm", "secret": "<64 hex characters>"}
```

| Platform | `kind` | Why |
|---|---|---|
| iOS | `apns` | Apple directly |
| Android | `fcm` | Firebase, the only path there is |

**An iPhone must not send `fcm`.** Firebase on iOS relays to APNs, so it puts
Google on a path Apple already serves and removes nothing. The server cannot
enforce this: a Firebase token does not say which platform it came from, so this
is the application's to get right.

`secret` is what a later `revokeWake` presents to take the registration back. A
token is an address, not a credential: without it, anybody who learned a token
could silence that phone. Sixty four hex characters, or omit it and accept that
the registration cannot be revoked.

### What the server does with it, and what it refuses to do

It wakes **every registered device on a fixed schedule**, not the one device a
message is for. That is the privacy property and not a simplification: waking on
arrival would mean this server knows which device belongs to which mailbox tag,
and would tell Apple and Google the timing of every conversation. A rhythm that
is identical for every device carries neither. See `wake.rs`.

So the push carries nothing. The message is in the mailbox and the device goes
to look; the server could not read it if it tried.

A server started with neither an APNs key nor a Firebase service account refuses
`registerWake` with a reason, rather than accepting a registration it will never
act on.

## Voice

A second set of entry points, deliberately not JSON. These are called from an
audio callback fifty times a second in each direction, and a base64 encode plus
a JSON parse per frame would be a hundred allocations a second on the thread
where allocation is the one thing you must not do. They fill caller-owned
buffers and return counts: nothing to free, nothing to allocate.

```c
int64_t rotelyx_call_open(uint64_t session, int32_t bytes_per_frame, int32_t fidelity,
                          const uint8_t *call, int32_t call_len);
int32_t rotelyx_call_capture(int64_t call, const int16_t *pcm, int32_t samples,
                             uint8_t *out, int32_t out_capacity);
int32_t rotelyx_call_deliver(int64_t call, const uint8_t *datagram, int32_t len,
                             uint64_t now_ms);
int32_t rotelyx_call_playback(int64_t call, int16_t *pcm, int32_t capacity);
int32_t rotelyx_call_stats(int64_t call, char **response_json);
int32_t rotelyx_call_close(int64_t call);
```

**Audio format**: signed 16 bit, 48 kHz, mono, 960 samples a frame, which is
20 ms. `ROTELYX_FRAME_SAMPLES` is that number. If your capture gives you
something else, resample before you get here: the engine's window is fixed and
a frame that is not 960 samples is refused rather than quietly mixed.

`bytes_per_frame` sets the rate. 60 is 24 kbit/s, 30 is 12. `fidelity` non-zero
recovers loss by asking for it again at the cost of seconds of buffer, which is
right for a voice message and wrong for a live call; zero conceals instead.

`call` is the identifier both ends agreed on for **this** call, at least eight
bytes, fresh for every call, and it is not optional. **Reusing one reinstates
the defect it exists to close**, with no error and no symptom: the library
checks the length and cannot check the freshness, because it sees one call at a
time. The media keys are derived from the group's
exported secret and the speaker's position in the roster, and both are fixed for
an entire MLS epoch while the frame counter restarts at zero, so without a value
that changes per call a second call repeats the first one's key and nonce from
the first frame. Pass whatever your call signalling already carries: the side
that rings mints it, the side that answers echoes it.

`rotelyx_call_open` returns a handle, or a negative reason: **-1** no such
session, **-2** no conversation yet, **-3** not in its own roster, **-4** too
many participants or a bad policy, **-5** no usable call binding. Negative rather than a message because the
audio path does not allocate.

### The three that run on the audio thread

**`rotelyx_call_capture`** takes 20 ms from the microphone and writes a
datagram, returning its length. **It returns 0 for the first frame of a call**,
which is not an error: the codec's window is 40 ms over a 20 ms hop, so the
first frame only primes it. That is 20 ms of added latency and it is the price
of the longer window.

**`rotelyx_call_deliver`** takes a datagram that arrived and the time it
arrived, in milliseconds from any monotonic clock. It returns 0 for a datagram
that failed to authenticate as well as for one that succeeded: a forged packet
is not the caller's error and there is nothing for them to do about it.

**`rotelyx_call_playback`** fills 960 samples for the speaker and **always
returns a full frame**, filling a gap with silence. An audio callback handed
fewer samples than it asked for produces a click, and a click is worse than the
silence it replaced.

```dart
// On the capture callback.
final n = _capture(call, pcm, 960, buf, 1200);
if (n > 0) socket.send(buf.asTypedList(n));   // n == 0 is the first frame

// On a datagram arriving.
_deliver(call, bytes, bytes.length, DateTime.now().millisecondsSinceEpoch);

// On the playback callback.
_playback(call, out, 960);                     // always 960
```

## What is not here

**No transport.** The app supplies the network. This library seals and opens; it
does not connect. That is deliberate: an app that already has a working socket
should not be made to adopt a second one.

**No packet loss concealment.** A gap plays as silence. Filling it with
something plausible is a real technique and it is not built, so the honest
behaviour is the audible one rather than a guess dressed up as audio.

**No mixing.** One remote speaker is played. A group call needs several summed,
which is a separate problem and doing it badly is worse than not doing it.

**No echo cancellation, ever.** It cannot live here. Cancelling echo requires
knowing what the speaker is playing, aligned in time with what the microphone
heard, so whoever owns the microphone must own the speaker. On a phone the right
answer is the platform's own: `VOICE_COMMUNICATION` with `AcousticEchoCanceler`
on Android, `AVAudioSession` in `.playAndRecord` with mode `.voiceChat` on iOS.
Two independent plugins for capture and playback will not get this, and the
symptom is a call that howls on speakerphone.
