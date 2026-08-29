//! Rotelyx for a phone, or a laptop, or anything that is not a browser.
//!
//! # What this is
//!
//! `rotelyx-wasm` wraps the engine for JavaScript. This wraps the same engine,
//! the same crate, for everything else: Android through `dart:ffi` or JNI, iOS
//! through a static library, Flutter desktop through a plugin.
//!
//! It reimplements nothing. `rotelyx-wasm` is an `rlib` as well as a `cdylib`
//! and its browser-only dependencies are gated to `wasm32`, so the code that
//! runs in the browser is the code that runs here, byte for byte. If protocol
//! logic ever appears in this file, that is a defect: two implementations of a
//! handshake diverge, and the divergence is a security bug that presents as an
//! interoperability bug.
//!
//! # This ABI touches the network, in exactly one place
//!
//! Everything below except `net.rs` is offline. `session.send` hands back
//! ciphertext for the caller to move and `session.receive` takes ciphertext the
//! caller already has: twenty operations, not one of which opens a socket. That
//! is what lets a phone carry bytes however it can.
//!
//! `rotelyx_net_*` breaks that, and it is the only thing that does. Voice needs
//! datagrams and needs to cross NAT, and neither survives a WebSocket to the
//! mailbox: that is TCP, one lost segment stalls everything behind it, and on a
//! call a frame that arrives late is worse than one that never arrives.
//!
//! It also has a weight. This crate declared `rotelyx-net` before for one enum;
//! reaching the transport puts a QUIC stack and a relay client in the binary of
//! every build that links this library, including one that never calls anybody.
//!
//! See `net.rs`, which says what it costs and refuses to offer a direct path.
//!
//! # Why one function instead of forty two
//!
//! The engine's surface is 42 calls, all of which take and return base64 or hex
//! strings. Exposed as 42 typed C functions that is roughly fifteen hundred
//! lines of `unsafe` marshalling, all of which has to be right, plus a matching
//! fifteen hundred on the consuming side.
//!
//! Instead there is one:
//!
//! ```c
//! int32_t rotelyx_call(const char *request_json, char **response_json);
//! void    rotelyx_string_free(char *s);
//! const char *rotelyx_abi_version(void);
//! ```
//!
//! Three symbols. The caller sends `{"op":"session.send","handle":1,"text":"hi"}`
//! and gets `{"ok":true,"result":"..."}`. A Dart wrapper for the whole engine is
//! about a hundred lines, adding an operation does not change the ABI, and there
//! is exactly one place where a string crosses the boundary rather than 42.
//!
//! **This is right for messaging and will be wrong for audio.** These calls
//! happen when a person does something, so a JSON encode is free. A call moves
//! 50 frames a second in each direction and will need raw buffers with no
//! allocation. That is a second, separate entry point, and it is not built.
//!
//! # Handles, not pointers
//!
//! A session is an integer into a registry held here, not a pointer handed
//! across the boundary. A wrapper cannot then free one twice, use one after
//! freeing, or fabricate one: the worst it can do with a bad handle is get an
//! error back. Given that the alternative is raw pointers in a language with a
//! garbage collector, this is not a close call.

use std::collections::HashMap;
use std::ffi::{c_char, CStr, CString};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use rotelyx_wasm::{Session, SessionKey};
use serde_json::{json, Value};

/// The shape of a request and a response. Bump on any incompatible change, so
/// that a wrapper built against an older engine says so instead of misreading.
const ABI_VERSION: &str = "1";

// ---------------------------------------------------------------------------
// The registry
// ---------------------------------------------------------------------------

struct Registry {
    sessions: HashMap<u64, Session>,
    keys: HashMap<u64, SessionKey>,
}

fn registry() -> &'static Mutex<Registry> {
    static REGISTRY: std::sync::OnceLock<Mutex<Registry>> = std::sync::OnceLock::new();
    REGISTRY.get_or_init(|| {
        Mutex::new(Registry {
            sessions: HashMap::new(),
            keys: HashMap::new(),
        })
    })
}

fn next_handle() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// A poisoned lock means a previous call panicked while holding it.
///
/// Recovered rather than propagated: the alternative is that one panic in one
/// operation makes every later operation fail for the lifetime of the process,
/// which on a phone is until the user force-quits. The state behind the lock is
/// a map of handles, and a panic mid-insert leaves it consistent.
fn lock() -> std::sync::MutexGuard<'static, Registry> {
    match registry().lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

// ---------------------------------------------------------------------------
// Argument helpers
// ---------------------------------------------------------------------------

type Res = Result<Value, String>;

fn str_arg(req: &Value, name: &str) -> Result<String, String> {
    req.get(name)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| format!("missing string argument `{name}`"))
}

fn u64_arg(req: &Value, name: &str) -> Result<u64, String> {
    req.get(name)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| format!("missing integer argument `{name}`"))
}

fn opt_u64(req: &Value, name: &str, default: u64) -> u64 {
    req.get(name).and_then(|v| v.as_u64()).unwrap_or(default)
}

fn list_arg(req: &Value, name: &str) -> Result<Vec<String>, String> {
    let arr = req
        .get(name)
        .and_then(|v| v.as_array())
        .ok_or_else(|| format!("missing array argument `{name}`"))?;
    arr.iter()
        .map(|v| {
            v.as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| format!("`{name}` must be an array of strings"))
        })
        .collect()
}

/// Engine errors reach here as `rotelyx_wasm::Error`, whose `Display` is the
/// message the browser would have shown. Same text on every platform, which is
/// what makes a bug report from a phone comparable to one from a tab.
fn engine<T>(r: Result<T, rotelyx_wasm::Error>) -> Result<T, String> {
    r.map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

fn dispatch(req: &Value) -> Res {
    let op = req
        .get("op")
        .and_then(|v| v.as_str())
        .ok_or("missing `op`")?;

    // Operations that need no handle.
    match op {
        "abi.version" => return Ok(json!(ABI_VERSION)),
        "protocol.version" => return Ok(json!(rotelyx_wasm::protocol_version())),
        "protocol.maxMembers" => return Ok(json!(rotelyx_wasm::max_members())),

        "session.new" => {
            let label = str_arg(req, "label")?;
            let session = engine(Session::new(&label))?;
            let handle = next_handle();
            lock().sessions.insert(handle, session);
            return Ok(json!(handle));
        }
        "session.unseal" => {
            let blob = str_arg(req, "blob")?;
            let key_handle = u64_arg(req, "key")?;
            let mut reg = lock();
            // The borrow of `reg.keys` ends before `reg.sessions` is touched,
            // which is why this is a block rather than one statement: the two
            // are different fields, so the compiler can split the borrow, but
            // only if the first one has finished.
            let session = {
                let key = reg.keys.get(&key_handle).ok_or("no such key handle")?;
                engine(Session::unseal_session(&blob, key))?
            };
            let handle = next_handle();
            reg.sessions.insert(handle, session);
            return Ok(json!(handle));
        }
        "session.free" => {
            let handle = u64_arg(req, "handle")?;
            return Ok(json!(lock().sessions.remove(&handle).is_some()));
        }

        "key.create" => {
            let passphrase = str_arg(req, "passphrase")?;
            let key = engine(SessionKey::create(&passphrase))?;
            let handle = next_handle();
            lock().keys.insert(handle, key);
            return Ok(json!(handle));
        }
        "key.unlock" => {
            let passphrase = str_arg(req, "passphrase")?;
            let blob = str_arg(req, "blob")?;
            let key = engine(SessionKey::unlock(&passphrase, &blob))?;
            let handle = next_handle();
            lock().keys.insert(handle, key);
            return Ok(json!(handle));
        }
        "key.free" => {
            let handle = u64_arg(req, "handle")?;
            return Ok(json!(lock().keys.remove(&handle).is_some()));
        }
        "key.sealBlob" => {
            let handle = u64_arg(req, "key")?;
            let data = str_arg(req, "data")?;
            let reg = lock();
            let key = reg.keys.get(&handle).ok_or("no such key handle")?;
            return Ok(json!(engine(rotelyx_wasm::seal_blob(key, &data))?));
        }
        "key.openBlob" => {
            let handle = u64_arg(req, "key")?;
            let blob = str_arg(req, "blob")?;
            let reg = lock();
            let key = reg.keys.get(&handle).ok_or("no such key handle")?;
            return Ok(json!(engine(rotelyx_wasm::open_blob(key, &blob))?));
        }

        // Needs no session: the digest is over the envelope's own bytes.
        //
        // Delivery peeks and removal waits for this receipt, so an envelope
        // nobody acknowledges sits until its TTL and the tag fills, after which
        // the server refuses deposits and messages are lost with nothing said.
        // Send it after the envelope is opened and written down, never on
        // arrival: not acknowledging costs re-delivery, acknowledging something
        // unstored loses it.
        "mailbox.receiptFor" => {
            let envelope = str_arg(req, "envelope")?;
            return Ok(json!(engine(rotelyx_wasm::receipt_for(&envelope))?));
        }

        "rendezvous.tag" => {
            let passphrase = str_arg(req, "passphrase")?;
            return Ok(json!(engine(rotelyx_wasm::rendezvous_tag(&passphrase))?));
        }
        "rendezvous.seal" => {
            let tag = str_arg(req, "tag")?;
            let payload = str_arg(req, "payload")?;
            return Ok(json!(engine(rotelyx_wasm::seal_under(&tag, &payload))?));
        }
        "rendezvous.open" => {
            let envelope = str_arg(req, "envelope")?;
            let tag = str_arg(req, "tag")?;
            return Ok(json!(engine(rotelyx_wasm::open_under(&envelope, &tag))?));
        }
        _ => {}
    }

    // Everything else acts on a session.
    let handle = u64_arg(req, "handle")?;

    // Sealing needs a session and a key at once. Handled before the mutable
    // lookup below, because two shared borrows of two different fields are
    // fine and a mutable one plus a shared one is not.
    if op == "session.sealSession" {
        let key_handle = u64_arg(req, "key")?;
        let reg = lock();
        let key = reg.keys.get(&key_handle).ok_or("no such key handle")?;
        let session = reg.sessions.get(&handle).ok_or("no such session handle")?;
        return Ok(json!(engine(session.seal_session(key))?));
    }

    let mut reg = lock();
    let s = reg.sessions.get_mut(&handle).ok_or("no such session handle")?;

    let out = match op {
        "session.keyPackage" => json!(engine(s.key_package())?),
        "session.hybridPublicKey" => json!(s.hybrid_public_key()),
        "session.found" => {
            engine(s.found())?;
            Value::Null
        }
        "session.invite" => {
            let kp = str_arg(req, "keyPackage")?;
            let inv = engine(s.invite(&kp))?;
            json!({
                "commit": inv.commit,
                "welcome": inv.welcome,
                "ratchetTree": inv.ratchet_tree,
            })
        }
        "session.join" => {
            let welcome = str_arg(req, "welcome")?;
            let tree = str_arg(req, "ratchetTree")?;
            engine(s.join(&welcome, &tree))?;
            Value::Null
        }
        "session.encapsulateTo" => {
            let pk = str_arg(req, "hybridPublicKey")?;
            json!(engine(s.encapsulate_to(&pk))?)
        }
        "session.openPq" => {
            let ct = str_arg(req, "ciphertext")?;
            engine(s.open_pq(&ct))?;
            Value::Null
        }
        "session.beginGroupPq" => {
            let keys = list_arg(req, "hybridPublicKeys")?;
            json!(engine(s.begin_group_pq(keys))?)
        }
        "session.openGroupPq" => {
            let wrapped = str_arg(req, "wrapped")?;
            engine(s.open_group_pq(&wrapped))?;
            Value::Null
        }
        "session.commitPq" => json!(engine(s.commit_pq())?),

        // A conversation read back from storage cannot send until it has moved
        // to a fresh epoch.
        //
        // A file is a copy, and a copy that resumes sending is sending at
        // generations the other side has already spent: the receiver deletes
        // each generation's secret as it uses it, so those messages are refused
        // and nothing says so. The core marks a restored session and refuses
        // until this has run.
        //
        // It was reachable from the browser, which binds the method directly,
        // and not from here, so on a phone "keep my chats" produced a
        // conversation that opened and would not send. Returns the commit, which
        // the caller must deliver before anything else.
        "session.rekeyAfterRestore" => json!(engine(s.rekey_after_restore())?),

        "session.send" => {
            let text = str_arg(req, "text")?;
            json!(engine(s.send(&text))?)
        }
        "session.receive" => {
            let message = str_arg(req, "message")?;
            // Passed through as the object the binding produces: which of three
            // things arrived, rather than "the plaintext or null". A caller that
            // cannot tell a member joining from a routine rekey cannot surface
            // the one and stay quiet about the other, and surfacing membership
            // changes is a security control. See ADV-7 in the threat model.
            let json = engine(s.receive(&message))?;
            serde_json::from_str::<Value>(&json)
                .unwrap_or_else(|_| Value::String(json))
        }

        "session.seal" => {
            let ct = str_arg(req, "ciphertext")?;
            json!(engine(s.seal(&ct, u64_arg(req, "timeBucket")?))?)
        }
        "session.open" => {
            let envelope = str_arg(req, "envelope")?;
            json!(engine(s.open(
                &envelope,
                u64_arg(req, "timeBucket")?,
                opt_u64(req, "lookback", 0)
            ))?)
        }
        "session.sealForGroup" => {
            let ct = str_arg(req, "ciphertext")?;
            json!(engine(s.seal_for_group(&ct, u64_arg(req, "timeBucket")?))?)
        }
        "session.sealCommitForGroup" => {
            let ct = str_arg(req, "ciphertext")?;
            json!(engine(
                s.seal_commit_for_group(&ct, u64_arg(req, "timeBucket")?)
            )?)
        }
        "session.openMine" => {
            let envelope = str_arg(req, "envelope")?;
            json!(engine(s.open_mine(
                &envelope,
                u64_arg(req, "timeBucket")?,
                opt_u64(req, "lookback", 0)
            ))?)
        }
        "session.paddedPayload" => {
            let ct = str_arg(req, "ciphertext")?;
            json!(engine(s.padded_payload(&ct))?)
        }

        "session.myTag" => json!(engine(s.my_tag(u64_arg(req, "timeBucket")?))?),
        "session.myPollingTags" => json!(engine(
            s.my_polling_tags(u64_arg(req, "timeBucket")?, opt_u64(req, "lookback", 0))
        )?),
        "session.recipientTags" => json!(engine(s.recipient_tags(u64_arg(req, "timeBucket")?))?),
        "session.commitRecipientTags" => {
            json!(engine(s.commit_recipient_tags(u64_arg(req, "timeBucket")?))?)
        }
        "session.tagFor" => json!(engine(s.tag_for(u64_arg(req, "timeBucket")?))?),
        "session.pollingTags" => json!(engine(
            s.polling_tags(u64_arg(req, "timeBucket")?, opt_u64(req, "lookback", 0))
        )?),

        // Revoking a member, or a device of your own that is gone.
        //
        // A removal is a commit, not a local setting: a leaf that is not in the
        // group can still decrypt everything the current epoch can, and
        // forgetting it on this device changes nothing about that. So this
        // hands back a commit, and the caller has to deliver it the way it
        // delivers the one from an invitation, through `sealCommitForGroup`,
        // addressed at the epoch the others are still on.
        //
        // Absent from this ABI until 29 August 2026, so the browser and the
        // desktop could revoke and the phone could not. That is the wrong way
        // round: a phone is the device that gets lost.
        "session.removeMember" => {
            let key = str_arg(req, "signatureKey")?;
            json!(engine(s.remove_member(&key))?)
        }

        // The roster with the key that identifies each member.
        //
        // Exposed together with `removeMember`, because either without the
        // other is useless: `roster` gives labels, a label is a claim two
        // members can both make, and removal takes a signature key.
        "session.rosterDetail" => json!(engine(s.roster_detail())?),

        "session.roster" => json!(engine(s.roster())?),
        "session.epoch" => json!(s.epoch()),
        "session.memberCount" => json!(s.member_count()),
        "session.safetyNumber" => json!(engine(s.safety_number())?),

        other => return Err(format!("unknown op `{other}`")),
    };

    Ok(out)
}

// ---------------------------------------------------------------------------
// The C boundary
// ---------------------------------------------------------------------------

/// Run one request. Returns 0 on success and -1 on failure.
///
/// `response` is always set to an owned C string that the caller must release
/// with [`rotelyx_string_free`], on success and on failure alike, so a wrapper
/// has one cleanup path rather than two. On success it is
/// `{"ok":true,"result":...}`; on failure `{"ok":false,"error":"..."}`.
///
/// # Safety
///
/// `request` must be a NUL-terminated UTF-8 string, and `response` must be a
/// valid pointer to write one pointer into.
#[no_mangle]
pub unsafe extern "C" fn rotelyx_call(request: *const c_char, response: *mut *mut c_char) -> i32 {
    if response.is_null() {
        return -1;
    }

    let reply = |value: Value| -> *mut c_char {
        // `to_string` on a serde value cannot fail, and a NUL cannot appear in
        // its output, so the CString cannot fail either.
        CString::new(value.to_string())
            .unwrap_or_else(|_| CString::new("{\"ok\":false,\"error\":\"encoding\"}").unwrap())
            .into_raw()
    };

    let result = (|| -> Res {
        if request.is_null() {
            return Err("request is null".into());
        }
        let text = CStr::from_ptr(request)
            .to_str()
            .map_err(|_| "request is not UTF-8".to_string())?;
        let parsed: Value =
            serde_json::from_str(text).map_err(|e| format!("request is not JSON: {e}"))?;

        // A panic in the engine must not unwind across the C boundary, which is
        // undefined behaviour. Caught here and reported as an error, which also
        // means a malformed input can crash a call rather than the process.
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| dispatch(&parsed))) {
            Ok(r) => r,
            Err(_) => Err("the engine panicked; this is a bug, please report it".into()),
        }
    })();

    match result {
        Ok(value) => {
            *response = reply(json!({"ok": true, "result": value}));
            0
        }
        Err(message) => {
            *response = reply(json!({"ok": false, "error": message}));
            -1
        }
    }
}

/// Release a string returned by [`rotelyx_call`].
///
/// # Safety
///
/// `s` must be a pointer this library returned, and must not be used after.
#[no_mangle]
pub unsafe extern "C" fn rotelyx_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

/// The request and response shape this library speaks. Never freed: static.
/// Hand the audio backend the Android context, once, before any call.
///
/// # Why this is needed and why it is a separate entry point
///
/// Audio on Android goes through oboe, which asks `ndk-context` for the JavaVM
/// and the Activity. Those cannot be discovered from Rust: the VM is created by
/// the runtime and the Activity belongs to Java, so somebody on the Java side
/// has to pass them down.
///
/// An `ndk-glue` application gets this for free because glue owns `main`. This
/// is a library inside a Flutter application, which owns nothing, so nothing was
/// setting it and `ndk_context::android_context()` aborted the process. Not an
/// exception a caller could catch and not an error code: an abort, which the
/// operating system reports as the application closing. Pressing call killed the
/// app with no message anywhere, which is what a real phone did.
///
/// # Safety
///
/// Called by the JVM through JNI with a live `JNIEnv` and a `Context`. The
/// context is turned into a global reference and deliberately leaked: it has to
/// outlive this call and every audio stream opened afterwards, and the process
/// ending is the only thing that ends it.
///
/// The name is the binding. JNI resolves by symbol, so this spells out the
/// application's package, and renaming the package without renaming this
/// compiles perfectly and then fails at the first call, on a device, with
/// `UnsatisfiedLinkError`. It must stay in step with `Native.kt`, which is
/// `com.rotelyx.app`.
#[cfg(target_os = "android")]
#[no_mangle]
pub extern "system" fn Java_com_rotelyx_app_Native_initAndroidContext(
    env: jni::JNIEnv,
    _class: jni::objects::JClass,
    context: jni::objects::JObject,
) {
    use std::sync::Once;

    // Once, because a second call would leak a second global reference and
    // replace a pointer the audio backend may already be holding.
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let Ok(vm) = env.get_java_vm() else {
            return;
        };
        let Ok(context) = env.new_global_ref(context) else {
            return;
        };

        unsafe {
            ndk_context::initialize_android_context(
                vm.get_java_vm_pointer() as *mut std::ffi::c_void,
                context.as_obj().as_raw() as *mut std::ffi::c_void,
            );
        }

        // Leaked on purpose. The global reference has to outlive every stream
        // the backend opens, and there is no later moment that could free it
        // safely.
        std::mem::forget(context);
        std::mem::forget(vm);
    });
}

#[no_mangle]
pub extern "C" fn rotelyx_abi_version() -> *const c_char {
    concat!("1", "\0").as_ptr() as *const c_char
}

// ---------------------------------------------------------------------------
// The audio path
// ---------------------------------------------------------------------------
//
// # Why this is not JSON
//
// Everything above crosses the boundary as JSON because it happens when a
// person taps something. A call moves fifty frames a second in each direction,
// and each one is 960 samples in and a datagram out. Base64 and a JSON parse
// per frame would be a hundred allocations a second in a garbage-collected
// runtime, on the audio thread, which is where allocation is exactly what you
// must not do.
//
// So these take and fill caller-owned buffers and return counts. No allocation
// per frame, nothing to free, and a wrapper can call them from a real-time
// callback.
//
// # What the app owns and this does not
//
// The microphone and the speaker. This never opens a device, and that is a
// deliberate boundary rather than an omission: cancelling echo requires knowing
// what the speaker is playing aligned in time with what the microphone heard, so
// whoever owns one must own both. On a phone the right canceller is the
// platform's own, and it only works if capture and playback share a
// voice-configured audio session. See `docs/MOBILE.md`.

use rotelyx_codec::mdct::{FRAME, WINDOW};
// The layered codec, which is what the desktop and the terminal client use.
//
// This was the base codec, and the two ends of a real call could not read each
// other: the phone encoded Telyx frames and the desktop decoded layered ones,
// so every frame crossed the network, authenticated, and failed to decode.
// Neither side reported a fault, because an undecodable frame is concealed
// rather than counted, and both people heard silence on an open call.
//
// A layered frame carries the base layer plus whatever refinement fits, so this
// is the wider of the two formats and the one to converge on.
use rotelyx_codec::layered::{LayeredDecoder, LayeredEncoder, LayeredFrame};
use rotelyx_media::transport::{MediaIn, MediaOut};
use rotelyx_media::{Mode, Playout, SenderKeys};
pub mod net;

use rotelyx_net::PathPolicy;

/// Samples in one frame: 960 at 48 kHz is 20 ms, which is what the app hands us.
pub const ROTELYX_FRAME_SAMPLES: i32 = FRAME as i32;

/// Bytes a protected frame can reach. A caller sizing a buffer by this is
/// always safe.
pub const ROTELYX_MAX_DATAGRAM: i32 = 1200;

struct Call {
    out: MediaOut,

    /// One receiver per other participant, by their index.
    ///
    /// # Why not one
    ///
    /// A receiver is keyed for the sender it listens to: `SenderKeys::derive`
    /// takes the sender's index, so a receiver built with your own index
    /// authenticates nothing anybody else sends. The first version of this did
    /// exactly that, and the test said "the listener heard nothing at all
    /// across 59 frames", which is the correct outcome of using the wrong key
    /// and would have been a silent one-way call on a phone.
    ///
    /// A map rather than a single peer because a group call has several, and
    /// the frame format already carries five bits of sender identity for this.
    inbound: HashMap<u8, MediaIn>,
    encoder: LayeredEncoder,
    decoder: LayeredDecoder,

    /// The encoder needs a 40 ms window and the app gives us 20 ms at a time,
    /// so one frame of history is held here. The first frame of a call produces
    /// no datagram for that reason, which is 20 ms of added latency and the
    /// price of the longer window.
    history: Vec<f32>,
    primed: bool,

    /// Decoded audio waiting for the app to collect it. The app pulls on its own
    /// clock, which may not be ours.
    pending: std::collections::VecDeque<f32>,

    concealed: u64,
}

fn calls() -> &'static Mutex<HashMap<i64, Call>> {
    static CALLS: std::sync::OnceLock<Mutex<HashMap<i64, Call>>> = std::sync::OnceLock::new();
    CALLS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn call_lock() -> std::sync::MutexGuard<'static, HashMap<i64, Call>> {
    match calls().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

/// Open a call on an established session.
///
/// `bytes_per_frame` sets the rate: 60 is 24 kbit/s, 30 is 12. `fidelity`
/// non-zero recovers loss by asking for it again, at the cost of seconds of
/// buffer, and is wrong for a live call; zero conceals instead.
///
/// Returns a call handle, or a negative number on failure. The reason is
/// available from `rotelyx_call` with `{"op":"abi.version"}`... no: failures
/// here are reported by the return value alone, because this is called from a
/// path that must not allocate. -1 no such session, -2 no conversation yet,
/// -3 the session is not in its own roster, -4 too many speakers, -5 no usable
/// call binding.
///
/// # Safety
///
/// `call` must point at `call_len` readable bytes, or be null. They are copied
/// before this returns and are not retained.
#[no_mangle]
pub unsafe extern "C" fn rotelyx_call_open(
    session: u64,
    bytes_per_frame: i32,
    fidelity: i32,
    call: *const u8,
    call_len: i32,
) -> i64 {
    // The value both ends agreed on for this call, which is what stops a second
    // call inside one MLS epoch from repeating the first call's nonces. The
    // caller passes the identifier its own signalling already carries. **-5** if
    // it is missing or too short: refusing is the only safe answer, because the
    // alternative is a call that encrypts under a key it has already used.
    let binding = if call.is_null() || call_len <= 0 {
        return -5;
    } else {
        // Safety: the caller promises `call_len` readable bytes at `call`, for
        // the duration of this call. Copied immediately.
        let bytes = unsafe { std::slice::from_raw_parts(call, call_len as usize) };
        match rotelyx_media::CallBinding::new(bytes) {
            Ok(b) => b,
            Err(_) => return -5,
        }
    };

    let (base, index, members) = {
        let reg = lock();
        let Some(s) = reg.sessions.get(&session) else {
            return -1;
        };
        let Ok(base) = s.media_base_key() else {
            return -2;
        };
        let Ok(index) = s.sender_index() else {
            return -3;
        };
        (base, index, s.member_count())
    };

    // A media header carries five bits of sender identity.
    if index >= rotelyx_media::MAX_SENDERS {
        return -4;
    }

    let mode = if fidelity != 0 {
        Mode::Fidelity
    } else {
        Mode::Conversational
    };

    // Calls never take a direct path: on one, the other party learns your
    // address. `MediaOut` refuses any policy that permits one, so this is not a
    // choice a caller can get wrong.
    let Ok(out) = MediaOut::with_mode(
        PathPolicy::RelayOnly,
        SenderKeys::derive(&base, index as u8, &binding),
        mode,
    ) else {
        return -4;
    };

    // A receiver for every other participant, keyed for them rather than for
    // us. Built at open time from the roster, so a group call works without a
    // second round of setup when somebody first speaks.
    let mut inbound = HashMap::new();
    for other in 0..members.min(rotelyx_media::MAX_SENDERS) {
        if other == index {
            continue;
        }
        let Ok(rx) = MediaIn::with_mode(
            PathPolicy::RelayOnly,
            SenderKeys::derive(&base, other as u8, &binding),
            mode,
        ) else {
            return -4;
        };
        inbound.insert(other as u8, rx);
    }

    let bytes = if bytes_per_frame <= 0 { 60 } else { bytes_per_frame as usize };
    let handle = next_handle() as i64;
    call_lock().insert(
        handle,
        Call {
            out,
            inbound,
            encoder: LayeredEncoder::new(bytes),
            decoder: LayeredDecoder::new(bytes),
            history: vec![0.0; FRAME],
            primed: false,
            pending: std::collections::VecDeque::new(),
            concealed: 0,
        },
    );
    handle
}

/// Encode and protect one 20 ms frame of captured audio.
///
/// `pcm` is `samples` signed 16 bit mono samples at 48 kHz; `samples` must be
/// [`ROTELYX_FRAME_SAMPLES`]. Writes the datagram to `out` and returns its
/// length, 0 if this frame only primed the window, or negative on failure.
///
/// # Safety
///
/// `pcm` must be readable for `samples` values and `out` writable for
/// `out_capacity` bytes.
#[no_mangle]
pub unsafe extern "C" fn rotelyx_call_capture(
    call: i64,
    pcm: *const i16,
    samples: i32,
    out: *mut u8,
    out_capacity: i32,
) -> i32 {
    if pcm.is_null() || out.is_null() || samples != ROTELYX_FRAME_SAMPLES || out_capacity < 0 {
        return -1;
    }
    let mut reg = call_lock();

    let Some(c) = reg.get_mut(&call) else { return -1 };

    let input = std::slice::from_raw_parts(pcm, samples as usize);

    // A 40 ms window over a 20 ms hop: the previous frame followed by this one.
    let mut window = Vec::with_capacity(WINDOW);
    window.extend_from_slice(&c.history);
    window.extend(input.iter().map(|s| *s as f32 / 32768.0));
    c.history
        .copy_from_slice(&window[FRAME..]);

    if !c.primed {
        c.primed = true;
        return 0;
    }

    let Ok(frame) = c.encoder.encode(&window) else { return -2 };
    // As bytes, because what the transport carries is a datagram and what the
    // far side parses is `LayeredFrame::from_bytes`.
    let packet = frame.to_bytes();
    let Ok(datagram) = c.out.frame(&packet) else { return -3 };

    if datagram.len() > out_capacity as usize {
        return -4;
    }
    std::ptr::copy_nonoverlapping(datagram.as_ptr(), out, datagram.len());
    datagram.len() as i32
}

/// Hand over a datagram that arrived, with the time it arrived in milliseconds.
///
/// The clock only has to be monotonic and in milliseconds; it is used for the
/// jitter estimate, not for anything cryptographic. Returns 0, or negative on
/// failure. A datagram that fails to authenticate is dropped and reported as
/// success, because that is not the caller's error and there is nothing for
/// them to do about it.
///
/// # Safety
///
/// `datagram` must be readable for `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn rotelyx_call_deliver(
    call: i64,
    datagram: *const u8,
    len: i32,
    now_ms: u64,
) -> i32 {
    if datagram.is_null() || len < 0 {
        return -1;
    }
    let mut reg = call_lock();
    let Some(c) = reg.get_mut(&call) else { return -1 };

    let bytes = std::slice::from_raw_parts(datagram, len as usize);

    // The sender id is a claim, not a fact: it selects which key checks the
    // tag, and a datagram that lies about it routes to the receiver that
    // rejects it. Reported as success either way, because a forged packet is
    // not the caller's error and there is nothing for them to do about it.
    let Ok(sender) = rotelyx_media::claimed_sender(bytes) else {
        return 0;
    };
    if let Some(rx) = c.inbound.get_mut(&sender) {
        rx.accept(bytes, now_ms);
    }
    0
}

/// Collect 20 ms of audio for the speaker.
///
/// Fills `pcm` with [`ROTELYX_FRAME_SAMPLES`] samples and returns how many were
/// written. A gap is filled with silence and still returns a full frame,
/// because an audio callback handed fewer samples than it asked for produces a
/// click, and a click is worse than the silence it replaced.
///
/// # Safety
///
/// `pcm` must be writable for `capacity` values.
#[no_mangle]
pub unsafe extern "C" fn rotelyx_call_playback(call: i64, pcm: *mut i16, capacity: i32) -> i32 {
    if pcm.is_null() || capacity < ROTELYX_FRAME_SAMPLES {
        return -1;
    }
    let mut reg = call_lock();
    let Some(c) = reg.get_mut(&call) else { return -1 };

    // One participant for now: mixing several speakers is a separate problem
    // and doing it badly is worse than not doing it. With one remote party
    // this is that party.
    let Some(rx) = c.inbound.values_mut().next() else {
        let out = std::slice::from_raw_parts_mut(pcm, FRAME);
        out.fill(0);
        return ROTELYX_FRAME_SAMPLES;
    };

    while c.pending.len() < FRAME {
        match rx.play() {
            Playout::Frame(packet) => match LayeredFrame::from_bytes(&packet)
                .and_then(|frame| c.decoder.decode(&frame))
            {
                Ok(audio) => c.pending.extend(audio),
                Err(_) => {
                    c.pending.extend(std::iter::repeat_n(0.0, FRAME));
                    c.concealed += 1;
                }
            },
            Playout::Missing => {
                // Conversational mode does not wait. Silence is a poor
                // concealment and an honest one: packet loss concealment is
                // not built, and pretending otherwise would hide that.
                c.pending.extend(std::iter::repeat_n(0.0, FRAME));
                c.concealed += 1;
            }
            // Waiting for a retransmission, or nothing has arrived yet. Give
            // the app silence rather than blocking its audio thread.
            Playout::Waiting | Playout::Starved => {
                c.pending.extend(std::iter::repeat_n(0.0, FRAME));
                break;
            }
        }
    }

    let out = std::slice::from_raw_parts_mut(pcm, FRAME);
    for slot in out.iter_mut() {
        let s = c.pending.pop_front().unwrap_or(0.0);
        *slot = (s.clamp(-1.0, 1.0) * 32767.0) as i16;
    }
    ROTELYX_FRAME_SAMPLES
}

/// What a debug overlay needs. Allocates, so not for the audio thread.
///
/// # Safety
///
/// `response` must be a valid pointer to write one pointer into. Free with
/// [`rotelyx_string_free`].
#[no_mangle]
pub unsafe extern "C" fn rotelyx_call_stats(call: i64, response: *mut *mut c_char) -> i32 {
    if response.is_null() {
        return -1;
    }
    let reg = call_lock();
    let value = match reg.get(&call) {
        Some(c) => json!({"ok": true, "result": {
            "framesSent": c.out.frames_sent(),
            // The worst of any participant, because a HUD showing an average
            // hides the one connection that is actually failing.
            "bufferMs": c.inbound.values().map(|r| r.delay_ms()).max().unwrap_or(0),
            "droppedTooLate": c.inbound.values().map(|r| r.dropped()).sum::<u64>(),
            "participants": c.inbound.len(),
            "concealed": c.concealed,
            "recoverable": c.out.recoverable(),
        }}),
        None => json!({"ok": false, "error": "no such call handle"}),
    };
    let ok = value["ok"] == json!(true);
    *response = CString::new(value.to_string())
        .unwrap_or_else(|_| CString::new("{\"ok\":false}").unwrap())
        .into_raw();
    if ok { 0 } else { -1 }
}

/// End a call and release everything it held.
#[no_mangle]
pub extern "C" fn rotelyx_call_close(call: i64) -> i32 {
    if call_lock().remove(&call).is_some() { 0 } else { -1 }
}
