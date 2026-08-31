//! The one part of this ABI that touches the network.
//!
//! # Read this before adding anything else here
//!
//! Every other operation in this crate is offline. `session.send` hands back
//! ciphertext for the caller to move; `session.receive` takes ciphertext the
//! caller already has. Twenty operations and not one of them opens a socket.
//!
//! That is deliberate and it is what lets a phone carry bytes however it can:
//! over the mailbox, over a push, over a piece of paper. **This module crosses
//! that line**, and it is the only one that does.
//!
//! # Why it had to be crossed
//!
//! Voice needs datagrams and it needs to cross NAT. The mailbox is a WebSocket,
//! which is TCP: one lost segment stalls everything behind it, and on a call a
//! frame that arrives late is worse than one that never arrives at all. There
//! is no arrangement of store-and-forward that fixes that.
//!
//! So a call gets a QUIC connection and nothing else does. Text still goes
//! through the caller. If a future operation wants a socket, the question to
//! ask first is whether it genuinely cannot be carried by the application, and
//! the answer for everything except live media is that it can.
//!
//! # What this costs, stated rather than discovered
//!
//! The crate already declared `rotelyx-net` and used it for one enum. Reaching
//! the transport turns that dependency into real weight in the phone's binary:
//! a QUIC stack, a relay client and the address machinery. That is the price of
//! calls and it is paid by every build that links this library, including one
//! that never places a call.
//!
//! # Relay only, and not as a preference
//!
//! [`rotelyx_media::transport::MediaOut`] refuses to be constructed on a
//! connection whose policy permits a direct path, because a direct path shows
//! the peer this device's address. `rotelyx_call_open` already forces
//! [`PathPolicy::RelayOnly`], so an endpoint opened here with anything else
//! produces a call that fails on the first frame for a reason nothing reports.
//!
//! This module therefore does not offer the choice.

use std::collections::HashMap;
use std::ffi::{c_char, CStr};
use std::sync::{Mutex, OnceLock};

use rotelyx_core::{Identity, RotelyxEndpoint};
use rotelyx_net::{
    Connection, EndpointAddr, NetConfig, PathPolicy, RelayPolicy, RelayUrl, TransportAddr,
};

/// The runtime the network runs on.
///
/// One for the process, started on first use. The ABI is synchronous and the
/// transport is not, so every call here blocks on this runtime rather than
/// asking the caller to bring one. A phone's audio thread must not block, which
/// is why the operations that happen per frame ([`send`] and [`recv`]) do not
/// await anything: only opening and connecting do.
fn runtime() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            // Two threads. The transport needs one to make progress while a
            // blocking call holds another, and a phone has no use for more.
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("the network runtime could not start")
    })
}

struct Endpoint {
    endpoint: RotelyxEndpoint,
    config: NetConfig,
}

struct Held {
    endpoints: HashMap<i64, Endpoint>,
    connections: HashMap<i64, Connection>,
    next: i64,
}

fn held() -> &'static Mutex<Held> {
    static HELD: OnceLock<Mutex<Held>> = OnceLock::new();
    HELD.get_or_init(|| {
        Mutex::new(Held {
            endpoints: HashMap::new(),
            connections: HashMap::new(),
            next: 1,
        })
    })
}

fn lock() -> std::sync::MutexGuard<'static, Held> {
    match held().lock() {
        Ok(g) => g,
        Err(p) => p.into_inner(),
    }
}

/// Read a C string, or return None rather than reading past the end.
///
/// # Safety
///
/// The caller promises a null-terminated string or null.
unsafe fn text(p: *const c_char) -> Option<String> {
    if p.is_null() {
        return None;
    }
    CStr::from_ptr(p).to_str().ok().map(str::to_owned)
}

/// Bind an endpoint that can be reached through a relay.
///
/// `secret` is thirty two bytes of identity, hex encoded. It is this device's
/// long-term key on the transport and it is the caller's to keep: the same
/// bytes on two devices is one identity in two places, which the transport will
/// not stop and which nobody will enjoy debugging.
///
/// `relay` is the relay's URL.
///
/// Returns a handle, or a negative number: -1 the arguments are not readable,
/// -2 the secret is not thirty two bytes of hex, -3 the relay URL will not
/// parse, -4 the endpoint would not bind.
///
/// # Safety
///
/// Both pointers must be null-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn rotelyx_net_open(secret_hex: *const c_char, relay: *const c_char) -> i64 {
    let (Some(secret_hex), Some(relay)) = (text(secret_hex), text(relay)) else {
        return -1;
    };

    let Ok(bytes) = data_encoding::HEXLOWER_PERMISSIVE.decode(secret_hex.as_bytes()) else {
        return -2;
    };
    let Ok(bytes): Result<[u8; 32], _> = bytes.try_into() else {
        return -2;
    };

    let Ok(url) = relay.parse::<RelayUrl>() else {
        return -3;
    };

    let identity = Identity::from_bytes(bytes);
    let config = NetConfig::new(RelayPolicy::SelfHosted(vec![url]), PathPolicy::RelayOnly);

    let bound = runtime().block_on(RotelyxEndpoint::bind(&identity, config.clone()));
    let Ok(endpoint) = bound else { return -4 };

    let mut h = lock();
    let handle = h.next;
    h.next += 1;
    h.endpoints.insert(handle, Endpoint { endpoint, config });
    handle
}

/// This endpoint's address, for the peer to connect to.
///
/// Base64url of the JSON the transport uses, with **the IP addresses removed**
/// and the relay put in their place.
///
/// That filtering is not tidiness. An `EndpointAddr` carries whatever the
/// endpoint knows about reaching itself, which on an ordinary device includes
/// its LAN address. Publishing that to whoever receives the invitation is
/// handing them a location, on the one configuration whose entire purpose is
/// not revealing it. The same reasoning and the same fix as `encode_addr` in
/// the terminal client, where it was found by reading what got printed.
///
/// Returns 0 and writes the string, or a negative number. The caller frees the
/// string with `rotelyx_string_free`.
///
/// # Safety
///
/// `out` must be a valid pointer to a `*mut c_char`.
#[no_mangle]
pub unsafe extern "C" fn rotelyx_net_addr(endpoint: i64, out: *mut *mut c_char) -> i32 {
    if out.is_null() {
        return -1;
    }

    let h = lock();
    let Some(held) = h.endpoints.get(&endpoint) else {
        return -2;
    };

    let mut addr: EndpointAddr = held.endpoint.addr();

    if !held.config.paths().permits_direct() {
        addr.addrs.retain(|a| !matches!(a, TransportAddr::Ip(_)));

        // Removing the IPs leaves nothing to route on, because the address is
        // read the moment the endpoint binds and the relay is not established
        // yet. The relay from the configuration is the right thing to publish:
        // it is where this endpoint can be reached, it is already public, and
        // it is what the peer will use.
        for url in held.config.relays().urls() {
            addr.addrs.insert(TransportAddr::Relay(url.clone()));
        }
    }

    let Ok(json) = serde_json::to_vec(&addr) else {
        return -3;
    };
    let encoded = data_encoding::BASE64URL_NOPAD.encode(&json);

    match std::ffi::CString::new(encoded) {
        Ok(s) => {
            *out = s.into_raw();
            0
        }
        Err(_) => -3,
    }
}

/// Connect to a peer, given what [`rotelyx_net_addr`] produced on their side.
///
/// Blocks until the connection is up or fails. Returns a connection handle, or
/// -1 unreadable arguments, -2 no such endpoint, -3 the address will not
/// decode, -4 the connection failed.
///
/// # Safety
///
/// `addr` must be a null-terminated string.
#[no_mangle]
pub unsafe extern "C" fn rotelyx_net_connect(endpoint: i64, addr: *const c_char) -> i64 {
    let Some(addr) = text(addr) else { return -1 };

    let Ok(bytes) = data_encoding::BASE64URL_NOPAD.decode(addr.trim().as_bytes()) else {
        return -3;
    };
    let Ok(target): Result<EndpointAddr, _> = serde_json::from_slice(&bytes) else {
        return -3;
    };

    // The endpoint is cloned out rather than held across the await, because the
    // lock is a plain mutex and the connect blocks for as long as the network
    // takes. Holding it would stop every other call in the process.
    let transport = {
        let h = lock();
        let Some(held) = h.endpoints.get(&endpoint) else {
            return -2;
        };
        held.endpoint.transport().clone()
    };

    let connected = runtime().block_on(transport.connect(target, rotelyx_core::ALPN));
    let Ok(session) = connected else { return -4 };

    let (_send, _recv, conn) = session.split();

    let mut h = lock();
    let handle = h.next;
    h.next += 1;
    h.connections.insert(handle, conn);
    handle
}

/// Wait up to `timeout_ms` for a peer to connect.
///
/// Returns a handle, 0 when nobody connected in time, -2 no such endpoint, -4
/// something arrived and failed.
///
/// # Why this takes a timeout and does not simply block
///
/// Because the caller is single threaded and does not know it.
///
/// Written first as a blocking accept, which is the obvious shape and is wrong
/// for every consumer this ABI has. A Dart isolate has one thread: a blocking
/// accept there does not wait alongside other work, it stops the isolate, so
/// the connect that was supposed to happen concurrently never runs and the two
/// sides deadlock waiting for each other. Found by writing exactly that test
/// and watching it hang for ten minutes.
///
/// On a phone it would be worse than a deadlock. Blocking the interface thread
/// for twenty seconds is an application the system offers to close.
///
/// So this returns, and the caller asks again. Zero means "not yet", which is
/// the ordinary answer and not a failure.
#[no_mangle]
pub extern "C" fn rotelyx_net_accept(endpoint: i64, timeout_ms: i32) -> i64 {
    let transport = {
        let h = lock();
        let Some(held) = h.endpoints.get(&endpoint) else {
            return -2;
        };
        held.endpoint.transport().clone()
    };

    let waited = runtime().block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms.max(0) as u64),
            transport.accept(),
        )
        .await
    });

    let Ok(accepted) = waited else { return 0 };
    let Ok(session) = accepted else { return -4 };

    let (_send, _recv, conn) = session.split();

    let mut h = lock();
    let handle = h.next;
    h.next += 1;
    h.connections.insert(handle, conn);
    handle
}

/// Send one datagram.
///
/// Does not block and does not await: QUIC datagrams are fire and forget, which
/// is what makes them right for voice. Returns 0, or -1 unreadable, -2 no such
/// connection, -3 the transport refused it, which for a datagram means it was
/// larger than the path will carry.
///
/// # Safety
///
/// `data` must point to `len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn rotelyx_net_send(connection: i64, data: *const u8, len: i32) -> i32 {
    if data.is_null() || len < 0 {
        return -1;
    }

    let h = lock();
    let Some(conn) = h.connections.get(&connection) else {
        return -2;
    };

    let bytes = std::slice::from_raw_parts(data, len as usize);
    match conn.send_datagram(bytes.to_vec().into()) {
        Ok(()) => 0,
        Err(_) => -3,
    }
}

/// Read one datagram, waiting up to `timeout_ms` for one.
///
/// Returns the number of bytes written, 0 when nothing arrived in time, or a
/// negative number. A timeout rather than a blocking read so the caller's audio
/// loop keeps its own clock: a read that blocks forever is one that cannot be
/// stopped when the call ends.
///
/// # Safety
///
/// `out` must point to `capacity` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn rotelyx_net_recv(
    connection: i64,
    out: *mut u8,
    capacity: i32,
    timeout_ms: i32,
) -> i32 {
    if out.is_null() || capacity <= 0 {
        return -1;
    }

    let conn = {
        let h = lock();
        let Some(conn) = h.connections.get(&connection) else {
            return -2;
        };
        conn.clone()
    };

    let waited = runtime().block_on(async {
        tokio::time::timeout(
            std::time::Duration::from_millis(timeout_ms.max(0) as u64),
            conn.read_datagram(),
        )
        .await
    });

    let Ok(Ok(bytes)) = waited else {
        // Either the timeout expired or the connection is gone. Both are
        // reported as "nothing", because an audio loop asks again either way
        // and the difference is visible from the connection's own state.
        return 0;
    };

    if bytes.len() > capacity as usize {
        return -3;
    }

    std::ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len());
    bytes.len() as i32
}

/// Close a connection.
#[no_mangle]
pub extern "C" fn rotelyx_net_close(connection: i64) -> i32 {
    let mut h = lock();
    match h.connections.remove(&connection) {
        Some(_) => 0,
        None => -2,
    }
}

/// Shut an endpoint down and forget it.
///
/// Connections opened from it are not closed here: a caller that shuts the
/// endpoint while a call is running has made a mistake, and taking the call
/// down silently would hide it.
#[no_mangle]
pub extern "C" fn rotelyx_net_shutdown(endpoint: i64) -> i32 {
    let mut h = lock();
    match h.endpoints.remove(&endpoint) {
        Some(_) => 0,
        None => -2,
    }
}
