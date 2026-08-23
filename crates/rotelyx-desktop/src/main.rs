//! Rotelyx desktop.
//!
//! A native window over the same protocol stack the CLI drives: real QUIC, real
//! MLS, real admission control, sealed identity on disk.
//!
//! ## Trust boundary
//!
//! Tauri's IPC is in process, so plaintext never crosses a socket. That is the
//! meaningful difference from the browser harness, which speaks over loopback
//! and therefore admits anything on the machine that can reach that port.
//!
//! What remains outside the boundary is the operating system and anything with
//! code execution on the device. That is unavoidable in any client that renders
//! a message to a screen.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod chats;
mod engine;
mod handshake;
mod meeting;
mod resume;
mod keyfile;

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use rotelyx_core::store::{self, Paths, StoredInvitation};
use rotelyx_core::{epoch_at, Identity, Invitation};
use rotelyx_net::EndpointAddr;
use tauri::{Emitter, Manager};
use tokio::sync::mpsc;

use engine::{Command, Engine, Event};

/// Process wide state. One identity, one session at a time.
struct App {
    identity: Identity,
    paths: Paths,
    /// The identity's passphrase, kept for the life of the window.
    ///
    /// A saved conversation is sealed under it, and a person asked for the same
    /// passphrase again every time they open a conversation would reasonably
    /// conclude the first attempt had failed. Zeroized when the window closes.
    passphrase: zeroize::Zeroizing<String>,
    /// Sender into the running session, if any.
    session: Mutex<Option<mpsc::UnboundedSender<Command>>>,
    /// The key every conversation on disk is sealed with.
    ///
    /// Derived once, at the door. Argon2id here is 64 MiB and three passes on
    /// purpose, so deriving it per conversation would make drawing a list of
    /// ten take ten seconds.
    chat_key: rotelyx_wasm::SessionKey,
}

fn now_epoch() -> Result<u64> {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the unix epoch")?
        .as_secs();
    Ok(epoch_at(secs))
}

pub(crate) fn encode_addr(addr: &EndpointAddr) -> Result<String> {
    let json = serde_json::to_vec(addr).context("encoding address")?;
    Ok(data_encoding::BASE64URL_NOPAD.encode(&json))
}

pub(crate) fn decode_addr(s: &str) -> Result<EndpointAddr> {
    let bytes = data_encoding::BASE64URL_NOPAD
        .decode(s.trim().as_bytes())
        .context("address is not valid base64")?;
    serde_json::from_slice(&bytes).context("address is not a valid Rotelyx address")
}

// ---------------------------------------------------------------------------
// Commands the window can call
// ---------------------------------------------------------------------------

#[derive(serde::Serialize)]
struct Snapshot {
    id: String,
    invitations: usize,
    /// The relay this window was started with, so the field is not empty next to
    /// a hint naming a host that does not exist.
    ///
    /// It used to be neither: the box showed `http://relay.example:3340` in grey
    /// and the process took no relay at all, because it parses no command line.
    /// Somebody starting it with `--relay` was told nothing and got nothing.
    relay: String,
    /// The mailbox this window was started with.
    ///
    /// A phone has no listening socket, moves between networks and is asleep
    /// most of the time, so a mailbox is the only place one can be reached. A
    /// window started without one can still do everything it did before and
    /// cannot meet a phone.
    mailbox: String,
}

/// An invitation code as a QR, so a phone can take it off the screen.
///
/// # Why this exists
///
/// The code is eighty-six characters of base64url. Reading that aloud, or typing
/// it from one screen into another, is where a pairing goes wrong: one wrong
/// character and the holder is refused with no way to see why. The phone client
/// already has a camera and a decoder, and this is the other half of that pair.
///
/// # Why an SVG string and not an image
///
/// The window is a web view. An SVG drops into it with no encoding step, no
/// temporary file and no second format to keep in step, and it stays sharp when
/// somebody leans in with a phone that is not focusing.
///
/// # Why the correction level is the highest one
///
/// The mark sits in the middle of the symbol, and every module it covers is a
/// module a scanner never sees. Level H can lose thirty percent of the code and
/// still read it, which is what pays for the logo. It was medium here and the
/// phone client has always used H, so the two drew visibly different pictures
/// of the same thing.
///
/// The plate is `LOGO_SHARE` of the width, the same fraction the phone uses and
/// the same fraction its `test/meeting_code_test.dart` asserts against. Raising
/// it is how a beautiful code that nothing can scan gets shipped.
fn qr_svg(code: &str) -> Result<String, String> {
    use qrcode::render::svg;
    use qrcode::{EcLevel, QrCode};

    let qr = QrCode::with_error_correction_level(code, EcLevel::H)
        .map_err(|e| format!("that code does not fit in a QR: {e}"))?;

    // Fixed modules rather than a minimum size, because the logo has to be
    // placed on this drawing afterwards and that needs the dimension to be
    // known rather than whatever the renderer settled on. Four modules of quiet
    // zone on each side is what the standard asks for.
    let across = qr.width() as u32 + 8;
    let module = ((QR_TARGET + across / 2) / across).max(4);
    let side = across * module;

    let drawing = qr
        .render()
        .module_dimensions(module, module)
        .dark_color(svg::Color(QR_DARK))
        .light_color(svg::Color("#ffffff"))
        .quiet_zone(true)
        .build();

    // The renderer puts an XML declaration in front. That belongs at the top of
    // a file and not in the middle of a document: this string is assigned to an
    // element's `innerHTML`, where a processing instruction is at best ignored.
    // Cut to the element itself, which is the only part that is being asked for.
    let at = drawing
        .find("<svg")
        .ok_or("the renderer produced something that is not an svg")?;
    let mut svg = drawing[at..].to_string();

    // The renderer has no reason to declare the xlink namespace and does not.
    // Without it the `xlink:href` below is an unbound prefix, which an HTML
    // parser forgives and an XML one refuses outright: opened as a file the
    // drawing became an error page with the code underneath it. Declared here
    // so it is a valid document wherever it ends up, not only inside the one
    // element it is currently written into.
    const OPEN: &str = "<svg ";
    svg.insert_str(
        OPEN.len(),
        r#"xmlns:xlink="http://www.w3.org/1999/xlink" "#,
    );

    let close = svg
        .rfind("</svg>")
        .ok_or("the renderer produced an svg with no end")?;
    svg.insert_str(close, &mark_plate(side));
    Ok(svg)
}

/// Roughly how many pixels across the finished symbol should be.
///
/// Not exact: the real width is a whole number of modules, and a module is a
/// whole number of pixels so the edges stay on pixel boundaries instead of
/// blurring across them.
const QR_TARGET: u32 = 300;

/// The dark modules, which are not quite black.
///
/// The same value the phone client uses, so a screenshot of one beside the
/// other does not show two different products.
const QR_DARK: &str = "#0B0A0F";

/// How much of the symbol's width the logo plate takes.
const LOGO_SHARE: f64 = 0.24;

/// The mark, on a white plate, centred on a symbol `side` pixels across.
///
/// The white ring around the mark is not decoration. It separates the logo from
/// the modules beside it so a scanner reads a clean boundary rather than a
/// smear, and the rounded clip is what keeps the mark's own corners off the
/// modules diagonally out from it.
fn mark_plate(side: u32) -> String {
    let side = side as f64;
    let plate = side * LOGO_SHARE;
    let left = (side - plate) / 2.0;
    let pad = plate * 0.08;
    let inner = plate - pad * 2.0;

    format!(
        concat!(
            r#"<rect x="{left:.1}" y="{left:.1}" width="{plate:.1}" height="{plate:.1}""#,
            r##" rx="{plate_radius:.1}" fill="#ffffff"/>"##,
            r#"<clipPath id="rotelyx-mark-clip">"#,
            r#"<rect x="{inset:.1}" y="{inset:.1}" width="{inner:.1}" height="{inner:.1}""#,
            r#" rx="{mark_radius:.1}"/>"#,
            r#"</clipPath>"#,
            // Both spellings of the same attribute. `href` is what SVG2 says
            // and `xlink:href` is what WebKit wanted before that, and the
            // window is a WebKit whose version is whatever the machine has.
            // A viewer that understands both takes `href`.
            r#"<image href="rotelyx-mark.png" xlink:href="rotelyx-mark.png""#,
            r#" x="{inset:.1}" y="{inset:.1}""#,
            r#" width="{inner:.1}" height="{inner:.1}""#,
            r#" clip-path="url(#rotelyx-mark-clip)"/>"#,
        ),
        left = left,
        plate = plate,
        plate_radius = plate * 0.24,
        inset = left + pad,
        inner = inner,
        mark_radius = inner * 0.18,
    )
}

#[tauri::command]
fn invitation_qr(code: String) -> Result<String, String> {
    qr_svg(code.trim())
}

#[cfg(test)]
mod qr_tests {
    use super::*;

    /// A real invitation code has to fit, and the picture has to be a picture.
    ///
    /// Eighty-six characters of base64url is the whole point: it is exactly the
    /// length that is miserable to read aloud and easy to mistype, and it is the
    /// reason a camera is worth having. If it ever stops fitting, the code got
    /// longer and somebody needs to know before a phone is pointed at nothing.
    #[test]
    fn an_invitation_code_fits_in_a_qr() {
        let code = "HqKKk-8fPRC7cTEaXLt1cxsKF3vOTkJKC1j6kmrZ3BJXxnFKQmifUbaqDsR3TWfYLKkImwQ2xWpR9sW9mr_UqA";
        assert_eq!(code.len(), 86, "the invitation code is not the length this assumes");

        // The size the specification requires, checked rather than assumed.
        //
        // A decoder is not available here, so the module count stands in for
        // one, and it has now caught a wrong number three times: version 5 at
        // 37 modules, on the arithmetic that version 5 holds 106 bytes, which
        // it holds at level **L** and not at M; version 6 at 41, right for M
        // and wrong once the level went to H to make room for the logo; and
        // version 8 at 49, on the belief that H at version 8 holds 86 bytes. It
        // holds 84. The answer is version 9, at 53.
        let qr = qrcode::QrCode::with_error_correction_level(code, qrcode::EcLevel::H)
            .expect("encode");
        assert_eq!(qr.width(), 53, "not the version this code needs");

        let svg = qr_svg(code).expect("a code this length must encode");
        assert!(svg.starts_with("<svg"), "that is not an svg: {}", &svg[..40.min(svg.len())]);
        assert!(svg.contains("</svg>"));
        assert!(svg.len() > 500, "an svg that small cannot be a QR of 86 characters");
    }

    /// Not a test of behaviour: writes the drawing out so it can be looked at.
    ///
    /// Ignored, because a picture is not an assertion and this needs a person.
    #[test]
    #[ignore]
    fn write_the_drawing_out() {
        // A meeting code, which is what the window actually draws. It used to
        // dump an invitation, so the picture being looked at was not the
        // picture being shipped.
        let code = rotelyx_wasm::new_meeting_code().expect("entropy");
        println!("  {code}");
        let svg = qr_svg(&code).expect("encode");
        let to = std::env::var("ROTELYX_QR_OUT").expect("set ROTELYX_QR_OUT");
        std::fs::write(to, svg).expect("write");
    }

    /// What the window draws is a code the phone accepts.
    ///
    /// This is the assertion that was missing while the desktop drew its
    /// transport invitation and every phone pointed at it answered "that is not
    /// a Rotelyx code". The drawing and the reader are checked against each
    /// other here so that cannot be true again without a test saying so.
    #[test]
    fn the_drawing_carries_a_code_the_phone_accepts() {
        let code = rotelyx_wasm::new_meeting_code().expect("entropy");
        assert!(code.starts_with("RTLX1"), "not a meeting code: {code}");

        // Accepted by the same reader both clients use, and it fits.
        assert_eq!(
            rotelyx_wasm::read_meeting_code(&code).expect("its own code"),
            code
        );
        let svg = qr_svg(&code).expect("a meeting code must fit in a QR");
        assert!(svg.starts_with("<svg"));

        // A meeting code is far shorter than an invitation, so at the same
        // correction level it is a much smaller symbol: easier to read from
        // across a desk, which is where this one is read from.
        let qr = qrcode::QrCode::with_error_correction_level(&code, qrcode::EcLevel::H)
            .expect("encode");
        assert!(
            qr.width() <= 33,
            "a meeting code should be version 4 or smaller, got {} modules",
            qr.width()
        );
    }

    /// The mark is in it, and it is inside the drawing rather than after it.
    ///
    /// An `<image>` written past `</svg>` renders as nothing at all, which is
    /// exactly what the desktop showed before this: a plain code beside the
    /// phone's, with no sign that anything had been attempted.
    #[test]
    fn the_mark_is_set_into_the_code() {
        let svg = qr_svg("HqKKk-8fPRC7cTEaXLt1cxsKF3vOTkJKC1j6kmrZ3BJXxnFKQmifUbaqDsR3TWfYLKkImwQ2xWpR9sW9mr_UqA")
            .expect("encode");

        let image = svg.find("rotelyx-mark.png").expect("the mark is not in the drawing");
        let end = svg.rfind("</svg>").expect("no end tag");
        assert!(image < end, "the mark was written past the end of the svg");
        assert!(svg.contains("clip-path"), "the mark is not clipped to its plate");
        assert!(
            svg.contains("xlink:href"),
            "only the SVG2 spelling is there, and the window may be an older WebKit"
        );

        // And the prefix is bound, or the drawing is not a document any XML
        // parser will open. This is not hypothetical: it was rendered as a file
        // and came back as a parse error with the code below it.
        let declared = svg.find("xmlns:xlink").expect("the xlink prefix is not bound");
        let used = svg.find("xlink:href").expect("checked above");
        assert!(declared < used, "the prefix is used before it is declared");
    }

    /// Centred, and the size the phone client uses.
    ///
    /// Off centre it covers modules the logo was never budgeted for, and the
    /// correction level stops paying for it. The share is asserted here and in
    /// the phone client's `test/meeting_code_test.dart` for the same reason.
    #[test]
    fn the_plate_is_centred_and_the_agreed_share() {
        assert_eq!(LOGO_SHARE, 0.24, "the phone client asserts against this number");

        let side = 400.0_f64;
        let plate = side * LOGO_SHARE;
        let drawn = mark_plate(400);

        let left = (side - plate) / 2.0;
        assert!(
            drawn.contains(&format!(r#"x="{left:.1}" y="{left:.1}""#)),
            "the plate is not centred: {drawn}"
        );
    }

    /// Room to grow, so a longer code does not fail on somebody's screen first.
    #[test]
    fn a_longer_code_still_fits() {
        let long = "A".repeat(160);
        assert!(qr_svg(&long).is_ok(), "no headroom above the current code length");
    }

    /// And something that cannot be drawn is reported, not panicked over.
    #[test]
    fn a_code_too_long_is_refused_rather_than_panicking() {
        let absurd = "A".repeat(8000);
        assert!(qr_svg(&absurd).is_err());
    }
}

/// One live invitation, as the window lists them.
#[derive(serde::Serialize)]
struct InvitationRow {
    code: String,
    expires_in_hours: u64,
}

#[tauri::command]
fn snapshot(app: tauri::State<'_, Arc<App>>) -> Result<Snapshot, String> {
    let epoch = now_epoch().map_err(|e| e.to_string())?;
    let invitations = store::load_invitations(&app.paths.invitations, epoch)
        .map_err(|e| e.to_string())?
        .len();
    Ok(Snapshot {
        id: app.identity.id().to_string(),
        invitations,
        relay: std::env::var("ROTELYX_RELAY").unwrap_or_default(),
        mailbox: std::env::var("ROTELYX_MAILBOX")
            .ok()
            .filter(|url| !url.trim().is_empty())
            .unwrap_or_else(|| MAILBOX.to_string()),
    })
}

#[tauri::command]
fn issue_invitation(app: tauri::State<'_, Arc<App>>, hours: u64) -> Result<String, String> {
    let epoch = now_epoch().map_err(|e| e.to_string())?;
    let expires = epoch + hours.max(1);
    let invitation = Invitation::issue(expires);
    let stored = StoredInvitation {
        secret: *invitation.secret_bytes(),
        // The address this invitation is answered on. See `Invitation`.
        transport: *invitation.transport_bytes(),
        expires_at_epoch: expires,
    };
    let code = stored.code();

    store::add_invitation(&app.paths.invitations, stored, epoch).map_err(|e| e.to_string())?;
    Ok(code)
}

#[tauri::command]
fn invitations(app: tauri::State<'_, Arc<App>>) -> Result<Vec<InvitationRow>, String> {
    let epoch = now_epoch().map_err(|e| e.to_string())?;
    let live = store::load_invitations(&app.paths.invitations, epoch).map_err(|e| e.to_string())?;
    Ok(live
        .iter()
        .map(|inv| InvitationRow {
            code: inv.code(),
            // An epoch is an hour, so this is already hours.
            expires_in_hours: inv.expires_at_epoch.saturating_sub(epoch),
        })
        .collect())
}

/// Withdraw an invitation, which is what blocking means here.
///
/// There is no identity to ban. A caller arrives on a key belonging to one
/// invitation and nothing else, so a list of identities to refuse is a list of
/// values that never arrive. What can be withdrawn is the invitation, and that
/// is checked against a secret this side holds rather than against something
/// the caller chose to say about itself.
#[tauri::command]
fn block(app: tauri::State<'_, Arc<App>>, code: String) -> Result<bool, String> {
    let epoch = now_epoch().map_err(|e| e.to_string())?;
    let code = code.trim();
    let live = store::load_invitations(&app.paths.invitations, epoch).map_err(|e| e.to_string())?;
    let target = live
        .iter()
        .find(|inv| inv.code() == code)
        .ok_or_else(|| "that is not a code this device issued".to_string())?;

    // The conversation that ran on it goes too. An invitation withdrawn while
    // its conversation stays on the disk is a person told they are blocked and a
    // file that still decrypts everything they said.
    let address = target.to_invitation().address();
    let withdrawn = store::revoke_invitation(&app.paths.invitations, &target.secret, epoch)
        .map_err(|e| e.to_string())?;
    if withdrawn {
        crate::resume::forget(&app.paths, &address).map_err(|e| e.to_string())?;
    }
    Ok(withdrawn)
}

#[tauri::command]
fn send_message(app: tauri::State<'_, Arc<App>>, text: String) -> Result<(), String> {
    let guard = app.session.lock().map_err(|_| "state poisoned".to_string())?;
    let tx = guard.as_ref().ok_or("no session is running")?;
    tx.send(Command::Send { text }).map_err(|_| "session ended".to_string())
}

/// Start talking.
///
/// Refused by the engine, with a reason, on a session that may take a direct
/// path: audio over one is this machine's address handed to the other end. The
/// window learns that through an error event rather than here, because by the
/// time this returns the engine has not looked at it yet.
#[tauri::command]
fn start_call(app: tauri::State<'_, Arc<App>>) -> Result<(), String> {
    let guard = app.session.lock().map_err(|_| "state poisoned".to_string())?;
    let tx = guard.as_ref().ok_or("no session is running")?;
    tx.send(Command::StartCall).map_err(|_| "session ended".to_string())
}

/// Stop talking. The session stays up and text keeps working.
#[tauri::command]
fn end_call(app: tauri::State<'_, Arc<App>>) -> Result<(), String> {
    let guard = app.session.lock().map_err(|_| "state poisoned".to_string())?;
    let tx = guard.as_ref().ok_or("no session is running")?;
    tx.send(Command::EndCall).map_err(|_| "session ended".to_string())
}

#[tauri::command]
fn hangup(app: tauri::State<'_, Arc<App>>) -> Result<(), String> {
    let mut guard = app.session.lock().map_err(|_| "state poisoned".to_string())?;
    if let Some(tx) = guard.take() {
        let _ = tx.send(Command::Hangup);
    }
    Ok(())
}

/// The conversations this identity has, newest first.
#[tauri::command]
fn chats(app: tauri::State<'_, Arc<App>>) -> Result<Vec<chats::Row>, String> {
    Ok(chats::list(&identity_path(), &app.chat_key))
}

/// Carry on a conversation that is already on disk.
///
/// The first thing this sends is a commit, because a copy resumed from a file is
/// at generations the other side has already seen. Until they apply it they
/// cannot read anything from here, which is a gap of one round trip and the
/// price of resuming at all.
#[tauri::command]
fn open_chat(
    window: tauri::Window,
    app: tauri::State<'_, Arc<App>>,
    id: String,
) -> Result<(), String> {
    let (tx, mut rx) = mpsc::unbounded_channel::<Command>();
    {
        let mut guard = app.session.lock().map_err(|_| "state poisoned".to_string())?;
        if guard.is_some() {
            return Err("a session is already running".into());
        }
        *guard = Some(tx);
    }

    let emitter = window.clone();
    let emit: Arc<dyn Fn(Event) + Send + Sync> = Arc::new(move |event: Event| {
        let _ = emitter.emit("rotelyx", event);
    });

    let app_handle = app.inner().clone();
    let window_for_reset = window.clone();
    let key = app.chat_key.clone();
    let calls_as = Identity::from_bytes(*app.identity.to_storage_bytes());
    let relay = std::env::var("ROTELYX_RELAY").ok();

    tauri::async_runtime::spawn(async move {
        let outcome = meeting::resume(
            &identity_path(),
            key,
            &id,
            calls_as,
            relay,
            emit.clone(),
            &mut rx,
        )
        .await;

        if let Err(e) = outcome {
            emit(Event::Error { text: format!("{e:#}") });
        }

        if let Ok(mut guard) = app_handle.session.lock() {
            *guard = None;
        }
        let _ = window_for_reset.emit(
            "rotelyx",
            Event::Status {
                text: "Session ended".into(),
            },
        );
    });

    Ok(())
}

/// Forget one./// Forget one.
///
/// The file goes and nothing else does. The group still holds this device as a
/// member, so forgetting is not leaving: the others go on addressing a leaf
/// that no longer answers, and there is no way to tell them from here.
#[tauri::command]
fn forget_chat(app: tauri::State<'_, Arc<App>>, id: String) -> Result<(), String> {
    let _ = &app;
    chats::forget(&identity_path(), &id).map_err(|e| format!("{e:#}"))
}

/// Remove somebody from the conversation./// Remove somebody from the conversation.
///
/// By the key that identifies them, which is what the members list carries. A
/// label would not do: two members can choose the same one, and a position in
/// the tree shifts as people come and go.
#[tauri::command]
fn remove_member(app: tauri::State<'_, Arc<App>>, key: String) -> Result<(), String> {
    let guard = app.session.lock().map_err(|_| "state poisoned".to_string())?;
    let session = guard.as_ref().ok_or("no session is running")?;
    session
        .send(Command::Remove { key })
        .map_err(|_| "the session has ended".to_string())
}

/// Ask who is in the conversation. The answer arrives as an event.
#[tauri::command]
fn who_is_here(app: tauri::State<'_, Arc<App>>) -> Result<(), String> {
    let guard = app.session.lock().map_err(|_| "state poisoned".to_string())?;
    let session = guard.as_ref().ok_or("no session is running")?;
    session
        .send(Command::WhoIsHere)
        .map_err(|_| "the session has ended".to_string())
}

/// Mint a meeting code, which is what the phone's QR carries./// Mint a meeting code, which is what the phone's QR carries.
///
/// Not an invitation: see `meeting.rs` for why an invitation cannot fit in a
/// scannable symbol. This is 120 random bits naming a place at the mailbox.
#[tauri::command]
fn meeting_code() -> Result<String, String> {
    rotelyx_wasm::new_meeting_code().map_err(|e| e.to_string())
}

/// The same code, grouped so a person can read it aloud.
///
/// What is displayed stays something [`meeting`] accepts, so copying what is on
/// screen works. A displayed form the reader refuses is a code that fails for a
/// reason nobody can see.
#[tauri::command]
fn meeting_code_shown(code: String) -> String {
    rotelyx_wasm::pretty_meeting_code(code.trim())
}

/// Meet a phone at the place a code names.
///
/// `role` is `show` for the side that minted the code and `read` for the side
/// that scanned or typed one. The difference is not cosmetic: the reader speaks
/// first, and the shower keeps listening at the meeting place afterwards so
/// somebody else can arrive later.
#[tauri::command]
fn meet(
    window: tauri::Window,
    app: tauri::State<'_, Arc<App>>,
    code: String,
    role: String,
    mailbox: String,
    // Tell the other side when their messages were read. Off unless the window
    // asks for it, which is the same default the phone client keeps: a receipt
    // is one more envelope per read, and envelopes are what the operator of a
    // mailbox can count.
    receipts: Option<bool>,
    // The relay a call routes through. A conversation met through a code carries
    // messages without one; a call needs it, because the only other path is
    // direct and a direct path hands the other party this machine's address.
    relay: Option<String>,
) -> Result<(), String> {
    let role = match role.as_str() {
        "show" => meeting::Role::Host,
        "read" => meeting::Role::Guest,
        other => return Err(format!("unknown role {other}")),
    };

    let mailbox = mailbox.trim().to_string();
    if mailbox.is_empty() {
        return Err("a meeting needs a mailbox: it is the only place a phone can be reached".into());
    }

    let (tx, mut rx) = mpsc::unbounded_channel::<Command>();
    {
        let mut guard = app.session.lock().map_err(|_| "state poisoned".to_string())?;
        if guard.is_some() {
            return Err("a session is already running".into());
        }
        *guard = Some(tx);
    }

    let emitter = window.clone();
    let emit: Arc<dyn Fn(Event) + Send + Sync> = Arc::new(move |event: Event| {
        let _ = emitter.emit("rotelyx", event);
    });

    let app_handle = app.inner().clone();
    let window_for_reset = window.clone();
    let keeping = Some((identity_path(), app.chat_key.clone()));

    let calls_as = Identity::from_bytes(*app.identity.to_storage_bytes());

    // The name the other side sees. It proves nothing on its own, which is what
    // the safety number is for, and it is on screen from the moment there is a
    // conversation.
    let display_name = "desktop".to_string();

    tauri::async_runtime::spawn(async move {
        let outcome = meeting::run(
            &code,
            &display_name,
            &mailbox,
            role,
            receipts.unwrap_or(false),
            calls_as,
            relay,
            keeping,
            emit.clone(),
            &mut rx,
        )
        .await;

        if let Err(e) = outcome {
            emit(Event::Error { text: format!("{e:#}") });
        }

        if let Ok(mut guard) = app_handle.session.lock() {
            *guard = None;
        }
        let _ = window_for_reset.emit(
            "rotelyx",
            Event::Status {
                text: "Session ended".into(),
            },
        );
    });

    Ok(())
}

/// Start a session. `mode` is either `listen` or `connect`.
#[tauri::command]
fn start(
    window: tauri::Window,
    app: tauri::State<'_, Arc<App>>,
    mode: String,
    open: Option<bool>,
    addr: Option<String>,
    invite: Option<String>,
    // A relay to route through, and what a call needs. Left out, the session is
    // direct only: fine for text, and a call is refused because a direct path
    // shows the other end this machine's address. Both sides need the same one.
    relay: Option<String>,
) -> Result<(), String> {
    let epoch = now_epoch().map_err(|e| e.to_string())?;

    let (tx, mut rx) = mpsc::unbounded_channel::<Command>();
    {
        let mut guard = app.session.lock().map_err(|_| "state poisoned".to_string())?;
        if guard.is_some() {
            return Err("a session is already running".into());
        }
        *guard = Some(tx);
    }

    // Events reach the window through Tauri's IPC, which is in process. No
    // socket is involved and no plaintext leaves the address space.
    let emitter = window.clone();
    let emit: Arc<dyn Fn(Event) + Send + Sync> = Arc::new(move |event: Event| {
        let _ = emitter.emit("rotelyx", event);
    });

    // The identity is re-derived rather than shared, so the engine owns its own
    // copy and nothing has to be locked on the hot path.
    let identity = Identity::from_bytes(*app.identity.to_storage_bytes());
    let paths = app.paths.clone();
    let passphrase = app.passphrase.clone();
    let app_handle = app.inner().clone();
    let window_for_reset = window.clone();

    tauri::async_runtime::spawn(async move {
        let engine = match Engine::new(
            identity,
            paths,
            passphrase,
            epoch,
            emit.clone(),
            relay.as_deref(),
        ) {
            Ok(e) => e,
            Err(e) => {
                emit(Event::Error { text: format!("{e:#}") });
                emit(Event::Disconnected { reason: "could not start".into() });
                return;
            }
        };

        let outcome = match mode.as_str() {
            "listen" => engine.listen(open.unwrap_or(false), &mut rx).await,
            "connect" => {
                let addr = addr.unwrap_or_default();
                engine.connect(&addr, invite.as_deref(), &mut rx).await
            }
            other => Err(anyhow::anyhow!("unknown mode {other}")),
        };

        if let Err(e) = outcome {
            // `{:#}` prints the whole context chain, which is what turns
            // "connecting failed" into a legible refusal.
            emit(Event::Error { text: format!("{e:#}") });
        }

        if let Ok(mut guard) = app_handle.session.lock() {
            *guard = None;
        }
        let _ = window_for_reset.emit(
            "rotelyx",
            Event::Status {
                text: "Session ended".into(),
            },
        );
    });

    Ok(())
}

/// The mailbox to meet at when the window was not told one.
///
/// Not empty, which is what it was. A window started straight from the binary
/// rather than through `scripts/rotelyx-desktop` had no mailbox, so asking it
/// for a code refused before drawing anything, and the only thing on screen was
/// the invitation text: a code that looked like the answer and is the one thing
/// a phone cannot use. The relay is deliberately not defaulted the same way,
/// because an empty relay means direct only, which is a choice, and a mailbox
/// nobody named is not.
///
/// The same one the phone client ships with, so the two arrive at the same
/// place without either being configured.
const MAILBOX: &str = "wss://mail-rotelyx.ideoa.co/mailbox";

fn identity_path() -> PathBuf {
    if let Ok(p) = std::env::var("ROTELYX_IDENTITY") {
        return PathBuf::from(p);
    }
    // Beside the executable's working directory keeps the harness predictable.
    // A shipped client would use the platform config directory.
    PathBuf::from("rotelyx-identity.key")
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "rotelyx=info,warn".into()),
        )
        .init();

    let path = identity_path();
    // Said before the prompt, not after the failure.
    //
    // A person handed "Choose a passphrase" with no context has no way to know
    // whether they are unlocking something they already have or creating
    // something new, and the difference matters: there is no recovery for either
    // and only one of them can be got wrong twice.
    let making_one = !path.exists();
    if making_one {
        eprintln!("no identity at {}, so this makes one.", path.display());
        if std::env::var("ROTELYX_PASSPHRASE").is_ok() {
            eprintln!("Sealed with ROTELYX_PASSPHRASE, which is what the environment");
            eprintln!("of this process holds and anything running as this user can read.");
        } else {
            eprintln!("It is sealed with the passphrase you choose now, and there is");
            eprintln!("no way to recover it. An empty one is refused.");
        }
        eprintln!();
    }

    let (identity, passphrase) = match keyfile::load_with_passphrase(&path) {
        Ok(pair) => pair,
        Err(e) => {
            let what = if making_one { "create" } else { "open" };
            eprintln!("could not {what} the identity at {}: {e:#}", path.display());
            std::process::exit(1);
        }
    };

    // Derived here, once, before the window opens. It is the one slow thing in
    // starting up and it is slow on purpose: it is what stands between a copied
    // home directory and every conversation in it.
    let chat_key = match chats::key(&path, &passphrase) {
        Ok(key) => key,
        Err(e) => {
            eprintln!("cannot open the conversations kept here: {e:#}");
            std::process::exit(1);
        }
    };

    let app = Arc::new(App {
        paths: Paths::from_identity(&path),
        identity,
        passphrase,
        session: Mutex::new(None),
        chat_key,
    });

    tauri::Builder::default()
        .manage(app)
        .invoke_handler(tauri::generate_handler![
            snapshot,
            issue_invitation,
            block,
            invitations,
            invitation_qr,
            meeting_code,
            meeting_code_shown,
            remove_member,
            who_is_here,
            chats,
            open_chat,
            forget_chat,
            meet,
            start,
            start_call,
            end_call,
            send_message,
            hangup,
        ])
        .setup(|app| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_title("Rotelyx");
            }
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("running the Rotelyx window");
}
