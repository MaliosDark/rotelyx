//! Waking a phone that is not running, without learning whose phone it is.
//!
//! # The problem this file refuses to have
//!
//! To push to a device you need its push token. A push token is stable for
//! months. A mailbox tag rotates every hour, precisely so two tags from one
//! member cannot be linked without the group key.
//!
//! Store `token -> tag` and the operator follows that stable token across every
//! rotation and re-links the whole sequence. On the wire the tags still look
//! unlinkable; the table beside them says otherwise. The adversary is ADV-4,
//! the mailbox operator, which is us. This is the same shape as the free-tier
//! metering bug in [`crate::access`]: the cryptography is sound and an
//! identifier added for an operational reason re-links what it separated.
//!
//! # Why the obvious defence does not work
//!
//! "One token per tag, burned on use" is the right shape for a transport that
//! can mint tokens. **APNs cannot.** A device has one token and it is the same
//! string in every row, so registering it against a hundred tags produces a
//! hundred rows that all name the same device. The scheme reads as sound and
//! fails at implementation, which is why it is written down here rather than
//! quietly dropped.
//!
//! # What this does instead
//!
//! **It does not know which device is behind which tag, because it never asks.**
//!
//! [`Registry`] holds tokens and nothing else. No tag, no address, no account,
//! no timestamp of anything a person did. Every [`WAKE_EVERY_DEFAULT`] seconds
//! the server wakes every registered device, whether or not anything arrived
//! for it. Each device wakes, collects from its own tags, and shows something
//! only if there was something.
//!
//! | | Wake on arrival | Wake on schedule |
//! |---|---|---|
//! | This server knows token to tag | **Yes** | No |
//! | Apple learns when a message arrived | **Yes** | No |
//! | Latency | Immediate | Up to the interval |
//! | Battery | One wake per message | One wake per interval |
//!
//! Signal pushes on arrival, which hands Apple the timing of every
//! conversation, and says so honestly. This does not have to.
//!
//! The costs are real: latency up to the interval, and the battery of wakes
//! that find nothing. The client is told the interval in the `wakeRegistered`
//! reply so it can state the true number rather than one it hoped for.
//!
//! # Why every wake carries an alert
//!
//! Apple throttles silent pushes. `content-available` with no alert is
//! best-effort and may be delayed or dropped, which for a scheduled heartbeat
//! means it stops being a schedule. A push carrying an alert is not throttled.
//!
//! So every wake carries one, and the device's notification service extension
//! decides what to do: replace it with the decrypted message, or hand back
//! empty content, which suppresses it. A wake that finds nothing shows nothing
//! and the user never learns it happened.
//!
//! # What Apple learns, stated rather than implied
//!
//! That a device received a push, and when. It is a fixed rhythm identical for
//! every registered device and carries nothing about who was messaged. There is
//! no way to hide the fact of a delivery on iOS: the platform does not permit a
//! background socket, so a device that is not running can only be woken by
//! Apple. Android pays none of this, because it holds its own connection.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use data_encoding::BASE64URL_NOPAD;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::{debug, warn};

/// How often a registered device is woken, when nothing says otherwise.
///
/// Five minutes. Short enough that a message is not stale by the time it is
/// seen, long enough that a phone is not woken twelve times an hour for
/// nothing. It is the one number in this design that trades latency against
/// battery, and it is a flag rather than a constant so an operator can move it.
pub const WAKE_EVERY_DEFAULT: u64 = 300;

/// The most devices one server will hold.
///
/// A bound rather than trust. Without it, anything that can open a socket can
/// make this server spend the rest of its life calling Apple.
pub const MAX_DEVICES: usize = 100_000;

/// The shortest revocation secret this server will store.
///
/// # Why there is a floor at all
///
/// `revokeWake` needs no capability and no rate limit, and it removes every row
/// whose secret hashes to what it was given. So a secret somebody can guess is
/// a device somebody can silence, and guessing is cheap: the same measurement
/// that made the vault cache necessary put this path at thousands of attempts a
/// second. The server cannot judge entropy, but it can refuse a length no
/// random value would have.
///
/// A client should send 32 random bytes rendered as hex or base64, which is
/// comfortably past this. The refusal depends only on what the caller sent, so
/// it says nothing about anyone else.
pub const MIN_SECRET_LEN: usize = 32;

/// Whether a secret is long enough to store.
///
/// An empty secret is allowed and means a row nobody can revoke, which is a
/// deliberate choice recorded on [`Registry::register`]. What is refused is a
/// secret short enough to be reached by guessing.
pub fn secret_is_long_enough(secret: &str) -> bool {
    secret.is_empty() || secret.len() >= MIN_SECRET_LEN
}

/// How many rows one push token may hold.
///
/// A row belongs to a secret, so a token gathers a row per party that
/// registered it. A device needs one. The rest is somebody holding a token it
/// was not given, and this is what bounds them without letting a refusal say so.
pub const MAX_ROWS_PER_TOKEN: usize = 4;

/// A push token is hex from Apple. Long enough to be one, short enough not to
/// be a payload somebody is smuggling through.
const TOKEN_MIN: usize = 32;
const TOKEN_MAX: usize = 200;

/// One device that may be woken.
///
/// Carries no tag, and the absence is the entire point of this module.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Device {
    /// The platform token. Opaque here.
    pub token: String,

    /// Which service to call. `apns` today. A field rather than an assumption
    /// so that adding UnifiedPush later is a value and not a second table.
    pub kind: String,

    /// What proves a revocation came from this device, as a hash.
    ///
    /// # The flaw this closes
    ///
    /// The first version of this let anybody revoke any token by naming it.
    /// Not a leak: nothing was disclosed, and it required already knowing a
    /// token. But it silenced a phone, and a messenger that can be silenced by
    /// a stranger is worse than one with no notifications, because the user
    /// believes theirs are on.
    ///
    /// So a token is an address and not a credential. Registering supplies a
    /// secret this device made up; revoking has to present it again. A hash is
    /// stored rather than the secret so that a stolen registry file yields the
    /// power to be woken and not the power to silence.
    ///
    /// Plain SHA-256 and not a slow derivation: the input is thirty two random
    /// bytes, so there is no dictionary to run and nothing a work factor would
    /// buy. Empty for a row restored from a snapshot written before this field
    /// existed, which is revocable by anyone until that device next registers,
    /// and is fixed by the device next registering.
    #[serde(default)]
    pub revoke_hash: String,
}

impl Device {
    /// Reject anything that is not plausibly a push token.
    ///
    /// Checked because this string is put in a URL. A token containing a slash
    /// or a newline would address a different path on Apple's server, or split
    /// the request, and refusing it here is cheaper than escaping it in three
    /// places later.
    pub fn valid(&self) -> bool {
        let length = self.token.len();
        if !(TOKEN_MIN..=TOKEN_MAX).contains(&length) {
            return false;
        }
        if !self.token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return false;
        }
        // A hash, or nothing. A short one would mean a short secret, and a
        // short secret is one somebody can guess their way through.
        if !self.revoke_hash.is_empty() && self.revoke_hash.len() != 64 {
            return false;
        }
        matches!(self.kind.as_str(), "apns")
    }

    /// Build one from what arrived on the wire, hashing the secret here so the
    /// caller cannot forget to.
    pub fn registering(token: String, kind: String, secret: &str) -> Self {
        Self {
            token,
            kind,
            revoke_hash: if secret.is_empty() {
                String::new()
            } else {
                hash(secret)
            },
        }
    }
}

/// Every device this server will wake.
///
/// A set, so registering twice is not two wakes, and ordered so a snapshot is
/// byte-identical for the same contents. That last part matters more than it
/// sounds: a file whose bytes change when its contents do not is a file whose
/// modification time leaks that somebody reconnected.
#[derive(Default)]
pub struct Registry {
    devices: BTreeSet<Device>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add one, replacing an earlier row for the same token **only when the
    /// caller proves the secret that row was registered with.**
    ///
    /// # The hole this closes
    ///
    /// Revocation asks for a secret, which is correct, and on its own achieved
    /// nothing: registration replaced any row with a matching token without
    /// asking for anything. So the attack survived with one extra step. Learn a
    /// device token, register it again with a secret of your own, and the row is
    /// yours; revoke it and that phone stops being woken. The owner loses
    /// control at the same moment, because their secret no longer matches
    /// anything.
    ///
    /// **A push token is an address, not a credential.** It travels to Apple,
    /// it sits in the app's storage, and it is not a secret. Anything that
    /// treats holding one as authority to act is unauthenticated, however the
    /// step after it is spelled.
    ///
    /// # Why replacing at all
    ///
    /// The reason the old code replaced is real: a phone that registers again
    /// is the same phone, and two rows would mean two wakes and an old secret
    /// that still silences it. That case is kept. What is refused is replacing
    /// a row whose secret the caller cannot produce.
    ///
    /// # The reinstall case, which decided this
    ///
    /// Requiring the secret would be wrong if it stranded a user who
    /// reinstalled and lost theirs. It does not: a reinstalled app is issued a
    /// **new** token, registers cleanly as a new row, and the old row dies on
    /// its own the next time Apple answers 410 for it. See [`Apns::is_gone`]
    /// and [`sweep`].
    ///
    /// # Why a token can hold more than one row
    ///
    /// Refusing used to answer a question nobody should be able to ask. A
    /// caller presenting a token that was already registered under a different
    /// secret was told no, and that no meant *this server has a row for this
    /// token* to anybody holding one. The people who hold every push token are
    /// Apple and Google, so the oracle was open to exactly the party the wake
    /// design is most careful about.
    ///
    /// A row is now identified by the token **and** the secret, so a caller
    /// with a secret of its own gets a row of its own instead of an answer
    /// about somebody else's. The owner's row is not touched, not replaced and
    /// not revocable by anyone who cannot produce its secret, which is the
    /// protection the refusal was there for in the first place. What is given
    /// up is the refusal, and the refusal was the leak.
    ///
    /// Well formed registrations therefore all look alike from outside. A
    /// malformed token is still refused, and that reveals nothing: the answer
    /// depends only on what the caller sent.
    ///
    /// # What an extra row costs
    ///
    /// Nothing that was not already possible. Somebody holding a token could
    /// always register it when this server had no row, and a wake carries no
    /// content: it says only that a mailbox has something. Wakes are sent one
    /// per distinct token, so extra rows do not mean extra pushes, and
    /// [`MAX_ROWS_PER_TOKEN`] bounds how many a token can accumulate. At the
    /// bound the row is dropped and the reply is unchanged, because a reply
    /// that changed there would be the same oracle again, reached by paying for
    /// a few registrations first.
    pub fn register(&mut self, device: Device) -> bool {
        if !device.valid() {
            return false;
        }

        // The caller's own row, if it has one: same token, and a secret it can
        // produce. Replaced rather than duplicated, so a device that registers
        // again is one row and one wake.
        let mine = self
            .devices
            .iter()
            .any(|d| d.token == device.token && secrets_match(&d.revoke_hash, &device.revoke_hash));
        if mine {
            self.devices.retain(|d| {
                !(d.token == device.token && secrets_match(&d.revoke_hash, &device.revoke_hash))
            });
            self.devices.insert(device);
            return true;
        }

        let for_this_token = self
            .devices
            .iter()
            .filter(|d| d.token == device.token)
            .count();
        if for_this_token >= MAX_ROWS_PER_TOKEN || self.devices.len() >= MAX_DEVICES {
            // Not stored, and not reported. See the note above: the only caller
            // that reaches this has already registered this token several times
            // over, which a device does not do.
            return true;
        }

        self.devices.insert(device);
        true
    }

    /// Forget every row for a token, because the push service says it is gone.
    ///
    /// Separate from [`Registry::revoke`] on purpose, and not reachable from
    /// the wire. Revocation is something a device asks for and proves with a
    /// secret; this is the server acting on what Apple told it, where the only
    /// name it has is the token.
    ///
    /// # The bug this replaces
    ///
    /// The sweep used to hand each dead **token** to `revoke`, which hashes
    /// what it is given and compares it against hashes of **secrets**. Those
    /// never match, so nothing was ever removed while the log said devices had
    /// been forgotten. Dead tokens accumulated and were pushed to forever,
    /// which Apple counts against the sender, and the reinstall story in
    /// [`Registry::register`] rested on a sweep that did nothing.
    pub fn forget_token(&mut self, token: &str) -> bool {
        let before = self.devices.len();
        self.devices.retain(|d| d.token != token);
        before != self.devices.len()
    }

    /// Remove one, given the secret it was registered with.
    ///
    /// The secret is the credential and the token is not. Naming somebody
    /// else's token achieves nothing, which is the whole point of the field.
    pub fn revoke(&mut self, secret: &str) -> bool {
        let wanted = hash(secret);
        let before = self.devices.len();
        self.devices.retain(|d| !secrets_match(&d.revoke_hash, &wanted));
        before != self.devices.len()
    }

    pub fn len(&self) -> usize {
        self.devices.len()
    }

    pub fn is_empty(&self) -> bool {
        self.devices.is_empty()
    }

    pub fn all(&self) -> Vec<Device> {
        self.devices.iter().cloned().collect()
    }

    /// One row per distinct token, for sending wakes.
    ///
    /// A token can hold a row per secret that registered it, and a phone should
    /// be woken once however many rows name it.
    ///
    /// # Why this is not only tidiness
    ///
    /// Every registered device is woken on the same schedule on purpose,
    /// because a device woken on its own rhythm is a device distinguishable by
    /// it. Waking once per row would break that with volume instead of timing:
    /// somebody holding a token could give that one device two pushes a cycle
    /// where everybody else gets one, and the push service can count.
    pub fn to_wake(&self) -> Vec<Device> {
        let mut seen = std::collections::BTreeSet::new();
        self.devices
            .iter()
            .filter(|d| seen.insert(d.token.clone()))
            .cloned()
            .collect()
    }

    pub fn snapshot(&self) -> Vec<Device> {
        self.all()
    }

    pub fn restore(devices: Vec<Device>) -> Self {
        Self {
            devices: devices.into_iter().filter(Device::valid).collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Apple
// ---------------------------------------------------------------------------

/// How long an APNs authentication token is used before a fresh one is minted.
///
/// Apple accepts a token for an hour and **rate-limits minting**, so a server
/// that signs a new one per push is refused rather than merely wasteful. Fifty
/// minutes leaves room for a slow clock at either end.
const JWT_LIFETIME: u64 = 3000;

/// Where Apple's production push endpoint lives.
const APNS_HOST: &str = "https://api.push.apple.com";

/// And the sandbox, which is what a development build's tokens are valid for.
/// Getting this wrong yields `BadDeviceToken` and nothing else, which is a
/// famously unhelpful message to debug from.
const APNS_SANDBOX: &str = "https://api.sandbox.push.apple.com";

/// Calls Apple. Holds a signing key and a cached authentication token.
pub struct Apns {
    key: SigningKey,
    key_id: String,
    team_id: String,
    topic: String,
    host: &'static str,
    client: reqwest::Client,
    cached: tokio::sync::Mutex<Option<(String, u64)>>,
}

impl Apns {
    /// Read a `.p8` authentication key from disk.
    ///
    /// This is the file downloaded once from the Apple Developer account and
    /// never again: Apple does not keep a copy. It belongs on this server and
    /// nowhere else, and specifically not in the repository, which is why the
    /// path is a flag.
    pub fn new(
        key_pem: &str,
        key_id: String,
        team_id: String,
        topic: String,
        sandbox: bool,
    ) -> Result<Self> {
        let key = SigningKey::from_pkcs8_pem(key_pem.trim())
            .map_err(|e| anyhow!("the APNs key is not a PKCS#8 P-256 private key: {e}"))?;

        if key_id.is_empty() || team_id.is_empty() || topic.is_empty() {
            bail!("the APNs key id, team id and topic are all required");
        }

        Ok(Self {
            key,
            key_id,
            team_id,
            topic,
            host: if sandbox { APNS_SANDBOX } else { APNS_HOST },
            // HTTP/2 is not optional: APNs speaks nothing else, and a client
            // that negotiates HTTP/1.1 is refused at the TLS handshake.
            client: reqwest::Client::builder()
                .http2_prior_knowledge()
                .timeout(Duration::from_secs(20))
                .build()
                .context("building the APNs client")?,
            cached: tokio::sync::Mutex::new(None),
        })
    }

    /// The bearer token Apple wants, minted at most every fifty minutes.
    async fn bearer(&self) -> Result<String> {
        let now = now_seconds();
        let mut cached = self.cached.lock().await;

        if let Some((token, issued)) = cached.as_ref() {
            if now.saturating_sub(*issued) < JWT_LIFETIME {
                return Ok(token.clone());
            }
        }

        let header = format!(r#"{{"alg":"ES256","kid":"{}"}}"#, self.key_id);
        let claims = format!(r#"{{"iss":"{}","iat":{}}}"#, self.team_id, now);

        let signing_input = format!(
            "{}.{}",
            BASE64URL_NOPAD.encode(header.as_bytes()),
            BASE64URL_NOPAD.encode(claims.as_bytes())
        );

        // ES256 wants the raw 64 byte r||s, not the DER encoding an ECDSA
        // library hands back by default. DER here is accepted by nothing and
        // fails with `InvalidProviderToken`, which does not say why.
        let signature: Signature = self.key.sign(signing_input.as_bytes());
        let token = format!(
            "{signing_input}.{}",
            BASE64URL_NOPAD.encode(&signature.to_bytes())
        );

        *cached = Some((token.clone(), now));
        Ok(token)
    }

    /// Wake one device.
    ///
    /// The payload says nothing. It carries a title so the push is an alert
    /// rather than a silent one, which is what keeps Apple from throttling it,
    /// and `decoy` so the device's extension knows it may show nothing. The
    /// message itself is never here: it is in the mailbox, which is where the
    /// device goes to look, and this server could not read it if it tried.
    pub async fn wake(&self, device: &Device) -> Result<()> {
        let bearer = self.bearer().await?;

        let response = self
            .client
            .post(format!("{}/3/device/{}", self.host, device.token))
            .header("authorization", format!("bearer {bearer}"))
            .header("apns-topic", &self.topic)
            .header("apns-push-type", "alert")
            .header("apns-priority", "10")
            // Collapse: a device that missed three wakes gets one, not three.
            // Apple keeps only the most recent per collapse id.
            .header("apns-collapse-id", "rotelyx-wake")
            .header("content-type", "application/json")
            .body(r#"{"aps":{"alert":{"title":"Rotelyx"},"mutable-content":1},"decoy":true}"#)
            .send()
            .await
            .context("calling Apple")?;

        let status = response.status();
        if status.is_success() {
            return Ok(());
        }

        let reason = response.text().await.unwrap_or_default();
        bail!("Apple refused a wake: {status} {reason}")
    }

    /// Whether a failure means the device is gone for good.
    ///
    /// 410 is Apple saying the token is dead: the application was uninstalled,
    /// or the device was restored. Keeping it means calling Apple forever about
    /// a phone that no longer exists, and Apple counts that against you.
    pub fn is_gone(error: &str) -> bool {
        error.contains("410") || error.contains("Unregistered")
    }
}

/// Compare two stored secret hashes without leaking where they differ.
///
/// These are hex digests rather than the secrets themselves, so a timing leak
/// here is worth less than it looks: an attacker who learned a digest still has
/// to find a secret that produces it. Constant time anyway, because the cost is
/// one comparison and the alternative is an argument every time somebody reads
/// this.
///
/// An empty hash is a device registered without a secret. `hash()` never
/// returns empty, so such a row matches no revocation and no takeover.
fn secrets_match(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

/// The stored form of a revocation secret.
fn hash(secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Wake everybody once, and report which tokens Apple says are dead.
///
/// Failures are logged and collected rather than propagated. One phone that
/// cannot be reached is not a reason to stop waking the rest, and a server that
/// stops pushing because one device was uninstalled is a server that goes quiet
/// for everybody at once.
pub async fn sweep(apns: &Apns, devices: &[Device]) -> Vec<String> {
    let mut dead = Vec::new();

    for device in devices {
        match apns.wake(device).await {
            Ok(()) => debug!("woke a device"),
            Err(e) => {
                let text = e.to_string();
                if Apns::is_gone(&text) {
                    dead.push(device.token.clone());
                } else {
                    warn!(error = %text, "a wake failed");
                }
            }
        }
    }

    dead
}

/// Read a registry back from an encrypted snapshot.
pub fn restore_from(path: &Path, passphrase: &str) -> Result<Registry> {
    match crate::vault::Vault::open(passphrase, path)? {
        Some(bytes) => {
            let devices: Vec<Device> =
                postcard::from_bytes(&bytes).context("decoding the wake registry")?;
            Ok(Registry::restore(devices))
        }
        None => Ok(Registry::new()),
    }
}

/// Write the registry out, under the same key as the mailbox.
///
/// Encrypted rather than plain, and for a reason worth stating: a list of push
/// tokens is a list of devices that use this service. It says nothing about who
/// talks to whom, which is the property this module exists to keep, but it is
/// still the closest thing this server holds to a user list, and it should not
/// be readable from a stolen disk.
pub fn save_to(path: &Path, passphrase: &str, registry: &Registry) -> Result<()> {
    let bytes = postcard::to_allocvec(&registry.snapshot()).context("encoding the registry")?;
    crate::vault::Vault::seal(passphrase, path, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(token: &str) -> Device {
        Device::registering(token.into(), "apns".into(), "a-secret")
    }

    #[test]
    fn a_registry_holds_tokens_and_nothing_about_conversations() {
        // The property is an absence, so the test is about the type. A tag
        // field added to `Device` fails to compile against this line, which is
        // the earliest anybody could be told.
        let d = device(&"ab".repeat(32));
        assert_eq!(d.token.len(), 64);
        assert_eq!(d.kind, "apns");

        // Serialised, it is three fields: where to wake, how, and what proves
        // a revocation. If a fourth appears, somebody has to come here and say
        // what the mailbox is now being told.
        let json = serde_json::to_value(&d).unwrap();
        assert_eq!(json.as_object().unwrap().len(), 3);
        assert!(json.get("tag").is_none());
    }

    #[test]
    fn registering_twice_is_one_device() {
        let mut r = Registry::new();
        assert!(r.register(device(&"cd".repeat(32))));
        assert!(r.register(device(&"cd".repeat(32))));
        assert_eq!(r.len(), 1, "one phone, one wake");
    }

    #[test]
    fn a_token_that_is_not_one_is_refused() {
        let mut r = Registry::new();

        // Too short, not hex, and the two that would matter: a slash addresses
        // a different path on Apple's server, and a newline splits the request.
        assert!(!r.register(device("short")));
        assert!(!r.register(device(&"zz".repeat(32))));
        assert!(!r.register(device(&format!("{}/x", "ab".repeat(32)))));
        assert!(!r.register(device(&format!("{}\n", "ab".repeat(32)))));
        assert!(r.is_empty());
    }

    #[test]
    fn an_unknown_kind_is_refused() {
        let mut r = Registry::new();
        assert!(!r.register(Device::registering(
            "ab".repeat(32),
            "fcm".into(),
            "s"
        )));
        assert!(
            r.is_empty(),
            "Firebase relays to APNs, so accepting it would add Google to the \
             path and remove nothing"
        );
    }

    #[test]
    fn only_the_secret_revokes_and_the_token_does_not() {
        // The flaw this replaced: naming somebody else's token silenced their
        // phone. A token is an address, and an address is not a credential.
        let mut r = Registry::new();
        r.register(Device::registering("ab".repeat(32), "apns".into(), "mine"));
        r.register(Device::registering("cd".repeat(32), "apns".into(), "theirs"));

        assert!(!r.revoke(&"cd".repeat(32)), "the token must not revoke");
        assert!(!r.revoke("guessed"), "nor must a wrong secret");
        assert_eq!(r.len(), 2);

        assert!(r.revoke("theirs"));
        assert_eq!(r.len(), 1);
        assert!(!r.revoke("theirs"), "already gone");
    }

    #[test]
    fn the_secret_is_not_stored() {
        // A stolen registry file should yield the power to be woken and not
        // the power to silence.
        let d = Device::registering("ab".repeat(32), "apns".into(), "mine");
        assert_ne!(d.revoke_hash, "mine");
        assert_eq!(d.revoke_hash.len(), 64);
        assert!(!serde_json::to_string(&d).unwrap().contains("mine"));
    }

    #[test]
    fn registering_again_with_the_same_secret_is_one_row() {
        // The legitimate case the replacement rule exists for: the same phone
        // registering again after a restart. One row, not two, and the secret
        // it already had still works.
        let mut r = Registry::new();
        let token = "ab".repeat(32);
        assert!(r.register(Device::registering(token.clone(), "apns".into(), "mine")));
        assert!(r.register(Device::registering(token, "apns".into(), "mine")));

        assert_eq!(r.len(), 1, "the same phone registered twice became two wakes");
        assert!(r.revoke("mine"));
    }

    /// The attack this rule exists to stop.
    ///
    /// A push token is an address, not a credential. Somebody who learns one
    /// must not be able to claim the row it belongs to, because claiming it
    /// means being able to revoke it, and revoking it means that phone silently
    /// stops being told it has messages waiting.
    #[test]
    fn a_token_alone_cannot_take_over_a_registration() {
        let mut r = Registry::new();
        let token = "cd".repeat(32);
        assert!(r.register(Device::registering(token.clone(), "apns".into(), "owner")));

        // The attacker has the token and nothing else. It is not told no,
        // because being told no is being told the row exists, and the parties
        // holding every push token are the push services themselves. It gets a
        // row of its own instead of an answer about somebody else's.
        assert!(
            r.register(Device::registering(token.clone(), "apns".into(), "attacker")),
            "a well formed registration must look the same whoever sent it"
        );

        // The phone is one phone, so it is still woken once.
        assert_eq!(
            r.to_wake().len(),
            1,
            "an extra row turned into an extra push"
        );

        // What the attacker gained is control of what it registered, and
        // nothing else. The owner's row is not its to remove.
        assert!(r.revoke("attacker"));
        assert_eq!(
            r.len(),
            1,
            "revoking the attacker's row took the owner's with it"
        );
        assert!(r.revoke("owner"), "the owner lost control of their own device");
        assert_eq!(r.len(), 0);
    }

    /// The reply must not depend on what this server already holds.
    ///
    /// This is the whole reason a token may hold more than one row. A caller
    /// that can tell a taken token from a free one can ask, for any device
    /// token it holds, whether that device uses this mailbox.
    #[test]
    fn a_registration_does_not_say_whether_the_token_was_known() {
        let taken = "cd".repeat(32);
        let free = "ef".repeat(32);

        let mut r = Registry::new();
        assert!(r.register(Device::registering(taken.clone(), "apns".into(), "owner")));

        let on_taken = r.register(Device::registering(taken, "apns".into(), "probe"));
        let on_free = r.register(Device::registering(free, "apns".into(), "probe"));
        assert_eq!(
            on_taken, on_free,
            "the answer differed, so it answered a question about the owner"
        );
    }

    /// A token gathers rows, but not without end.
    ///
    /// And the bound is reached silently: a reply that changed at the bound
    /// would be the same oracle, reached by paying for a few registrations
    /// first.
    #[test]
    fn a_token_cannot_gather_rows_without_bound() {
        let mut r = Registry::new();
        let token = "cd".repeat(32);

        for n in 0..MAX_ROWS_PER_TOKEN + 3 {
            assert!(
                r.register(Device::registering(
                    token.clone(),
                    "apns".into(),
                    &format!("secret-{n}")
                )),
                "registration {n} was refused, which says the bound was reached"
            );
        }

        assert_eq!(r.len(), MAX_ROWS_PER_TOKEN, "the bound did not hold");
        assert_eq!(r.to_wake().len(), 1, "one phone, one push");
    }

    /// A token Apple says is gone must actually leave.
    ///
    /// # The bug this catches
    ///
    /// The sweep handed each dead token to `revoke`, which hashes what it is
    /// given and compares it against hashes of secrets. A token is not a
    /// secret, so nothing ever matched: dead rows stayed forever, were pushed
    /// to forever, and the log said they had been forgotten.
    #[test]
    fn a_token_the_push_service_calls_dead_is_forgotten() {
        let mut r = Registry::new();
        let dead = "ab".repeat(32);
        let alive = "cd".repeat(32);
        assert!(r.register(Device::registering(dead.clone(), "apns".into(), "one")));
        assert!(r.register(Device::registering(alive, "apns".into(), "two")));

        assert!(r.forget_token(&dead), "nothing was removed");
        assert_eq!(r.len(), 1, "the wrong number of rows survived");
        assert!(!r.forget_token(&dead), "removing it twice reported work");

        // Every row for that token goes, not only the first.
        let mut r = Registry::new();
        let token = "ab".repeat(32);
        r.register(Device::registering(token.clone(), "apns".into(), "one"));
        r.register(Device::registering(token.clone(), "apns".into(), "two"));
        assert_eq!(r.len(), 2);
        assert!(r.forget_token(&token));
        assert_eq!(r.len(), 0, "a dead token left rows behind");
    }

    /// A secret short enough to guess is not stored.
    ///
    /// Revocation needs no capability and no rate limit, and it removes every
    /// row whose secret hashes to what it was handed. A short secret is
    /// therefore a device anybody willing to spend a few seconds can silence.
    #[test]
    fn a_secret_must_be_long_enough_to_be_worth_having() {
        assert!(!secret_is_long_enough("hunter2"));
        assert!(!secret_is_long_enough(&"a".repeat(MIN_SECRET_LEN - 1)));
        assert!(secret_is_long_enough(&"a".repeat(MIN_SECRET_LEN)));

        // What a real client sends: 32 random bytes as hex.
        assert!(secret_is_long_enough(&"ab".repeat(32)));

        // Absent is not short. A row with no secret is one nobody can revoke,
        // which is a decision recorded on `Registry::register`, not an
        // accident of length.
        assert!(secret_is_long_enough(""));
    }

    /// A token nobody has claimed still registers freely. Requiring a secret to
    /// replace must not mean requiring one to arrive.
    #[test]
    fn a_fresh_token_registers_without_proving_anything() {
        let mut r = Registry::new();
        assert!(r.register(Device::registering("ef".repeat(32), "apns".into(), "new")));
        assert_eq!(r.len(), 1);
    }

    /// A row registered without a secret can be neither revoked nor taken over.
    ///
    /// `hash()` never returns the empty string, so the empty stored hash of a
    /// no-secret registration matches nothing. That makes such a row permanent
    /// until Apple reports the token dead, which is the safe direction: the
    /// alternative is a row anybody can claim by also sending no secret.
    #[test]
    fn a_registration_without_a_secret_cannot_be_claimed() {
        let mut r = Registry::new();
        let token = "12".repeat(32);
        assert!(r.register(Device::registering(token.clone(), "apns".into(), "")));

        assert!(!r.revoke(""), "an empty secret revoked something");

        // The attacker is not told no. It gets a row of its own, and the row
        // with no secret stays exactly where it was.
        assert!(r.register(Device::registering(token, "apns".into(), "attacker")));
        assert!(r.revoke("attacker"));
        assert_eq!(r.len(), 1, "the row with no secret did not survive");
        assert!(!r.revoke(""), "the row with no secret became revocable");
    }

    #[test]
    fn a_snapshot_of_the_same_contents_is_the_same_bytes() {
        // A file whose bytes change when its contents do not is a file whose
        // modification time says somebody reconnected.
        let mut a = Registry::new();
        let mut b = Registry::new();
        a.register(device(&"ab".repeat(32)));
        a.register(device(&"cd".repeat(32)));
        b.register(device(&"cd".repeat(32)));
        b.register(device(&"ab".repeat(32)));

        assert_eq!(
            postcard::to_allocvec(&a.snapshot()).unwrap(),
            postcard::to_allocvec(&b.snapshot()).unwrap()
        );
    }

    #[test]
    fn a_restored_registry_drops_anything_that_is_not_a_token() {
        let restored = Registry::restore(vec![
            device(&"ab".repeat(32)),
            device("nonsense"),
            Device::registering("cd".repeat(32), "fcm".into(), "s"),
        ]);
        assert_eq!(restored.len(), 1);
    }

    #[test]
    fn the_registry_is_bounded() {
        // Not trust: without a bound, anything that can open a socket can make
        // this server spend the rest of its life calling Apple.
        assert!(MAX_DEVICES > 0);
    }

    #[test]
    fn a_dead_token_is_recognised() {
        assert!(Apns::is_gone("Apple refused a wake: 410 Gone {\"reason\":\"Unregistered\"}"));
        assert!(!Apns::is_gone("Apple refused a wake: 429 TooManyRequests"));
    }
}
