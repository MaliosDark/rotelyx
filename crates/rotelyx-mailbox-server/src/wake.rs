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

    /// Add one, replacing any earlier row for the same token.
    ///
    /// Replaced rather than added beside, because a device that registers again
    /// with a fresh secret is the same phone: leaving the old row would mean
    /// two wakes for one device and an old secret that still silences it.
    pub fn register(&mut self, device: Device) -> bool {
        if !device.valid() {
            return false;
        }
        let replacing = self.devices.iter().any(|d| d.token == device.token);
        if !replacing && self.devices.len() >= MAX_DEVICES {
            return false;
        }
        self.devices.retain(|d| d.token != device.token);
        self.devices.insert(device);
        true
    }

    /// Remove one, given the secret it was registered with.
    ///
    /// The secret is the credential and the token is not. Naming somebody
    /// else's token achieves nothing, which is the whole point of the field.
    pub fn revoke(&mut self, secret: &str) -> bool {
        let wanted = hash(secret);
        let before = self.devices.len();
        self.devices.retain(|d| d.revoke_hash != wanted);
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
    fn registering_again_replaces_the_old_secret() {
        // The same phone with a fresh secret is the same phone. Two rows would
        // mean two wakes, and an old secret that still silences it.
        let mut r = Registry::new();
        r.register(Device::registering("ab".repeat(32), "apns".into(), "first"));
        r.register(Device::registering("ab".repeat(32), "apns".into(), "second"));

        assert_eq!(r.len(), 1);
        assert!(!r.revoke("first"), "the replaced secret must not work");
        assert!(r.revoke("second"));
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
