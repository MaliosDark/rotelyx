//! Calling Apple and Google, and nothing else.
//!
//! # Why this is its own crate
//!
//! Two servers push. The mailbox wakes every registered device on a schedule,
//! which is what it does when nobody has left it a ticket, and the notifier
//! wakes one device because a ticket said to, which is what makes a wake
//! immediate. They are different services with deliberately different
//! knowledge, and the only thing they share is how to talk to a push provider.
//!
//! Sharing it as a crate rather than copying it keeps the JWT handling, the
//! token caching and the "this device is gone" detection in one place. Two
//! copies of that would drift, and the copy that drifted would be the one
//! nobody noticed had stopped delivering.
//!
//! # What is deliberately not here
//!
//! The registry. Which devices exist, and any means of listing them, belongs
//! to whoever holds it, and the notifier holds nothing: it is handed a token,
//! it pushes, it forgets. A crate that both use must not offer it a place to
//! keep one.

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use data_encoding::BASE64URL_NOPAD;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::DecodePrivateKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

/// The shortest token either provider issues, and the longest.
///
/// A bound rather than an exact length: APNs issues 64 hex characters today
/// and Firebase's are longer, and neither has promised to keep the length it
/// has.
const TOKEN_MIN: usize = 32;
const TOKEN_MAX: usize = 200;

/// One device that may be woken.
///
/// Carries no tag, and the absence is the entire point of this module.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Device {
    /// The platform token. Opaque here.
    pub token: String,

    /// Which service to call, `apns` or `fcm`. A field rather than an
    /// assumption so that adding UnifiedPush later is a value and not a second
    /// table.
    ///
    /// # `fcm` is for Android and nothing else
    ///
    /// Firebase on iOS **relays to APNs**, so an iPhone registering `fcm` would
    /// put Google on a path Apple already serves and would remove nothing. On
    /// Android there is no APNs and Firebase is the only path, which is why it
    /// is accepted at all.
    ///
    /// This server cannot tell the two apart: a Firebase token does not say
    /// which platform it came from. So it is the application that has to
    /// register `apns` on iOS and `fcm` on Android, and this note is here
    /// because the reason is not visible from the code.
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
        matches!(self.kind.as_str(), "apns" | "fcm")
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

// ---------------------------------------------------------------------------

/// Where Google's push endpoint lives, per project.
const FCM_HOST: &str = "https://fcm.googleapis.com";

/// Where a service account exchanges a signed assertion for an access token.
const GOOGLE_TOKEN_HOST: &str = "https://oauth2.googleapis.com";

/// The one scope this needs. Not `cloud-platform`, which would be every Google
/// API this project has.
const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";

/// Calls Google. Holds a service account key and a cached access token.
///
/// # Why this is a second thing and not a flag on the first
///
/// Apple takes a signed token directly. Google takes a signed assertion,
/// exchanges it for an access token at a different host, and pushes to a third
/// URL shaped around a project id. The two share the idea of a cached bearer
/// and nothing else, and folding them together would be a struct with two of
/// every field where half are always unset.
pub struct Fcm {
    /// The service account's RSA key, PKCS#8 DER.
    key: Vec<u8>,
    client_email: String,
    project_id: String,
    client: reqwest::Client,
    /// Where to send. A field so a test can point it at a local server and
    /// check what this actually puts on the wire.
    host: String,
    token_host: String,
    cached: tokio::sync::Mutex<Option<(String, u64)>>,
}

impl Fcm {
    /// Read a service account JSON, the file the Firebase console hands out.
    ///
    /// Three fields are used and the rest ignored: the key, who it belongs to,
    /// and which project to push to.
    pub fn new(service_account: &str) -> Result<Self> {
        let json: serde_json::Value =
            serde_json::from_str(service_account).context("the service account is not JSON")?;

        let pem = json["private_key"]
            .as_str()
            .context("the service account has no private_key")?;
        let client_email = json["client_email"]
            .as_str()
            .context("the service account has no client_email")?
            .to_owned();
        let project_id = json["project_id"]
            .as_str()
            .context("the service account has no project_id")?
            .to_owned();

        Ok(Self {
            key: pkcs8_from_pem(pem)?,
            client_email,
            project_id,
            client: reqwest::Client::new(),
            host: FCM_HOST.to_owned(),
            token_host: GOOGLE_TOKEN_HOST.to_owned(),
            cached: tokio::sync::Mutex::new(None),
        })
    }

    /// The same, pointed somewhere else, so a test can read what this sends.
    #[cfg(test)]
    fn at(mut self, host: String) -> Self {
        self.token_host = host.clone();
        self.host = host;
        self
    }

    /// A signed assertion, exchanged for an access token, cached until it is
    /// nearly stale.
    ///
    /// Google's tokens last an hour and minting one is a network round trip, so
    /// a server that minted per push would add a round trip to every wake and
    /// would be doing it for every device at once.
    async fn bearer(&self) -> Result<String> {
        let now = now_seconds();
        let mut cached = self.cached.lock().await;
        if let Some((token, minted)) = cached.as_ref() {
            if now < minted + JWT_LIFETIME {
                return Ok(token.clone());
            }
        }

        let assertion = self.assertion(now)?;
        let response = self
            .client
            .post(format!("{}/token", self.token_host))
            .header("content-type", "application/x-www-form-urlencoded")
            // Built by hand rather than by asking `reqwest` for its form and
            // json features. Two features for two request bodies is a larger
            // dependency for a smaller reason, and what goes in each of these
            // is fixed and short.
            .body(format!(
                "grant_type={}&assertion={}",
                form_encode("urn:ietf:params:oauth:grant-type:jwt-bearer"),
                form_encode(&assertion),
            ))
            .send()
            .await
            .context("asking Google for an access token")?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("Google refused an access token: {status} {body}");
        }

        let json: serde_json::Value =
            serde_json::from_str(&body).context("Google's token reply is not JSON")?;
        let token = json["access_token"]
            .as_str()
            .context("Google's token reply has no access_token")?
            .to_owned();

        *cached = Some((token.clone(), now));
        Ok(token)
    }

    /// The signed assertion, RS256 over the service account's claims.
    fn assertion(&self, now: u64) -> Result<String> {
        let header = br#"{"alg":"RS256","typ":"JWT"}"#;
        let claims = format!(
            r#"{{"iss":"{}","scope":"{FCM_SCOPE}","aud":"{}/token","iat":{now},"exp":{}}}"#,
            self.client_email,
            self.token_host,
            now + 3600,
        );

        let signing_input = format!(
            "{}.{}",
            data_encoding::BASE64URL_NOPAD.encode(header),
            data_encoding::BASE64URL_NOPAD.encode(claims.as_bytes()),
        );

        let pair = ring::signature::RsaKeyPair::from_pkcs8(&self.key)
            .map_err(|_| anyhow::anyhow!("the service account key is not an RSA key"))?;
        let mut signature = vec![0u8; pair.public().modulus_len()];
        pair.sign(
            &ring::signature::RSA_PKCS1_SHA256,
            &ring::rand::SystemRandom::new(),
            signing_input.as_bytes(),
            &mut signature,
        )
        .map_err(|_| anyhow::anyhow!("signing the assertion failed"))?;

        Ok(format!(
            "{signing_input}.{}",
            data_encoding::BASE64URL_NOPAD.encode(&signature)
        ))
    }

    /// Wake one device.
    ///
    /// The payload says nothing, for the same reason Apple's says nothing: the
    /// message is in the mailbox, which is where the device goes to look, and
    /// this server could not read it if it tried.
    ///
    /// `collapse_key` is Google's word for Apple's collapse id, and does the
    /// same job: a device that missed three wakes gets one.
    pub async fn wake(&self, device: &Device) -> Result<()> {
        let bearer = self.bearer().await?;

        let body = serde_json::json!({
            "message": {
                "token": device.token,
                "notification": { "title": "Rotelyx" },
                "android": {
                    "priority": "high",
                    "collapse_key": "rotelyx-wake",
                },
                "data": { "decoy": "true" },
            }
        });

        let response = self
            .client
            .post(format!(
                "{}/v1/projects/{}/messages:send",
                self.host, self.project_id
            ))
            .header("authorization", format!("Bearer {bearer}"))
            .header("content-type", "application/json")
            .body(body.to_string())
            .send()
            .await
            .context("calling Google")?;

        let status = response.status();
        if status.is_success() {
            return Ok(());
        }

        let reason = response.text().await.unwrap_or_default();
        bail!("Google refused a wake: {status} {reason}")
    }

    /// Whether a failure means the device is gone for good.
    ///
    /// Google says `UNREGISTERED` with a 404 for a token that belonged to an
    /// application that was uninstalled. `INVALID_ARGUMENT` is a token that was
    /// never valid, which is equally not worth calling about again.
    pub fn is_gone(error: &str) -> bool {
        error.contains("UNREGISTERED") || error.contains("INVALID_ARGUMENT")
    }
}

/// Percent encode a form value.
///
/// Only what a form body needs: everything that is not unreserved becomes a
/// percent escape. The two values this is used on are a fixed URN and a base64url
/// assertion, so this is small on purpose rather than general.
fn form_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// The DER inside a PKCS#8 PEM.
///
/// Google hands out `-----BEGIN PRIVATE KEY-----`, which is PKCS#8, which is
/// what the signer wants once the armour is off.
fn pkcs8_from_pem(pem: &str) -> Result<Vec<u8>> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .flat_map(|line| line.chars())
        .filter(|c| !c.is_whitespace())
        .collect();
    data_encoding::BASE64
        .decode(body.as_bytes())
        .context("the service account key is not base64")
}

/// Compare two stored secret hashes without leaking where they differ.
///
/// These are hex digests rather than the secrets themselves, so a timing leak
/// here is worth less than it looks: an attacker who learned a digest still has
/// to find a secret that produces it. Constant time anyway, because the cost is
/// one comparison and the alternative is an argument every time somebody reads
/// this.
///
/// The stored form of a revocation secret.
///
/// Public because the registry that holds these lives in the mailbox and has
/// to write the same value this reads.
pub fn hash(secret: &str) -> String {
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
pub async fn sweep(pushers: &Pushers, devices: &[Device]) -> Vec<String> {
    let mut dead = Vec::new();

    for device in devices {
        // Dispatched on what the device said it was when it registered. A
        // device whose service this server was not configured for is skipped
        // rather than reported dead: the token is fine, the operator has not
        // set up that side, and dropping it would make the registration
        // silently disappear.
        let (result, gone): (Result<()>, fn(&str) -> bool) = match device.kind.as_str() {
            "apns" => match pushers.apns.as_ref() {
                Some(apns) => (apns.wake(device).await, Apns::is_gone),
                None => continue,
            },
            "fcm" => match pushers.fcm.as_ref() {
                Some(fcm) => (fcm.wake(device).await, Fcm::is_gone),
                None => continue,
            },
            other => {
                warn!(kind = %other, "a device registered for a service this does not call");
                continue;
            }
        };

        match result {
            Ok(()) => debug!("woke a device"),
            Err(e) => {
                let text = e.to_string();
                if gone(&text) {
                    dead.push(device.token.clone());
                } else {
                    warn!(error = %text, "a wake failed");
                }
            }
        }
    }

    dead
}

/// Whatever push services this server was configured to call.
///
/// Both optional and both allowed at once: a deployment with iOS users and no
/// Android ones is the ordinary case, and so is the reverse.
#[derive(Default)]
pub struct Pushers {
    pub apns: Option<Arc<Apns>>,
    pub fcm: Option<Arc<Fcm>>,
}

impl Pushers {
    /// Whether this server can wake anything at all.
    pub fn any(&self) -> bool {
        self.apns.is_some() || self.fcm.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Not Google's and not anybody's: what is under test is what this module
    /// puts on the wire, and that needs a key that signs, not a key that means
    /// something.
    const TEST_SERVICE_ACCOUNT_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDPuz+ju1jbAbJo\n\
lU7s8LDHNbHcGeR4ER+uNksHkHCNfsn8St/RJIGaNxI7svcRcTRqL5iues/OWwAG\n\
LKkFaLBTSYk7fjD8O0uTCqJmEM/5NH/0ohh84VJUbOYUINKWQ7YlHGsZEdVA87QP\n\
4HjOffnLLRYj7/Qvcz+ykSEqRLxnhatEzknojENRe5YctztkCzXmeJAoF2L4R/rP\n\
mbHJXTz5SQ7m3VrSfZvIcfpdB3TYmNwWUtZCInsp7rcSJXVbFbrJpmlkq+qvai8x\n\
hHYq80E5RQK2HsjZ+vX8UHfD3g+wyBGNtRsMg+6seqKxKxEQ9HLPOBVNMwv1KoAT\n\
12Qu/R/nAgMBAAECggEAGI9ugEjDwi0Kr3PLv5bbh8oQ69GB4jJAGSRhLZVFwWz2\n\
q6YcnUkgK6AMP1OzA3RreoyDFEn/7Ml0kMZR+4o7orVEjOyoFQJbtphgyAl/1VqA\n\
MGfD1mv7hHDVqRaSX2LFE9Eu1ml12baWmPP0xJE/aea8QeZ6a+vH4bBoB+vVjLWZ\n\
4Gsfw6jkEh418wpZP3QrkurIO7b2H+DN9MwOFHsv8Qmme7k2Jui6J9AcPTF0SkyN\n\
IQgGEjxiq1BCg7Rpgy+pwOEVEP7DRemuJ40hnxy5RObAbeQAJ5/ZcKHZCjj6XAHA\n\
6MUPxddMd3kxZAA/aLDLbB/nXmaLzIb9ghsbbmBfAQKBgQD8U0/jEsX/IsC7c5zI\n\
rqsZwaGoj48t0odFgQXTapSIvePY1iDjgs/d4w2Nkb03zPAba0xmc6pPvxRlMeVQ\n\
iJUBu7m/IP9Izy4znLw2iRnXceF2kgiFL+xfegChjD9T32f3lFAICgDNK+2ElQlq\n\
/aYK485Gp08qBYI4CF+y02v9AQKBgQDSwa/STOgfk06I4bBNSEBgGf20Hyh7waGo\n\
SU69Q6q9kxOwCB+JXOXsAAuyrWZv/9HwCvKkqOfo0khcWbP8mC8NpgG+3IRMvvuB\n\
bfxDIFOLZD06aken1VZlMw8kM+LXE0Rq97oyapCqovjk6eAFOpDkelxcVzpaygRK\n\
+2guEAfU5wKBgCJN+Vh33u9W/Dj/+NrX1G9GAgJ2shKawsVSS0Z5AQSuPGHoisQj\n\
rrsN+XO70qvZcvNnXRW4t/jrk4xGglS2nPuFWDWB+PMfJ7rgnj4T2a2O0AZcyEfD\n\
QjGg1qEf/iQbBXmFcnQFWCKMzFfwIz2mioKEgjDc4khmQ1P233vifpYBAoGBAKpR\n\
QCcxY3zw7EyOJo2tz+hZ2L8RVwP8DQoUg/9LidW93/En/2RgoKZBuzJgEyJ7mErm\n\
bgRHQ3LRTQzkqSF+Urgy6cI2Luxegp2sJmqQ2zMQhLKKZPHq4/DQfHIDRFQPDAFt\n\
xRktKU/ceEt1/UX8eE9L2wv8qfnou+NknGJtLgcNAoGAKmk6m99xOg9sd4OJdn+v\n\
Ic8saHWJz3l1++Ssskf/0B8hVr3VTn61YN0L0DZH36stC4HJuPR0a+tZuIXZIKiE\n\
qv1shR1KSQ4H6tlaj+V8yNhKGRi6ME094biJSj4UXptd9IfhMt6r6s/LvcH3WU9Z\n\
4hRrDIrOpS/SYkEjMv0ONHI=\n\
-----END PRIVATE KEY-----";

   fn test_service_account() -> String {
        serde_json::json!({
            "type": "service_account",
            "project_id": "rotelyx-test",
            "private_key": TEST_SERVICE_ACCOUNT_KEY,
            "client_email": "wake@rotelyx-test.iam.gserviceaccount.com",
        })
        .to_string()
    }


   /// the first push fails.
    #[test]
    fn an_incomplete_service_account_is_refused_at_startup() {
        for missing in ["project_id", "client_email", "private_key"] {
            let mut json: serde_json::Value =
                serde_json::from_str(&test_service_account()).expect("valid");
            json.as_object_mut().expect("an object").remove(missing);
            assert!(
                Fcm::new(&json.to_string()).is_err(),
                "a service account with no {missing} was accepted"
            );
        }
        assert!(
            Fcm::new("not json").is_err(),
            "something that is not a service account was accepted"
        );
        assert!(
            Fcm::new(&test_service_account()).is_ok(),
            "a complete service account was refused"
        );
    }


   #[test]
    fn the_assertion_claims_what_google_asks_for() {
        let fcm = Fcm::new(&test_service_account()).expect("a service account");
        let assertion = fcm.assertion(1_700_000_000).expect("signing");

        let parts: Vec<&str> = assertion.split('.').collect();
        assert_eq!(
            parts.len(),
            3,
            "an assertion is header, claims and signature"
        );

        let claims = BASE64URL_NOPAD
            .decode(parts[1].as_bytes())
            .expect("the claims are base64url");
        let claims: serde_json::Value =
            serde_json::from_slice(&claims).expect("the claims are JSON");

        assert_eq!(claims["iss"], "wake@rotelyx-test.iam.gserviceaccount.com");
        assert_eq!(claims["scope"], FCM_SCOPE, "a wider scope than this needs");
        assert_eq!(claims["iat"], 1_700_000_000);
        assert_eq!(
            claims["exp"], 1_700_003_600,
            "an assertion that never expires"
        );

        let header = BASE64URL_NOPAD
            .decode(parts[0].as_bytes())
            .expect("the header is base64url");
        let header: serde_json::Value =
            serde_json::from_slice(&header).expect("the header is JSON");
        assert_eq!(header["alg"], "RS256", "Google takes RS256 and not ES256");
    }


   /// Everything else here checks a value this module computed. This checks
    /// the request it puts on a socket: that the assertion is exchanged at the
    /// token endpoint, that the access token that comes back is the bearer on
    /// the push, and that the push goes to the project's own URL. Those are
    /// three places a mistake produces a phone that silently stops receiving,
    /// and none of them are visible from the inside.
    #[tokio::test]
    async fn what_it_sends_is_what_google_asks_for() {
        use axum::{routing::post, Router};
        use std::sync::{Arc, Mutex};

        #[derive(Default)]
        struct Seen {
            token_body: String,
            push_path: String,
            push_auth: String,
            push_body: String,
        }

        let seen = Arc::new(Mutex::new(Seen::default()));

        let app = Router::new()
            .route(
                "/token",
                post({
                    let seen = seen.clone();
                    move |body: String| async move {
                        seen.lock().expect("not poisoned").token_body = body;
                        r#"{"access_token":"an-access-token","expires_in":3599}"#
                    }
                }),
            )
            .route(
                "/v1/projects/{project}/messages:send",
                post({
                    let seen = seen.clone();
                    move |uri: axum::http::Uri,
                          headers: axum::http::HeaderMap,
                          body: String| async move {
                        let mut seen = seen.lock().expect("not poisoned");
                        seen.push_path = uri.path().to_owned();
                        seen.push_auth = headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or_default()
                            .to_owned();
                        seen.push_body = body;
                        "{}"
                    }
                }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let addr = listener.local_addr().expect("an address");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let fcm = Fcm::new(&test_service_account())
            .expect("a service account")
            .at(format!("http://{addr}"));

        let device = Device::registering("ab".repeat(32), "fcm".into(), "a-long-enough-secret");
        fcm.wake(&device)
            .await
            .expect("the push should be accepted");

        let seen = seen.lock().expect("not poisoned");

        // The assertion was exchanged, with the grant type Google requires.
        assert!(
            seen.token_body
                .contains("grant_type=urn%3Aietf%3Aparams%3Aoauth"),
            "the token request did not carry the grant type: {}",
            seen.token_body
        );
        assert!(
            seen.token_body.contains("assertion=") && seen.token_body.contains('.'),
            "the token request carried no assertion"
        );

        // The token that came back is what the push presented. A push that
        // carried the assertion instead, or an empty bearer, is refused by
        // Google with a message that says nothing about which of the two.
        assert_eq!(
            seen.push_auth, "Bearer an-access-token",
            "the push did not present the access token that was just fetched"
        );

        // And it went to this project, not to a URL with the project missing.
        assert_eq!(seen.push_path, "/v1/projects/rotelyx-test/messages:send");

        // The payload names the device and says nothing else about it.
        let body: serde_json::Value =
            serde_json::from_str(&seen.push_body).expect("the push body is JSON");
        assert_eq!(body["message"]["token"], device.token);
        assert_eq!(
            body["message"]["android"]["collapse_key"], "rotelyx-wake",
            "three missed wakes should collapse into one"
        );
        assert!(
            !seen.push_body.contains("tag") && !seen.push_body.contains("mailbox"),
            "the push carries something about the conversation: {}",
            seen.push_body
        );
    }


   /// Google's tokens last an hour and minting one is a round trip. A server
    /// that minted per push would add one to every wake, and would do it for
    /// every device at once on every sweep.
    #[tokio::test]
    async fn the_access_token_is_fetched_once() {
        use axum::{routing::post, Router};
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        let mints = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route(
                "/token",
                post({
                    let mints = mints.clone();
                    move || async move {
                        mints.fetch_add(1, Ordering::SeqCst);
                        r#"{"access_token":"an-access-token","expires_in":3599}"#
                    }
                }),
            )
            .route(
                "/v1/projects/{project}/messages:send",
                post(|| async { "{}" }),
            );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a port");
        let addr = listener.local_addr().expect("an address");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let fcm = Fcm::new(&test_service_account())
            .expect("a service account")
            .at(format!("http://{addr}"));
        let device = Device::registering("ab".repeat(32), "fcm".into(), "a-long-enough-secret");

        for _ in 0..3 {
            fcm.wake(&device).await.expect("accepted");
        }

        assert_eq!(
            mints.load(Ordering::SeqCst),
            1,
            "an access token was minted per push"
        );
    }


   /// The grant type is a URN full of colons and the assertion is base64url.
    /// A body that did not escape the first would be read as two parameters.
    #[test]
    fn form_values_are_escaped() {
        assert_eq!(
            form_encode("urn:ietf:params:oauth:grant-type:jwt-bearer"),
            "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"
        );
        // base64url's alphabet passes through untouched, which is what keeps a
        // signature from being mangled on the way out.
        assert_eq!(form_encode("aA0-_.~"), "aA0-_.~");
    }


   #[test]
    fn a_dead_google_token_is_recognised() {
        assert!(Fcm::is_gone("Google refused a wake: 404 UNREGISTERED"));
        assert!(Fcm::is_gone("Google refused a wake: 400 INVALID_ARGUMENT"));
        assert!(
            !Fcm::is_gone("Google refused a wake: 503 UNAVAILABLE"),
            "a service that is briefly down is not a device that is gone"
        );
    }

}
