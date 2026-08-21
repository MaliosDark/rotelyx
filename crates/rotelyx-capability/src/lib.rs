//! Capability tokens: the format, and the verifying half of it.
//!
//! # Why this is its own crate
//!
//! Two programs have to agree on what a token is: the mailbox, which checks
//! them, and whatever issues them. Only the first of those is in this
//! repository.
//!
//! Issuing is a commercial operation. It needs a signing key, a decision about
//! what to sell and at what price, and a payment processor, none of which
//! belong in a repository people are meant to clone and run. So the issuing
//! code lives in a separate crate that is not published here, and this crate is
//! the contract between them: the token format, the tier definitions, and
//! verification.
//!
//! **A mailbox started without an issuer public key runs perfectly well.** It
//! accepts no tokens, everyone gets the free tier, and nothing else changes.
//! That is the mode a self-hosted operator wants, and it is the reason this
//! split costs the project nothing.
//!
//! What deliberately stays here rather than leaving with the issuer:
//!
//! - **Verification**, because an operator has to be able to check tokens.
//! - **The client's redeemer**, because clients blind and unblind their own
//!   tokens, and clients are open source.
//! - **The tier definitions**, because the server enforces them.
//!
//! What leaves is the code that holds a signing key.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use data_encoding::BASE64URL_NOPAD;
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Domain separation, so a mailbox token can never be replayed as a signature
/// over anything else this project signs.
pub const TOKEN_CONTEXT: &[u8] = b"rotelyx mailbox capability v1";

/// The metering period. Quota is expressed per period and the counter resets
/// when one rolls over.
pub const PERIOD_HOURS: u64 = 24;

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("token is not valid base64url")]
    Encoding,
    #[error("token is malformed")]
    Malformed,
    #[error("token signature does not verify")]
    BadSignature,
    #[error("token expired")]
    Expired,
    #[error("this server accepts no tokens: it was started without an issuer key")]
    NoIssuer,
}

/// What a client is allowed to do.
///
/// Deliberately a closed set rather than a bag of numbers in the token: a
/// client cannot mint itself a tier that the server has never heard of, and
/// changing what a tier means does not require reissuing anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Tier {
    Free,
    Plus,
    /// The largest group the client will build at all.
    PlusPlus,
}

/// The limits a tier carries.
///
/// Every one of these is enforceable without reading a byte of content. That is
/// the constraint that decided the list: a limit the mailbox cannot check
/// blindly is not a limit it can sell.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Longest an uncollected envelope is kept, in seconds.
    pub ttl_seconds: u64,
    /// Envelopes held under one tag before deposits are refused.
    ///
    /// Clamped by `rotelyx_mailbox::MAX_PER_TAG`, so a tier asking for more
    /// than the store's ceiling quietly receives the ceiling instead. Pinned by
    /// a test, because the failure is invisible: the tier reports what it was
    /// sold and delivers less.
    pub max_per_tag: usize,
    /// Recipients one fan-out may name. This is the group size ceiling.
    pub max_fanout: usize,
    /// Largest envelope payload accepted, in bytes. A padding bucket size.
    pub max_payload: usize,
    /// Bytes of payload per period. Zero means unmetered.
    pub bytes_per_period: u64,
}

impl Tier {
    pub fn limits(self) -> Limits {
        match self {
            // Enough for ordinary one to one and small group use, and not
            // enough to host a community on. A free client cannot address a
            // large group or store a large attachment, and no amount of
            // reconnecting changes that.
            // Twenty five holds a family, a team or a circle of friends, which
            // is what an unpaid messenger has to do well or it is not a
            // messenger. It does not hold a community, and that is the line.
            Tier::Free => Limits {
                ttl_seconds: 7 * 24 * 3600,
                max_per_tag: 64,
                max_fanout: 25,
                max_payload: 64 * 1024,
                bytes_per_period: 64 * 1024 * 1024,
            },

            // 256 is where the ratchet tree still fits a 64 KiB padding bucket
            // with a quarter to spare. Past it the tree pays for a bucket it
            // barely fills, which is why the next step up costs more.
            Tier::Plus => Limits {
                ttl_seconds: 30 * 24 * 3600,
                max_per_tag: 256,
                max_fanout: 256,
                max_payload: 8 * 1024 * 1024,
                bytes_per_period: 8 * 1024 * 1024 * 1024,
            },

            // A thousand is the client's own ceiling. Each membership change
            // costs every member 128 KiB here against 32 KiB at 256, and the
            // mailbox stores a thousand copies of every message, so this tier
            // is genuinely more expensive to serve rather than merely gated.
            Tier::PlusPlus => Limits {
                ttl_seconds: 90 * 24 * 3600,
                max_per_tag: 256,
                max_fanout: 1_000,
                max_payload: 8 * 1024 * 1024,
                bytes_per_period: 64 * 1024 * 1024 * 1024,
            },
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Tier::Free => "free",
            Tier::Plus => "plus",
            Tier::PlusPlus => "plus++",
        }
    }
}

/// The signed part of a token.
///
/// No field identifies the holder. `id` is random and exists only so the meter
/// has something to count against.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Claims {
    pub id: [u8; 16],
    pub tier: Tier,
    /// Hours since the Unix epoch. Coarse on purpose: an expiry to the second
    /// would narrow down when a token was bought.
    pub expires_hour: u64,
    /// Payload bytes allowed per period, overriding the tier default when
    /// non-zero. Lets one token be sold with a larger allowance without
    /// inventing a tier for it.
    pub quota_bytes: u64,
}

/// A verified capability.
#[derive(Clone, Copy, Debug)]
pub struct Capability {
    pub id: [u8; 16],
    pub tier: Tier,
    pub limits: Limits,
}

impl Capability {
    /// What an unauthenticated client gets.
    /// The tier a caller gets before it presents anything.
    ///
    /// # Why the id is random rather than zero
    ///
    /// The meter counts against `id`, so a constant here puts every
    /// unauthenticated client in the world into one bucket. The free tier allows
    /// 64 MiB a period and a period is a day, so one client depositing 64 MiB
    /// took the whole free allowance away from everybody else on that mailbox
    /// until the period rolled over. At a fanout of 25 and 64 KiB an envelope
    /// that is 41 deposits, needing no token, no payment and no identity: the
    /// metering that exists to stop abuse was the way to do it.
    ///
    /// A fresh id per caller gives each one its own allowance. It is generated
    /// here and never leaves this process, so it identifies nobody and links
    /// nothing: two connections from one client get different ids, which is
    /// weaker linkage than a bought token, not stronger.
    pub fn free() -> Self {
        let mut id = [0u8; 16];
        getrandom::fill(&mut id).expect("OS CSPRNG unavailable");
        Self {
            id,
            tier: Tier::Free,
            limits: Tier::Free.limits(),
        }
    }
}

/// Verifies tokens. This is what the mailbox holds.
pub struct Verifier(VerifyingKey);

impl Verifier {
    pub fn from_public_hex(hex: &str) -> Option<Self> {
        let bytes = decode_hex(hex, 32)?;
        VerifyingKey::from_bytes(&bytes.try_into().ok()?).ok().map(Self)
    }

    /// Check a token and return what it permits.
    ///
    /// `now_hour` is passed in rather than read from the clock so expiry is
    /// testable and so clock handling stays in one place.
    pub fn verify(&self, token: &str, now_hour: u64) -> Result<Capability, TokenError> {
        let raw = BASE64URL_NOPAD
            .decode(token.trim().as_bytes())
            .map_err(|_| TokenError::Encoding)?;

        if raw.len() <= 64 {
            return Err(TokenError::Malformed);
        }
        let (body, sig) = raw.split_at(raw.len() - 64);

        let signature =
            Signature::from_slice(sig).map_err(|_| TokenError::Malformed)?;

        let mut signed = Vec::with_capacity(TOKEN_CONTEXT.len() + body.len());
        signed.extend_from_slice(TOKEN_CONTEXT);
        signed.extend_from_slice(body);

        // Signature before parsing: refuse to interpret bytes nobody vouched
        // for.
        self.0
            .verify(&signed, &signature)
            .map_err(|_| TokenError::BadSignature)?;

        let claims: Claims =
            postcard::from_bytes(body).map_err(|_| TokenError::Malformed)?;

        if claims.expires_hour <= now_hour {
            return Err(TokenError::Expired);
        }

        let mut limits = claims.tier.limits();
        if claims.quota_bytes > 0 {
            limits.bytes_per_period = claims.quota_bytes;
        }

        Ok(Capability {
            id: claims.id,
            tier: claims.tier,
            limits,
        })
    }
}

/// What one token has spent in the current period.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize)]
struct Spent {
    period: u64,
    bytes: u64,
}

/// Counts consumption per token.
///
/// Holds no address, no tag and no content: a random token id and a byte count,
/// reset every period. The whole point is that this table would tell an
/// attacker who seized it nothing about anybody.
#[derive(Default)]
pub struct Meter {
    spent: HashMap<[u8; 16], Spent>,
}

/// The outcome of asking to spend.
#[derive(Debug, PartialEq, Eq)]
pub enum Charge {
    /// Allowed. `remaining` is what is left this period.
    Allowed { remaining: u64 },
    /// Refused, and by how much it would have overshot.
    OverQuota { limit: u64, used: u64 },
}

impl Meter {
    /// Charge `bytes` against a capability.
    ///
    /// Refuses rather than allowing an overshoot, because a quota that is only
    /// checked after the fact is not a quota.
    pub fn charge(&mut self, cap: &Capability, bytes: u64, now_hour: u64) -> Charge {
        let limit = cap.limits.bytes_per_period;
        if limit == 0 {
            return Charge::Allowed { remaining: u64::MAX };
        }

        let period = now_hour / PERIOD_HOURS;
        let entry = self.spent.entry(cap.id).or_default();

        if entry.period != period {
            *entry = Spent { period, bytes: 0 };
        }

        let would_be = entry.bytes.saturating_add(bytes);
        if would_be > limit {
            return Charge::OverQuota {
                limit,
                used: entry.bytes,
            };
        }

        entry.bytes = would_be;
        Charge::Allowed {
            remaining: limit - entry.bytes,
        }
    }

    /// Drop counters from periods that have passed. Called on the same timer as
    /// the envelope sweep.
    pub fn sweep(&mut self, now_hour: u64) -> usize {
        let period = now_hour / PERIOD_HOURS;
        let before = self.spent.len();
        self.spent.retain(|_, s| s.period == period);
        before - self.spent.len()
    }

    #[cfg(test)]
    #[cfg(test)]
    pub fn tracked(&self) -> usize {
        self.spent.len()
    }

    /// Write the counters to `path`.
    ///
    /// # Why this has to exist
    ///
    /// A meter that lives only in memory hands every token a fresh allowance
    /// on every restart. Anyone who noticed would restart-farm the service, and
    /// an operator deploying twice a week would be giving the month away
    /// without ever seeing it in a log.
    ///
    /// # What ends up on disk
    ///
    /// A random 16 byte id, a period number and a byte count, per token. No
    /// address, no tag, no content, nothing that names a person. Seized whole,
    /// this file says how much some anonymous credential spent and nothing
    /// else. It is written 0600 anyway.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let encoded = postcard::to_allocvec(&self.spent)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Write beside the target and rename, so a crash mid-write leaves the
        // previous snapshot intact rather than a truncated file that reads as
        // "nobody has spent anything".
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, &encoded)?;
        restrict(&temporary)?;
        fs::rename(&temporary, path)
    }

    /// Read counters back, discarding any from periods that have already
    /// passed.
    ///
    /// A missing file is not an error: that is a first start.
    pub fn load(path: &Path, now_hour: u64) -> std::io::Result<Self> {
        let bytes = match fs::read(path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e),
        };

        let spent: HashMap<[u8; 16], Spent> = postcard::from_bytes(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let mut meter = Self { spent };
        meter.sweep(now_hour);
        Ok(meter)
    }
}

#[cfg(unix)]
fn restrict(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict(_: &Path) -> std::io::Result<()> {
    Ok(())
}

pub fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn decode_hex(hex: &str, expected: usize) -> Option<Vec<u8>> {
    let hex = hex.trim();
    if hex.len() != expected * 2 {
        return None;
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
        .collect()
}

pub mod blind;

#[cfg(test)]
mod vectors;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

#[cfg(test)]
mod tests;
