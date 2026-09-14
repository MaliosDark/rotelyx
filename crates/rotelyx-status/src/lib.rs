//! Availability, recorded and rendered.
//!
//! Both the relay and the mailbox show a status strip on their landing page,
//! and they show the same one. This is that one: a second copy would drift, and
//! two strips whose colours mean subtly different things are worse than none.
//!
//! # What it records, and why a file is needed at all
//!
//! Half-hour bucket numbers, and nothing else. No addresses, no identifiers, no
//! counts of anything.
//!
//! Without a file the strip can only say "up since this process started", so it
//! is green from the left edge after every restart and an outage is never
//! visible. A service that is down serves no status page, so the only way it
//! can report having been down is to have written something beforehand.
//!
//! What the file reveals is exactly what somebody polling from outside could
//! have measured anyway, which is why it is safe to publish. What it must never
//! grow into is a record of traffic: a relay's whole exposure is which
//! endpoints talk to which, and a page saying how many are connected publishes
//! the size and rhythm of a community to anybody who polls it.
//!
//! # Load, without numbers
//!
//! The strip also says how the service is doing, not only whether it is there:
//! **operational**, **busy** or **under strain**, the three words every status
//! page people trust uses, drawn as three colours. That is the whole of what
//! leaves the process. The service decides the word from what it measures
//! about itself (how full it is, how long a deposit takes, whether it has had
//! to refuse anybody) and reports the word, never the measurement, so the page
//! can show a bar going amber while a town is moving in without telling the
//! next visitor how large the town is. Each bucket keeps the worst word said
//! during it, which is what a person reading it later wants to know.

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Buckets in the strip, and how long each covers.
///
/// 96 half hours is two days: long enough to see a restart, short enough that
/// each bar is still a usable width on a phone.
pub const BUCKETS: usize = 96;
pub const BUCKET_MINUTES: u64 = 30;

/// How a service is doing, in the words a status page uses.
///
/// Ordered, so the worst of a bucket can be kept: strained > busy > fine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// Serving, with room to spare.
    Operational = 0,
    /// Serving, and working for it: the point at which a person would notice
    /// nothing yet and an operator would want to know.
    Busy = 1,
    /// Serving, and refusing or slowing: somebody is noticing.
    Strained = 2,
}

impl Level {
    fn class(self) -> &'static str {
        match self {
            Level::Operational => "up",
            Level::Busy => "busy",
            Level::Strained => "strained",
        }
    }

    /// The word on the page.
    pub fn text(self) -> &'static str {
        match self {
            Level::Operational => "Operational",
            Level::Busy => "Busy",
            Level::Strained => "Under strain",
        }
    }

    fn from_code(code: u64) -> Self {
        match code {
            2 => Level::Strained,
            1 => Level::Busy,
            _ => Level::Operational,
        }
    }
}

/// One service's availability.
pub struct Status {
    started: OnceLock<Instant>,
    file: OnceLock<PathBuf>,
    /// The word right now, as last reported by the service.
    level: std::sync::atomic::AtomicU8,
}

impl Default for Status {
    fn default() -> Self {
        Self::new()
    }
}

impl Status {
    pub const fn new() -> Self {
        Self {
            started: OnceLock::new(),
            file: OnceLock::new(),
            level: std::sync::atomic::AtomicU8::new(0),
        }
    }

    /// What the service says about itself now. Kept for the page, and folded
    /// into the current bucket on the next heartbeat, worst word wins.
    pub fn report(&self, level: Level) {
        self.level
            .store(level as u8, std::sync::atomic::Ordering::Relaxed);
    }

    /// The word right now.
    pub fn level(&self) -> Level {
        Level::from_code(u64::from(
            self.level.load(std::sync::atomic::Ordering::Relaxed),
        ))
    }

    /// Begin counting uptime. Call once, when the service starts serving.
    ///
    /// Not done lazily on the first page view, or a service nobody visits for a
    /// day reports one minute of uptime.
    pub fn started_now(&self) {
        let _ = self.started.set(Instant::now());
    }

    /// Record availability to this path. Optional: without it there is no
    /// history before the current process.
    pub fn record_at(&self, path: PathBuf) {
        let _ = self.file.set(path);
    }

    pub fn uptime(&self) -> Duration {
        self.started.get().map(Instant::elapsed).unwrap_or_default()
    }

    /// Note that the current bucket was served.
    ///
    /// Call about once a minute rather than once a bucket: a service that dies
    /// four minutes into a half hour has still served it, and recording only on
    /// the boundary loses up to thirty minutes of history per restart.
    pub fn heartbeat(&self) {
        let Some(path) = self.file.get() else { return };
        let now = current_bucket();
        let level = self.level();

        let mut seen = self.recorded();
        match seen.last_mut() {
            // Already on record for this bucket: only a worse word changes it.
            Some((bucket, worst)) if *bucket == now => {
                if level <= *worst {
                    return;
                }
                *worst = level;
            }
            _ => seen.push((now, level)),
        }
        seen.sort_unstable_by_key(|(b, _)| *b);
        seen.dedup_by_key(|(b, _)| *b);
        let keep = seen.len().saturating_sub(BUCKETS * 2);
        // A line per bucket, the level after a space; a bare number, which is
        // what earlier versions wrote, reads as operational.
        let text = seen[keep..]
            .iter()
            .map(|(b, l)| {
                if *l == Level::Operational {
                    b.to_string()
                } else {
                    format!("{b} {}", *l as u8)
                }
            })
            .collect::<Vec<_>>()
            .join("\n");
        // Written whole and renamed, so a service killed mid-write leaves the
        // previous file rather than half of a new one.
        let temp = path.with_extension("tmp");
        if std::fs::write(&temp, text).is_ok() {
            let _ = std::fs::rename(&temp, path);
        }
    }

    fn recorded(&self) -> Vec<(u64, Level)> {
        self.file
            .get()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|t| {
                t.lines()
                    .filter_map(|l| {
                        let mut parts = l.split_whitespace();
                        let bucket: u64 = parts.next()?.parse().ok()?;
                        let level = parts
                            .next()
                            .and_then(|c| c.parse::<u64>().ok())
                            .map(Level::from_code)
                            .unwrap_or(Level::Operational);
                        Some((bucket, level))
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// How many buckets are on record, for the line under the strip.
    pub fn recorded_count(&self) -> usize {
        self.recorded().len()
    }

    /// The strip, as HTML.
    pub fn strip(&self) -> String {
        let now = current_bucket();
        let recorded = self.recorded();
        let uptime = self.uptime();

        // The oldest bucket anything is known about. Before it, grey means "no
        // record", which is not "down" and must not be drawn as though it were.
        let known_from = recorded
            .first()
            .map(|(b, _)| *b)
            .unwrap_or_else(|| now.saturating_sub(uptime.as_secs() / (BUCKET_MINUTES * 60)));

        let mut out = String::with_capacity(BUCKETS * 64);
        out.push_str("<div class=\"bars\">");
        for slot in 0..BUCKETS {
            let bucket = now.saturating_sub((BUCKETS - 1 - slot) as u64);
            let found = recorded.binary_search_by_key(&bucket, |(b, _)| *b).ok();
            let (class, word) = if bucket == now {
                // In progress. Always drawn, because the page is being rendered
                // so something is running. Coloured by the word the service
                // says about itself right now, or the worst it has said this
                // bucket, whichever is worse: a bucket that was strained ten
                // minutes ago is still a strained bucket.
                //
                // Deriving "in progress" from `uptime % bucket != 0` is the
                // obvious version and it is wrong: a service up for under a
                // second has a remainder of zero, so nothing was drawn at all
                // and a running service showed 96 grey bars, which reads as
                // down.
                let worst = found
                    .map(|i| recorded[i].1)
                    .unwrap_or(Level::Operational)
                    .max(self.level());
                (format!("part {}", worst.class()), worst.text())
            } else if let Some(i) = found {
                (recorded[i].1.class().to_string(), recorded[i].1.text())
            } else if bucket >= known_from {
                // Inside the recorded window with no heartbeat. The only colour
                // here that is a measurement rather than an absence, and the
                // whole reason for keeping a file.
                ("down".to_string(), "Not serving")
            } else {
                ("unknown".to_string(), "No record")
            };
            // The bucket's half hour, in UTC, on hover: what a person reading
            // a bar wants to know, and the one thing the colour does not say.
            let start = bucket * BUCKET_MINUTES * 60;
            let end = start + BUCKET_MINUTES * 60;
            out.push_str(&format!(
                "<i class=\"{class}\" title=\"{:02}:{:02} to {:02}:{:02} UTC: {word}\"></i>",
                (start / 3600) % 24,
                (start / 60) % 60,
                (end / 3600) % 24,
                (end / 60) % 60,
            ));
        }
        out.push_str("</div>");
        out
    }

    /// The block above the strip: the dot, the word, and the uptime.
    pub fn headline(&self) -> String {
        let level = self.level();
        format!(
            "<div class=\"status {}\"><span class=\"dot\"></span><b>{}</b><span>up {}</span></div>",
            level.class(),
            level.text(),
            self.uptime_text()
        )
    }

    /// Uptime, as a person would say it.
    pub fn uptime_text(&self) -> String {
        let s = self.uptime().as_secs();
        let (d, h, m) = (s / 86_400, (s % 86_400) / 3600, (s % 3600) / 60);
        if d > 0 {
            format!("{d}d {h}h")
        } else if h > 0 {
            format!("{h}h {m}m")
        } else {
            format!("{m}m")
        }
    }
}

fn current_bucket() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() / (BUCKET_MINUTES * 60))
        .unwrap_or(0)
}

/// The legend. Shared so the two pages cannot disagree about what a colour
/// means, and present at all because a red bar with nothing naming it is worse
/// than no bar.
pub const LEGEND: &str = concat!(
    "<p class=\"legend\">",
    "<span><i class=\"up\"></i>operational</span>",
    "<span><i class=\"busy\"></i>busy</span>",
    "<span><i class=\"strained\"></i>under strain</span>",
    "<span><i class=\"down\"></i>not serving</span>",
    "<span><i class=\"unknown\"></i>no record</span>",
    "</p>"
);

/// The styles the strip needs. Inline, because both pages ship a single
/// document with no fetchable resources and a content security policy that
/// says so.
/// The page keeps itself current with a plain refresh, not a script.
///
/// Both landing pages ship `default-src 'none'`, and loosening a server's
/// policy so a status widget can poll is a poor trade; a page this small
/// reloading every half minute costs nothing and needs no exception. Put in
/// the head of the page.
pub const REFRESH: &str = "<meta http-equiv=\"refresh\" content=\"30\">";

pub const STYLE: &str = concat!(
    ".status{display:flex;align-items:center;gap:10px;margin:26px 0 12px}",
    ".dot{width:9px;height:9px;border-radius:50%;background:#2ea043;",
    "box-shadow:0 0 0 4px rgba(46,160,67,.16)}",
    ".status.busy .dot{background:#d29922;box-shadow:0 0 0 4px rgba(210,153,34,.18)}",
    ".status.strained .dot{background:#e5672b;box-shadow:0 0 0 4px rgba(229,103,43,.18)}",
    ".status b{font-size:.95rem;font-weight:650}",
    ".status span{margin-left:auto;font:600 .64rem ui-monospace,Menlo,monospace;",
    "letter-spacing:.1em;text-transform:uppercase;opacity:.65}",
    ".bars{display:flex;gap:2px;height:34px;align-items:flex-end;margin:0 0 8px}",
    ".bars i{flex:1;border-radius:1px;min-width:2px}",
    ".up{background:#2ea043;height:100%}",
    ".busy{background:#d29922;height:100%}",
    ".strained{background:#e5672b;height:100%}",
    ".part{height:78%;opacity:.85}",
    ".down{background:#cf3b3b;height:88%}",
    ".unknown{background:#2a2721;height:60%}",
    ".legend{display:flex;gap:14px;flex-wrap:wrap;margin:0 0 8px;font-size:.78rem;opacity:.7}",
    ".legend span{display:flex;align-items:center;gap:6px}",
    ".legend i{width:9px;height:9px;border-radius:2px;display:inline-block}",
    ".scale{display:flex;justify-content:space-between;",
    "font:600 .6rem ui-monospace,Menlo,monospace;letter-spacing:.1em;",
    "text-transform:uppercase;opacity:.45;margin-bottom:6px}",
    ".note{font-size:.78rem;opacity:.5;margin:0 0 22px}"
);

#[cfg(test)]
mod tests {
    use super::*;

    fn count(html: &str, class: &str) -> usize {
        html.matches(&format!("class=\"{class}\"")).count()
    }

    /// With no file, nothing may be claimed about the past.
    #[test]
    fn without_a_record_nothing_is_asserted_as_an_outage() {
        let s = Status::new();
        s.started_now();
        let strip = s.strip();

        assert_eq!(strip.matches("class=\"part ").count(), 1, "the bucket in progress");
        assert_eq!(
            count(&strip, "down"),
            0,
            "no record, so no outage may be drawn"
        );
        assert_eq!(
            count(&strip, "up") + strip.matches("class=\"part ").count() + count(&strip, "unknown"),
            BUCKETS
        );
        assert!(
            strip.contains("<i class=\"part up\" title=\"") && strip.ends_with("Operational\"></i></div>"),
            "the newest bucket belongs on the right, beside the `now` label"
        );
    }

    /// A gap in the record is an outage, and it is the reason the file exists.
    #[test]
    fn a_gap_in_the_record_is_drawn_as_not_serving() {
        let dir = std::env::temp_dir().join(format!("rotelyx-status-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("gap");

        let now = current_bucket();
        // Eight served, eight missing, four served.
        let mut buckets: Vec<u64> = (13..=20).map(|n| now - n).collect();
        buckets.extend((1..=4).map(|n| now - n));
        buckets.sort_unstable();
        std::fs::write(
            &path,
            buckets
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
        )
        .expect("write");

        let s = Status::new();
        s.started_now();
        s.record_at(path.clone());
        let strip = s.strip();

        assert_eq!(count(&strip, "up"), 12, "the twelve recorded buckets");
        assert_eq!(
            count(&strip, "down"),
            8,
            "the gap, measured rather than assumed"
        );
        let part = strip.matches("class=\"part ").count();
        assert_eq!(part, 1);
        assert_eq!(
            count(&strip, "up") + count(&strip, "down") + part + count(&strip, "unknown"),
            BUCKETS
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The word a service says about itself colours the bar, and the worst
    /// word said during a bucket is what the bucket keeps.
    #[test]
    fn the_worst_word_of_a_bucket_is_what_it_keeps() {
        let dir = std::env::temp_dir().join(format!("rotelyx-status-level-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("levels");

        let s = Status::new();
        s.started_now();
        s.record_at(path.clone());
        s.heartbeat();
        assert!(s.strip().contains("class=\"part up\""), "fine to begin with");

        s.report(Level::Strained);
        s.heartbeat();
        assert!(s.strip().contains("class=\"part strained\""));
        assert!(s.headline().contains("Under strain"));

        // Easing off does not rewrite what happened: the bucket stays the
        // worst it was, and only the headline says things are better now.
        s.report(Level::Busy);
        s.heartbeat();
        assert!(s.strip().contains("class=\"part strained\""));
        assert!(s.headline().contains("Busy"));

        // And it is written down that way.
        let text = std::fs::read_to_string(&path).expect("file");
        assert!(text.trim().ends_with(" 2"), "the bucket was recorded with its level: {text:?}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The heartbeat writes, and does not rewrite for the same bucket.
    #[test]
    fn the_heartbeat_records_once_per_bucket() {
        let dir = std::env::temp_dir().join(format!("rotelyx-beat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("beat");

        let s = Status::new();
        s.started_now();
        s.record_at(path.clone());

        for _ in 0..5 {
            s.heartbeat();
        }
        let text = std::fs::read_to_string(&path).expect("written");
        assert_eq!(
            text.lines().count(),
            1,
            "five beats in one bucket is one line"
        );
        assert_eq!(s.recorded_count(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn uptime_reads_as_a_person_would_say_it() {
        let s = Status::new();
        assert_eq!(s.uptime_text(), "0m", "not started is zero, not a panic");
    }
}
