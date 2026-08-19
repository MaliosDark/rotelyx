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

use std::path::PathBuf;
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Buckets in the strip, and how long each covers.
///
/// 96 half hours is two days: long enough to see a restart, short enough that
/// each bar is still a usable width on a phone.
pub const BUCKETS: usize = 96;
pub const BUCKET_MINUTES: u64 = 30;

/// One service's availability.
pub struct Status {
    started: OnceLock<Instant>,
    file: OnceLock<PathBuf>,
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
        }
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

        let mut seen = self.recorded();
        if seen.last() == Some(&now) {
            return;
        }
        seen.push(now);
        seen.sort_unstable();
        seen.dedup();
        let keep = seen.len().saturating_sub(BUCKETS * 2);
        let text = seen[keep..]
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join("\n");

        // Written whole and renamed, so a service killed mid-write leaves the
        // previous file rather than half of a new one.
        let temp = path.with_extension("tmp");
        if std::fs::write(&temp, text).is_ok() {
            let _ = std::fs::rename(&temp, path);
        }
    }

    fn recorded(&self) -> Vec<u64> {
        self.file
            .get()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .map(|t| t.lines().filter_map(|l| l.trim().parse().ok()).collect())
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
            .copied()
            .unwrap_or_else(|| now.saturating_sub(uptime.as_secs() / (BUCKET_MINUTES * 60)));

        let mut out = String::with_capacity(BUCKETS * 24);
        out.push_str("<div class=\"bars\">");
        for slot in 0..BUCKETS {
            let bucket = now.saturating_sub((BUCKETS - 1 - slot) as u64);

            let class = if bucket == now {
                // In progress. Always drawn, because the page is being rendered
                // so something is running, and always amber, because the bucket
                // has not finished being served.
                //
                // Deriving this from `uptime % bucket != 0` is the obvious
                // version and it is wrong: a service up for under a second has
                // a remainder of zero, so nothing was drawn at all and a
                // running service showed 96 grey bars, which reads as down.
                "part"
            } else if recorded.binary_search(&bucket).is_ok() {
                "up"
            } else if bucket >= known_from {
                // Inside the recorded window with no heartbeat. The only colour
                // here that is a measurement rather than an absence, and the
                // whole reason for keeping a file.
                "down"
            } else {
                "unknown"
            };

            out.push_str("<i class=\"");
            out.push_str(class);
            out.push_str("\"></i>");
        }
        out.push_str("</div>");
        out
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
    "<span><i class=\"up\"></i>served</span>",
    "<span><i class=\"part\"></i>in progress</span>",
    "<span><i class=\"down\"></i>not serving</span>",
    "<span><i class=\"unknown\"></i>no record</span>",
    "</p>"
);

/// The styles the strip needs. Inline, because both pages ship a single
/// document with no fetchable resources and a content security policy that
/// says so.
pub const STYLE: &str = concat!(
    ".status{display:flex;align-items:center;gap:10px;margin:26px 0 12px}",
    ".dot{width:9px;height:9px;border-radius:50%;background:#2ea043;",
    "box-shadow:0 0 0 4px rgba(46,160,67,.16)}",
    ".status b{font-size:.95rem;font-weight:650}",
    ".status span{margin-left:auto;font:600 .64rem ui-monospace,Menlo,monospace;",
    "letter-spacing:.1em;text-transform:uppercase;opacity:.65}",
    ".bars{display:flex;gap:2px;height:34px;align-items:flex-end;margin:0 0 8px}",
    ".bars i{flex:1;border-radius:1px;min-width:2px}",
    ".up{background:#2ea043;height:100%}",
    ".part{background:#d29922;height:78%}",
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

        assert_eq!(count(&strip, "part"), 1, "the bucket in progress");
        assert_eq!(count(&strip, "down"), 0, "no record, so no outage may be drawn");
        assert_eq!(
            count(&strip, "up") + count(&strip, "part") + count(&strip, "unknown"),
            BUCKETS
        );
        assert!(
            strip.ends_with("<i class=\"part\"></i></div>"),
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
            buckets.iter().map(u64::to_string).collect::<Vec<_>>().join("\n"),
        )
        .expect("write");

        let s = Status::new();
        s.started_now();
        s.record_at(path.clone());
        let strip = s.strip();

        assert_eq!(count(&strip, "up"), 12, "the twelve recorded buckets");
        assert_eq!(count(&strip, "down"), 8, "the gap, measured rather than assumed");
        assert_eq!(count(&strip, "part"), 1);
        assert_eq!(
            count(&strip, "up") + count(&strip, "down") + count(&strip, "part")
                + count(&strip, "unknown"),
            BUCKETS
        );

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
        assert_eq!(text.lines().count(), 1, "five beats in one bucket is one line");
        assert_eq!(s.recorded_count(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn uptime_reads_as_a_person_would_say_it() {
        let s = Status::new();
        assert_eq!(s.uptime_text(), "0m", "not started is zero, not a panic");
    }
}
