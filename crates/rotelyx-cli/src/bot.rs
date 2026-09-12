//! Being addressed by a program instead of typed at.
//!
//! A bot on the platforms that made bots popular is a token held by a server
//! that reads the conversation in the clear. There is no way to build that
//! here and no reason to want it: a participant in Rotelyx holds keys, sits in
//! the roster, moves the safety number when it arrives, and can be removed by
//! anybody in the conversation. A bot is a member, not an integration.
//!
//! What was missing was not the capability. `listen` and `connect` already run
//! a full member; they just talked in sentences meant for a person. This is the
//! same session speaking a line of JSON per event and reading a line of JSON
//! per instruction, so a program can be the member without screen-scraping.
//!
//! One rule is load-bearing and is the reason this is a mode rather than a
//! parser bolted onto the human one: **in machine mode, a line that is not a
//! valid instruction is never sent to anybody.** A bot that crashes prints a
//! stack trace to stdout, and a lenient reader would encrypt that stack trace
//! and deliver it to the conversation. Refusal is reported back on stdout and
//! goes no further.

use std::fmt;

use data_encoding::BASE64;
use serde::{Deserialize, Serialize};

/// Who the session is talking to.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Wire {
    /// Somebody at a terminal.
    Human,
    /// A program, one JSON object per line, both ways.
    Json,
}

impl Wire {
    /// Report something that happened, in whichever language this session
    /// speaks.
    pub fn emit(self, event: &Event) {
        match self {
            Wire::Human => println!("{event}"),
            // A serialisation that fails would drop the event silently, which
            // for a membership change is exactly the thing the threat model
            // says must never be silent. Nothing here can fail (no maps with
            // non-string keys, no floats), and if that ever stops being true
            // the bot should hear about it rather than miss a join.
            Wire::Json => match serde_json::to_string(event) {
                Ok(line) => println!("{line}"),
                Err(e) => println!(
                    r#"{{"event":"refused","problem":"an event could not be encoded: {e}"}}"#
                ),
            },
        }
    }
}

/// Something that happened in the conversation.
///
/// Serialised with the variant in an `event` field, so a bot can switch on one
/// key and ignore what it does not know: new variants are added here over time
/// and must not break a reader written before them.
#[derive(Serialize, Debug, PartialEq)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum Event {
    /// The session is up and the group is this large at this epoch.
    Ready { members: usize, epoch: u64 },

    /// The digits that say nobody is in the middle, and the name they belong
    /// to.
    ///
    /// A bot that never checks this is a bot that can be talked to by whoever
    /// answered the address, which is the one thing end to end encryption is
    /// for. Compare it against what you were told out of band, the same way a
    /// person would, and refuse to work if it differs.
    Safety { peer: String, number: String },

    /// Application data from a member.
    ///
    /// `from` is absent for a message MLS could not attribute to a leaf, which
    /// a bot should treat as unattributed rather than as anybody in
    /// particular. `text` is present when the payload is UTF-8 and `base64`
    /// when it is not; exactly one of them is there, so a bot that only
    /// handles text can check for `text` and skip the rest.
    Message {
        #[serde(skip_serializing_if = "Option::is_none")]
        from: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        text: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        base64: Option<String>,
    },

    /// Somebody was added. Named, never counted: see ADV-7.
    Joined { who: String },
    /// Somebody was removed.
    Left { who: String },
    /// The size after a membership change.
    Members { count: usize },

    /// A call is running.
    CallStarted { kbit_per_second: usize, mono: bool },
    /// A call stopped, with what it did.
    CallEnded {
        frames_sent: u64,
        frames_received: u64,
        queued_ms: usize,
        dropped_ms: usize,
    },

    /// An instruction was not carried out, and why. Never fatal.
    Refused { problem: String },
    /// The session is over.
    Closed { reason: String },
}

impl Event {
    /// An event carrying a payload, choosing its own representation.
    pub fn message(from: Option<String>, bytes: &[u8]) -> Event {
        match std::str::from_utf8(bytes) {
            Ok(text) => Event::Message {
                from,
                text: Some(text.to_owned()),
                base64: None,
            },
            Err(_) => Event::Message {
                from,
                text: None,
                base64: Some(BASE64.encode(bytes)),
            },
        }
    }

    /// Shorthand for the refusals, which are all built from a message.
    pub fn refused(problem: impl fmt::Display) -> Event {
        Event::Refused {
            problem: problem.to_string(),
        }
    }
}

/// The same events as sentences.
///
/// Both renderings live here on purpose: a line that a person reads and a line
/// a program parses are the same fact, and keeping them in one place is what
/// stops the two modes from drifting into reporting different things.
impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Ready { .. } => {
                write!(f, "connected: type to send, /call to talk, Ctrl-D to quit")
            }
            Event::Message { text, base64, .. } => match (text, base64) {
                (Some(t), _) => write!(f, "peer: {t}"),
                (None, Some(b)) => write!(f, "peer: [{} bytes, base64] {b}", b.len()),
                (None, None) => write!(f, "peer: []"),
            },
            Event::Safety { peer, number } => write!(f, "[peer {peer}, safety number {number}]"),
            Event::Joined { who } => write!(f, "[joined: {who}]"),
            Event::Left { who } => write!(f, "[left: {who}]"),
            Event::Members { count } => write!(f, "[the group is now {count} members]"),
            Event::CallStarted {
                kbit_per_second,
                mono,
            } => write!(
                f,
                "[call started: {kbit_per_second} kbit/s, microphone is {}]",
                if *mono { "mono" } else { "stereo, averaged" }
            ),
            Event::CallEnded {
                frames_sent,
                frames_received,
                queued_ms,
                dropped_ms,
            } => write!(
                f,
                "[call ended: {frames_sent} sent, {frames_received} received, \
                 {queued_ms} ms queued, {dropped_ms} ms of microphone dropped]"
            ),
            Event::Refused { problem } => write!(f, "[{problem}]"),
            Event::Closed { reason } => write!(f, "[{reason}]"),
        }
    }
}

/// What a program can ask this member to do.
///
/// Unknown fields are rejected rather than ignored, so a bot that misspells
/// `text` is told about it instead of sending nothing and looking delivered.
#[derive(Deserialize, Debug, PartialEq)]
#[serde(tag = "do", rename_all = "snake_case", deny_unknown_fields)]
pub enum Command {
    /// Send application data to the conversation.
    Send { text: String },
    /// Ask for the membership again, unprompted by any change.
    Members,
    /// Leave.
    Quit,
}

/// One line of stdin, in machine mode.
///
/// The error is a sentence for the bot's author, and the caller's only correct
/// response to it is to report it: see the rule at the top of this file.
pub fn parse(line: &str) -> Result<Command, String> {
    serde_json::from_str(line).map_err(|e| format!("not an instruction: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_line_that_is_not_an_instruction_is_refused_rather_than_sent() {
        // The whole reason machine mode is a mode. Every one of these is
        // something a real bot prints to stdout when it goes wrong, and none
        // of them may end up encrypted and delivered to people.
        for line in [
            "hello",
            "Traceback (most recent call last):",
            "{}",
            r#"{"do":"send"}"#,
            r#"{"do":"send","txt":"typo"}"#,
            r#"{"do":"explode"}"#,
            r#"{"do":"send","text":"ok"} trailing"#,
            "",
        ] {
            assert!(parse(line).is_err(), "{line} was accepted");
        }
    }

    #[test]
    fn the_instructions_a_bot_can_give() {
        assert_eq!(
            parse(r#"{"do":"send","text":"hello"}"#).unwrap(),
            Command::Send {
                text: "hello".into()
            }
        );
        assert_eq!(parse(r#"{"do":"members"}"#).unwrap(), Command::Members);
        assert_eq!(parse(r#"{"do":"quit"}"#).unwrap(), Command::Quit);
    }

    #[test]
    fn an_event_names_itself_and_keeps_its_absent_fields_absent() {
        let line = serde_json::to_string(&Event::message(None, b"hi")).unwrap();
        assert_eq!(line, r#"{"event":"message","text":"hi"}"#);

        let line = serde_json::to_string(&Event::message(Some("ab".into()), b"hi")).unwrap();
        assert_eq!(line, r#"{"event":"message","from":"ab","text":"hi"}"#);
    }

    #[test]
    fn a_payload_that_is_not_text_survives_as_bytes() {
        // A bot reading `text` and ignoring the rest must never be handed
        // mangled UTF-8 that looks like text.
        let bytes = [0xff, 0x00, 0x10];
        let Event::Message { text, base64, .. } = Event::message(None, &bytes) else {
            panic!("not a message");
        };
        assert!(text.is_none());
        assert_eq!(BASE64.decode(base64.unwrap().as_bytes()).unwrap(), bytes);
    }

    #[test]
    fn a_membership_change_reaches_both_readers_naming_who() {
        // ADV-7: a change announced as a count only is how a ghost member
        // stays invisible. Neither rendering may lose the name.
        let joined = Event::Joined { who: "4f2a".into() };
        assert!(joined.to_string().contains("4f2a"));
        assert!(serde_json::to_string(&joined).unwrap().contains("4f2a"));
    }

    #[test]
    fn every_event_says_something_in_both_languages() {
        // The two renderings are one fact in two languages, and an event that
        // serialises to nothing useful in either is a change somebody made
        // halfway.
        for event in [
            Event::Ready {
                members: 2,
                epoch: 1,
            },
            Event::message(None, b"x"),
            Event::Safety {
                peer: "a".into(),
                number: "1".into(),
            },
            Event::Joined { who: "a".into() },
            Event::Left { who: "a".into() },
            Event::Members { count: 2 },
            Event::CallStarted {
                kbit_per_second: 19,
                mono: true,
            },
            Event::CallEnded {
                frames_sent: 1,
                frames_received: 2,
                queued_ms: 3,
                dropped_ms: 4,
            },
            Event::refused("no"),
            Event::Closed {
                reason: "bye".into(),
            },
        ] {
            assert!(!event.to_string().is_empty());
            let json = serde_json::to_string(&event).unwrap();
            assert!(json.starts_with(r#"{"event":""#), "{json}");
        }
    }
}
