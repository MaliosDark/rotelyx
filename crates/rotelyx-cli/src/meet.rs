//! Meeting a phone: the mailbox transport, from the command line.
//!
//! # Why this exists
//!
//! `listen` and `connect` speak the direct transport: a code names an
//! endpoint, and whoever holds it dials. The phone does not speak that. It has
//! no listening socket and is asleep most of the time, so everything it does
//! goes through a mailbox, and the code it hands out names a meeting place
//! there, not an endpoint. A bot started with `listen` could be reached by
//! another copy of this program and by nothing anybody actually carries in
//! their pocket. Ten bots were written and tested against each other before
//! anybody noticed that no phone could add one.
//!
//! This is the same loop the desktop runs, [`rotelyx_meeting`], driven from
//! stdin and stdout the way `listen` is, so a bot written for one transport
//! runs on the other with a different flag and nothing else changed.
//!
//! # Which side speaks first
//!
//! A guest reads a code the phone showed and knocks. A host mints a code and
//! waits for the phone to read it. A bot is usually the host: its code goes in
//! a README or on a screen, and whoever wants it in their conversation opens
//! the link. Either way the conversation that comes out is the same, and it is
//! written down beside the identity so the next run carries it on.

use std::sync::{Arc, Mutex};

use anyhow::{bail, Result};
use rotelyx_core::Identity;
use rotelyx_meeting::{chats, Command, Event as Met, Present, Role};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;

use crate::bot::{self, Command as BotCommand, Event, Wire};

/// Where a phone's link points, and what it carries after the `#`.
///
/// The same two strings as `lib/rotelyx/invite_link.dart` in the phone
/// client: the code, and after a `~`, the mailbox it should be met at.
const LINK_PREFIX: &str = "https://rotelyx.com/i#";
const MAILBOX_MARK: char = '~';

/// The mailbox a code names when it names none: Ideoa Labs production, the
/// one the phone client ships with.
pub const DEFAULT_MAILBOX: &str = "wss://m1.telyx.me/mailbox";

pub struct Args {
    /// A code or link, read from the phone. Absent when hosting or resuming.
    pub code: Option<String>,
    pub name: String,
    /// Given on the command line, or taken from the link, or the default.
    pub mailbox: Option<String>,
    pub host: bool,
    pub relay: Option<String>,
    /// Where a call between more than two meets, as the relay publishes it at
    /// `/room`. Absent means this member can be in a call of two and refuses a
    /// group one, which is better than joining a group call only half of it
    /// can hear.
    pub room: Option<String>,
    /// A PNG the others show beside this side's messages.
    pub picture: Option<Vec<u8>>,
    pub wire: Wire,
}

/// The code inside a link, and the mailbox beside it if the link names one.
///
/// A bare code passes through. People paste what they were given.
pub fn read_link(input: &str) -> (String, Option<String>) {
    let text = input.trim();
    let fragment = match text.find('#') {
        Some(at) if text.starts_with("http://") || text.starts_with("https://") => &text[at + 1..],
        _ => text,
    };
    match fragment.split_once(MAILBOX_MARK) {
        Some((code, mailbox)) if !mailbox.is_empty() => {
            (code.to_string(), Some(mailbox.to_string()))
        }
        Some((code, _)) => (code.to_string(), None),
        None => (fragment.to_string(), None),
    }
}

/// A link a phone opens to meet this code at this mailbox.
pub fn link_for(code: &str, mailbox: &str) -> String {
    format!("{LINK_PREFIX}{code}{MAILBOX_MARK}{mailbox}")
}

pub async fn meet(
    identity_path: &std::path::Path,
    identity: Identity,
    passphrase: &str,
    args: Args,
) -> Result<()> {
    let wire = args.wire;
    let key = chats::key(identity_path, passphrase)?;
    let keeping = Some((identity_path.to_path_buf(), key.clone()));

    let (tx, mut rx) = mpsc::unbounded_channel();
    let roster: Arc<Mutex<Vec<Present>>> = Arc::new(Mutex::new(Vec::new()));
    let events = translate(wire, args.name.clone(), roster.clone());
    let reader = tokio::spawn(read_stdin(wire, tx, roster));

    // A conversation already on disk is carried on, with a new meeting place
    // beside it when hosting was asked for: that is how somebody new gets
    // into a conversation that exists, and it is what the phone's "Add
    // someone" does.
    let kept = chats::list(identity_path, &key).into_iter().next();

    let outcome = match (args.code, args.host, kept) {
        (None, host, Some(row)) => {
            aside!(wire, "carrying on with {}", row.label);
            let code = if host {
                let code = rotelyx_wasm::new_meeting_code().map_err(|e| anyhow::anyhow!("{e}"))?;
                let mailbox = args.mailbox.clone().unwrap_or_else(|| DEFAULT_MAILBOX.to_string());
                wire.emit(&Event::Code {
                    code: rotelyx_wasm::pretty_meeting_code(&code),
                    link: link_for(&code, &mailbox),
                });
                Some(code)
            } else {
                None
            };
            rotelyx_meeting::resume(
                identity_path,
                key,
                &row.id,
                identity,
                args.relay,
                args.room.clone(),
                args.picture.clone(),
                code,
                events,
                &mut rx,
            )
            .await
        }

        (None, false, None) => bail!(
            "nothing to carry on: this identity has never met anybody. \
             Give it a code from a phone, or --host to show one"
        ),

        // Mint a code and wait at it. With a conversation already kept, a
        // code given here starts a new one beside it, as the phone would.
        (code, true, _) => {
            let code = match code {
                Some(given) => rotelyx_wasm::read_meeting_code(&read_link(&given).0)
                    .map_err(|e| anyhow::anyhow!("{e}"))?,
                None => rotelyx_wasm::new_meeting_code().map_err(|e| anyhow::anyhow!("{e}"))?,
            };
            let mailbox = args.mailbox.unwrap_or_else(|| DEFAULT_MAILBOX.to_string());
            wire.emit(&Event::Code {
                code: rotelyx_wasm::pretty_meeting_code(&code),
                link: link_for(&code, &mailbox),
            });
            rotelyx_meeting::run(
                &code,
                &args.name,
                &mailbox,
                Role::Host,
                false,
                identity,
                args.relay,
                args.room.clone(),
                keeping,
                args.picture.clone(),
                events,
                &mut rx,
            )
            .await
        }

        // Read the phone's code and knock. A kept conversation is left where
        // it is: a new code is a new conversation.
        (Some(given), false, _) => {
            let (code, in_link) = read_link(&given);
            let code =
                rotelyx_wasm::read_meeting_code(&code).map_err(|e| anyhow::anyhow!("{e}"))?;
            // What the link says wins over the default, and what the command
            // line says wins over the link: somebody who typed a mailbox
            // meant it.
            let mailbox = args
                .mailbox
                .or(in_link)
                .unwrap_or_else(|| DEFAULT_MAILBOX.to_string());
            rotelyx_meeting::run(
                &code,
                &args.name,
                &mailbox,
                Role::Guest,
                false,
                identity,
                args.relay,
                args.room.clone(),
                keeping,
                args.picture.clone(),
                events,
                &mut rx,
            )
            .await
        }
    };

    reader.abort();
    match outcome {
        Ok(()) => {
            wire.emit(&Event::Closed {
                reason: "left the conversation".into(),
            });
            Ok(())
        }
        Err(e) => {
            wire.emit(&Event::Closed {
                reason: format!("{e:#}"),
            });
            Err(e)
        }
    }
}

/// What the conversation says, in the words the bot interface uses.
///
/// The meeting loop reports to a window; a bot reads the same events `listen`
/// prints, so they are the same events here whichever transport a bot is on.
/// Anything that has no counterpart there goes to stderr, where a person can
/// read it and a parser never sees it.
fn translate(
    wire: Wire,
    me: String,
    roster: Arc<Mutex<Vec<Present>>>,
) -> Arc<dyn Fn(Met) + Send + Sync> {
    Arc::new(move |event| match event {
        Met::Connected {
            peer,
            safety_number,
            members,
            epoch,
            ..
        } => {
            wire.emit(&Event::Ready {
                me: me.clone(),
                members,
                epoch,
            });
            wire.emit(&Event::Safety {
                peer,
                number: safety_number,
            });
        }
        Met::Message { text, from } => wire.emit(&Event::message(from, text.as_bytes())),
        Met::GroupChanged {
            members,
            added,
            removed,
            ..
        } => {
            for who in added {
                wire.emit(&Event::Joined { who });
            }
            for who in removed {
                wire.emit(&Event::Left { who });
            }
            wire.emit(&Event::Members { count: members });
        }
        Met::AdditionProposed { by, name } => wire.emit(&Event::Proposed { by, who: name }),
        Met::Refused { why } => wire.emit(&Event::refused(why)),
        Met::Members { members } => {
            wire.emit(&Event::Roster {
                members: members.iter().map(|who| who.label.clone()).collect(),
            });
            wire.emit(&Event::Members {
                count: members.len(),
            });
            *roster.lock().expect("not poisoned") = members;
        }
        Met::Disconnected { reason } => wire.emit(&Event::Closed { reason }),
        Met::Error { text } => wire.emit(&Event::refused(text)),
        Met::CallStarted { kbit, mono } => wire.emit(&Event::CallStarted {
            kbit_per_second: kbit,
            mono,
        }),
        Met::CallEnded {
            sent,
            received,
            queued_ms,
            dropped_ms,
            ..
        } => wire.emit(&Event::CallEnded {
            frames_sent: sent,
            frames_received: received,
            queued_ms,
            dropped_ms,
        }),
        Met::Status { text } => aside!(wire, "{text}"),
        Met::Listening { .. } | Met::CallLevel { .. } => {}
    })
}

/// Stdin, until it ends. A line is an instruction in machine mode and a
/// message in human mode, exactly as on the direct transport.
async fn read_stdin(
    wire: Wire,
    tx: mpsc::UnboundedSender<Command>,
    roster: Arc<Mutex<Vec<Present>>>,
) {
    let mut lines = BufReader::new(tokio::io::stdin()).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let command = match wire {
            Wire::Json => match bot::parse(&line) {
                Ok(BotCommand::Send { text }) => Command::Send { text },
                Ok(BotCommand::Members) => Command::WhoIsHere,
                Ok(BotCommand::Remove { who }) => match removal_key(&roster, &who) {
                    Some(key) => Command::Remove { key },
                    None => {
                        wire.emit(&Event::refused(format!(
                            "nobody in this conversation is {who}; ask for members first"
                        )));
                        continue;
                    }
                },
                Ok(BotCommand::Call) => Command::StartCall,
                Ok(BotCommand::Hangup) => Command::EndCall,
                Ok(BotCommand::Confirm) => Command::Confirm,
                Ok(BotCommand::Dismiss) => Command::Dismiss,
                Ok(BotCommand::Picture { base64 }) => {
                    match data_encoding::BASE64.decode(base64.as_bytes()) {
                        Ok(bytes) => Command::Picture { png: bytes },
                        Err(e) => {
                            wire.emit(&Event::refused(format!("that picture is not base64: {e}")));
                            continue;
                        }
                    }
                }
                Ok(BotCommand::Quit) => break,
                Err(problem) => {
                    wire.emit(&Event::refused(problem));
                    continue;
                }
            },
            Wire::Human => match line.trim() {
                "" => continue,
                "/members" => Command::WhoIsHere,
                "/call" => Command::StartCall,
                "/hangup" => Command::EndCall,
                "/confirm" => Command::Confirm,
                "/dismiss" => Command::Dismiss,
                "/quit" => break,
                text if text.starts_with("/remove ") => {
                    let who = text["/remove ".len()..].trim();
                    match removal_key(&roster, who) {
                        Some(key) => Command::Remove { key },
                        None => {
                            println!("[nobody here is {who}; /members lists them]");
                            continue;
                        }
                    }
                }
                text => Command::Send {
                    text: text.to_string(),
                },
            },
        };
        if tx.send(command).is_err() {
            break;
        }
    }
    // Dropping the sender is how the loop is told to stop.
}

/// The key a member is removed by, from the label the bot knows them as.
///
/// Two members can pick the same label. The first match is taken, which is a
/// bot's problem to know about and the roster event to solve: it lists the
/// keys as well.
fn removal_key(roster: &Mutex<Vec<Present>>, who: &str) -> Option<String> {
    roster
        .lock()
        .expect("not poisoned")
        .iter()
        .find(|p| p.label == who || p.key == who)
        .map(|p| p.key.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_link_a_code_and_a_link_naming_a_mailbox_all_read_the_same_code() {
        let code = "RTLX1ABCDEFGHIJKLMNOPQRSTUVWXYZ234";
        assert_eq!(read_link(code), (code.to_string(), None));
        assert_eq!(
            read_link(&format!("{LINK_PREFIX}{code}")),
            (code.to_string(), None)
        );
        assert_eq!(
            read_link(&format!("{LINK_PREFIX}{code}~wss://m.example/mailbox")),
            (
                code.to_string(),
                Some("wss://m.example/mailbox".to_string())
            )
        );
        // What the phone writes is what this reads back.
        let link = link_for(code, "wss://m.example/mailbox");
        assert_eq!(
            read_link(&link),
            (
                code.to_string(),
                Some("wss://m.example/mailbox".to_string())
            )
        );
    }

    #[test]
    fn a_bare_code_with_a_trailing_mark_and_nothing_after_it_is_still_a_code() {
        assert_eq!(read_link("RTLX1AAAA~"), ("RTLX1AAAA".to_string(), None));
    }
}
