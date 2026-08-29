# Reporting a vulnerability

**Do not open a public issue for a security problem.** Send it to
**contact@ideoa.co.uk** instead.

A public issue is a working exploit handed to everybody who reads the
repository, including the people running the relays and mailboxes this project
asks you to trust. That is true even for a report that looks minor: the value of
a finding is decided after it is understood, not before, and it cannot be
un-published afterwards.

## What to send

Whatever you have. A partial report that arrives is worth more than a complete
one that does not, so none of this is a requirement:

- What breaks, and what an attacker gets out of it.
- Where it is: a file and a line, a crate, a URL, or a description of the flow.
- How to reproduce it. A failing test, a script, a packet capture, or the steps.
- Which build you were looking at: a commit hash, or the version string a client
  shows.
- Whether anybody else has been told, and whether you intend to publish.

If you want the report encrypted, say so in a first message with nothing
sensitive in it and we will arrange a key.

## What happens next

- We acknowledge receipt within **three working days**. If you do not hear back
  in that time, assume the mail went astray and send it again.
- We tell you what we think it is, and whether we agree with your assessment,
  within **ten working days**.
- We fix it, and we say publicly what was wrong once a fix is out. The write-up
  names the finder unless you ask us not to.

There is no bug bounty. This is a pre-release project run by a small team and we
would rather be honest about that than imply a payment that does not exist.

## What is in scope

The protocol crates, the relay, the mailbox server, the desktop client, the
phone client, the browser build, and anything this repository publishes as a
binary or ships to a browser.

## What is not a finding

- **That the project has only been audited internally.** It says so on the
  front page and in
  [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md). It is a stated condition, not a
  discovery.
- **Anything listed as unsolved in the threat model**, section by section. A
  global passive adversary correlating flows, a compromised device rendering
  plaintext, statistical disclosure against rotating tags: all three are written
  down as things this design does not defend against. A new attack *within* one
  of those classes may still be worth reporting, and a way to solve one of them
  certainly is.
- **A missing header or a scanner grade** on a static page that serves no
  session and holds no key, unless you can say what an attacker does with it.

## Disclosure

We ask for ninety days before publication, and we will move faster than that
whenever we can. If we go quiet, or if we are still arguing about severity after
ninety days, publish. A deadline that only the reporter honours is not a
deadline, and a project that hides behind one deserves the write-up it gets.
