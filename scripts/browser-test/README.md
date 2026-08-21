# Two tabs, one conversation

Drives the deployed browser client through a whole conversation in a real
Chrome: load the page, open one side, join from the other, compare the safety
numbers, confirm them, and send a message each way.

Everything else in this repository tests Rotelyx against itself. This tests the
page a person actually opens, against the mailbox actually deployed, and it
found nothing wrong the first time it ran, which is worth as much as a failure
would have been: before this, nobody had ever opened it.

    scripts/browser-test/run https://rotelyx.ideoa.co/chat.html

Needs `google-chrome` and Python 3. No packages: `cdp.py` speaks enough of the
DevTools protocol to evaluate JavaScript in a page, which is all this needs.

**It deposits real envelopes in whatever mailbox the page points at.** The
rendezvous phrase is random per run, so two runs cannot collide and neither can
a run collide with somebody's conversation. Envelopes expire on the mailbox's
own schedule.

Not in CI. It needs a browser and a deployed site, and a test that fails when
the network is slow is a test people learn to re-run. Run it after deploying.
