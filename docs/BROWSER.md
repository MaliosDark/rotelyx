# The browser client

What runs in a tab, what it can and cannot do, and the failure modes that
produce no error anywhere.

Split out of [`DEPLOYMENT.md`](DEPLOYMENT.md). The browser client is a different
piece of software from the native one, with a different threat model, and it had
outgrown being an appendix to a deployment guide.

Last updated 17 August 2026.

---

## Building it

`site/chat.html` plus the engine in `site/assets/`, built from `crates/rotelyx-wasm`.

```sh
scripts/build-wasm
```

Needs `rustup target add wasm32-unknown-unknown` and
`cargo install wasm-bindgen-cli --version 0.2.127`. **The CLI version must match
the `wasm-bindgen` crate version exactly**, or the generated glue does not load.
The script checks both before it starts.

**1.5 MB of wasm, 531 KB gzipped. Serve it compressed.**

It used to be 2.35 MB, and the difference is two things that were written down
as optional steps and therefore never run:

| | bytes | gzipped |
|---|---|---|
| default release build | 2,352,899 | 749,195 |
| `wasm` profile plus `--remove-name-section` | **1,510,029** | **531,303** |
| | -35.8% | -29.1% |

The `wasm` profile optimises for size rather than speed. That is the right trade
here and the wrong one natively: this module is downloaded before anything can
happen, often on a phone on a cellular connection, and what it does once loaded
is seal and open messages a person typed. Nobody can perceive how fast a
ChaCha20 runs. Everybody perceives a blank screen.

`--remove-name-section` drops 397 KB of debugging symbol names, 17 percent of
the binary, whose only purpose is readable stack traces. Production traces
become numeric, which for a client holding keys is arguably the better default.

The build is not verified by the test suite. The native tests cover the logic,
not the compilation: open `site/chat.html` and complete a handshake before
deploying.

**Uploads do not take effect on their own.** CWP serves `.html`, `.js` and
`.wasm` with `expires max`, which Cloudflare honours for ten years. A new build
is uploaded and nobody ever asks for it again, so the page keeps running old
code, and a page paired with a stale module fails with `doesn't provide an
export named` and a completely dead screen.

`scripts/stamp-wasm` puts a hash of the wasm into the URLs the page requests, so
each build is a different resource and a stale cache cannot serve half a pair.
`scripts/build-wasm` runs it, which is the point: it was a step to remember and
now it is not. The stamp must go on the **binary** too, passed
explicitly to `init()`: the generated loader resolves the wasm path against
`import.meta.url`, which drops the query string.

That is a workaround. The fix is the `location /rotelyx/` block below, and it
is deployed. **Use `alias`, not `root`.**

It is in [`docs/nginx-site.conf`](nginx-site.conf), beside the relay's, so it
is reviewable rather than living only on one machine:

```nginx
location /rotelyx/ {
    alias /home/OPERATOR/public_html/rotelyx/;   # trailing slash required
    types {
        application/wasm  wasm;
        text/javascript   js;
    }
    add_header Cache-Control "no-cache";
}
```

`root` appends the whole request URI to the path it is given, so
`root .../public_html/rotelyx` turns a request for `/rotelyx/x.js` into a look
in `public_html/rotelyx/rotelyx/`, which does not exist. `alias` replaces the
matched prefix instead. The block was deployed with `root` for six days: every
upload to that directory was ignored, the site served a stale module and then
404ed, and the page went dead in exactly the way the paragraph above predicts.

Two things worth keeping from that. **Recommending an nginx block in a document
is not the same as somebody writing a correct one**, and nothing checked this
one. And the failure was silent in the worst way: `verify-deployment` reported
both files as differing from source, which is also true of a merely old
deployment, so the report read as "behind" when it meant "down". It compares the
page's cache stamp against the served module now, and says so in its own
paragraph.

**`.wasm` must be served as `application/wasm`.** With the wrong type the
browser refuses the streaming compile and falls back to a slower path, with only
a console warning to say why. Check with:

```sh
curl -s -o /dev/null -w '%{content_type}\n' https://rotelyx.com/rotelyx/rotelyx_wasm_bg.wasm
```

If it is not `application/wasm`, add to nginx:

```nginx
	types { application/wasm wasm; }
```


### What the browser build is and is not

The message layer is identical to the native client: the same MLS group, the
same X-Wing hybrid keys, the same padding and rotating tags. What is missing is
the transport. A browser cannot open a UDP socket, so QUIC and hole punching
cannot run, and **every browser message goes through the mailbox**. There is
never a direct path.

Two consequences that do not apply to the native client:

- The mailbox operator always learns that two parties are talking. On a direct
  path nobody does.
- The code is re delivered on every page load, so the operator could serve
  different code to one visitor. Verifying an installed binary once is a
  different guarantee from trusting a server on every visit.

Use it to try Rotelyx and to reach a device that cannot install anything. Do not
use it where a compromised operator is in scope.

### Four things in that flow that fail silently if broken

Each of these is pinned by a test in `rotelyx-mailbox-server`, because none of
them produces a visible error when it goes wrong.

1. **The post-quantum secret must be staged before its commit arrives.** MLS
   looks the pre-shared key up by id and refuses the commit outright. The
   welcome and the ciphertext therefore travel together, ahead of the commit.
2. **Envelopes are routed by tag, not by phase.** The commit is deposited under
   the meeting tag but arrives after the conversation already exists. Deciding
   on "have we joined yet" drops it and leaves one side an epoch behind.
3. **Rendezvous payloads are padded and JSON is not self delimiting.** An MLS
   message ends where it ends; a JSON parser handed trailing NUL bytes fails.
   The padding comes off in `openUnder`, and deliberately not in
   `Session::open`, whose payload must reach MLS exactly as padded.
4. **The tag key is pinned at the epoch both sides share.** Deriving it per
   epoch makes a sender one commit ahead deposit under a tag the recipient
   cannot compute.

### Groups, and why 256

The page holds up to **256 people** in one conversation. Not an MLS limit.
Measured on the deployment machine, up to a thousand:

| Members | Ratchet tree | Padded | Welcome | Commit | Padded |
|---|---|---|---|---|---|
| 2 | 415 B | 1 KiB | 378 B | 830 B | 1 KiB |
| 32 | 6.1 KB | 8 KiB | 378 B | 3.4 KB | 4 KiB |
| 256 | 47 KB | 64 KiB | 378 B | 21.8 KB | 32 KiB |
| 512 | 94 KB | 128 KiB | 378 B | 42.8 KB | 64 KiB |
| 1024 | 188 KB | 256 KiB | 378 B | 85 KB | 128 KiB |

The tree grows about 186 bytes per member and the commit about 83. Both are
TreeKEM and not something a client can avoid. The welcome never grows: it is
encrypted to one joiner.

**The padding ladder used to be the real limit, not the crypto.** It jumped
64 KiB straight to 1 MiB, so a thousand member commit paid twelve times its own
size and a single join cost every member a megabyte. That was paying to hide a
number the operator can approximate anyway: a commit's size is a function of the
member count, and a group message is a run of deposits it can count.

The ladder now doubles from a 1 KiB floor, so nothing pays more than double. A
join at a thousand members costs each member 128 KiB instead of 1 MiB.

The floor did not move, which is the part that matters: every message from a one
word reply to a long paragraph still lands in the same 1 KiB bucket. Above the
floor a length is now known to within a factor of two rather than eight, which
affects files and control traffic and not conversation.

**Membership changes are rare next to messages.** An ordinary text message costs
each member 1 KiB at any group size.

**Every member has their own tag.** A single shared tag would hand every member
every other member's mail, and whichever one acknowledged a message first would
remove it from under the rest. A member's tag is derived from the group's pinned key
and that member's signature key, so everyone computes the same value for a given
recipient and nobody outside can.

**The mailbox does not fan out, and this section used to say it did.** A
request that named every recipient so the server could make the copies was
built, described here as the price of large groups, and removed: it handed the
operator the whole recipient set in one frame, and an audit found that no client
had ever sent one. Both this page and the phone seal per recipient and deposit
each envelope separately, which is what the removed request existed to avoid.

The trade that was claimed for it was real and it was not being paid for
anything: the operator could already reach the same conclusion by watching which
connection listens on which tag, so the request made an existing inference cheap
without buying a group size that anybody was using. What remains of it is
`maxFanout` in a granted tier, which is a width limit and not a request.

**The padding stays on the client.** The server refuses a payload that is not
already a bucket size. A server that padded on the sender's behalf would be
handed the true length, which is the one thing the buckets exist to withhold.

### Three delivery bugs that produced no error at all

Recorded because each cost hours and each looked like something else. All three
share a shape: an envelope that is well formed, signed correctly, and delivered
to a tag nobody is watching.

**One time window, used everywhere.** The client subscribed with one window and
checked arriving envelopes against another, so a message from a device whose
clock had already turned the hour was delivered and then discarded. It looks
asymmetric between two devices, because it depends on whose clock leads. There
is now a single `WINDOW` constant and no second place to change.

**Tags rotate, so subscriptions have to be refreshed.** A client subscribes to a
window of buckets and that set goes stale when the hour turns. Nothing errors;
messages simply stop. A timer re-subscribes once a minute, which is far more
often than an hourly rotation needs and costs only the difference.

**Nobody leaves the meeting place early.** The host must never leave, or people
cannot join later. The guest must not leave until it has applied the
post-quantum commit, which travels under that same tag: a guest that
unsubscribed on the welcome never saw the commit, sat an epoch behind the host,
derived different tags, and lost every message until the refresh timer papered
over it a minute later. That one line was both bugs at once.

### Four things about groups that fail silently

None of these raises an error anywhere. Each is pinned by a test.

1. **The tag key is per epoch, not per conversation.** It comes from the MLS
   exporter. Pinning one value works only while the group never changes: add a
   third member and the founder holds a key from epoch 1 while the newcomer
   derives one at epoch 2. Clients keep the last three epochs and re-derive
   whenever the epoch moves.
2. **A commit is addressed one epoch back.** `invite` merges its own commit, so
   the inviter has already moved on; the members waiting for that commit cannot
   derive the new key, because that commit is what will move them there.
3. **Applying a commit means re-subscribing.** The epoch moved, so the tags
   moved. A client that does not re-subscribe goes quiet while everyone else
   addresses it at the new epoch.
4. **The host stays at the meeting place, guests leave it.** A guest still
   listening there reads knocks meant for the host, and acknowledging one takes
   it away entirely, so the newcomer waits forever with nothing on screen.

### The post-quantum secret has to be chosen, not derived

For two parties, encapsulation is enough: both ends arrive at the same value.
For a group it is useless, because encapsulation *derives* a secret rather than
carrying a chosen one, and MLS looks a pre-shared key up by a single id. A
commit carrying different material per member fails for everyone but one.

So the committer picks one group secret and seals it to each member: X-Wing
protects a wrapping key, XChaCha20-Poly1305 protects the secret. Both halves of
X-Wing still have to break for it to leak. 1192 bytes per recipient, once per
rotation.

### Conversations across a reload

A browser tab holds the MLS group state, and closing it used to end the
conversation permanently: the state cannot be reconstructed from anywhere else,
because forward secrecy means nobody keeps the material to rebuild it.

The page now offers to keep it, sealed under a passphrase, in local storage.

**What that blob is.** The signing key, the hybrid key and the whole MLS group
state. Whoever holds it and the passphrase can read what that member can read.
It is not a backup of messages, it is a copy of the participant. Local storage
is readable by any script that ever runs on the origin and survives long after
the tab closes, which is why nothing goes in it unencrypted.

**Why the key is derived once.** Argon2id at 64 MiB takes about a second, which
is what makes a passphrase worth something. The MLS state changes with every
message, since sending and receiving both turn the ratchet, so a page that
re-derived per save would stall a second per message. The cost is paid at
unlock and the key is held for the life of the tab.

**Discarding is permanent.** There is no server-side copy to fall back on.

### The meeting phrase is not authentication

Two people who have never exchanged a key need somewhere to put the first
message, so both type the same phrase and it becomes one mailbox slot. Nothing
in the handshake needs to be private: a key package is public, a welcome is
encrypted to the joiner's own key, and the hybrid ciphertext is encapsulated to
their public key.

What the phrase does not do is prove who answered. Anyone who learns it before
the intended party arrives can reply in their place, and both sides would finish
a handshake with the attacker. **Comparing the safety number aloud is the only
thing that detects this**, which is why the page shows it before enabling the
composer.

---
