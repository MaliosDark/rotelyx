# Rotelyx deployment

What is deployed, where, and why each choice was made. Written so that whoever
picks this up later, including us on a different machine, does not have to
reconstruct it from memory.

Last updated 17 August 2026.

## Two addresses this document does not contain

`RELAY_HOST` and `NGINX_HOST` stand for the operator's own LAN addresses: the
machine running the relay and mailbox, and the machine running nginx in front of
them. Substitute your own.

They are placeholders rather than real values on purpose. The public hostnames
below are in DNS and say nothing a lookup does not already say, but a private
address says which network the operator sits on and how it is laid out, which is
free reconnaissance for anybody who reads a repository. Keep the real values
somewhere that is not committed: `docs/DEPLOYMENT.local.md` is ignored by git for
exactly this.

Two subjects that lived here have moved out, because this file had become the
place anything hard to classify ended up:

| Document | Subject |
|---|---|
| [`ACCESS.md`](ACCESS.md) | Tiers, capability tokens, blind issuance, metering |
| [`BROWSER.md`](BROWSER.md) | The browser client and its failure modes |
| [`THREAT-MODEL.md`](THREAT-MODEL.md) | What Rotelyx defends against, and what it does not |
| [`PQ-COMPOSITION.md`](PQ-COMPOSITION.md) | The post-quantum construction, specified for review |

---

## 1. Hosts and names

| Name | Purpose | Status |
|---|---|---|
| `relay-rotelyx.ideoa.co` | Relay for peers that cannot hole punch | DNS and nginx configured, **backend not yet running** |
| `mail-rotelyx.ideoa.co` | Blind mailbox | **Live and verified**, `101` through the full chain |
| `rotelyx.ideoa.co` | Static site and browser client | Content in `site/`, ready to upload |

### Network layout

```
client ──▶ Cloudflare ──▶ nginx (NGINX_HOST:443) ──▶ relay (RELAY_HOST:3340)
```

nginx and the relay are on **different machines**, which is why the relay binds
`0.0.0.0` rather than loopback.

---

## 2. Cloudflare

The relay sits behind Cloudflare's proxy, and that is the right setup for now.

**What Cloudflare cannot see:** message content. Everything is encrypted twice,
by MLS at the message layer and by TLS at the transport, and Cloudflare holds
neither key.

**What it does:** absorbs floods, hides the origin address, and terminates TLS
so the origin does not pay for handshakes from traffic that gets refused anyway.

**The one thing worth knowing:** Cloudflare observes which addresses connect and
when. That is not a new exposure. A relay learns who talks to whom by
definition, which is ADV-3 in the threat model and the reason path selection
prefers any direct path over any relayed one. Cloudflare sees an IP level
version of what the relay already records.

If the relay ever moves to a rented server rather than a machine at home, the
proxy stops being necessary and can be turned off. There is no reason to do it
before then, and no urgency when it happens.

---

## 3. nginx

CWP generates the server blocks. Only one addition is needed, in **both** the
`:80` and the `:443` block for `relay-rotelyx.ideoa.co`, placed before
`location /`:

```nginx
	location /relay {
		proxy_pass http://RELAY_HOST:3340;

		proxy_http_version 1.1;
		proxy_set_header Upgrade    $http_upgrade;
		proxy_set_header Connection "upgrade";
		proxy_set_header Host       $host;
		proxy_set_header X-Real-IP  $remote_addr;
		proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
		proxy_set_header X-Forwarded-Proto $scheme;

		proxy_read_timeout  7d;
		proxy_send_timeout  7d;
		proxy_buffering off;
		proxy_cache off;
	}

	location = /ping {
		proxy_pass http://RELAY_HOST:3340;
		proxy_set_header Host $host;
		access_log off;
	}
```

The full block, including rate limiting, is in
[`nginx-relay.conf`](nginx-relay.conf).

### Rate limiting, and why not a challenge

The relay's clients are **programs, not browsers**. A captcha needs a human and
a DOM, so hCaptcha and everything like it cannot apply here, self hosted or not.

The real exposure is cheaper to state: the allowlist is consulted **after** the
TLS handshake completes. An unauthorised peer therefore forces the expensive
part before being refused. The relay protocol does expose `accept_conn_limit`
and `accept_conn_burst`, and both are marked *not currently implemented*, so
there is no connection cap inside the relay at all.

nginx terminates TLS in this deployment, which means nginx pays that cost and
nginx is the correct place to cap it. A limit inside the relay would fire after
the expensive work had already happened.

| Layer | What it stops | What it does not |
|---|---|---|
| nginx `limit_conn` / `limit_req` | **Not deployed.** CWP rejected both directives, so they were removed from the live configuration | Nothing now: the relay limits itself, below |
| Relay status page | Availability only, no traffic and no limits. The record is half-hour bucket numbers: no addresses, no identifiers, no counts | Nothing. It publishes what an outside observer could measure by polling |
| Relay admission control | 8 concurrent and 30/minute per identity, 4096 in total, refused without saying why | An attacker willing to generate more than 4096 keypairs, who then meets the total cap |
| Relay `client_rx` | 512 KiB/s per connection | Somebody staying under it |
| Relay allowlist | Any peer not explicitly permitted | The TLS handshake that precedes it |
| Proof of work, if added | Sustained abuse from a permitted peer | A flood, since it runs after TLS |

Proof of work is worth considering for a relay that is **open** rather than
allowlisted. `rotelyx-core::access` already implements a non transferable one,
bound to sender, recipient and hour, and it could gate relay admission the same
way it gates peer reachability. For an allowlisted relay it adds little: an
unauthorised peer is already refused, and cheaply.

### Three things that are easy to get wrong

**`proxy.inc` is deliberately not included in that block.** CWP's shared proxy
file may pin `proxy_http_version 1.0` or rewrite `Connection`, and either breaks
the WebSocket upgrade. The failure mode is that no client connects and nothing
unusual appears in the logs.

**The `:443` block matters more than the `:80` one.** Clients connect over
HTTPS. A setup tested only on port 80 works in testing and fails in production.

**The default 60 second timeout would cut every session.** Relay connections are
long lived, so `proxy_read_timeout` and `proxy_send_timeout` are raised to a
week.

---

## 3a. Neither service survives a reboot

There is no systemd unit for either the relay or the mailbox. They are started
by hand, which means a reboot, an OOM kill or a crash takes the deployment down
until somebody notices, and on 18 August somebody did: all three WebSocket
endpoints were returning 502 while the static site kept returning 200, which is
exactly the shape that makes an outage look like everything is fine.

The mailbox restarts cleanly because it holds nothing:

```sh
rotelyx-mailbox-server --bind 0.0.0.0:3341
```

The relay refused to start for exactly one reason, and it is deliberate rather
than a bug: no `--allow <file>` and no `--open`. It will not fall open because
somebody forgot a flag. `/etc/rotelyx/community.allow` does not exist on this
machine, so it now runs `--open`.

**Open is a decision, and this is what it costs.** Anybody who finds the
hostname can use the relay's bandwidth, and its connection log covers people the
operator has no relationship with. It does **not** cost confidentiality: a relay
forwards ciphertext it cannot read whoever sent it. Closing it is one file and
one flag, and the unit file says how.

**Unit files are the fix**, and they are in `docs/systemd/`.

### Without root, which is what this machine uses

`loginctl show-user $USER --property=Linger` already says `Linger=yes` here,
which means user services keep running after the last session ends. So no root
is needed at all:

```sh
mkdir -p ~/.config/systemd/user
# Four options have to come out for an unprivileged service. See below.
sed -e '/^User=/d' -e 's/^WantedBy=multi-user.target/WantedBy=default.target/' \
    -e '/^PrivateDevices=/d'      -e '/^ProtectKernelTunables=/d' \
    -e '/^ProtectKernelModules=/d' -e '/^ProtectControlGroups=/d' \
    -e 's/^ProtectHome=read-only/ProtectHome=no/' \
    docs/systemd/rotelyx-mailbox.service > ~/.config/systemd/user/rotelyx-mailbox.service
systemctl --user daemon-reload
systemctl --user enable --now rotelyx-mailbox
```

Those four options all drop capabilities, and an unprivileged service may not.
Without removing them the unit fails with `status=218/CAPABILITIES`, which names
the step rather than the option and is not obvious from the message. Everything
else in the unit works unprivileged and is kept.

**Verified rather than assumed**: killing the process with `kill -9` brought it
back in five seconds under a new PID.

If `Linger` is off, `sudo loginctl enable-linger $USER` turns it on, and that is
the only line in this section that needs root.

### With root, for a machine where that is the right shape

```sh
sudo cp docs/systemd/rotelyx-mailbox.service /etc/systemd/system/
sudo cp docs/systemd/rotelyx-relay.service   /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now rotelyx-mailbox rotelyx-relay
```

The system units keep the full hardening: no new privileges, a read-only
system, no device access, no kernel tunables, and only `AF_INET`/`AF_INET6`.

Both restart on any exit including a clean one, because a service that decided
to stop is still a service nobody can reach. Both drop every capability they do
not need: no new privileges, a read-only system, no device access, and only
`AF_INET`/`AF_INET6`.

The relay's unit ships `--open`, which is what this deployment was running,
because no allowlist has ever existed on the machine. **That is a decision, not
a default**, and the unit file says so at the top along with how to close it. An
open relay costs capacity and logs rather than confidentiality: a relay forwards
ciphertext it cannot read either way.

## 3b. The blind mailbox

`rotelyx-mailbox-server` wraps the `rotelyx-mailbox` library in a WebSocket
front end. It holds no key and cannot read anything it stores.

```sh
rotelyx-mailbox-server --bind 0.0.0.0:3341
```

| Route | Purpose |
|---|---|
| `/mailbox` | WebSocket. Deposit and subscribe |
| `/ping` | Health probe. 200 |
| `/` | Landing page, self contained |

**Port 3341, TCP only.** Chosen to sit next to the relay's 3340 without
colliding. Nothing else is opened.

### nginx

Same shape as the relay, different port and path. Add to **both** the `:80` and
`:443` blocks for `mail-rotelyx.ideoa.co`, before `location /`:

```nginx
	location /mailbox {
		limit_conn rotelyx_conn 10;
		limit_req  zone=rotelyx_req burst=20 nodelay;

		proxy_pass http://RELAY_HOST:3341;

		proxy_http_version 1.1;
		proxy_set_header Upgrade    $http_upgrade;
		proxy_set_header Connection "upgrade";
		proxy_set_header Host       $host;
		proxy_set_header X-Real-IP  $remote_addr;

		proxy_read_timeout  7d;
		proxy_send_timeout  7d;
		proxy_buffering off;
		proxy_cache off;
	}

	location = /ping {
		proxy_pass http://RELAY_HOST:3341;
		proxy_set_header Host $host;
		access_log off;
	}
```

The same three traps apply as for the relay: do not include `proxy.inc`, do not
test only on port 80, and do not leave the 60 second timeout in place.

### Firewall

```sh
iptables -A INPUT -p tcp --dport 3341 -s NGINX_HOST -j ACCEPT
iptables -A INPUT -p tcp --dport 3341 -j DROP
```

### The wire protocol

JSON over WebSocket. Deliberately small.

| Direction | Frame |
|---|---|
| Client | `{"op":"subscribe","tags":["<64 hex>", ...]}` |
| Client | `{"op":"deposit","envelope":"<base64>"}` |
| Client | `{"op":"fanout","tags":["<64 hex>", ...],"payload":"<base64>"}` |
| Client | `{"op":"unsubscribe","tags":["<64 hex>", ...]}` |
| Client | `{"op":"auth","token":"<base64url>"}` |
| Server | `{"op":"ready","waiting":N}` |
| Server | `{"op":"envelope","envelope":"<base64>"}` |
| Server | `{"op":"stored"}` |
| Server | `{"op":"fannedout","stored":N,"asked":M}` |
| Server | `{"op":"dropped","listening":N}` |
| Server | `{"op":"tier","tier":"plus","maxFanout":256,...}` |
| Server | `{"op":"overquota","limit":N,"used":M,"tier":"..."}` |
| Server | `{"op":"error","message":"..."}` |

A deposit carries no tag field. The tag is inside the envelope, so there is
nothing for a client to get wrong and nothing for the server to cross check.

### Three behaviours worth knowing before operating it

**Delivery is exactly once.** Collection removes. Two devices polling the same
tag race, and one loses the message. That is a real limit on multi device use,
and it is preferred over a mailbox that keeps copies of what it has delivered.

**A client never receives its own deposit.** Both sides of a conversation share
one tag. Without this rule a sender races its own recipient and, because
collection removes, sometimes wins and the message is simply gone.

**Nothing is persisted.** A restart drops every uncollected envelope. Envelopes
have a TTL of seven days by default, which the store enforces both on a timer
and on collection, so a missed sweep can never serve an expired envelope.

### What the operator can see

| Observable | Visible |
|---|---|
| Contents, length, sender, recipient | No |
| Which tags exist and when they are busy | **Yes** |
| Which tags one connection asks for together | **Yes** |
| Connecting addresses | **Yes** |

The last three are ADV-3 and the reason a native client prefers a direct path.

---

## 4. Running the relay

```sh
rotelyx-relay --bind 0.0.0.0:3340 --allow /etc/rotelyx/community.allow \
    --status ~/.local/state/rotelyx/relay-status
```

`--status` records availability so the landing page can show history. Without
it the strip can only say "up since this process started", so every restart
looks like the beginning of time and an outage is never visible: a relay that is
down serves no page, so the only way it can report having been down is to have
written something beforehand. Under `ProtectSystem=strict` the unit needs a
matching `ReadWritePaths`, or the file is silently unwritable and the strip
quietly has no history.

`community.allow` holds one endpoint id per line. `#` starts a comment. Get an
id with:

```sh
rotelyx-cli --identity alice.key id
```

The relay **refuses to start** without `--allow` or `--open`, and refuses to
start on an empty allowlist rather than falling open. A relay that silently
serves the whole internet is the failure nobody notices, because it works
perfectly.

### Firewall

The relay binds `0.0.0.0` because nginx is on another machine. That exposes port
3340 to the internal network, so restrict it to nginx:

```sh
iptables -A INPUT -p tcp --dport 3340 -s NGINX_HOST -j ACCEPT
iptables -A INPUT -p tcp --dport 3340 -j DROP
```

Without this, anything on the internal network can bypass nginx and talk to the
relay directly.

### What the relay does not open

Only **TCP 3340**. Verified with `ss` against a running instance.

The relay protocol also supports QUIC address discovery on **UDP 7842**, and it
is **disabled** here: the binary passes `quic: None`. That keeps everything
proxyable through nginx's HTTP module, which cannot forward UDP.

The cost is that peers learn their public address by other means, which may
lower the hole punch success rate. If it is enabled later, that UDP port must be
exposed **directly**, bypassing nginx.

---

## 5. Verification

After any nginx change:

```sh
# WebSocket upgrade. Must answer 101 Switching Protocols.
#
# The relay requires its subprotocol identifier and answers 400 without one.
# That is correct behaviour, not a fault: a server that upgraded any WebSocket
# it was offered would accept anything. The mailbox does not require one.
#
# --http1.1 is not optional against a CDN. Without it curl negotiates HTTP/2,
# where this handshake does not exist, and the 400 that comes back looks like a
# broken proxy when nothing is wrong.
curl -i -N --http1.1 \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  -H "Sec-WebSocket-Protocol: rotelyx-relay-v2" \
  https://relay-rotelyx.ideoa.co/relay

# Health. Must answer 200.
curl -s -o /dev/null -w "%{http_code}\n" https://relay-rotelyx.ideoa.co/ping
```

| Response | Meaning |
|---|---|
| `101` | Working |
| `502` | nginx cannot reach the backend. The relay is not running, or the firewall blocks it |
| `200` on `/relay` | The upgrade is not being proxied. Check `proxy_http_version` and the `Upgrade` header |
| `400` | Reached the backend, handshake rejected. Two ordinary causes before suspecting a fault: `curl` negotiated **HTTP/2** with the CDN, where a classic `Upgrade` does not apply, so retry with `--http1.1`; or the **subprotocol header is missing**, which the relay requires and the mailbox does not |

### Verified state, 16 August 2026

| Endpoint | Result |
|---|---|
| `https://relay-rotelyx.ideoa.co/relay` | `101 Switching Protocols` |
| `https://mail-rotelyx.ideoa.co/ping` | `200`, body `ok` |
| `https://mail-rotelyx.ideoa.co/mailbox` | `101 Switching Protocols` |
| `https://rotelyx.ideoa.co/mailbox` | `101 Switching Protocols` |

Both run through Cloudflare, then pfSense doing HAProxy with TLS, then nginx on
`NGINX_HOST`, then the service on `RELAY_HOST`.

**The bind is the thing that breaks this.** Both services must listen on
`0.0.0.0`, not `127.0.0.1`: nginx is on a different machine, and a loopback bind
gives a `502` that looks like the process is down when it is running fine.

---

## 6. Pointing clients at it

Relay selection is explicit in code. There is no default and no discovery:

```rust
let config = NetConfig::new(
    RelayPolicy::SelfHosted(vec!["https://relay-rotelyx.ideoa.co".parse()?]),
    PathPolicy::PreferDirect,
);
```

`PreferDirect` means the relay is used **only** when no direct path exists. Any
direct path beats any relayed path at any latency, which is the point of the
policy.

### The hostname is hard to change later

It is compiled into client configuration. Moving it means every deployed client
stops finding the relay. Pick it once.

---

## 6a. The browser client needs its own Content-Security-Policy

The static site lives outside this repository, and this section exists so that
the one header it cannot do without is written down somewhere that is version
controlled.

Every page except one is static and can be served under a policy that permits
nothing:

```
default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline';
script-src 'unsafe-inline'; base-uri 'self'; form-action 'none';
frame-ancestors 'none'
```

**`chat.html` is not one of those pages, and that policy stops it dead.** It
loads a WebAssembly module from its own origin, instantiates it, and opens a
WebSocket to the mailbox. Under `default-src 'none'` with no `connect-src`,
all four of those are refused and the page renders and then does nothing, with
the reason visible only in the browser console.

That is not a hypothetical: it is how the site was served, and it is why nobody
had seen the browser client work.

Serve `chat.html` with this instead, and nothing wider:

```
default-src 'none'; img-src 'self' data:; style-src 'unsafe-inline';
script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; connect-src 'self';
base-uri 'self'; form-action 'none'; frame-ancestors 'none'
```

| Addition | Why |
|---|---|
| `script-src 'self'` | load `./rotelyx/rotelyx_wasm.js` as a module |
| `script-src 'wasm-unsafe-eval'` | instantiate it. Chrome refuses without this whenever a policy is present at all |
| `connect-src 'self'` | fetch the `.wasm`, and reach `wss://<host>/mailbox`, which is same origin behind the reverse proxy |

Nothing else is widened: no third party origin, and no `unsafe-eval`.

A mailbox address typed into the page by hand is a different origin and stays
blocked. That is deliberate rather than an oversight: a page that can be
pointed at any server is a page that can be told to send somewhere else.

On Apache this belongs in a `<Files "chat.html">` block so the strict policy
still covers everything else. On nginx it is a `location = /chat.html` with its
own `add_header`, remembering that `add_header` in a `location` replaces the
inherited one rather than adding to it.

## What has actually been verified

The module itself is sound, and that was checked rather than assumed: it parses
as a valid module, the 61 symbols the JavaScript calls all exist as exports, the
31 functions the module imports are all defined by the glue, and the cache stamp
in `chat.html` matches the hash of the `.wasm` beside it.

**Nobody has yet opened the page in a browser.** Everything above is static
analysis. It rules out a broken module and it found the header, and it is not a
substitute for loading the page and completing a handshake.

## 7. What is not deployed

| Component | State |
|---|---|
| Mailbox server | **Built and tested, not deployed.** `rotelyx-mailbox-server`, port 3341 |
| Browser client | **Built and tested, not uploaded.** `site/`, 2.6 MB |
| Mailbox persistence | Not implemented. A restart drops every uncollected envelope |
| Push notifications | Not implemented |
| Multi region relays | One region. Add more when there are users to justify them |

---

## 8. Outstanding field test

The reason the relay exists at all is untested. Every test so far runs on
loopback, which needs no hole punching, so NAT traversal has never been
exercised.

Needed:

- [ ] Relay running on a public address
- [ ] Two devices behind **different** NATs
- [ ] Measure how often a direct path is established
- [ ] Measure how often `PreferDirect` costs a connection that `Fastest` would
      have kept

That last measurement is the honest cost of the path policy, and we currently
have no number for it.
