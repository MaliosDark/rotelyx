# Rotelyx deployment

What is deployed, where, and why each choice was made. Written so that whoever
picks this up later, including us on a different machine, does not have to
reconstruct it from memory.

Last updated 16 August 2026.

---

## 1. Hosts and names

| Name | Purpose | Status |
|---|---|---|
| `relay-rotelyx.ideoa.co` | Relay for peers that cannot hole punch | DNS and nginx configured, **backend not yet running** |
| `mail-rotelyx.ideoa.co` | Blind mailbox | Reserved. **No server exists yet**, `rotelyx-mailbox` is a library only |

### Network layout

```
client ──▶ Cloudflare ──▶ nginx (192.168.68.44:443) ──▶ relay (192.168.68.46:3340)
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
		proxy_pass http://192.168.68.46:3340;

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
		proxy_pass http://192.168.68.46:3340;
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
| nginx `limit_conn` / `limit_req` | Connection floods, before the backend is touched | An attacker with many source addresses |
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

## 4. Running the relay

```sh
rotelyx-relay --bind 0.0.0.0:3340 --allow /etc/rotelyx/community.allow
```

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
iptables -A INPUT -p tcp --dport 3340 -s 192.168.68.44 -j ACCEPT
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
curl -i -N \
  -H "Connection: Upgrade" -H "Upgrade: websocket" \
  -H "Sec-WebSocket-Version: 13" \
  -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
  https://relay-rotelyx.ideoa.co/relay

# Health. Must answer 200.
curl -s -o /dev/null -w "%{http_code}\n" https://relay-rotelyx.ideoa.co/ping
```

| Response | Meaning |
|---|---|
| `101` | Working |
| `502` | nginx cannot reach the backend. The relay is not running, or the firewall blocks it |
| `200` on `/relay` | The upgrade is not being proxied. Check `proxy_http_version` and the `Upgrade` header |
| `400` | Reached the relay but the handshake was rejected. Expected from `curl`, which does not complete a real WebSocket handshake |

**Current state, 16 August 2026: `502`.** nginx and TLS are working. The relay
binary has not been deployed to `192.168.68.46` yet.

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

## 7. What is not deployed

| Component | State |
|---|---|
| Mailbox server | Does not exist. `rotelyx-mailbox` is a library: envelopes, buckets, tags, expiry. No binary listens anywhere |
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
