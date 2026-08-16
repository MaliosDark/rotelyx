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

## 2. The Cloudflare problem

> [!CAUTION]
> **The relay is currently behind Cloudflare's proxy, and that defeats the
> reason the relay is self hosted.**

Verified on 16 August 2026: the name resolves to Cloudflare addresses and
responses carry `server: cloudflare` and a `cf-ray` header, so the orange cloud
is on.

### Why it matters here specifically

A relay's whole security position is stated in the threat model as ADV-3:

> A relay learns which endpoint talks to which, and when. That is the social
> graph, it is inherent to relayed transport, and no configuration removes it.
> Run your own so that pairing is visible to you rather than to a stranger.

Cloudflare in proxy mode terminates TLS. It therefore observes which addresses
connect to the relay, when, and for how long. **That is exactly the metadata
self hosting exists to keep within the operator's control.**

It does **not** see message content. Content is encrypted twice over, by MLS at
the message layer and by QUIC and TLS at the transport, and Cloudflare holds
neither key. The exposure is metadata, not messages.

### What to do

Set the DNS record for `relay-rotelyx.ideoa.co` to **DNS only**, the grey cloud,
so traffic reaches the origin directly.

**What is given up by doing that:**

- DDoS absorption. A relay is a plausible target, and without Cloudflare the
  origin takes the traffic
- Origin IP concealment. The server's real address becomes public

**Why it is still the right call for this service:** both of those protect
availability, and the threat model ranks availability last on purpose. A denial
of service is recoverable. A social graph disclosed to a third party is not.

If DDoS protection is needed later, the honest options are a provider that does
not terminate TLS, or absorbing it at the origin. Not Cloudflare in proxy mode.

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
