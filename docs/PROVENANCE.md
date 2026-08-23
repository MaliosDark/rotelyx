# Provenance and licences

Rotelyx's transport is **derived from [iroh](https://github.com/n0-computer/iroh)**
and vendored into this repository. No upstream networking package is downloaded.

The lineage is worth stating plainly:

```mermaid
%%{init: {'theme':'base','themeVariables':{
  'primaryColor':'#1B222D','primaryTextColor':'#DFE5EE','primaryBorderColor':'#8B96A8',
  'lineColor':'#8B96A8','fontFamily':'ui-monospace, SFMono-Regular, Menlo, monospace'}}}%%
flowchart LR
    T["<b>Tailscale</b><br/>NAT traversal<br/>BSD-3-Clause"] --> I
    Q["<b>quinn</b><br/>QUIC<br/>MIT / Apache-2.0"] --> N["<b>noq</b><br/>N0's quinn fork"]
    N --> I["<b>iroh</b><br/>N0, INC.<br/>MIT / Apache-2.0"]
    I --> R["<b>Rotelyx</b><br/>Andryu Schittone<br/>AGPL-3.0"]

    style R fill:#33280F,stroke:#E8A33D,color:#E8A33D
    style I fill:#1B222D,stroke:#8B96A8,color:#DFE5EE
    style T fill:#1B222D,stroke:#8B96A8,color:#DFE5EE
    style Q fill:#1B222D,stroke:#8B96A8,color:#DFE5EE
    style N fill:#1B222D,stroke:#8B96A8,color:#DFE5EE
```

**Nobody in this lineage wrote NAT traversal from zero.** Tailscale did the
original work, N0 derived from it, Rotelyx derives from that. Building on it is
the normal case, not the exception.

### The defensible claim

> Rotelyx ships its own transport, derived from iroh and substantially rewritten
> for metadata resistance.

### The indefensible one

> We wrote a transport library from scratch.

Do not make it. Full provenance, licence obligations and the per subsystem
replacement plan are in
[`crates/rotelyx-net/VENDORING.md`](crates/rotelyx-net/VENDORING.md) and
[`crates/rotelyx-net/NOTICE`](crates/rotelyx-net/NOTICE). Those notices are a
licence obligation and must not be removed.

---

## The obligation that comes with the code

Deriving from somebody else's work means their fixes stop arriving. `cargo
update` will never change a line under `crates/net`, so a hole they close stays
open here until a person reads what they did and ports it.

[`docs/UPSTREAM.md`](UPSTREAM.md) is where that reading is recorded, and
`scripts/watch-upstream` and `scripts/audit-dependencies` run weekly to say when
more of it is due. Both are part of the licence's practical cost, not only its
legal one.
