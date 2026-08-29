# Artifact hashes

The SHA-256 of everything that ships, so that what a server hands you can
be checked against the source it claims to come from.

The builds are reproducible: `scripts/build-wasm` and
`scripts/build-release` on this source produce these bytes exactly. That
was not true until the build paths were remapped, and it is the property
that makes this file mean something rather than decorate.

**Read this from git, not from a web page.** A hash served by the same
origin as the file it describes proves nothing: whoever can replace one
can replace the other. This travels with the source, which is a channel
the server does not control.

| Artifact | SHA-256 | Bytes |
|---|---|---|
| `rotelyx_wasm_bg.wasm` | `2b67f4b6e74999c276c5c24268d9158f5de7ca99ca722728e46f2b7ef23a1986` | 1588741 |
| `rotelyx_wasm.js` | `d2841379a5ca06723aa0befa6f013f32654a5a16a0e938777022f422d513e6bd` | 90101 |
| `rotelyx-relay` | `cac1489b7df63f538d96b55c4b65de94cd47d1d5744725671161178bf92f03b7` | 13088256 |
| `rotelyx-mailbox-server` | `0f36c95c985cc0dee1b6166255fb1ba8c9998aa594da08440bf2cba359a1ef5d` | 10150048 |

To check a running deployment, in one command:

```sh
scripts/verify-deployment https://rotelyx.com
```

It fetches what the server is serving and compares against the table
above. It exits non-zero when they differ, which is either an older
build or somebody having changed it. It says nothing about what a
browser was handed: a page can only run what the server sent it, so
the check has to come from outside.

By hand:

```sh
curl -s https://rotelyx.com/rotelyx/rotelyx_wasm_bg.wasm | sha256sum
```

To check that this file is honest, build it yourself:

```sh
scripts/build-wasm && scripts/build-release && scripts/artifact-hashes --check
```
