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
| `rotelyx_wasm_bg.wasm` | `b04f44254ca51370e7f790c4fc6c9eeeeee61e0ab6ff5a1649896c3fc3fae86f` | 1505819 |
| `rotelyx_wasm.js` | `2c6036de61489120c7aaaeccb82a465c099f28cb11ad453f0da6301938e2c803` | 73298 |
| `rotelyx-relay` | `f0d335e73a183f40c5b6556ee9bd92df0ccd9e1942ffdf366989f4a89334a3f7` | 8885216 |
| `rotelyx-mailbox-server` | `9b33a387a19c8dbf6c7b969c27d2a900bf34744f7a9b842ddf08f1ae4e34c1a6` | 3908416 |

To check a running deployment:

```sh
curl -s https://rotelyx.ideoa.co/rotelyx/rotelyx_wasm_bg.wasm | sha256sum
```

To check that this file is honest, build it yourself:

```sh
scripts/build-wasm && scripts/build-release && scripts/artifact-hashes --check
```
