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
| `rotelyx_wasm_bg.wasm` | `9a71d8877f3db90df24de2018c83ad9e2fb3518ccc9b9723d5b9344d606a34c0` | 1515508 |
| `rotelyx_wasm.js` | `66994f4e8f30ff8590a0936e1c22ca4190c498f4408aa58e055969f63995b3af` | 75850 |
| `rotelyx-relay` | `3210ec97ba09e00394155b877d34036a9f6ef1efb977fbec49da7f509d9ad4cb` | 8958312 |
| `rotelyx-mailbox-server` | `92c48481a0b8821de909b9b169482704d230052901a8cb00644ee866c314b6cb` | 9939208 |

To check a running deployment, in one command:

```sh
scripts/verify-deployment https://rotelyx.com
```

It fetches what the server is serving and compares. It exits non-zero when they
differ, which is either an older build or somebody having changed it, and it
says nothing about what a browser was handed: a page can only run what the
server sent it, so the check has to come from outside.

By hand:

```sh
curl -s https://rotelyx.com/rotelyx/rotelyx_wasm_bg.wasm | sha256sum
```

To check that this file is honest, build it yourself:

```sh
scripts/build-wasm && scripts/build-release && scripts/artifact-hashes --check
```
