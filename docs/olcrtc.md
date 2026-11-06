# olcrtc in this repository

`olcrtc/` holds the tunnel core both apps and every olcOS server run. It is
[ghostlane-project/olcrtc](https://github.com/ghostlane-project/olcrtc), the
maintained continuation of the archived `openlibrecommunity/olcrtc`, taken at
a release and kept with `git subtree --squash`. The olcOS changes sit on top
as ordinary commits, so `git log -- olcrtc` shows exactly what olcOS changed
and why.

| | |
|---|---|
| Upstream | <https://github.com/ghostlane-project/olcrtc> |
| Release | `v0.14.0`, commit `0955ba7f2041d1480524292c4af4135a192fe267` (see `olcrtc.upstream`) |
| License | Apache-2.0 (`olcrtc/LICENSE`, `olcrtc/NOTICE`); the original WTFPL text is kept in `olcrtc/docs/upstream-license-wtfpl.txt` |
| Go module path | `github.com/openlibrecommunity/olcrtc`, as upstream |

## What olcOS changes

- Telemost (goolom) forwards a VP8 stream reliably only as frames of one RTP
  packet. The engine reports that (`engine.SinglePacketRelay`) and passes the
  relay's keyframe requests to the transport; on such a relay `vp8channel`
  sizes KCP segments to one packet, sends data as interframes and paces the
  data lane by acknowledged pushes.
- `olcrtc/mobile/zz_olcos_logflags.go` pins the log prefix the apps parse.
- `olcrtc/internal/protect/zz_olcos_ipsec.go` keeps ICE off iOS IPsec tunnels.

Each upstream file olcOS modified starts with a `Changed by olcOS` line.

## How the servers get the same core

A server does not clone this repository. `server/srv.sh` clones upstream at
the commit in `olcrtc.upstream`, applies `server/olcrtc-core.patch` and builds
`cmd/olcrtc`. The patch is generated from the commits here:

```bash
scripts/make-core-patch.sh            # after committing a change in olcrtc/
scripts/make-core-patch.sh --check    # CI: fails when the patch is stale
```

It leaves out `olcrtc/mobile/` and the `zz_olcos_*` files, which only the
phones use. The server records the patch's SHA-256 next to the core, and the
apps compare the upstream commit plus that hash with their own to offer a
core update.

Rules for changes in `olcrtc/`:

- Modify upstream files, do not add or delete them. The server update
  restores tracked files before it applies the patch again, and `git apply`
  refuses to create a file that already exists. Code only the phones need can
  go into a new `zz_olcos_*.go` file, which stays out of the patch.
- Mark a modified file with the `Changed by olcOS` line.
- Keep upstream's conventions inside `olcrtc/` (its `AGENTS.md`), so a change
  can be offered upstream as is.

## Updating to a new upstream release

```bash
scripts/update-olcrtc.sh v0.15.0
```

The script pulls the release with `git subtree pull --squash`, rewrites
`olcrtc.upstream` and the default pin in `server/srv.sh`, regenerates the
patch and runs `scripts/parity_check.py`, which compares `server/srv.sh` with
upstream's `install.sh`. On a merge conflict, resolve it, commit, and run the
script again with `--continue`.

Then, in the same release of the apps, move their core pin to the new commit
(`AppConstants.upstreamCorePin` on iOS, `Maintenance.CORE_PIN` on Android)
and point their `olcos-core` submodule at the new tag.
