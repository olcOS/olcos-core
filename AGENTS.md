# olcos-core: working rules

Read [README.md](README.md), [docs/architecture.md](docs/architecture.md) and
[docs/olcrtc.md](docs/olcrtc.md) before changing a subsystem. Code and tests
take precedence over comments.

## Repositories

- `olcOS/olcos-core` (this one, public): olcrtc, the gomobile module, the
  engines and the server scripts.
- `olcOS/olcos-ios` and `olcOS/olcos-android` (public): the apps. Each has
  this repository as the `olcos-core/` submodule, pinned to a tag.
- `olcOS/olcos` (public): releases, the user guide, issues and the one-line
  server bootstrap (`install.sh`, which runs `server/install.sh` from a tag
  here).
- The public repositories are the source of truth. Older private `-dev`
  repositories and snapshots are not.

## Commits and releases

- Factual Conventional Commits: `fix(agent): reject an expired invite`. Do not
  attribute commits to an AI, a prompt, a conversation or a user request.
- Follow the owner's authorization for commits, pushes, tags and releases.
- A tag here (`v0.x.y`) is what the apps' submodules and the server bootstrap
  point at. Do not move or delete a published tag.

## Contracts that other code depends on

- `olcrtc/`: upstream at the release in `olcrtc.upstream` plus olcOS commits.
  Modify upstream files, do not add or delete them (only `zz_olcos_*.go`
  files may be added), mark modified files with the `Changed by olcOS` line,
  and run `scripts/make-core-patch.sh` after committing. Keep upstream's
  conventions inside `olcrtc/`. Do not open forks, issues or pull requests
  upstream on the owner's behalf without being asked.
- `server/olcrtc-core.patch` is generated. Its SHA-256 and the upstream commit
  form the core identity the apps compare with a server's; any change to it
  makes the apps offer a core update.
- `server/srv.sh` mirrors `olcrtc/install.sh`. Keep the `boc/eoc olcrtc-ios`
  and rejected blocks intact; `scripts/parity_check.py` enforces them.
- `mobile/go.mod` keeps the module path
  `github.com/openlibrecommunity/olcrtc-ios/gomobile`. The apps upload
  `mobile/agent` and `mobile/bond` to servers and build them there with a
  one-line go.mod naming that path; the binary's version is a hash of that
  go.mod and the sources. Both packages stay standard-library only.
- `server/agent-status/*.sh`, `server/xray/*.sh`, `server/add-carrier.sh` and
  `server/rotate-key.sh` are uploaded by the apps as they are; their output
  formats (`KEY=value` lines) are parsed by both apps.
- One gomobile bind for everything (`scripts/lib-bind.sh`). Keep
  `golang.org/x/mobile` in `mobile/go.mod` on the version `olcrtc/go.mod`
  requires.

## Licenses

Keep [LICENSE](LICENSE) (MIT), [NOTICE](NOTICE), `olcrtc/LICENSE`,
`olcrtc/NOTICE` (Apache-2.0) and `olcrtc/docs/upstream-license-wtfpl.txt`.

## Secrets

Never commit server addresses, SSH keys, connection links, invites, room IDs
or tokens, including in tests, fixtures and docs. Use documentation addresses
(`192.0.2.x`, `example.com`).
