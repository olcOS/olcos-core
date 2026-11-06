<h1 align="center">olcos-core</h1>

<p align="center">
  The shared core of the olcOS apps for iPhone and Android: the olcrtc tunnel, the Go code both apps<br>
  bind with gomobile, and the scripts that set up a server.
</p>

> [!IMPORTANT]
> **Just want to install the app?** This repository only holds the core's source. The ready-made files and a
> step-by-step guide are in the [main olcOS repository](https://github.com/olcOS/olcos) and on the
> [website](https://olcos.github.io/en/#download).

<p align="center">
  <a href="https://olcos.github.io/en/">Website</a> ·
  <a href="https://github.com/olcOS/olcos/blob/main/README.en.md">Guide</a> ·
  <a href="https://github.com/olcOS/olcos-ios">iOS</a> ·
  <a href="https://github.com/olcOS/olcos-android">Android</a> ·
  <a href="README.md">Русский</a>
</p>

## What it is

olcOS gets around mobile internet whitelists: the phone and your server join the same video call (VK Calls, Yandex
Telemost, SaluteJazz, MTS Link, Jitsi) and carry the traffic inside it. Everything that does not depend on a
particular phone lives here. The [iOS](https://github.com/olcOS/olcos-ios) and
[Android](https://github.com/olcOS/olcos-android) apps include this repository as the `olcos-core/` submodule and add
only the user interface and the system VPN glue.

## What is inside

| Folder | Contents |
|---|---|
| `olcrtc/` | the [olcrtc](https://github.com/ghostlane-project/olcrtc) core (Apache-2.0) at the release named in `olcrtc.upstream`, with the olcOS changes on top as separate commits |
| `mobile/` | the gomobile module: tun2socks (`tunstack`), room bonding for the "whole server" mode (`bond`) and the server agent (`agent`) |
| `engine/`, `profile/`, `olcos/` | the engine interface, the `olcrtc://` and `vless://` parsers, the Xray engine |
| `server/` | the olcrtc server setup (`srv.sh`), the one-line installer (`install.sh`), Xray, the agent's scripts and the server's core patch |
| `scripts/` | the iOS and Android builds, patch generation, olcrtc updates, checks |
| `docs/` | [architecture](docs/architecture.md) and [how olcrtc is kept here](docs/olcrtc.md) |

Both apps bind the core in a single gomobile run: two Go frameworks cannot live in one app, each brings its own
runtime. A server builds the same core from olcrtc at the pinned commit plus `server/olcrtc-core.patch`, and the
apps compare the server's core with their own and offer an update when they differ.

## A server in one command

On a fresh Debian, Ubuntu, Fedora or CentOS VPS, as root:

```bash
curl -fsSL https://raw.githubusercontent.com/olcOS/olcos/main/install.sh | sudo bash
```

The command from the main repository downloads `server/install.sh` from here, installs olcrtc and the agent and
prints an invite. Scan it in olcOS and the phone becomes the server's owner. Settings are described at the top of
[server/install.sh](server/install.sh).

## Building

You need the Go version from `mobile/go.mod`.

```bash
git clone https://github.com/olcOS/olcos-core
cd olcos-core
scripts/build-ios.sh          # macOS and Xcode, output: build/Mobile.xcframework
scripts/build-android.sh      # JDK, Android SDK and NDK, output: build/olcoscore.aar
```

The checks CI runs:

```bash
go test ./...                              # engines and profiles
(cd mobile && go test ./...)               # tunstack, bonding, agent
python3 scripts/parity_check.py            # srv.sh keeps up with olcrtc/install.sh
scripts/make-core-patch.sh --check         # the server patch matches olcrtc/
python3 scripts/test_server_scripts.py
python3 scripts/test_xray_server_script.py
```

## Changing and updating olcrtc

Changes to `olcrtc/` are ordinary commits; regenerate the server patch after them. A new olcrtc release comes in with
`scripts/update-olcrtc.sh <tag>`. Details and constraints are in [docs/olcrtc.md](docs/olcrtc.md).

## Bugs and security

Report app bugs in the [main repository's issues](https://github.com/olcOS/olcos/issues); core and server script
bugs can go here too. Do not post connection links, keys or your servers' addresses. Report vulnerabilities
privately, see [SECURITY.md](SECURITY.md).

## License

The olcOS code is under the [MIT license](LICENSE). The `olcrtc/` directory is under Apache-2.0, see
[olcrtc/LICENSE](olcrtc/LICENSE) and [olcrtc/NOTICE](olcrtc/NOTICE). Third-party components are listed in
[NOTICE](NOTICE).
