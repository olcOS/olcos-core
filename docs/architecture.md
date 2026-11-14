# Architecture

olcos-core is the part of olcOS that does not depend on the phone: the tunnel
cores, the server scripts and the Go code that both apps bind with gomobile.
The iOS and Android apps keep only the user interface and the platform glue
(Network Extension on iOS, `VpnService` on Android).

```
┌──────────────────────────────────────────────────────────────────┐
│ UI             SwiftUI (olcos-ios)      │  Jetpack Compose        │
│                                         │  (olcos-android)        │
├──────────────────────────────────────────────────────────────────┤
│ Platform       NEPacketTunnelProvider   │  VpnService             │
│ adapter        (tun fd, routes, protect, notifications)           │
├──────────────────────────────────────────────────────────────────┤
│ olcos-core     one gomobile bind, one Go runtime per process:     │
│ (this repo)      olcrtc/mobile   the olcrtc client                │
│                  mobile/tunstack tun2socks (Outline SDK)          │
│                  mobile/bond     the "whole server" bonding client│
│                  olcos           engine interface, Xray engine    │
├──────────────────────────────────────────────────────────────────┤
│ Server         server/srv.sh     olcrtc server in Podman          │
│                server/xray       Xray VLESS + REALITY in Podman   │
│                mobile/agent      the server agent the apps talk to│
│                mobile/bond       the server half of bonding       │
├──────────────────────────────────────────────────────────────────┤
│ Profiles       olcrtc://, vless://, subscriptions                 │
└──────────────────────────────────────────────────────────────────┘
```

## One bind, one runtime

Two gomobile frameworks cannot be linked into one binary: each carries its own
Go runtime and the symbols collide. So every Go package an app needs comes out
of a single `gomobile bind` run from `mobile/`:

```
github.com/openlibrecommunity/olcrtc/mobile   (olcrtc/mobile)
./tunstack ./bond                             (mobile/)
github.com/olcOS/olcos-core/olcos             (this module)
```

`scripts/build-ios.sh` and `scripts/build-android.sh` run that bind with the
same flags the release builds use. `mobile/go.mod` resolves the two local
modules with `replace` directives, so a checkout of this repository is all a
build needs.

## olcrtc

`olcrtc/` is [ghostlane-project/olcrtc](https://github.com/ghostlane-project/olcrtc)
(Apache-2.0) at the release named in `olcrtc.upstream`, plus the olcOS changes
as ordinary commits on top. `docs/olcrtc.md` explains how the tree is kept and
updated. The Go module path stays `github.com/openlibrecommunity/olcrtc`, the
one upstream uses.

The servers build the same core: `server/srv.sh` clones upstream at the pinned
commit and applies `server/olcrtc-core.patch`, which is generated from the
commits in `olcrtc/` (`scripts/make-core-patch.sh`). The apps compare the
server's pin and patch hash with their own and offer an update when they
differ.

## Engine interface

`engine/` defines a small internal interface (not bound directly):

```go
type Engine interface {
    Kind() Kind                                 // "olcrtc" | "xray"
    Start(ctx context.Context, p Profile, h Host) (Session, error)
}
```

`Host` is what the platform implements (tun fd, protect, log, notify).
`Session` exposes the local SOCKS address or tun ownership, traffic counters
and health events whose reasons match the apps' `HealthReason` values.

The bound surface lives in package `olcos`: flat functions and one JSON
channel, `Runtime.Invoke(method, jsonIn string) string`, the same approach as
libXray and Outline. gobind does not carry slices of structs or generics, and a
panic across the language boundary kills the process, so richer types stay on
the Go side.

## Memory budget

An iOS packet tunnel extension is killed at about 50 MiB. Go has to stay well
under that: `TuneForNetworkExtension` sets a soft memory limit with aggressive
GC, and the apps call it before starting a tunnel. Only one engine runs at a
time; both share the process limit.

The Xray JSON loader links the config package of every protocol, whatever
`engine/xray/distro.go` registers. A smaller Xray engine would have to build
the protobuf config directly instead of loading JSON.

## Xray: two ways to feed the tunnel

| Variant | How | Notes |
|---|---|---|
| A. native `tun` inbound | the tun fd goes to Xray through `XRAY_TUN_FD`, gVisor stack | one component, UDP; memory on iOS not measured yet |
| B. SOCKS inbound + tun2socks | Xray listens on 127.0.0.1, `mobile/tunstack` feeds it | reuses the olcrtc path; TCP only |

The apps use variant B today.

## Name lookups in VPN mode

`mobile/tunstack` carries TCP, and a name lookup leaves the phone over UDP. So
tunstack answers the lookup itself (`names.go`): it asks a resolver through
the session and hands the reply back as the UDP answer the system waits for.
Resolvers are asked in this order:

1. over HTTPS, the operator of the DNS address from the app's settings, when
   that address is Cloudflare's, Google's, Quad9's or Yandex's; any other
   address is asked first as it is, over TCP;
2. over HTTPS, Cloudflare and then Google;
3. over TCP port 53, `8.8.8.8`, `9.9.9.9` and the address from the settings.

The next resolver is asked as well when the one before fails, refuses or stays
silent for a second and a half, and one that failed is asked last for a while.
Over HTTPS the server sees a connection to the resolver, the certificate is
checked on the phone, and the names stay unread; over TCP the server can read
them. A lookup for IPv6 addresses gets an empty answer at once, because the
tunnel carries IPv4 only. Other UDP is dropped.

It was different before: the lookup was answered "truncated" and the system
repeated it over TCP to the address from the settings. A server that does not
reach that one address left the phone without names while the session carried
traffic. `Tunnel.CheckNames` asks through the same resolvers, so the apps'
session watch does not take such a server for a dead session.

## Xray server

`server/xray/install.sh` installs VLESS + REALITY + XTLS-Vision in Podman from
the official `ghcr.io/xtls/xray-core` image at a pinned tag. Keys come from
one-shot containers and are parsed by label. The REALITY target has to pass
`xray tls ping` from the server itself (TLS 1.3, H2, a certificate under the
REALITY record limit) and must not be a host that the censor or Xray itself
treats specially. One deployment per host: an existing one is adopted, not
duplicated.

Field defaults follow what is known about DPI in Russia: a reset right after
the ClientHello is what unwanted TLS gets, so the engine reports it as the
camouflage being detected rather than as a network error.

## References

- gobind type rules: <https://pkg.go.dev/golang.org/x/mobile/cmd/gobind>
- libXray (JSON `Invoke`, iOS memory policy): <https://github.com/XTLS/libXray>
- sing-box libbox platform interface: <https://github.com/SagerNet/sing-box/tree/main/experimental/libbox>
- Outline method channel: <https://github.com/OutlineFoundation/outline-apps/blob/master/client/go/outline/method_channel.go>
- Xray tun inbound: <https://github.com/XTLS/Xray-core/blob/main/proxy/tun/README.md>
- Xray REALITY: <https://xtls.github.io/en/config/transports/reality.html>
