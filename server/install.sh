#!/bin/bash
# olcOS server installer: one command on a fresh VPS (Debian, Ubuntu, Fedora,
# CentOS; root). It installs the olcrtc server (Jitsi / data channel unless
# told otherwise), the olcOS agent, and prints a device invite with full
# management: scan it with olcOS on any phone — that phone becomes the owner
# and manages everything else from the app (rooms, protocols, invites for the
# family, the core update).
#
#   curl -fsSL https://raw.githubusercontent.com/olcOS/olcos/main/install.sh | sudo bash
#
# Settings (environment variables, all optional):
#   OLCOS_NAME       the server's name on the phone (default: the hostname)
#   OLCOS_HOST       the public address the phone reaches (default: detected)
#   OLCOS_CARRIER    jitsi (default), telemost, vkcalls, salutejazz, mtslink …
#   OLCOS_TRANSPORT  datachannel (default), vp8channel, seichannel …
#   OLCOS_ROOM       the room (empty: a random Jitsi room is made)
#   OLCOS_JITSI_URL  the Jitsi server for a Jitsi room
#   OLCOS_DNS        the resolver the server uses (default 1.1.1.1:53)
#   OLCOS_SOURCE     where the pieces are fetched from: a raw olcOS/olcos-core tree
#                    (default: main; the bootstrap in olcOS/olcos pins a release tag)
#
# Everything the phones later do goes through the agent; SSH is only used by
# this script, once. The script can be run again: an installed server is kept
# and only a new invite is printed.
set -euo pipefail

SOURCE="${OLCOS_SOURCE:-https://raw.githubusercontent.com/olcOS/olcos-core/main}"
WORK=/opt/olcos-install
AGENT_DIR=/opt/olcos-agent
SHARE_DIR=/opt/olcos-share
SHARE_CONTAINER=olcos-share
SHARE_IMAGE=docker.io/library/busybox:1.37.0
GO_IMAGE=docker.io/library/golang:1.26-alpine3.22
AGENT_SOURCES="config.go auth.go camouflage.go certs.go state.go server.go install.go invites.go share.go usage.go configlock_unix.go configlock_windows.go cmd/olcos-agent/main.go"

say() { printf '\n[olcOS] %s\n' "$*"; }
die() { printf '\n[olcOS] ERROR: %s\n' "$*" >&2; printf '[olcOS] log: %s\n' "$WORK/install.log" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root: curl -fsSL … | sudo bash"
mkdir -p "$WORK" && chmod 700 "$WORK"
exec > >(tee -a "$WORK/install.log") 2>&1

pkg_install() {
    if command -v apt-get >/dev/null 2>&1; then DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null 2>&1 || true
    elif command -v dnf >/dev/null 2>&1; then dnf install -y -q "$@" >/dev/null 2>&1 || true
    elif command -v yum >/dev/null 2>&1; then yum install -y -q "$@" >/dev/null 2>&1 || true
    fi
}
command -v curl >/dev/null 2>&1 || { say "installing curl"; command -v apt-get >/dev/null 2>&1 && apt-get update -qq >/dev/null 2>&1 || true; pkg_install curl; }
command -v curl >/dev/null 2>&1 || die "curl is needed"

fetch() { curl -fsSL "$SOURCE/$1" -o "$2" || die "could not fetch $1 from $SOURCE"; }

# --- what the phone reaches ---------------------------------------------------
NAME="${OLCOS_NAME:-$(hostname -s 2>/dev/null || hostname)}"
HOST="${OLCOS_HOST:-}"
if [ -z "$HOST" ]; then
    HOST=$(curl -4 -fsS --max-time 8 https://api.ipify.org 2>/dev/null || curl -4 -fsS --max-time 8 https://ifconfig.me 2>/dev/null || true)
    [ -n "$HOST" ] || HOST=$(hostname -I 2>/dev/null | awk '{print $1}')
fi
[ -n "$HOST" ] || die "the server's public address could not be found: run again with OLCOS_HOST=<address>"
say "server: $NAME at $HOST"

# --- the olcrtc server -------------------------------------------------------
EXISTING=$(podman ps -a --format '{{.Names}}' 2>/dev/null | grep -E '^olcrtc-server-[a-z0-9]+$' | head -n 1 || true)
if [ -n "$EXISTING" ] && [ -s "$WORK/uri.txt" ] && [ "${OLCOS_REINSTALL:-0}" != "1" ]; then
    CONTAINER="$EXISTING"
    URI=$(cat "$WORK/uri.txt")
    say "the server is already installed ($CONTAINER): keeping it"
else
    say "fetching the server script"
    fetch server/srv.sh "$WORK/srv.sh"
    chmod +x "$WORK/srv.sh"
    # The core the apps are built from: the upstream commit olcrtc/ is based
    # on plus the olcOS patch series. A server on another commit, or without
    # the series, fails every tunnel right after the handshake.
    fetch olcrtc.upstream "$WORK/olcrtc.upstream"
    PIN=$(sed -n 's/^OLCRTC_COMMIT=\([0-9a-f]\{40\}\)$/\1/p' "$WORK/olcrtc.upstream" | head -n 1)
    [ -n "$PIN" ] || die "the core pin was not found in $SOURCE/olcrtc.upstream"
    fetch server/olcrtc-core.patch "$WORK/olcrtc-core.patch"
    PATCH_ID=$(sha256sum "$WORK/olcrtc-core.patch" | cut -d' ' -f1)
    say "installing the olcrtc server (this takes 5-15 minutes: podman and a Go build)"
    set +e
    env OLCRTC_CARRIER="${OLCOS_CARRIER:-jitsi}" OLCRTC_TRANSPORT="${OLCOS_TRANSPORT:-datachannel}" \
        OLCRTC_ROOM_ID="${OLCOS_ROOM:-}" ${OLCOS_JITSI_URL:+OLCRTC_JITSI_URL="$OLCOS_JITSI_URL"} \
        OLCRTC_DNS="${OLCOS_DNS:-1.1.1.1:53}" OLCRTC_CONFIG_NAME=olcos-installer OLCRTC_PIN="$PIN" \
        OLCRTC_CORE_PATCH="$WORK/olcrtc-core.patch" OLCRTC_CORE_PATCH_ID="$PATCH_ID" \
        bash "$WORK/srv.sh" > "$WORK/srv.log" 2>&1
    RC=$?
    set -e
    tail -n 40 "$WORK/srv.log"
    [ "$RC" -eq 0 ] || die "the server install failed (see $WORK/srv.log)"
    URI=$(sed -n 's/^OLCRTC_URI=//p' "$WORK/srv.log" | tail -n 1 | tr -d '\r')
    CONTAINER=$(sed -n 's/^OLCRTC_CONTAINER=//p' "$WORK/srv.log" | tail -n 1 | tr -d '\r')
    [ -n "$URI" ] || die "the server printed no connection link (see $WORK/srv.log)"
    [ -n "$CONTAINER" ] || CONTAINER=$(podman ps -a --format '{{.Names}}' | grep -E '^olcrtc-server-[a-z0-9]+$' | head -n 1)
    printf '%s\n' "$URI" > "$WORK/uri.txt"; chmod 600 "$WORK/uri.txt"
    say "server container: $CONTAINER"
fi

# --- the agent ---------------------------------------------------------------
say "building the olcOS agent"
mkdir -p "$AGENT_DIR/src/agent/cmd/olcos-agent" "$AGENT_DIR/cache" && chmod 700 "$AGENT_DIR"
printf 'module github.com/openlibrecommunity/olcrtc-ios/gomobile\n\ngo 1.22\n' > "$AGENT_DIR/src/go.mod"
for f in $AGENT_SOURCES; do fetch "mobile/agent/$f" "$AGENT_DIR/src/agent/$f"; done
# shellcheck disable=SC2046 # the file list is meant to split
VERSION=$(cat "$AGENT_DIR/src/go.mod" $(for f in $AGENT_SOURCES; do printf '%s ' "$AGENT_DIR/src/agent/$f"; done) | sha256sum | cut -c1-8)
if [ ! -x "$AGENT_DIR/olcos-agent" ] || [ "$(cat "$AGENT_DIR/version" 2>/dev/null)" != "$VERSION" ]; then
    podman image exists "$GO_IMAGE" 2>/dev/null || podman pull -q "$GO_IMAGE" >/dev/null
    podman run --rm --name olcos-agent-build --network none -v "$AGENT_DIR:/work:Z" -w /work/src \
        -e GOCACHE=/work/cache -e CGO_ENABLED=0 -e GOTOOLCHAIN=local "$GO_IMAGE" \
        go build -trimpath -o /work/olcos-agent.new ./agent/cmd/olcos-agent > "$WORK/agent-build.log" 2>&1 \
        || die "the agent did not build (see $WORK/agent-build.log)"
    mv -f "$AGENT_DIR/olcos-agent.new" "$AGENT_DIR/olcos-agent"
    printf '%s\n' "$VERSION" > "$AGENT_DIR/version"
fi
if [ ! -s "$AGENT_DIR/config.json" ]; then
    # No owner yet: the invite below makes the first phone the owner.
    "$AGENT_DIR/olcos-agent" init -dir "$AGENT_DIR" -port 0 -host "$HOST" > "$WORK/agent-init.txt" || die "the agent could not be initialised"
fi
AGENT_PORT=$("$AGENT_DIR/olcos-agent" show -dir "$AGENT_DIR" | sed -n 's/^OLCOS_AGENT_PORT=//p' | head -n 1)
[ -n "$AGENT_PORT" ] || die "the agent has no port"
# The status scripts the phones read (the same ones the apps install).
mkdir -p "$WORK/status"
for s in readiness carriers xray; do
    fetch "server/agent-status/$s.sh" "$WORK/status/$s.sh"
    sed -i "s/__BASE__/$CONTAINER/g" "$WORK/status/$s.sh"
    "$AGENT_DIR/olcos-agent" set-script -dir "$AGENT_DIR" -name "$s" -file "$WORK/status/$s.sh" >/dev/null
done
cat > /etc/systemd/system/olcos-agent.service <<UNIT
[Unit]
Description=olcOS server agent
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
ExecStart=$AGENT_DIR/olcos-agent serve -dir $AGENT_DIR
Restart=always
RestartSec=2
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable olcos-agent >/dev/null 2>&1 || true
systemctl restart olcos-agent || die "the agent service did not start"
say "agent listening on port $AGENT_PORT"

# --- the invite --------------------------------------------------------------
SHARE_PORT=""
if podman container exists "$SHARE_CONTAINER" 2>/dev/null; then
    podman start "$SHARE_CONTAINER" >/dev/null 2>&1 || true
    SHARE_PORT=$(podman port "$SHARE_CONTAINER" 8080/tcp 2>/dev/null | head -n 1 | sed 's/.*://')
fi
mkdir -p "$SHARE_DIR" && chmod 755 "$SHARE_DIR"
[ -f "$SHARE_DIR/index.html" ] || : > "$SHARE_DIR/index.html"
if [ -z "$SHARE_PORT" ]; then
    podman image exists "$SHARE_IMAGE" 2>/dev/null || podman pull -q "$SHARE_IMAGE" >/dev/null
    for _ in 1 2 3; do
        SHARE_PORT=$(( 20000 + RANDOM % 40000 ))
        if podman run -d --name "$SHARE_CONTAINER" --restart=always -p "$SHARE_PORT:8080" -v "$SHARE_DIR:/www:ro,Z" "$SHARE_IMAGE" httpd -f -p 8080 -h /www >/dev/null 2>"$WORK/share.err"; then
            break
        fi
        SHARE_PORT=""
        podman rm -f "$SHARE_CONTAINER" >/dev/null 2>&1 || true
    done
    [ -n "$SHARE_PORT" ] || die "the share server did not start (see $WORK/share.err)"
fi
LINK=$("$AGENT_DIR/olcos-agent" share -dir "$AGENT_DIR" -name "$NAME" -host "$HOST" -share-port "$SHARE_PORT" -share-dir "$SHARE_DIR" -role owner -uri "$URI" | sed -n 's/^OLCOS_INVITE_LINK=//p')
[ -n "$LINK" ] || die "the invite could not be made"
printf '%s\n' "$LINK" > "$WORK/invite.txt"; chmod 600 "$WORK/invite.txt"

# Open the two ports where a host firewall is on; a cloud firewall must be
# opened by hand (the note below).
for p in "$AGENT_PORT" "$SHARE_PORT"; do
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -qi active; then ufw allow "$p"/tcp >/dev/null 2>&1 || true; fi
    if command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then firewall-cmd --add-port="$p"/tcp >/dev/null 2>&1 || true; firewall-cmd --permanent --add-port="$p"/tcp >/dev/null 2>&1 || true; fi
done

command -v qrencode >/dev/null 2>&1 || pkg_install qrencode
printf '\n\n'
if command -v qrencode >/dev/null 2>&1; then qrencode -t ANSIUTF8 -m 2 "$LINK"; fi
cat <<MSG

================================================================================
  olcOS: сервер готов / the server is ready

  Ссылка-приглашение (полное управление) / invite link (full management):
  $LINK

  Отсканируйте QR или вставьте ссылку в olcOS на телефоне. Этот телефон станет
  владельцем сервера: комнаты, протоколы, приглашения для семьи, обновление ядра
  делаются из приложения. Ссылка одноразовая, она в $WORK/invite.txt.

  Scan the QR code or paste the link into olcOS on the phone. That phone becomes
  the server's owner: rooms, protocols, invites for the family and the core
  update are done from the app. The link is one-time; a copy is in $WORK/invite.txt.

  Откройте порты TCP $AGENT_PORT и $SHARE_PORT во внешнем файрволе (панель хостера),
  если он есть. / Open TCP ports $AGENT_PORT and $SHARE_PORT in the provider's firewall, if any.
================================================================================
MSG
