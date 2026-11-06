# shellcheck shell=bash
# Shared by build-ios.sh and build-android.sh; sourced, not run.
#
# The one gomobile bind both apps use: the olcrtc client (olcrtc/mobile),
# tun2socks (mobile/tunstack), the bonding client (mobile/bond) and the Xray
# engine (package olcos), in one framework because a process can host only
# one Go runtime. The olcOS changes to olcrtc are commits in olcrtc/, so the
# tree is bound as checked out: nothing is patched or copied in for the build.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MOBILE="$ROOT/mobile"
# shellcheck disable=SC2034 # used by the scripts that source this file
BIND_PACKAGES=(
  github.com/openlibrecommunity/olcrtc/mobile
  ./tunstack
  ./bond
  github.com/olcOS/olcos-core/olcos
)
# -trimpath and the ldflags keep host paths and symbols out of the binary;
# -checklinkname=0 is needed by xray-core dependencies that use go:linkname.
# shellcheck disable=SC2034
BIND_FLAGS=(-trimpath -ldflags='-s -w -buildid= -checklinkname=0')

die() { echo "error: $*" >&2; exit 1; }

prepare_gomobile() {
  [ -f "$ROOT/olcrtc/mobile/runtime.go" ] || die "olcrtc/ is incomplete: $ROOT/olcrtc/mobile/runtime.go is missing"
  command -v go >/dev/null 2>&1 || die "Go not found; install the version in mobile/go.mod"
  # gomobile installs into $(go env GOPATH)/bin, which is not on PATH by default.
  local gopath
  gopath="$(go env GOPATH)"
  export PATH="$PATH:$gopath/bin"
  (cd "$MOBILE" && go mod download)
  # The gomobile CLI must match the golang.org/x/mobile version the module
  # binds against, or the generator and the bound runtime drift apart.
  local version
  version="$(cd "$MOBILE" && go list -m -f '{{.Version}}' golang.org/x/mobile)"
  echo "note: gomobile@$version"
  go install "golang.org/x/mobile/cmd/gomobile@$version"
  gomobile init
}
