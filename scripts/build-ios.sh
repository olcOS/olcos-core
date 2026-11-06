#!/usr/bin/env bash
# Binds the olcOS Go core for iOS into an xcframework.
#
#   scripts/build-ios.sh [output.xcframework]    (default: build/Mobile.xcframework)
#
# olcos-ios calls this through its scripts/build-framework.sh. Needs macOS
# with Xcode and Go (the version in mobile/go.mod).
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib-bind.sh"

OUT="${1:-$ROOT/build/Mobile.xcframework}"
mkdir -p "$(dirname "$OUT")"
OUT="$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")"

prepare_gomobile
echo "note: gomobile bind -target=ios -> $OUT (about 5 minutes on the first run)"
cd "$MOBILE"
gomobile bind -target=ios "${BIND_FLAGS[@]}" -o "$OUT" "${BIND_PACKAGES[@]}"
echo "done: $OUT"
