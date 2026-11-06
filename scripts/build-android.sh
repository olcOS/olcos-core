#!/usr/bin/env bash
# Binds the olcOS Go core for Android into an AAR.
#
#   scripts/build-android.sh [output.aar]    (default: build/olcoscore.aar)
#
# Needs Go (the version in mobile/go.mod), a JDK (gomobile runs javac), the
# Android SDK and an NDK (ANDROID_HOME, ANDROID_NDK_HOME; the newest NDK under
# the SDK is used when ANDROID_NDK_HOME is not set). Phones (arm64) and the
# emulator (amd64) only: the two 32-bit ABIs would double the bind time.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib-bind.sh"

OUT="${1:-$ROOT/build/olcoscore.aar}"
mkdir -p "$(dirname "$OUT")"
OUT="$(cd "$(dirname "$OUT")" && pwd)/$(basename "$OUT")"

: "${ANDROID_HOME:?set ANDROID_HOME to the Android SDK}"
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
  ANDROID_NDK_HOME="$(ls -d "$ANDROID_HOME"/ndk/* 2>/dev/null | sort -V | tail -n 1 || true)"
  export ANDROID_NDK_HOME
fi
[ -d "${ANDROID_NDK_HOME:-}" ] || die "no Android NDK (set ANDROID_NDK_HOME)"
echo "note: NDK at $ANDROID_NDK_HOME"

prepare_gomobile
echo "note: gomobile bind -target=android -> $OUT"
cd "$MOBILE"
gomobile bind -target=android/arm64,android/amd64 -androidapi 26 "${BIND_FLAGS[@]}" -o "$OUT" "${BIND_PACKAGES[@]}"
echo "done: $OUT ($(du -h "$OUT" | cut -f1))"
