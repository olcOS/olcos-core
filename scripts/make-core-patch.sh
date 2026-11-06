#!/usr/bin/env bash
# Writes server/olcrtc-core.patch: the olcOS changes to olcrtc/ as one patch
# against the upstream release named in olcrtc.upstream. srv.sh applies it on
# the servers and the apps upload it, so a server builds the same core the
# apps bind. The apps tell a server's core by the upstream commit plus the
# patch's SHA-256, so the output has to be byte-for-byte stable: the same
# commits always give the same file.
#
# Left out, because the server binary does not use them:
#   olcrtc/mobile/            the gomobile package (phones only)
#   olcrtc/**/zz_olcos_*.go   olcOS-only files that never conflict upstream
#
#   scripts/make-core-patch.sh            write the patch
#   scripts/make-core-patch.sh --check    fail if the committed one is stale
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/server/olcrtc-core.patch"
cd "$ROOT"

# The upstream tree is the one the last `git subtree add/pull --squash`
# brought in: its squash commit carries the git-subtree-dir trailer and holds
# the upstream tree at its root.
SQUASH="$(git log -1 --format=%H --grep='^git-subtree-dir: olcrtc$')"
[ -n "$SQUASH" ] || { echo "error: no subtree squash commit for olcrtc/" >&2; exit 1; }
SPLIT="$(git show -s --format=%B "$SQUASH" | sed -n 's/^git-subtree-split: //p')"
PIN="$(sed -n 's/^OLCRTC_COMMIT=//p' olcrtc.upstream)"
if [ "$SPLIT" != "$PIN" ]; then
  echo "error: olcrtc.upstream names $PIN but olcrtc/ was last taken from $SPLIT" >&2
  exit 1
fi

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT
# --no-color/--no-ext-diff and the fixed abbreviation keep local git
# configuration out of the bytes.
git -c core.abbrev=8 -c diff.noprefix=false -c diff.mnemonicPrefix=false -c diff.relative=false \
  diff --no-color --no-ext-diff --abbrev=8 "$SQUASH^{tree}" "HEAD^{tree}:olcrtc" -- . \
  ':(exclude)mobile' ':(exclude,glob)**/zz_olcos_*' > "$TMP"

# The server update restores tracked files before it re-applies the patch,
# and git apply refuses to create a file that already exists: olcOS changes
# may modify upstream files but not add or delete them (zz_olcos_* files,
# left out above, are the exception).
if grep -qE '^(new|deleted) file mode' "$TMP"; then
  echo "error: the patch would add or delete files in olcrtc/; see docs/olcrtc.md" >&2
  exit 1
fi

if [ "${1:-}" = "--check" ]; then
  if ! cmp -s "$TMP" "$OUT"; then
    echo "error: server/olcrtc-core.patch is stale; run scripts/make-core-patch.sh and commit it" >&2
    exit 1
  fi
  echo "server/olcrtc-core.patch is current ($(sha256sum "$OUT" | cut -c1-16)…)"
  exit 0
fi
cp "$TMP" "$OUT"
echo "wrote server/olcrtc-core.patch ($(wc -l < "$OUT") lines, sha256 $(sha256sum "$OUT" | cut -d' ' -f1))"
