#!/usr/bin/env bash
# Moves olcrtc/ to another upstream release and regenerates the server patch.
#
#   scripts/update-olcrtc.sh v0.15.0
#
# `git subtree pull --squash` merges the new release under the olcOS commits;
# if it stops on a conflict, resolve it, commit, and run this script again
# with --continue to finish the pin and the patch. The apps pin the same
# commit (AppConstants.upstreamCorePin on iOS, the matching constant on
# Android): update them in the same release.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
die() { echo "error: $*" >&2; exit 1; }

[ $# -ge 1 ] || die "usage: scripts/update-olcrtc.sh <tag> [--continue]"
TAG="$1"
REPO="$(sed -n 's/^OLCRTC_REPO=//p' olcrtc.upstream)"
[ -n "$REPO" ] || die "OLCRTC_REPO missing from olcrtc.upstream"

if [ "${2:-}" != "--continue" ]; then
  git diff --quiet && git diff --cached --quiet || die "commit or stash local changes first"
  git subtree pull --prefix=olcrtc "$REPO" "$TAG" --squash -m "chore(olcrtc): update to $TAG"
fi

SQUASH="$(git log -1 --format=%H --grep='^git-subtree-dir: olcrtc$')"
COMMIT="$(git show -s --format=%B "$SQUASH" | sed -n 's/^git-subtree-split: //p')"
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || die "could not read the upstream commit from $SQUASH"

OLD="$(sed -n 's/^OLCRTC_COMMIT=//p' olcrtc.upstream)"
sed -i.bak -e "s/^OLCRTC_TAG=.*/OLCRTC_TAG=$TAG/" -e "s/^OLCRTC_COMMIT=.*/OLCRTC_COMMIT=$COMMIT/" olcrtc.upstream
sed -i.bak "s/OLCRTC_PIN=\"\${OLCRTC_PIN:-$OLD}\"/OLCRTC_PIN=\"\${OLCRTC_PIN:-$COMMIT}\"/" server/srv.sh
rm -f olcrtc.upstream.bak server/srv.sh.bak
grep -q "OLCRTC_PIN:-$COMMIT}" server/srv.sh || die "server/srv.sh: the default pin was not updated"

scripts/make-core-patch.sh
python3 scripts/parity_check.py || echo "note: srv.sh drifted from olcrtc/install.sh; adopt or reject the new upstream lines"

git add olcrtc.upstream server/srv.sh server/olcrtc-core.patch
git commit -q -m "chore(olcrtc): pin $TAG and regenerate the server patch"
echo "olcrtc/ is on $TAG ($COMMIT). Update the apps' core pin to $COMMIT."
