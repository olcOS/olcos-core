#!/usr/bin/env bash
# olcos-core: remove an Xray deployment created by install.sh.
# Usage: OLCOS_XRAY_ID=<id> ./uninstall.sh   (keys are kept unless OLCOS_XRAY_PURGE=1)
set -euo pipefail
ID="${OLCOS_XRAY_ID:-}"
[[ -n "$ID" ]] || { echo "OLCOS_XRAY_ID is required" >&2; exit 1; }
CONTAINER="olcos-xray-${ID}"
ROOT="${OLCOS_XRAY_PREFIX:-/opt}/olcos-xray-${ID}"
podman rm -f "${CONTAINER}" >/dev/null 2>&1 || true
if [[ "${OLCOS_XRAY_PURGE:-0}" == "1" ]]; then
  rm -rf "${ROOT}"
else
  rm -rf "${ROOT}/config"
fi
echo "removed ${CONTAINER}"
