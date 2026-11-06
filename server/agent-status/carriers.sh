set -e
CNAME="__BASE__"
if ! podman ps -a --format '{{.Names}}' | grep -q "^${CNAME}$" 2>/dev/null; then
    echo "ERROR: container ${CNAME} not found" >&2; exit 1
fi
DEPLOY_DIR=$(podman inspect --format '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}{{break}}{{end}}{{end}}' "${CNAME}")
if [ -z "$DEPLOY_DIR" ] || [ ! -f "$DEPLOY_DIR/server.yaml" ]; then
    echo "ERROR: server.yaml not found for ${CNAME} (deploy dir: ${DEPLOY_DIR:-unknown})" >&2; exit 1
fi
for f in "$DEPLOY_DIR"/server.yaml "$DEPLOY_DIR"/server-*.yaml; do
    [ -f "$f" ] || continue
    BASE_F=$(basename "$f")
    case "$BASE_F" in
        server.yaml)   C="${CNAME}" ;;
        server-*.yaml) SUF="${BASE_F#server-}"; C="${CNAME}-${SUF%.yaml}" ;;
        *) continue ;;
    esac
    STATUS=$(podman ps -a --filter "name=^${C}$" --format '{{.Status}}' 2>/dev/null | head -1)
    [ -n "$STATUS" ] || STATUS="missing"
    echo "OLCRTC_CARRIER_BEGIN"
    echo "FILE=$BASE_F"
    echo "PROVIDER=$(sed -n 's/^  provider: "\(.*\)"$/\1/p' "$f" 2>/dev/null | head -1)"
    echo "TRANSPORT=$(sed -n 's/^  transport: "\(.*\)"$/\1/p' "$f" 2>/dev/null | head -1)"
    echo "ROOM=$(sed -n 's/^  id: "\(.*\)"$/\1/p' "$f" 2>/dev/null | head -1)"
    echo "CONTAINER=$C"
    echo "STATUS=$STATUS"
    echo "OLCRTC_CARRIER_END"
done
echo "OLCRTC_CORE=$(git -C "$DEPLOY_DIR" rev-parse HEAD 2>/dev/null || true)"
echo "OLCRTC_CORE_PATCH=$(cat "$DEPLOY_DIR/.olcos-core-patch" 2>/dev/null || true)"
