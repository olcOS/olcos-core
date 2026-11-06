command -v podman >/dev/null 2>&1 && echo 'PODMAN=yes' || echo 'PODMAN=no'
podman image exists docker.io/library/golang:1.26-alpine3.22 2>/dev/null && echo 'IMAGE=yes' || echo 'IMAGE=no'
_c=$(podman ps -a --filter 'name=^__BASE__$' --format '{{.Status}}' 2>/dev/null); _rc=$?; printf 'CONTAINER=%s\n' "$(printf '%s\n' "$_c" | head -1)"; printf 'CONTAINER_RC=%s\n' "$_rc"
df -h / 2>/dev/null | awk 'NR==2{printf "DISK=%s/%s\n",$3,$2}'
free -m 2>/dev/null | awk 'NR==2{printf "RAM=%sM/%sM\n",$3,$2}'
uptime 2>/dev/null | sed 's/.*up *//;s/,.*load.*//' | awk '{printf "UPTIME=%s\n",$0}'
echo 'READINESS_END'
