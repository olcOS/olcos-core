podman ps -a --filter 'name=olcos-xray-' --format 'XRAY={{.Names}}	{{.Status}}' 2>/dev/null || true
