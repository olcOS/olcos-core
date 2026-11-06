package xray

// Feature registrations, a subset of xray-core main/distro/all/all.go: no
// commander/gRPC API, no reverse proxy, no CLI commands, no TOML/YAML loaders.
//
// This does NOT keep other protocols out of the binary. The JSON loader below
// (main/json → infra/conf) imports the config package of every protocol and
// transport, so VMess, Trojan, Shadowsocks, WireGuard, Hysteria, XHTTP,
// WebSocket, gRPC and the rest are linked and registered whatever this list
// says (`go list -deps ./engine/xray` shows them). A smaller engine for the
// ~50 MiB iOS packet-tunnel budget (docs/architecture.md) would have to build
// the protobuf config directly instead of loading JSON.
import (
	// Mandatory features.
	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"

	// Optional features actually used by the rendered configs.
	_ "github.com/xtls/xray-core/app/dns"
	_ "github.com/xtls/xray-core/app/log"
	_ "github.com/xtls/xray-core/app/policy"
	_ "github.com/xtls/xray-core/app/router"
	_ "github.com/xtls/xray-core/app/stats"

	// Fix dependency cycle caused by core import in internet package.
	_ "github.com/xtls/xray-core/transport/internet/tagged/taggedimpl"

	// Inbound and outbound proxies.
	_ "github.com/xtls/xray-core/proxy/blackhole"
	_ "github.com/xtls/xray-core/proxy/dns"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/socks"
	_ "github.com/xtls/xray-core/proxy/vless/outbound"

	// Transports.
	_ "github.com/xtls/xray-core/transport/internet/reality"
	_ "github.com/xtls/xray-core/transport/internet/tcp"
	_ "github.com/xtls/xray-core/transport/internet/tls"
	_ "github.com/xtls/xray-core/transport/internet/udp"

	// Transport headers.
	_ "github.com/xtls/xray-core/transport/internet/headers/noop"

	// JSON config loader.
	_ "github.com/xtls/xray-core/main/json"
)
