// Package xray implements the VLESS engine on top of xray-core and renders the
// JSON configs consumed by it: REALITY with XTLS-Vision for a server of one's
// own, and TLS over WebSocket, gRPC, HTTPUpgrade or XHTTP for a server that
// sits behind a CDN, which is what public lists mostly carry.
//
// Config field names follow the official REALITY reference
// (https://xtls.github.io/en/config/transports/reality.html) and the
// VLESS-TCP-XTLS-Vision-REALITY example in XTLS/Xray-examples.
package xray

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"

	xtls "github.com/xtls/xray-core/transport/internet/tls"

	"github.com/olcOS/olcos-core/engine"
)

// Profile parameter keys (engine.Profile.Params) understood by this engine.
// They mirror the vless:// share-link fields from XTLS/Xray-core#716.
const (
	ParamSNI         = "sni"  // realitySettings.serverName
	ParamFingerprint = "fp"   // realitySettings.fingerprint (default chrome)
	ParamPublicKey   = "pbk"  // realitySettings.password (alias publicKey)
	ParamShortID     = "sid"  // realitySettings.shortId
	ParamSpiderX     = "spx"  // realitySettings.spiderX
	ParamFlow        = "flow" // users[].flow (default xtls-rprx-vision)
	ParamNetwork     = "type" // streamSettings.network: tcp (default), ws, grpc, httpupgrade, xhttp
	ParamMLDSA65     = "pqv"  // realitySettings.mldsa65Verify

	ParamSecurity    = "security"    // streamSettings.security: reality (default) or tls
	ParamHost        = "host"        // Host header of ws, httpupgrade and xhttp
	ParamPath        = "path"        // path of ws, httpupgrade and xhttp
	ParamALPN        = "alpn"        // tlsSettings.alpn, comma-separated
	ParamServiceName = "serviceName" // grpcSettings.serviceName
	ParamAuthority   = "authority"   // grpcSettings.authority
	ParamMode        = "mode"        // grpc: gun or multi; xhttp: its own mode
	ParamExtra       = "extra"       // xhttpSettings.extra, a JSON object

	// ParamDirect is not a share-link field: the app sets it at engine.start
	// to the destinations a session reaches directly, never through the
	// server, in the olcrtc core's direct-list syntax (directRules).
	ParamDirect = "olcos.direct"
)

const (
	defaultFlow        = "xtls-rprx-vision"
	defaultFingerprint = "chrome"
	defaultSpiderX     = "/"
)

// How the connection to the server is protected.
const (
	SecurityReality = "reality"
	SecurityTLS     = "tls"
)

// Security says how p's connection to the server is protected. A profile
// that does not say is REALITY: every link written before TLS was accepted.
func Security(p engine.Profile) string {
	if s := strings.ToLower(strings.TrimSpace(p.Params[ParamSecurity])); s != "" {
		return s
	}
	return SecurityReality
}

// Network names the transport under VLESS in the words of a share link:
// tcp, ws, grpc, httpupgrade or xhttp. The older names clients still write
// are folded into these.
func Network(p engine.Profile) string {
	switch n := strings.ToLower(strings.TrimSpace(p.Params[ParamNetwork])); n {
	case "", "raw":
		return "tcp"
	case "websocket":
		return "ws"
	case "splithttp":
		return "xhttp"
	default:
		return n
	}
}

var (
	uuidRe    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	shortIDRe = regexp.MustCompile(`^(?:[0-9a-fA-F]{2}){0,8}$`)
)

// ClientOptions controls the local inbound of the rendered client config.
type ClientOptions struct {
	// SocksPort > 0 renders a 127.0.0.1 SOCKS5 inbound that the platform's
	// tun2socks stack feeds (variant B in docs/architecture.md).
	SocksPort int
	// SocksUser and SocksPass, both set, make that SOCKS5 inbound require
	// username/password authentication (RFC 1929): another app on the phone
	// cannot use the loopback listener, or find the tunnel through it.
	SocksUser, SocksPass string
	// TunFD >= 0 renders the native tun inbound instead (variant A). Mutually
	// exclusive with SocksPort. The fd itself is passed via XRAY_TUN_FD.
	TunFD int
	// LogLevel is one of debug, info, warning, error, none.
	LogLevel string
}

// ValidateProfile checks the Xray-specific fields of p.
func ValidateProfile(p engine.Profile) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if p.Kind != engine.KindXray {
		return fmt.Errorf("xray: profile kind %q", p.Kind)
	}
	if !uuidRe.MatchString(p.Secret) {
		return errors.New("xray: secret is not a UUID")
	}
	if p.Host == "" {
		return errors.New("xray: empty host")
	}
	if p.Port <= 0 || p.Port > 65535 {
		return fmt.Errorf("xray: invalid port %d", p.Port)
	}
	network := Network(p)
	switch network {
	case "tcp", "ws", "grpc", "httpupgrade", "xhttp":
	default:
		return fmt.Errorf("xray: network %q not supported", network)
	}
	switch security := Security(p); security {
	case SecurityReality:
		if p.Params[ParamPublicKey] == "" {
			return errors.New("xray: missing pbk (REALITY public key)")
		}
		if sid := p.Params[ParamShortID]; !shortIDRe.MatchString(sid) {
			return fmt.Errorf("xray: shortId %q must be 0..16 hex chars, even length", sid)
		}
		// xray-core carries REALITY over these three only.
		if network != "tcp" && network != "grpc" && network != "xhttp" {
			return fmt.Errorf("xray: REALITY does not run over %q", network)
		}
	case SecurityTLS:
	default:
		// No plain VLESS: without TLS the server sees, and anyone on the
		// path can read, every destination.
		return fmt.Errorf("xray: security %q not supported (reality or tls)", security)
	}
	return nil
}

// RenderClientConfig produces the xray-core JSON for a client profile.
func RenderClientConfig(p engine.Profile, o ClientOptions) ([]byte, error) {
	if err := ValidateProfile(p); err != nil {
		return nil, err
	}
	if (o.SocksPort > 0) == (o.TunFD >= 0) {
		return nil, errors.New("xray: set exactly one of SocksPort or TunFD")
	}
	if (o.SocksUser == "") != (o.SocksPass == "") {
		return nil, errors.New("xray: set both SOCKS username and password, or neither")
	}
	if len(o.SocksUser) > 255 || len(o.SocksPass) > 255 {
		return nil, errors.New("xray: SOCKS username and password are 255 bytes at most")
	}
	level := o.LogLevel
	if level == "" {
		level = "warning"
	}

	var inbound map[string]any
	if o.SocksPort > 0 {
		// UDP stays off: olcos-ios tunstack forwards TCP CONNECT only.
		settings := map[string]any{"udp": false}
		if o.SocksUser != "" {
			settings["auth"] = "password"
			settings["accounts"] = []any{map[string]any{"user": o.SocksUser, "pass": o.SocksPass}}
		}
		inbound = map[string]any{
			"tag": "socks-in", "listen": "127.0.0.1", "port": o.SocksPort, "protocol": "socks",
			"settings": settings,
		}
	} else {
		inbound = map[string]any{
			"tag": "tun-in", "protocol": "tun",
			// fd is supplied through the XRAY_TUN_FD environment variable
			// (proxy/tun/README.md); nothing to put in the JSON.
			"settings": map[string]any{},
		}
	}

	domains, ips := directRules(p.Params[ParamDirect])
	routed := len(domains) > 0 || len(ips) > 0
	if routed {
		// A SOCKS or tun client may hand over an address; the name inside the
		// connection picks the route without replacing the destination.
		inbound["sniffing"] = map[string]any{
			"enabled": true, "destOverride": []string{"http", "tls"}, "routeOnly": true,
		}
	}

	cfg := map[string]any{
		// No access log: it would put every destination the phone visits
		// into the app's log.
		"log": map[string]any{"loglevel": level, "access": "none", "dnsLog": false},
		// stats + policy expose outbound>>>proxy>>>traffic>>>{uplink,downlink}
		// counters that engine.Session.Stats reads for the measured hero picture.
		"stats": map[string]any{},
		"policy": map[string]any{"system": map[string]any{
			"statsOutboundUplink": true, "statsOutboundDownlink": true,
		}},
		"inbounds": []any{inbound},
		"outbounds": []any{
			map[string]any{
				"tag": "proxy", "protocol": "vless",
				"settings": map[string]any{"vnext": []any{map[string]any{
					"address": p.Host, "port": p.Port,
					"users": []any{map[string]any{
						"id": p.Secret, "encryption": "none", "flow": flow(p),
					}},
				}}},
				"streamSettings": streamSettings(p),
			},
			map[string]any{"tag": "direct", "protocol": "freedom"},
			map[string]any{"tag": "block", "protocol": "blackhole"},
		},
	}
	if routed {
		// Unlisted traffic takes the first outbound, the server.
		var rules []any
		if len(domains) > 0 {
			rules = append(rules, map[string]any{"type": "field", "domain": domains, "outboundTag": "direct"})
		}
		if len(ips) > 0 {
			rules = append(rules, map[string]any{"type": "field", "ip": ips, "outboundTag": "direct"})
		}
		cfg["routing"] = map[string]any{"domainStrategy": "AsIs", "rules": rules}
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// flow is the VLESS flow of p. Vision runs over plain TCP only; a REALITY
// link that names none gets it, as every server the app sets up uses it.
func flow(p engine.Profile) string {
	if Network(p) != "tcp" {
		return ""
	}
	if f := p.Params[ParamFlow]; f != "" || Security(p) != SecurityReality {
		return f
	}
	return defaultFlow
}

// fingerprint is the browser whose TLS hello the client imitates. A name
// Xray does not know would fail the whole config, so it becomes the default.
func fingerprint(p engine.Profile) string {
	name := strings.ToLower(strings.TrimSpace(p.Params[ParamFingerprint]))
	if name == "" || name == "unsafe" || name == "hellogolang" || xtls.GetFingerprint(name) == nil {
		return defaultFingerprint
	}
	return name
}

// streamSettings renders how p reaches its server: the protection (REALITY
// or TLS) and the transport under it.
func streamSettings(p engine.Profile) map[string]any {
	get := func(k, def string) string {
		if v := p.Params[k]; v != "" {
			return v
		}
		return def
	}
	network := Network(p)
	stream := map[string]any{"network": network}
	if Security(p) == SecurityTLS {
		// The name on the certificate: the link's sni, else the Host header
		// it sends, else the address itself. The certificate is always
		// verified; a link asking to skip that is not obeyed.
		name := p.Params[ParamSNI]
		if name == "" {
			name = get(ParamHost, p.Host)
		}
		tls := map[string]any{"serverName": name, "fingerprint": fingerprint(p)}
		if alpn := alpnList(p.Params[ParamALPN]); len(alpn) > 0 {
			tls["alpn"] = alpn
		}
		stream["security"], stream["tlsSettings"] = SecurityTLS, tls
	} else {
		reality := map[string]any{
			"serverName":  p.Params[ParamSNI],
			"fingerprint": fingerprint(p),
			"password":    p.Params[ParamPublicKey],
			"shortId":     p.Params[ParamShortID],
			"spiderX":     get(ParamSpiderX, defaultSpiderX),
		}
		if v := p.Params[ParamMLDSA65]; v != "" {
			reality["mldsa65Verify"] = v
		}
		stream["security"], stream["realitySettings"] = SecurityReality, reality
	}
	hostPath := func() map[string]any {
		out := map[string]any{"path": get(ParamPath, "/")}
		if h := p.Params[ParamHost]; h != "" {
			out["host"] = h
		}
		return out
	}
	switch network {
	case "ws":
		stream["wsSettings"] = hostPath()
	case "httpupgrade":
		stream["httpupgradeSettings"] = hostPath()
	case "xhttp":
		settings := hostPath()
		if m := p.Params[ParamMode]; m != "" {
			settings["mode"] = m
		}
		// What else the server expects of XHTTP (padding, headers) rides in
		// the link as a JSON object.
		if e := strings.TrimSpace(p.Params[ParamExtra]); strings.HasPrefix(e, "{") && json.Valid([]byte(e)) {
			settings["extra"] = json.RawMessage(e)
		}
		stream["xhttpSettings"] = settings
	case "grpc":
		settings := map[string]any{"serviceName": p.Params[ParamServiceName]}
		if a := p.Params[ParamAuthority]; a != "" {
			settings["authority"] = a
		}
		if p.Params[ParamMode] == "multi" {
			settings["multiMode"] = true
		}
		stream["grpcSettings"] = settings
	}
	return stream
}

// alpnList splits a link's alpn value. Lists pass it around percent-encoded
// again and again (http%25252F1.1), so it is decoded until it stops
// changing; anything that is not a protocol name TLS knows is dropped.
func alpnList(raw string) []string {
	for i := 0; i < 32 && strings.Contains(raw, "%"); i++ {
		dec, err := url.QueryUnescape(raw)
		if err != nil || dec == raw {
			break
		}
		raw = dec
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		switch name := strings.ToLower(strings.TrimSpace(part)); name {
		case "h2", "h3", "http/1.1":
			if !slices.Contains(out, name) {
				out = append(out, name)
			}
		}
	}
	return out
}

// directRules splits the app's direct list. It is the olcrtc core's syntax —
// `domain:<name>` for a name and everything under it, `full:<name>`, an
// address or a CIDR prefix, one per line, # comments — which Xray's routing
// reads natively; anything else is skipped.
func directRules(text string) (domains, ips []string) {
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "domain:"), strings.HasPrefix(line, "full:"):
			domains = append(domains, line)
		default:
			if _, err := netip.ParsePrefix(line); err == nil {
				ips = append(ips, line)
			} else if _, err := netip.ParseAddr(line); err == nil {
				ips = append(ips, line)
			}
		}
	}
	return domains, ips
}

// ServerOptions describes one REALITY inbound for the server module.
type ServerOptions struct {
	Port       int
	ClientUUID string
	ClientName string
	// Target is the real TLS 1.3 + H2 site that unauthenticated traffic is
	// forwarded to, e.g. "www.example.com:443". Never a *.ru/*.ir/*.cn,
	// Apple or Microsoft host (Xray-core PR #6508, issue #6402).
	Target      string
	ServerNames []string
	PrivateKey  string
	ShortIDs    []string
	// MaxTimeDiffMillis defaults to 60000 when zero.
	MaxTimeDiffMillis int
	LogLevel          string
}

// RenderServerConfig produces the xray-core JSON for the server container.
func RenderServerConfig(o ServerOptions) ([]byte, error) {
	if o.Port <= 0 || o.Port > 65535 {
		return nil, fmt.Errorf("xray: invalid port %d", o.Port)
	}
	if !uuidRe.MatchString(o.ClientUUID) {
		return nil, errors.New("xray: client id is not a UUID")
	}
	if o.Target == "" || o.PrivateKey == "" || len(o.ServerNames) == 0 || len(o.ShortIDs) == 0 {
		return nil, errors.New("xray: target, privateKey, serverNames and shortIds are required")
	}
	for _, s := range o.ShortIDs {
		if !shortIDRe.MatchString(s) {
			return nil, fmt.Errorf("xray: shortId %q must be 0..16 hex chars, even length", s)
		}
	}
	name := o.ClientName
	if name == "" {
		name = "client-1"
	}
	level := o.LogLevel
	if level == "" {
		level = "warning"
	}
	mtd := o.MaxTimeDiffMillis
	if mtd == 0 {
		mtd = 60000
	}
	cfg := map[string]any{
		// No access log: Xray would otherwise print every client address and
		// destination to stdout, that is to `podman logs` (and the agent).
		"log": map[string]any{"loglevel": level, "access": "none", "dnsLog": false},
		"inbounds": []any{map[string]any{
			"tag": "vless-in", "listen": "0.0.0.0", "port": o.Port, "protocol": "vless",
			"settings": map[string]any{
				"clients":    []any{map[string]any{"id": o.ClientUUID, "flow": defaultFlow, "email": name}},
				"decryption": "none",
			},
			"streamSettings": map[string]any{
				"network": "tcp", "security": "reality",
				"realitySettings": map[string]any{
					"target":      o.Target,
					"serverNames": o.ServerNames,
					"privateKey":  o.PrivateKey,
					"shortIds":    o.ShortIDs,
					"maxTimeDiff": mtd,
				},
			},
			"sniffing": map[string]any{"enabled": true, "destOverride": []any{"http", "tls", "quic"}},
		}},
		"outbounds": []any{
			map[string]any{"tag": "direct", "protocol": "freedom"},
			map[string]any{"tag": "block", "protocol": "blackhole"},
		},
		// A client must not reach the server's own services or its provider's
		// private network through the proxy (cloud metadata at 169.254.169.254
		// among them): by IP and, through IPIfNonMatch, by a name resolving to one.
		"routing": map[string]any{
			"domainStrategy": "IPIfNonMatch",
			"rules": []any{map[string]any{
				"type": "field", "outboundTag": "block", "ip": PrivateNets,
			}},
		},
	}
	return json.MarshalIndent(cfg, "", "  ")
}

// PrivateNets are the destinations a server never proxies to. Written out
// instead of geoip:private so a config does not depend on geoip.dat; the
// server script carries the same list.
var PrivateNets = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7", "fe80::/10",
}
