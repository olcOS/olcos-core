// Package xray implements the VLESS + REALITY + XTLS-Vision engine on top of
// xray-core and renders the JSON configs consumed by it.
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
	"regexp"
	"strings"

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
	ParamNetwork     = "type" // streamSettings.network (only tcp for now)
	ParamMLDSA65     = "pqv"  // realitySettings.mldsa65Verify

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

var (
	uuidRe    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	shortIDRe = regexp.MustCompile(`^(?:[0-9a-fA-F]{2}){0,8}$`)
)

// ClientOptions controls the local inbound of the rendered client config.
type ClientOptions struct {
	// SocksPort > 0 renders a 127.0.0.1 SOCKS5 inbound that the platform's
	// tun2socks stack feeds (variant B in docs/architecture.md).
	SocksPort int
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
	if p.Params[ParamPublicKey] == "" {
		return errors.New("xray: missing pbk (REALITY public key)")
	}
	if sid := p.Params[ParamShortID]; !shortIDRe.MatchString(sid) {
		return fmt.Errorf("xray: shortId %q must be 0..16 hex chars, even length", sid)
	}
	if n := p.Params[ParamNetwork]; n != "" && n != "tcp" && n != "raw" {
		return fmt.Errorf("xray: network %q not supported yet (tcp/raw only)", n)
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
	get := func(k, def string) string {
		if v := p.Params[k]; v != "" {
			return v
		}
		return def
	}
	level := o.LogLevel
	if level == "" {
		level = "warning"
	}

	var inbound map[string]any
	if o.SocksPort > 0 {
		inbound = map[string]any{
			"tag": "socks-in", "listen": "127.0.0.1", "port": o.SocksPort, "protocol": "socks",
			// UDP stays off: olcos-ios tunstack forwards TCP CONNECT only.
			"settings": map[string]any{"udp": false},
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

	reality := map[string]any{
		"serverName":  p.Params[ParamSNI],
		"fingerprint": get(ParamFingerprint, defaultFingerprint),
		"password":    p.Params[ParamPublicKey],
		"shortId":     p.Params[ParamShortID],
		"spiderX":     get(ParamSpiderX, defaultSpiderX),
	}
	if v := p.Params[ParamMLDSA65]; v != "" {
		reality["mldsa65Verify"] = v
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
						"id": p.Secret, "encryption": "none", "flow": get(ParamFlow, defaultFlow),
					}},
				}}},
				"streamSettings": map[string]any{
					"network": "tcp", "security": "reality", "realitySettings": reality,
				},
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
