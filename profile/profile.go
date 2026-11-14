// Package profile parses and exports share links into engine.Profile.
//
// Supported schemes:
//
//   - vless://<uuid>@<host>:<port>?<query>#<name>  (XTLS/Xray-core discussion #716)
//   - olcrtc://<carrier>?<transport>[params]@<roomID>#<key>[%clientID][$name]
//     (olcos-ios docs/uri.md; only the fields the Go core needs are extracted,
//     the Swift parser App/Models/OlcrtcURI.swift stays authoritative for UI)
//
// Subscriptions: one link per line, whole body base64 (v2rayNG#1804); see Parse
// SubscriptionBody.
package profile

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/olcOS/olcos-core/engine"
)

// Parse dispatches on the URL scheme.
func Parse(raw string) (engine.Profile, error) {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(raw, "vless://"):
		return ParseVLESS(raw)
	case strings.HasPrefix(raw, "olcrtc://"):
		return ParseOlcrtc(raw)
	}
	return engine.Profile{}, errors.New("profile: unsupported scheme")
}

// ParseVLESS parses a vless:// share link. Keys are case-sensitive and must
// not repeat (#716). The link's protection is REALITY or TLS; every other
// field is kept verbatim in Params, where the Xray engine reads the ones it
// knows (transport, path, host, alpn), so export round-trips.
func ParseVLESS(raw string) (engine.Profile, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return engine.Profile{}, fmt.Errorf("profile: %w", err)
	}
	if u.Scheme != "vless" || u.User == nil {
		return engine.Profile{}, errors.New("profile: not a vless link")
	}
	host := u.Hostname()
	portStr := u.Port()
	if host == "" || portStr == "" {
		return engine.Profile{}, errors.New("profile: vless link needs host:port")
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return engine.Profile{}, fmt.Errorf("profile: bad port %q", portStr)
	}
	params := map[string]string{}
	seen := map[string]bool{}
	for _, kv := range strings.Split(u.RawQuery, "&") {
		if kv == "" {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		if seen[k] {
			return engine.Profile{}, fmt.Errorf("profile: duplicate key %q", k)
		}
		seen[k] = true
		dv, err := url.QueryUnescape(v)
		if err != nil {
			return engine.Profile{}, fmt.Errorf("profile: key %q: %w", k, err)
		}
		params[k] = dv
	}
	if enc := params["encryption"]; enc != "" && enc != "none" {
		return engine.Profile{}, fmt.Errorf("profile: unsupported encryption %q", enc)
	}
	switch sec := params["security"]; sec {
	case "reality":
		// The default, so a REALITY profile does not carry the word.
		delete(params, "security")
	case "tls":
	default:
		return engine.Profile{}, fmt.Errorf("profile: security %q not supported (reality or tls)", sec)
	}
	delete(params, "encryption")
	return engine.Profile{
		Kind:   engine.KindXray,
		Name:   u.Fragment,
		Host:   host,
		Port:   port,
		Secret: u.User.Username(),
		Params: params,
	}, nil
}

// ExportVLESS renders the canonical share link. Query keys are emitted in a
// fixed order so exports are byte-stable.
func ExportVLESS(p engine.Profile) (string, error) {
	if p.Kind != engine.KindXray {
		return "", errors.New("profile: not an xray profile")
	}
	if p.Secret == "" || p.Host == "" || p.Port == 0 {
		return "", errors.New("profile: incomplete xray profile")
	}
	order := []string{"flow", "sni", "fp", "pbk", "sid", "spx", "pqv", "type"}
	security := p.Params["security"]
	if security == "" {
		security = "reality"
	}
	q := "encryption=none&security=" + url.QueryEscape(security)
	emitted := map[string]bool{"security": true}
	for _, k := range order {
		if v, ok := p.Params[k]; ok && v != "" {
			q += "&" + k + "=" + url.QueryEscape(v)
			emitted[k] = true
		}
	}
	// Any extra keys, sorted for stability.
	extra := make([]string, 0)
	for k, v := range p.Params {
		if !emitted[k] && v != "" {
			extra = append(extra, k)
		}
	}
	sortStrings(extra)
	for _, k := range extra {
		q += "&" + k + "=" + url.QueryEscape(p.Params[k])
	}
	host := p.Host
	if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
		host = "[" + host + "]"
	}
	s := fmt.Sprintf("vless://%s@%s:%d?%s", p.Secret, host, p.Port, q)
	if p.Name != "" {
		s += "#" + url.PathEscape(p.Name)
	}
	return s, nil
}

// ParseOlcrtc extracts carrier, transport, room, key and optional name from an
// olcrtc:// link. Transport parameters are kept in Params["transport"] raw.
func ParseOlcrtc(raw string) (engine.Profile, error) {
	body, ok := strings.CutPrefix(raw, "olcrtc://")
	if !ok {
		return engine.Profile{}, errors.New("profile: not an olcrtc link")
	}
	main, frag, _ := strings.Cut(body, "#")
	if frag == "" {
		return engine.Profile{}, errors.New("profile: olcrtc link needs #key")
	}
	at := strings.LastIndex(main, "@")
	if at < 0 {
		return engine.Profile{}, errors.New("profile: olcrtc link needs @roomID")
	}
	head, room := main[:at], main[at+1:]
	carrier, transport, _ := strings.Cut(head, "?")
	if carrier == "" || room == "" {
		return engine.Profile{}, errors.New("profile: olcrtc link needs carrier and room")
	}
	key := frag
	var clientID, name string
	if i := strings.IndexByte(key, '$'); i >= 0 {
		name, key = key[i+1:], key[:i]
	}
	if i := strings.IndexByte(key, '%'); i >= 0 {
		clientID, key = key[i+1:], key[:i]
	}
	params := map[string]string{"transport": transport}
	if clientID != "" {
		params["clientID"] = clientID
	}
	if name != "" {
		if n, err := url.PathUnescape(name); err == nil {
			name = n
		}
	}
	return engine.Profile{
		Kind:   engine.KindOlcrtc,
		Name:   name,
		Host:   carrier,
		Room:   room,
		Secret: key,
		Params: params,
	}, nil
}

// ParseSubscriptionBody decodes a subscription payload: either base64 of
// newline-separated links or plain newline-separated links. Unparseable
// lines are returned in errs with their line number; valid profiles are still
// returned so one bad line does not hide the rest.
func ParseSubscriptionBody(body string) (profiles []engine.Profile, errs []error) {
	text := strings.TrimSpace(body)
	if !strings.Contains(text, "://") {
		if dec, err := base64.StdEncoding.DecodeString(padB64(text)); err == nil {
			text = string(dec)
		} else if dec, err := base64.URLEncoding.DecodeString(padB64(text)); err == nil {
			text = string(dec)
		}
	}
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		p, err := Parse(line)
		if err != nil {
			errs = append(errs, fmt.Errorf("line %d: %w", i+1, err))
			continue
		}
		profiles = append(profiles, p)
	}
	return profiles, errs
}

func padB64(s string) string {
	s = strings.TrimRight(s, "=")
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	return s
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
