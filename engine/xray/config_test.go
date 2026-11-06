package xray

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/olcOS/olcos-core/engine"
)

func sample() engine.Profile {
	return engine.Profile{
		Kind: engine.KindXray, Host: "203.0.113.10", Port: 443,
		Secret: "8f3f2c1e-7a5b-4d2e-9c1a-0b6d5e4f3a21",
		Params: map[string]string{
			ParamSNI: "www.example.com", ParamPublicKey: "PBK", ParamShortID: "6ba85179e30d4fc2",
		},
	}
}

func TestRenderClientSocks(t *testing.T) {
	out, err := RenderClientConfig(sample(), ClientOptions{SocksPort: 1080, TunFD: -1})
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{`"protocol": "socks"`, `"port": 1080`, `"flow": "xtls-rprx-vision"`,
		`"fingerprint": "chrome"`, `"password": "PBK"`, `"shortId": "6ba85179e30d4fc2"`, `"spiderX": "/"`,
		`"security": "reality"`, `"serverName": "www.example.com"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in\n%s", want, s)
		}
	}
	if strings.Contains(s, "mldsa65Verify") {
		t.Error("mldsa65Verify must be omitted when pqv is empty")
	}
}

func TestRenderClientRoutesTheDirectListStraightOut(t *testing.T) {
	p := sample()
	p.Params[ParamDirect] = "# Russian sites\ndomain:ru\nfull:vk.com\n10.0.0.0/8\n203.0.113.7\nnonsense"
	out, err := RenderClientConfig(p, ClientOptions{SocksPort: 1080, TunFD: -1})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Inbounds []struct {
			Sniffing struct {
				Enabled   bool `json:"enabled"`
				RouteOnly bool `json:"routeOnly"`
			} `json:"sniffing"`
		} `json:"inbounds"`
		Routing struct {
			Rules []struct {
				Domain      []string `json:"domain"`
				IP          []string `json:"ip"`
				OutboundTag string   `json:"outboundTag"`
			} `json:"rules"`
		} `json:"routing"`
		Outbounds []struct {
			Tag string `json:"tag"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	if !cfg.Inbounds[0].Sniffing.Enabled || !cfg.Inbounds[0].Sniffing.RouteOnly {
		t.Error("the inbound must read the name to route by it, without replacing the destination")
	}
	if len(cfg.Routing.Rules) != 2 ||
		strings.Join(cfg.Routing.Rules[0].Domain, ",") != "domain:ru,full:vk.com" ||
		strings.Join(cfg.Routing.Rules[1].IP, ",") != "10.0.0.0/8,203.0.113.7" {
		t.Fatalf("rules: %+v", cfg.Routing.Rules)
	}
	for _, rule := range cfg.Routing.Rules {
		if rule.OutboundTag != "direct" {
			t.Errorf("a listed destination goes %q, want direct", rule.OutboundTag)
		}
	}
	if cfg.Outbounds[0].Tag != "proxy" {
		t.Error("everything unlisted must keep going through the server")
	}

	plain, err := RenderClientConfig(sample(), ClientOptions{SocksPort: 1080, TunFD: -1})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(plain), "routing") || strings.Contains(string(plain), "sniffing") {
		t.Error("no list, no routing: everything through the server as before")
	}
}

func TestRenderClientTun(t *testing.T) {
	out, err := RenderClientConfig(sample(), ClientOptions{TunFD: 7})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), `"protocol": "tun"`) {
		t.Fatalf("tun inbound expected:\n%s", out)
	}
	if _, err := RenderClientConfig(sample(), ClientOptions{SocksPort: 1080, TunFD: 7}); err == nil {
		t.Fatal("SocksPort and TunFD together must fail")
	}
}

func TestValidateProfile(t *testing.T) {
	bad := sample()
	bad.Params[ParamShortID] = "abc"
	if err := ValidateProfile(bad); err == nil {
		t.Error("odd-length shortId must fail")
	}
	bad = sample()
	bad.Secret = "not-a-uuid"
	if err := ValidateProfile(bad); err == nil {
		t.Error("non-UUID secret must fail")
	}
	bad = sample()
	delete(bad.Params, ParamPublicKey)
	if err := ValidateProfile(bad); err == nil {
		t.Error("missing pbk must fail")
	}
	bad = sample()
	bad.Params[ParamNetwork] = "xhttp"
	if err := ValidateProfile(bad); err == nil {
		t.Error("xhttp is not supported yet")
	}
}

func TestRenderServer(t *testing.T) {
	out, err := RenderServerConfig(ServerOptions{
		Port: 443, ClientUUID: "8f3f2c1e-7a5b-4d2e-9c1a-0b6d5e4f3a21", Target: "www.example.com:443",
		ServerNames: []string{"www.example.com"}, PrivateKey: "PRIV", ShortIDs: []string{"6ba85179e30d4fc2", ""},
	})
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{`"target": "www.example.com:443"`, `"decryption": "none"`, `"maxTimeDiff": 60000`,
		`"email": "client-1"`, `"flow": "xtls-rprx-vision"`, `"listen": "0.0.0.0"`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %s in\n%s", want, s)
		}
	}
	if _, err := RenderServerConfig(ServerOptions{Port: 443, ClientUUID: "x"}); err == nil {
		t.Error("incomplete server options must fail")
	}
}
