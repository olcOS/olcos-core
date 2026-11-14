package xray

import (
	"encoding/json"
	"os"
	"regexp"
	"slices"
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
	bad.Params[ParamNetwork] = "kcp"
	if err := ValidateProfile(bad); err == nil {
		t.Error("an unknown transport must fail")
	}
	bad = sample()
	bad.Params[ParamNetwork] = "ws"
	if err := ValidateProfile(bad); err == nil {
		t.Error("REALITY does not run over WebSocket")
	}
	bad = behindCDN()
	bad.Params[ParamSecurity] = "none"
	if err := ValidateProfile(bad); err == nil {
		t.Error("VLESS without TLS must fail")
	}
	for _, network := range []string{"grpc", "xhttp"} {
		ok := sample()
		ok.Params[ParamNetwork] = network
		if err := ValidateProfile(ok); err != nil {
			t.Errorf("REALITY over %s: %v", network, err)
		}
	}
}

// behindCDN is a server as public lists carry them: VLESS in a WebSocket
// under TLS, the address a CDN's, no REALITY key at all.
func behindCDN() engine.Profile {
	return engine.Profile{
		Kind: engine.KindXray, Host: "198.51.100.20", Port: 443,
		Secret: "8f3f2c1e-7a5b-4d2e-9c1a-0b6d5e4f3a21",
		Params: map[string]string{
			ParamSecurity: "tls", ParamNetwork: "ws", ParamSNI: "cdn.example.com",
			ParamHost: "cdn.example.com", ParamPath: "/tunnel?ed=2048", ParamFingerprint: "firefox",
			ParamALPN: "http/1.1",
		},
	}
}

// stream is the streamSettings of the rendered config's first outbound.
func stream(t *testing.T, p engine.Profile) (settings map[string]any, flow string) {
	t.Helper()
	out, err := RenderClientConfig(p, ClientOptions{SocksPort: 1080, TunFD: -1})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Outbounds []struct {
			Settings struct {
				Vnext []struct {
					Users []struct {
						Flow string `json:"flow"`
					} `json:"users"`
				} `json:"vnext"`
			} `json:"settings"`
			StreamSettings map[string]any `json:"streamSettings"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	return cfg.Outbounds[0].StreamSettings, cfg.Outbounds[0].Settings.Vnext[0].Users[0].Flow
}

func TestRenderClientBehindCDN(t *testing.T) {
	settings, flow := stream(t, behindCDN())
	if settings["network"] != "ws" || settings["security"] != "tls" {
		t.Fatalf("network and security: %v", settings)
	}
	if _, has := settings["realitySettings"]; has {
		t.Error("a TLS server has no REALITY settings")
	}
	tls := settings["tlsSettings"].(map[string]any)
	if tls["serverName"] != "cdn.example.com" || tls["fingerprint"] != "firefox" {
		t.Errorf("tlsSettings: %v", tls)
	}
	if alpn, _ := tls["alpn"].([]any); len(alpn) != 1 || alpn[0] != "http/1.1" {
		t.Errorf("alpn: %v", tls["alpn"])
	}
	if _, has := tls["allowInsecure"]; has {
		t.Error("the certificate is always verified")
	}
	ws := settings["wsSettings"].(map[string]any)
	if ws["path"] != "/tunnel?ed=2048" || ws["host"] != "cdn.example.com" {
		t.Errorf("wsSettings: %v", ws)
	}
	// Vision runs over plain TCP only.
	if flow != "" {
		t.Errorf("flow over WebSocket: %q", flow)
	}
}

func TestRenderClientTransports(t *testing.T) {
	p := behindCDN()
	p.Params[ParamNetwork] = "httpupgrade"
	settings, _ := stream(t, p)
	if hu := settings["httpupgradeSettings"].(map[string]any); hu["path"] != "/tunnel?ed=2048" || hu["host"] != "cdn.example.com" {
		t.Errorf("httpupgradeSettings: %v", hu)
	}

	p = behindCDN()
	p.Params[ParamNetwork], p.Params[ParamMode] = "xhttp", "packet-up"
	settings, _ = stream(t, p)
	if x := settings["xhttpSettings"].(map[string]any); x["path"] != "/tunnel?ed=2048" || x["mode"] != "packet-up" {
		t.Errorf("xhttpSettings: %v", x)
	}

	// The names clients wrote before xray-core renamed its transports.
	p = behindCDN()
	p.Params[ParamNetwork] = "websocket"
	if settings, _ = stream(t, p); settings["network"] != "ws" || settings["wsSettings"] == nil {
		t.Errorf("websocket: %v", settings)
	}

	p = sample()
	p.Params[ParamNetwork], p.Params[ParamServiceName], p.Params[ParamMode] = "grpc", "tunnel", "multi"
	settings, flow := stream(t, p)
	if settings["security"] != "reality" || settings["realitySettings"] == nil {
		t.Errorf("REALITY over gRPC: %v", settings)
	}
	if g := settings["grpcSettings"].(map[string]any); g["serviceName"] != "tunnel" || g["multiMode"] != true {
		t.Errorf("grpcSettings: %v", g)
	}
	if flow != "" {
		t.Errorf("flow over gRPC: %q", flow)
	}

	// A TLS server over plain TCP keeps the flow its link names, none included.
	p = behindCDN()
	p.Params[ParamNetwork] = "tcp"
	if _, flow = stream(t, p); flow != "" {
		t.Errorf("a TLS link without a flow got %q", flow)
	}
	// REALITY over TCP without one still gets Vision, as before.
	if _, flow = stream(t, sample()); flow != "xtls-rprx-vision" {
		t.Errorf("REALITY over TCP: flow %q", flow)
	}
}

func TestTLSNameFallsBackToTheHostHeaderThenTheAddress(t *testing.T) {
	p := behindCDN()
	delete(p.Params, ParamSNI)
	settings, _ := stream(t, p)
	if name := settings["tlsSettings"].(map[string]any)["serverName"]; name != "cdn.example.com" {
		t.Errorf("without sni: %v", name)
	}
	delete(p.Params, ParamHost)
	p.Host = "edge.example.net"
	settings, _ = stream(t, p)
	if name := settings["tlsSettings"].(map[string]any)["serverName"]; name != "edge.example.net" {
		t.Errorf("without sni and host: %v", name)
	}
	if _, has := settings["wsSettings"].(map[string]any)["host"]; has {
		t.Error("no Host header was named")
	}
}

// A list writes any browser name; one Xray does not know must not cost the
// connection.
func TestAnUnknownFingerprintBecomesTheDefault(t *testing.T) {
	cases := map[string]string{
		"": "chrome", "chrome": "chrome", "Firefox": "firefox", "qq": "qq", "ios": "ios",
		"netscape": "chrome", "unsafe": "chrome", "hellogolang": "chrome",
	}
	for in, want := range cases {
		for _, p := range []engine.Profile{sample(), behindCDN()} {
			p.Params[ParamFingerprint] = in
			settings, _ := stream(t, p)
			block, _ := settings["realitySettings"].(map[string]any)
			if block == nil {
				block = settings["tlsSettings"].(map[string]any)
			}
			if got := block["fingerprint"]; got != want {
				t.Errorf("fp %q over %v: %v, want %q", in, settings["security"], got, want)
			}
		}
	}
}

func TestXHTTPExtraIsPassedOnWhenItIsAnObject(t *testing.T) {
	p := behindCDN()
	p.Params[ParamNetwork] = "xhttp"
	p.Params[ParamExtra] = `{"xPaddingBytes":"100-1000","noGRPCHeader":true}`
	settings, _ := stream(t, p)
	extra, _ := settings["xhttpSettings"].(map[string]any)["extra"].(map[string]any)
	if extra["xPaddingBytes"] != "100-1000" || extra["noGRPCHeader"] != true {
		t.Errorf("extra: %v", settings["xhttpSettings"])
	}
	for _, bad := range []string{"", "nonsense", `["a"]`, `{"open":`} {
		p.Params[ParamExtra] = bad
		settings, _ = stream(t, p)
		if _, has := settings["xhttpSettings"].(map[string]any)["extra"]; has {
			t.Errorf("extra %q was passed on", bad)
		}
	}
}

func TestALPNList(t *testing.T) {
	cases := map[string][]string{
		"":                           nil,
		"http/1.1":                   {"http/1.1"},
		"h2,http/1.1":                {"h2", "http/1.1"},
		"h3%2Ch2%2Chttp%2F1.1":       {"h3", "h2", "http/1.1"},
		"http%2525252525252F1.1":     {"http/1.1"},
		"H2, h2 ,nonsense,http/1.1 ": {"h2", "http/1.1"},
		"%zz":                        nil,
	}
	for raw, want := range cases {
		if got := alpnList(raw); !slices.Equal(got, want) {
			t.Errorf("alpnList(%q) = %v, want %v", raw, got, want)
		}
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
	var cfg struct {
		Routing struct {
			DomainStrategy string `json:"domainStrategy"`
			Rules          []struct {
				OutboundTag string   `json:"outboundTag"`
				IP          []string `json:"ip"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Routing.DomainStrategy != "IPIfNonMatch" || len(cfg.Routing.Rules) != 1 ||
		cfg.Routing.Rules[0].OutboundTag != "block" {
		t.Fatalf("private destinations must be routed to the blackhole: %+v", cfg.Routing)
	}
	for _, want := range []string{"127.0.0.0/8", "169.254.0.0/16", "10.0.0.0/8", "::1/128"} {
		if !slices.Contains(cfg.Routing.Rules[0].IP, want) {
			t.Errorf("%s is not blocked: %v", want, cfg.Routing.Rules[0].IP)
		}
	}
}

// The server script writes the same private-network list as the Go reference.
func TestServerScriptBlocksTheSamePrivateNets(t *testing.T) {
	script, err := os.ReadFile("../../server/xray/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^PRIVATE_NETS_JSON='(\[.*\])'$`).FindSubmatch(script)
	if m == nil {
		t.Fatal("PRIVATE_NETS_JSON not found in server/xray/install.sh")
	}
	var nets []string
	if err := json.Unmarshal(m[1], &nets); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(nets, PrivateNets) {
		t.Errorf("server/xray/install.sh blocks %v, the Go reference %v", nets, PrivateNets)
	}
}

func TestRenderClientSocksAuth(t *testing.T) {
	out, err := RenderClientConfig(sample(), ClientOptions{SocksPort: 1080, TunFD: -1, SocksUser: "u", SocksPass: "p"})
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		Inbounds []struct {
			Settings struct {
				Auth     string `json:"auth"`
				Accounts []struct {
					User string `json:"user"`
					Pass string `json:"pass"`
				} `json:"accounts"`
			} `json:"settings"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(out, &cfg); err != nil {
		t.Fatal(err)
	}
	set := cfg.Inbounds[0].Settings
	if set.Auth != "password" || len(set.Accounts) != 1 || set.Accounts[0].User != "u" || set.Accounts[0].Pass != "p" {
		t.Fatalf("socks settings %+v", set)
	}
	if _, err := RenderClientConfig(sample(), ClientOptions{SocksPort: 1080, TunFD: -1, SocksUser: "u"}); err == nil {
		t.Fatal("a username without a password was accepted")
	}
	if _, err := RenderClientConfig(sample(), ClientOptions{SocksPort: 1080, TunFD: -1, SocksUser: strings.Repeat("u", 256), SocksPass: "p"}); err == nil {
		t.Fatal("a 256-byte username was accepted")
	}
}

func TestConfigsKeepNoAccessLog(t *testing.T) {
	client, err := RenderClientConfig(sample(), ClientOptions{SocksPort: 1080, TunFD: -1})
	if err != nil {
		t.Fatal(err)
	}
	server, err := RenderServerConfig(ServerOptions{
		Port: 443, ClientUUID: sample().Secret, Target: "www.example.com:443",
		ServerNames: []string{"www.example.com"}, PrivateKey: "KEY", ShortIDs: []string{"6ba85179e30d4fc2"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, out := range map[string][]byte{"client": client, "server": server} {
		var cfg struct {
			Log struct {
				Access string `json:"access"`
				DNSLog bool   `json:"dnsLog"`
			} `json:"log"`
		}
		if err := json.Unmarshal(out, &cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.Log.Access != "none" || cfg.Log.DNSLog {
			t.Errorf("%s log %+v: the access log must be off", name, cfg.Log)
		}
	}
}
