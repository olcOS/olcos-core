package xray

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"

	"github.com/olcOS/olcos-core/engine"
)

// A certificate for one name, signed by itself, as PEM lines the way Xray's
// JSON takes them.
func testCert(t *testing.T, name string) (cert, key []string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	lines := func(kind string, b []byte) []string {
		return strings.Split(strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: b}))), "\n")
	}
	return lines("CERTIFICATE", der), lines("EC PRIVATE KEY", keyDER)
}

func startXray(t *testing.T, cfg any) {
	t.Helper()
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := core.LoadConfig("json", bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	inst, err := core.New(loaded)
	if err != nil {
		t.Fatalf("new instance: %v", err)
	}
	if err := inst.Start(); err != nil {
		_ = inst.Close()
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() { _ = inst.Close() })
}

// A VLESS server behind TLS on loopback, the way a server behind a CDN looks
// to a client, and the config this package renders for a link to it. trust
// says whether the client knows the server's certificate.
func throughTLSServer(t *testing.T, network string, server map[string]any, link map[string]string, certName string, trust bool) (*http.Client, string) {
	t.Helper()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)

	const id = "b831381d-6324-4d53-ad4f-8cda48b30811"
	cert, key := testCert(t, certName)
	serverPort, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	serverStream := map[string]any{
		"network": network, "security": "tls",
		"tlsSettings": map[string]any{"certificates": []any{map[string]any{"certificate": cert, "key": key}}},
	}
	for k, v := range server {
		serverStream[k] = v
	}
	startXray(t, map[string]any{
		"log": map[string]any{"loglevel": "none"},
		"inbounds": []any{map[string]any{
			"listen": "127.0.0.1", "port": serverPort, "protocol": "vless",
			"settings":       map[string]any{"clients": []any{map[string]any{"id": id}}, "decryption": "none"},
			"streamSettings": serverStream,
		}},
		// Xray does not proxy to loopback unless told to, and the target of
		// this test is there.
		"outbounds": []any{map[string]any{
			"protocol": "freedom",
			"settings": map[string]any{"finalRules": []any{map[string]any{"action": "allow"}}},
		}},
	})

	params := map[string]string{ParamSecurity: SecurityTLS, ParamNetwork: network}
	for k, v := range link {
		params[k] = v
	}
	p := engine.Profile{Kind: engine.KindXray, Name: "t", Host: "127.0.0.1", Port: serverPort, Secret: id, Params: params}
	socksPort, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := RenderClientConfig(p, ClientOptions{SocksPort: socksPort, TunFD: -1, LogLevel: "none"})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	var client map[string]any
	if err := json.Unmarshal(raw, &client); err != nil {
		t.Fatal(err)
	}
	if trust {
		// The one thing the test adds to the rendered config: the test
		// certificate as an authority, since no public one signed it.
		tls := client["outbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)
		tls["certificates"] = []any{map[string]any{"usage": "verify", "certificate": cert}}
	}
	startXray(t, client)

	transport := &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "socks5", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(socksPort))}),
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport, Timeout: 10 * time.Second}, target.URL
}

func get(client *http.Client, target string) (int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// Each transport a public list uses must carry a request end to end: the
// rendered client config against a real Xray server, both on loopback.
func TestTLSTransportsCarryARequest(t *testing.T) {
	const name = "cdn.test"
	cases := []struct {
		network string
		server  map[string]any
		link    map[string]string
	}{
		{"tcp", nil, map[string]string{ParamSNI: name}},
		{"ws", map[string]any{"wsSettings": map[string]any{"path": "/ray"}},
			map[string]string{ParamSNI: name, ParamHost: name, ParamPath: "/ray?ed=2048", ParamALPN: "http%252F1.1"}},
		// No sni in the link: the Host header names the certificate.
		{"ws", map[string]any{"wsSettings": map[string]any{"path": "/"}}, map[string]string{ParamHost: name}},
		{"httpupgrade", map[string]any{"httpupgradeSettings": map[string]any{"path": "/up"}},
			map[string]string{ParamSNI: name, ParamHost: name, ParamPath: "/up"}},
		{"grpc", map[string]any{"grpcSettings": map[string]any{"serviceName": "tunnel"}},
			map[string]string{ParamSNI: name, ParamServiceName: "tunnel", ParamMode: "gun"}},
		{"xhttp", map[string]any{"xhttpSettings": map[string]any{"path": "/x"}},
			map[string]string{ParamSNI: name, ParamHost: name, ParamPath: "/x", ParamMode: "auto", ParamExtra: `{"xPaddingBytes":"100-1000"}`}},
	}
	for _, tc := range cases {
		t.Run(tc.network, func(t *testing.T) {
			client, target := throughTLSServer(t, tc.network, tc.server, tc.link, name, true)
			status, err := get(client, target)
			if err != nil {
				t.Fatalf("request through %s: %v", tc.network, err)
			}
			if status != http.StatusNoContent {
				t.Fatalf("status %d through %s", status, tc.network)
			}
		})
	}
}

// The certificate is checked whatever a link asks for: one nobody vouches
// for, or one for another name, carries nothing.
func TestTLSRefusesACertificateItCannotVerify(t *testing.T) {
	ws := map[string]any{"wsSettings": map[string]any{"path": "/ray"}}
	cases := []struct {
		name     string
		link     map[string]string
		certName string
		trust    bool
	}{
		{"nobody vouches for it", map[string]string{ParamSNI: "cdn.test", ParamPath: "/ray", "allowInsecure": "1", "insecure": "1"}, "cdn.test", false},
		{"it names another server", map[string]string{ParamSNI: "cdn.test", ParamPath: "/ray"}, "other.test", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, target := throughTLSServer(t, "ws", ws, tc.link, tc.certName, tc.trust)
			if status, err := get(client, target); err == nil {
				t.Fatalf("the request went through with status %d", status)
			}
		})
	}
}
