package profile

import (
	"encoding/base64"
	"testing"

	"github.com/olcOS/olcos-core/engine"
	"github.com/olcOS/olcos-core/engine/xray"
)

const sampleVLESS = "vless://8f3f2c1e-7a5b-4d2e-9c1a-0b6d5e4f3a21@203.0.113.10:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.example.com&fp=chrome&pbk=SOpt6JuKzZbOIhVMlcQEP5BhNJbdETn8QlBWL9vtyw0&sid=6ba85179e30d4fc2&spx=%2F&type=tcp#olcOS%20test"

func TestParseVLESSRoundTrip(t *testing.T) {
	p, err := ParseVLESS(sampleVLESS)
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != engine.KindXray || p.Host != "203.0.113.10" || p.Port != 443 {
		t.Fatalf("bad endpoint: %+v", p)
	}
	if p.Name != "olcOS test" || p.Params["sni"] != "www.example.com" || p.Params["spx"] != "/" {
		t.Fatalf("bad params: %+v", p)
	}
	if err := xray.ValidateProfile(p); err != nil {
		t.Fatalf("profile should be valid for xray engine: %v", err)
	}
	out, err := ExportVLESS(p)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := ParseVLESS(out)
	if err != nil {
		t.Fatalf("re-parse %q: %v", out, err)
	}
	if p2.Secret != p.Secret || p2.Params["pbk"] != p.Params["pbk"] || p2.Params["sid"] != p.Params["sid"] || p2.Name != p.Name {
		t.Fatalf("round trip mismatch:\n%+v\n%+v", p, p2)
	}
}

func TestParseVLESSRejects(t *testing.T) {
	cases := map[string]string{
		"duplicate key": "vless://8f3f2c1e-7a5b-4d2e-9c1a-0b6d5e4f3a21@h:443?security=reality&sni=a&sni=b",
		"tls security":  "vless://8f3f2c1e-7a5b-4d2e-9c1a-0b6d5e4f3a21@h:443?security=tls&sni=a",
		"no port":       "vless://8f3f2c1e-7a5b-4d2e-9c1a-0b6d5e4f3a21@h?security=reality",
		"encryption":    "vless://8f3f2c1e-7a5b-4d2e-9c1a-0b6d5e4f3a21@h:443?security=reality&encryption=aes",
	}
	for name, raw := range cases {
		if _, err := ParseVLESS(raw); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestParseVLESSIPv6Export(t *testing.T) {
	p := engine.Profile{Kind: engine.KindXray, Host: "2001:db8::1", Port: 443,
		Secret: "8f3f2c1e-7a5b-4d2e-9c1a-0b6d5e4f3a21", Params: map[string]string{"pbk": "k", "sni": "s"}}
	out, err := ExportVLESS(p)
	if err != nil {
		t.Fatal(err)
	}
	want := "vless://8f3f2c1e-7a5b-4d2e-9c1a-0b6d5e4f3a21@[2001:db8::1]:443?encryption=none&security=reality&sni=s&pbk=k"
	if out != want {
		t.Fatalf("got %q want %q", out, want)
	}
}

func TestParseOlcrtc(t *testing.T) {
	p, err := ParseOlcrtc("olcrtc://jitsi?smux,mtu=1200@room-abc#KEY123%client9$My%20VPS")
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != engine.KindOlcrtc || p.Host != "jitsi" || p.Room != "room-abc" || p.Secret != "KEY123" {
		t.Fatalf("bad profile %+v", p)
	}
	if p.Params["transport"] != "smux,mtu=1200" || p.Params["clientID"] != "client9" || p.Name != "My VPS" {
		t.Fatalf("bad params %+v", p)
	}
	if _, err := ParseOlcrtc("olcrtc://jitsi@room"); err == nil {
		t.Fatal("missing key must fail")
	}
}

func TestParseSubscriptionBodyBase64(t *testing.T) {
	plain := sampleVLESS + "\nolcrtc://telemost?@room#K\n\nnot-a-link\n"
	body := base64.StdEncoding.EncodeToString([]byte(plain))
	ps, errs := ParseSubscriptionBody(body)
	if len(ps) != 2 {
		t.Fatalf("want 2 profiles, got %d (%v)", len(ps), errs)
	}
	if len(errs) != 1 {
		t.Fatalf("want 1 error, got %v", errs)
	}
	if ps[0].Kind != engine.KindXray || ps[1].Kind != engine.KindOlcrtc {
		t.Fatalf("kinds: %v %v", ps[0].Kind, ps[1].Kind)
	}
}
