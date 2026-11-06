package xray

import (
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	cases := map[string]string{
		"[Warning] transport/internet/reality: REALITY: processed invalid connection":                                                 ReasonKeyMismatch,
		"[Warning] proxy/vless/outbound: failed to find an available destination > dial tcp 1.2.3.4:443: connect: connection refused": ReasonHostUnreachable,
		"[Info] app/proxyman/outbound: failed to process outbound traffic > dial tcp 1.2.3.4:443: i/o timeout":                        ReasonTimedOut,
		"[Info] app/proxyman/outbound: failed to process outbound traffic > dial tcp: lookup example.invalid: no such host":           ReasonDNSUnreachable,
		"[Info] app/proxyman/outbound: failed to process outbound traffic > connect: network is unreachable":                          ReasonNetworkDown,
		"[Info] app/proxyman/outbound: failed to process outbound traffic > read tcp: connection reset by peer":                       ReasonCarrierRejected,
	}
	for in, want := range cases {
		got, ok := classify(in)
		if !ok || got != want {
			t.Errorf("classify(%q) = %q,%v want %q", in, got, ok, want)
		}
	}
	if r, ok := classify("[Info] from tcp:127.0.0.1:1 accepted tcp:example.com:443 [socks-in >> proxy]"); ok {
		t.Errorf("info line must not classify, got %q", r)
	}
}

// A local app closing or idling on its SOCKS connection is routine traffic,
// not a verdict on the server.
func TestClassifyIgnoresTheLocalSide(t *testing.T) {
	for _, line := range []string{
		"[Info] [1] app/proxyman/inbound: connection ends > proxy/socks: failed to transport all TCP response > write tcp 127.0.0.1:10808->127.0.0.1:53211: write: broken pipe",
		"[Info] [2] proxy/socks: failed to read request > read tcp 127.0.0.1:10808->127.0.0.1:53212: i/o timeout",
		"[Info] [3] app/proxyman/inbound: connection ends > read tcp [::1]:10808->[::1]:53213: read: connection reset by peer",
	} {
		if r, ok := classify(line); ok {
			t.Errorf("classify(%q) = %q, want no reason", line, r)
		}
	}
	server := "[Info] [4] app/proxyman/outbound: failed to process outbound traffic > proxy/vless/outbound: failed to find an available destination > write tcp 192.0.2.10:50000->203.0.113.1:443: write: broken pipe"
	if r, ok := classify(server); !ok || r != ReasonCarrierRejected {
		t.Errorf("server-side broken pipe = %q,%v want %q", r, ok, ReasonCarrierRejected)
	}
}

func TestHealthEmitterDebounce(t *testing.T) {
	now := time.Unix(0, 0)
	e := newHealthEmitter(5 * time.Second)
	e.now = func() time.Time { return now }
	if !e.offer(ReasonTimedOut) {
		t.Fatal("first offer must pass")
	}
	if e.offer(ReasonTimedOut) {
		t.Fatal("repeat inside window must be dropped")
	}
	if !e.offer(ReasonKeyMismatch) {
		t.Fatal("different reason must pass")
	}
	now = now.Add(6 * time.Second)
	if !e.offer(ReasonTimedOut) {
		t.Fatal("offer after window must pass")
	}
}
