package xray

import (
	"strings"
	"sync"
	"time"

	"github.com/olcOS/olcos-core/engine"
)

// HealthReason raw values shared with the olcos-ios Swift enum
// (App/Models/HealthFailure.swift). Never rename; add new ones on both sides.
const (
	ReasonKeyMismatch     = "keyMismatch"
	ReasonHostUnreachable = "hostUnreachable"
	ReasonTimedOut        = "timedOut"
	ReasonNetworkDown     = "networkDown"
	ReasonDNSUnreachable  = "dnsUnreachable"
	ReasonCarrierRejected = "carrierRejected"
)

// classify maps an xray-core warning/error line to a HealthReason. Order
// matters: the first matching rule wins. Substrings come from xray-core
// transport/internet/reality/reality.go, proxy/vless/outbound/outbound.go and
// Go's net package error texts.
//
// xray-core logs dial failures at INFO ("failed to process outbound traffic >
// failed to find an available destination > dial tcp …: connection refused",
// app/proxyman/outbound/handler.go), so the client runs with loglevel info and
// only lines carrying a failure marker are inspected.
func classify(msg string) (string, bool) {
	m := strings.ToLower(msg)
	if !strings.Contains(m, "reality:") && !strings.Contains(m, "failed to") {
		return "", false
	}
	switch {
	// Wrong pbk/shortId, a plain TLS server instead of REALITY, or an
	// on-path MITM: the client received the target's real certificate and the
	// REALITY verification failed.
	case strings.Contains(m, "reality: received real certificate"),
		strings.Contains(m, "reality: processed invalid connection"),
		strings.Contains(m, "reality: sharedkey == nil"),
		strings.Contains(m, "reality: publickey == nil"):
		return ReasonKeyMismatch, true
	// Failures between a local app and our SOCKS inbound — an app closing its
	// connection early ("write tcp 127.0.0.1:…: broken pipe") or idling past
	// the handshake ("read tcp 127.0.0.1:…: i/o timeout") — are routine and
	// say nothing about the server; the outbound logs its own failures.
	case isLocalSide(m):
		return "", false
	case strings.Contains(m, "no such host"),
		strings.Contains(m, "server misbehaving"),
		strings.Contains(m, "failed to lookup"):
		return ReasonDNSUnreachable, true
	case strings.Contains(m, "network is unreachable"),
		strings.Contains(m, "no route to host"):
		return ReasonNetworkDown, true
	case strings.Contains(m, "i/o timeout"),
		strings.Contains(m, "deadline exceeded"),
		strings.Contains(m, "handshake timeout"):
		return ReasonTimedOut, true
	case strings.Contains(m, "connection refused"):
		return ReasonHostUnreachable, true
	// A reset after the ClientHello is what RU DPI does to unwanted TLS
	// (docs/architecture.md); the "carrier" here is the camouflage itself.
	case strings.Contains(m, "connection reset by peer"),
		strings.Contains(m, "broken pipe"),
		strings.Contains(m, "eof") && strings.Contains(m, "failed to find an available destination"):
		return ReasonCarrierRejected, true
	}
	return "", false
}

// isLocalSide reports a log line about the loopback SOCKS inbound rather than
// the connection to the server.
func isLocalSide(m string) bool {
	return strings.Contains(m, "127.0.0.1") || strings.Contains(m, "[::1]") ||
		strings.Contains(m, "app/proxyman/inbound") || strings.Contains(m, "proxy/socks")
}

// healthEmitter debounces repeated reasons so a burst of failing dials does
// not flood the UI: the same reason is forwarded at most once per window.
type healthEmitter struct {
	mu     sync.Mutex
	last   map[string]time.Time
	window time.Duration
	now    func() time.Time
}

func newHealthEmitter(window time.Duration) *healthEmitter {
	return &healthEmitter{last: map[string]time.Time{}, window: window, now: time.Now}
}

// offer returns true when the event should be delivered.
func (e *healthEmitter) offer(reason string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	t := e.now()
	if prev, ok := e.last[reason]; ok && t.Sub(prev) < e.window {
		return false
	}
	e.last[reason] = t
	return true
}

// deliver pushes ev into ch without blocking; a full channel drops the event
// (the UI only needs the latest state, and Notify still receives every one).
func deliver(ch chan engine.HealthEvent, ev engine.HealthEvent) {
	select {
	case ch <- ev:
	default:
	}
}
