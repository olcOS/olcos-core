package xray

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	xlog "github.com/xtls/xray-core/common/log"

	"github.com/olcOS/olcos-core/engine"
)

type testHost struct {
	tun   int
	mu    sync.Mutex
	logs  []string
	notes []string
}

func (h *testHost) Protect(int) error { return nil }
func (h *testHost) TunFD() int        { return h.tun }
func (h *testHost) Log(_ int, msg string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.logs = append(h.logs, msg)
}
func (h *testHost) Notify(kind, payload string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.notes = append(h.notes, kind+":"+payload)
}

func testProfile() engine.Profile {
	return engine.Profile{
		Kind: engine.KindXray, Name: "t", Host: "203.0.113.1", Port: 443,
		Secret: "b831381d-6324-4d53-ad4f-8cda48b30811",
		Params: map[string]string{
			ParamSNI: "www.example.com", ParamFingerprint: "chrome",
			ParamPublicKey: "SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc", ParamShortID: "0123456789abcdef",
		},
	}
}

// TestStartStopOffline boots a real xray instance with a SOCKS inbound and no
// network access to the server: the listener must come up, Stats must read the
// counters, and Close must be idempotent.
func TestStartStopOffline(t *testing.T) {
	h := &testHost{tun: -1}
	sess, err := Engine{}.Start(context.Background(), testProfile(), h)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if sess.OwnsTun() {
		t.Fatal("OwnsTun should be false for the SOCKS variant")
	}
	addr := sess.SocksAddr()
	if !strings.HasPrefix(addr, "127.0.0.1:") {
		t.Fatalf("unexpected socks addr %q", addr)
	}
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("socks listener not reachable: %v", err)
	}
	_ = c.Close()
	st := sess.Stats()
	if !st.Connected || st.BytesUp != 0 || st.BytesDown != 0 {
		t.Fatalf("unexpected initial stats %+v", st)
	}
	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := sess.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if sess.Stats().Connected {
		t.Fatal("Connected must be false after Close")
	}
	if _, err := net.DialTimeout("tcp", addr, 500*time.Millisecond); err == nil {
		t.Fatal("socks listener still open after Close")
	}
	h.mu.Lock()
	joined := strings.Join(h.logs, "\n")
	h.mu.Unlock()
	if !strings.Contains(joined, "xray: started") {
		t.Fatalf("host did not receive start log; got:\n%s", joined)
	}
}

// TestHealthEventAfterCloseIsDropped replays a race that killed the packet
// tunnel: a log line captured the session just before Close, and its health
// event was sent after Close had closed the channel (a panic).
func TestHealthEventAfterCloseIsDropped(t *testing.T) {
	h := &testHost{tun: -1}
	sess, err := Engine{}.Start(context.Background(), testProfile(), h)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	sinkMu.RLock()
	capturedHost, captured := logSink, active
	sinkMu.RUnlock()
	if capturedHost == nil || captured == nil {
		t.Fatal("Start did not install the log sink")
	}
	if err := sess.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	h.mu.Lock()
	before := len(h.notes)
	h.mu.Unlock()
	handle(capturedHost, captured, &xlog.GeneralMessage{
		Severity: xlog.Severity_Warning,
		Content:  "proxy/vless/outbound: failed to find an available destination > dial tcp 203.0.113.1:443: connect: connection refused",
	})
	if _, open := <-captured.health; open {
		t.Fatal("a health event was queued after Close")
	}
	h.mu.Lock()
	after := len(h.notes)
	h.mu.Unlock()
	if after != before {
		t.Fatalf("host was notified of %d health events after Close", after-before)
	}
}

func TestStartRejectsInvalidProfile(t *testing.T) {
	p := testProfile()
	delete(p.Params, ParamPublicKey)
	if _, err := (Engine{}).Start(context.Background(), p, &testHost{tun: -1}); err == nil {
		t.Fatal("expected validation error without pbk")
	}
}

type authHost struct {
	testHost
	user, pass string
}

func (h *authHost) SocksAuth() (string, string) { return h.user, h.pass }

// socksGreet runs the SOCKS5 method negotiation (and, for method 2, the
// RFC 1929 exchange) and returns the method the listener chose and, when it
// chose username/password, the status of that exchange.
func socksGreet(t *testing.T, addr string, method byte, user, pass string) (chosen, status byte) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := c.Write([]byte{5, 1, method}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatalf("method reply: %v", err)
	}
	if reply[1] != 2 {
		return reply[1], 0xff
	}
	msg := append([]byte{1, byte(len(user))}, user...)
	msg = append(append(msg, byte(len(pass))), pass...)
	if _, err := c.Write(msg); err != nil {
		t.Fatalf("auth: %v", err)
	}
	if _, err := io.ReadFull(c, reply); err != nil {
		return 2, 0xff // a refused login may just close the connection
	}
	return 2, reply[1]
}

// TestSocksListenerRequiresTheHostsCredentials: with SocksAuth from the host,
// another local client cannot use the listener without the password.
func TestSocksListenerRequiresTheHostsCredentials(t *testing.T) {
	h := &authHost{testHost: testHost{tun: -1}, user: "olcos", pass: "s3cret-for-this-session"}
	sess, err := Engine{}.Start(context.Background(), testProfile(), h)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer sess.Close()
	addr := sess.SocksAddr()
	if chosen, _ := socksGreet(t, addr, 0, "", ""); chosen != 0xff {
		t.Fatalf("no-auth greeting: method %d accepted", chosen)
	}
	if _, status := socksGreet(t, addr, 2, "olcos", "wrong"); status == 0 {
		t.Fatal("a wrong password was accepted")
	}
	if chosen, status := socksGreet(t, addr, 2, "olcos", "s3cret-for-this-session"); chosen != 2 || status != 0 {
		t.Fatalf("the right password: method %d, status %d", chosen, status)
	}
}
