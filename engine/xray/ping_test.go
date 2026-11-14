package xray

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"

	"github.com/olcOS/olcos-core/profile"
)

func TestPingRefusesANonHTTPURL(t *testing.T) {
	if _, err := Ping(context.Background(), testProfile(), "ftp://example.com/"); err == nil {
		t.Fatal("expected an error for a non-http(s) URL")
	}
}

// A server that is not there must fail the ping (a TCP-connect probe would
// fail too here; the point is that Ping returns an error, not a latency).
func TestPingFailsWhenNothingAnswers(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close() // a closed port: connection refused
	p := testProfile()
	p.Host, p.Port = "127.0.0.1", port
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	started := time.Now()
	if _, err := Ping(ctx, p, ""); !errors.Is(err, ErrPingFailed) {
		t.Fatalf("Ping = %v, want ErrPingFailed", err)
	}
	if took := time.Since(started); took > 10*time.Second {
		t.Fatalf("a refused server took %s to report", took)
	}
}

// A server that accepts TCP but is not an Xray REALITY server passes a
// TCP-connect probe; the real ping must still fail.
func TestPingFailsAgainstAPlainTCPListener(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
				_, _ = c.Read(buf)
			}(c)
		}
	}()
	p := testProfile()
	p.Host, p.Port = "127.0.0.1", l.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if rtt, err := Ping(ctx, p, ""); err == nil {
		t.Fatalf("Ping through a non-REALITY listener reported %d ms", rtt)
	}
}

// slowListener holds every new connection back before its first byte is
// read, the way a path through a CDN is slow to come up and quick after.
type slowListener struct {
	net.Listener
	delay time.Duration
}

func (l slowListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &slowConn{Conn: c, wake: time.Now().Add(l.delay), closed: make(chan struct{})}, nil
}

type slowConn struct {
	net.Conn
	wake   time.Time
	closed chan struct{}
	once   sync.Once
}

func (c *slowConn) Read(b []byte) (int, error) {
	if d := time.Until(c.wake); d > 0 {
		select {
		case <-time.After(d):
		case <-c.closed:
		}
	}
	return c.Conn.Read(b)
}

func (c *slowConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func slowTarget(t *testing.T, delay time.Duration) (*http.Client, string) {
	t.Helper()
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	target.Listener = slowListener{Listener: target.Listener, delay: delay}
	target.Start()
	t.Cleanup(target.Close)
	transport := &http.Transport{TLSHandshakeTimeout: pingWarmupTimeout, ResponseHeaderTimeout: pingWarmupTimeout}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: transport}, target.URL
}

// A path that takes two seconds to come up is a slow server, not a dead one:
// the warm-up waits for it, and the samples then measure the warmed path.
func TestMeasureWaitsForASlowPathToComeUp(t *testing.T) {
	client, target := slowTarget(t, 2*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rtt, err := measure(ctx, client, target)
	if err != nil {
		t.Fatalf("measure = %v, want a latency", err)
	}
	if rtt > 1000 {
		t.Fatalf("measure = %d ms: the samples must run over the warmed connection, not set the path up again", rtt)
	}
}

// A path that never comes up is named after the warm-up and one more try,
// not after every sample has waited its turn.
func TestMeasureGivesUpOnADeadPathAfterOneMoreTry(t *testing.T) {
	client, target := slowTarget(t, 30*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	started := time.Now()
	if _, err := measure(ctx, client, target); !errors.Is(err, ErrPingFailed) {
		t.Fatalf("measure = %v, want ErrPingFailed", err)
	}
	took := time.Since(started)
	if limit := pingWarmupTimeout + pingSampleTimeout + time.Second; took > limit {
		t.Fatalf("a dead path took %s to report, want under %s", took, limit)
	}
}

// End to end against a real server: OLCOS_TEST_VLESS=vless://… go test -run Live
func TestPingLive(t *testing.T) {
	link := strings.TrimSpace(os.Getenv("OLCOS_TEST_VLESS"))
	if link == "" {
		t.Skip("OLCOS_TEST_VLESS not set")
	}
	p, err := profile.Parse(link)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	rtt, err := Ping(ctx, p, "")
	if err != nil {
		t.Fatalf("Ping: %v", err)
	}
	t.Logf("round trip through the tunnel: %d ms", rtt)
	if rtt <= 0 {
		t.Fatalf("rtt = %d", rtt)
	}
}

// A probe whose local port was taken between its choice and its use must be
// told apart from a server that does not work: the start is tried again on
// another port. This pins the failure Xray reports for a taken port.
func TestAStartOnATakenPortIsRecognised(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port
	raw, err := RenderClientConfig(testProfile(), ClientOptions{SocksPort: port, TunFD: -1, LogLevel: "none"})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := core.LoadConfig("json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	inst, err := core.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer inst.Close()
	err = inst.Start()
	if err == nil {
		t.Fatal("an instance started on a port that is taken")
	}
	if !portTaken(fmt.Errorf("xray: start: %w", err)) {
		t.Fatalf("a taken port is not recognised: %v", err)
	}
	if portTaken(ErrPingFailed) {
		t.Fatal("a server that does not answer reads as a taken port")
	}
}

// The app looks through a list with several pings at once: each has its own
// client and its own port, and each names its own server.
func TestPingsSideBySideEachReportTheirOwnServer(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close() // a closed port: connection refused
	const side = 6
	errs := make(chan error, side)
	for i := 0; i < side; i++ {
		go func() {
			p := testProfile()
			p.Host, p.Port = "127.0.0.1", port
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			_, err := Ping(ctx, p, "")
			errs <- err
		}()
	}
	for i := 0; i < side; i++ {
		if err := <-errs; !errors.Is(err, ErrPingFailed) {
			t.Fatalf("Ping = %v, want ErrPingFailed", err)
		}
	}
}
