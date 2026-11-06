package xray

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

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
