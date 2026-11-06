package agent

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// startTestServer wires the same listener/handler Serve uses, but with an
// injected state, on an ephemeral port. Returns the address, the pinned cert
// sha, and a stop func.
func startTestServer(t *testing.T, cfg *Config, st *State) (addr, certSHA string, stop func()) {
	t.Helper()
	certPEM, keyPEM, sha, err := generateCert("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	peek := &tlsPeekListener{Listener: ln, config: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	srv := &http.Server{Handler: newHandler(cfg, st)}
	go srv.Serve(peek)
	return ln.Addr().String(), sha, func() { _ = srv.Close() }
}

// TestPlainHTTPGetsNginx400: a plain-text HTTP request to the TLS port must get
// nginx's "plain HTTP to HTTPS port" 400, not a TLS error — so a probe sees an
// ordinary web server.
func TestPlainHTTPGetsNginx400(t *testing.T) {
	addr, _, stop := startTestServer(t, testConfig(), testState(nil))
	defer stop()

	c, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(c, "GET / HTTP/1.1\r\nHost: probe\r\n\r\n")
	data, _ := io.ReadAll(c)
	resp := string(data)
	if !strings.Contains(resp, "400 Bad Request") || !strings.Contains(resp, "HTTPS port") {
		t.Fatalf("want nginx plain-HTTP-to-HTTPS 400, got:\n%s", resp)
	}
	if !strings.Contains(resp, "Server: nginx") {
		t.Fatalf("400 should carry Server: nginx:\n%s", resp)
	}
}

// TestSlowClientDoesNotBlockAccept: a connection that opens but sends nothing
// must not stall new connections. The agent runs for days on a public port, so
// one silent (slowloris) socket cannot be allowed to block the accept path.
func TestSlowClientDoesNotBlockAccept(t *testing.T) {
	k := newTestKey(t)
	cfg := testConfig(k.device(RoleOwner))
	addr, _, stop := startTestServer(t, cfg, testState(map[string]string{"readiness": "ok"}))
	defer stop()

	// A silent connection, accepted first, that never sends a byte.
	slow, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	time.Sleep(100 * time.Millisecond) // let it be accepted first

	done := make(chan int, 1)
	go func() {
		client := &http.Client{
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
			Timeout:   8 * time.Second,
		}
		path := statusPath(cfg)
		req := k.sign(t, "GET", path, nil, time.Now(), "slow-block-nonce")
		r, _ := http.NewRequest("GET", "https://"+addr+path, nil)
		r.Header = req.Header
		resp, err := client.Do(r)
		if err != nil {
			done <- -1
			return
		}
		done <- resp.StatusCode
	}()

	select {
	case code := <-done:
		if code != 200 {
			t.Fatalf("signed request behind a slow client returned %d", code)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("a silent connection stalled the accept loop (signed request blocked > 4s)")
	}
}

// TestTLSSignedRequestEndToEnd: a real TLS client whose signed request is
// accepted, and whose pinned-cert check matches the sha the installer printed.
func TestTLSSignedRequestEndToEnd(t *testing.T) {
	k := newTestKey(t)
	cfg := testConfig(k.device(RoleOwner))
	addr, certSHA, stop := startTestServer(t, cfg, testState(map[string]string{"readiness": "ready"}))
	defer stop()

	var pinSeen string
	client := &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // we pin by leaf-cert sha, exactly like the app
			VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
				sum := sha256.Sum256(raw[0])
				pinSeen = hex.EncodeToString(sum[:])
				return nil
			},
		},
	}}
	path := statusPath(cfg)
	req := k.sign(t, "GET", path, nil, time.Now(), "e2e-nonce")
	url := "https://" + addr + path
	realReq, _ := http.NewRequest("GET", url, nil)
	realReq.Header = req.Header
	resp, err := client.Do(realReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("want 200, got %d: %s", resp.StatusCode, b)
	}
	if pinSeen != certSHA {
		t.Fatalf("pinned cert sha mismatch: client saw %s, installer printed %s", pinSeen, certSHA)
	}
	var out struct {
		Outputs map[string]string `json:"outputs"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out.Outputs["readiness"] != "ready" {
		t.Fatalf("status payload wrong: %+v", out)
	}
}

// flakyListener fails its first accepts the way an exhausted process does,
// then hands out conns until it is closed.
type flakyListener struct {
	mu     sync.Mutex
	fails  int
	conns  chan net.Conn
	closed chan struct{}
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if l.fails > 0 {
		l.fails--
		l.mu.Unlock()
		return nil, errors.New("accept tcp: too many open files")
	}
	l.mu.Unlock()
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *flakyListener) Close() error   { close(l.closed); return nil }
func (l *flakyListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

// A moment without file descriptors must not end serve: the loop backs off
// and keeps accepting; only a closed listener ends it.
func TestAcceptLoopOutlivesTemporaryErrors(t *testing.T) {
	fl := &flakyListener{fails: 3, conns: make(chan net.Conn, 1), closed: make(chan struct{})}
	peek := &tlsPeekListener{Listener: fl, config: &tls.Config{}}
	server, client := net.Pipe()
	defer client.Close()
	fl.conns <- server
	go func() { _, _ = client.Write([]byte{0x16}) }() // the first byte of a TLS handshake

	accepted := make(chan error, 1)
	go func() {
		c, err := peek.Accept()
		if c != nil {
			_ = c.Close()
		}
		accepted <- err
	}()
	select {
	case err := <-accepted:
		if err != nil {
			t.Fatalf("accept after temporary errors: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the accept loop gave up on a temporary error")
	}

	_ = fl.Close()
	if _, err := peek.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("a closed listener must end the loop, got %v", err)
	}
	if d := nextAcceptDelay(nextAcceptDelay(0)); d != 10*time.Millisecond {
		t.Fatalf("backoff %v, want 5 ms doubling", d)
	}
	if d := nextAcceptDelay(800 * time.Millisecond); d != time.Second {
		t.Fatalf("backoff %v, want the 1 s ceiling", d)
	}
}
