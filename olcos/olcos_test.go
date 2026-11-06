package olcos

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/olcOS/olcos-core/engine"
)

// slowEngine blocks in Start until release is closed, so a test can call Stop
// while an engine is booting.
type slowEngine struct {
	entered chan struct{}
	release chan struct{}
	closed  *atomic.Int32
}

func (slowEngine) Kind() engine.Kind { return "test-slow" }

func (e slowEngine) Start(context.Context, engine.Profile, engine.Host) (engine.Session, error) {
	close(e.entered)
	<-e.release
	return &fakeSession{closed: e.closed, health: make(chan engine.HealthEvent)}, nil
}

type fakeSession struct {
	closed *atomic.Int32
	health chan engine.HealthEvent
}

func (*fakeSession) SocksAddr() string                   { return "127.0.0.1:1" }
func (*fakeSession) OwnsTun() bool                       { return false }
func (*fakeSession) Stats() engine.Stats                 { return engine.Stats{} }
func (s *fakeSession) Health() <-chan engine.HealthEvent { return s.health }
func (s *fakeSession) Close() error {
	if s.closed.Add(1) == 1 {
		close(s.health)
	}
	return nil
}

// A Stop that arrives while the engine is still booting used to find no
// session, return, and leave the engine that came up afterwards running.
func TestStopDuringStartClosesTheNewSession(t *testing.T) {
	eng := slowEngine{entered: make(chan struct{}), release: make(chan struct{}), closed: new(atomic.Int32)}
	engine.Register(eng)
	rt := New()
	done := make(chan error, 1)
	go func() {
		_, err := rt.start(engine.Profile{Kind: eng.Kind(), Secret: "x"})
		done <- err
	}()
	<-eng.entered
	if err := rt.Stop(); err != nil {
		t.Fatalf("Stop during start: %v", err)
	}
	close(eng.release)
	select {
	case err := <-done:
		if !errors.Is(err, errStoppedDuringStart) {
			t.Fatalf("start returned %v, want errStoppedDuringStart", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("start did not return")
	}
	if eng.closed.Load() != 1 {
		t.Fatalf("the session that came up after Stop was closed %d times, want 1", eng.closed.Load())
	}
	rt.mu.Lock()
	sess, starting := rt.sess, rt.starting
	rt.mu.Unlock()
	if sess != nil || starting {
		t.Fatalf("runtime still holds a session (%v) or is starting (%v)", sess, starting)
	}
}

func decode(t *testing.T, s string) envelope {
	t.Helper()
	var e envelope
	if err := json.Unmarshal([]byte(s), &e); err != nil {
		t.Fatalf("bad envelope %q: %v", s, err)
	}
	return e
}

func TestInvokeVersionListsBothEngines(t *testing.T) {
	e := decode(t, New().Invoke("core.version", "{}"))
	if !e.OK || !strings.Contains(string(e.Result), `"olcrtc"`) || !strings.Contains(string(e.Result), `"xray"`) {
		t.Fatalf("unexpected: %+v", e)
	}
}

func TestInvokeParseThenRender(t *testing.T) {
	r := New()
	link := `{"link":"vless://8f3f2c1e-7a5b-4d2e-9c1a-0b6d5e4f3a21@203.0.113.10:443?security=reality&sni=www.example.com&pbk=PBK&sid=6ba85179e30d4fc2#n"}`
	e := decode(t, r.Invoke("profile.parse", link))
	if !e.OK {
		t.Fatalf("parse failed: %s", e.Error)
	}
	in := `{"profile":` + string(e.Result) + `,"socks_port":1080}`
	e2 := decode(t, r.Invoke("xray.render_client", in))
	if !e2.OK || !strings.Contains(string(e2.Result), "xtls-rprx-vision") {
		t.Fatalf("render failed: %+v", e2)
	}
}

func TestInvokeNeverPanics(t *testing.T) {
	r := New()
	for _, in := range []string{"", "null", "{", `{"link":123}`} {
		for _, m := range []string{"profile.parse", "profile.export", "xray.render_client", "xray.render_server", "nope"} {
			e := decode(t, r.Invoke(m, in))
			if e.OK {
				t.Errorf("%s(%q) unexpectedly ok", m, in)
			}
		}
	}
}

func TestEngineProbeTCP(t *testing.T) {
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
			c.Close()
		}
	}()
	port := l.Addr().(*net.TCPAddr).Port
	rt := New()
	in, _ := json.Marshal(map[string]any{
		"profile":    engine.Profile{Kind: engine.KindXray, Host: "127.0.0.1", Port: port, Secret: "x"},
		"timeout_ms": 2000,
	})
	var out struct {
		OK     bool `json:"ok"`
		Result struct {
			RTT int64 `json:"rtt_ms"`
		} `json:"result"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(rt.Invoke("engine.probe", string(in))), &out); err != nil {
		t.Fatal(err)
	}
	if !out.OK {
		t.Fatalf("probe failed: %s", out.Error)
	}
	if out.Result.RTT < 0 {
		t.Fatalf("negative rtt %d", out.Result.RTT)
	}
	// Closed port: connection refused within the timeout.
	l.Close()
	if err := json.Unmarshal([]byte(rt.Invoke("engine.probe", string(in))), &out); err != nil {
		t.Fatal(err)
	}
	if out.OK {
		t.Fatal("probe against a closed port must fail")
	}
}

func TestEnginePingRefusesWhatItCannotMeasure(t *testing.T) {
	rt := New()
	for _, in := range []string{
		`{}`,
		`{"profile":{"kind":"olcrtc","secret":"x"}}`,
		`{"uri":"vless://not-a-link"}`,
		`{`,
	} {
		if out := rt.Invoke("engine.ping", in); !strings.Contains(out, `"ok":false`) {
			t.Errorf("engine.ping(%s) = %s, want an error envelope", in, out)
		}
	}
}

func TestEngineStartRespectsSocksPort(t *testing.T) {
	// A wrong-kind profile fails before the engine boots; the port hint must
	// still have been recorded so the next start uses it.
	rt := New()
	in := `{"profile":{"kind":"bogus","secret":"x"},"socks_port":18080}`
	if out := rt.Invoke("engine.start", in); !strings.Contains(out, `"ok":false`) {
		t.Fatalf("expected failure, got %s", out)
	}
	rt.mu.Lock()
	got := rt.socksPort
	rt.mu.Unlock()
	if got != 18080 {
		t.Fatalf("socks port hint not recorded: %d", got)
	}
	h := &host{rt: rt}
	if h.SocksPort() != 18080 {
		t.Fatalf("host hint = %d", h.SocksPort())
	}
}

func TestEngineStartSetsSocksAuthEachTime(t *testing.T) {
	rt := New()
	h := &host{rt: rt}
	in := `{"profile":{"kind":"bogus","secret":"x"},"socks_port":18080,"socks_user":"u","socks_pass":"p"}`
	_ = rt.Invoke("engine.start", in)
	if u, p := h.SocksAuth(); u != "u" || p != "p" {
		t.Fatalf("socks auth not recorded: %q %q", u, p)
	}
	_ = rt.Invoke("engine.start", `{"profile":{"kind":"bogus","secret":"x"}}`)
	if u, p := h.SocksAuth(); u != "" || p != "" {
		t.Fatalf("a start without credentials kept the earlier ones: %q %q", u, p)
	}
}
