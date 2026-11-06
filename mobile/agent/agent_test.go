package agent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// --- helpers ---------------------------------------------------------------

type testKey struct {
	priv *ecdsa.PrivateKey
	spki []byte
	id   string
}

func newTestKey(t *testing.T) testKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{priv: priv, spki: spki, id: deviceIDFromSPKI(spki)}
}

func (k testKey) device(role Role) Device {
	return Device{
		ID:        k.id,
		PublicKey: base64.StdEncoding.EncodeToString(k.spki),
		Name:      "test",
		Role:      role,
		AddedAt:   time.Now().Unix(),
	}
}

// sign builds a signed request against handler h for the given method/path.
func (k testKey) sign(t *testing.T, method, pathQuery string, body []byte, now time.Time, nonce string) *http.Request {
	t.Helper()
	ts := strconv.FormatInt(now.Unix(), 10)
	canon := canonicalString(method, pathQuery, ts, nonce, body)
	digest := sha256.Sum256([]byte(canon))
	sig, err := ecdsa.SignASN1(rand.Reader, k.priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, pathQuery, bytes.NewReader(body))
	req.Header.Set("X-Olc-Device", k.id)
	req.Header.Set("X-Olc-Time", ts)
	req.Header.Set("X-Olc-Nonce", nonce)
	req.Header.Set("X-Olc-Sig", base64.RawURLEncoding.EncodeToString(sig))
	req.RemoteAddr = "203.0.113.9:40000"
	return req
}

func testConfig(devices ...Device) *Config {
	return &Config{
		Port:    28000,
		Prefix:  "abcdefghijklmnopqrstuv",
		CertSHA: "00",
		Devices: devices,
		Scripts: map[string]string{"readiness": "echo ok"},
	}
}

// a state whose scripts never touch the OS: the runner echoes a canned map.
func testState(outputs map[string]string) *State {
	s := newState(nil, 0)
	s.setOutputs(outputs)
	return s
}

func do(h http.Handler, req *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// --- canonical string ------------------------------------------------------

func TestCanonicalString(t *testing.T) {
	body := []byte(`{"a":1}`)
	bh := sha256.Sum256(body)
	want := "POST\n/p/v1/exec\n1700000000\nnonce123\n" + hex.EncodeToString(bh[:])
	got := canonicalString("POST", "/p/v1/exec", "1700000000", "nonce123", body)
	if got != want {
		t.Fatalf("canonical mismatch:\n got %q\nwant %q", got, want)
	}
	// empty body hashes the empty string
	eh := sha256.Sum256(nil)
	wantEmpty := "GET\n/p/v1/status\n1\nn\n" + hex.EncodeToString(eh[:])
	if got := canonicalString("GET", "/p/v1/status", "1", "n", nil); got != wantEmpty {
		t.Fatalf("empty-body canonical mismatch:\n got %q\nwant %q", got, wantEmpty)
	}
}

// --- auth ------------------------------------------------------------------

func statusPath(c *Config) string { return "/" + c.Prefix + "/v1/status" }

func TestValidSignatureAccepted(t *testing.T) {
	k := newTestKey(t)
	cfg := testConfig(k.device(RoleOwner))
	h := newHandler(cfg, testState(map[string]string{"readiness": "ok"}))
	req := k.sign(t, "GET", statusPath(cfg), nil, time.Now(), "nonce-ok-1")
	rec := do(h, req)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Version uint64            `json:"version"`
		At      int64             `json:"at"`
		Outputs map[string]string `json:"outputs"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Outputs["readiness"] != "ok" {
		t.Fatalf("status outputs wrong: %+v", resp)
	}
}

func TestWrongKeyRejected(t *testing.T) {
	registered := newTestKey(t)
	attacker := newTestKey(t)
	cfg := testConfig(registered.device(RoleOwner))
	h := newHandler(cfg, testState(nil))
	// attacker signs but presents the registered device id
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "n-wrong-key"
	canon := canonicalString("GET", statusPath(cfg), ts, nonce, nil)
	digest := sha256.Sum256([]byte(canon))
	sig, _ := ecdsa.SignASN1(rand.Reader, attacker.priv, digest[:])
	req := httptest.NewRequest("GET", statusPath(cfg), nil)
	req.Header.Set("X-Olc-Device", registered.id)
	req.Header.Set("X-Olc-Time", ts)
	req.Header.Set("X-Olc-Nonce", nonce)
	req.Header.Set("X-Olc-Sig", base64.RawURLEncoding.EncodeToString(sig))
	req.RemoteAddr = "203.0.113.9:1"
	rec := do(h, req)
	assert404(t, rec)
}

func TestStaleTimeRejected(t *testing.T) {
	k := newTestKey(t)
	cfg := testConfig(k.device(RoleOwner))
	h := newHandler(cfg, testState(nil))
	req := k.sign(t, "GET", statusPath(cfg), nil, time.Now().Add(-10*time.Minute), "n-stale")
	rec := do(h, req)
	assert404(t, rec)
}

func TestReplayedNonceRejected(t *testing.T) {
	k := newTestKey(t)
	cfg := testConfig(k.device(RoleOwner))
	h := newHandler(cfg, testState(map[string]string{"readiness": "ok"}))
	now := time.Now()
	first := k.sign(t, "GET", statusPath(cfg), nil, now, "n-replay")
	if rec := do(h, first); rec.Code != 200 {
		t.Fatalf("first use should pass, got %d", rec.Code)
	}
	// same nonce again (fresh signature, same nonce) → rejected
	second := k.sign(t, "GET", statusPath(cfg), nil, now, "n-replay")
	rec := do(h, second)
	assert404(t, rec)
}

func TestUnknownPathIs404(t *testing.T) {
	k := newTestKey(t)
	cfg := testConfig(k.device(RoleOwner))
	h := newHandler(cfg, testState(nil))
	// a validly-signed request to a path outside the prefix
	req := k.sign(t, "GET", "/admin", nil, time.Now(), "n-badpath")
	rec := do(h, req)
	assert404(t, rec)
}

func TestUnsignedRequestIs404(t *testing.T) {
	cfg := testConfig()
	h := newHandler(cfg, testState(nil))
	req := httptest.NewRequest("GET", statusPath(cfg), nil)
	req.RemoteAddr = "203.0.113.9:2"
	rec := do(h, req)
	assert404(t, rec)
}

// the camouflage 404 for a bad path and for a bad signature must be
// indistinguishable (same status, same meaningful headers, same body).
func TestCamouflageIndistinguishable(t *testing.T) {
	k := newTestKey(t)
	cfg := testConfig(k.device(RoleOwner))
	h := newHandler(cfg, testState(nil))

	badPath := k.sign(t, "GET", "/nope", nil, time.Now(), "n-cam-1")
	badSig := httptest.NewRequest("GET", statusPath(cfg), nil)
	badSig.Header.Set("X-Olc-Device", k.id)
	badSig.Header.Set("X-Olc-Time", strconv.FormatInt(time.Now().Unix(), 10))
	badSig.Header.Set("X-Olc-Nonce", "n-cam-2")
	badSig.Header.Set("X-Olc-Sig", base64.RawURLEncoding.EncodeToString([]byte("garbage")))
	badSig.RemoteAddr = "203.0.113.9:3"

	r1 := do(h, badPath)
	r2 := do(h, badSig)
	if r1.Code != 404 || r2.Code != 404 {
		t.Fatalf("both must be 404, got %d and %d", r1.Code, r2.Code)
	}
	if r1.Body.String() != r2.Body.String() {
		t.Fatalf("bodies differ:\n%q\n%q", r1.Body.String(), r2.Body.String())
	}
	for _, hdr := range []string{"Server", "Content-Type", "Content-Length"} {
		if r1.Header().Get(hdr) != r2.Header().Get(hdr) {
			t.Fatalf("header %s differs: %q vs %q", hdr, r1.Header().Get(hdr), r2.Header().Get(hdr))
		}
	}
	if r1.Header().Get("Server") != "nginx" {
		t.Fatalf("Server header should be nginx, got %q", r1.Header().Get("Server"))
	}
	if !strings.Contains(r1.Body.String(), "404 Not Found") {
		t.Fatalf("body should look like nginx 404: %q", r1.Body.String())
	}
}

// --- roles -----------------------------------------------------------------

func TestMemberCannotExec(t *testing.T) {
	k := newTestKey(t)
	cfg := testConfig(k.device(RoleMember))
	h := newHandler(cfg, testState(nil))
	body := []byte(`{"script":"ZWNobyBoaQ==","timeout":5}`)
	req := k.sign(t, "POST", "/"+cfg.Prefix+"/v1/exec", body, time.Now(), "n-exec-member")
	rec := do(h, req)
	assert404(t, rec)
}

func TestMemberCannotPutScripts(t *testing.T) {
	k := newTestKey(t)
	cfg := testConfig(k.device(RoleMember))
	h := newHandler(cfg, testState(nil))
	body := []byte(`{"scripts":{"readiness":"echo ok"}}`)
	req := k.sign(t, "PUT", "/"+cfg.Prefix+"/v1/scripts", body, time.Now(), "n-put-member")
	rec := do(h, req)
	assert404(t, rec)
}

func TestMemberCanRestartRoom(t *testing.T) {
	k := newTestKey(t)
	cfg := testConfig(k.device(RoleMember))
	st := testState(nil)
	var gotAction, gotContainer string
	st.roomAction = func(container, action string) error {
		gotContainer, gotAction = container, action
		return nil
	}
	h := newHandler(cfg, st)
	path := "/" + cfg.Prefix + "/v1/rooms/olcrtc-server-abcd1234/restart"
	req := k.sign(t, "POST", path, nil, time.Now(), "n-restart")
	rec := do(h, req)
	if rec.Code != 200 {
		t.Fatalf("member restart should pass, got %d body=%s", rec.Code, rec.Body.String())
	}
	if gotContainer != "olcrtc-server-abcd1234" || gotAction != "restart" {
		t.Fatalf("roomAction got %q %q", gotContainer, gotAction)
	}
}

// --- container name validation --------------------------------------------

func TestContainerNameValidation(t *testing.T) {
	good := []string{"olcrtc-server-abcd1234", "olcrtc-server-abcd1234-salutejazz", "olcos-xray-wxyz5678"}
	bad := []string{"olcrtc-server", "nginx", "olcrtc-server-../etc", "olcrtc-server-A", "", "olcos-xray-", "rm -rf"}
	for _, c := range good {
		if !validContainer(c) {
			t.Errorf("want valid: %q", c)
		}
	}
	for _, c := range bad {
		if validContainer(c) {
			t.Errorf("want invalid: %q", c)
		}
	}
}

// --- state version & long poll ---------------------------------------------

func TestVersionBumpsOnlyOnChange(t *testing.T) {
	s := newState(nil, 0)
	s.setOutputs(map[string]string{"readiness": "a"})
	v1 := s.Version()
	s.setOutputs(map[string]string{"readiness": "a"}) // identical
	if s.Version() != v1 {
		t.Fatalf("version bumped on identical outputs: %d → %d", v1, s.Version())
	}
	s.setOutputs(map[string]string{"readiness": "b"}) // changed
	if s.Version() <= v1 {
		t.Fatalf("version did not bump on change: %d → %d", v1, s.Version())
	}
}

func TestEventsReturnOnChange(t *testing.T) {
	s := newState(nil, 0)
	s.setOutputs(map[string]string{"x": "1"})
	start := s.Version()
	go func() {
		time.Sleep(20 * time.Millisecond)
		s.setOutputs(map[string]string{"x": "2"})
	}()
	v := s.waitForChange(start, 2*time.Second)
	if v <= start {
		t.Fatalf("waitForChange should return a newer version, got %d (start %d)", v, start)
	}
}

func TestEventsReturnOnTimeout(t *testing.T) {
	s := newState(nil, 0)
	s.setOutputs(map[string]string{"x": "1"})
	start := s.Version()
	t0 := time.Now()
	v := s.waitForChange(start, 60*time.Millisecond)
	if time.Since(t0) < 40*time.Millisecond {
		t.Fatalf("returned too early, not a real timeout")
	}
	if v != start {
		t.Fatalf("timeout should return the same version, got %d (start %d)", v, start)
	}
}

func TestEventsImmediateWhenBehind(t *testing.T) {
	s := newState(nil, 0)
	s.setOutputs(map[string]string{"x": "1"})
	s.setOutputs(map[string]string{"x": "2"})
	cur := s.Version()
	t0 := time.Now()
	v := s.waitForChange(cur-1, 5*time.Second) // caller is behind → return at once
	if time.Since(t0) > 500*time.Millisecond {
		t.Fatalf("should return immediately when caller is behind")
	}
	if v != cur {
		t.Fatalf("want current version %d, got %d", cur, v)
	}
}

// --- camouflage body size caps (status) ------------------------------------

func TestStatusOutputCapped(t *testing.T) {
	big := strings.Repeat("x", 40*1024)
	s := testState(map[string]string{"readiness": big})
	capped := s.statusOutputs()
	if len(capped["readiness"]) > maxOutputBytes {
		t.Fatalf("output not capped: %d > %d", len(capped["readiness"]), maxOutputBytes)
	}
}

// --- init / config round trip ----------------------------------------------

func TestConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	k := newTestKey(t)
	cfg := testConfig(k.device(RoleOwner))
	cfg.CertPEM = "CERT"
	cfg.KeyPEM = "KEY"
	if err := cfg.Save(dir); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Prefix != cfg.Prefix || got.Port != cfg.Port || len(got.Devices) != 1 {
		t.Fatalf("round trip lost fields: %+v", got)
	}
	if got.Devices[0].ID != k.id || got.Devices[0].Role != RoleOwner {
		t.Fatalf("device lost: %+v", got.Devices[0])
	}
	pub, err := got.Devices[0].parsedKey()
	if err != nil || pub == nil {
		t.Fatalf("stored key not parseable: %v", err)
	}
}

func TestDeviceIDStable(t *testing.T) {
	k := newTestKey(t)
	again := deviceIDFromSPKI(k.spki)
	if again != k.id || len(k.id) != 16 {
		t.Fatalf("device id unstable or wrong length: %q vs %q", k.id, again)
	}
}

// --- certs -----------------------------------------------------------------

func TestGenerateCert(t *testing.T) {
	certPEM, keyPEM, sha, err := generateCert("198.51.100.10")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(certPEM, "BEGIN CERTIFICATE") || !strings.Contains(keyPEM, "BEGIN EC PRIVATE KEY") {
		t.Fatalf("PEM output malformed")
	}
	if len(sha) != 64 {
		t.Fatalf("cert sha should be 64 hex chars, got %d", len(sha))
	}
	// the sha must be the sha256 of the leaf cert DER
	block := certPEM
	if !strings.Contains(block, "CERTIFICATE") {
		t.Fatal("no cert")
	}
}

// helper
func assert404(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != 404 {
		t.Fatalf("want camouflage 404, got %d body=%s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Server") != "nginx" {
		t.Fatalf("404 should carry Server: nginx, got %q", rec.Header().Get("Server"))
	}
}

var _ = io.Discard

// A room action is answered as soon as podman is done; the status scripts run
// afterwards, so a phone with a short timeout never sees an error for a stop
// that worked.
func TestRoomActionAnswersBeforeTheStatusRefresh(t *testing.T) {
	k := newTestKey(t)
	cfg := testConfig(k.device(RoleMember))
	st := newState(map[string]string{"readiness": "echo ok"}, 0)
	release := make(chan struct{})
	ran := make(chan struct{}, 1)
	st.runScript = func(_, _ string) string {
		select {
		case ran <- struct{}{}:
		default:
		}
		<-release
		return "ok"
	}
	st.roomAction = func(string, string) error { return nil }
	h := newHandler(cfg, st)
	req := k.sign(t, "POST", "/"+cfg.Prefix+"/v1/rooms/olcrtc-server-abcd1234/stop", nil, time.Now(), "n-stop-fast")
	done := make(chan int, 1)
	go func() { done <- do(h, req).Code }()
	select {
	case code := <-done:
		if code != 200 {
			t.Fatalf("stop: want 200, got %d", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the answer waited for the status scripts")
	}
	select {
	case <-ran:
	case <-time.After(3 * time.Second):
		t.Fatal("the status was never refreshed after the action")
	}
	close(release)
}

func TestRateMemoryForgetsAddressesPastTheWindow(t *testing.T) {
	a := newAuthn()
	old := time.Now().Add(-2 * rateWindow)
	for i := 0; i <= rateMemory; i++ {
		a.rate["198.51.100.1:"+strconv.Itoa(i)] = &rateEntry{count: 1, since: old}
	}
	a.rate["203.0.113.7"] = &rateEntry{count: 1, since: time.Now()}
	a.allow("203.0.113.9:40000")
	if len(a.rate) != 2 {
		t.Fatalf("rate map holds %d entries; only the two within the window may stay", len(a.rate))
	}
}
