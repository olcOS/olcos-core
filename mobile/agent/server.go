package agent

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxBodyBytes   = 256 * 1024       // the largest request body accepted
	maxExecOutput  = 64 * 1024        // exec/job output cap (tail)
	maxLogLines    = 2000             // GET log line ceiling
	eventsWait     = 25 * time.Second // events long-poll budget
	scriptRunLimit = 10 * time.Second // per status-script timeout
)

var containerRE = regexp.MustCompile(`^(olcrtc-server|olcos-xray)-[a-z0-9-]+$`)
var roomActions = map[string]bool{"start": true, "stop": true, "restart": true}

func validContainer(c string) bool { return containerRE.MatchString(c) }

// apiHandler is the agent's single HTTP handler. Every request that is not a
// correctly signed call to a known endpoint leaves through the camouflage 404.
//
// config.json on disk is the source of truth while the agent runs: the phones
// mint and revoke invites with the CLI (over SSH, or through exec), which only
// rewrites the file. So every request is judged by the file as it is now
// (currentLocked), and every change the API makes reads the file, applies
// itself and writes it back in one step under mu (change), never a copy read
// long ago. The certificate, port and API prefix stay those serve started
// with: changing them needs a restart.
type apiHandler struct {
	mu     sync.Mutex  // guards cfg and stamp
	cfg    *Config     // the devices, invites and scripts requests are judged by
	dir    string      // config.json's directory; "" keeps cfg in memory only (tests)
	stamp  configStamp // the version of config.json cfg was read from
	state  *State
	auth   *authn
	prefix string // "/<apiPrefix>/v1/"
	usage  *usageCollector
}

var (
	errConfigRead = errors.New("config unreadable")
	errConfigSave = errors.New("could not save")
	errNoInvite   = errors.New("no usable invite")
	errNoDevice   = errors.New("no such device")
	errLastOwner  = errors.New("the last owner cannot be revoked")

	// errAlreadyPaired ends a change that has nothing to write: the caller
	// already holds what it asked for.
	errAlreadyPaired = errors.New("already paired")
)

func newHandler(cfg *Config, state *State) *apiHandler {
	return &apiHandler{
		cfg:    cfg,
		state:  state,
		auth:   newAuthn(),
		prefix: "/" + cfg.Prefix + "/v1/",
	}
}

// currentLocked returns the config to judge a request by: re-read when
// config.json changed since it was last read. A file that does not read or
// parse leaves the copy in memory in place, and is tried again next time.
// The caller holds h.mu.
func (h *apiHandler) currentLocked() *Config {
	if h.dir == "" {
		return h.cfg
	}
	if stamp, err := statConfig(h.dir); err != nil || stamp == h.stamp {
		return h.cfg
	}
	if cfg, stamp, err := loadStamped(h.dir); err == nil {
		h.adoptLocked(cfg, stamp)
	}
	return h.cfg
}

// adoptLocked installs a config read from disk. Status scripts a CLI call
// changed reach the status cache too: swapped here, in order, and run off
// the request path.
func (h *apiHandler) adoptLocked(cfg *Config, stamp configStamp) {
	scriptsChanged := !maps.Equal(h.cfg.Scripts, cfg.Scripts)
	h.cfg, h.stamp = cfg, stamp
	if scriptsChanged && h.state != nil {
		h.state.useScripts(cfg.Scripts)
		go h.state.refresh()
	}
}

// change applies fn to the config as it is on disk now and writes the result
// back, under h.mu and the lock the CLI takes too (lockConfig), so neither a
// concurrent request nor a CLI write is lost. An error from fn aborts the
// change: nothing is written, and the copy fn saw is thrown away. A caller
// that changes the scripts hands them to the status cache itself
// (handleScripts).
func (h *apiHandler) change(fn func(*Config) error) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.dir == "" {
		return fn(h.cfg)
	}
	unlock, err := lockConfig(h.dir)
	if err != nil {
		return errConfigRead
	}
	defer unlock()
	disk, stamp, err := loadStamped(h.dir)
	if err != nil {
		return errConfigRead
	}
	h.adoptLocked(disk, stamp)
	next := disk.clone()
	if next == nil {
		return errConfigRead
	}
	if err := fn(next); err != nil {
		return err
	}
	written, err := next.saveStamped(h.dir)
	if err != nil {
		return errConfigSave
	}
	h.cfg, h.stamp = next, written
	return nil
}

// authenticate verifies a signed request against the devices on disk now, so
// a device the CLI added or revoked counts at once. It returns a copy of the
// caller's device, or nil for any failure.
func (h *apiHandler) authenticate(r *http.Request, body []byte) *Device {
	h.mu.Lock()
	defer h.mu.Unlock()
	dev := h.auth.verify(h.currentLocked(), r, body, time.Now())
	if dev == nil {
		return nil
	}
	d := *dev
	return &d
}

func (h *apiHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Outside the secret prefix: unauthenticated junk. Count it and vanish.
	if !strings.HasPrefix(r.URL.Path, h.prefix) {
		h.auth.allow(r.RemoteAddr)
		writeCamouflage404(w)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		writeCamouflage404(w)
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, h.prefix)
	// Pairing is the one call made before a device has a key to sign with:
	// an invite code stands in for the signature (invites.go).
	if rest == "pair" && r.Method == http.MethodPost {
		h.handlePair(w, r, body)
		return
	}

	dev := h.authenticate(r, body)
	if dev == nil {
		h.auth.allow(r.RemoteAddr)
		writeCamouflage404(w)
		return
	}

	switch {
	case rest == "status" && r.Method == http.MethodGet:
		h.handleStatus(w)
	case rest == "events" && r.Method == http.MethodGet:
		h.handleEvents(w, r)
	case rest == "devices" && r.Method == http.MethodGet:
		h.requireOwner(dev, w, func() { h.handleDevices(w) })
	case rest == "usage" && r.Method == http.MethodGet:
		h.requireOwner(dev, w, func() { h.handleUsage(w) })
	case strings.HasPrefix(rest, "devices/") && r.Method == http.MethodDelete:
		h.requireOwner(dev, w, func() { h.handleRevoke(w, strings.TrimPrefix(rest, "devices/")) })
	case rest == "invites" && r.Method == http.MethodPost:
		h.requireOwner(dev, w, func() { h.handleInvites(w, body) })
	case rest == "exec" && r.Method == http.MethodPost:
		h.requireOwner(dev, w, func() { h.handleExec(w, body) })
	case rest == "scripts" && r.Method == http.MethodPut:
		h.requireOwner(dev, w, func() { h.handleScripts(w, body) })
	case strings.HasPrefix(rest, "rooms/"):
		h.handleRooms(w, r, strings.TrimPrefix(rest, "rooms/"))
	default:
		writeCamouflage404(w)
	}
}

// requireOwner runs fn only for an owner; a member is indistinguishable from an
// unknown caller (camouflage 404), per the spec's role model.
func (h *apiHandler) requireOwner(dev *Device, w http.ResponseWriter, fn func()) {
	if dev.Role != RoleOwner {
		writeCamouflage404(w)
		return
	}
	fn()
}

func (h *apiHandler) handleStatus(w http.ResponseWriter) {
	writeJSON(w, 200, map[string]any{
		"version": h.state.Version(),
		"at":      time.Now().Unix(),
		"outputs": h.state.statusOutputs(),
	})
}

func (h *apiHandler) handleEvents(w http.ResponseWriter, r *http.Request) {
	since, _ := strconv.ParseUint(r.URL.Query().Get("since"), 10, 64)
	v := h.state.waitForChange(since, eventsWait)
	writeJSON(w, 200, map[string]any{"version": v})
}

func (h *apiHandler) handleDevices(w http.ResponseWriter) {
	type dev struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Role    Role   `json:"role"`
		AddedAt int64  `json:"added_at"`
		Revoked bool   `json:"revoked"`
	}
	h.mu.Lock()
	devices := h.currentLocked().Devices
	list := make([]dev, 0, len(devices))
	for _, d := range devices {
		list = append(list, dev{d.ID, d.Name, d.Role, d.AddedAt, d.Revoked})
	}
	h.mu.Unlock()
	writeJSON(w, 200, map[string]any{"devices": list})
}

// handleUsage answers GET usage (owner only): per device id, when it was last
// seen, whether it is connected now and how much it moved (usage.go). A pass
// over the containers' logs runs first unless one ran in the last
// usageMinGap; the answer waits for it a moment, and a slow pass finishes for
// the next request.
func (h *apiHandler) handleUsage(w http.ResponseWriter) {
	if h.usage == nil {
		writeJSON(w, 200, usageReport{At: time.Now().Unix(), Devices: []usageRow{}})
		return
	}
	if done := h.usage.start(usageMinGap); done != nil {
		timer := time.NewTimer(usageServeWait)
		select {
		case <-done:
		case <-timer.C:
		}
		timer.Stop()
	}
	writeJSON(w, 200, h.usage.report())
}

func (h *apiHandler) handleExec(w http.ResponseWriter, body []byte) {
	var req struct {
		Script  string `json:"script"`
		Timeout int    `json:"timeout"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, "bad request")
		return
	}
	script, err := base64.StdEncoding.DecodeString(req.Script)
	if err != nil {
		writeError(w, "script is not valid base64")
		return
	}
	timeout := req.Timeout
	if timeout <= 0 || timeout > 600 {
		timeout = 600
	}
	exit, out := runBash(string(script), time.Duration(timeout)*time.Second, maxExecOutput)
	writeJSON(w, 200, map[string]any{"exit": exit, "output": out})
}

func (h *apiHandler) handleScripts(w http.ResponseWriter, body []byte) {
	var req struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Scripts == nil {
		writeError(w, "bad request")
		return
	}
	if err := h.change(func(c *Config) error {
		c.Scripts = req.Scripts
		return nil
	}); err != nil {
		writeError(w, "could not save")
		return
	}
	h.state.setScripts(req.Scripts)
	writeJSON(w, 200, map[string]any{"version": h.state.Version()})
}

// handleRooms serves both POST rooms/{c}/{action} and GET rooms/{c}/log.
func (h *apiHandler) handleRooms(w http.ResponseWriter, r *http.Request, tail string) {
	parts := strings.Split(tail, "/")
	if len(parts) != 2 {
		writeCamouflage404(w)
		return
	}
	container, verb := parts[0], parts[1]
	if !validContainer(container) {
		writeCamouflage404(w)
		return
	}

	if verb == "log" && r.Method == http.MethodGet {
		lines, _ := strconv.Atoi(r.URL.Query().Get("lines"))
		if lines <= 0 || lines > maxLogLines {
			lines = 200
		}
		writeJSON(w, 200, map[string]any{"log": podmanLog(container, lines)})
		return
	}
	if r.Method == http.MethodPost && roomActions[verb] {
		if h.state.roomAction == nil {
			writeError(w, "no room controller")
			return
		}
		if err := h.state.roomAction(container, verb); err != nil {
			writeError(w, err.Error())
			return
		}
		// The action is done: answer now. Re-reading the status runs every
		// status script and can take longer than the phone waits, which
		// would report a stop that worked as an error; the new version
		// reaches the phone through events.
		go h.state.refresh()
		writeJSON(w, 200, map[string]any{"version": h.state.Version()})
		return
	}
	writeCamouflage404(w)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		writeCamouflage404(w)
		return
	}
	w.Header().Set("Server", "nginx")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(data)
}

// writeError is for an authenticated caller: a real, small error is more use to
// the app than another camouflage 404, and it reveals nothing to an outsider
// (who never gets this far). It mirrors the server contract's `ERROR:` line.
func writeError(w http.ResponseWriter, msg string) {
	writeJSON(w, http.StatusBadGateway, map[string]any{"error": msg})
}

// --- real runners (used by serve, not by unit tests) -----------------------

func runBash(script string, timeout time.Duration, cap int) (int, string) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-c", script)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	out := capBytes(buf.String(), cap)
	if ctx.Err() == context.DeadlineExceeded {
		return 124, out + "\n[timed out]"
	}
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode(), out
		}
		return 1, out + "\n" + err.Error()
	}
	return 0, out
}

func bashRunner(_, script string) string {
	_, out := runBash(script, scriptRunLimit, maxOutputBytes)
	return out
}

func podmanRoomAction(container, action string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "podman", action, container).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s", action, container, strings.TrimSpace(string(out)))
	}
	return nil
}

func podmanLog(container string, lines int) string {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, "podman", "logs", "--tail", strconv.Itoa(lines), container).CombinedOutput()
	return capBytes(redactLog(string(out)), maxOutputBytes)
}

// redactLog removes the obvious secrets a container log can carry, matching the
// spirit of the app's LogStore.redactSecrets (64-hex keys and token-like
// assignments). The agent never ships a raw key to the app.
var hexKeyRE = regexp.MustCompile(`\b[0-9a-fA-F]{64}\b`)
var tokenRE = regexp.MustCompile(`(?i)(token|pass|passwd|password)([=:]\s*)\S+`)

func redactLog(s string) string {
	s = hexKeyRE.ReplaceAllString(s, "[redacted]")
	s = tokenRE.ReplaceAllString(s, "$1$2[redacted]")
	return s
}

// --- TLS with a plain-HTTP guard -------------------------------------------

// Serve loads the config in dir and runs the agent until the process is
// stopped. Plain HTTP to the TLS port gets nginx's 400; everything else goes
// through the signed API or the camouflage 404.
func Serve(dir string) error {
	// The certificate, port and API prefix are read here once; devices,
	// invites and scripts follow config.json while serving (apiHandler).
	cfg, stamp, err := loadStamped(dir)
	if err != nil {
		return err
	}
	cert, err := tls.X509KeyPair([]byte(cfg.CertPEM), []byte(cfg.KeyPEM))
	if err != nil {
		return fmt.Errorf("bad certificate: %w", err)
	}

	state := newState(cfg.Scripts, safetyInterval)
	state.runScript = bashRunner
	state.roomAction = podmanRoomAction
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go state.watch(ctx)

	usage := newUsageCollector(filepath.Join(dir, usageFile))
	usage.running = podmanRunning
	usage.readLogs = podmanLogLines
	go usage.run(ctx)

	h := newHandler(cfg, state)
	h.dir, h.stamp = dir, stamp
	h.usage = usage

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", cfg.Port))
	if err != nil {
		return err
	}
	peek := &tlsPeekListener{
		Listener: ln,
		config:   &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       90 * time.Second,
	}
	return srv.Serve(peek)
}

// tlsPeekListener wraps a TCP listener: it looks at the first byte of each
// connection and only speaks TLS when it is a real handshake (0x16). A plain
// HTTP request gets nginx's "sent to HTTPS port" 400 and the connection closes,
// so a casual probe sees an ordinary nginx, never a protocol error.
//
// The first-byte peek carries a read deadline, so it must run OFF the accept
// path: a connection that opens and sends nothing would otherwise block every
// other connection for the whole deadline (a trivial slowloris against a
// service meant to run for days). Each accepted connection is classified in its
// own goroutine and only the finished TLS connections are handed to Accept.
type tlsPeekListener struct {
	net.Listener
	config *tls.Config
	ready  chan net.Conn
	errc   chan error
	start  sync.Once
}

func (l *tlsPeekListener) Accept() (net.Conn, error) {
	l.start.Do(func() {
		l.ready = make(chan net.Conn)
		l.errc = make(chan error, 1)
		go l.acceptLoop()
	})
	select {
	case c := <-l.ready:
		return c, nil
	case err := <-l.errc:
		return nil, err
	}
}

// acceptLoop hands every accepted connection to classify. An accept error
// other than a closed listener (out of file descriptors, a connection reset
// before it was taken) passes: the agent backs off the way net/http does
// (5 ms doubling to 1 s) and keeps accepting, instead of ending serve over a
// moment of load.
func (l *tlsPeekListener) acceptLoop() {
	var delay time.Duration
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				l.errc <- err
				return
			}
			delay = nextAcceptDelay(delay)
			time.Sleep(delay)
			continue
		}
		delay = 0
		go l.classify(c)
	}
}

func nextAcceptDelay(delay time.Duration) time.Duration {
	if delay == 0 {
		return 5 * time.Millisecond
	}
	return min(2*delay, time.Second)
}

func (l *tlsPeekListener) classify(c net.Conn) {
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(c)
	first, err := br.Peek(1)
	_ = c.SetReadDeadline(time.Time{})
	if err != nil || len(first) == 0 {
		_ = c.Close()
		return
	}
	pc := &peekedConn{Conn: c, r: br}
	if first[0] == 0x16 { // TLS handshake record
		l.ready <- tls.Server(pc, l.config)
		return
	}
	writePlainHTTP400(pc)
	_ = c.Close()
}

// peekedConn restores bytes consumed by the buffered peek so TLS (or the raw
// writer) sees the full stream.
type peekedConn struct {
	net.Conn
	r *bufio.Reader
}

func (p *peekedConn) Read(b []byte) (int, error) { return p.r.Read(b) }

var _ io.Reader = (*bytes.Buffer)(nil)
