package bond

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The whole path runs in-process: an app speaks SOCKS5 to a Client, whose
// lanes are small SOCKS5 servers that shape traffic like a slow tunnel
// (rate, delay, deep buffers), dial the bond server and can die, stall, go
// down and come back, or refuse and hold CONNECTs on demand; the bond server
// dials test targets on loopback and can be restarted under live streams.

var testKey = bytes.Repeat([]byte{0xab}, 32)

// MARK: Lanes

type testLane struct {
	listenPort int
	user, pass string
	// rate is bytes per second each way for the whole lane: every connection
	// through it shares the budget, as streams share one tunnel. 0: as fast
	// as it goes. setRate changes it while the lane runs (rateNow).
	rate     float64
	rateBits atomic.Uint64
	delay    time.Duration

	mu       sync.Mutex
	ln       net.Listener // the current runtime's; down closes it, up opens another
	conns    []net.Conn
	stalled  atomic.Bool
	connects atomic.Int64 // CONNECTs received, refused and held ones included
	// refuse, when not zero, is the SOCKS5 reply every CONNECT gets instead of
	// being served: repHostUnreachable is what the core answers once its
	// tunnel session is gone.
	refuse atomic.Int32
	// hold keeps every CONNECT for this long (nanoseconds) before answering
	// it, as the core parks one while its room is being joined again.
	hold atomic.Int64

	upstream, downstream pacer // the rate, booked toward the exit and toward the app
}

func newTestLane(t *testing.T, rate float64, delay time.Duration) *testLane {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := &testLane{ln: ln, listenPort: ln.Addr().(*net.TCPAddr).Port, rate: rate, delay: delay}
	go l.serve(ln)
	t.Cleanup(l.down)
	return l
}

func (l *testLane) serve(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go l.handle(c)
	}
}

func (l *testLane) port() int { return l.listenPort }

// setRate changes the lane's speed while it runs, as a room out of a dark
// spell or no longer held down speeds up.
func (l *testLane) setRate(rate float64) { l.rateBits.Store(math.Float64bits(rate)) }

func (l *testLane) rateNow() float64 {
	if bits := l.rateBits.Load(); bits != 0 {
		return math.Float64frombits(bits)
	}
	return l.rate
}

// down ends the lane's runtime: its port refuses connections and every
// connection it carried is closed.
func (l *testLane) down() {
	l.mu.Lock()
	ln := l.ln
	l.mu.Unlock()
	_ = ln.Close()
	l.kill()
}

// up starts the lane again on the port it had, as the app's lane supervisor
// restarts a lane's runtime on the same local port.
func (l *testLane) up(t *testing.T) {
	t.Helper()
	ln, err := listenAgain(laneAddr(l.listenPort))
	if err != nil {
		t.Fatalf("lane back on port %d: %v", l.listenPort, err)
	}
	l.mu.Lock()
	l.ln = ln
	l.mu.Unlock()
	go l.serve(ln)
}

// listenAgain listens on an address that was in use a moment ago, giving the
// system a few seconds to let go of it.
func listenAgain(addr string) (net.Listener, error) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		ln, err := net.Listen("tcp", addr)
		if err == nil || time.Now().After(deadline) {
			return ln, err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (l *testLane) track(c net.Conn) {
	l.mu.Lock()
	l.conns = append(l.conns, c)
	l.mu.Unlock()
}

// kill closes every connection the lane carries, as a dying tunnel does.
func (l *testLane) kill() {
	l.mu.Lock()
	conns := l.conns
	l.conns = nil
	l.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

// handle is a SOCKS5 server that, like the olcrtc core, reads its handshake
// with exact reads.
func (l *testLane) handle(c net.Conn) {
	l.track(c)
	var head [2]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return
	}
	if _, err := io.ReadFull(c, make([]byte, head[1])); err != nil {
		return
	}
	if l.user != "" {
		_, _ = c.Write([]byte{5, 2})
		var ah [2]byte
		_, _ = io.ReadFull(c, ah[:])
		u := make([]byte, ah[1])
		_, _ = io.ReadFull(c, u)
		var pl [1]byte
		_, _ = io.ReadFull(c, pl[:])
		p := make([]byte, pl[0])
		_, _ = io.ReadFull(c, p)
		if string(u) != l.user || string(p) != l.pass {
			_, _ = c.Write([]byte{1, 1})
			_ = c.Close()
			return
		}
		_, _ = c.Write([]byte{1, 0})
	} else {
		_, _ = c.Write([]byte{5, 0})
	}
	req, err := readRequest(c)
	if err != nil {
		_ = c.Close()
		return
	}
	if req.cmd == 3 {
		_, _ = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0x12, 0x34})
		_, _ = io.Copy(io.Discard, c)
		return
	}
	l.connects.Add(1)
	if hold := time.Duration(l.hold.Load()); hold > 0 {
		time.Sleep(hold)
	}
	if code := byte(l.refuse.Load()); code != repSuccess {
		_, _ = c.Write(socksReply(code))
		// Closing with the client's hello still unread would reset the
		// connection, and the reset can overtake the reply.
		closeWrite(c)
		_, _ = io.Copy(io.Discard, c)
		_ = c.Close()
		return
	}
	target, err := net.DialTimeout("tcp", req.target, 5*time.Second)
	if err != nil {
		_, _ = c.Write(socksReply(repHostUnreachable))
		_ = c.Close()
		return
	}
	l.track(target)
	_, _ = c.Write(socksReply(repSuccess))
	go l.shape(target, c, &l.upstream)
	go l.shape(c, target, &l.downstream)
}

// pacer books one direction of a lane's rate for every connection through
// it, so N connections share the lane's speed instead of each getting it.
type pacer struct {
	mu   sync.Mutex
	free time.Time // when everything booked so far is through
}

// book reserves n bytes at rate; when they are through.
func (p *pacer) book(n int, rate float64) time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	if now := time.Now(); p.free.Before(now) {
		p.free = now
	}
	p.free = p.free.Add(time.Duration(float64(n) / rate * float64(time.Second)))
	return p.free
}

// shape carries src to dst at the lane's rate (booked on pace, which every
// connection through the lane shares) and delay, through a buffer of up to
// 2 MiB like a tunnel's own.
func (l *testLane) shape(dst, src net.Conn, pace *pacer) {
	type chunk struct {
		b  []byte
		at time.Time
	}
	ch := make(chan chunk, 64)
	go func() {
		defer close(ch)
		buf := make([]byte, 32<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				ch <- chunk{append([]byte(nil), buf[:n]...), time.Now()}
			}
			if err != nil {
				return
			}
		}
	}()
	for ck := range ch {
		for l.stalled.Load() {
			time.Sleep(10 * time.Millisecond)
		}
		if wait := time.Until(ck.at.Add(l.delay)); wait > 0 {
			time.Sleep(wait)
		}
		if rate := l.rateNow(); rate > 0 {
			time.Sleep(time.Until(pace.book(len(ck.b), rate)))
		}
		if _, err := dst.Write(ck.b); err != nil {
			_ = src.Close()
			_ = dst.Close()
			for range ch {
			}
			return
		}
	}
	closeWrite(dst)
}

// MARK: Targets

// source sends n bytes made from seed, then ends its side.
func source(t *testing.T, n int, seed int64) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, io.LimitReader(rand.New(rand.NewSource(seed)), int64(n)))
				closeWrite(c)
				_, _ = io.Copy(io.Discard, c)
			}()
		}
	}()
	return ln.Addr().String()
}

func echo(t *testing.T) string {
	t.Helper()
	addr, _ := countedEcho(t)
	return addr
}

// countedEcho is echo that counts the connections it took: how often the
// target was dialed.
func countedEcho(t *testing.T) (string, *atomic.Int64) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := new(atomic.Int64)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
				closeWrite(c)
			}()
		}
	}()
	return ln.Addr().String(), accepted
}

// echoRound sends p through an echo connection and reads it back within
// limit: how long that took, and why it failed or that it came back changed.
func echoRound(c net.Conn, p []byte, limit time.Duration) (time.Duration, error) {
	start := time.Now()
	_ = c.SetDeadline(start.Add(limit))
	defer func() { _ = c.SetDeadline(time.Time{}) }()
	if _, err := c.Write(p); err != nil {
		return time.Since(start), err
	}
	back := make([]byte, len(p))
	if _, err := io.ReadFull(c, back); err != nil {
		return time.Since(start), err
	}
	if !bytes.Equal(back, p) {
		return time.Since(start), errors.New("the echo came back changed")
	}
	return time.Since(start), nil
}

func digest(n int, seed int64) [32]byte {
	h := sha256.New()
	_, _ = io.Copy(h, io.LimitReader(rand.New(rand.NewSource(seed)), int64(n)))
	var d [32]byte
	copy(d[:], h.Sum(nil))
	return d
}

// MARK: Setup

type rig struct {
	client *Client
	lanes  []*testLane
	server *server
}

func startServer(t *testing.T, key []byte) (*server, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	s := newServer(func() ([]byte, error) { return key, nil },
		func(ctx context.Context, target string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", target)
		})
	go func() { _ = s.serve(ln) }()
	return s, ln.Addr().(*net.TCPAddr).Port
}

func newRig(t *testing.T, serverKey []byte, user, pass string, lanes ...*testLane) *rig {
	t.Helper()
	s, port := startServer(t, serverKey)
	r := clientRig(t, port, user, pass, lanes...)
	r.server = s
	return r
}

// clientRig is a client whose lanes reach the bond server listening on port.
func clientRig(t *testing.T, port int, user, pass string, lanes ...*testLane) *rig {
	t.Helper()
	c := NewClient(0, user, pass, hex.EncodeToString(testKey), "127.0.0.1", port)
	for _, l := range lanes {
		c.AddLane(l.port(), l.user, l.pass)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Stop)
	return &rig{client: c, lanes: lanes}
}

// restartableServer is the in-process bond server on a fixed address that
// can crash and come back there, as the real one does on a redeploy or under
// --restart=always: the old process's listener and every connection it held,
// toward the lanes and toward the targets, close at once.
type restartableServer struct {
	key  []byte
	addr string
	port int
	proc *serverProcess // the running one
}

// serverProcess is one run of the server: the listener it serves and every
// connection it holds.
type serverProcess struct {
	ln    net.Listener
	mu    sync.Mutex
	conns []net.Conn
	dead  bool
}

// keep tracks a connection of the process; one that comes after the crash
// dies with it.
func (p *serverProcess) keep(c net.Conn) {
	p.mu.Lock()
	dead := p.dead
	if !dead {
		p.conns = append(p.conns, c)
	}
	p.mu.Unlock()
	if dead {
		_ = c.Close()
	}
}

func (p *serverProcess) Accept() (net.Conn, error) {
	c, err := p.ln.Accept()
	if err == nil {
		p.keep(c)
	}
	return c, err
}

func (p *serverProcess) Close() error   { return p.ln.Close() }
func (p *serverProcess) Addr() net.Addr { return p.ln.Addr() }

// crash ends the process: its listener and every connection it held close.
func (p *serverProcess) crash() {
	p.mu.Lock()
	p.dead = true
	conns := p.conns
	p.conns = nil
	p.mu.Unlock()
	_ = p.ln.Close()
	for _, c := range conns {
		_ = c.Close()
	}
}

func startRestartableServer(t *testing.T, key []byte) *restartableServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &restartableServer{key: key, addr: ln.Addr().String(), port: ln.Addr().(*net.TCPAddr).Port}
	s.run(ln)
	t.Cleanup(func() { s.proc.crash() })
	return s
}

// run starts a fresh server process on ln.
func (s *restartableServer) run(ln net.Listener) {
	p := &serverProcess{ln: ln}
	srv := newServer(func() ([]byte, error) { return s.key, nil },
		func(ctx context.Context, target string) (net.Conn, error) {
			var d net.Dialer
			c, err := d.DialContext(ctx, "tcp", target)
			if err == nil {
				p.keep(c)
			}
			return c, err
		})
	s.proc = p
	go func() { _ = srv.serve(p) }()
}

// restart crashes the running process and starts a new one, which knows
// nothing of the old one's sessions, on the same address.
func (s *restartableServer) restart(t *testing.T) {
	t.Helper()
	s.proc.crash()
	ln, err := listenAgain(s.addr)
	if err != nil {
		t.Fatalf("bond server back on %s: %v", s.addr, err)
	}
	s.run(ln)
}

// dial opens an app connection through the client; the SOCKS5 reply code.
func (r *rig) dial(t *testing.T, target, user, pass string) (net.Conn, byte) {
	t.Helper()
	c, err := net.Dial("tcp", r.client.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	req, err := connectRequest(target)
	if err != nil {
		t.Fatal(err)
	}
	// A reply may take a while (lanes still answering) but not forever.
	_ = c.SetDeadline(time.Now().Add(60 * time.Second))
	defer func() { _ = c.SetDeadline(time.Time{}) }()
	if _, err := c.Write(append(greeting(user, pass), req...)); err != nil {
		t.Fatal(err)
	}
	if err := readGreetingReply(c, user); err != nil {
		return c, 0xFF
	}
	err = readConnectReply(c)
	var refused socksRefusedError
	switch {
	case err == nil:
		return c, repSuccess
	case errors.As(err, &refused):
		return c, refused.code
	default:
		t.Fatalf("reply: %v", err)
		return nil, 0
	}
}

// readAll reads until EOF, calling at(n) as bytes come in.
func readAll(t *testing.T, c net.Conn, at func(n int)) ([32]byte, int) {
	t.Helper()
	h := sha256.New()
	buf := make([]byte, 64<<10)
	total := 0
	_ = c.SetReadDeadline(time.Now().Add(60 * time.Second))
	for {
		n, err := c.Read(buf)
		h.Write(buf[:n])
		total += n
		if at != nil && n > 0 {
			at(total)
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("read after %d bytes: %v", total, err)
			}
			break
		}
	}
	var d [32]byte
	copy(d[:], h.Sum(nil))
	return d, total
}

// MARK: Tests

func TestBondCarriesBothWays(t *testing.T) {
	r := newRig(t, testKey, "", "", newTestLane(t, 0, 0), newTestLane(t, 0, 0), newTestLane(t, 0, 0))
	c, rep := r.dial(t, echo(t), "", "")
	if rep != repSuccess {
		t.Fatalf("reply %d", rep)
	}
	const n = 3 << 20
	data := make([]byte, n)
	rand.New(rand.NewSource(1)).Read(data)
	go func() {
		_, _ = c.Write(data)
		closeWrite(c)
	}()
	got, total := readAll(t, c, nil)
	if total != n || got != sha256.Sum256(data) {
		t.Fatalf("echo came back as %d bytes, intact=%v", total, got == sha256.Sum256(data))
	}
	if r.client.Bonded() != 1 || r.client.Plain() != 0 {
		t.Fatalf("bonded %d, plain %d", r.client.Bonded(), r.client.Plain())
	}
	for i, l := range r.lanes {
		if l.connects.Load() == 0 {
			t.Fatalf("lane %d carried nothing", i)
		}
	}
}

func TestBondSpeedAddsUp(t *testing.T) {
	lanes := []*testLane{
		newTestLane(t, 1<<20, 20*time.Millisecond),
		newTestLane(t, 1<<20, 60*time.Millisecond),
		newTestLane(t, 2<<20, 100*time.Millisecond),
	}
	r := newRig(t, testKey, "", "", lanes...)
	const n = 12 << 20
	c, rep := r.dial(t, source(t, n, 2), "", "")
	if rep != repSuccess {
		t.Fatalf("reply %d", rep)
	}
	start := time.Now()
	got, total := readAll(t, c, nil)
	elapsed := time.Since(start)
	if total != n || got != digest(n, 2) {
		t.Fatalf("got %d bytes, intact=%v", total, got == digest(n, 2))
	}
	rate := float64(n) / elapsed.Seconds() / (1 << 20)
	t.Logf("%d MiB in %v: %.2f MiB/s over lanes of 1+1+2 MiB/s", n>>20, elapsed.Round(time.Millisecond), rate)
	if rate < 2.4 { // the fastest lane alone gives 2
		t.Fatalf("%.2f MiB/s: the lanes did not add up", rate)
	}
}

func TestLaneBytesCountWhatEachLaneCarried(t *testing.T) {
	lanes := []*testLane{
		newTestLane(t, 1<<20, 20*time.Millisecond),
		newTestLane(t, 4<<20, 20*time.Millisecond),
	}
	r := newRig(t, testKey, "", "", lanes...)
	const n = 8 << 20
	c, rep := r.dial(t, source(t, n, 4), "", "")
	if rep != repSuccess {
		t.Fatalf("reply %d", rep)
	}
	if _, total := readAll(t, c, nil); total != n {
		t.Fatalf("got %d bytes", total)
	}
	rx := laneRx(t, r.client.LaneBytes(), 2)
	if rx[0] == 0 || rx[1] == 0 {
		t.Fatalf("every lane carried part of the stream: %v", rx)
	}
	if rx[0]+rx[1] < n {
		t.Fatalf("the lanes together carried %d of %d bytes", rx[0]+rx[1], n)
	}
	if rx[1] <= rx[0] {
		t.Fatalf("the faster lane carried less: %v", rx)
	}
}

// laneRx reads LaneBytes: the bytes each of `want` lanes carried toward the app.
func laneRx(t *testing.T, text string, want int) []int64 {
	t.Helper()
	parts := strings.Split(text, ",")
	if len(parts) != want {
		t.Fatalf("LaneBytes %q: want %d lanes", text, want)
	}
	rx := make([]int64, want)
	for i, p := range parts {
		pair := strings.Split(p, ":")
		if len(pair) != 2 {
			t.Fatalf("LaneBytes %q: lane %d is not rx:tx", text, i)
		}
		v, err := strconv.ParseInt(pair[0], 10, 64)
		if err != nil {
			t.Fatalf("LaneBytes %q: %v", text, err)
		}
		rx[i] = v
	}
	return rx
}

func TestBondSurvivesALaneDying(t *testing.T) {
	lanes := []*testLane{
		newTestLane(t, 2<<20, 20*time.Millisecond),
		newTestLane(t, 2<<20, 40*time.Millisecond),
		newTestLane(t, 2<<20, 30*time.Millisecond),
	}
	r := newRig(t, testKey, "", "", lanes...)
	const n = 12 << 20
	c, rep := r.dial(t, source(t, n, 3), "", "")
	if rep != repSuccess {
		t.Fatalf("reply %d", rep)
	}
	var once sync.Once
	got, total := readAll(t, c, func(total int) {
		if total > 3<<20 {
			once.Do(lanes[1].kill)
		}
	})
	if total != n || got != digest(n, 3) {
		t.Fatalf("got %d bytes, intact=%v", total, got == digest(n, 3))
	}
}

func TestBondSurvivesAStall(t *testing.T) {
	lanes := []*testLane{
		newTestLane(t, 2<<20, 20*time.Millisecond),
		newTestLane(t, 2<<20, 40*time.Millisecond),
		newTestLane(t, 2<<20, 30*time.Millisecond),
	}
	r := newRig(t, testKey, "", "", lanes...)
	const n = 12 << 20
	c, rep := r.dial(t, source(t, n, 4), "", "")
	if rep != repSuccess {
		t.Fatalf("reply %d", rep)
	}
	var once sync.Once
	start := time.Now()
	got, total := readAll(t, c, func(total int) {
		if total > 3<<20 {
			once.Do(func() { lanes[0].stalled.Store(true) })
		}
	})
	if total != n || got != digest(n, 4) {
		t.Fatalf("got %d bytes, intact=%v", total, got == digest(n, 4))
	}
	if elapsed := time.Since(start); elapsed > 20*time.Second {
		t.Fatalf("took %v: the stalled lane held the stream up", elapsed)
	}
	lanes[0].stalled.Store(false)
}

func TestBondManyConnectionsAtOnce(t *testing.T) {
	r := newRig(t, testKey, "", "",
		newTestLane(t, 4<<20, 10*time.Millisecond), newTestLane(t, 4<<20, 30*time.Millisecond))
	const n = 200 << 10
	target := source(t, n, 5)
	want := digest(n, 5)
	var wg sync.WaitGroup
	errs := make(chan string, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, rep := r.dial(t, target, "", "")
			if rep != repSuccess {
				errs <- "reply " + strconv.Itoa(int(rep))
				return
			}
			got, total := readAll(t, c, nil)
			if total != n || got != want {
				errs <- "got " + strconv.Itoa(total) + " bytes"
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Error(e)
	}
}

func TestBondReportsAnUnreachableTarget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := ln.Addr().String()
	_ = ln.Close()
	r := newRig(t, testKey, "", "", newTestLane(t, 0, 0), newTestLane(t, 0, 0))
	if _, rep := r.dial(t, closed, "", ""); rep != repHostUnreachable {
		t.Fatalf("reply %d, want host unreachable", rep)
	}
}

func TestWrongKeyGoesPlain(t *testing.T) {
	other := bytes.Repeat([]byte{0xcd}, 32)
	r := newRig(t, other, "", "", newTestLane(t, 0, 0), newTestLane(t, 0, 0))
	c, rep := r.dial(t, echo(t), "", "")
	if rep != repSuccess {
		t.Fatalf("reply %d", rep)
	}
	_, _ = c.Write([]byte("ping"))
	closeWrite(c)
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "ping" {
		t.Fatalf("got %q, %v", got, err)
	}
	if r.client.Plain() != 1 || r.client.Bonded() != 0 {
		t.Fatalf("bonded %d, plain %d", r.client.Bonded(), r.client.Plain())
	}
	if rx := laneRx(t, r.client.LaneBytes(), 2); rx[0]+rx[1] < int64(len("ping")) {
		t.Fatalf("the plain connection's lane counted nothing: %v", rx)
	}
	if !r.client.isOff() {
		t.Fatal("bonding should be off for a while")
	}
}

func TestListedDestinationsSkipTheLanes(t *testing.T) {
	r := newRig(t, testKey, "", "", newTestLane(t, 0, 0), newTestLane(t, 0, 0))
	r.client.SetDirectRules("# local targets go straight\n127.0.0.0/8\n")
	c, rep := r.dial(t, echo(t), "", "")
	if rep != repSuccess {
		t.Fatalf("reply %d", rep)
	}
	_, _ = c.Write([]byte("ping"))
	closeWrite(c)
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "ping" {
		t.Fatalf("got %q, %v", got, err)
	}
	if r.client.Direct() != 1 || r.client.Bonded() != 0 || r.client.Plain() != 0 {
		t.Fatalf("direct %d, bonded %d, plain %d", r.client.Direct(), r.client.Bonded(), r.client.Plain())
	}
	for i, l := range r.lanes {
		if l.connects.Load() != 0 {
			t.Fatalf("lane %d was used for a listed destination", i)
		}
	}
}

func TestDirectRulesMatchLikeTheCore(t *testing.T) {
	r := parseDirect("domain:ru\nfull:vk.com\n10.0.0.0/8\n203.0.113.7\nnot a rule\n# note")
	for target, want := range map[string]bool{
		"yandex.ru:443": true, "RU:80": true, "ya.ru.:443": true, "vk.com:443": true,
		"m.vk.com:443": false, "example.com:443": false, "10.1.2.3:22": true,
		"203.0.113.7:443": true, "203.0.113.8:443": false, "[::ffff:10.0.0.1]:80": true,
	} {
		if got := r.matchTarget(target); got != want {
			t.Errorf("%s: %v, want %v", target, got, want)
		}
	}
	if parseDirect("\n# nothing\n") != nil {
		t.Fatal("a list with no rules is no list")
	}
	var none *directRules
	if none.matchTarget("yandex.ru:443") {
		t.Fatal("no list matches nothing")
	}
}

func TestAppLogin(t *testing.T) {
	r := newRig(t, testKey, "me", "secret", newTestLane(t, 0, 0), newTestLane(t, 0, 0))
	if _, rep := r.dial(t, echo(t), "me", "wrong"); rep != 0xFF {
		t.Fatalf("a wrong password got reply %d", rep)
	}
	if _, rep := r.dial(t, echo(t), "me", "secret"); rep != repSuccess {
		t.Fatalf("reply %d", rep)
	}
}

func TestLaneLoginAndUDPAssociateGoThroughOneLane(t *testing.T) {
	a, b := newTestLane(t, 0, 0), newTestLane(t, 0, 0)
	a.user, a.pass, b.user, b.pass = "lane", "pw", "lane", "pw"
	r := newRig(t, testKey, "", "", a, b)
	c, err := net.Dial("tcp", r.client.ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte{5, 1, 0, 5, 3, 0, 1, 0, 0, 0, 0, 0, 0})
	reply := make([]byte, 2+10)
	if _, err := io.ReadFull(c, reply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply[2:], []byte{5, 0, 0, 1, 127, 0, 0, 1, 0x12, 0x34}) {
		t.Fatalf("UDP ASSOCIATE reply %v", reply[2:])
	}
	// And a CONNECT bonds through lanes that want a login.
	conn, rep := r.dial(t, echo(t), "", "")
	if rep != repSuccess {
		t.Fatalf("reply %d", rep)
	}
	_, _ = conn.Write([]byte("hi"))
	closeWrite(conn)
	if got, _ := io.ReadAll(conn); string(got) != "hi" {
		t.Fatalf("got %q", got)
	}
	if r.client.Bonded() != 1 {
		t.Fatalf("bonded %d", r.client.Bonded())
	}
}

func TestAnAppResetReachesTheTarget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	closedAt := make(chan time.Time, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		chunk := make([]byte, 32<<10)
		for {
			if _, err := c.Write(chunk); err != nil {
				closedAt <- time.Now()
				return
			}
		}
	}()
	r := newRig(t, testKey, "", "", newTestLane(t, 1<<20, 0), newTestLane(t, 1<<20, 0))
	c, rep := r.dial(t, ln.Addr().String(), "", "")
	if rep != repSuccess {
		t.Fatalf("reply %d", rep)
	}
	_, _ = io.ReadFull(c, make([]byte, 256<<10))
	_ = c.(*net.TCPConn).SetLinger(0)
	_ = c.Close()
	start := time.Now()
	select {
	case at := <-closedAt:
		if d := at.Sub(start); d > 5*time.Second {
			t.Fatalf("the target closed %v later", d)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the target was never closed")
	}
}

func TestHelloChecks(t *testing.T) {
	now := time.Now()
	h := hello{client: [8]byte{9}, lane: 1, lanes: 3, unix: uint64(now.Unix()), target: "example.org:443"}
	h.session[0] = 7
	b, err := h.marshal(testKey)
	if err != nil {
		t.Fatal(err)
	}
	got, err := readHello(bytes.NewReader(b), testKey, now)
	if err != nil || got != h {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
	tampered := bytes.Clone(b)
	tampered[len(tampered)-40] ^= 1
	if _, err := readHello(bytes.NewReader(tampered), testKey, now); !errors.Is(err, errBadHello) {
		t.Fatalf("tampered: %v", err)
	}
	if _, err := readHello(bytes.NewReader(b), bytes.Repeat([]byte{1}, 32), now); !errors.Is(err, errBadHello) {
		t.Fatalf("wrong key: %v", err)
	}
	if _, err := readHello(bytes.NewReader(b), testKey, now.Add(clockSkew+time.Minute)); !errors.Is(err, errBadHello) {
		t.Fatalf("old hello: %v", err)
	}
}

func TestFramesRoundTrip(t *testing.T) {
	var b []byte
	b = appendFrame(b, 9, []byte("abc"))
	b = appendFrame(b, 10, []byte{})
	b = appendAck(b, 11, 1<<40)
	b = appendReset(b)
	r := bytes.NewReader(b)
	want := []inFrame{
		{kind: kindData, seq: 9, payload: []byte("abc")},
		{kind: kindEnd, seq: 10},
		{kind: kindAck, seq: 11, got: 1 << 40},
		{kind: kindReset},
	}
	for i, w := range want {
		f, err := readFrame(r)
		if err != nil || f.kind != w.kind || f.seq != w.seq || f.got != w.got || !bytes.Equal(f.payload, w.payload) {
			t.Fatalf("frame %d: %+v, %v", i, f, err)
		}
	}
	big := binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint32(nil, 0), maxPayload+1)
	if _, err := readFrame(bytes.NewReader(big)); !errors.Is(err, errBadFrame) {
		t.Fatalf("oversized frame: %v", err)
	}
}

func TestKeyFiles(t *testing.T) {
	dir := t.TempDir()
	hexKey := hex.EncodeToString(testKey)
	bare := filepath.Join(dir, "key")
	yaml := filepath.Join(dir, "server.yaml")
	_ = os.WriteFile(bare, []byte(hexKey+"\n"), 0o600)
	_ = os.WriteFile(yaml, []byte("mode: srv\ncrypto:\n  key: \""+hexKey+"\"\n"), 0o600)
	for _, p := range []string{bare, yaml} {
		if k, err := readKeyFile(p); err != nil || !bytes.Equal(k, testKey) {
			t.Fatalf("%s: %x, %v", filepath.Base(p), k, err)
		}
	}
	_ = os.WriteFile(bare, []byte("nope"), 0o600)
	if _, err := readKeyFile(bare); !errors.Is(err, errBadKey) {
		t.Fatalf("bad key: %v", err)
	}
}

func TestOnlyLocalPeersMaySpeak(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:5000": true, "10.88.0.4:5000": true, "100.64.1.1:5000": true,
		"8.8.8.8:5000": false, "[2001:db8::1]:5000": false,
	} {
		tcp, _ := net.ResolveTCPAddr("tcp", addr)
		if localPeer(tcp) != ok {
			t.Errorf("%s: want %v", addr, ok)
		}
	}
}

func TestTheExitPolicyHoldsForTargets(t *testing.T) {
	dial := allowedDialer("")
	for _, target := range []string{"127.0.0.1:80", "10.0.0.1:80", "192.168.1.1:443", "[::1]:80"} {
		if _, err := dial(context.Background(), target); err == nil {
			t.Errorf("%s was dialed", target)
		}
	}
}
