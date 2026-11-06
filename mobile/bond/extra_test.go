package bond

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The parts of the lane recovery, restart, logging and striping fixes the
// acceptance tests do not reach directly: the rejoin mark on the wire, the
// server's side of a rejoin, a restart that sends no end frame, how one
// lane's or every lane's "cannot reach it" counts, the wake-up of waiting
// redials and their one-at-a-time calls to a lane in trouble, what the server
// log may say, which lane may take a frame, the re-timing of what a lane
// holds once it proves its speed, what a lane's speed is read from, and the
// reorder window toward older and newer peers.

func TestRejoinRidesInTheLanesByte(t *testing.T) {
	now := time.Now()
	h := hello{client: [8]byte{1}, lane: 2, lanes: 3, rejoin: true, unix: uint64(now.Unix()), target: "example.org:443"}
	h.session[0] = 9
	b, err := h.marshal(testKey)
	if err != nil {
		t.Fatal(err)
	}
	first := h
	first.rejoin = false
	fb, _ := first.marshal(testKey)
	if len(b) != len(fb) {
		t.Fatalf("a rejoin hello is %d bytes, a first one %d: the layout changed", len(b), len(fb))
	}
	// A server from before the mark stores this byte as the lane count and
	// never reads it.
	if b[29] != 0x83 || fb[29] != 0x03 {
		t.Fatalf("lanes byte %#x (rejoin) and %#x (first)", b[29], fb[29])
	}
	got, err := readHello(bytes.NewReader(b), testKey, now)
	if err != nil || got != h {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
	// However many lanes, the count never spills into the mark.
	many := first
	many.lanes = 200
	mb, _ := many.marshal(testKey)
	if got, err := readHello(bytes.NewReader(mb), testKey, now); err != nil || got.rejoin {
		t.Fatalf("200 lanes read back as %+v, %v", got, err)
	}
}

// subConn is a lane's sub-connection to the bond server without the lane:
// the hello sent, and the server's one-byte reply read.
func subConn(t *testing.T, port int, h hello) (net.Conn, byte) {
	t.Helper()
	c, err := net.Dial("tcp", laneAddr(port))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	h.unix = uint64(time.Now().Unix())
	b, err := h.marshal(testKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(b); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	var reply [1]byte
	if _, err := io.ReadFull(c, reply[:]); err != nil {
		t.Fatalf("no reply: %v", err)
	}
	_ = c.SetReadDeadline(time.Time{})
	return c, reply[0]
}

// sendHello is subConn's reply alone.
func sendHello(t *testing.T, port int, h hello) byte {
	t.Helper()
	_, reply := subConn(t, port, h)
	return reply
}

func TestServerTurnsAwayARejoinItDoesNotKnow(t *testing.T) {
	target, dialed := countedEcho(t)
	_, port := startServer(t, testKey)
	stray := hello{lane: 1, lanes: 2, rejoin: true, target: target}
	stray.session[0] = 1
	if reply := sendHello(t, port, stray); reply != replyRefused {
		t.Fatalf("a rejoin for a stream the server never saw: reply %d", reply)
	}
	time.Sleep(100 * time.Millisecond)
	if n := dialed.Load(); n != 0 {
		t.Fatalf("the target was dialed %d times for a stream the server never saw", n)
	}
	// A stream a first hello opened takes its lanes back.
	open := hello{lane: 0, lanes: 2, target: target}
	open.session[0] = 2
	if reply := sendHello(t, port, open); reply != replyOK {
		t.Fatalf("first hello: reply %d", reply)
	}
	back := open
	back.lane, back.rejoin = 1, true
	if reply := sendHello(t, port, back); reply != replyOK {
		t.Fatalf("a rejoin for an open stream: reply %d", reply)
	}
	if n := dialed.Load(); n != 1 {
		t.Fatalf("the target was dialed %d times for one stream", n)
	}
}

// cutListener cuts every connection it accepted, and itself, while the
// server's connections to targets stay up: a restart as the client sees it,
// without the end frame an in-process crash can let out when it closes a
// target before the lanes.
type cutListener struct {
	net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func (l *cutListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil {
		l.mu.Lock()
		l.conns = append(l.conns, c)
		l.mu.Unlock()
	}
	return c, err
}

func (l *cutListener) cut() {
	_ = l.Listener.Close()
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.conns {
		_ = c.Close()
	}
}

func TestARestartedServerEndsTheStreamItForgot(t *testing.T) {
	quickRedial(t, 200*time.Millisecond, 2*time.Second)
	target, dialed := countedEcho(t)
	newSrv := func() *server {
		return newServer(func() ([]byte, error) { return testKey, nil },
			func(ctx context.Context, target string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", target)
			})
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	before := &cutListener{Listener: ln}
	t.Cleanup(before.cut)
	go func() { _ = newSrv().serve(before) }()
	r := clientRig(t, ln.Addr().(*net.TCPAddr).Port, "", "", newTestLane(t, 0, 5*time.Millisecond), newTestLane(t, 0, 5*time.Millisecond))
	app, rep := r.dial(t, target, "", "")
	if rep != repSuccess {
		t.Fatalf("reply %d", rep)
	}
	if _, err := echoRound(app, []byte("before"), 5*time.Second); err != nil {
		t.Fatal(err)
	}

	before.cut()
	after, err := listenAgain(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = after.Close() })
	go func() { _ = newSrv().serve(after) }()
	start := time.Now()
	_ = app.SetReadDeadline(start.Add(10 * time.Second))
	_, err = io.Copy(io.Discard, app)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatal("the connection hangs after the bond server restarted")
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("the connection ended %v after the restart", took.Round(time.Millisecond))
	}
	if n := dialed.Load(); n != 1 {
		t.Fatalf("the target was dialed %d times", n)
	}
}

func TestEveryLaneSayingUnreachableSwitchesBondingOff(t *testing.T) {
	lanes := []*testLane{newTestLane(t, 0, 0), newTestLane(t, 0, 0)}
	r := newRig(t, testKey, "", "", lanes...)
	for _, l := range lanes {
		l.refuse.Store(int32(repHostUnreachable))
	}
	_, _ = r.dial(t, echo(t), "", "")
	if !r.client.isOff() {
		t.Fatal("every lane said the bond server cannot be reached, and bonding stayed on")
	}
}

func TestALaneThatKeepsSayingUnreachableSitsOut(t *testing.T) {
	lanes := []*testLane{newTestLane(t, 0, 0), newTestLane(t, 0, 0), newTestLane(t, 0, 0)}
	r := newRig(t, testKey, "", "", lanes...)
	lanes[0].refuse.Store(int32(repHostUnreachable))
	target := echo(t)
	// Connections that carry enough to call every lane (see joinAfter).
	p := make([]byte, joinAfter)
	for i := 0; i < 2; i++ {
		c, rep := r.dial(t, target, "", "")
		if rep != repSuccess {
			t.Fatalf("connection %d: reply %d", i, rep)
		}
		if _, err := echoRound(c, p, 5*time.Second); err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
	}
	for deadline := time.Now().Add(5 * time.Second); !r.client.isBenched(0); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("lane 0 answered host unreachable twice and still takes new connections")
		}
	}
	if r.client.isOff() || r.client.Bonded() != 2 {
		t.Fatalf("bonding off %v, bonded %d of 2", r.client.isOff(), r.client.Bonded())
	}
}

// A stream that waits out a long redial delay calls the lane back as soon as
// the lane carries again for any other connection.
func TestARedialWakesWhenTheLaneIsBack(t *testing.T) {
	quickRedial(t, 5*time.Second, 2*time.Second)
	lanes := []*testLane{newTestLane(t, 0, 0), newTestLane(t, 0, 0), newTestLane(t, 0, 0)}
	r := newRig(t, testKey, "", "", lanes...)
	target := echo(t)
	rng := rand.New(rand.NewSource(41))
	// Streams carry enough to have every lane (see joinAfter).
	bulk := func(c net.Conn) {
		t.Helper()
		p := make([]byte, joinAfter)
		rng.Read(p)
		if _, err := echoRound(c, p, 5*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	waiting, rep := r.dial(t, target, "", "")
	if rep != repSuccess {
		t.Fatalf("reply %d", rep)
	}
	bulk(waiting)
	if !usesLane(t, r, waiting, 2, rng, make([]byte, 64<<10), time.Now().Add(5*time.Second)) {
		t.Fatal("the stream never carried anything over lane 2")
	}
	// Lane 2's runtime ends: the stream waits out its long redial delay.
	lanes[2].down()
	time.Sleep(200 * time.Millisecond)
	lanes[2].up(t)
	connects := lanes[2].connects.Load()
	other, rep := r.dial(t, target, "", "")
	if rep != repSuccess {
		t.Fatalf("reply %d", rep)
	}
	bulk(other)
	start := time.Now()
	for lanes[2].connects.Load()-connects < 2 {
		if time.Since(start) > 3*time.Second {
			r.client.mu.Lock()
			l := *r.client.lanes[2]
			r.client.mu.Unlock()
			t.Fatalf("the waiting stream did not call lane 2 back once it carried again (%d calls since; lane 2: %d failures, benched %v, dropped %v, probing %v)",
				lanes[2].connects.Load()-connects, l.failures, time.Now().Before(l.benched), l.dropped, l.probing)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !usesLane(t, r, waiting, 2, rng, make([]byte, 64<<10), time.Now().Add(5*time.Second)) {
		t.Fatal("the waiting stream carries nothing over lane 2")
	}
}

// logLines collects what the log package writes while a test runs.
type logLines struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logLines) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logLines) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

func TestServerLogNamesNoTargetAndHoldsFloodsBack(t *testing.T) {
	out := &logLines{}
	old := log.Writer()
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(old) })

	addr := &net.TCPAddr{IP: net.IPv4(93, 184, 216, 34), Port: 443}
	targetErr := &net.OpError{Op: "read", Net: "tcp", Addr: addr, Err: os.NewSyscallError("read", syscall.ECONNRESET)}
	for _, err := range []error{targetErr, errLanesLost, errPeerReset, fmt.Errorf("pump: %w", targetErr)} {
		if why, detail := failure(err); strings.Contains(why+detail, "93.184") || strings.Contains(why+detail, "443") {
			t.Fatalf("%v is logged as %q %q", err, why, detail)
		}
	}

	var l serverLog
	const marker = "flood-marker"
	for i := 0; i < 3*warnBurst; i++ {
		l.warn("flood", marker+" %d", i)
	}
	if n := strings.Count(out.String(), marker); n != warnBurst {
		t.Fatalf("%d of %d lines of one kind written in a minute (limit %d)", n, 3*warnBurst, warnBurst)
	}
	why, detail := failure(errLanesLost)
	l.failed([16]byte{0xde, 0xad, 0xbe, 0xef}, 3*time.Second, why, detail)
	if !strings.Contains(out.String(), "deadbeef failed after 3s: every lane was gone") {
		t.Fatalf("a failed session is not logged with its reason and duration:\n%s", out.String())
	}
	why, detail = failure(fmt.Errorf("pump: %w", targetErr))
	l.failed([16]byte{0xfe, 0xed}, time.Second, why, detail)
	if !strings.Contains(out.String(), "feed0000 failed after 1s: its target connection failed (reset by peer)") {
		t.Fatalf("a failed target connection is not logged with what kind of failure it was:\n%s", out.String())
	}
	line := l.summary(2)
	for _, want := range []string{"2 open", "2 failed", "every lane was gone", "its target connection failed (reset by peer): 1",
		fmt.Sprintf("%d lines held back", 2*warnBurst)} {
		if !strings.Contains(line, want) {
			t.Fatalf("summary %q lacks %q", line, want)
		}
	}
	if line := l.summary(0); line != "" {
		t.Fatalf("an idle period still logs %q", line)
	}
}

func TestATrickleLaneIsKeptOffFramesTheOthersCarrySooner(t *testing.T) {
	now := time.Now()
	holding := func(sb *sub, n int64) *sub {
		sb.sent = n
		sb.flights = []flight{{end: n, at: now, due: now.Add(time.Hour)}}
		return sb
	}
	fast := holding(&sub{lane: 0, rate: 1 << 20, minRTT: 60 * time.Millisecond, proven: true}, 256<<10) // a full queue, 0.25 s
	far := holding(&sub{lane: 1, rate: 2 << 20, minRTT: 200 * time.Millisecond, proven: true}, 400<<10) // farther away, as fast
	trickle := &sub{lane: 2, rate: 20 << 10, minRTT: 120 * time.Millisecond, proven: true}              // idle, but a frame takes it 0.8 s
	unknown := &sub{lane: 3, rate: 50, minRTT: 120 * time.Millisecond}                                  // has carried only pings: a floor, not a speed
	s := &stripe{subs: []*sub{fast, far, trickle, unknown}}
	for _, c := range []struct {
		sb   *sub
		want bool
		what string
	}{
		{fast, true, "the fast lane"},
		{far, true, "a lane farther away but as fast"},
		{trickle, false, "a trickling lane"},
		{unknown, true, "a lane that has to learn its speed"},
	} {
		if got := s.timely(c.sb, maxPayload, now); got != c.want {
			t.Errorf("%s may take a full frame: %v, want %v", c.what, got, c.want)
		}
	}
	// Lanes far behind with what they hold (gone dark) hand the turn on.
	s.subs = []*sub{fast, trickle}
	fast.flights[0].due = now.Add(-2 * time.Second)
	if !s.timely(trickle, maxPayload, now) {
		t.Error("with the only other lane 2 s behind, the trickling lane still may not carry")
	}
}

func TestWhatALaneHoldsIsRetimedOnceItsSpeedIsKnown(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	s := newStripe(local)
	defer s.finish()
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	sb := &sub{lane: 0}
	for seq := uint32(0); seq < 2; seq++ {
		f := &outFrame{payload: make([]byte, 994), holder: sb, due: now.Add(sb.eta(994))}
		s.frames[seq] = f
		sb.sent += frameSize(f.payload)
		sb.flights = append(sb.flights, flight{seq: seq, end: sb.sent, at: now, due: f.due})
	}
	if d := s.frames[1].due.Sub(now); d != etaGuess {
		t.Fatalf("a frame on a lane with nothing measured is due in %v, want the guess %v", d, etaGuess)
	}
	// The lane proves slow: 1000 bytes take it 0.1 s, plus 50 ms on the way.
	sb.rate, sb.minRTT, sb.proven = 10_000, 100*time.Millisecond, true
	s.retime(sb, now)
	want := now.Add(250 * time.Millisecond) // both frames, 2000 bytes, then half a round trip
	if got := s.frames[1].due; got.Sub(want).Abs() > time.Millisecond || sb.flights[1].due != got {
		t.Fatalf("the second frame is due %v after its speed is known, want %v", got.Sub(now), want.Sub(now))
	}
}

func TestASenderKeepsThePeersReorderBufferSmall(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	s := newStripe(local)
	defer s.finish()
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := 0; i < 600; i++ {
		s.cut([]byte{byte(i)})
	}
	sb := &sub{lane: 0, rate: 100 << 20, minRTT: time.Millisecond}
	taken := 0
	for {
		if _, _, ok := s.take(sb, time.Now()); !ok {
			break
		}
		taken++
	}
	// The peer holds every one of them while its app does not read.
	if taken != 256 {
		t.Fatalf("%d frames went out past the peer's delivery point (limit 256: 4 MiB of 16 KiB frames)", taken)
	}
}

func TestAReceiverTakesWhatAnOlderSenderSends(t *testing.T) {
	// A sender from before the window was halved sends up to 512 frames past
	// what the receiver has delivered.
	const olderWindow = 512
	local, peer := net.Pipe()
	defer peer.Close()
	s := newStripe(local)
	defer s.finish()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.file(0, inFrame{kind: kindData, seq: olderWindow - 1, payload: []byte{1}}); err != nil {
		t.Fatalf("a frame %d past the delivery point: %v", olderWindow-1, err)
	}
	if err := s.file(0, inFrame{kind: kindData, seq: 4 * olderWindow, payload: []byte{1}}); !errors.Is(err, errBadFrame) {
		t.Fatalf("a frame far past any window: %v", err)
	}
}

// A frame no sender keeping to its window sends fails the session, and the
// server's line says which lane brought it and its numbers.
func TestABadFrameIsLoggedWithItsLaneAndNumbers(t *testing.T) {
	out := &logLines{}
	old := log.Writer()
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(old) })

	_, port := startServer(t, testKey)
	h := hello{lane: 1, lanes: 3, target: echo(t)}
	h.session[0] = 3
	c, reply := subConn(t, port, h)
	if reply != replyOK {
		t.Fatalf("reply %d", reply)
	}
	if _, err := c.Write(appendFrame(nil, 600, []byte("abc"))); err != nil {
		t.Fatal(err)
	}
	const want = "a bad frame on lane 2 (seq 600, expected from 0, 3 bytes)"
	for deadline := time.Now().Add(5 * time.Second); !strings.Contains(out.String(), want); {
		if time.Now().After(deadline) {
			t.Fatalf("the server's log lacks %q:\n%s", want, out.String())
		}
		time.Sleep(20 * time.Millisecond)
	}

	// The summary counts the reason, not each frame's numbers.
	var l serverLog
	err := &badFrameError{lane: 0, seq: 70123, next: 69500, finSeq: 70200, size: 1380}
	if !errors.Is(err, errBadFrame) {
		t.Fatal("a bad frame's error is not errBadFrame to errors.Is")
	}
	why, detail := failure(fmt.Errorf("stream: %w", err))
	l.started()
	l.failed([16]byte{1}, time.Second, why, detail)
	if want := "a bad frame on lane 1 (seq 70123, expected from 69500, end at 70200, 1380 bytes)"; !strings.Contains(out.String(), want) {
		t.Fatalf("the server's log lacks %q:\n%s", want, out.String())
	}
	if line := l.summary(0); !strings.Contains(line, "(a bad frame: 1)") {
		t.Fatalf("summary %q", line)
	}
}

func TestATargetFailureSaysWhatKindItWas(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(93, 184, 216, 34), Port: 443}
	op := func(name string, err error) error {
		return fmt.Errorf("pump: %w", &net.OpError{Op: name, Net: "tcp", Addr: addr, Err: os.NewSyscallError(name, err)})
	}
	for _, c := range []struct {
		err  error
		kind string
	}{
		{io.ErrUnexpectedEOF, "EOF"},
		{op("read", syscall.ECONNRESET), "reset by peer"},
		{op("write", syscall.EPIPE), "broken pipe"},
		{op("read", syscall.ETIMEDOUT), "timed out"},
		{&net.OpError{Op: "read", Net: "tcp", Addr: addr, Err: os.ErrDeadlineExceeded}, "timed out"},
		{op("write", syscall.ECONNREFUSED), "refused"},
		{op("read", syscall.EHOSTUNREACH), "unreachable"},
		{op("write", syscall.ENETUNREACH), "unreachable"},
		{op("read", errors.New("no buffer space available")), "other"},
	} {
		want := "its target connection failed (" + c.kind + ")"
		if why, detail := failure(c.err); why != want || detail != "" {
			t.Errorf("%v: %q %q, want %q", c.err, why, detail, want)
		}
	}
}

func TestPingsDoNotPassForALanesSpeed(t *testing.T) {
	stats := &laneStats{}
	stats.store(1<<20, 50*time.Millisecond) // a download proved 1 MiB/s
	sb := &sub{stats: stats}
	now := time.Now()
	sb.sampleAt = now
	sb.sample(now.Add(time.Second), 300) // pings: 300 bytes in a second
	if r, _ := stats.load(); r != 1<<20 {
		t.Fatalf("a stream of pings told the next stream the lane does %.0f B/s, not the %d it proved", r, 1<<20)
	}
	if sb.proven {
		t.Fatal("pings proved a speed")
	}
	sb.busy = true // the lane held frames back: what it carried is its speed
	sb.sample(now.Add(2*time.Second), 300+600<<10)
	if r, _ := stats.load(); !sb.proven || r < 600<<10 {
		t.Fatalf("a full reading of 600 KiB/s: proven %v, passed on as %.0f B/s", sb.proven, r)
	}
}

// pingThenBulk is a target that answers each byte it gets with the same
// byte, until it gets 'b': then it sends n bytes and ends.
func pingThenBulk(t *testing.T, n int) string {
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
				cmd := make([]byte, 1)
				for {
					if _, err := io.ReadFull(c, cmd); err != nil {
						return
					}
					if cmd[0] == 'b' {
						_, _ = io.Copy(c, io.LimitReader(rand.New(rand.NewSource(13)), int64(n)))
						closeWrite(c)
						return
					}
					_, _ = c.Write(cmd)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// A connection that has carried only small messages has not shown any
// lane's speed: when it turns into a download, a trickling lane must not
// pass for a fast one and hold up what the others carry.
func TestATrickleLaneAddsNoStallsAfterPings(t *testing.T) {
	lanes := []*testLane{
		newTestLane(t, 1<<20, 30*time.Millisecond),
		newTestLane(t, 1<<20, 30*time.Millisecond),
		newTestLane(t, 20<<10, 60*time.Millisecond),
	}
	r := newRig(t, testKey, "", "", lanes...)
	const n = 8 << 20
	c, rep := r.dial(t, pingThenBulk(t, n), "", "")
	if rep != repSuccess {
		t.Fatalf("reply %d", rep)
	}
	for i := 0; i < 30; i++ {
		if _, err := echoRound(c, []byte("p"), 5*time.Second); err != nil {
			t.Fatalf("ping %d: %v", i, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := c.Write([]byte("b")); err != nil {
		t.Fatal(err)
	}
	var last time.Time
	var gap time.Duration
	got, total := readAll(t, c, func(int) {
		now := time.Now()
		if !last.IsZero() {
			gap = max(gap, now.Sub(last))
		}
		last = now
	})
	if total != n || got != digest(n, 13) {
		t.Fatalf("got %d of %d bytes, intact=%v", total, n, got == digest(n, 13))
	}
	t.Logf("a download after 30 pings, with a 20 KiB/s lane among two of 1 MiB/s: longest pause %v", gap.Round(time.Millisecond))
	if gap > 1200*time.Millisecond {
		t.Fatalf("the app saw a pause of %v (limit 1.2 s)", gap.Round(time.Millisecond))
	}
}

// A lane whose room is gone parks every CONNECT in its core for up to a
// minute and refuses all of them once 64 wait. When such a lane drops the
// open streams, they must not all call it back at once.
func TestStreamsCallATroubledLaneBackOneAtATime(t *testing.T) {
	quickRedial(t, 50*time.Millisecond, 2*time.Second)
	lanes := []*testLane{
		newTestLane(t, 0, 5*time.Millisecond),
		newTestLane(t, 0, 5*time.Millisecond),
		newTestLane(t, 0, 5*time.Millisecond),
	}
	r := newRig(t, testKey, "", "", lanes...)
	target := echo(t)
	conns := make([]net.Conn, 8)
	for i := range conns {
		c, rep := r.dial(t, target, "", "")
		if rep != repSuccess {
			t.Fatalf("connection %d: reply %d", i, rep)
		}
		conns[i] = c
	}
	time.Sleep(300 * time.Millisecond) // every lane joins every stream
	lanes[2].hold.Store(int64(1500 * time.Millisecond))
	lanes[2].refuse.Store(int32(repHostUnreachable))
	connects := lanes[2].connects.Load()
	lanes[2].kill()
	time.Sleep(time.Second) // the first calls back are still parked
	if n := lanes[2].connects.Load() - connects; n > 1 {
		t.Fatalf("%d of %d streams called lane 2 back at once while its core parked them", n, len(conns))
	}
	for i, c := range conns {
		if _, err := echoRound(c, []byte("still here"), 5*time.Second); err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
	}
}
