package bond

import (
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"sync"
	"testing"
	"time"
)

// A lane that goes dark (its peer stops confirming for a few seconds, as VK
// and Telemost rooms do about once a minute) or turns slow must cost the
// connections on it no more than a short hiccup, and what a connection holds
// in memory must stay bounded: the VPN extension lives in about 50 MB.

// pingTogether has every connection send size bytes through its echo and
// wait for them, gap apart, while more(round) says so: the slowest round
// trip, how many there were, how many took over a second, and the first
// failure.
func pingTogether(conns []net.Conn, size int, gap time.Duration, more func(round int) bool) (worst time.Duration, rounds, slow int, err error) {
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i, c := range conns {
		wg.Add(1)
		go func(i int, c net.Conn) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(i + 1)))
			p := make([]byte, size)
			for n := 0; more(n); n++ {
				rng.Read(p)
				d, e := echoRound(c, p, 15*time.Second)
				mu.Lock()
				rounds++
				worst = max(worst, d)
				if d > time.Second {
					slow++
				}
				if e != nil && err == nil {
					err = fmt.Errorf("connection %d, round %d: %w", i, n, e)
				}
				mu.Unlock()
				if e != nil {
					return
				}
				time.Sleep(gap)
			}
		}(i, c)
	}
	wg.Wait()
	return worst, rounds, slow, err
}

// Request/response connections (an idle chat, an API call) must not each wait
// out a dark lane on their own: a frame that is late there is sent again over
// another lane without waiting for other traffic to wake the stream, well
// before any stall timer. A round trip may take a hiccup, never a second: a
// stall timer that is merely shorter (1 s instead of 2) still costs every
// connection over a second.
func TestDarkLaneDoesNotFreezeOpenConnections(t *testing.T) {
	lanes := []*testLane{
		newTestLane(t, 2<<20, 30*time.Millisecond),
		newTestLane(t, 2<<20, 30*time.Millisecond),
		newTestLane(t, 2<<20, 30*time.Millisecond),
	}
	r := newRig(t, testKey, "", "", lanes...)
	target := echo(t)
	conns := make([]net.Conn, 6)
	for i := range conns {
		c, rep := r.dial(t, target, "", "")
		if rep != repSuccess {
			t.Fatalf("connection %d: reply %d", i, rep)
		}
		conns[i] = c
	}
	// Warm-up: every lane measured on every connection.
	healthy, _, _, err := pingTogether(conns, 300, 0, func(n int) bool { return n < 15 })
	if err != nil {
		t.Fatalf("warm-up: %v", err)
	}

	lanes[1].stalled.Store(true)
	dark := time.AfterFunc(5*time.Second, func() { lanes[1].stalled.Store(false) })
	defer dark.Stop()
	until := time.Now().Add(5 * time.Second)
	worst, rounds, slow, err := pingTogether(conns, 300, 200*time.Millisecond,
		func(int) bool { return time.Now().Before(until) })
	lanes[1].stalled.Store(false)
	if err != nil {
		t.Fatalf("while lane 1 was dark: %v", err)
	}
	t.Logf("healthy: slowest round trip %v; lane 1 dark for 5 s: slowest of %d round trips %v, %d over a second",
		healthy.Round(time.Millisecond), rounds, worst.Round(time.Millisecond), slow)
	if worst > time.Second {
		t.Fatalf("a round trip took %v while one of three lanes was dark (limit 1 s; %d of %d over a second): the connection waited out the dark lane by itself",
			worst.Round(time.Millisecond), slow, rounds)
	}
}

// A bulk transfer already does well on a dark lane (the acks of the other
// lanes keep it moving); it must stay that way.
func TestDarkLaneBulkKeepsFlowing(t *testing.T) {
	lanes := []*testLane{
		newTestLane(t, 1<<20, 30*time.Millisecond),
		newTestLane(t, 1<<20, 30*time.Millisecond),
		newTestLane(t, 1<<20, 30*time.Millisecond),
	}
	r := newRig(t, testKey, "", "", lanes...)
	const n = 14 << 20
	c, rep := r.dial(t, source(t, n, 7), "", "")
	if rep != repSuccess {
		t.Fatalf("reply %d", rep)
	}
	var last, darkAt time.Time
	var gap time.Duration
	got, total := readAll(t, c, func(total int) {
		now := time.Now()
		if !last.IsZero() {
			gap = max(gap, now.Sub(last))
		}
		last = now
		if total > 3<<20 && darkAt.IsZero() {
			darkAt = now
			lanes[1].stalled.Store(true)
			time.AfterFunc(5*time.Second, func() { lanes[1].stalled.Store(false) })
		}
	})
	if total != n || got != digest(n, 7) {
		t.Fatalf("got %d of %d bytes, intact=%v", total, n, got == digest(n, 7))
	}
	if darkAt.IsZero() {
		t.Fatal("the lane never went dark")
	}
	t.Logf("14 MiB over 3 x 1 MiB/s with lane 1 dark for 5 s: longest pause %v", gap.Round(time.Millisecond))
	if gap > 1500*time.Millisecond {
		t.Fatalf("the app saw a pause of %v (limit 1.5 s)", gap.Round(time.Millisecond))
	}
}

// A lane that is alive but crawls (Telemost or VK holding a room back to
// about 20 KiB/s) must not hold up frames the fast lanes would have
// delivered long ago: adding it may not help, but it must not hurt. The
// transfer runs for about 10 s because a lane flipping between stalled and
// not only starts to hold frames a few seconds in.
func TestTrickleLaneAddsNoStalls(t *testing.T) {
	run := func(withTrickle bool) (float64, time.Duration) {
		lanes := []*testLane{
			newTestLane(t, 1<<20, 30*time.Millisecond),
			newTestLane(t, 1<<20, 30*time.Millisecond),
		}
		if withTrickle {
			lanes = append(lanes, newTestLane(t, 20<<10, 60*time.Millisecond))
		}
		r := newRig(t, testKey, "", "", lanes...)
		const n = 20 << 20
		c, rep := r.dial(t, source(t, n, 11), "", "")
		if rep != repSuccess {
			t.Fatalf("reply %d", rep)
		}
		start := time.Now()
		var last time.Time
		var gap time.Duration
		got, total := readAll(t, c, func(int) {
			now := time.Now()
			if !last.IsZero() {
				gap = max(gap, now.Sub(last))
			}
			last = now
		})
		if total != n || got != digest(n, 11) {
			t.Fatalf("trickle=%v: got %d of %d bytes, intact=%v", withTrickle, total, n, got == digest(n, 11))
		}
		return float64(n) / time.Since(start).Seconds() / (1 << 20), gap
	}
	alone, alonePause := run(false)
	with, withPause := run(true)
	t.Logf("two 1 MiB/s lanes: %.2f MiB/s, longest pause %v; plus a 20 KiB/s lane: %.2f MiB/s, longest pause %v",
		alone, alonePause.Round(time.Millisecond), with, withPause.Round(time.Millisecond))
	if with < 0.85*alone {
		t.Errorf("the trickling lane cost speed: %.2f MiB/s with it, %.2f without (limit 0.85x)", with, alone)
	}
	if withPause > 1200*time.Millisecond {
		t.Errorf("with the trickling lane the app saw a pause of %v (limit 1.2 s)", withPause.Round(time.Millisecond))
	}
}

// heapInUse is the Go heap in use after a full collection.
func heapInUse() int64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return int64(m.HeapInuse)
}

// An app that stops reading (a paused player, a slow consumer) makes the
// stream buffer what is already on its way; that has to stay small enough for
// several such connections to fit in the VPN extension. The figure includes
// the in-process server's half and the test lanes' buffers.
func TestStalledReaderMemoryIsBounded(t *testing.T) {
	lanes := []*testLane{
		newTestLane(t, 0, 5*time.Millisecond),
		newTestLane(t, 0, 5*time.Millisecond),
		newTestLane(t, 0, 5*time.Millisecond),
	}
	r := newRig(t, testKey, "", "", lanes...)
	target := source(t, 64<<20, 9)
	before := heapInUse()
	const streams = 4
	for i := 0; i < streams; i++ {
		c, rep := r.dial(t, target, "", "")
		if rep != repSuccess {
			t.Fatalf("connection %d: reply %d", i, rep)
		}
		_ = c.(*net.TCPConn).SetReadBuffer(64 << 10)
		// The app never reads.
	}
	time.Sleep(6 * time.Second)
	each := float64(heapInUse()-before) / streams / (1 << 20)
	t.Logf("%d connections whose app does not read: %.1f MiB of Go heap each", streams, each)
	if each > 6 {
		t.Fatalf("%.1f MiB per connection whose app does not read (limit 6 MiB)", each)
	}
}

// The fixed cost of an idle bonded connection (client and server halves,
// and the test lanes' copy buffers) must not grow.
func TestIdleConnectionCostDoesNotGrow(t *testing.T) {
	lanes := []*testLane{
		newTestLane(t, 0, 5*time.Millisecond),
		newTestLane(t, 0, 5*time.Millisecond),
		newTestLane(t, 0, 5*time.Millisecond),
	}
	r := newRig(t, testKey, "", "", lanes...)
	target := echo(t)
	before := heapInUse()
	const n = 60
	for i := 0; i < n; i++ {
		c, rep := r.dial(t, target, "", "")
		if rep != repSuccess {
			t.Fatalf("connection %d: reply %d", i, rep)
		}
		if _, err := echoRound(c, []byte("ping"), 10*time.Second); err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
	}
	time.Sleep(2 * time.Second) // the late lanes join
	if b := r.client.Bonded(); b != n {
		t.Fatalf("bonded %d of %d", b, n)
	}
	each := float64(heapInUse()-before) / n / (1 << 20)
	t.Logf("%d idle bonded connections over 3 lanes: %.2f MiB of Go heap each", n, each)
	if each > 1.0 {
		t.Fatalf("%.2f MiB per idle bonded connection (limit 1.0 MiB)", each)
	}
}
