package bond

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

// Found in the field: a room held down to a trickle for a while (VK's dark
// spells, Telemost holding a peer back) was judged slow and then got no
// frame to prove otherwise for the rest of the stream, and every new stream
// took the old reading from the lane's stats; only an app restart (a new
// client, fresh stats) brought it back.
func TestASlowLaneThatSpeedsUpCarriesAgain(t *testing.T) {
	lanes := []*testLane{
		newTestLane(t, 1<<20, 30*time.Millisecond),
		newTestLane(t, 1<<20, 30*time.Millisecond),
		newTestLane(t, 20<<10, 60*time.Millisecond),
	}
	r := newRig(t, testKey, "", "", lanes...)
	const n = 30 << 20
	c, rep := r.dial(t, source(t, n, 13), "", "")
	if rep != repSuccess {
		t.Fatalf("reply %d", rep)
	}
	slow := r.client.statsOf(2)
	var before int64
	var spedUpAt time.Time
	got, total := readAll(t, c, func(total int) {
		if total > 8<<20 && spedUpAt.IsZero() {
			spedUpAt = time.Now()
			before = slow.rx.Load()
			lanes[2].setRate(1 << 20)
		}
	})
	if total != n || got != digest(n, 13) {
		t.Fatalf("got %d of %d bytes, intact=%v", total, n, got == digest(n, 13))
	}
	if spedUpAt.IsZero() {
		t.Fatal("the lane never sped up")
	}
	carried := slow.rx.Load() - before
	t.Logf("the 20 KiB/s lane carried %d KiB of the first 8 MiB; sped up to 1 MiB/s, it carried %.1f MiB of the remaining 22 MiB in %v",
		before>>10, float64(carried)/(1<<20), time.Since(spedUpAt).Round(time.Millisecond))
	if carried < 2<<20 {
		t.Fatalf("after speeding up, the lane carried %.1f MiB of the remaining 22 MiB (want 2 MiB or more): the stream never looked at it again",
			float64(carried)/(1<<20))
	}
}

// Stopping the client (the app disconnects, or its session restarts) ends
// every stream with a word to the server, so it lets the targets go at once
// instead of waiting out the lanes for orphanWait on each.
func TestAStoppedClientTellsTheServer(t *testing.T) {
	lanes := []*testLane{
		newTestLane(t, 0, 5*time.Millisecond),
		newTestLane(t, 0, 5*time.Millisecond),
		newTestLane(t, 0, 5*time.Millisecond),
	}
	r := newRig(t, testKey, "", "", lanes...)
	target := echo(t)
	const streams = 4
	for i := 0; i < streams; i++ {
		c, rep := r.dial(t, target, "", "")
		if rep != repSuccess {
			t.Fatalf("connection %d: reply %d", i, rep)
		}
		if _, err := echoRound(c, []byte("ping"), 10*time.Second); err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
	}
	time.Sleep(500 * time.Millisecond) // the late lanes join
	start := time.Now()
	r.client.Stop()
	for {
		r.server.mu.Lock()
		open := r.server.active
		r.server.mu.Unlock()
		if open == 0 {
			break
		}
		if time.Since(start) > 5*time.Second {
			t.Fatalf("%d of %d streams still open on the server 5 s after the client stopped: it waits out the lanes instead of being told",
				open, streams)
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Logf("%d streams ended on the server %v after Stop", streams, time.Since(start).Round(time.Millisecond))
	r.server.log.mu.Lock()
	told := r.server.log.failures["the client reset it"]
	r.server.log.mu.Unlock()
	if told != streams {
		t.Fatalf("the server took %d of %d streams as reset by the client", told, streams)
	}
}

// A target the bond server takes long to dial (a name that does not resolve,
// a host that drops the SYN) is the server's verdict to give: the lanes
// carried the hello fine, and must not count a failure each, let alone sit
// out, for every such connection.
func TestASlowTargetDialDoesNotBenchTheLanes(t *testing.T) {
	old := subTimeout
	subTimeout = 2 * time.Second
	defer func() { subTimeout = old }()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	srv := newServer(func() ([]byte, error) { return testKey, nil },
		func(ctx context.Context, target string) (net.Conn, error) {
			if strings.HasPrefix(target, "203.0.113.") {
				select {
				case <-time.After(3 * time.Second):
				case <-ctx.Done():
				}
				return nil, errors.New("no route to host")
			}
			var d net.Dialer
			return d.DialContext(ctx, "tcp", target)
		})
	go func() { _ = srv.serve(ln) }()
	lanes := []*testLane{
		newTestLane(t, 0, 20*time.Millisecond),
		newTestLane(t, 0, 20*time.Millisecond),
		newTestLane(t, 0, 20*time.Millisecond),
	}
	r := clientRig(t, ln.Addr().(*net.TCPAddr).Port, "", "", lanes...)
	r.server = srv

	start := time.Now()
	_, rep := r.dial(t, "203.0.113.9:443", "", "")
	took := time.Since(start)
	if rep != repHostUnreachable {
		t.Fatalf("a target the server cannot reach: reply %d after %v, want host unreachable (%d) from the server's own verdict",
			rep, took.Round(time.Millisecond), repHostUnreachable)
	}
	if took > 10*time.Second {
		t.Fatalf("the server's verdict took %v to reach the app (its dial gave up after 3 s)", took.Round(time.Millisecond))
	}
	r.client.mu.Lock()
	failed, benched := 0, 0
	for _, l := range r.client.lanes {
		failed += l.failures
		if time.Now().Before(l.benched) {
			benched++
		}
	}
	r.client.mu.Unlock()
	if failed+benched > 0 {
		t.Fatalf("the lanes counted %d failures (%d sit out) for the server's slow dial of a target", failed, benched)
	}
	c, rep := r.dial(t, echo(t), "", "")
	if rep != repSuccess {
		t.Fatalf("the next connection: reply %d", rep)
	}
	if _, err := echoRound(c, []byte("ping"), 10*time.Second); err != nil {
		t.Fatal(err)
	}
	if b := r.client.Bonded(); b != 1 {
		t.Fatalf("the next connection went plain (bonded %d)", b)
	}
	t.Logf("unreachable target answered in %v, lanes untouched, the next connection bonded", took.Round(time.Millisecond))
}
