package bond

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"testing"
	"time"
)

// A lane's runtime can end and be restarted by the app on the same local port
// 20 to 130 s later; the bond server can be restarted under live streams; a
// lane can refuse while the others are still joining their rooms. Streams
// that are already open must take a returning lane back, fail fast instead of
// hanging when the server forgot them, and one lane's trouble must not switch
// bonding off for everyone.

// quickRedial shortens the client's redial and bench timing for one test, so
// a lane can be gone for several redial rounds within seconds.
func quickRedial(t *testing.T, base, bench time.Duration) {
	t.Helper()
	oldBase, oldBench := redialBase, benchFor
	redialBase, benchFor = base, bench
	t.Cleanup(func() { redialBase, benchFor = oldBase, oldBench })
}

// echoAll sends fresh bytes through every connection's echo; the first
// failure.
func echoAll(conns []net.Conn, rng *rand.Rand, p []byte) error {
	for i, c := range conns {
		rng.Read(p)
		if _, err := echoRound(c, p, 15*time.Second); err != nil {
			return fmt.Errorf("connection %d: %w", i, err)
		}
	}
	return nil
}

// usesLane has c alone send fresh bytes through its echo until lane i has
// carried at least 16 KiB more toward the app, or until deadline: whether it
// did. With the other connections idle, what lane i carries is c's.
func usesLane(t *testing.T, r *rig, c net.Conn, i int, rng *rand.Rand, p []byte, deadline time.Time) bool {
	t.Helper()
	start := laneRx(t, r.client.LaneBytes(), len(r.lanes))[i]
	for time.Now().Before(deadline) {
		rng.Read(p)
		if _, err := echoRound(c, p, 15*time.Second); err != nil {
			t.Fatalf("echo: %v", err)
		}
		if laneRx(t, r.client.LaneBytes(), len(r.lanes))[i]-start >= 16<<10 {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// Long connections (video, a download, a messenger) must not run on fewer
// lanes for the rest of their life because a lane was gone for longer than a
// few redials. The outage is 320 redial bases long, so a redial budget that
// is merely larger (eight doublings reach 255 bases) still runs out before
// the lane is back.
func TestOpenStreamsTakeBackALaneThatReturnsLate(t *testing.T) {
	quickRedial(t, 25*time.Millisecond, 2*time.Second)
	lanes := []*testLane{
		newTestLane(t, 2<<20, 20*time.Millisecond),
		newTestLane(t, 2<<20, 20*time.Millisecond),
		newTestLane(t, 2<<20, 20*time.Millisecond),
	}
	r := newRig(t, testKey, "", "", lanes...)
	target := echo(t)
	open := make([]net.Conn, 3)
	for i := range open {
		c, rep := r.dial(t, target, "", "")
		if rep != repSuccess {
			t.Fatalf("connection %d: reply %d", i, rep)
		}
		open[i] = c
	}
	rng := rand.New(rand.NewSource(31))
	p := make([]byte, 64<<10)
	busy := func() {
		t.Helper()
		if err := echoAll(open, rng, p); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	for i := 0; i < 5; i++ {
		busy()
	}

	// Lane 1's runtime ends; the supervisor brings it back on the same port
	// 8 s later, far past the first few redials.
	lanes[1].down()
	for gone := time.Now(); time.Since(gone) < 8*time.Second; {
		busy()
	}
	lanes[1].up(t)
	back := time.Now()
	connects := lanes[1].connects.Load()
	rx := laneRx(t, r.client.LaneBytes(), 3)[1]
	for {
		busy()
		redials := lanes[1].connects.Load() - connects
		carried := laneRx(t, r.client.LaneBytes(), 3)[1] - rx
		if redials >= int64(len(open)) && carried > 0 {
			t.Logf("the open connections dialed lane 1 again %v after it came back", time.Since(back).Round(time.Millisecond))
			break
		}
		if time.Since(back) > 20*time.Second {
			t.Fatalf("lane 1 has been back for 20 s: the %d open connections dialed it %d times and it carried %d bytes for them",
				len(open), redials, carried)
		}
	}
	for i, c := range open {
		if !usesLane(t, r, c, 1, rng, p, time.Now().Add(10*time.Second)) {
			t.Fatalf("connection %d carries nothing over lane 1 since it came back", i)
		}
	}
}

// A lane that could not be reached when a connection opened, whether its dial
// failed or it was benched and not even tried, must still be taken up by that
// connection once it is back.
func TestStreamOpenedWhileLaneBenchedUsesItLater(t *testing.T) {
	quickRedial(t, 100*time.Millisecond, 2*time.Second)
	lanes := []*testLane{
		newTestLane(t, 2<<20, 20*time.Millisecond),
		newTestLane(t, 2<<20, 20*time.Millisecond),
		newTestLane(t, 2<<20, 20*time.Millisecond),
	}
	r := newRig(t, testKey, "", "", lanes...)
	target := echo(t)
	lanes[2].down()
	// The first two connections try lane 2 and fail (two failures bench it);
	// the third opens while it is benched and does not try it.
	how := []string{
		"lane 2 was down and its dial failed",
		"lane 2 was down and its second failed dial benched it",
		"lane 2 was benched and not tried",
	}
	conns := make([]net.Conn, len(how))
	for i := range conns {
		c, rep := r.dial(t, target, "", "")
		if rep != repSuccess {
			t.Fatalf("connection %d: reply %d", i, rep)
		}
		conns[i] = c
	}
	opened := time.Now()
	rng := rand.New(rand.NewSource(32))
	p := make([]byte, 64<<10)
	for time.Since(opened) < 6*time.Second {
		if err := echoAll(conns, rng, p); err != nil {
			t.Fatal(err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	connects := lanes[2].connects.Load()
	lanes[2].up(t)
	back := time.Now()
	deadline := back.Add(20 * time.Second)
	for _, i := range []int{2, 0, 1} {
		if !usesLane(t, r, conns[i], 2, rng, p, deadline) {
			t.Fatalf("lane 2 has been back for %v: connection %d (opened when %s) never took it up; lane 2 got %d CONNECTs since",
				time.Since(back).Round(time.Millisecond), i, how[i], lanes[2].connects.Load()-connects)
		}
	}
	t.Logf("every connection carries data over lane 2 %v after it came back", time.Since(back).Round(time.Millisecond))
}

// A restarted bond server (a crash, or the app redeploying it) knows none of
// the old streams. A lane's redial must not open such a stream again there
// (that dials the target a second time and splices the middle of one
// conversation onto a new one): the app's connection must end at once so the
// app can retry, instead of hanging. A server that still knows the stream
// takes it back, though: when every lane drops at once (a network change)
// and the lanes call back, the connection carries on.
func TestBondServerRestartFailsOpenStreamsFast(t *testing.T) {
	target, dialed := countedEcho(t)
	srv := startRestartableServer(t, testKey)
	lanes := []*testLane{newTestLane(t, 0, 10*time.Millisecond), newTestLane(t, 0, 10*time.Millisecond)}
	r := clientRig(t, srv.port, "", "", lanes...)
	app, rep := r.dial(t, target, "", "")
	if rep != repSuccess {
		t.Fatalf("reply %d", rep)
	}
	rng := rand.New(rand.NewSource(33))
	p := make([]byte, 1000)
	rounds := func(when string) {
		t.Helper()
		for i := 0; i < 20; i++ {
			rng.Read(p)
			if _, err := echoRound(app, p, 10*time.Second); err != nil {
				t.Fatalf("%s: %v", when, err)
			}
		}
	}
	rounds("before the restart")
	for _, l := range lanes {
		l.kill()
	}
	rounds("every lane dropped at once while the bond server ran on, and the connection did not survive it")
	if n := dialed.Load(); n != 1 {
		t.Fatalf("the target was dialed %d times before the restart", n)
	}

	srv.restart(t)
	restarted := time.Now()
	_ = app.SetDeadline(restarted.Add(20 * time.Second))
	rng.Read(p)
	_, err := app.Write(p)
	buf := make([]byte, 64<<10)
	read := 0
	for err == nil {
		var n int
		n, err = app.Read(buf)
		read += n
	}
	took := time.Since(restarted)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("the connection still hangs 20 s after the bond server restarted (%d bytes came back; the target was dialed %d times)",
			read, dialed.Load())
	}
	t.Logf("the connection ended %v after the restart (%d bytes came back): %v", took.Round(time.Millisecond), read, err)
	if took > 5*time.Second {
		t.Fatalf("the connection ended only %v after the bond server restarted (limit 5 s)", took.Round(time.Millisecond))
	}
	// A redial still on its way gets the time to reach the new server.
	time.Sleep(2 * time.Second)
	if n := dialed.Load(); n != 1 {
		t.Fatalf("the target was dialed %d times: a lane's redial opened the stream again on the restarted server", n)
	}
	// The app's retry goes through the restarted server, bonded.
	again, rep := r.dial(t, target, "", "")
	if rep != repSuccess {
		t.Fatalf("a new connection after the restart: reply %d", rep)
	}
	if _, err := echoRound(again, []byte("again"), 10*time.Second); err != nil {
		t.Fatalf("a new connection after the restart: %v", err)
	}
	if r.client.Bonded() != 2 || r.client.Plain() != 0 {
		t.Fatalf("a new connection after the restart was not bonded (bonded %d, plain %d)", r.client.Bonded(), r.client.Plain())
	}
}

// A lane whose tunnel session is gone answers a CONNECT with "host
// unreachable" at once, and one whose exit found nothing listening on the
// bond server's port (a server restarting) gets "connection refused", while
// lanes rejoining their rooms answer only after bondWait. Either is one lane
// in trouble, not a bond server that cannot be reached: bonding must not be
// switched off, and once the lanes answer normally, connections bond again
// instead of going plain for bondOffFor.
func TestOneLaneFailingDoesNotSwitchBondingOff(t *testing.T) {
	const connRefused byte = 5 // SOCKS5 "connection refused"
	for _, tc := range []struct {
		name string
		code byte
	}{
		{"host unreachable", repHostUnreachable},
		{"connection refused", connRefused},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel() // both cases wait out the slow lanes, side by side
			lanes := []*testLane{
				newTestLane(t, 0, 10*time.Millisecond),
				newTestLane(t, 0, 10*time.Millisecond),
				newTestLane(t, 0, 10*time.Millisecond),
			}
			r := newRig(t, testKey, "", "", lanes...)
			target := echo(t)
			lanes[0].refuse.Store(int32(tc.code))
			lanes[1].hold.Store(int64(10 * time.Second)) // longer than bondWait (8 s)
			lanes[2].hold.Store(int64(10 * time.Second))
			start := time.Now()
			first, rep := r.dial(t, target, "", "")
			if rep == repSuccess {
				// Through, so the counters have settled for it.
				if _, err := echoRound(first, []byte("first"), 10*time.Second); err != nil {
					t.Fatalf("first connection: %v", err)
				}
			}
			t.Logf("first connection: reply %d after %v; bonded %d, plain %d",
				rep, time.Since(start).Round(time.Millisecond), r.client.Bonded(), r.client.Plain())
			if r.client.isOff() {
				t.Fatalf("lane 0 answered %q while the other lanes were still on their way: bonding was switched off for everyone", tc.name)
			}

			lanes[0].refuse.Store(0)
			lanes[1].hold.Store(0)
			lanes[2].hold.Store(0)
			bonded, plain := r.client.Bonded(), r.client.Plain()
			c, rep := r.dial(t, target, "", "")
			if rep != repSuccess {
				t.Fatalf("second connection: reply %d", rep)
			}
			if _, err := echoRound(c, []byte("second"), 10*time.Second); err != nil {
				t.Fatalf("second connection: %v", err)
			}
			if r.client.Plain() != plain || r.client.Bonded() != bonded+1 {
				t.Fatalf("with every lane answering again a new connection was not bonded (bonded %d -> %d, plain %d -> %d): one lane's failure switched bonding off for everyone",
					bonded, r.client.Bonded(), plain, r.client.Plain())
			}
		})
	}
}
