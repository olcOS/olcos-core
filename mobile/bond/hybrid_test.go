package bond

import (
	"math/rand"
	"slices"
	"testing"
	"time"
)

// startClient is a client with n lanes on ports nobody listens on: only its
// choices are looked at.
func startClient(n int) *Client {
	c := NewClient(0, "", "", "", "127.0.0.1", 1)
	for i := 0; i < n; i++ {
		c.AddLane(1, "", "")
	}
	return c
}

func TestAStreamStartsOnTheLaneWithTheMostRoomToSpare(t *testing.T) {
	c := startClient(4)
	c.lanes[1].stats.store(2400<<10, 40*time.Millisecond) // MTS Link
	c.lanes[2].stats.store(600<<10, 60*time.Millisecond)  // Jitsi
	c.lanes[3].stats.store(4<<20, 30*time.Millisecond)    // fast, but suspended
	c.lanes[3].stats.suspend(time.Now())
	order, total := c.startOrder()
	if total != 4 || order[0] != 1 {
		t.Fatalf("start order %v: want the fastest healthy lane (1) first", order)
	}
	if order[len(order)-1] != 3 {
		t.Fatalf("start order %v: a suspended lane goes last", order)
	}
	// The fast lane busy with 3 MB in flight: the next stream starts elsewhere.
	c.lanes[1].stats.inflight.Store(3 << 20)
	if order, _ := c.startOrder(); order[0] == 1 {
		t.Fatalf("start order %v: a lane with no room to spare still goes first", order)
	}
	c.lanes[1].stats.inflight.Store(0)

	// Lanes nothing is known of yet take turns, so short connections spread.
	fresh := startClient(3)
	var firsts []int
	for i := 0; i < 3; i++ {
		order, _ := fresh.startOrder()
		firsts = append(firsts, order[0])
	}
	slices.Sort(firsts)
	if !slices.Equal(firsts, []int{0, 1, 2}) {
		t.Fatalf("three streams over three unknown lanes started on %v", firsts)
	}
}

func TestTheBackupLaneIsFromAnotherFailureGroup(t *testing.T) {
	c := startClient(3)
	c.SetLaneGroup(0, "jitsi.example")
	c.SetLaneGroup(1, "jitsi.example")
	c.lanes[0].stats.store(700<<10, 40*time.Millisecond)
	c.lanes[1].stats.store(650<<10, 40*time.Millisecond)
	c.lanes[2].stats.store(300<<10, 40*time.Millisecond)
	order, _ := c.startOrder()
	if order[0] != 0 || order[1] != 2 {
		t.Fatalf("start order %v: after a Jitsi lane, the next try goes to the lane on another host", order)
	}
	if g0, g1, g2 := c.lanes[0].stats.failGroup(0), c.lanes[1].stats.failGroup(1), c.lanes[2].stats.failGroup(2); g0 != g1 || g0 == g2 {
		t.Fatalf("groups %d %d %d", g0, g1, g2)
	}
	// A troubled lane makes its group-mate a worse start too.
	c.lanes[0].stats.suspend(time.Now())
	if order, _ := c.startOrder(); order[0] != 2 {
		t.Fatalf("start order %v: with one Jitsi lane suspended the other host's lane goes first", order)
	}
}

func TestTheClientAsksTheServerForItsBudget(t *testing.T) {
	c := startClient(2)
	if c.budget.limit.Load() != defaultBudget/2 || c.id[7] != budgetCode(defaultBudget/2) {
		t.Fatalf("default: %d for its own sending, %d asked of the server", c.budget.limit.Load(), int(c.id[7])*budgetUnits)
	}
	c.SetMemoryBudget(6 << 20)
	if c.budget.limit.Load() != 3<<20 || c.id[7] != budgetCode(3<<20) {
		t.Fatalf("6 MiB: %d for its own sending, %d asked of the server", c.budget.limit.Load(), int(c.id[7])*budgetUnits)
	}
}

// A short request and its answer go over one lane; a download takes them all.
func TestShortConnectionsUseOneLaneAndDownloadsAll(t *testing.T) {
	lanes := []*testLane{
		newTestLane(t, 2<<20, 20*time.Millisecond),
		newTestLane(t, 2<<20, 20*time.Millisecond),
		newTestLane(t, 2<<20, 20*time.Millisecond),
	}
	r := newRig(t, testKey, "", "", lanes...)
	connects := func() (n int64) {
		for _, l := range lanes {
			n += l.connects.Load()
		}
		return n
	}
	target := echo(t)
	for i := 0; i < 6; i++ {
		c, rep := r.dial(t, target, "", "")
		if rep != repSuccess {
			t.Fatalf("reply %d", rep)
		}
		if _, err := echoRound(c, []byte("GET / HTTP/1.1"), 5*time.Second); err != nil {
			t.Fatal(err)
		}
		_ = c.Close()
	}
	time.Sleep(300 * time.Millisecond)
	if n := connects(); n != 6 {
		t.Fatalf("six short connections opened %d sub-connections, want one each", n)
	}
	before := connects()
	const n = 4 << 20
	c, rep := r.dial(t, source(t, n, 21), "", "")
	if rep != repSuccess {
		t.Fatalf("reply %d", rep)
	}
	if got, total := readAll(t, c, nil); total != n || got != digest(n, 21) {
		t.Fatalf("download: %d bytes", total)
	}
	if d := connects() - before; d != 3 {
		t.Fatalf("a 4 MiB download opened %d sub-connections, want every lane (3)", d)
	}
}

// A first lane that does not answer (its room is being joined again) costs
// a connection about a second, not its whole wait.
func TestASlowFirstLaneIsBackedUpSoon(t *testing.T) {
	lanes := []*testLane{newTestLane(t, 0, 10*time.Millisecond), newTestLane(t, 0, 10*time.Millisecond)}
	r := newRig(t, testKey, "", "", lanes...)
	for _, l := range lanes {
		l.hold.Store(int64(8 * time.Second))
	}
	order, _ := r.client.startOrder() // the next stream starts on order[1]
	lanes[order[0]].hold.Store(0)
	start := time.Now()
	c, rep := r.dial(t, echo(t), "", "")
	if rep != repSuccess {
		t.Fatalf("reply %d", rep)
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("the connection waited %v for its first lane", took.Round(time.Millisecond))
	}
	p := make([]byte, 1000)
	rand.New(rand.NewSource(5)).Read(p)
	if _, err := echoRound(c, p, 5*time.Second); err != nil {
		t.Fatal(err)
	}
}
