package bond

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Deterministic tests of the scheduler: a stripe with no timer and a clock
// the test moves, lanes that are subs with no connection under them, and
// the peer's acks fed by hand. Nothing here waits on real time.

type rigClock struct{ now time.Time }

func (c *rigClock) at(d time.Duration) time.Time { return c.now.Add(d) }

// fakeStripe is a stripe without timer or goroutines, on the test's clock.
func fakeStripe(clk *rigClock) *stripe {
	s := &stripe{frames: make(map[uint32]*outFrame), pending: make(map[uint32][]byte), finSeq: -1,
		done: make(chan struct{}), clock: func() time.Time { return clk.now }}
	s.outCond = sync.NewCond(&s.mu)
	s.inCond = sync.NewCond(&s.mu)
	s.readCond = sync.NewCond(&s.mu)
	return s
}

// fakeLane puts a proven lane of rate bytes a second and round trip rtt on
// s, sharing stats with every stripe given the same stats.
func fakeLane(s *stripe, lane int, rate float64, rtt time.Duration, stats *laneStats) *sub {
	sb := &sub{lane: lane, group: stats.failGroup(lane), stats: stats, rate: rate, minRTT: rtt, baseRTT: rtt,
		proven: rate > 0, startCap: capProbe}
	s.subs = append(s.subs, sb)
	return sb
}

// cutN cuts n frames of size bytes.
func cutN(s *stripe, n, size int) {
	for i := 0; i < n; i++ {
		s.cut(make([]byte, size))
		s.freshBytes += size
		s.charge(int64(size))
	}
}

// send has sb take and book one frame now; false when it takes none.
func send(s *stripe, sb *sub, now time.Time) (uint32, bool) {
	seq, f, ok := s.take(sb, now)
	if ok {
		s.sending(sb, seq, f, now)
	}
	return seq, ok
}

// ackAll has the peer confirm everything sb carried, delivered too.
func ackAll(s *stripe, sb *sub) {
	s.onAck(sb, s.peerNext, sb.sent)
}

func TestASilentLaneIsSuspendedForEveryStreamWithinHalfASecond(t *testing.T) {
	clk := &rigClock{now: time.Unix(1_000_000, 0)}
	quiet, other := newLaneStats("lane 1"), newLaneStats("lane 2")
	s := fakeStripe(clk)
	a := fakeLane(s, 0, 1<<20, 40*time.Millisecond, quiet)
	b := fakeLane(s, 1, 1<<20, 40*time.Millisecond, other)
	cutN(s, 4, 1000)
	s.mu.Lock()
	seq, ok := send(s, a, clk.now)
	if !ok {
		t.Fatal("lane 1 took nothing")
	}
	s.mu.Unlock()
	if want := 500 * time.Millisecond; a.softAfter() != want {
		t.Fatalf("a 40 ms lane is taken for stalled after %v, want %v", a.softAfter(), want)
	}
	s.checkAt(clk.at(499 * time.Millisecond))
	if a.stalled {
		t.Fatal("stalled before half a second")
	}
	clk.now = clk.at(500 * time.Millisecond)
	s.checkAt(clk.now)
	if !a.stalled || len(s.resend) != 1 || s.resend[0] != seq {
		t.Fatalf("after half a second of silence: stalled %v, to send again %v", a.stalled, s.resend)
	}
	// The other lane carries the frame again at once.
	s.mu.Lock()
	if got, ok := send(s, b, clk.now); !ok || got != seq {
		t.Fatalf("lane 2 took %d (%v), want the stalled frame %d", got, ok, seq)
	}
	s.mu.Unlock()

	// Another stream through the same lane holds off it while suspended.
	s2 := fakeStripe(clk)
	a2 := fakeLane(s2, 0, 1<<20, 40*time.Millisecond, quiet)
	b2 := fakeLane(s2, 1, 1<<20, 40*time.Millisecond, other)
	cutN(s2, 8, 1000)
	s2.mu.Lock()
	if _, ok := send(s2, a2, clk.now); ok {
		t.Fatal("another stream sent a frame on the suspended lane")
	}
	if _, ok := send(s2, b2, clk.now); !ok {
		t.Fatal("the healthy lane took nothing")
	}
	// Once the suspension is up, the lane carries a probe copy, not a frame.
	clk.now = clk.at(suspendBase)
	if _, f, ok := s2.take(a2, clk.now); !ok || f.holder != b2 || !a2.probeNext {
		t.Fatalf("after the suspension the lane took %v (probe %v), want a copy of the healthy lane's frame", ok, a2.probeNext)
	}
	s2.mu.Unlock()

	// The lane confirms what it held: it carries again, for everyone.
	s.mu.Lock()
	s.onAck(a, 0, a.sent)
	s.mu.Unlock()
	if until, probe := quiet.health(clk.now); !until.IsZero() || probe {
		t.Fatalf("after it confirmed: suspended until %v, owes a probe %v", until, probe)
	}
	if quiet.soft.Load() != 1 {
		t.Fatalf("%d soft stalls counted", quiet.soft.Load())
	}
}

func TestTheHardStallThresholdsStayForTeardown(t *testing.T) {
	clk := &rigClock{now: time.Unix(1_000_000, 0)}
	s := fakeStripe(clk)
	var grew atomic.Int32
	s.onGrow = func() { grew.Add(1) }
	a := fakeLane(s, 0, 1<<20, 40*time.Millisecond, newLaneStats("lane 1"))
	cutN(s, 1, 1000)
	s.mu.Lock()
	send(s, a, clk.now)
	s.mu.Unlock()
	s.checkAt(clk.at(600 * time.Millisecond))
	// Alone, the lane keeps its frame (no one else could carry it) and the
	// stream calls the other lanes.
	if !a.stalled || len(a.flights) != 1 || len(s.resend) != 0 {
		t.Fatalf("a lone lane's soft stall: stalled %v, holds %d, to send again %d", a.stalled, len(a.flights), len(s.resend))
	}
	waitFor := func(cond func() bool) bool {
		for i := 0; i < 1000 && !cond(); i++ {
			time.Sleep(time.Millisecond)
		}
		return cond()
	}
	if !waitFor(func() bool { return grew.Load() == 1 }) {
		t.Fatal("a stream whose only lane stalled did not call the others")
	}
	s.checkAt(clk.at(stallMin))
	if !a.hard || len(s.resend) != 1 || a.stats.hard.Load() != 1 {
		t.Fatalf("after %v: hard %v, to send again %d", stallMin, a.hard, len(s.resend))
	}
}

func TestBaseRoundTripFollowsTheLastTwentySeconds(t *testing.T) {
	t0 := time.Unix(1_000_000, 0)
	var w minWindow
	w.add(40*time.Millisecond, t0)
	for d := time.Second; d <= 30*time.Second; d += time.Second {
		w.add(180*time.Millisecond, t0.Add(d))
	}
	if got := w.get(t0.Add(30 * time.Second)); got != 180*time.Millisecond {
		t.Fatalf("a room moved to a media server 180 ms away still reads %v 30 s later", got)
	}
	var early minWindow
	early.add(40*time.Millisecond, t0)
	for d := time.Second; d <= 10*time.Second; d += time.Second {
		early.add(180*time.Millisecond, t0.Add(d))
	}
	if got := early.get(t0.Add(10 * time.Second)); got != 40*time.Millisecond {
		t.Fatalf("10 s on, the old reading should still stand: got %v", got)
	}
	// A lane that went quiet keeps its last reading.
	var q minWindow
	q.add(60*time.Millisecond, t0)
	if got := q.get(t0.Add(time.Hour)); got != 60*time.Millisecond {
		t.Fatalf("a quiet lane forgot its round trip: %v", got)
	}
}

func TestASlowLaneIsMeasuredWithABurstOfProbes(t *testing.T) {
	clk := &rigClock{now: time.Unix(1_000_000, 0)}
	s := fakeStripe(clk)
	fast := fakeLane(s, 0, 4<<20, 30*time.Millisecond, newLaneStats("lane 1"))
	slow := fakeLane(s, 1, 10<<10, 30*time.Millisecond, newLaneStats("lane 2"))
	cutN(s, 40, maxPayload)
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := 0; i < 16; i++ {
		if _, ok := send(s, fast, clk.now); !ok {
			t.Fatalf("the fast lane took only %d frames", i)
		}
	}
	slow.probedAt = clk.now.Add(-probeEvery)
	copies, bytes := 0, 0
	for {
		seq, f, ok := s.take(slow, clk.now)
		if !ok {
			break
		}
		if !slow.probeNext || f.holder != fast {
			t.Fatalf("the slow lane took frame %d for itself", seq)
		}
		s.sending(slow, seq, f, clk.now)
		copies++
		bytes += len(f.payload)
	}
	if copies < 4 || copies > probeBurstFrames || bytes < probeBurstBytes {
		t.Fatalf("a burst of %d copies, %d bytes (want 4 to %d, %d bytes at least)", copies, bytes, probeBurstFrames, probeBurstBytes)
	}
	// The lane has sped up: the burst's 64 KiB arrive in 100 ms plus a round trip.
	clk.now = clk.at(130 * time.Millisecond)
	s.onAck(slow, s.peerNext, slow.sent)
	if slow.rate < 400<<10 {
		t.Fatalf("after the burst the lane reads %.0f B/s, want about 640 KiB/s", slow.rate)
	}
}

func TestTheWindowIsAboutASecondOfTheLanesAndWithinTheBudget(t *testing.T) {
	clk := &rigClock{now: time.Unix(1_000_000, 0)}
	s := fakeStripe(clk)
	s.peerAcksEarly = true
	a := fakeLane(s, 0, 512<<10, time.Millisecond, nil)
	a.baseRTT, a.rate = time.Millisecond, 512<<10
	fakeLane(s, 1, 256<<10, time.Millisecond, nil)
	if w := s.sendWindow(); w != 768<<10 {
		t.Fatalf("lanes of 512 and 256 KiB/s: a window of %d, want 768 KiB", w)
	}
	s.subs[0].rate, s.subs[1].rate = 50<<20, 50<<20
	if w := s.sendWindow(); w != windowCeil {
		t.Fatalf("fast lanes: a window of %d, want the ceiling %d", w, windowCeil)
	}
	s.subs[0].rate, s.subs[1].rate = 1000, 1000
	if w := s.sendWindow(); w != windowFloor {
		t.Fatalf("trickling lanes: a window of %d, want the floor %d", w, windowFloor)
	}

	// Two streams share a budget of 512 KiB: what one holds, the other
	// cannot, beyond budgetFloor.
	b := newBudget(512 << 10)
	one, two := fakeStripe(clk), fakeStripe(clk)
	for _, st := range []*stripe{one, two} {
		st.budget, st.peerAcksEarly = b, true
		fakeLane(st, 0, 100<<20, 10*time.Millisecond, nil)
	}
	sendAll := func(s *stripe) int {
		s.mu.Lock()
		defer s.mu.Unlock()
		n := 0
		for {
			if _, ok := send(s, s.subs[0], clk.now); !ok {
				return n
			}
			n++
		}
	}
	cutN(one, 16, maxPayload) // a read-ahead's worth
	if n := sendAll(one); n != 16 {
		t.Fatalf("the first stream sent %d of 16 frames within the budget", n)
	}
	cutN(two, 16, maxPayload)
	n := sendAll(two)
	if got := two.winBytes; got > budgetFloor || n == 0 {
		t.Fatalf("with the budget spent, the second stream sent %d frames, %d bytes (want at least one, %d at most)", n, got, budgetFloor)
	}
	// The peer delivers what the first sent: its share is free again.
	one.mu.Lock()
	one.onAck(one.subs[0], one.nextSeq, one.subs[0].sent)
	one.mu.Unlock()
	if one.winBytes != 0 || b.used.Load() != two.held {
		t.Fatalf("after delivery the first stream holds %d, the budget %d (the second's %d)", one.winBytes, b.used.Load(), two.held)
	}
	if n := sendAll(two); n == 0 {
		t.Fatal("the second stream did not take up the freed budget")
	}
}

func TestTowardAnOlderPeerTheWindowNeverStopsShortOfItsAcks(t *testing.T) {
	clk := &rigClock{now: time.Unix(1_000_000, 0)}
	s := fakeStripe(clk)
	s.budget = newBudget(0) // spent before it began
	fakeLane(s, 0, 100<<20, 10*time.Millisecond, nil)
	cutN(s, 300, maxPayload)
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for {
		if _, ok := send(s, s.subs[0], clk.now); !ok {
			break
		}
		n++
	}
	// A receiver from before acks its delivery point every 32 frames: a
	// window of fewer would wait for an ack that never comes.
	if n < legacyAckFrames || n > windowFrames {
		t.Fatalf("%d frames out toward an older peer, want %d to %d", n, legacyAckFrames, windowFrames)
	}
}

func TestAStalledLanesFramesGoToAnotherFailureGroupFirst(t *testing.T) {
	clk := &rigClock{now: time.Unix(1_000_000, 0)}
	s := fakeStripe(clk)
	g := func(group int) *laneStats { st := newLaneStats(""); st.setGroup(group); return st }
	jitsi1 := fakeLane(s, 0, 1<<20, 40*time.Millisecond, g(0))
	jitsi2 := fakeLane(s, 1, 1<<20, 40*time.Millisecond, g(0))
	salute := fakeLane(s, 2, 1<<20, 40*time.Millisecond, g(2))
	cutN(s, 1, 1000)
	s.mu.Lock()
	seq, _ := send(s, jitsi1, clk.now)
	s.mu.Unlock()
	clk.now = clk.at(time.Second)
	s.checkAt(clk.now)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.resend) != 1 {
		t.Fatalf("to send again: %v", s.resend)
	}
	if got, ok := send(s, jitsi2, clk.now); ok && got == seq {
		t.Fatal("the stalled lane's frame went to a lane on the same host first")
	}
	if got, ok := send(s, salute, clk.now); !ok || got != seq {
		t.Fatalf("the other host's lane took %d (%v), want %d", got, ok, seq)
	}
	// With the other group's lane full, the same-host lane takes it after
	// groupGrace rather than let it wait.
	s.resend = append(s.resend, seq)
	s.frames[seq].holder, s.frames[seq].requeued = jitsi1, clk.now
	salute.sent = salute.peerGot + salute.capacity()
	if got, ok := send(s, jitsi2, clk.now); !ok || got != seq {
		t.Fatalf("with the other group full, the same-host lane took %d (%v)", got, ok)
	}
}

func TestAStreamCallsItsOtherLanesOnlyWhenItEarnsThem(t *testing.T) {
	clk := &rigClock{now: time.Unix(1_000_000, 0)}
	grown := func(s *stripe) bool {
		s.mu.Lock()
		defer s.mu.Unlock()
		return s.grown
	}
	start := func() *stripe {
		s := fakeStripe(clk)
		s.onGrow = func() {}
		fakeLane(s, 0, 2<<20, 40*time.Millisecond, newLaneStats(""))
		return s
	}

	// A short request and its answer: one lane is enough.
	s := start()
	cutN(s, 1, 500)
	s.mu.Lock()
	send(s, s.subs[0], clk.now)
	ackAll(s, s.subs[0])
	s.subs[0].got += 3000
	s.active(clk.at(80*time.Millisecond), 3000)
	s.askedAt = time.Time{}
	s.mu.Unlock()
	s.checkAt(clk.at(5 * time.Second))
	if grown(s) {
		t.Fatal("a short request and answer called the other lanes")
	}

	// A download that has moved joinAfter.
	s = start()
	s.mu.Lock()
	s.active(clk.now, joinAfter)
	s.mu.Unlock()
	if !grown(s) {
		t.Fatalf("a stream that moved %d did not call the other lanes", joinAfter)
	}

	// A stream busy for growBusy, slowly.
	s = start()
	s.mu.Lock()
	for d := time.Duration(0); d <= growBusy; d += 100 * time.Millisecond {
		s.active(clk.at(d), 2000)
	}
	s.mu.Unlock()
	if !grown(s) {
		t.Fatal("a stream busy for a second did not call the other lanes")
	}

	// A request whose answer does not come.
	s = start()
	cutN(s, 1, 500)
	s.mu.Lock()
	send(s, s.subs[0], clk.now)
	ackAll(s, s.subs[0])
	s.mu.Unlock()
	s.checkAt(clk.at(waitAnswer - time.Millisecond))
	if grown(s) {
		t.Fatal("called the other lanes before waitAnswer")
	}
	s.checkAt(clk.at(waitAnswer))
	if !grown(s) {
		t.Fatal("a request unanswered for a second did not call the other lanes")
	}

	// An upload its lane holds back for longer than a round trip.
	s = start()
	s.subs[0].rate = 200 << 10 // a share of 64 KiB, well below joinAfter
	cutN(s, 20, maxPayload)
	s.mu.Lock()
	for {
		if _, ok := send(s, s.subs[0], clk.now); !ok {
			break
		}
	}
	send(s, s.subs[0], clk.at(10*time.Millisecond))
	limitedEarly := s.grown
	send(s, s.subs[0], clk.at(60*time.Millisecond))
	s.mu.Unlock()
	if limitedEarly || !grown(s) {
		t.Fatalf("held back by its lane: called the others early %v, after a round trip %v", limitedEarly, grown(s))
	}
}
