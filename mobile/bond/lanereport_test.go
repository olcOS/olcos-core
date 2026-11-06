package bond

import (
	"log"
	"strings"
	"testing"
	"time"
)

// A lane's periodic line is what an app's or an operator's log shows of one
// room: what it carried, what was sent again for it, how it stalled, and how
// fast it moves. It says nothing else: no address, no room, no key.
func TestALaneSaysWhatItCarriedEveryPeriod(t *testing.T) {
	st := newLaneStats("lane 2")
	now := time.Now()

	if line := st.report(now); line != "" {
		t.Fatalf("a lane that carried nothing is reported: %q", line)
	}
	st.noteRx(2<<10, now)
	st.tx.Add(1 << 10)
	line := st.report(now)
	for _, want := range []string{"bond: lane 2 up:", "tx 1KB", "rx 2KB", "frames 0", "resent 0", "in flight 0B"} {
		if !strings.Contains(line, want) {
			t.Fatalf("line %q lacks %q", line, want)
		}
	}
	if again := st.report(now); again != "" {
		t.Fatalf("a lane that carried nothing since its line is reported again: %q", again)
	}

	st.suspend(now)
	st.noteRx(1<<10, now)
	if line := st.report(now.Add(500 * time.Millisecond)); !strings.Contains(line, "suspended") {
		t.Fatalf("a suspended lane is not reported as one: %q", line)
	}
}

// A minute of a lane going in and out of trouble is a few lines, not a flood.
func TestALanesStateLinesStayUnderTheMinuteCap(t *testing.T) {
	st := newLaneStats("lane 1")
	now := time.Now()
	lines := 0
	for i := 0; i < 3*stateLines; i++ {
		if st.stateLine("carries again", now.Add(time.Duration(i)*time.Millisecond)) != "" {
			lines++
		}
	}
	if lines != stateLines {
		t.Fatalf("%d state lines in a minute of %d changes (limit %d)", lines, 3*stateLines, stateLines)
	}
	if line := st.stateLine("carries again", now.Add(2*time.Minute)); line == "" {
		t.Fatalf("the next minute's first state line is held back")
	}
}

// The client writes its lanes' lines itself, every reportEvery, until Stop.
func TestTheClientReportsItsLanesUntilItStops(t *testing.T) {
	out := &logLines{}
	old := log.Writer()
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(old) })
	defer func(d time.Duration) { reportEvery = d }(reportEvery)
	reportEvery = 20 * time.Millisecond

	c := NewClient(0, "", "", "", "127.0.0.1", 1)
	c.AddLane(1, "", "")
	c.AddLane(2, "", "")
	c.lanes[0].stats.noteRx(3<<10, time.Now())
	go c.reportLanes()

	waitForLine(t, out, "bond: lane 1 up:")
	if lines := out.String(); strings.Contains(lines, "lane 2 up") {
		t.Fatalf("a lane that carried nothing is reported:\n%s", lines)
	}

	c.Stop()
	c.lanes[0].stats.noteRx(1<<10, time.Now())
	time.Sleep(5 * reportEvery)
	if n := strings.Count(out.String(), "bond: lane 1 up:"); n != 1 {
		t.Fatalf("%d lines for lane 1 after Stop: the report runs on", n)
	}
}

// And the server writes its lanes' lines, per client and lane, until it stops.
func TestTheServerReportsItsLanesUntilItStops(t *testing.T) {
	out := &logLines{}
	old := log.Writer()
	log.SetOutput(out)
	t.Cleanup(func() { log.SetOutput(old) })
	defer func(d time.Duration) { reportEvery = d }(reportEvery)
	reportEvery = 20 * time.Millisecond

	s := newServer(func() ([]byte, error) { return make([]byte, 32), nil }, nil)
	st := newLaneStats("client beef lane 1")
	st.tx.Add(4 << 20)
	s.stats[statsKey{}] = st
	stop := make(chan struct{})
	go s.reportLanes(stop)

	waitForLine(t, out, "bond: client beef lane 1 up:")
	if !strings.Contains(out.String(), "tx 4.0MB") {
		t.Fatalf("the server's lane line lacks what the lane carried:\n%s", out.String())
	}

	close(stop)
	st.tx.Add(1 << 10)
	time.Sleep(5 * reportEvery)
	if n := strings.Count(out.String(), "bond: client beef lane 1 up:"); n != 1 {
		t.Fatalf("%d lines for the lane after the server stopped: the report runs on", n)
	}
}

// waitForLine waits a moment for want to reach the log, failing with what was
// written instead.
func waitForLine(t *testing.T, out *logLines, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(out.String(), want) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no %q in the log:\n%s", want, out.String())
}
