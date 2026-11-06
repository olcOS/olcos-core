package bond

import (
	"fmt"
	"math"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// statsFor is how long a lane's measurement stays good without a new one.
	statsFor = 5 * time.Minute
	// rttWindowFor: a lane's base round trip is the least of this long. A room
	// moved to a farther media server reads as farther within it, instead of
	// looking late for every frame until statsFor is up.
	rttWindowFor = 20 * time.Second

	// A lane whose sub-connection confirms nothing for a while (softAfter) is
	// suspended for every stream on it: no new frames for suspendBase, twice
	// that each time it stalls again without carrying in between, up to
	// suspendMax. After that it carries one probe burst before frames again.
	suspendBase = time.Second
	suspendMax  = 8 * time.Second

	// stateLines bounds a lane's state-change lines a minute; the periodic
	// line counts everything regardless.
	stateLines = 6
)

// laneStats is what the streams on one lane learned about it and share: a
// new stream starts from its speed instead of probing, every stream keeps
// off it while it is suspended, and the counters feed the lane's log line.
// rx and tx count the bytes the lane carried for every stream, toward the
// app and from it. Its mutex is the last one taken (under a stripe's mu) and
// takes no other.
type laneStats struct {
	mu     sync.Mutex
	rate   float64
	minRTT minWindow
	srtt   time.Duration
	at     time.Time

	suspendUntil time.Time
	suspendFor   time.Duration
	needsProbe   bool      // carry a probe burst before frames again
	probeAt      time.Time // when a stream last took the lane's probe
	// trouble is closed (and replaced) when the lane is suspended: a stream
	// that runs on this lane alone calls the others at once.
	trouble chan struct{}

	label   string
	lineMin time.Time // the minute stateN counts lines in
	stateN  int
	shown   [2]int64 // rx, tx at the last periodic line

	// group+1 of the lane's failure group; 0: its own.
	group atomic.Int32

	rx, tx atomic.Int64
	// What streams sent on the lane: frames, those sent again for another
	// lane (stalled or late), probe copies; soft and hard stalls, benches.
	frames, resent, probes atomic.Int64
	soft, hard, benches    atomic.Int64
	// inflight is what this side has sent on the lane and the peer has not
	// confirmed yet, every stream together.
	inflight atomic.Int64
	// rxPeak is the most the lane carried toward this side in a second
	// lately (rxMeter): a floor of its speed that way, which this side's own
	// readings (of what it sends) cannot show.
	rxMeter meter
}

func newLaneStats(label string) *laneStats {
	return &laneStats{label: label, trouble: make(chan struct{})}
}

func (l *laneStats) load() (float64, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Since(l.at) > statsFor {
		return 0, 0
	}
	return l.rate, l.minRTT.get(time.Now())
}

func (l *laneStats) store(rate float64, minRTT time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.at) > statsFor {
		l.minRTT = minWindow{}
	}
	l.rate = rate
	l.minRTT.add(minRTT, now)
	l.at = now
}

// noteRTT folds one round trip into the lane's smoothed one (the log's).
func (l *laneStats) noteRTT(rtt time.Duration) {
	l.mu.Lock()
	if l.srtt == 0 {
		l.srtt = rtt
	} else {
		l.srtt = (7*l.srtt + rtt) / 8
	}
	l.mu.Unlock()
}

func (l *laneStats) noteRx(n int64, now time.Time) {
	l.rx.Add(n)
	l.mu.Lock()
	l.rxMeter.add(n, now)
	l.mu.Unlock()
}

// rxRates: what the lane carried toward this side in the last second, and
// at most in a second lately.
func (l *laneStats) rxRates(now time.Time) (recent, peak float64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rxMeter.recent(now), l.rxMeter.peakAt(now)
}

// failGroup is the lane's failure group: lanes in one (rooms on the same
// conference host) tend to fail together.
func (l *laneStats) failGroup(lane int) int {
	if l != nil {
		if g := l.group.Load(); g > 0 {
			return int(g - 1)
		}
	}
	return lane
}

func (l *laneStats) setGroup(g int) { l.group.Store(int32(g + 1)) }

// health: until when the lane is suspended (zero when it is not) and whether
// it owes a probe burst before it carries frames.
func (l *laneStats) health(now time.Time) (until time.Time, probe bool) {
	if l == nil {
		return time.Time{}, false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Before(l.suspendUntil) {
		return l.suspendUntil, true
	}
	return time.Time{}, l.needsProbe
}

// troubled: a channel closed the next time the lane is suspended.
func (l *laneStats) troubled() <-chan struct{} {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.trouble
}

// suspend takes the lane off new frames for every stream; the state line to
// log, if any. A lane already suspended stays as it is.
func (l *laneStats) suspend(now time.Time) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.soft.Add(1)
	if now.Before(l.suspendUntil) {
		return ""
	}
	switch {
	case l.suspendFor == 0:
		l.suspendFor = suspendBase
	case l.needsProbe:
		// Stalled again without carrying in between.
		l.suspendFor = min(2*l.suspendFor, suspendMax)
	}
	l.suspendUntil = now.Add(l.suspendFor)
	l.needsProbe = true
	l.probeAt = time.Time{}
	close(l.trouble)
	l.trouble = make(chan struct{})
	return l.stateLine("suspended for "+l.suspendFor.String(), now)
}

// recheck: the lane is back after trouble (a stream lost it, or the client
// benched it): it carries a probe burst before frames.
func (l *laneStats) recheck() {
	l.mu.Lock()
	l.needsProbe = true
	l.probeAt = time.Time{}
	l.mu.Unlock()
}

// progress: the lane confirmed something for some stream, so it carries;
// the state line to log when that ends a suspension.
func (l *laneStats) progress(now time.Time) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.suspendUntil.IsZero() && !l.needsProbe {
		return ""
	}
	was := !l.suspendUntil.IsZero()
	l.suspendUntil, l.suspendFor, l.needsProbe, l.probeAt = time.Time{}, 0, false, time.Time{}
	if !was {
		return ""
	}
	return l.stateLine("carries again", now)
}

// claimProbe: whether a stream may send the lane's probe burst now; one
// stream at a time, again after probeEvery if nothing came of it.
func (l *laneStats) claimProbe(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.probeAt.IsZero() && now.Sub(l.probeAt) < probeEvery {
		return false
	}
	l.probeAt = now
	return true
}

// hardStall counts a sub-connection that confirmed nothing for stallAfter.
func (l *laneStats) hardStall(now time.Time) string {
	l.hard.Add(1)
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.stateLine("stalled", now)
}

// benched counts the client setting the lane aside after failed calls.
func (l *laneStats) benched(now time.Time, d time.Duration) string {
	l.benches.Add(1)
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.stateLine("sits out "+d.String(), now)
}

// stateLine is the lane's line for a change of state, at most stateLines a
// minute. Holds mu.
func (l *laneStats) stateLine(state string, now time.Time) string {
	if now.Sub(l.lineMin) >= time.Minute {
		l.lineMin, l.stateN = now, 0
	}
	if l.stateN >= stateLines {
		return ""
	}
	l.stateN++
	return l.lineLocked(state, now)
}

// report is the lane's periodic line; empty when it carried nothing since
// the last one.
func (l *laneStats) report(now time.Time) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	rx, tx := l.rx.Load(), l.tx.Load()
	if rx == l.shown[0] && tx == l.shown[1] {
		return ""
	}
	l.shown = [2]int64{rx, tx}
	state := "up"
	switch {
	case now.Before(l.suspendUntil):
		state = "suspended"
	case l.needsProbe:
		state = "to probe"
	}
	return l.lineLocked(state, now)
}

// lineLocked: one compact line of the lane's numbers. Only the lane's label
// (its number, as the app counts its rooms) names it: never an address, a
// room or a key. Holds mu.
func (l *laneStats) lineLocked(state string, now time.Time) string {
	frames, resent := l.frames.Load(), l.resent.Load()
	share := 0.0
	if frames > 0 {
		share = 100 * float64(resent) / float64(frames)
	}
	rate := l.rate
	if now.Sub(l.at) > statsFor {
		rate = 0
	}
	return fmt.Sprintf("bond: %s %s: tx %s rx %s, frames %d, resent %d (%.1f%%), probes %d, stalls %d soft %d hard, benched %d, rtt %s min %s, rate %s/s, in %s/s, in flight %s",
		l.label, state, size(l.tx.Load()), size(l.rx.Load()), frames, resent, share, l.probes.Load(),
		l.soft.Load(), l.hard.Load(), l.benches.Load(), l.srtt.Round(time.Millisecond),
		l.minRTT.get(now).Round(time.Millisecond), size(int64(rate)), size(int64(l.rxMeter.peakAt(now))),
		size(l.inflight.Load()))
}

func size(n int64) string {
	switch {
	case n >= 10<<20:
		return fmt.Sprintf("%dMB", n>>20)
	case n >= 1<<20:
		return fmt.Sprintf("%.1fMB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%dKB", n>>10)
	default:
		return fmt.Sprintf("%dB", n)
	}
}

// minWindow is the least sample of about the last rttWindowFor, kept in a
// few buckets: an old low sample is forgotten once newer ones exist, and
// with none newer the last ones stand (a lane that went quiet is not
// forgotten for being quiet).
type minWindow struct {
	b [4]struct {
		v  time.Duration
		at time.Time // when the bucket began
	}
}

func (w *minWindow) add(v time.Duration, now time.Time) {
	if v <= 0 {
		return
	}
	if b := &w.b[0]; b.v > 0 && now.Sub(b.at) < rttWindowFor/4 {
		b.v = min(b.v, v)
		return
	}
	copy(w.b[1:], w.b[:3])
	w.b[0].v, w.b[0].at = v, now
}

func (w *minWindow) get(now time.Time) time.Duration {
	var m time.Duration
	for _, b := range w.b {
		if b.v > 0 && now.Sub(b.at) < rttWindowFor && (m == 0 || b.v < m) {
			m = b.v
		}
	}
	if m == 0 {
		m = w.b[0].v
	}
	return m
}

// meter reads a byte count's rate over spans of meterSpan, and the highest
// of the last statsFor.
type meter struct {
	at   time.Time
	n    int64
	last float64 // the last span's rate
	peak float64
	pAt  time.Time
}

const meterSpan = time.Second

func (m *meter) add(n int64, now time.Time) {
	if m.at.IsZero() {
		m.at = now
	}
	m.n += n
	if el := now.Sub(m.at); el >= meterSpan {
		r := float64(m.n) / el.Seconds()
		m.last = r
		if r >= m.peak || now.Sub(m.pAt) > statsFor {
			m.peak, m.pAt = r, now
		}
		m.at, m.n = now, 0
	}
}

// recent is the rate of the last second or so; 0 once the count stood still.
func (m *meter) recent(now time.Time) float64 {
	if now.Sub(m.at) > 2*meterSpan {
		return 0
	}
	return m.last
}

func (m *meter) peakAt(now time.Time) float64 {
	if now.Sub(m.pAt) > statsFor {
		return 0
	}
	return m.peak
}

// memBudget bounds what one side's streams hold past their peer's delivery
// point, and have read ahead, together (stripe.held): the streams share it,
// each always keeping budgetFloor. nil: no bound.
type memBudget struct {
	limit atomic.Int64
	used  atomic.Int64
}

func newBudget(limit int64) *memBudget {
	b := &memBudget{}
	b.limit.Store(limit)
	return b
}

func (b *memBudget) free() int64 {
	if b == nil {
		return math.MaxInt64 / 2
	}
	return b.limit.Load() - b.used.Load()
}

func (b *memBudget) add(n int64) {
	if b != nil {
		b.used.Add(n)
	}
}
