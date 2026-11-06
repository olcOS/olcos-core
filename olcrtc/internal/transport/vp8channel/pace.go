// Changed by olcOS (https://github.com/olcOS/olcos-core): see docs/olcrtc.md there.

package vp8channel

// ai-generated: the whole file (issue #12: the cap a data lane keeps after it
// has been dark).

import "time"

const (
	// defaultGrowEvery is how often a capped lane whose cap holds data back
	// raises the cap by a quarter, while the peer answers: it doubles in
	// about six seconds. An SFU that stopped forwarding a stream over its
	// budget does it again as soon as the stream is back over it, and each
	// time costs the tunnel seconds of nothing, control included. Recovery
	// has to outrun those spells: a relay that suspends a stream every ten
	// seconds for reasons of its own ratcheted a lane from 1801 to 434
	// KiB/s over 80 s when the cap grew by an eighth and every spell halved
	// it.
	defaultGrowEvery = 2 * time.Second
	// capObeyed is how far over its cap a lane's busiest second may go and
	// still count as having kept to it: the token bucket lets a burst of
	// paceBurst through, so a saturated lane measures a little over. A lane
	// that kept to its cap and went dark anyway did not go dark for the
	// rate it was writing, and halving it again would only ratchet it down.
	capObeyed = 1.25
	// minPaceRate is the lowest cap, in bytes per second: a probe's worth a
	// few times a second.
	minPaceRate = 16 << 10
	// quietRate is what a lane writes per second at most for its going dark
	// not to be its own doing: a lane that mostly acknowledges the peer's
	// transfer is dark because that transfer is loud, and capping it would
	// only slow the acknowledgements. Nor is a lane writing less than an
	// eighth of its full rate the one that took the stream over an SFU's
	// budget: on a lossy path it goes dark for a burst of loss, and a cap
	// would only make it slower.
	quietRate = 4 * minPaceRate
	// paceBurst is how much credit a capped lane may bank, in time at its
	// rate, so a lull does not turn into a burst over the budget.
	paceBurst = 50 * time.Millisecond
	// paceQuarter is one bucket of the sent history: sentRate is the
	// busiest four of them in a row, a second, over the last sixteen. A
	// lane counts its path dark two seconds after the last answer, so the
	// second that went over the budget lies further back than that.
	paceQuarter = 250 * time.Millisecond
)

// pace caps what a data lane writes once the lane has been dark: half of
// what it was writing, raised by an eighth every grow interval in which the
// cap held data back, and lifted once it passes what the lane can write
// anyway. Times are monoNow values.
type pace struct {
	// rate is the cap in bytes per second, zero for none. credit is what
	// may still go now, refilled at rate since creditAt. held says the cap
	// left data queued since the cap last grew, at grownAt.
	rate     float64
	credit   float64
	creditAt int64
	held     bool
	grownAt  int64
	// sent counts the bytes written in the last sixteen quarters of a
	// second, the newest beginning at sentAt.
	sent   [16]int
	sentAt int64
}

// wrote counts n bytes written at now, and takes them off the credit.
func (s *pace) wrote(now int64, n int) {
	s.roll(now)
	s.sent[0] += n
	s.credit -= float64(n)
}

// roll moves the sent-rate window on to now.
func (s *pace) roll(now int64) {
	for now-s.sentAt >= int64(paceQuarter) {
		copy(s.sent[1:], s.sent[:len(s.sent)-1])
		s.sent[0] = 0
		s.sentAt += int64(paceQuarter)
		if now-s.sentAt >= int64(len(s.sent))*int64(paceQuarter) {
			s.sent, s.sentAt = [len(s.sent)]int{}, now
		}
	}
}

// sentRate is the bytes per second written over the busiest second of the
// last four.
func (s *pace) sentRate(now int64) float64 {
	s.roll(now)
	window, busiest := 0, 0
	for i, n := range s.sent {
		window += n
		if i >= 4 {
			window -= s.sent[i-4]
		}
		busiest = max(busiest, window)
	}
	return float64(busiest)
}

// slow caps the lane at half of sent, the busiest second it wrote before it
// went dark, or of its cap if that was lower. A lane that was quiet, wrote
// less than an eighth of full, its uncapped rate, or kept within a cap it
// already had did not take the path over any budget and stays as it was. It
// reports whether the cap changed.
func (s *pace) slow(now int64, sent, full float64) bool {
	if sent < max(quietRate, full/8) || (s.rate > 0 && sent <= s.rate*capObeyed) {
		return false
	}
	if s.rate > 0 {
		sent = min(sent, s.rate)
	}
	s.rate = max(sent/2, minPaceRate)
	s.credit, s.creditAt, s.held, s.grownAt = 0, now, false, now
	return true
}

// cutTo caps the lane at delivered, the rate its packets were getting
// through at: the loss was read as following the lane's rate (a policer or
// shaper that drops, an SFU budget by rate), where half of what is written
// is retransmission and only a rate at what survives carries anything. The
// guards of slow do not apply: the evidence is the path's own answer, not a
// guess at what took it over a budget. The cap grows back a quarter at a
// time as pace ever did, and the lane that overruns is cut here again.
func (s *pace) cutTo(delivered float64) {
	s.rate = max(delivered, minPaceRate)
	s.credit, s.creditAt, s.held, s.grownAt = 0, monoNow(), false, monoNow()
}

// grow raises the cap by a quarter when it held data back for a whole grow
// interval, and lifts it once it reaches full, the most the lane writes
// uncapped. It reports whether the cap changed.
func (s *pace) grow(now int64, every time.Duration, full float64) bool {
	if s.rate == 0 || !s.held || now-s.grownAt < int64(every) {
		return false
	}
	s.rate += s.rate / 4
	if s.rate >= full {
		s.rate = 0
	}
	s.held, s.grownAt = false, now
	return true
}

// allow refills the credit up to now and reports how many bytes may go, or
// -1 without a cap.
func (s *pace) allow(now int64) int {
	if s.rate == 0 {
		return -1
	}
	s.credit += s.rate * float64(now-s.creditAt) / float64(time.Second)
	s.credit = min(s.credit, max(s.rate*paceBurst.Seconds(), kcpMTU))
	s.creditAt = now
	return int(max(s.credit, 0))
}

// singleRate paces a single-packet data lane at about what the relay
// forwards. Telemost forwards each subscriber what fits its own estimate of
// the subscriber's bandwidth and drops the rest, so a lane above that
// estimate loses frames and a lane far below it wastes the path. The lane
// grows while nearly every push comes back acknowledged and the round trip
// stays near its floor, and backs off when pushes go unanswered, the round
// trip climbs over the floor, or the round trip is high outright — all of
// which mean the relay (or the path to a thin subscriber) is queueing what it
// cannot forward.
//
// The window the lane sizes is the bandwidth-delay product over the UNLOADED
// round trip (the floor), never the current one: sizing it from a round trip
// that already carries a queue would let the window grow as the queue grows,
// the bufferbloat feedback loop that collapsed a thin home-to-server path
// (round trip climbing past ten seconds) while a fat datacenter path, whose
// round trip never rose, ran at megabits.
//
// The thresholds come from the measurements in writer.go: with keyframes
// rare, the relay answered 96-100% of pushes at rates from 300 KiB/s to
// 3 MiB/s, its queue adds about half a second under load, and a path past its
// budget reads 10-60%.
type singleRate struct {
	rate     float64 // bytes a second, zero until the lane first writes
	credit   float64
	creditAt int64
	// changedAt is when the rate last changed and since the first delivery
	// bucket judged against it; pushes and acks are the evidence so far.
	changedAt int64
	since     int64
	pushes    int
	acks      int
	// minRTT is the lowest smoothed round trip seen lately, in ms: the path
	// without the relay's queue. It is taken afresh every
	// singleMinRTTWindow so a path that got slower is not judged by its
	// old floor.
	minRTT int32
	minAt  int64
	// sizedAt is when the lane last sized its KCP window.
	sizedAt int64
}

const (
	// A low start lets the floor (minRTT) be measured on a near-empty path,
	// even a thin one, before the rate grows into it.
	singleStartRate = 64 << 10
	singleMinRate   = 16 << 10
	singleMaxRate   = 8 << 20
	// singleBurst is how much credit the lane may bank, in time at its rate.
	singleBurst = 20 * time.Millisecond
	// singleJudgeEvery is the least time between two changes of the rate,
	// and singleMinJudged the fewest pushes a change rests on.
	singleJudgeEvery = time.Second
	singleMinJudged  = 24
	singleGrow       = 1.25
	singleCut        = 0.8
	// A share of pushes acknowledged at or over singleGoodShare lets the
	// rate grow, one under singleFairShare cuts it.
	singleGoodShare = 0.85
	singleFairShare = 0.70
	// The round trip over its floor that stops growth, and the one that
	// cuts the rate: the relay's queue holds about half a second under any
	// steady load, so only more than that is the lane's doing.
	singleQueueGrow = 700 * time.Millisecond
	singleQueueCut  = time.Second
	// singleAbsQueue cuts the rate whenever the round trip is this high
	// outright, however the floor reads: no healthy tunnel path sits here, so
	// it is a standing queue even when the floor was itself measured high.
	singleAbsQueue = 1500 * time.Millisecond
	// singleMinRTTWindow is how long a round-trip floor is kept before a
	// higher one may replace it, and only then if the sample is not itself
	// plainly congested (below twice the floor).
	singleMinRTTWindow = 10 * time.Second
	// singleMinWindow is the smallest KCP send window, in segments;
	// singleWindowSlack is what the window covers beyond the floor round
	// trip, and singleWindowBase the floor to assume until one is measured.
	singleMinWindow   = 8
	singleWindowSlack = 250 * time.Millisecond
	singleWindowBase  = 300 * time.Millisecond
)

// start sets the first rate and reports whether it did.
func (r *singleRate) start(now int64) bool {
	if r.rate != 0 {
		return false
	}
	r.rate, r.creditAt, r.changedAt = singleStartRate, now, now
	return true
}

// allow refills the credit up to now and returns it in bytes.
func (r *singleRate) allow(now int64) int {
	r.credit += r.rate * float64(now-r.creditAt) / float64(time.Second)
	r.credit = min(r.credit, max(r.rate*singleBurst.Seconds(), 2*singleSampleSize))
	r.creditAt = now
	return int(r.credit)
}

// wrote takes n bytes off the credit.
func (r *singleRate) wrote(n int) { r.credit -= float64(n) }

// judge weighs the pushes acknowledged since the rate last changed, with
// srtt the conn's smoothed round trip in ms, and moves the rate. newest is
// the delivery bucket of the newest push, from which a change judges anew.
// It returns the share judged and whether the rate changed.
func (r *singleRate) judge(track *deliveryTrack, now, newest int64, srtt int32) (float64, bool) {
	if r.rate == 0 {
		return 0, false
	}
	if srtt > 0 && (r.minRTT == 0 || srtt < r.minRTT ||
		(now-r.minAt > int64(singleMinRTTWindow) && srtt < 2*r.minRTT)) {
		r.minRTT, r.minAt = srtt, now
	}
	pushes, acks, _ := track.take(r.since)
	r.pushes, r.acks = r.pushes+pushes, r.acks+acks
	if r.pushes < singleMinJudged || now-r.changedAt < int64(singleJudgeEvery) {
		return 0, false
	}
	share := float64(r.acks) / float64(r.pushes)
	r.pushes, r.acks = 0, 0
	queued := time.Duration(srtt-r.minRTT) * time.Millisecond
	old := r.rate
	switch {
	case time.Duration(srtt)*time.Millisecond > singleAbsQueue,
		r.minRTT > 0 && queued > singleQueueCut,
		share < singleFairShare:
		r.rate = max(r.rate*singleCut, singleMinRate)
	case share >= singleGoodShare && queued < singleQueueGrow:
		r.rate = min(r.rate*singleGrow, singleMaxRate)
	default:
		return share, false
	}
	r.changedAt, r.since = now, newest+1
	return share, r.rate != old
}

// halve cuts the rate as the lane goes dark.
func (r *singleRate) halve(now, newest int64) {
	if r.rate == 0 {
		r.rate = singleStartRate
	}
	r.rate = max(r.rate/2, singleMinRate)
	r.changedAt, r.since, r.pushes, r.acks = now, newest+1, 0, 0
}

// window is the KCP send window, in segments of mtu bytes: the bandwidth-
// delay product at the current rate over the UNLOADED round trip (the floor),
// at least singleMinWindow and at most ceiling. Sizing it from the floor, not
// the current round trip, is what stops the window from growing as a queue
// builds.
func (r *singleRate) window(ceiling, mtu int) int {
	base := time.Duration(r.minRTT) * time.Millisecond
	if base <= 0 {
		base = singleWindowBase
	}
	rtt := base + singleWindowSlack
	return min(max(int(r.rate*rtt.Seconds())/mtu, singleMinWindow), max(ceiling, singleMinWindow))
}
