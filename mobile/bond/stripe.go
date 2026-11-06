package bond

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"slices"
	"sync"
	"time"
)

const (
	// windowFrames bounds how far past the peer's delivery point a frame may
	// be sent, whatever the window in bytes allows: receivers take 512
	// (acceptFrames), so this stays the contract with older peers both ways.
	windowFrames = 256
	// acceptFrames is how far past its own delivery point a receiver takes
	// frames: the window of every sender so far, the older ones included.
	acceptFrames = 512
	// readAhead is how much of the local side is read before a lane takes it.
	readAhead = 256 << 10
	// ackEvery: a receiver reports at least this often per sub-connection,
	// and at once whenever it has read everything that had arrived.
	ackEvery = 32 << 10
	// subBuffer is a sub-connection's read buffer: frame heads and small
	// frames come through it, a larger payload straight into its own slice.
	subBuffer = 16 << 10

	// A stream keeps about windowTime of its lanes' combined rate past the
	// peer's delivery point (windowFloor to windowCeil), which bounds the
	// peer's reorder buffer, and less when the side's budget (memBudget) is
	// spent, down to budgetFloor. A peer from before the hello's extFlag
	// reports its delivery point only every windowFrames/8 frames, so toward
	// one a stream always may have legacyAckFrames out.
	windowTime      = time.Second
	windowFloor     = 256 << 10
	windowCeil      = 4 << 20
	budgetFloor     = 64 << 10
	legacyAckFrames = windowFrames/8 + 1

	// A lane may hold about its rate times (its base round trip +
	// queueTarget, or two round trips when that is more) unconfirmed, so
	// every lane's queue drains in about the same time and frames arrive
	// close to their turn, while a lane that is not full yet can still
	// double what it carries every round trip. A lane not measured yet starts
	// at capProbe and grows by what it delivers (doubling every round trip)
	// until its round trip shows a queue.
	capProbe    = 64 << 10
	capMax      = 16 << 20
	queueTarget = 200 * time.Millisecond
	sampleMin   = 200 * time.Millisecond
	// A lane takes a frame only when it would deliver it no later than the
	// soonest other lane could, plus that lane's own time or etaSlack,
	// whichever is more (a lane behind with what it holds counts as that much
	// later): one far slower than the rest, such as a room holding its speed
	// down to a trickle, would make the frame late for its turn and the peer
	// wait for it with everything after it. Lanes that are merely farther
	// away keep their share.
	etaSlack = queueTarget
	// etaGuess is when a frame on a lane with no round trip measured yet is
	// expected to arrive, so it is rescued soon if that lane is slow; a lane
	// that proves its speed in time has what it holds re-timed (retime).
	etaGuess = 150 * time.Millisecond

	// A frame another lane is rescueLate overdue with is sent again by the
	// next lane with room, and a timer wakes the writers for it, as nothing
	// else may on a quiet stream. A lane with nothing else to send also sends
	// again what another lane would deliver rescueMargin later than it. Only
	// the rescueScan oldest frames in flight are looked at; a frame is
	// rescued once. A lane in the failure group of the lane that holds a
	// frame leaves it to a lane of another group with room, for groupGrace.
	rescueScan   = 64
	rescueMargin = 20 * time.Millisecond
	rescueLate   = 150 * time.Millisecond
	checkMin     = 50 * time.Millisecond
	groupGrace   = rescueLate

	// A lane kept off frames for being slow (timely) carries a burst of
	// copies of frames other lanes hold every probeEvery while the stream
	// sends: the stream never waits for the copies, and their round trip
	// shows how fast the lane carries now (learnBurst). So does a lane back
	// from a suspension or a loss before it takes frames again. A burst is
	// probeBurstBytes or probeBurstFrames copies, whichever comes first: one
	// frame's timing alone was too coarse to read a lane by.
	probeEvery       = 3 * time.Second
	probeBurstBytes  = 64 << 10
	probeBurstFrames = 10

	// A sub-connection that confirms nothing for softAfter (softMin at
	// least, softUnknown before its round trip is known) suspends its lane
	// for every stream and has its frames sent again over the other lanes;
	// one that goes on so for stallAfter (stallMin at least) counts a hard
	// stall, and one stalled for stallDrop more is closed and dialed again.
	softMin     = 500 * time.Millisecond
	softUnknown = time.Second
	stallMin    = 2 * time.Second
	stallDrop   = 30 * time.Second
	// orphanWait is how long a stream with no sub-connection left waits for
	// a new one before it gives up.
	orphanWait = 30 * time.Second
	// lingerWait bounds the goodbye: the last acks out, then the peer's end.
	lingerWait = 2 * time.Second

	// A client's stream starts on one lane and calls the others (onGrow)
	// once it has moved joinAfter, has kept busy (data each growGap) for
	// growBusy, has waited waitAnswer (or four round trips) for an answer to
	// what it sent, was held back by its lane for longer than a round trip,
	// or its lane failed it: short connections pay for one lane, not all.
	joinAfter  = 256 << 10
	growGap    = 250 * time.Millisecond
	growBusy   = time.Second
	waitAnswer = time.Second
)

var (
	errLanesLost = errors.New("bond: every lane is gone")
	errPeerGone  = errors.New("bond: the other side ended the stream")
	errPeerReset = errors.New("bond: the other side failed the stream")
)

// stripe carries one byte stream in each direction over a changing set of
// sub-connections.
//
// Out: the local side is cut into numbered frames; a sub-connection's writer
// takes the next frame while its lane has room (see sub.capacity) and keeps
// it on the lane's list until the peer confirms it. Frames of a lane that
// dies or stalls go to the front of the queue again, and a lane that would
// otherwise idle sends again what a slower lane still holds. In: every
// sub-connection's reader files frames by number, dropping copies; one
// writer passes them to the local side in order.
//
// The end of a direction is a numbered frame of its own, so it travels,
// waits and is resent like data. The stream is over when both ends are
// delivered and confirmed; it fails when no sub-connection is left for
// orphanWait, or on a local error.
type stripe struct {
	local io.ReadWriteCloser
	// onLoss hears that a sub-connection of a lane went away while the
	// stream still needs it. Set before the first add.
	onLoss func(lane int)
	// onGrow, when set, is called once (on its own goroutine) when the
	// stream should have every lane (see joinAfter). Set before the first add.
	onGrow func()
	// budget bounds what this side's streams hold together; nil: no bound.
	// peerAcksEarly: the peer reports its delivery point once it delivered
	// all that arrived (its hello said so), so the window may be small.
	// Both set before the first add.
	budget        *memBudget
	peerAcksEarly bool
	// clock is time.Now unless a test sets it.
	clock func() time.Time

	// mu guards the stripe's state and every sub's but c, r, lane, group and
	// stats, which are fixed at add. A laneStats has its own mutex, taken
	// under mu, last; nothing else is locked while mu is held, and onLoss and
	// onGrow are called after it is released.
	mu       sync.Mutex
	outCond  *sync.Cond // writers wait here
	inCond   *sync.Cond // the local writer waits here
	readCond *sync.Cond // the local reader waits here
	subs     []*sub     // the live ones
	readers  sync.WaitGroup
	writers  sync.WaitGroup
	// orphanSince: since when no sub-connection is live (zero while one is).
	orphanSince time.Time
	timer       *time.Timer
	timerAt     time.Time
	// wakeAt: a suspended lane may take frames again then.
	wakeAt time.Time
	logs   []string // lines to write once mu is released

	// Out.
	frames     map[uint32]*outFrame // cut, not yet confirmed
	fresh      []uint32             // never sent, in order
	freshBytes int
	resend     []uint32 // to send again, in order
	nextSeq    uint32
	ended      bool   // the local side's reading half is over, its end frame cut
	peerNext   uint32 // the peer delivered every frame below this
	// inWin: the payload sizes of the frames from peerNext to fresh[0]
	// (sent, not delivered yet), winBytes their sum; held is freshBytes +
	// winBytes as charged to the budget.
	inWin    []int32
	winBytes int64
	held     int64

	// Growing (onGrow).
	grown        bool
	moved        int64     // frame bytes in and out
	activeSince  time.Time // data moved every growGap since then
	lastActive   time.Time
	askedAt      time.Time // sent data and heard nothing since
	limitedSince time.Time // a lane held back frames with work waiting since then

	// In.
	pending      map[uint32][]byte
	next         uint32
	finSeq       int64 // the peer's end frame, -1 until seen
	inDone       bool  // the peer's end is delivered
	ackNext      bool  // `next` moved far enough to be worth an ack of its own
	reportedNext uint32

	closing bool  // both directions are over: the goodbye is under way
	over    bool  // closed down
	failed  error // why, when it was not a clean end

	done     chan struct{}
	doneOnce sync.Once
}

type outFrame struct {
	payload  []byte    // empty: the end frame
	holder   *sub      // the lane it was last sent on
	due      time.Time // when it should reach the peer that way
	rescued  bool
	requeued time.Time // when it last went to the resend queue
}

type sub struct {
	lane  int
	group int // failure group (laneStats.failGroup)
	c     net.Conn
	r     *bufio.Reader
	stats *laneStats
	dead  bool
	// settled: its unconfirmed bytes are off the lane's in-flight count.
	settled bool

	// Out, on this lane.
	sent     int64    // frame bytes written
	peerGot  int64    // frame bytes the peer reports as arrived
	flights  []flight // frames written here and not confirmed yet, in order
	progress time.Time
	// stalled: it confirmed nothing for softAfter while it held frames; it
	// takes none until it confirms again. stallSince: since when it
	// confirmed nothing; hard: that has lasted stallAfter.
	stalled    bool
	stallSince time.Time
	hard       bool
	rate       float64 // bytes per second the lane delivers
	// minRTT is the least round trip of the last rttWindowFor (rtt), which
	// says when frames are late; baseRTT the least of the stream's life,
	// which sizes the lane's share: a window over a lane that never drains
	// would read its own queue as distance and let it grow.
	minRTT    time.Duration
	baseRTT   time.Duration
	rtt       minWindow
	sampleAt  time.Time
	sampleGot int64
	busy      bool // the lane, not the stream, held frames back this sample
	// proven: rate was read while the lane, not the stream, set the pace.
	// Until then it is only a floor (a lane that carried pings reads as a
	// few bytes a second) and the lane is treated as still probing.
	proven   bool
	startup  bool // still finding its speed: may carry startCap
	startCap int64
	// A probe burst (burst): probedAt when the last began; burstOn while
	// its copies go out; burstAt, burstBytes, burstFrames what went out;
	// burstOut the copies not confirmed yet; burstNext where the next copy
	// is looked for. probeNext marks the frame take just handed out as one.
	probedAt    time.Time
	burstOn     bool
	burstAt     time.Time
	burstBytes  int
	burstFrames int
	burstOut    int
	burstNext   uint32
	probeNext   bool

	// In, on this lane.
	got      int64
	reported int64
	ackDue   bool
}

type flight struct {
	seq  uint32
	end  int64 // sub.sent once this frame was written
	at   time.Time
	due  time.Time // when it should reach the peer this way
	size int       // payload bytes
	// probe: a copy sent to measure the lane, not to carry the stream.
	probe bool
}

func newStripe(local io.ReadWriteCloser) *stripe {
	s := &stripe{
		local:       local,
		frames:      make(map[uint32]*outFrame),
		pending:     make(map[uint32][]byte),
		finSeq:      -1,
		orphanSince: time.Now(),
		done:        make(chan struct{}),
	}
	s.outCond = sync.NewCond(&s.mu)
	s.inCond = sync.NewCond(&s.mu)
	s.readCond = sync.NewCond(&s.mu)
	s.timer = time.AfterFunc(orphanWait, s.check)
	s.timerAt = s.orphanSince.Add(orphanWait)
	return s
}

func (s *stripe) time() time.Time {
	if s.clock != nil {
		return s.clock()
	}
	return time.Now()
}

// unlock releases mu, then writes the lines gathered under it.
func (s *stripe) unlock() {
	logs := s.logs
	s.logs = nil
	s.mu.Unlock()
	for _, l := range logs {
		log.Print(l)
	}
}

func (s *stripe) logLine(line string) {
	if line != "" {
		s.logs = append(s.logs, line)
	}
}

// run moves the stream until it is over; nil for a clean end.
func (s *stripe) run() error {
	go s.pumpOut()
	s.pumpIn()
	<-s.done
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.failed
}

// add puts one more sub-connection to work; false (and c closed) when the
// stream is already over. stats, when given, is what earlier streams learned
// about the lane, and what this one teaches the next.
func (s *stripe) add(lane int, c net.Conn, stats *laneStats) bool {
	s.mu.Lock()
	if s.closing || s.over {
		s.mu.Unlock()
		_ = c.Close()
		return false
	}
	now := s.time()
	sb := &sub{lane: lane, group: stats.failGroup(lane), c: c, r: bufio.NewReaderSize(c, subBuffer), stats: stats, startCap: capProbe}
	if stats != nil {
		sb.rate, sb.minRTT = stats.load()
		sb.baseRTT = sb.minRTT
		sb.rtt.add(sb.minRTT, now)
	}
	sb.proven = sb.rate > 0
	sb.startup = sb.rate <= 0
	s.subs = append(s.subs, sb)
	s.orphanSince = time.Time{}
	s.rehome(now)
	s.readers.Add(1)
	s.writers.Add(1)
	s.outCond.Broadcast()
	s.mu.Unlock()
	go s.write(sb)
	go s.read(sb)
	return true
}

// isOver: no sub-connection can join any more.
func (s *stripe) isOver() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closing || s.over
}

// pumpOut cuts the local side into frames until it ends. It reads no further
// ahead than readAhead, nor past a frame while the budget is spent.
func (s *stripe) pumpOut() {
	buf := make([]byte, maxPayload)
	for {
		s.mu.Lock()
		for (s.freshBytes >= readAhead || (s.freshBytes >= maxPayload && s.budget.free() <= 0)) && !s.over {
			s.readCond.Wait()
		}
		over := s.over
		s.mu.Unlock()
		if over {
			return
		}
		n, err := s.local.Read(buf)
		s.mu.Lock()
		if n > 0 && !s.over {
			s.cut(append([]byte(nil), buf[:n]...))
			s.freshBytes += n
			s.charge(int64(n))
		}
		if err != nil && isClosed(err) && !s.over {
			s.cut([]byte{})
			s.ended = true
		}
		s.outCond.Broadcast()
		s.mu.Unlock()
		if err != nil {
			if !isClosed(err) {
				s.fail(err)
			}
			return
		}
	}
}

func (s *stripe) cut(p []byte) {
	s.frames[s.nextSeq] = &outFrame{payload: p}
	s.fresh = append(s.fresh, s.nextSeq)
	s.nextSeq++
}

// charge moves what the stream holds against the budget by n.
func (s *stripe) charge(n int64) {
	s.held += n
	s.budget.add(n)
}

// write sends this lane's share: acks first, then frames while it has room.
func (s *stripe) write(sb *sub) {
	defer s.writers.Done()
	var buf []byte // grows on first use: an idle sub-connection stays small
	for {
		buf = buf[:0]
		s.mu.Lock()
		for {
			if sb.dead || s.over {
				s.mu.Unlock()
				return
			}
			if sb.ackDue || s.ackNext {
				buf = appendAck(buf, s.next, sb.got)
				sb.reported, sb.ackDue = sb.got, false
				s.reportedNext, s.ackNext = s.next, false
			}
			if !s.closing {
				now := s.time()
				if seq, f, ok := s.take(sb, now); ok {
					buf = appendFrame(buf, seq, f.payload)
					s.sending(sb, seq, f, now)
				}
			}
			if len(buf) > 0 {
				break
			}
			if s.closing {
				s.mu.Unlock()
				return
			}
			s.outCond.Wait()
		}
		s.unlock()
		if _, err := sb.c.Write(buf); err != nil {
			s.lose(sb)
			return
		}
	}
}

// sending books the frame take handed sb as on its way now.
func (s *stripe) sending(sb *sub, seq uint32, f *outFrame, now time.Time) {
	due := now.Add(sb.eta(len(f.payload)))
	n := frameSize(f.payload)
	sb.sent += n
	probe := sb.probeNext
	sb.probeNext = false
	if probe {
		sb.burstOut++
	}
	if st := sb.stats; st != nil {
		st.tx.Add(n)
		st.inflight.Add(n)
		st.frames.Add(1)
		if probe {
			st.probes.Add(1)
		}
	}
	if sb.sampleAt.IsZero() {
		// The first rate sample spans from here, so a lane is measured on
		// its first confirmation that comes sampleMin later, however slow
		// it is.
		sb.sampleAt, sb.sampleGot = now, sb.peerGot
	}
	sb.flights = append(sb.flights, flight{seq: seq, end: sb.sent, at: now, due: due,
		size: len(f.payload), probe: probe})
	if len(sb.flights) == 1 {
		s.arm(now.Add(sb.softAfter()))
	}
	s.arm(due.Add(rescueLate))
}

// gate is what a lane in trouble may send: everything, nothing (it is
// suspended), or only a probe burst (it is back and not measured yet).
type gate int

const (
	gateOpen gate = iota
	gateShut
	gateProbe
)

// laneGate: what sb's lane may send now. A lane in trouble calls the other
// lanes in (onGrow); it is held back only while another lane can carry.
func (s *stripe) laneGate(sb *sub, now time.Time) gate {
	until, probe := sb.stats.health(now)
	if !probe {
		return gateOpen
	}
	s.growNow()
	if !until.IsZero() {
		if !s.hasOther(sb, now, false) {
			return gateOpen
		}
		if s.wakeAt.IsZero() || until.Before(s.wakeAt) {
			s.wakeAt = until
		}
		s.arm(until)
		return gateShut
	}
	if !s.hasOther(sb, now, true) {
		return gateOpen
	}
	return gateProbe
}

// hasOther: a lane other than sb's can carry now; healthy: one that owes no
// probe either.
func (s *stripe) hasOther(sb *sub, now time.Time, healthy bool) bool {
	for _, o := range s.subs {
		if o == sb || o.dead || o.stalled {
			continue
		}
		if until, probe := o.stats.health(now); until.IsZero() && (!healthy || !probe) {
			return true
		}
	}
	return false
}

// leaveToOtherGroup: sb shares a failure group with the lane a frame came
// from, the frame became urgent less than groupGrace before now, and a lane
// of another group has room for it: that lane takes it.
func (s *stripe) leaveToOtherGroup(sb *sub, from *sub, since, now time.Time) bool {
	if from == nil || sb.group != from.group || !now.Before(since.Add(groupGrace)) {
		return false
	}
	for _, o := range s.subs {
		if o == sb || o.group == from.group || o.dead || o.stalled || o.sent-o.peerGot >= o.capacity() {
			continue
		}
		if until, _ := o.stats.health(now); until.IsZero() {
			return true
		}
	}
	return false
}

// take picks what sb sends next: a frame to send again, else the next new
// one inside the peer's window, else a frame a slower lane holds; each only
// when sb would deliver it in good time (timely). A lane refused a new frame
// for its speed gets a probe burst now and then instead (burst).
func (s *stripe) take(sb *sub, now time.Time) (uint32, *outFrame, bool) {
	if sb.stalled {
		return 0, nil, false
	}
	if sb.refresh(now) {
		s.retime(sb, now)
	}
	work := len(s.resend) > 0 || s.windowOpen(now)
	if sb.sent-sb.peerGot >= sb.capacity() {
		sb.busy = sb.busy || work
		if work {
			s.limited(sb, now)
		}
		return 0, nil, false
	}
	if !work {
		s.limitedSince = time.Time{}
	}
	switch s.laneGate(sb, now) {
	case gateShut:
		return 0, nil, false
	case gateProbe:
		return s.burst(sb, now, true)
	}
	if sb.burstOn {
		if seq, f, ok := s.burst(sb, now, false); ok {
			return seq, f, true
		}
	}
	for len(s.resend) > 0 {
		seq := s.resend[0]
		f, ok := s.frames[seq]
		if !ok {
			s.resend = s.resend[1:]
			continue
		}
		if s.leaveToOtherGroup(sb, f.holder, f.requeued, now) || !s.timely(sb, len(f.payload), now) {
			break
		}
		s.resend = s.resend[1:]
		f.holder, f.due = sb, now.Add(sb.eta(len(f.payload)))
		s.countResent(sb)
		return seq, f, true
	}
	if seq, f, ok := s.rescue(sb, now, true); ok {
		s.countResent(sb)
		return seq, f, true
	}
	refused := false
	if s.windowOpen(now) {
		seq := s.fresh[0]
		if f := s.frames[seq]; s.timely(sb, len(f.payload), now) {
			n := len(f.payload)
			s.fresh = s.fresh[1:]
			s.freshBytes -= n
			s.inWin = append(s.inWin, int32(n))
			s.winBytes += int64(n)
			s.readCond.Signal()
			f.holder, f.due = sb, now.Add(sb.eta(n))
			if n > 0 {
				s.active(now, frameSize(f.payload))
				if s.askedAt.IsZero() && !s.grown && s.onGrow != nil {
					s.askedAt = now
					s.arm(now.Add(s.answerWait()))
				}
			}
			return seq, f, true
		}
		refused = true
	}
	if seq, f, ok := s.rescue(sb, now, false); ok {
		s.countResent(sb)
		return seq, f, true
	}
	if refused {
		return s.burst(sb, now, false)
	}
	return 0, nil, false
}

func (s *stripe) countResent(sb *sub) {
	if sb.stats != nil {
		sb.stats.resent.Add(1)
	}
}

// windowOpen: the next new frame fits the window past the peer's delivery
// point (sendWindow); never past windowFrames, and toward a peer that acks
// late always up to legacyAckFrames, which it acks without waiting.
func (s *stripe) windowOpen(now time.Time) bool {
	if len(s.fresh) == 0 {
		return false
	}
	out := s.fresh[0] - s.peerNext
	switch {
	case out >= windowFrames:
		return false
	case s.winBytes == 0, !s.peerAcksEarly && out < legacyAckFrames:
		return true
	}
	return s.winBytes+int64(len(s.frames[s.fresh[0]].payload)) <= s.sendWindow()
}

// sendWindow is the bytes the stream may have past the peer's delivery
// point: windowTime of what its live lanes carry, within windowFloor and
// windowCeil, and no more than the budget leaves it (budgetFloor at least).
func (s *stripe) sendWindow() int64 {
	var rate float64
	for _, o := range s.subs {
		if !o.dead && !o.stalled {
			rate += o.rate
		}
	}
	w := min(max(int64(rate*windowTime.Seconds()), windowFloor), windowCeil)
	return min(w, max(budgetFloor, s.winBytes+s.budget.free()))
}

// burst hands sb the next copy of a probe burst: copies of frames other
// lanes hold, sent back to back, whose confirmation shows what the lane
// carries now (learnBurst). lane: the lane's own probe after trouble,
// claimed from its stats so that one stream at a time sends it; else this
// stream's, every probeEvery, for a lane it keeps off frames for being slow.
func (s *stripe) burst(sb *sub, now time.Time, lane bool) (uint32, *outFrame, bool) {
	if !sb.burstOn {
		if len(sb.flights) > 0 || sb.burstOut > 0 {
			return 0, nil, false
		}
		// Nothing to copy: the turn is not taken from another stream.
		if _, _, ok := s.probeCopy(sb, s.peerNext); !ok {
			return 0, nil, false
		}
		if lane {
			if !sb.stats.claimProbe(now) {
				return 0, nil, false
			}
		} else if now.Sub(sb.probedAt) < probeEvery {
			return 0, nil, false
		}
		sb.burstOn, sb.burstAt, sb.burstBytes, sb.burstFrames, sb.burstNext = true, now, 0, 0, s.peerNext
		sb.probedAt = now
	}
	seq, f, ok := s.probeCopy(sb, sb.burstNext)
	if !ok {
		sb.burstOn = false
		return 0, nil, false
	}
	sb.burstNext = seq + 1
	sb.burstBytes += len(f.payload)
	sb.burstFrames++
	if sb.burstBytes >= probeBurstBytes || sb.burstFrames >= probeBurstFrames {
		sb.burstOn = false
	}
	sb.probeNext = true
	return seq, f, true
}

// probeCopy is a copy of the oldest frame from `from` on that another lane
// holds: the frame stays that lane's to deliver, so the stream does not wait
// for the copy. An end frame has no bytes to measure.
func (s *stripe) probeCopy(sb *sub, from uint32) (uint32, *outFrame, bool) {
	limit := s.nextSeq
	if len(s.fresh) > 0 {
		limit = s.fresh[0]
	}
	for seq, n := max(s.peerNext, from), 0; seq < limit && n < rescueScan; seq++ {
		f, ok := s.frames[seq]
		if !ok {
			continue
		}
		n++
		if f.holder == nil || f.holder == sb || f.holder.dead || len(f.payload) == 0 {
			continue
		}
		return seq, f, true
	}
	return 0, nil, false
}

// rescue sends again the oldest frame in flight on another lane that is
// overdue there, or (unless onlyLate, and only a lane that knows its own
// speed) that this lane would deliver clearly sooner.
func (s *stripe) rescue(sb *sub, now time.Time, onlyLate bool) (uint32, *outFrame, bool) {
	limit := s.nextSeq
	if len(s.fresh) > 0 {
		limit = s.fresh[0]
	}
	for seq, n := s.peerNext, 0; seq < limit && n < rescueScan; seq++ {
		f, ok := s.frames[seq]
		if !ok {
			continue
		}
		n++
		if f.rescued || f.holder == nil || f.holder == sb || f.holder.dead || f.holder.stalled {
			continue
		}
		if late := f.due.Add(rescueLate); !now.Before(late) {
			// Late: worth a copy from any lane that is not slow itself, as
			// the frame is rescued only once.
			if s.leaveToOtherGroup(sb, f.holder, late, now) || !s.timely(sb, len(f.payload), now) {
				continue
			}
		} else if onlyLate || !sb.proven || !now.Add(sb.eta(len(f.payload))+rescueMargin).Before(f.due) {
			continue
		}
		f.rescued = true
		return seq, f, true
	}
	return 0, nil, false
}

// timely: sb would deliver a frame of n bytes sent now in good time next to
// every other lane (see etaSlack), each counted as late as it is behind
// already, and as slow as it has surely been (its floor, until it proves its
// speed). A lane that has not proven its own speed is let through to learn
// it; what it holds is rescued if it turns out slow. A suspended lane is no
// one to wait for.
func (s *stripe) timely(sb *sub, n int, now time.Time) bool {
	if !sb.proven {
		return true
	}
	mine := sb.reach(n) + sb.lateness(now)
	for _, o := range s.subs {
		if o == sb || o.dead || o.stalled {
			continue
		}
		if o.refresh(now) {
			s.retime(o, now)
		}
		if o.rate <= 0 {
			continue
		}
		if until, _ := o.stats.health(now); !until.IsZero() {
			continue
		}
		if theirs := o.floorEta(n) + o.lateness(now); mine > theirs+max(etaSlack, theirs) {
			return false
		}
	}
	return true
}

// read files the peer's frames and acks from one sub-connection.
func (s *stripe) read(sb *sub) {
	defer s.readers.Done()
	for {
		f, err := readFrame(sb.r)
		if err != nil {
			s.lose(sb)
			return
		}
		if f.kind == kindReset {
			s.drop(errPeerReset)
			return
		}
		s.mu.Lock()
		if f.kind == kindAck {
			s.onAck(sb, f.seq, f.got)
			s.unlock()
			continue
		}
		now := s.time()
		size := frameSize(f.payload)
		sb.got += size
		if sb.stats != nil {
			sb.stats.noteRx(size, now)
		}
		if err := s.file(sb.lane, f); err != nil {
			s.mu.Unlock()
			s.fail(err)
			return
		}
		if f.kind == kindData {
			s.askedAt = time.Time{}
			s.active(now, size)
		}
		if sb.got-sb.reported >= ackEvery || sb.r.Buffered() == 0 {
			sb.ackDue = true
			s.outCond.Broadcast()
		}
		s.unlock()
	}
}

// file takes one data or end frame that came on lane.
func (s *stripe) file(lane int, f inFrame) error {
	if f.seq < s.next || (s.finSeq >= 0 && int64(f.seq) > s.finSeq) {
		return nil // a copy, or nothing
	}
	if f.seq-s.next >= acceptFrames {
		return &badFrameError{lane: lane, seq: f.seq, next: s.next, finSeq: s.finSeq, size: len(f.payload)}
	}
	if f.kind == kindEnd {
		s.finSeq = int64(f.seq)
	} else if _, ok := s.pending[f.seq]; !ok {
		s.pending[f.seq] = f.payload
	}
	s.inCond.Signal()
	return nil
}

// badFrameError is a frame further past the receiver's delivery point than
// any sender keeping to its window goes: bytes on a lane that are not what
// its sender wrote, or a sender out of step. It is errBadFrame to errors.Is,
// and says which lane brought it and its numbers, never what it carries.
type badFrameError struct {
	lane   int    // as the client numbers its lanes, from 0
	seq    uint32 // the frame's number
	next   uint32 // the receiver's delivery point
	finSeq int64  // the peer's end frame, -1 until seen
	size   int    // payload bytes; 0 for an end frame
}

func (e *badFrameError) Error() string { return errBadFrame.Error() + " " + e.where() }

func (e *badFrameError) Unwrap() error { return errBadFrame }

// where is the lane, counted from 1 as the app counts its rooms, and the
// numbers: "on lane 2 (seq 70123, expected from 69500, 1380 bytes)".
func (e *badFrameError) where() string {
	end := ""
	if e.finSeq >= 0 {
		end = fmt.Sprintf(", end at %d", e.finSeq)
	}
	return fmt.Sprintf("on lane %d (seq %d, expected from %d%s, %d bytes)", e.lane+1, e.seq, e.next, end, e.size)
}

// onAck takes the peer's report for sb: frames it confirms are done with,
// and the lane's rate and round trip are measured from it.
func (s *stripe) onAck(sb *sub, next uint32, got int64) {
	now := s.time()
	if next > s.peerNext && next <= s.nextSeq {
		for seq := s.peerNext; seq < next; seq++ {
			delete(s.frames, seq)
		}
		k := min(int(next-s.peerNext), len(s.inWin))
		var freed int64
		for _, n := range s.inWin[:k] {
			freed += int64(n)
		}
		s.inWin = s.inWin[k:]
		s.winBytes -= freed
		s.charge(-freed)
		s.peerNext = next
		s.outCond.Broadcast()
	}
	if got > sb.peerGot && got <= sb.sent {
		i := 0
		var newest time.Time
		for i < len(sb.flights) && sb.flights[i].end <= got {
			delete(s.frames, sb.flights[i].seq)
			newest = sb.flights[i].at
			if sb.flights[i].probe && sb.burstOut > 0 {
				sb.burstOut--
			}
			i++
		}
		sb.flights = sb.flights[i:]
		if !newest.IsZero() {
			rtt := now.Sub(newest)
			sb.rtt.add(rtt, now)
			sb.minRTT = sb.rtt.get(now)
			if sb.baseRTT == 0 || rtt < sb.baseRTT {
				sb.baseRTT = rtt
			}
			if sb.stats != nil {
				sb.stats.noteRTT(rtt)
			}
			if sb.startup {
				if rtt > sb.baseRTT+queueTarget {
					sb.startup = false
				} else {
					sb.startCap += got - sb.peerGot
				}
			}
		}
		if !sb.burstOn && sb.burstOut == 0 && sb.burstBytes > 0 {
			s.learnBurst(sb, now, got)
			sb.burstBytes = 0
		}
		proven := sb.proven
		sb.sample(now, got)
		if sb.stats != nil {
			sb.stats.inflight.Add(-(got - sb.peerGot))
			s.logLine(sb.stats.progress(now))
		}
		sb.peerGot = got
		sb.progress = now
		recovered := sb.stalled
		sb.stalled, sb.hard = false, false
		if !proven && sb.proven {
			s.retime(sb, now)
		}
		if recovered {
			s.rehome(now)
		}
		s.outCond.Broadcast()
	}
	s.maybeClose()
}

// learnBurst takes a probe burst's round trip for the lane's speed: what its
// bytes took beyond the lane's round trip is the lane's rate now. Only a
// higher reading counts (copies alone cannot show a lane slower than it has
// read), and no higher than the fastest other lane, as a burst's timing is
// too coarse to put a lane ahead of them; the frames the lane then takes
// measure it properly (sample), from here.
func (s *stripe) learnBurst(sb *sub, now time.Time, got int64) {
	transit := max(now.Sub(sb.burstAt)-sb.minRTT, time.Millisecond)
	r := float64(sb.burstBytes) / transit.Seconds()
	var fastest float64
	for _, o := range s.subs {
		if o != sb && !o.dead {
			fastest = max(fastest, o.rate)
		}
	}
	if fastest > 0 {
		r = min(r, fastest)
	}
	if r > sb.rate {
		sb.rate = r
	}
	sb.sampleAt, sb.sampleGot, sb.busy = now, got, false
}

// retime gives the frames sb holds the arrival times its speed says, once it
// has proven it: they went out with a guess, which a lane that is merely
// busy misses, and a frame rescued for that goes out twice for nothing.
func (s *stripe) retime(sb *sub, now time.Time) {
	for i := range sb.flights {
		fl := &sb.flights[i]
		fl.due = now.Add(time.Duration(float64(fl.end-sb.peerGot)/sb.rate*float64(time.Second)) + sb.minRTT/2)
		if f, ok := s.frames[fl.seq]; ok && f.holder == sb {
			f.due = fl.due
		}
	}
	if len(sb.flights) > 0 {
		s.arm(sb.flights[0].due.Add(rescueLate))
	}
}

// sample measures the lane's delivery rate over at least sampleMin (and a
// round trip). A lower reading counts only when the lane itself held frames
// back; otherwise the stream simply had less to send. A reading proves the
// lane's speed when the lane set the pace: it held frames back, or carried
// capProbe or more per sampleMin; only a proven rate is passed on to other
// streams.
func (sb *sub) sample(now time.Time, got int64) {
	if sb.sampleAt.IsZero() {
		sb.sampleAt, sb.sampleGot, sb.busy = now, got, false
		return
	}
	elapsed := now.Sub(sb.sampleAt)
	if elapsed < max(sampleMin, sb.minRTT) {
		return
	}
	r := float64(got-sb.sampleGot) / elapsed.Seconds()
	switch {
	case r > sb.rate:
		sb.rate = r
	case sb.busy:
		sb.rate = 0.75*sb.rate + 0.25*r
	}
	sb.proven = sb.proven || sb.busy || r*sampleMin.Seconds() >= capProbe
	sb.sampleAt, sb.sampleGot, sb.busy = now, got, false
	if sb.stats != nil && sb.proven {
		sb.stats.store(sb.rate, sb.minRTT)
	}
}

func (sb *sub) capacity() int64 {
	base := sb.baseRTT
	if base == 0 {
		base = sb.minRTT
	}
	c := int64(capProbe)
	if sb.rate > 0 && base > 0 {
		c = int64(sb.rate * max(base+queueTarget, 2*base).Seconds())
	}
	if sb.startup {
		c = max(c, sb.startCap)
	}
	return min(max(c, capProbe), capMax)
}

// eta is how long a frame of n bytes sent now would take to reach the peer.
// A lane that has not proven its speed is taken to carry what it may per
// round trip, once a round trip is known, so what it holds is due soon and
// rescued soon if it turns out slow; before that, etaGuess.
func (sb *sub) eta(n int) time.Duration {
	queued := float64(sb.sent - sb.peerGot + int64(frameHead+n))
	switch {
	case sb.proven:
		return sb.floorEta(n)
	case sb.minRTT > 0:
		rate := max(sb.rate, float64(sb.startCap)/sb.minRTT.Seconds())
		return time.Duration(queued/rate*float64(time.Second)) + sb.minRTT/2
	default:
		return etaGuess
	}
}

// floorEta is eta at the rate the lane has shown: its speed once proven,
// until then a floor, so no sooner than it surely delivers. Needs a rate.
func (sb *sub) floorEta(n int) time.Duration {
	queued := float64(sb.sent - sb.peerGot + int64(frameHead+n))
	return time.Duration(queued/sb.rate*float64(time.Second)) + sb.minRTT/2
}

// reach is eta as the lane may soon prove it: one still finding its speed
// is judged by what it may carry a round trip, at most twice its rate (it
// doubles a round trip at best), as its rate so far only shows what it was
// given.
func (sb *sub) reach(n int) time.Duration {
	if !sb.proven || !sb.startup || sb.minRTT <= 0 {
		return sb.eta(n)
	}
	rate := max(sb.rate, min(float64(sb.startCap)/sb.minRTT.Seconds(), 2*sb.rate))
	queued := float64(sb.sent - sb.peerGot + int64(frameHead+n))
	return time.Duration(queued/rate*float64(time.Second)) + sb.minRTT/2
}

// lateness is how far the lane is behind with what it holds: its oldest
// frame in flight should have been confirmed by its due time plus the way
// back.
func (sb *sub) lateness(now time.Time) time.Duration {
	if len(sb.flights) == 0 {
		return 0
	}
	return max(0, now.Sub(sb.flights[0].due.Add(sb.minRTT/2)))
}

// refresh gives a lane that has not proven its speed on this stream yet
// what another stream through it has proven since; true when it did.
// laneStats.mu is taken under stripe.mu, never the other way round.
func (sb *sub) refresh(now time.Time) bool {
	if sb.proven || sb.stats == nil {
		return false
	}
	rate, minRTT := sb.stats.load()
	if rate <= 0 {
		return false
	}
	sb.rate, sb.proven = rate, true
	if minRTT > 0 {
		sb.rtt.add(minRTT, now)
		sb.minRTT = sb.rtt.get(now)
		if sb.baseRTT == 0 || minRTT < sb.baseRTT {
			sb.baseRTT = minRTT
		}
	}
	return true
}

func (sb *sub) stallAfter() time.Duration {
	return max(stallMin, 4*sb.minRTT+2*queueTarget)
}

// softAfter is how long the lane may confirm nothing while it holds frames
// before it is taken for stalled: two and a half round trips plus
// queueTarget (softMin at least), and twice what one full frame takes it.
func (sb *sub) softAfter() time.Duration {
	d := softUnknown
	if sb.minRTT > 0 {
		d = max(softMin, 5*sb.minRTT/2+queueTarget)
	}
	if sb.proven && sb.rate > 0 {
		d = max(d, 2*time.Duration(float64(frameHead+maxPayload)/sb.rate*float64(time.Second)))
	}
	return min(d, sb.stallAfter())
}

// active notes n frame bytes moving either way now (see joinAfter).
func (s *stripe) active(now time.Time, n int64) {
	s.moved += n
	if s.activeSince.IsZero() || now.Sub(s.lastActive) > growGap {
		s.activeSince = now
	}
	s.lastActive = now
	s.maybeGrow(now)
}

// answerWait is how long a stream waits for an answer before it calls the
// other lanes: waitAnswer, or four of its lanes' longest round trip.
func (s *stripe) answerWait() time.Duration {
	d := time.Duration(waitAnswer)
	for _, o := range s.subs {
		d = max(d, 4*o.minRTT)
	}
	return d
}

// maybeGrow calls the other lanes when the stream has earned them.
func (s *stripe) maybeGrow(now time.Time) {
	if s.grown || s.onGrow == nil {
		return
	}
	busy := !s.activeSince.IsZero() && now.Sub(s.lastActive) <= growGap && now.Sub(s.activeSince) >= growBusy
	waiting := !s.askedAt.IsZero() && now.Sub(s.askedAt) >= s.answerWait()
	if s.moved >= joinAfter || busy || waiting {
		s.growNow()
	}
}

// limited: sb held back frames that were waiting; for longer than its round
// trip, the stream calls the other lanes.
func (s *stripe) limited(sb *sub, now time.Time) {
	if s.grown || s.onGrow == nil {
		return
	}
	if s.limitedSince.IsZero() {
		s.limitedSince = now
	} else if now.Sub(s.limitedSince) > max(sb.minRTT, checkMin) {
		s.growNow()
	}
}

func (s *stripe) growNow() {
	if s.grown || s.onGrow == nil {
		return
	}
	s.grown = true
	go s.onGrow()
}

// pumpIn passes the peer's frames to the local side in order, then ends the
// local side's writing half.
func (s *stripe) pumpIn() {
	for {
		s.mu.Lock()
		var payload []byte
		for payload == nil {
			if s.over {
				s.mu.Unlock()
				return
			}
			if p, ok := s.pending[s.next]; ok {
				payload = p
				delete(s.pending, s.next)
				s.next++
				// Reported once everything that came is delivered, too: a
				// sender keeping a window of only a few frames waits for it.
				if s.next-s.reportedNext >= windowFrames/8 || len(s.pending) == 0 {
					s.ackNext = true
					s.outCond.Broadcast()
				}
				break
			}
			if s.finSeq >= 0 && int64(s.next) == s.finSeq {
				s.next++
				s.inDone = true
				s.ackNext = true
				s.outCond.Broadcast()
				s.mu.Unlock()
				closeWrite(s.local)
				s.mu.Lock()
				s.maybeClose()
				s.mu.Unlock()
				return
			}
			s.inCond.Wait()
		}
		s.mu.Unlock()
		if _, err := s.local.Write(payload); err != nil {
			s.fail(err)
			return
		}
	}
}

// maybeClose starts the goodbye once both directions are delivered and
// confirmed: every lane sends a last ack (the peer may still wait to hear
// that its end arrived), ends its writing half, and the stream closes when
// the peer has done the same or lingerWait is up.
func (s *stripe) maybeClose() {
	if s.closing || s.over || !s.inDone || !s.ended || len(s.frames) != 0 {
		return
	}
	s.closing = true
	for _, sb := range s.subs {
		sb.ackDue = true
	}
	s.ackNext = true
	s.outCond.Broadcast()
	go func() {
		waitFor(&s.writers, lingerWait)
		s.mu.Lock()
		subs := slices.Clone(s.subs)
		s.mu.Unlock()
		for _, sb := range subs {
			closeWrite(sb.c)
		}
		waitFor(&s.readers, lingerWait)
		s.finish()
	}()
}

// lose takes a sub-connection out: its unconfirmed frames go to the others,
// and the owner hears about it while the stream still needs the lane. A lane
// that lost a sub-connection carries a probe burst before frames again, and
// a stream still on one lane calls the others.
func (s *stripe) lose(sb *sub) {
	s.mu.Lock()
	if sb.dead {
		s.mu.Unlock()
		return
	}
	sb.dead = true
	s.requeue(sb, s.time())
	s.settle(sb)
	s.subs = slices.DeleteFunc(s.subs, func(x *sub) bool { return x == sb })
	needed := !s.closing && !s.over
	if needed {
		if sb.stats != nil {
			sb.stats.recheck()
		}
		s.growNow()
		if len(s.subs) == 0 {
			s.orphanSince = time.Now()
			s.arm(s.orphanSince.Add(orphanWait))
		}
	}
	s.outCond.Broadcast()
	s.mu.Unlock()
	_ = sb.c.Close()
	if needed && s.onLoss != nil {
		s.onLoss(sb.lane)
	}
}

// settle takes what sb has in flight off its lane's count, once.
func (s *stripe) settle(sb *sub) {
	if !sb.settled && sb.stats != nil {
		sb.stats.inflight.Add(-(sb.sent - sb.peerGot))
	}
	sb.settled = true
}

// requeue sends sb's unconfirmed frames again, over whichever lanes take
// them: those it was the one to deliver, not copies of another lane's.
func (s *stripe) requeue(sb *sub, now time.Time) {
	for _, fl := range sb.flights {
		if fl.probe {
			continue
		}
		if f, ok := s.frames[fl.seq]; ok && (f.holder == sb || f.holder == nil || f.holder.dead || f.holder.stalled) {
			f.requeued = now
			s.resend = append(s.resend, fl.seq)
		}
	}
	sb.flights = nil
	sb.burstOn, sb.burstOut, sb.burstBytes = false, 0, 0
	slices.Sort(s.resend)
	s.resend = slices.Compact(s.resend)
}

// rehome sends again what stalled lanes kept for want of another lane, now
// that one can carry.
func (s *stripe) rehome(now time.Time) {
	moved := false
	for _, o := range s.subs {
		if o.stalled && len(o.flights) > 0 && s.hasOther(o, now, false) {
			s.requeue(o, now)
			moved = true
		}
	}
	if moved {
		s.outCond.Broadcast()
	}
}

// peerGone: the other side no longer knows this stream. That is the end
// when everything of ours is out and everything of theirs is in.
func (s *stripe) peerGone() {
	s.mu.Lock()
	clean := s.inDone && s.ended
	s.mu.Unlock()
	if clean {
		s.finish()
	} else {
		s.drop(errPeerGone)
	}
}

// arm makes sure check runs by `at`. Holds mu.
func (s *stripe) arm(at time.Time) {
	if s.over || (!s.timerAt.IsZero() && !at.Before(s.timerAt)) {
		return
	}
	s.timerAt = at
	if s.timer != nil {
		s.timer.Reset(time.Until(at))
	}
}

func (s *stripe) check() { s.checkAt(s.time()) }

// checkAt runs on the timer: lanes that confirm nothing are suspended and
// hand their frames to the others, lanes stalled for too long are closed
// (and dialed again by the owner), a stream that waited for an answer calls
// its other lanes, and a stream left without lanes gives up after
// orphanWait.
func (s *stripe) checkAt(now time.Time) {
	s.mu.Lock()
	if s.over {
		s.mu.Unlock()
		return
	}
	s.timerAt = time.Time{}
	var next time.Time
	soonest := func(t time.Time) {
		if next.IsZero() || t.Before(next) {
			next = t
		}
	}
	var drop []net.Conn
	moved := false
	for _, sb := range s.subs {
		switch {
		case sb.stalled:
			hardAt := sb.stallSince.Add(sb.stallAfter())
			if !sb.hard {
				if now.Before(hardAt) {
					soonest(hardAt)
				} else {
					sb.hard = true
					if sb.stats != nil {
						s.logLine(sb.stats.hardStall(now))
					}
					if len(sb.flights) > 0 {
						s.requeue(sb, now)
						moved = true
					}
				}
			}
			if at := hardAt.Add(stallDrop); now.Before(at) {
				soonest(at)
			} else {
				drop = append(drop, sb.c)
			}
		case len(sb.flights) > 0:
			since := sb.flights[0].at
			if sb.progress.After(since) {
				since = sb.progress
			}
			if at := since.Add(sb.softAfter()); now.Before(at) {
				soonest(at)
			} else {
				sb.stalled, sb.stallSince, sb.hard = true, since, false
				if sb.stats != nil {
					s.logLine(sb.stats.suspend(now))
				}
				if s.hasOther(sb, now, false) {
					s.requeue(sb, now)
					moved = true
				} else {
					s.growNow()
				}
				soonest(since.Add(sb.stallAfter()))
			}
		}
	}
	orphaned := false
	if len(s.subs) == 0 && !s.orphanSince.IsZero() && !s.closing {
		if at := s.orphanSince.Add(orphanWait); now.Before(at) {
			soonest(at)
		} else {
			orphaned = true
		}
	}
	if !s.wakeAt.IsZero() {
		if now.Before(s.wakeAt) {
			soonest(s.wakeAt)
		} else {
			s.wakeAt, moved = time.Time{}, true
		}
	}
	if !s.grown && s.onGrow != nil && !s.askedAt.IsZero() {
		if at := s.askedAt.Add(s.answerWait()); now.Before(at) {
			soonest(at)
		} else {
			s.maybeGrow(now)
		}
	}
	// A frame late on its lane is rescued by the next writer with room, and
	// on a quiet stream nothing else wakes one: wake them here, and look
	// again while such a frame waits (no sooner than checkMin, as on a busy
	// stream the oldest frames' deadlines pass every few milliseconds). With
	// one lane left there is no one to rescue it.
	limit := s.nextSeq
	if len(s.fresh) > 0 {
		limit = s.fresh[0]
	}
	if len(s.subs) < 2 {
		limit = s.peerNext
	}
	again := now.Add(checkMin)
	for seq, n := s.peerNext, 0; seq < limit && n < rescueScan; seq++ {
		f, ok := s.frames[seq]
		if !ok {
			continue
		}
		n++
		if f.rescued || f.holder == nil || f.holder.dead || f.holder.stalled {
			continue
		}
		at := f.due.Add(rescueLate)
		if !now.Before(at) {
			moved = true
		}
		if at.Before(again) {
			at = again
		}
		soonest(at)
	}
	if moved {
		s.outCond.Broadcast()
	}
	if !next.IsZero() {
		s.arm(next)
	}
	s.unlock()
	for _, c := range drop {
		_ = c.Close() // its reader fails, and lose() takes it from there
	}
	if orphaned {
		s.drop(errLanesLost)
	}
}

// fail ends the stream on a local error and tells the peer, which would
// otherwise keep its side open until its lanes time out.
func (s *stripe) fail(err error) {
	s.mu.Lock()
	if s.over {
		s.mu.Unlock()
		return
	}
	subs := slices.Clone(s.subs)
	s.mu.Unlock()
	var told sync.WaitGroup
	for _, sb := range subs {
		told.Add(1)
		go func() {
			defer told.Done()
			_ = sb.c.SetWriteDeadline(time.Now().Add(time.Second))
			_, _ = sb.c.Write(appendReset(nil))
		}()
	}
	told.Wait()
	s.drop(err)
}

// drop ends the stream without telling the peer.
func (s *stripe) drop(err error) {
	s.mu.Lock()
	if s.failed == nil && !s.over {
		s.failed = err
	}
	s.mu.Unlock()
	s.finish()
}

// finish closes everything once; the peer sees its sub-connections close.
func (s *stripe) finish() {
	s.doneOnce.Do(func() {
		s.mu.Lock()
		s.over = true
		if s.timer != nil {
			s.timer.Stop()
		}
		s.charge(-s.held)
		subs := slices.Clone(s.subs)
		for _, sb := range subs {
			s.settle(sb)
		}
		s.outCond.Broadcast()
		s.inCond.Broadcast()
		s.readCond.Broadcast()
		s.mu.Unlock()
		for _, sb := range subs {
			_ = sb.c.Close()
		}
		_ = s.local.Close()
		close(s.done)
	})
}

func waitFor(wg *sync.WaitGroup, limit time.Duration) {
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(limit):
	}
}

func closeWrite(c io.ReadWriteCloser) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

func isClosed(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe)
}
