package vp8channel

// ai-generated: the whole file (issue #12: the data lane against an SFU that
// stops forwarding a stream over its budget).

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"hash/crc32"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/rtp/codecs"
	kcp "github.com/xtaci/kcp-go/v5"

	"github.com/openlibrecommunity/olcrtc/internal/transport"
)

// budgetRelay is one direction of an SFU the way JVB forwards a stream: it
// measures what the sender pushes at it and, at every allocation, stops
// forwarding all of it while the last window was over the budget, and
// forwards it again once a window is back under. JVB allocates every 5 s;
// what matters is that the window outlasts KCP's retransmission rounds, so
// resending keeps the stream over the budget. Frames reach the receiver on
// their own goroutine, as they would off the network.
type budgetRelay struct {
	budget int // bytes per window; zero forwards everything
	window time.Duration

	mu       sync.Mutex
	arrivals []relayArrival
	dark     bool
	frames   chan []byte
}

type relayArrival struct {
	at   time.Time
	size int
}

func newBudgetRelay(budget int, window time.Duration) *budgetRelay {
	return &budgetRelay{budget: budget, window: window, frames: make(chan []byte, 4096)}
}

// write is the sender's track.
func (r *budgetRelay) write(frame []byte) bool {
	r.mu.Lock()
	r.arrivals = append(r.arrivals, relayArrival{at: time.Now(), size: len(frame)})
	dark := r.dark
	r.mu.Unlock()
	if dark {
		return true
	}
	select {
	case r.frames <- append([]byte(nil), frame...):
	default:
	}
	return true
}

// run re-decides every period and delivers frames to the receiver until ctx ends.
func (r *budgetRelay) run(ctx context.Context, period time.Duration, to func([]byte)) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case frame := <-r.frames:
				to(frame)
			}
		}
	}()
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			r.allocate(now)
		}
	}
}

func (r *budgetRelay) allocate(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	kept, total := r.arrivals[:0], 0
	for _, a := range r.arrivals {
		if now.Sub(a.at) <= r.window {
			kept = append(kept, a)
			total += a.size
		}
	}
	r.arrivals = kept
	r.dark = r.budget > 0 && total > r.budget
}

// newLaneTestTransport is a transport on a relay, with the lane's timers
// scaled down to the relay's.
func newLaneTestTransport(t *testing.T, cfg transport.Config, relay *budgetRelay) *streamTransport {
	t.Helper()
	cfg.ChannelID = "lane-test"
	tr := newStreamTransport(&fakeVideoStream{canSend: true}, nil, cfg, Options{FPS: 50, BatchSize: 8})
	tr.sampleWriter = relay.write
	tr.blackoutAfter = 600 * time.Millisecond
	tr.probeEvery = 100 * time.Millisecond
	tr.growEvery = 500 * time.Millisecond
	if err := tr.Connect(context.Background()); err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = tr.Close() })
	return tr
}

// TestDataLaneBringsBackAStreamTheSFUStoppedForwarding is issue #12 in
// small: a server pulls to a client through an SFU that stops forwarding the
// server's stream as soon as a burst takes it over its budget. KCP resends
// every unacknowledged segment on each timeout, so a lane that keeps writing
// whatever KCP queues keeps the stream over the budget and dark: the client
// stops receiving for as long as that lasts, which on JVB was minutes. A lane
// that goes quiet once nothing is acknowledged lets the SFU take the stream
// back, and the transfer keeps moving.
func TestDataLaneBringsBackAStreamTheSFUStoppedForwarding(t *testing.T) {
	runLanePair(t, lanePair{toClient: 512 << 10, pull: 768 << 10})
}

// TestDataLanesKeepAnsweringWhileBothAreDark pulls and pushes at once through
// an SFU that polices both directions, so both lanes go dark together, as a
// push started on the tail of a pull did live. A dark lane must still carry
// what answers the peer: holding back acknowledgements too leaves each side
// waiting for the other's, and neither direction comes back.
func TestDataLanesKeepAnsweringWhileBothAreDark(t *testing.T) {
	runLanePair(t, lanePair{toClient: 512 << 10, toServer: 512 << 10, pull: 512 << 10, push: 512 << 10})
}

// lanePair is a server and a client on budget relays: the budgets per
// window each way (zero forwards everything) and what to move each way. A
// budget is above what a lane paces itself down to after a spell, half of
// the 560 KiB/s these options allow, so coming back does not trip it again
// by construction.
type lanePair struct {
	toClient, toServer int
	pull, push         int
}

// runLanePair moves the pair's bytes and fails once nothing has arrived
// either way for five seconds before they all did.
func runLanePair(t *testing.T, pair lanePair) {
	t.Helper()
	const (
		window   = time.Second
		allocate = 500 * time.Millisecond
		stallFor = 5 * time.Second
	)
	toClient := newBudgetRelay(pair.toClient, window)
	toServer := newBudgetRelay(pair.toServer, window)

	var pulled, pushed atomic.Int64
	client := newLaneTestTransport(t, transport.Config{
		OnData: func(b []byte) { pulled.Add(int64(len(b))) },
	}, toServer)
	server := newLaneTestTransport(t, transport.Config{
		OnPeerData: func(_ string, b []byte) { pushed.Add(int64(len(b))) },
	}, toClient)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go toClient.run(ctx, allocate, client.handleIncomingFrame)
	go toServer.run(ctx, allocate, server.handleIncomingFrame)

	if err := client.ConfirmPeer(server.LocalPeerID()); err != nil {
		t.Fatalf("ConfirmPeer: %v", err)
	}
	peer := client.LocalPeerID()
	waitFor(t, 5*time.Second, "the server to see the client", func() bool {
		return server.peers.get(client.localEpochValue()) != nil
	})

	go sendChunks(ctx, pair.pull, func(b []byte) error { return server.SendTo(peer, b) })
	go sendChunks(ctx, pair.push, client.Send)

	want := int64(pair.pull + pair.push)
	last, lastMove := int64(0), time.Now()
	for pulled.Load()+pushed.Load() < want {
		time.Sleep(20 * time.Millisecond)
		if n := pulled.Load() + pushed.Load(); n != last {
			last, lastMove = n, time.Now()
			continue
		}
		if time.Since(lastMove) > stallFor {
			t.Fatalf("stalled: pulled %d of %d, pushed %d of %d, nothing moved for %s",
				pulled.Load(), pair.pull, pushed.Load(), pair.push, stallFor)
		}
	}
}

// sendChunks sends size random bytes through send in 16 KiB messages.
func sendChunks(ctx context.Context, size int, send func([]byte) error) {
	const chunk = 16 << 10
	payload := make([]byte, size)
	_, _ = rand.Read(payload)
	for off := 0; off < size && ctx.Err() == nil; off += chunk {
		if err := send(payload[off:min(off+chunk, size)]); err != nil {
			return
		}
	}
}

// waitFor polls cond until it holds or the timeout passes.
func waitFor(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// kcpSegments builds a KCP packet of the given commands, each with body as
// its data.
func kcpSegments(body []byte, cmds ...byte) []byte {
	var packet []byte
	for _, cmd := range cmds {
		hdr := make([]byte, kcp.IKCP_OVERHEAD)
		hdr[kcpCmdOff] = cmd
		binary.LittleEndian.PutUint32(hdr[kcpLenOff:], uint32(len(body))) //nolint:gosec // test body
		packet = append(append(packet, hdr...), body...)
	}
	return packet
}

func TestPushesWalksTheSegmentsAndStopsAtAHostileLength(t *testing.T) {
	ack, push := byte(kcp.IKCP_CMD_ACK), byte(kcp.IKCP_CMD_PUSH)
	if !pushes(kcpSegments(nil, ack, ack, push)) {
		t.Fatal("pushes() missed a push behind two acknowledgements")
	}
	if pushes(kcpSegments(nil, ack, ack)) || pushes(kcpSegments([]byte("x"), ack)) {
		t.Fatal("pushes() found a push among acknowledgements")
	}
	hostile := kcpSegments(nil, ack, push)
	binary.LittleEndian.PutUint32(hostile[kcpLenOff:], 0xffffffff)
	if pushes(hostile) {
		t.Fatal("pushes() read past a length longer than the packet")
	}
	if !answers(kcpSegments(nil, ack, push)) || !answers(kcpSegments(nil, kcp.IKCP_CMD_WINS)) ||
		answers(kcpSegments(nil, push, ack)) || answers([]byte{1, 2}) {
		t.Fatal("answers() misread the first segment")
	}
}

func TestKCPConnHoldsPushesBackButNotAnswers(t *testing.T) {
	out := make(chan *packetBuffer, 16)
	acks := make(chan *packetBuffer, 16)
	c := newKCPConn(out, 16, testEpochHdr(1))
	c.acks = acks
	write := func(p []byte) { _, _ = c.WriteTo(p, nil) }
	ack, push := byte(kcp.IKCP_CMD_ACK), byte(kcp.IKCP_CMD_PUSH)

	write(kcpSegments(nil, ack))
	write(kcpSegments([]byte("d"), push))
	write(kcpSegments([]byte("d"), ack, push))
	if len(acks) != 1 || len(out) != 2 {
		t.Fatalf("acks=%d out=%d, want the lone acknowledgement apart and the rest with the data", len(acks), len(out))
	}

	c.hold(time.Hour)
	write(kcpSegments([]byte("d"), push)) // held back
	write(kcpSegments([]byte("d"), push)) // held back, and kept as the probe
	write(kcpSegments([]byte("d"), ack, push))
	write(kcpSegments(nil, ack))
	if len(out) != 3 || len(acks) != 2 {
		t.Fatalf("while held: out=%d acks=%d, want only what answers the peer", len(out), len(acks))
	}
	c.probe()
	if len(out) != 4 {
		t.Fatalf("after the first probe: out=%d, want the push held back sent again", len(out))
	}
	c.probe()
	if len(out) != 4 {
		t.Fatalf("out=%d, want at most one probe per interval", len(out))
	}
	c.hold(0)
	write(kcpSegments([]byte("d"), push))
	if len(out) != 5 {
		t.Fatalf("after the hold: out=%d, want the push through", len(out))
	}
}

// TestDataLaneGoingDarkHoldsPushesAndKeepsProbing drives one lane by hand
// over a path that answers nothing. Going dark it has to hold the conn's
// pushes back, halve its frames and its KCP send window, and then keep one
// probe going out per interval on its own cadence: left to KCP, whose
// segment timeouts back off every time they go unanswered, the next push
// can be seconds away and the lane never learns the path is back. Once the
// peer answers, the hold lifts and a loud lane is paced.
func TestDataLaneGoingDarkHoldsPushesAndKeepsProbing(t *testing.T) {
	tr := newStreamTransport(&fakeVideoStream{canSend: true}, nil,
		transport.Config{ChannelID: "dark-lane"}, Options{FPS: 50, BatchSize: 64})
	tr.blackoutAfter = 100 * time.Millisecond
	tr.probeEvery = 20 * time.Millisecond
	out := make(chan *packetBuffer, 512)
	conn := newKCPConn(out, 16, testEpochHdr(1))
	windows := make(chan int, 16)
	lane := &dataLane{
		out: out, acks: make(chan *packetBuffer, 8), name: "dark-lane",
		conn: func() *kcpConn { return conn }, window: func(segments int) { windows <- segments },
	}
	samples := 0
	write := func([]byte) bool { samples++; return true }
	body := make([]byte, kcpMTU-kcp.IKCP_OVERHEAD)
	push := func() { _, _ = conn.WriteTo(kcpSegments(body, kcp.IKCP_CMD_PUSH), nil) }

	for range 400 {
		push()
	}
	for len(out) > 0 {
		lane.flush(tr, write)
	}
	for range 20 { // queued when the spell starts, for sift to drop
		push()
	}
	if lane.frames.limit != 0 || conn.holdEvery.Load() != 0 {
		t.Fatalf("frames %d, hold %d before any spell; want neither", lane.frames.limit, conn.holdEvery.Load())
	}

	time.Sleep(2 * tr.blackoutAfter)
	lane.flush(tr, write)
	if conn.holdEvery.Load() == 0 {
		t.Fatal("going dark left the conn sending pushes")
	}
	if want := tr.fullPackets() / 2; lane.frames.limit != want {
		t.Fatalf("frames %d going dark, want half of a full one (%d)", lane.frames.limit, want)
	}
	select {
	case segments := <-windows:
		if segments >= tr.sendWindow {
			t.Fatalf("KCP send window %d going dark, want it under the transport's %d", segments, tr.sendWindow)
		}
	default:
		t.Fatal("going dark left the KCP send window alone")
	}
	// Nothing is pushed from here on: the probes have to come from what the
	// lane dropped as it went dark, as they would when KCP has backed the
	// timeouts of everything it holds off past the spell.
	probes := 0
	for range 10 {
		time.Sleep(tr.probeEvery)
		before := samples
		lane.flush(tr, write)
		probes += samples - before
	}
	if probes < 5 {
		t.Fatalf("%d probes over ten intervals, want about one each", probes)
	}
	push()
	if len(out) != 0 {
		t.Fatalf("%d packets queued while the lane held pushes back", len(out))
	}

	conn.lastAck.Store(monoNow())
	lane.flush(tr, write)
	if conn.holdEvery.Load() != 0 {
		t.Fatal("the peer answered and the lane went on holding pushes back")
	}
	if lane.pace.rate == 0 {
		t.Fatal("a loud lane came back from a long spell unpaced")
	}
	if len(windows) == 0 {
		t.Fatal("the pace cap left the KCP send window alone")
	}
}

// TestKCPConnCountsWhatComesBackForItsPushes is the frame cap's evidence: a
// conn has to count the acknowledgements it delivers against the pushes they
// answer, or the cap never learns what share of the frames gets through.
func TestKCPConnCountsWhatComesBackForItsPushes(t *testing.T) {
	c := newKCPConn(make(chan *packetBuffer, 4), 8, testEpochHdr(1))
	wire := func(segs []byte) []byte {
		var crc [wireCRCLen]byte
		binary.BigEndian.PutUint32(crc[:], crc32.Checksum(segs, crcTable))
		return append(append([]byte(nil), segs...), crc[:]...)
	}
	c.delivery.count(1000, 1, 0, 0) // a push went out stamped 1000
	c.deliver(wire(kcpSegmentAt(kcp.IKCP_CMD_ACK, 1000, "")))
	c.deliver(wire(kcpSegmentAt(kcp.IKCP_CMD_ACK, 2000, ""))) // a later bucket answered
	if pushes, acks, _ := c.delivery.take(0); pushes != 1 || acks != 1 {
		t.Fatalf("the conn counted %d pushes and %d answers, want one of each", pushes, acks)
	}
}

// TestServerPeerLaneKeepsAQueueForAnswers is the server side of the ack
// queue: what only answers the peer has to go out ahead of the data a peer
// lane is holding, or a peer whose own lane is dark never hears from this
// one and both sides wait each other out.
func TestServerPeerLaneKeepsAQueueForAnswers(t *testing.T) {
	tr := newLossyTestTransport(t, transport.Config{OnPeerData: func(string, []byte) {}}, newLossyRelay(0, 0, 1))
	sess := tr.peerSessionFor(0xabcd1234)
	if sess == nil {
		t.Fatal("no peer session")
	}
	if sess.data.conn.acks == nil {
		t.Fatal("the peer's lane has no queue for what answers the peer")
	}
}

// TestDataLaneNeverAsksForMoreWindowThanTheTransportRunsWith: the publish
// limiter sets the transport's send window, a round trip of the ceiling for a
// paced writer (olcrtc#26), and a lane only ever asks for less than that.
func TestDataLaneNeverAsksForMoreWindowThanTheTransportRunsWith(t *testing.T) {
	paced := newStreamTransport(&limitedVideoStream{fakeVideoStream: &fakeVideoStream{canSend: true}, limit: 1 << 20},
		nil, transport.Config{ChannelID: "paced-lane"}, Options{FPS: 60, BatchSize: 64})
	if paced.sendWindow != kcpSendWindow(true) {
		t.Fatalf("a paced transport runs with %d segments, want %d", paced.sendWindow, kcpSendWindow(true))
	}
	windows := make(chan int, 4)
	lane := &dataLane{
		out: make(chan *packetBuffer, 4), conn: func() *kcpConn { return nil },
		window: func(segments int) { windows <- segments }, name: "paced-lane",
	}
	lane.resize(paced)
	if segments := <-windows; segments != paced.sendWindow {
		t.Fatalf("an uncapped lane asked for %d segments, want the transport's %d", segments, paced.sendWindow)
	}
	lane.frames.limit = minFramePackets
	lane.resize(paced)
	if segments := <-windows; segments >= paced.sendWindow {
		t.Fatalf("a capped lane asked for %d segments, want fewer than the transport's %d",
			segments, paced.sendWindow)
	}
}

func TestCappedLaneDropsStalePushesButNotAnswers(t *testing.T) {
	out := make(chan *packetBuffer, 8)
	l := &dataLane{out: out, pace: pace{rate: minPaceRate}}
	now := 10 * second
	hdr := testEpochHdr(1)
	queue := func(queued int64, cmds ...byte) {
		frame := append(append([]byte(nil), hdr[:]...), kcpSegments([]byte("d"), cmds...)...)
		out <- &packetBuffer{data: frame, queued: queued}
	}
	stale := now - 3*int64(capQueue)
	queue(stale, kcp.IKCP_CMD_PUSH)
	queue(stale, kcp.IKCP_CMD_ACK, kcp.IKCP_CMD_PUSH)
	queue(now, kcp.IKCP_CMD_PUSH)
	if got := l.takeFresh(now); got == nil || got.queued != stale {
		t.Fatal("takeFresh() dropped a stale packet that answers the peer")
	}
	if got := l.takeFresh(now); got == nil || got.queued != now {
		t.Fatal("takeFresh() did not skip the stale push to the fresh one")
	}
	l.pace.rate = 0
	queue(stale, kcp.IKCP_CMD_PUSH)
	if got := l.takeFresh(now); got == nil {
		t.Fatal("takeFresh() dropped a stale push on an uncapped lane")
	}
}

// The single-packet framing (writer.go): what a transport whose engine's
// relay is Telemost writes, and how it paces it. The relay's behaviour it
// answers to was measured live; these tests pin the transport's side.

func singleTransport() (*streamTransport, *[][]byte) {
	var written [][]byte
	p := &streamTransport{
		single:        true,
		frameInterval: time.Second / 60,
		batchSize:     64,
		sendWindow:    kcpSndWnd,
		bindingToken:  7,
		localEpoch:    0x11223344,
	}
	p.sampleWriter = func(b []byte) bool {
		written = append(written, append([]byte(nil), b...))
		return true
	}
	return p, &written
}

func TestSingleSampleIsOneRTPPacket(t *testing.T) {
	// pion packetizes a sample with its 1200-byte MTU less the RTP header,
	// and its VP8 payloader with a picture id, which takes up to four bytes
	// of descriptor once the id passes 127.
	payloader := &codecs.VP8Payloader{EnablePictureID: true}
	sample := make([]byte, singleSampleSize)
	for range 200 { // walk the picture id past 127
		if n := len(payloader.Payload(1200-12, sample)); n != 1 {
			t.Fatalf("a %d-byte sample took %d packets", singleSampleSize, n)
		}
	}
	if n := len(payloader.Payload(1200-12, make([]byte, singleSampleSize+8))); n < 2 {
		t.Fatalf("the budget has no margin: %d bytes still fit one packet", singleSampleSize+8)
	}
	// One KCP segment, its CRC and the batch framing fit the budget.
	if want := epochHdrLen + len(kcpBatchMagic) + batchLenLen + singleKCPMTU + wireCRCLen; want > singleSampleSize {
		t.Fatalf("a full segment makes a %d-byte sample, over %d", want, singleSampleSize)
	}
}

func TestSingleTransportWritesInterframesAndKeyframes(t *testing.T) {
	p, written := singleTransport()
	hdr := p.epochHeader()
	data := append(hdr[:], []byte("payload")...)
	if !p.writeFrameLocked(data) {
		t.Fatal("write failed")
	}
	key := p.epochHeader()
	if !p.writeSampleLocked(key[:]) {
		t.Fatal("keyframe write failed")
	}
	if got := (*written)[0][:vp8PrefixLen]; !bytes.Equal(got, vp8Interframe) {
		t.Fatalf("data went out as % x, want the interframe header", got)
	}
	if got := (*written)[1][:len(vp8Keepalive)]; !bytes.Equal(got, vp8Keepalive) {
		t.Fatalf("keyframe went out as % x, want the keyframe header", got)
	}
	// The receiver reads the epoch header behind either.
	for i, frame := range *written {
		token, src, _, ok := parseEpochHeader(frame)
		if !ok || token != p.bindingToken || src != p.localEpochValue() {
			t.Fatalf("frame %d: epoch header unreadable (ok=%v token=%x src=%x)", i, ok, token, src)
		}
	}
	if !bytes.Equal((*written)[0][epochHdrLen:], []byte("payload")) {
		t.Fatal("the payload changed")
	}
}

func TestOtherRelaysKeepTheKeyframeFraming(t *testing.T) {
	p, written := singleTransport()
	p.single = false
	hdr := p.epochHeader()
	_ = p.writeFrameLocked(append(hdr[:], 1, 2, 3))
	if got := (*written)[0][:len(vp8Keepalive)]; !bytes.Equal(got, vp8Keepalive) {
		t.Fatalf("a multi-packet relay's frame went out as % x", got)
	}
	if p.sampleBudget() != defaultMaxPayloadSize || p.kcpSegmentSize() != kcpMTU || p.writeTick() != p.frameInterval {
		t.Fatal("a multi-packet relay's transport changed its sizes or cadence")
	}
	if d := p.sampleDuration(time.Now()); d != p.frameInterval {
		t.Fatalf("sample duration %v, want the frame interval", d)
	}
}

func TestSingleSampleDurationFollowsTheWallClock(t *testing.T) {
	p, _ := singleTransport()
	start := time.Now()
	p.lastSampleAt = start
	if d := p.sampleDuration(start.Add(3 * time.Millisecond)); d != 3*time.Millisecond {
		t.Fatalf("3 ms apart moved the clock %v", d)
	}
	// Two samples in the same instant still move the 90 kHz clock a tick.
	if d := p.sampleDuration(start.Add(3 * time.Millisecond)); d < time.Second/90000 {
		t.Fatalf("back-to-back samples moved the clock %v, under a tick", d)
	}
	// A sample after a long silence moves it a frame, not the silence.
	if d := p.sampleDuration(start.Add(time.Minute)); d != p.frameInterval {
		t.Fatalf("a sample after a minute moved the clock %v", d)
	}
}

func TestKeyframeSchedule(t *testing.T) {
	var k keyframeSchedule
	t0 := time.Unix(1000, 0)
	if !k.due(t0) {
		t.Fatal("the first tick sends no keyframe")
	}
	if k.due(t0.Add(100 * time.Millisecond)) {
		t.Fatal("two keyframes inside the gap")
	}
	if !k.due(t0.Add(singleKeyframeWarmupEvery)) {
		t.Fatal("no keyframe while the stream warms up")
	}
	last := t0.Add(singleKeyframeWarmupEvery)
	for at := last.Add(singleKeyframeWarmupEvery); at.Before(t0.Add(singleKeyframeWarmup)); at = at.Add(singleKeyframeWarmupEvery) {
		if !k.due(at) {
			t.Fatalf("no warm-up keyframe at %v", at.Sub(t0))
		}
		last = at
	}
	// After the warm-up only the period, or a request, sends one.
	for at := last.Add(time.Second); at.Before(last.Add(singleKeyframePeriod)); at = at.Add(time.Second) {
		if k.due(at) {
			t.Fatalf("an unasked keyframe %v after the last", at.Sub(last))
		}
	}
	at := last.Add(singleKeyframePeriod)
	if !k.due(at) {
		t.Fatal("no keyframe after a whole period")
	}
	k.request()
	if k.due(at.Add(100 * time.Millisecond)) {
		t.Fatal("a request answered inside the gap")
	}
	if !k.due(at.Add(singleKeyframeGap)) {
		t.Fatal("a request went unanswered")
	}
	if k.due(at.Add(singleKeyframeGap + time.Second)) {
		t.Fatal("one request answered twice")
	}
	k.restart()
	if !k.due(at.Add(singleKeyframeGap + 2*time.Second)) {
		t.Fatal("a rebuilt stream does not warm up again")
	}
}

// judged fills a delivery track with pushes at 10 ms intervals for a second,
// acks share of them, and acknowledges one push past them, so the second
// is all there is to judge.
func judged(share float64) *deliveryTrack {
	track := &deliveryTrack{}
	const pushes = 100
	for i := range pushes {
		ts := uint32(i * 10)
		track.count(ts, 1, 0, 1)
		if float64(i) < share*pushes {
			track.count(ts, 0, 1, 0)
		}
	}
	track.count(5000, 1, 0, 1)
	track.count(5000, 0, 1, 0)
	return track
}

func TestSingleRateGrowsHoldsAndCuts(t *testing.T) {
	sec := int64(time.Second)
	cases := []struct {
		name      string
		share     float64
		srtt, min int32
		want      float64
	}{
		{"answered, no queue", 0.95, 300, 300, singleStartRate * singleGrow},
		{"answered, the relay's usual queue", 0.95, 800, 300, singleStartRate * singleGrow},
		{"answered, queue past growth", 0.95, 1050, 300, singleStartRate},
		{"answered, queue past a second", 0.95, 1400, 300, singleStartRate * singleCut},
		{"fair share", 0.75, 300, 300, singleStartRate},
		{"lossy", 0.5, 300, 300, singleStartRate * singleCut},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var r singleRate
			r.start(sec)
			r.minRTT, r.minAt = c.min, sec
			r.judge(judged(c.share), 3*sec, 1, c.srtt)
			if r.rate != c.want {
				t.Fatalf("rate %.0f, want %.0f", r.rate, c.want)
			}
		})
	}
}

func TestSingleRateWaitsForEvidenceAndTime(t *testing.T) {
	sec := int64(time.Second)
	var r singleRate
	r.start(sec)
	if _, changed := r.judge(judged(1), sec+sec/2, 1, 300); changed {
		t.Fatal("the rate changed within a second of the last change")
	}
	r = singleRate{}
	r.start(sec)
	if _, changed := r.judge(&deliveryTrack{}, 5*sec, 1, 300); changed {
		t.Fatal("the rate changed on no evidence")
	}
}

func TestSingleRateFloorCeilingAndDark(t *testing.T) {
	r := singleRate{rate: singleMinRate}
	r.halve(0, 0)
	if r.rate != singleMinRate {
		t.Fatalf("halved below the floor: %.0f", r.rate)
	}
	r = singleRate{rate: singleMaxRate}
	r.changedAt = 0
	r.judge(judged(1), 10*int64(time.Second), 1, 100)
	if r.rate > singleMaxRate {
		t.Fatalf("grew past the ceiling: %.0f", r.rate)
	}
	var fresh singleRate
	fresh.halve(0, 0)
	if fresh.rate != singleStartRate/2 {
		t.Fatalf("a lane dark before it wrote halves from the start rate, got %.0f", fresh.rate)
	}
}

func TestSingleRateWindow(t *testing.T) {
	// The window is sized from the floor (minRTT), not the current round trip.
	r := singleRate{rate: 1 << 20, minRTT: 500}
	want := int(float64(1<<20)*(0.5+singleWindowSlack.Seconds())) / singleKCPMTU
	if got := r.window(4096, singleKCPMTU); got != want {
		t.Fatalf("window %d, want %d", got, want)
	}
	if got := r.window(64, singleKCPMTU); got != 64 {
		t.Fatalf("window %d over the ceiling of 64", got)
	}
	// Before a floor is known, the assumed base keeps the window bounded.
	r = singleRate{rate: 1 << 20}
	wantBase := int(float64(1<<20)*(singleWindowBase.Seconds()+singleWindowSlack.Seconds())) / singleKCPMTU
	if got := r.window(4096, singleKCPMTU); got != wantBase {
		t.Fatalf("window %d with no floor yet, want %d", got, wantBase)
	}
	// A low rate never drops below the floor window.
	r = singleRate{rate: singleMinRate, minRTT: 50}
	if got := r.window(4096, singleKCPMTU); got != singleMinWindow {
		t.Fatalf("window %d, want the floor %d", got, singleMinWindow)
	}
}

func TestSingleRateCutsOnAbsoluteQueue(t *testing.T) {
	// Even if the floor was itself measured high, a plainly high round trip
	// is a standing queue and cuts the rate.
	sec := int64(time.Second)
	r := singleRate{rate: 1 << 20, minRTT: 1400, minAt: sec, changedAt: 0}
	before := r.rate
	r.judge(judged(1.0), 3*sec, 1, 1600) // 1600 ms > singleAbsQueue
	if r.rate >= before {
		t.Fatalf("rate %.0f did not cut on a %d ms round trip", r.rate, 1600)
	}
}

func TestSingleRateCredit(t *testing.T) {
	sec := int64(time.Second)
	var r singleRate
	r.start(0)
	if got := r.allow(0); got != 0 {
		t.Fatalf("credit %d before any time passed", got)
	}
	// Banked credit stops at the burst: a span at the rate, or two samples,
	// whichever is larger.
	burst := int(max(float64(singleStartRate)*singleBurst.Seconds(), 2*singleSampleSize))
	if got := r.allow(10 * sec); got != burst {
		t.Fatalf("credit %d after ten idle seconds, want the burst %d", got, burst)
	}
	r.wrote(1000)
	if got := r.allow(10 * sec); got != burst-1000 {
		t.Fatalf("credit %d after writing 1000 bytes, want %d", got, burst-1000)
	}
}

func TestSingleLaneWritesOnePacketSamplesAtItsRate(t *testing.T) {
	p, _ := singleTransport()
	out := make(chan *packetBuffer, 64)
	var pools [4]sync.Pool
	for range 40 {
		packet := acquirePacketBuffer(&pools, epochHdrLen+singleKCPMTU+wireCRCLen)
		hdr := p.epochHeader()
		copy(packet.data, hdr[:])
		packet.queued = monoNow()
		out <- packet
	}
	lane := dataLane{out: out, name: "test"}
	var sizes []int
	write := func(sample []byte) bool {
		sizes = append(sizes, len(sample))
		return true
	}
	now := monoNow()
	if lane.sendSingles(p, now, write) {
		t.Fatal("wrote before the rate had given any credit")
	}
	// A burst of credit writes some single-packet samples, each within the
	// one-packet budget.
	lane.rate.rate = 300 << 10
	if !lane.sendSingles(p, now+int64(10*time.Millisecond), write) {
		t.Fatal("wrote nothing with 10 ms of credit")
	}
	if len(sizes) < 1 {
		t.Fatal("wrote nothing with credit to spare")
	}
	for _, n := range sizes {
		if n > singleSampleSize {
			t.Fatalf("a %d-byte sample, over the one-packet budget", n)
		}
	}
	// However fast the lane may write, a tick writes at most its share.
	// Keep the clock within the stale window so the queued pushes still count.
	sizes = nil
	lane.rate.rate = singleMaxRate
	lane.sendSingles(p, now+int64(30*time.Millisecond), write)
	if len(sizes) != singleSamplesPerTick {
		t.Fatalf("wrote %d samples in one tick, want %d", len(sizes), singleSamplesPerTick)
	}
}

func TestSingleLaneDropsStalePushesButNotAnswers(t *testing.T) {
	now := monoNow()
	var pools [4]sync.Pool
	push := acquirePacketBuffer(&pools, epochHdrLen+kcpHeaderBytes+wireCRCLen)
	push.data[epochHdrLen+kcpCmdOff] = 81 // IKCP_CMD_PUSH
	push.queued = now - int64(2*singleStale)
	ack := acquirePacketBuffer(&pools, epochHdrLen+kcpHeaderBytes+wireCRCLen)
	ack.data[epochHdrLen+kcpCmdOff] = 82 // IKCP_CMD_ACK
	ack.queued = now - int64(2*singleStale)
	fresh := acquirePacketBuffer(&pools, epochHdrLen+kcpHeaderBytes+wireCRCLen)
	fresh.data[epochHdrLen+kcpCmdOff] = 81
	fresh.queued = now
	out := make(chan *packetBuffer, 4)
	out <- push
	out <- ack
	out <- fresh
	lane := dataLane{out: out}
	if got := lane.takeFreshSingle(now); got != ack {
		t.Fatal("a stale push was not dropped, or a stale acknowledgement was")
	}
	if got := lane.takeFreshSingle(now); got != fresh {
		t.Fatal("a fresh push was dropped")
	}
}

// kcpHeaderBytes is kcp-go's segment header.
const kcpHeaderBytes = 24

func TestWriterPaceSlowsWhenIdleAndSpeedsUpWhenBusy(t *testing.T) {
	p, _ := singleTransport()
	ticker := time.NewTicker(singleTick)
	defer ticker.Stop()
	pace := writerPace{ticker: ticker, fast: true}
	for range singleIdleTicks - 1 {
		pace.note(p, false)
	}
	if !pace.fast {
		t.Fatal("slowed down before the idle ticks ran out")
	}
	pace.note(p, false)
	if pace.fast {
		t.Fatal("still fast after the idle ticks")
	}
	pace.note(p, true)
	if !pace.fast || pace.idle != 0 {
		t.Fatal("did not speed up on data")
	}
	p.single = false
	pace.fast = false
	pace.note(p, true)
	if pace.fast {
		t.Fatal("a multi-packet transport's writer changed pace")
	}
}
