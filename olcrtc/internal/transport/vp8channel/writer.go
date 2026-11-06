package vp8channel

import (
	"encoding/binary"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v4/pkg/media"
)

// writerState holds the per-loop bookkeeping for writerLoop, extracted so the
// loop body stays within cognitive-complexity limits.
type writerState struct {
	p                   *streamTransport
	keepaliveEvery      int
	idleTicks           int
	forceKeepaliveEvery int
	ticksSinceKeepalive int
	// keyframeGap is the fewest ticks between two keyframes a relay asked
	// for: one that takes none of them asks without end.
	keyframeGap int
	// pendingControl holds a control frame that failed WriteSample and must be
	// retried on the next tick before consuming more frames.
	pendingControl *packetBuffer
	// data carries the single-peer data queue (ai-generated: issue #12).
	data dataLane
	// pendingDatagram is a lossy sample that failed WriteSample, or the
	// first datagram of the next route split off by batchDatagramSampleFrom.
	pendingDatagram []byte
}

// newWriterState is writerLoop's bookkeeping for p.
//
// ai-generated: the constructor, with the data lane.
func newWriterState(p *streamTransport) *writerState {
	return &writerState{
		p:                   p,
		keepaliveEvery:      max(int(keepaliveIdlePeriod/p.frameInterval), 1),
		forceKeepaliveEvery: max(int(forceKeepalivePeriod/p.frameInterval), 1),
		keyframeGap:         max(int(keyframeRequestGap/p.frameInterval), 1),
		data: dataLane{
			out: p.data.out, acks: p.data.acks, conn: p.dataConn, window: p.dataWindow, srtt: p.dataSRTT,
			name: "data",
		},
	}
}

func (w *writerState) releasePending() {
	if w.pendingControl != nil {
		w.pendingControl.release()
	}
	w.data.release()
}

func (w *writerState) writeSample(data []byte) bool {
	return w.p.writeFrameLocked(data)
}

// writeSampleLocked serializes every WriteSample call on the shared video
// track behind a single mutex. pion's TrackLocalStaticSample.WriteSample is
// NOT safe for concurrent use: it packetizes under its own lock but then
// releases that lock before pushing the resulting RTP packets onto the wire.
// Two concurrent callers therefore each reserve a contiguous block of RTP
// sequence numbers and then race to emit their packets, interleaving them on
// the wire. The receiver's VP8 reassembler enforces strict sequence
// contiguity, so any interleaved frame is discarded - which is exactly the
// server->client bulk-data stall in issue #95 (the server runs a per-peer
// peerWriterPump for data plus writerLoop for control/keepalive, both hitting
// this track at once). Funneling all writes through this mutex makes each
// sample's packetize+send atomic and keeps sequence numbers monotonic. Pion's
// VP8 payloader copies sample.Data into RTP payloads during Packetize, before
// WriteSample returns, so the writer can release its packet buffer afterward.
func (p *streamTransport) writeSampleLocked(data []byte) bool {
	return p.writeLocked(data, false)
}

// writeKeyframeLocked writes a frame the relay has to count as a keyframe:
// the periodic one that keeps it forwarding, and the answer to its request.
// On the transport's own VP8 every frame is one already.
func (p *streamTransport) writeKeyframeLocked(data []byte) bool {
	return p.writeLocked(data, true)
}

func (p *streamTransport) writeLocked(data []byte, keyframe bool) bool {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	// A carrier that is not the transport's own VP8 re-heads the frame for
	// its track. The payloader copies the sample before WriteSample returns,
	// so one buffer serves every write.
	if p.carrier != nil && p.carrier.dress != nil {
		p.dressBuf = p.carrier.dress(p.dressBuf, data, keyframe)
		data = p.dressBuf
	}
	// ai-generated: the charge and the written result (olcrtc#26). Every
	// sample this transport publishes passes here, so this is where the rate
	// the relay sees is counted - control frames and keepalives included,
	// which are charged but never held back.
	var written bool
	if p.sampleWriter != nil {
		written = p.sampleWriter(data)
	} else {
		written = p.track.WriteSample(media.Sample{
			Data:     data,
			Duration: p.sampleDuration(time.Now()),
		}) == nil
	}
	if written {
		p.limiter.Charge(len(data))
	}
	return written
}

// readyToSend reports whether the bucket has room for a bulk frame of this
// size. The control plane never asks. ai-generated: readyToSend (olcrtc#26).
func (p *streamTransport) readyToSend(frame []byte) bool {
	return p.limiter.Ready(len(frame))
}

// forceKeepalive emits a clean, fully-decodable VP8 keepalive keyframe at a
// steady cadence even while bulk data is flowing. During a sustained bulk
// transfer every emitted "frame" is the epoch header plus opaque KCP bytes,
// which never forms a decodable VP8 keyframe. The SFU asks for a keyframe (PLI)
// and, receiving none within its decode-timeout (~40 s), stops forwarding the
// track to subscribers. The periodic bare keyframe keeps the SFU's decoder
// satisfied.
//
// A relay that asks for one (requestKeyframe) is answered on the next tick
// rather than at the next beat, keyframeGap ticks after the last at the
// soonest: until it has a keyframe it forwards nothing of the track.
//
// A single-packet transport writes keyframes on its own schedule instead
// (keyframeSchedule): every one costs the stream what the relay holds of it.
func (w *writerState) forceKeepalive() {
	if w.p.single {
		if w.p.keyframes.due(time.Now()) {
			hdr := w.p.epochHeader()
			_ = w.p.writeSampleLocked(hdr[:])
		}
		return
	}
	w.ticksSinceKeepalive++
	due := w.ticksSinceKeepalive >= w.forceKeepaliveEvery
	if !due && w.ticksSinceKeepalive >= w.keyframeGap && w.p.keyframeWanted.Load() {
		due = true
	}
	if !due {
		return
	}
	w.p.keyframeWanted.Store(false)
	w.ticksSinceKeepalive = 0
	hdr := w.p.epochHeader()
	_ = w.p.writeKeyframeLocked(hdr[:])
}

// requestKeyframe is the relay asking for a keyframe. Only a carrier whose
// relay asks this way answers; on the others the two-second beat is all there
// is, as before.
func (p *streamTransport) requestKeyframe() {
	if p.carrier.answersKeyframeRequests() {
		p.keyframeWanted.Store(true)
	}
}

// drainControl flushes all queued control frames. Returns false when a frame
// failed to send (stored in pendingControl for retry next tick).
func (w *writerState) drainControl() bool {
	if w.pendingControl != nil {
		if !w.writeSample(w.pendingControl.data) {
			return false
		}
		w.pendingControl.release()
		w.pendingControl = nil
	}
	for {
		select {
		case frame := <-w.p.control.out:
			w.idleTicks = 0
			if !w.writeSample(frame.data) {
				w.pendingControl = frame
				return false
			}
			frame.release()
		default:
			return true
		}
	}
}

// drainDatagram sends queued lossy datagrams after control frames and before
// reliable KCP data. Returns false when a sample must be retried next tick.
func (w *writerState) drainDatagram() bool {
	if w.pendingDatagram != nil {
		if !w.writeSample(w.pendingDatagram) {
			return false
		}
		w.pendingDatagram = nil
	}
	for {
		select {
		case frame := <-w.p.datagram:
			// ai-generated: the rate check (olcrtc#26). The lossy lane rides
			// the same track as the bulk data and counts against the same
			// ceiling, so it waits for the bucket like the bulk data does.
			if !w.p.readyToSend(frame) {
				w.pendingDatagram = frame
				return false
			}
			sample := w.batchDatagramSampleFrom(w.p.datagram, frame)
			w.idleTicks = 0
			if !w.writeSample(sample) {
				w.pendingDatagram = sample
				return false
			}
		default:
			return true
		}
	}
}

// batchDatagramSampleFrom packs first and the datagrams queued behind it that
// share its epoch header into one OLUB sample, up to batchSize packets and
// defaultMaxPayloadSize bytes. A datagram bound elsewhere, or one that no
// longer fits, waits in pendingDatagram for the next sample.
func (w *writerState) batchDatagramSampleFrom(src <-chan []byte, first []byte) []byte {
	if len(first) <= epochHdrLen || w.p.batchSize <= 1 {
		return first
	}
	sample := make([]byte, 0, w.p.sampleBudget())
	sample = append(sample, first[:epochHdrLen]...)
	sample = append(sample, datagramBatchMagic[:]...)
	sample = appendBatchPacket(sample, first[epochHdrLen:])
	for packets := 1; packets < w.p.batchSize; packets++ {
		select {
		case frame := <-src:
			if !sameEpochHeader(first, frame) {
				w.pendingDatagram = frame
				return sample
			}
			payload := frame[epochHdrLen:]
			if len(sample)+2+len(payload) > w.p.sampleBudget() {
				w.pendingDatagram = frame
				return sample
			}
			sample = appendBatchPacket(sample, payload)
		default:
			if packets == 1 {
				return first
			}
			return sample
		}
	}
	return sample
}

// drainData sends one batched data frame, or a keepalive when idle.
//
// ai-generated: the data lane in place of the inline batching.
func (w *writerState) drainData() {
	if w.data.flush(w.p, w.writeSample) {
		w.idleTicks = 0
		return
	}
	// ai-generated: the held check (olcrtc#26). A tick that had data and
	// waited for the publisher's bucket is not an idle tick, so it does not
	// turn into a keepalive on top of what is already queued.
	if w.data.heldBack {
		return
	}
	w.idleTicks++
	if w.idleTicks >= w.keepaliveEvery {
		w.idleTicks = 0
		hdr := w.p.epochHeader()
		_ = w.writeSample(hdr[:])
	}
}

// dataConn is the single-peer data plane's KCP conn, nil while the plane is
// down or mid-restart.
//
// ai-generated: the whole function.
func (p *streamTransport) dataConn() *kcpConn {
	if rt := p.data.get(); rt != nil {
		return rt.conn
	}
	return nil
}

// dataSRTT is the single-peer data plane's smoothed KCP round trip in ms,
// zero while the plane is down.
func (p *streamTransport) dataSRTT() int32 {
	if rt := p.data.get(); rt != nil {
		return rt.sess.GetSRTT()
	}
	return 0
}

// dataWindow sets the single-peer data plane's KCP send window.
//
// ai-generated: the whole function.
func (p *streamTransport) dataWindow(segments int) {
	if rt := p.data.get(); rt != nil {
		rt.sess.SetWindowSize(segments, 0)
	}
}

func (p *streamTransport) writerLoop() {
	defer close(p.writerDone)

	ticker := time.NewTicker(p.writeTick())
	defer ticker.Stop()
	pace := writerPace{ticker: ticker, fast: true}

	w := newWriterState(p)
	defer w.releasePending()

	for {
		select {
		case <-p.closeCh:
			return
		case <-ticker.C:
			// Priority 0: keep a decodable keyframe flowing for the SFU.
			w.forceKeepalive()
			// Priority 1+2: drain all control frames before any bulk data.
			if !w.drainControl() {
				continue // a control frame is still failing; retry next tick
			}
			// Priority 2: lossy datagrams go before reliable bulk data.
			if !w.drainDatagram() {
				continue
			}
			// Priority 3: drain a batched data frame (or send keepalive).
			w.drainData()
			pace.note(p, w.data.busy)
		}
	}
}

// peerWriterPump drains a peer's outbound KCP queue and writes frames to the
// shared video track on the same frame ticker writerLoop uses for the
// client->server path, batching queued frames into one VP8 sample per tick.
// Draining on the ticker (rather than emitting each frame the instant it is
// queued) keeps the per-peer writes interleaved with the keyframe injection
// below and lets batchSampleFrom coalesce segments into full samples. The
// queue goes out through a data lane, which holds it back while the peer
// acknowledges nothing (lane.go). Stops when the peer session is released or
// the transport shuts down.
//
// ai-generated: the lane in place of the pump's own batching.
func (p *streamTransport) peerWriterPump(lane dataLane, done <-chan struct{}) {
	ticker := time.NewTicker(p.writeTick())
	defer ticker.Stop()
	pace := writerPace{ticker: ticker, fast: true}

	// Inject a decodable VP8 keyframe on the same cadence writerLoop uses for
	// the client->server path. The server's per-peer bulk path previously
	// emitted only opaque KCP data frames, which never form a decodable VP8
	// keyframe: the SFU's decoder times out (~40s without a keyframe) and stops
	// forwarding the server's track to the subscriber. The client side was
	// kept alive by writerLoop.forceKeepalive; the server side had no
	// equivalent, so the server->client direction collapsed first while the
	// client->server direction kept flowing (issue #95).
	keyframeEvery := max(int(forceKeepalivePeriod/p.frameInterval), 1)
	ticksSinceKeyframe := 0
	defer lane.release()

	for {
		select {
		case <-p.closeCh:
			return
		case <-done:
			return
		case <-ticker.C:
			// A single-packet transport's keyframes all come from
			// writerLoop, which runs on the server as well (keyframeSchedule).
			ticksSinceKeyframe++
			if !p.single && ticksSinceKeyframe >= keyframeEvery {
				ticksSinceKeyframe = 0
				hdr := p.epochHeader()
				_ = p.writeSampleLocked(hdr[:])
			}
			lane.flush(p, p.writeFrameLocked)
			pace.note(p, lane.busy)
		}
	}
}

func (p *streamTransport) canBatch(frame []byte) bool {
	return len(frame) > epochHdrLen && p.batchSize > 1
}

// batchSampleFrom coalesces up to batchSize KCP frames drained from src into a
// single VP8 sample, bounded by defaultMaxPayloadSize. The shared writerLoop
// drains the single-peer outbound queue; per-peer pumps drain their own queue
// through the same batching so the server->client path is built identically to
// the client.
func (p *streamTransport) batchSampleFrom(
	src <-chan *packetBuffer,
	first *packetBuffer,
	dst []byte,
) ([]byte, *packetBuffer) {
	return p.batchSampleUpTo(src, first, dst, p.batchSize)
}

// batchSampleUpTo is batchSampleFrom with at most limit packets in the
// sample: a data lane under a cap asks for fewer.
//
// ai-generated: the limit, split out of batchSampleFrom (issue #12).
func (p *streamTransport) batchSampleUpTo(
	src <-chan *packetBuffer,
	first *packetBuffer,
	dst []byte,
	limit int,
) ([]byte, *packetBuffer) {
	if !p.canBatch(first.data) {
		return first.data, nil
	}

	sample := prepareBatchBuffer(dst, src, first.data, limit, p.sampleBudget())
	sample = append(sample, first.data[:epochHdrLen]...)
	sample = append(sample, kcpBatchMagic[:]...)
	sample = appendBatchPacket(sample, first.data[epochHdrLen:])
	first.release()

	for packets := 1; packets < limit; packets++ {
		select {
		case frame, ok := <-src:
			if !ok {
				return sample, nil
			}
			if len(frame.data) <= epochHdrLen {
				frame.release()
				continue
			}
			payload := frame.data[epochHdrLen:]
			if len(sample)+2+len(payload) > p.sampleBudget() {
				return sample, frame
			}
			sample = appendBatchPacket(sample, payload)
			frame.release()
		default:
			return sample, nil
		}
	}
	return sample, nil
}

func prepareBatchBuffer(dst []byte, src <-chan *packetBuffer, first []byte, limit, budget int) []byte {
	packetSize := len(first) - epochHdrLen
	packetCount := max(min(limit, len(src)+1), 1)
	want := epochHdrLen + len(kcpBatchMagic) + packetCount*(batchLenLen+packetSize)
	if want > budget {
		want = budget
	}
	if cap(dst) < want {
		return make([]byte, 0, want)
	}
	return dst[:0]
}

// batchLenLen is the length prefix appendBatchPacket puts before a packet.
const batchLenLen = 2

func appendBatchPacket(dst, packet []byte) []byte {
	if len(packet) > 0xffff {
		return dst
	}
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(packet))) //nolint:gosec // bounded above
	dst = append(dst, lenBuf[:]...)
	return append(dst, packet...)
}

// Single-packet frames, for a relay that forwards nothing else reliably.
//
// Telemost's media server changed how it forwards VP8 in early October 2026.
// Measured against a live room from a datacenter on 2026-10-10:
//
//   - a keyframe of 5 KB or more is dropped outright, every packet of it,
//     and one of 2-3 KB loses most of its packets;
//   - a frame spread over several RTP packets mostly arrives incomplete: of
//     interframes of 3 KB at 120 a second, 18% got through whole;
//   - every keyframe drops what the server still holds of the stream, about
//     a third of a second of it: with a keyframe every second, 1000-byte
//     interframes got through 66% of the time, at any rate, and with one
//     every ten seconds 97%, even at 30 Mbit/s.
//
// This transport used to send every data frame as a keyframe of up to 60 KB
// and a bare keyframe on every idle tick, so through Telemost nothing but
// the smallest frames arrived, and a download stalled at 0 B/s. An engine
// whose relay behaves like that says so (engine.SinglePacketRelay), and the
// transport then publishes every frame as one RTP packet (singleSampleSize),
// data and idle keepalives as interframes, a keyframe only to start the
// stream, when the relay asks for one and every singleKeyframePeriod, and
// paces what it writes at what comes back acknowledged (singleRate). The
// same datacenter pair then moved 10 MB down at 3.8 Mbit/s and 2 MB up at
// 2 Mbit/s.
//
// Frames stay what the receiver has always read: it ignores the first 20
// bytes, where the VP8 header sits, so a peer on the previous framing reads
// these frames, and these peers read its.

const (
	// singleSampleSize is the largest VP8 sample pion sends as one RTP
	// packet: its 1200-byte MTU less the 12-byte RTP header and the 4-byte
	// VP8 descriptor with a picture id, with 4 bytes to spare. Telemost
	// forwarded frames of 1180 bytes as reliably as frames of 1000; at 1190
	// they took two packets and less than half arrived.
	singleSampleSize = 1180
	// singleKCPMTU is the KCP segment size that keeps one segment, its CRC
	// and the batch framing inside singleSampleSize.
	singleKCPMTU = 1100
	// singleTick is how often the writers run while data flows: at the
	// rates this relay carries, a frame every 2 ms per sample is what keeps
	// the stream smooth instead of bursting a tick's worth at once.
	singleTick = 2 * time.Millisecond
	// singleIdleTicks is how many fast ticks with nothing to write the
	// writers wait before they fall back to the frame interval, so an idle
	// tunnel does not wake the process 500 times a second.
	singleIdleTicks = 50
	// singleSamplesPerTick caps the samples a data lane writes in one tick.
	singleSamplesPerTick = 8
	// singleKeyframePeriod is how often a keyframe goes out on its own. The
	// relay stops forwarding a stream that has gone too long without one
	// (about 40 s), and each keyframe costs the third of a second the relay
	// holds, so one every 20 s.
	singleKeyframePeriod = 20 * time.Second
	// singleKeyframeWarmup is how long a stream sends a keyframe every
	// singleKeyframeWarmupEvery after it starts: the relay forwards nothing
	// to a subscriber until it has a keyframe, and a lost first one would
	// otherwise cost a whole period.
	singleKeyframeWarmup      = 2 * time.Second
	singleKeyframeWarmupEvery = 500 * time.Millisecond
	// singleKeyframeGap is the least time between two keyframes: requests
	// come in bursts when several subscribers join.
	singleKeyframeGap = 300 * time.Millisecond
	// singleStale is how long a push may wait in a lane's queue. Past that
	// KCP has most likely sent it again, and a queue that keeps it only
	// delays the rest: the round trip KCP measures grows with the queue,
	// its timeouts with the round trip, and the lane stalls on them.
	singleStale = 250 * time.Millisecond
	// vp8PrefixLen is how many bytes at the head of a frame the VP8 header
	// takes; the epoch header starts after it (wire.go).
	vp8PrefixLen = tokenOff
)

// vp8Interframe is a minimal VP8 interframe, padded to vp8PrefixLen. It
// heads every frame a single-packet transport writes except its keyframes.
var vp8Interframe = []byte{ //nolint:gochecknoglobals // wire constant
	0xb1, 0x01, 0x00, 0x08, 0x11, 0x18, 0x00, 0x18,
	0x00, 0x18, 0x58, 0x2f, 0xf4, 0x00, 0x08, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

// asInterframe rewrites the VP8 header of a sample about to be written into
// an interframe. The sample is the writer's own (a pooled packet, a batch
// buffer or a header copy), so it is rewritten in place.
func asInterframe(sample []byte) {
	if len(sample) >= vp8PrefixLen {
		copy(sample[:vp8PrefixLen], vp8Interframe)
	}
}

// writeFrameLocked is writeSampleLocked for every frame but a keyframe: on a
// single-packet transport it heads the frame with the interframe header
// first. Keyframes go to writeSampleLocked as they are.
func (p *streamTransport) writeFrameLocked(data []byte) bool {
	if p.single {
		asInterframe(data)
	}
	return p.writeSampleLocked(data)
}

// sampleBudget is the most bytes the transport puts in one sample.
func (p *streamTransport) sampleBudget() int {
	if p.single {
		return singleSampleSize
	}
	return defaultMaxPayloadSize
}

// kcpSegmentSize is the KCP MTU of this transport's sessions.
func (p *streamTransport) kcpSegmentSize() int {
	if p.single {
		return singleKCPMTU
	}
	return kcpMTU
}

// sampleDuration is how far the RTP clock moves after a sample. A
// single-packet transport writes several samples a tick, so it moves the
// clock by the time since the previous sample, keeping it on the wall clock;
// otherwise a sample is a frame interval. The caller holds writeMu.
func (p *streamTransport) sampleDuration(now time.Time) time.Duration {
	if !p.single {
		return p.frameInterval
	}
	d := now.Sub(p.lastSampleAt)
	p.lastSampleAt = now
	switch {
	case d < time.Second/90000+time.Microsecond: // one tick of the 90 kHz clock
		d = time.Second/90000 + time.Microsecond
	case d > time.Second:
		d = p.frameInterval
	}
	return d
}

// writeTick is how often the writers run: a single-packet transport runs
// fast while data flows (see writerPace).
func (p *streamTransport) writeTick() time.Duration {
	if p.single {
		return singleTick
	}
	return p.frameInterval
}

// writerPace switches a single-packet writer's ticker between singleTick
// while it writes and the frame interval once it has been idle for
// singleIdleTicks ticks.
type writerPace struct {
	ticker *time.Ticker
	fast   bool
	idle   int
}

// note records whether this tick wrote anything and retunes the ticker.
func (w *writerPace) note(p *streamTransport, busy bool) {
	if !p.single {
		return
	}
	switch {
	case busy:
		w.idle = 0
		if !w.fast {
			w.fast = true
			w.ticker.Reset(singleTick)
		}
	case w.fast:
		w.idle++
		if w.idle >= singleIdleTicks {
			w.fast = false
			w.ticker.Reset(p.frameInterval)
		}
	}
}

// keyframeSchedule decides when a single-packet transport writes a
// keyframe: every singleKeyframeWarmupEvery while the stream warms up, at
// a request from the relay, and every singleKeyframePeriod, never two
// within singleKeyframeGap.
type keyframeSchedule struct {
	requested atomic.Bool

	mu    sync.Mutex
	start time.Time
	last  time.Time
}

// request marks a keyframe as wanted; the relay's keyframe requests call it.
func (k *keyframeSchedule) request() { k.requested.Store(true) }

// due reports whether a keyframe goes out now and, when it does, counts it
// as sent.
func (k *keyframeSchedule) due(now time.Time) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.start.IsZero() {
		k.start = now
	}
	since := now.Sub(k.last)
	if !k.last.IsZero() && since < singleKeyframeGap {
		return false
	}
	switch {
	case k.last.IsZero(),
		now.Sub(k.start) < singleKeyframeWarmup && since >= singleKeyframeWarmupEvery,
		since >= singleKeyframePeriod,
		k.requested.Load():
	default:
		return false
	}
	k.requested.Store(false)
	k.last = now
	return true
}

// restart warms the stream up again, as a provider rebuild starts a new one.
func (k *keyframeSchedule) restart() {
	k.mu.Lock()
	k.start, k.last = time.Time{}, time.Time{}
	k.mu.Unlock()
}
