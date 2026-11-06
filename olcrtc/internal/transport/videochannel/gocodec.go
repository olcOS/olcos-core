// Changed by olcOS (https://github.com/olcOS/olcos-core): see docs/olcrtc.md there.

package videochannel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"codeberg.org/rape4me/kc/vp8"
)

// goEncoder is a pure Go VP8 encoder.
type goEncoder struct {
	enc       *vp8.Encoder
	width     int
	height    int
	frameSize int
	closed    atomic.Bool
	mu        sync.Mutex
}

func newGoEncoder(width, height, _ int) *goEncoder {
	enc := vp8.NewEncoder(width, height, 63)
	enc.SetKeyInterval(1)
	return &goEncoder{
		enc:       enc,
		width:     width,
		height:    height,
		frameSize: width * height,
	}
}

func (e *goEncoder) EncodeFrame(frame []byte) ([]byte, error) {
	if e.closed.Load() {
		return nil, ErrTransportClosed
	}
	if len(frame) != e.frameSize {
		return nil, fmt.Errorf("%w: got %d expected %d", ErrUnexpectedFrameSize, len(frame), e.frameSize)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	encoded, err := e.enc.Encode(frame)
	if err != nil {
		return nil, fmt.Errorf("vp8 encode: %w", err)
	}
	return encoded, nil
}

// Close stops the encoder. Further EncodeFrame calls fail.
func (e *goEncoder) Close() {
	e.closed.Store(true)
}

// goDecoder is a pure Go VP8 decoder.
// decoderQueueDepth bounds how many decoded frames wait for the extractor.
// Each one is a full grayscale plane the vp8 decoder allocates fresh - 2 MB at
// 1080p - and one decoder exists per remote track, so the queue depth is the
// dominant memory cost of this transport. It is deep enough to absorb an
// extraction that runs long without stalling the reader, and no deeper.
const decoderQueueDepth = 8

type goDecoder struct {
	dec       *vp8.Decoder
	maxPixels int
	frames    chan []byte
	closed    atomic.Bool
	closeOnce sync.Once
	closeCh   chan struct{}
}

// newGoDecoder decodes frames of at most width x height pixels. Both ends
// use one video size, so a larger keyframe comes from someone else in the
// room. The decoder allocates its planes before it reads a macroblock, about
// 400 MB for the 16383x16383 an 18-byte keyframe can declare, so such a
// keyframe is dropped.
//
// ai-generated: the size limit, here, in vp8KeyframeSize and in PushSample.
func newGoDecoder(width, height int) *goDecoder {
	return &goDecoder{
		dec:       vp8.NewDecoder(),
		maxPixels: width * height,
		frames:    make(chan []byte, decoderQueueDepth),
		closeCh:   make(chan struct{}),
	}
}

// vp8KeyframeSize returns the size a VP8 keyframe declares (RFC 6386, 9.1).
// ok is false for an interframe or a sample too short to be a keyframe.
func vp8KeyframeSize(sample []byte) (width, height int, ok bool) {
	if len(sample) < 10 || sample[0]&0x01 != 0 ||
		sample[3] != 0x9d || sample[4] != 0x01 || sample[5] != 0x2a {
		return 0, 0, false
	}
	width = int(binary.LittleEndian.Uint16(sample[6:8]) & 0x3fff)
	height = int(binary.LittleEndian.Uint16(sample[8:10]) & 0x3fff)
	return width, height, true
}

func (d *goDecoder) PushSample(sample []byte) error {
	if d.closed.Load() {
		return ErrTransportClosed
	}
	if w, h, ok := vp8KeyframeSize(sample); ok && w*h > d.maxPixels {
		return nil
	}
	frame, err := d.dec.Decode(sample)
	if err != nil {
		if errors.Is(err, vp8.ErrNoReference) {
			return nil
		}
		return nil
	}
	gray := frame.Grayscale()
	// Blocking here is deliberate. Every frame carries a fragment the peer is
	// waiting to have acknowledged, so dropping one costs a full retransmit
	// round; back-pressure onto the decode goroutine and its queue of encoded
	// frames is the cheaper of the two. It must not reach the RTP reader,
	// which stamps transport-cc arrival times (see readDecoderInput).
	//
	// ai-generated: the last sentence and the decode goroutine.
	select {
	case d.frames <- gray:
	case <-d.closeCh:
		return ErrTransportClosed
	}
	return nil
}

func (d *goDecoder) PopFrame() ([]byte, error) {
	select {
	case frame, ok := <-d.frames:
		if !ok {
			return nil, ErrTransportClosed
		}
		return frame, nil
	case <-d.closeCh:
		return nil, ErrTransportClosed
	}
}

// Close stops the decoder and unblocks PopFrame.
func (d *goDecoder) Close() {
	d.closeOnce.Do(func() {
		d.closed.Store(true)
		close(d.closeCh)
	})
}
