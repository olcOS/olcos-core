package goolom

import (
	"testing"
	"time"

	"github.com/pion/rtcp"

	"github.com/openlibrecommunity/olcrtc/internal/engine"
)

func TestSessionReconnectAndEndedHelpers(t *testing.T) {
	s := &Session{
		closeCh:        make(chan struct{}),
		keepAliveCh:    make(chan struct{}),
		sessionCloseCh: make(chan struct{}),
		telemetryCh:    make(chan struct{}, 1),
	}

	keepAliveCh, sessionCloseCh := s.resetSession()
	if keepAliveCh == nil || sessionCloseCh == nil || keepAliveCh != s.keepAliveCh || sessionCloseCh != s.sessionCloseCh {
		t.Fatal("resetSession() did not replace session channels")
	}

	s.subscriberReady.Store(true)
	s.publisherReady.Store(true)
	s.resetMediaState()
	if s.subscriberReady.Load() || s.publisherReady.Load() || s.subscriberConnCh() == nil {
		t.Fatal("resetMediaState() did not reset readiness")
	}

	s.queueReconnect()
	if !s.Drain() {
		t.Fatal("queueReconnect() did not enqueue")
	}

	s.SetShouldReconnect(func() bool { return false })
	s.queueReconnect()
	if s.Drain() {
		t.Fatal("queueReconnect() enqueued despite policy=false")
	}

	s.SetShouldReconnect(nil)
	if got := s.Request(false, false); got != engine.ReconnectQueued {
		t.Fatalf("first reconnect request = %v, want queued", got)
	}
	if got := s.Request(false, false); got != engine.ReconnectCoalesced {
		t.Fatalf("second reconnect request = %v, want coalesced", got)
	}
	if !s.Drain() || s.Drain() {
		t.Fatal("Drain() did not consume exactly one queued request")
	}

	s.telemetryActive.Store(true)
	s.stopTelemetry()
	select {
	case <-s.telemetryCh:
	default:
		t.Fatal("stopTelemetry() did not signal active telemetry")
	}

	ended := ""
	s.SetEndedCallback(func(reason string) { ended = reason })
	s.signalEnded("done")
	if !s.closed.Load() || ended != "done" {
		t.Fatalf("signalEnded() closed=%v reason=%q", s.closed.Load(), ended)
	}
}

func TestWaitForAckTimeoutAndClose(t *testing.T) {
	s := &Session{
		closeCh:    make(chan struct{}),
		ackWaiters: make(map[string]chan struct{}),
	}
	ch := s.registerAckWaiter("timeout")
	if s.waitForAck("timeout", ch, time.Millisecond) {
		t.Fatal("waitForAck(timeout) = true")
	}

	ch = s.registerAckWaiter("closed")
	close(s.closeCh)
	if s.waitForAck("closed", ch, time.Second) {
		t.Fatal("waitForAck(closeCh) = true")
	}
}

// Telemost's relay wants single-packet frames and rare keyframes, so the
// engine says so and passes the relay's keyframe requests on.

func TestTheEngineAsksForSinglePacketFrames(t *testing.T) {
	var s engine.SinglePacketRelay = &Session{}
	if !s.SinglePacketRelay() {
		t.Fatal("goolom does not ask for single-packet frames")
	}
	var _ engine.KeyframeRequestSource = &Session{}
}

func TestKeyframeRequestsReachTheTransport(t *testing.T) {
	s := &Session{}
	s.notePublisherRTCP([]rtcp.Packet{&rtcp.PictureLossIndication{}}) // nothing registered yet
	requests := 0
	s.SetKeyframeRequestHandler(func() { requests++ })
	s.notePublisherRTCP([]rtcp.Packet{
		&rtcp.ReceiverReport{},
		&rtcp.PictureLossIndication{},
		&rtcp.TransportLayerNack{},
		&rtcp.FullIntraRequest{},
	})
	if requests != 2 {
		t.Fatalf("%d requests passed on, want 2 (the PLI and the FIR)", requests)
	}
}
