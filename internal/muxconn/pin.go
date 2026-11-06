// Per-peer key pinning for multi-key rooms.
//
// A server serving several keys cannot know which key a peer holds until the
// peer's first record arrives. A PinGroup carries the source of the candidate
// ring (the ring in force when a record arrives, see RingSource) and the pin
// decision, shared by every Conn that belongs to the same peer (data and
// control planes), so whichever conn sees the first record that authenticates
// pins the key for all of them.
//
// Writes must never guess: sealing an early server frame (smux keepalive,
// window update) under the wrong key would make the peer drop it silently
// and corrupt the smux byte stream. Conn.Write therefore blocks until the
// group is pinned (or the conn closes). Single-key paths use PrePinned
// groups whose pin exists from birth, which makes the wait free and keeps
// the single-key behaviour exact.
//
// ai-generated: per-peer key pin over a crypto.KeyRing.
package muxconn

import (
	"sync"
	"sync/atomic"

	"github.com/openlibrecommunity/olcrtc/internal/crypto"
)

// RingSource is the key ring peers pair under, which a server replaces in
// place when its key file is reloaded. A group reads the ring of the moment a
// record arrives, never the one it was built with, so a group that has not
// paired yet pairs under the new ring.
//
// ai-generated: the whole type (ring reload on SIGHUP).
type RingSource struct {
	mu   sync.RWMutex
	ring *crypto.KeyRing
}

// NewRingSource builds a source whose current ring is ring.
func NewRingSource(ring *crypto.KeyRing) *RingSource {
	return &RingSource{ring: ring}
}

// Ring returns the current ring.
func (s *RingSource) Ring() *crypto.KeyRing {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ring
}

// Swap makes next the current ring and returns the ring it replaced. It waits
// for the pairings in flight (PinGroup.pair holds the read lock for the whole
// of one), so when it returns every pin made under the old ring is visible
// and every later pairing is tried against next: whoever walks the groups
// after a Swap sees all the ones the old ring paired, and none is paired to a
// key of that ring behind its back.
func (s *RingSource) Swap(next *crypto.KeyRing) *crypto.KeyRing {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.ring
	s.ring = next
	return prev
}

// PinGroup is the shared pairing state for one peer (or one single-link
// session generation). Create a fresh group per peer per (re)install - a
// reconnecting peer may return with a different key.
type PinGroup struct {
	src     *RingSource
	pinned  atomic.Pointer[crypto.RingEntry]
	pinOnce sync.Once
	pinCh   chan struct{}
}

// NewPinGroup builds an unpinned group over a ring that never changes. The
// first record any member conn opens under a ring entry pins that entry.
func NewPinGroup(ring *crypto.KeyRing) *PinGroup {
	return NewPinGroupFrom(NewRingSource(ring))
}

// NewPinGroupFrom builds an unpinned group over src, tried against the ring
// src holds when each record arrives.
//
// ai-generated: the whole function (ring reload on SIGHUP).
func NewPinGroupFrom(src *RingSource) *PinGroup {
	return &PinGroup{src: src, pinCh: make(chan struct{})}
}

// PrePinned builds a group that is pinned from birth - the exact single-key
// behaviour. keyID may be empty when the caller has no metering identity
// (client side, tests).
func PrePinned(keys *crypto.KeySet, keyID string) *PinGroup {
	ring := crypto.SingleEntry(keys, keyID)
	g := NewPinGroup(ring)
	g.pin(&ring.Entries()[0])
	return g
}

// pair tries the source's current ring on the first record of a group that
// has not paired and pins the entry that opens it. The read lock covers both
// steps (see RingSource.Swap).
//
// ai-generated: the whole method, moved out of Conn.open as it was.
func (g *PinGroup) pair(dst, record, aad []byte) ([]byte, error) {
	g.src.mu.RLock()
	defer g.src.mu.RUnlock()
	pt, matched, err := g.src.ring.TryOpen(dst, record, aad)
	if err != nil {
		return nil, err //nolint:wrapcheck // the caller sorts the crypto errors by what they are
	}
	g.pin(matched)
	return pt, nil
}

// pin publishes entry as the group's key. The first caller wins; the store
// happens before the channel close so a Write woken by pinCh always observes
// a non-nil pin.
func (g *PinGroup) pin(entry *crypto.RingEntry) {
	g.pinOnce.Do(func() {
		g.pinned.Store(entry)
		close(g.pinCh)
	})
}

// Pinned returns the pinned entry, or nil while pairing is still open.
func (g *PinGroup) Pinned() *crypto.RingEntry {
	return g.pinned.Load()
}

// KeyID returns the pinned key's metering id: "" while unpinned, for a
// PrePinned group built without one, or for a nil group.
func (g *PinGroup) KeyID() string {
	if g == nil {
		return ""
	}
	if e := g.pinned.Load(); e != nil {
		return e.KeyID
	}
	return ""
}

// PinWait returns the channel that closes once the group is pinned.
func (g *PinGroup) PinWait() <-chan struct{} { return g.pinCh }
