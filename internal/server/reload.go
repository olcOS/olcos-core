// Key ring reload.
//
// A server whose ring comes from a keys file takes a new ring while it runs,
// and no peer whose key stays notices. The ring is swapped in place
// (muxconn.RingSource), so a group that has not paired yet pairs under the
// new ring; the sessions of keys that stay are not touched, their key sets,
// replay windows and counters included; the sessions of keys that left are
// closed at once, because a removed key must never keep a tunnel. A reload
// that cannot be done ends the run: a server never goes on serving a ring its
// operator has replaced, and the supervisor that restarts it reads the file
// as a start does.
//
// ai-generated: the whole file (ring reload on SIGHUP).
package server

import (
	"context"
	"fmt"
	"strconv"
	"sync/atomic"

	"github.com/openlibrecommunity/olcrtc/internal/crypto"
	"github.com/openlibrecommunity/olcrtc/internal/logger"
	"github.com/openlibrecommunity/olcrtc/internal/muxconn"
)

// closeKeyRemoved is the reason a session is closed with when a reload took
// its key out of the ring.
const closeKeyRemoved = "key removed"

// KeyReload connects a running server to the place its key ring is kept.
// Each receive from Request asks for one reload: the server calls Read, builds
// a ring from the keys it returns and swaps it in.
type KeyReload struct {
	// Read returns the keys of the ring, 64 hex characters each, as the start
	// read them (Config.Keys), parsed the same way.
	Read func() ([]string, error)
	// Request delivers the reload requests; a request that arrives while one
	// is being served waits its turn.
	Request <-chan struct{}
}

// keyReload is what one reload did.
type keyReload struct {
	keys    int // keys in the new ring
	added   int // keys the old ring did not hold
	removed int // keys the new ring does not hold
	closed  int // sessions closed because their key left
}

// reloadKeys swaps the ring for the one read returns, and closes the sessions
// whose key is not in it. Nothing changes when read fails or its keys do not
// make a ring: the error is for the caller to end the run with. ctx is the
// run's, which a rebuilt single-link session is served under.
func (s *Server) reloadKeys(ctx context.Context, read func() ([]string, error)) (keyReload, error) {
	s.reloadMu.Lock()
	defer s.reloadMu.Unlock()
	keysHex, err := read()
	if err != nil {
		return keyReload{}, fmt.Errorf("read keys: %w", err)
	}
	prev := s.ring.Ring()
	next, err := prev.Reload(keysHex, crypto.Server)
	if err != nil {
		return keyReload{}, fmt.Errorf("build key ring: %w", err)
	}
	// From the swap on, every pairing is tried against next, and every pin
	// the old ring made is visible to the walk below (RingSource.Swap).
	s.ring.Swap(next)
	res := keyReload{keys: next.Len(), added: countUnheld(next, prev), removed: countUnheld(prev, next)}
	res.closed = s.closeRemoved(ctx, next)
	logger.Infof("key ring reloaded: %s (added %d, removed %d), closed %s",
		plural(res.keys, "key"), res.added, res.removed, plural(res.closed, "peer"))
	return res, nil
}

// closeRemoved closes every session pinned to a key ring does not hold, and
// returns how many. Peer routing closes the sessions of those peers and no
// other; a single-link server rebuilds its session the way it does a dead
// one, with a group of its own over the ring now in force (a transport that
// routes peers over one shared control session, which none does today,
// rebuilds peer routing the way a reconnect does).
func (s *Server) closeRemoved(ctx context.Context, ring *crypto.KeyRing) int {
	gone := make(map[string]*peerSession)
	s.sessMu.RLock()
	for id, peer := range s.peerSessions {
		if pinnedOutside(peer.group, ring) {
			gone[id] = peer
		}
	}
	single, session := s.group, s.session
	s.sessMu.RUnlock()

	s.closePeers(gone, func(peer *peerSession) {
		s.removePeer(peer, closeKeyRemoved)
		s.closePeerUDPFlows(peer.peerID)
	})
	closed := len(gone)
	if pinnedOutside(single, ring) {
		s.reinstallSessionFor(ctx, session, closeKeyRemoved)
		closed++
	}
	return closed
}

// pinnedOutside reports whether g is pinned to a key set ring does not hold.
// A group that has not paired is not: it pairs under the ring when its first
// record comes.
func pinnedOutside(g *muxconn.PinGroup, ring *crypto.KeyRing) bool {
	if g == nil {
		return false
	}
	entry := g.Pinned()
	return entry != nil && !ring.Holds(entry.Keys)
}

// countUnheld counts the entries of ring whose key set other does not hold.
func countUnheld(ring, other *crypto.KeyRing) int {
	n := 0
	for _, entry := range ring.Entries() {
		if !other.Holds(entry.Keys) {
			n++
		}
	}
	return n
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}

// keyReloads holds the error that ended a run because a reload failed.
type keyReloads struct{ failed atomic.Pointer[error] }

// failure is the error the run ends with: the reload's, if one failed, else
// fallback. It is safe on a nil *keyReloads, a run without reloads.
func (k *keyReloads) failure(fallback error) error {
	if k == nil {
		return fallback
	}
	if err := k.failed.Load(); err != nil {
		return *err
	}
	return fallback
}

// startKeyReloads serves the reload requests of reload until ctx ends or a
// reload fails, which stops the run through cancel. It returns nil for a run
// that has no reload.
func (s *Server) startKeyReloads(ctx context.Context, reload *KeyReload, cancel context.CancelFunc) *keyReloads {
	if reload == nil {
		return nil
	}
	k := &keyReloads{}
	s.goTracked(func() {
		s.watchKeyReloads(ctx, reload, func(err error) {
			k.failed.Store(&err)
			cancel()
		})
	})
	return k
}

// watchKeyReloads serves the requests one at a time. A reload that fails is
// reported to fail, and ends the watch: nothing after it is served.
func (s *Server) watchKeyReloads(ctx context.Context, reload *KeyReload, fail func(error)) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case <-reload.Request:
			if _, err := s.reloadKeys(ctx, reload.Read); err != nil {
				logger.Errorf("key ring reload failed, stopping: %v", err)
				fail(fmt.Errorf("reload key ring: %w", err))
				return
			}
		}
	}
}
