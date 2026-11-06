package server

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	goruntime "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	cryptopkg "github.com/openlibrecommunity/olcrtc/internal/crypto"
	"github.com/openlibrecommunity/olcrtc/internal/muxconn"
	"github.com/openlibrecommunity/olcrtc/internal/runtime"
	"github.com/openlibrecommunity/olcrtc/internal/transport"
	"github.com/openlibrecommunity/olcrtc/internal/tunnelcore"
	"github.com/openlibrecommunity/olcrtc/internal/udpwire"
)

// ai-generated: the whole file (a server takes a new key ring in place).

const (
	ringPSKA = relayClientPSK
	ringPSKB = "abcdefghijklmnopqrstuvwxyz012345"
	ringPSKC = "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345"
)

// errKeysGone stands in for a keys file that cannot be read.
var errKeysGone = errors.New("keys file: gone")

func hexes(psks ...string) []string {
	out := make([]string, 0, len(psks))
	for _, psk := range psks {
		out = append(out, hex.EncodeToString([]byte(psk)))
	}
	return out
}

// keysOf is the read of a keys file that holds psks.
func keysOf(psks ...string) func() ([]string, error) {
	return func() ([]string, error) { return hexes(psks...), nil }
}

func keyIDOfPSK(t *testing.T, psk string) string {
	t.Helper()
	id, err := cryptopkg.KeyIDFromHex(hexes(psk)[0])
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func keyRingOf(t *testing.T, psks ...string) *cryptopkg.KeyRing {
	t.Helper()
	ring, err := cryptopkg.NewKeyRing(hexes(psks...), cryptopkg.Server)
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

func ringOfPSKs(t *testing.T, psks ...string) *muxconn.RingSource {
	t.Helper()
	return muxconn.NewRingSource(keyRingOf(t, psks...))
}

// closeLog records what a server reports closed, as "session reason".
type closeLog struct {
	mu  sync.Mutex
	got []string
}

func (l *closeLog) add(sessionID, reason string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.got = append(l.got, sessionID+" "+reason)
}

func (l *closeLog) list() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.got...)
}

// reloadRig is a server routing peers over a relay (datachannel over jitsi or
// livekit), serving a ring it can reload, and the clients that join it.
type reloadRig struct {
	s       *Server
	closes  *closeLog
	mu      sync.Mutex
	clients map[string]*relayClient
}

func newReloadRig(t *testing.T, psks ...string) *reloadRig {
	t.Helper()
	link := &relayLinkStub{}
	s := newRelayServer(t, link)
	s.ring = ringOfPSKs(t, psks...)
	rig := &reloadRig{s: s, closes: &closeLog{}, clients: make(map[string]*relayClient)}
	s.onClose = rig.closes.add
	link.mu.Lock()
	link.toPeer = func(peerID string, data []byte) {
		rig.mu.Lock()
		client := rig.clients[peerID]
		rig.mu.Unlock()
		if client != nil {
			client.conn.Push(data)
		}
	}
	link.mu.Unlock()
	return rig
}

// client puts a client holding psk on the relay under peerID, without a
// handshake.
func (r *reloadRig) client(t *testing.T, peerID, psk string) *relayClient {
	t.Helper()
	client := newRelayClientKeyed(t, r.s, peerID, psk)
	r.mu.Lock()
	r.clients[peerID] = client
	r.mu.Unlock()
	return client
}

// join runs the handshake of a client holding psk and returns it with the
// session the server built for it, once its control loop runs.
func (r *reloadRig) join(t *testing.T, peerID, psk string) (*relayClient, *peerSession) {
	t.Helper()
	client := r.client(t, peerID, psk)
	client.handshake(t)
	peer := lookupPeer(r.s, peerID)
	if peer == nil {
		t.Fatalf("the server built no session for %s", peerID)
	}
	waitPeerControl(t, peer)
	return client, peer
}

func TestAReloadThatKeepsAPeersKeyLeavesThePeerRunning(t *testing.T) {
	rig := newReloadRig(t, ringPSKA)
	client, peer := rig.join(t, "peer-a", ringPSKA)
	sid := peer.sid()
	idA := keyIDOfPSK(t, ringPSKA)
	rig.s.meter.add(sid, 10, 20)

	res, err := rig.s.reloadKeys(context.Background(), keysOf(ringPSKA, ringPSKB))
	if err != nil {
		t.Fatalf("reloadKeys() error = %v", err)
	}

	if want := (keyReload{keys: 2, added: 1}); res != want {
		t.Fatalf("reloadKeys() = %+v, want %+v", res, want)
	}
	if lookupPeer(rig.s, "peer-a") != peer || peer.sid() != sid {
		t.Fatal("the reload replaced a peer whose key stays")
	}
	if peer.dataSession().IsClosed() || client.session.IsClosed() {
		t.Fatal("the reload closed a peer whose key stays")
	}
	if got := rig.closes.list(); len(got) != 0 {
		t.Fatalf("the reload reported %v closed", got)
	}
	// The peer is still metered under its key: its counters keep counting.
	if got := meteredKey(rig.s.meter, sid); got != idA {
		t.Fatalf("the peer's session is metered under %q after the reload, want its key", got)
	}
	rig.s.meter.add(sid, 1, 2)
	if got := rig.s.meter.snapshot().Keys[idA]; got != (StatsDirection{Up: 11, Down: 22}) {
		t.Fatalf("the key's counters = %+v, want 11 up and 22 down", got)
	}
}

func TestAReloadThatDropsAPeersKeyClosesThePeerAtOnce(t *testing.T) {
	rig := newReloadRig(t, ringPSKA, ringPSKB)
	_, peerA := rig.join(t, "peer-a", ringPSKA)
	clientB, peerB := rig.join(t, "peer-b", ringPSKB)
	sidA := peerA.sid()

	res, err := rig.s.reloadKeys(context.Background(), keysOf(ringPSKB))
	if err != nil {
		t.Fatalf("reloadKeys() error = %v", err)
	}

	if want := (keyReload{keys: 1, removed: 1, closed: 1}); res != want {
		t.Fatalf("reloadKeys() = %+v, want %+v", res, want)
	}
	if lookupPeer(rig.s, "peer-a") != nil || !peerA.dataSession().IsClosed() {
		t.Fatal("the peer of a removed key kept its session")
	}
	if got, want := rig.closes.list(), []string{sidA + " key removed"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("closed = %v, want %v", got, want)
	}
	if lookupPeer(rig.s, "peer-b") != peerB || peerB.dataSession().IsClosed() || clientB.session.IsClosed() {
		t.Fatal("the reload closed a peer whose key stays")
	}
}

// A removed key must never keep a tunnel: the client that held it is still
// there, and whatever it sends next is a stranger's.
func TestAPeerWhoseKeyWasRemovedCannotPairAgain(t *testing.T) {
	rig := newReloadRig(t, ringPSKA, ringPSKB)
	clientA, old := rig.join(t, "peer-a", ringPSKA)
	if _, err := rig.s.reloadKeys(context.Background(), keysOf(ringPSKB)); err != nil {
		t.Fatalf("reloadKeys() error = %v", err)
	}

	if _, err := clientA.conn.Write([]byte("still here")); err != nil {
		t.Fatalf("the client's Write() error = %v", err)
	}

	next := lookupPeer(rig.s, "peer-a")
	if next == nil || next == old {
		t.Fatal("the server built no session for the client's next record")
	}
	if next.group.Pinned() != nil {
		t.Fatal("a key the reload removed paired again")
	}
}

func TestAPeerPairsUnderAKeyTheReloadAdded(t *testing.T) {
	rig := newReloadRig(t, ringPSKA)
	// The session the server builds for a peer ahead of its first record, as
	// it does for one whose first records no key opens: its group is old,
	// and has not paired.
	early := rig.s.getPeerSession("peer-b")
	if early == nil || early.group.Pinned() != nil {
		t.Fatal("the server built no unpaired session for the peer")
	}
	if _, err := rig.s.reloadKeys(context.Background(), keysOf(ringPSKA, ringPSKB)); err != nil {
		t.Fatalf("reloadKeys() error = %v", err)
	}

	rig.client(t, "peer-b", ringPSKB).handshake(t)

	peer := lookupPeer(rig.s, "peer-b")
	if peer != early {
		t.Fatal("the server replaced the session it had built")
	}
	waitPeerControl(t, peer)
	if got := peer.group.KeyID(); got != keyIDOfPSK(t, ringPSKB) {
		t.Fatalf("the peer paired under key %q, want the key the reload added", got)
	}
	if got := meteredKey(rig.s.meter, peer.sid()); got != keyIDOfPSK(t, ringPSKB) {
		t.Fatalf("the peer's session is metered under %q, want the key the reload added", got)
	}
}

// /stats is read by an agent that takes a counter that goes back for a
// restart: a reload is not one.
func TestAReloadKeepsTheCountersOfEveryKey(t *testing.T) {
	rig := newReloadRig(t, ringPSKA, ringPSKB)
	_, peerA := rig.join(t, "peer-a", ringPSKA)
	_, peerB := rig.join(t, "peer-b", ringPSKB)
	rig.s.meter.add(peerA.sid(), 5, 6)
	rig.s.meter.add(peerB.sid(), 7, 8)
	before := rig.s.meter.snapshot()

	if _, err := rig.s.reloadKeys(context.Background(), keysOf(ringPSKB, ringPSKC)); err != nil {
		t.Fatalf("reloadKeys() error = %v", err)
	}

	after := rig.s.meter.snapshot()
	if !reflect.DeepEqual(after.Keys, before.Keys) || after.Total != before.Total {
		t.Fatalf("the counters changed across the reload: %+v, then %+v", before, after)
	}
}

func TestAReloadWritesOneLineWithoutKeyMaterial(t *testing.T) {
	rig := newReloadRig(t, ringPSKA, ringPSKB)
	rig.join(t, "peer-a", ringPSKA)
	out := captureLog(t)

	if _, err := rig.s.reloadKeys(context.Background(), keysOf(ringPSKB, ringPSKC)); err != nil {
		t.Fatalf("reloadKeys() error = %v", err)
	}

	var lines []string
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.Contains(line, "key ring") {
			lines = append(lines, line)
		}
	}
	if want := []string{"key ring reloaded: 2 keys (added 1, removed 1), closed 1 peer"}; !reflect.DeepEqual(lines, want) {
		t.Fatalf("the reload wrote %q, want %q", lines, want)
	}
	for _, psk := range []string{ringPSKA, ringPSKB, ringPSKC} {
		if strings.Contains(out.String(), hexes(psk)[0]) || strings.Contains(out.String(), keyIDOfPSK(t, psk)) {
			t.Fatal("the reload wrote key material")
		}
	}
}

func TestAReloadThatFailsLeavesTheRingAndThePeersAsTheyWere(t *testing.T) {
	cases := []struct {
		name string
		read func() ([]string, error)
		want error
	}{
		{"unreadable file", func() ([]string, error) { return nil, errKeysGone }, errKeysGone},
		{"empty ring", func() ([]string, error) { return nil, nil }, cryptopkg.ErrEmptyRing},
		{"bad hex", func() ([]string, error) { return []string{"zz"}, nil }, nil},
		{"short key", func() ([]string, error) { return []string{"aabb"}, nil }, cryptopkg.ErrInvalidKeySize},
		{"a good key and a bad one", func() ([]string, error) { return append(hexes(ringPSKB), "zz"), nil }, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rig := newReloadRig(t, ringPSKA, ringPSKB)
			_, peer := rig.join(t, "peer-a", ringPSKA)
			before := rig.s.ring.Ring()

			_, err := rig.s.reloadKeys(context.Background(), tc.read)

			if err == nil {
				t.Fatal("reloadKeys() accepted what it could not read")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("reloadKeys() error = %v, want %v", err, tc.want)
			}
			if rig.s.ring.Ring() != before {
				t.Fatal("a reload that failed changed the ring")
			}
			if lookupPeer(rig.s, "peer-a") != peer || peer.dataSession().IsClosed() || len(rig.closes.list()) != 0 {
				t.Fatal("a reload that failed closed a peer")
			}
		})
	}
}

func TestWatchKeyReloadsAppliesEachRequestAndStopsOnAFailure(t *testing.T) {
	rig := newReloadRig(t, ringPSKA)
	requests := make(chan struct{})
	reads := 0
	read := func() ([]string, error) {
		reads++
		if reads == 1 {
			return hexes(ringPSKA, ringPSKB), nil
		}
		return nil, errKeysGone
	}
	failed := make(chan error, 1)
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		rig.s.watchKeyReloads(context.Background(), &KeyReload{Read: read, Request: requests},
			func(err error) { failed <- err })
	}()

	requests <- struct{}{}
	requests <- struct{}{} // taken only when the first reload is done

	select {
	case err := <-failed:
		if !errors.Is(err, errKeysGone) {
			t.Fatalf("the watch failed with %v, want the read's error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the watch did not report a reload that failed")
	}
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the watch kept running after a reload failed")
	}
	if got := rig.s.ring.Ring().Len(); got != 2 {
		t.Fatalf("the ring has %d keys, want the first reload's 2", got)
	}
}

func TestWatchKeyReloadsStopsWithItsContext(t *testing.T) {
	rig := newReloadRig(t, ringPSKA)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		rig.s.watchKeyReloads(ctx, &KeyReload{Read: keysOf(ringPSKA), Request: make(chan struct{})},
			func(error) { t.Error("a watch that was stopped reported a failure") })
	}()
	cancel()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("the watch outlived its context")
	}
}

// A run whose operator replaced the ring must not go on serving the old one:
// the run ends with the reload's error, and the supervisor starts it again
// from the file.
func TestRunEndsWithTheErrorOfAFailedKeyReload(t *testing.T) {
	name := "keyreload-" + t.Name()
	transport.Register(name, func(context.Context, transport.Config) (transport.Transport, error) {
		return &linkStub{}, nil
	})
	requests := make(chan struct{}, 1)
	done := make(chan error, 1)
	go func() {
		done <- Run(context.Background(), Config{
			Transport: name, Keys: hexes(ringPSKA, ringPSKB),
			Reload: &KeyReload{Read: func() ([]string, error) { return nil, errKeysGone }, Request: requests},
		})
	}()

	requests <- struct{}{}

	select {
	case err := <-done:
		if !errors.Is(err, errKeysGone) {
			t.Fatalf("Run() error = %v, want the reload's error", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run kept serving a ring its operator tried to replace")
	}
}

func TestRunWithoutAKeyReloadIsAsItWas(t *testing.T) {
	name := "keyreload-" + t.Name()
	transport.Register(name, func(context.Context, transport.Config) (transport.Transport, error) {
		return &linkStub{}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, Config{Transport: name, Keys: hexes(ringPSKA)}) }()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run() error = %v, want nil after the context ended", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after its context ended")
	}
}

// pairSingleton sends the first record of a client holding psk to a server
// that serves one session over its link.
func pairSingleton(t *testing.T, srv *Server, psk string) {
	t.Helper()
	keys, err := cryptopkg.NewKeySet([]byte(psk), cryptopkg.Client)
	if err != nil {
		t.Fatal(err)
	}
	link := &clientLinkStub{send: func(data []byte) { srv.onData(data) }}
	conn := muxconn.New(link, keys)
	session, err := tunnelcore.NewSession(conn, tunnelcore.ClientRole, runtime.SmuxConfigFor(link))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = session.Close()
		_ = conn.Close()
	})
	if _, err := session.OpenStream(); err != nil {
		t.Fatalf("OpenStream() error = %v", err)
	}
}

func singletonGroup(srv *Server) *muxconn.PinGroup {
	srv.sessMu.RLock()
	defer srv.sessMu.RUnlock()
	return srv.group
}

func TestAReloadThatKeepsASingletonsKeyLeavesItsSession(t *testing.T) {
	rig := newLinkRigOn(t, &linkStub{}, ringOfPSKs(t, ringPSKA))
	closes := &closeLog{}
	rig.srv.onClose = closes.add
	pairSingleton(t, rig.srv, ringPSKA)
	rig.pair("sid-1")
	session := rig.dataSession()

	res, err := rig.srv.reloadKeys(context.Background(), keysOf(ringPSKA, ringPSKB))
	if err != nil {
		t.Fatalf("reloadKeys() error = %v", err)
	}

	if want := (keyReload{keys: 2, added: 1}); res != want {
		t.Fatalf("reloadKeys() = %+v, want %+v", res, want)
	}
	if rig.dataSession() != session || session.IsClosed() || len(closes.list()) != 0 {
		t.Fatal("the reload ended the session of a key that stays")
	}
	if got := singletonGroup(rig.srv).KeyID(); got != keyIDOfPSK(t, ringPSKA) {
		t.Fatalf("the session is pinned to %q, want its key", got)
	}
}

func TestAReloadThatDropsASingletonsKeyRebuildsItsSession(t *testing.T) {
	rig := newLinkRigOn(t, &linkStub{}, ringOfPSKs(t, ringPSKA, ringPSKB))
	closes := &closeLog{}
	rig.srv.onClose = closes.add
	pairSingleton(t, rig.srv, ringPSKA)
	rig.pair("sid-1")
	session, group := rig.dataSession(), singletonGroup(rig.srv)
	if group.KeyID() != keyIDOfPSK(t, ringPSKA) {
		t.Fatal("the session did not pair under the first key")
	}

	res, err := rig.srv.reloadKeys(context.Background(), keysOf(ringPSKB))
	if err != nil {
		t.Fatalf("reloadKeys() error = %v", err)
	}

	if want := (keyReload{keys: 1, removed: 1, closed: 1}); res != want {
		t.Fatalf("reloadKeys() = %+v, want %+v", res, want)
	}
	if rig.dataSession() == session || !session.IsClosed() {
		t.Fatal("the session of a removed key was not replaced")
	}
	if got, want := closes.list(), []string{"sid-1 key removed"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("closed = %v, want %v", got, want)
	}
	if next := singletonGroup(rig.srv); next == group || next.Pinned() != nil {
		t.Fatal("the rebuilt session did not start with a group of its own")
	}
	// A reload is not a carrier event: the link stays as it was.
	if asked := rig.link.requests(); len(asked) != 0 {
		t.Fatalf("the reload asked the link to rebuild: %v", asked)
	}
	if got := rig.srv.LinkState(); got != LinkUp {
		t.Fatalf("the link reads %q after the reload, want %q", got, LinkUp)
	}

	pairSingleton(t, rig.srv, ringPSKB)
	if got := singletonGroup(rig.srv).KeyID(); got != keyIDOfPSK(t, ringPSKB) {
		t.Fatalf("the rebuilt session paired under %q, want the key that stays", got)
	}
}

// restartPeer gives a session started over the pin group of the one it
// left. If a reload removed that group's key in between, the pin is not
// carried: the walk of the reload cannot see a session that was not there.
func TestASessionStartedOverDoesNotCarryAPinTheRingNoLongerHolds(t *testing.T) {
	rig := newReloadRig(t, ringPSKA, ringPSKB)
	_, old := rig.join(t, "peer-a", ringPSKA)
	rig.s.endPeer(old, "restarted", false)

	swapped, err := rig.s.ring.Ring().Reload(hexes(ringPSKB), cryptopkg.Server)
	if err != nil {
		t.Fatal(err)
	}
	rig.s.ring.Swap(swapped)

	next := rig.s.peerSessionIn("peer-a", old.group)
	if next == nil || next.group == old.group || next.group.Pinned() != nil {
		t.Fatal("a session started over carried a pin whose key had left the ring")
	}
}

func TestASessionStartedOverCarriesAPinTheRingStillHolds(t *testing.T) {
	rig := newReloadRig(t, ringPSKA, ringPSKB)
	_, old := rig.join(t, "peer-a", ringPSKA)
	rig.s.endPeer(old, "restarted", false)

	if _, err := rig.s.reloadKeys(context.Background(), keysOf(ringPSKA, ringPSKC)); err != nil {
		t.Fatalf("reloadKeys() error = %v", err)
	}

	next := rig.s.peerSessionIn("peer-a", old.group)
	if next == nil || next.group != old.group {
		t.Fatal("a session started over lost the pin of a key that stays")
	}
}

// closeSpy is a flow's socket that remembers it was closed.
type closeSpy struct {
	noopConn
	closed atomic.Bool
}

func (c *closeSpy) Close() error {
	c.closed.Store(true)
	return nil
}

// A UDP flow is fed by the internet, not by the peer, and answers under the
// key that opened it: left alone it goes on sending a removed key's peer
// whatever its target sends, for as long as the target does.
func TestAReloadEndsTheUDPFlowsOfAPeerWhoseKeyLeft(t *testing.T) {
	rig := newReloadRig(t, ringPSKA, ringPSKB)
	rig.join(t, "peer-a", ringPSKA)
	rig.join(t, "peer-b", ringPSKB)
	flows := map[string]*closeSpy{"peer-a": {}, "peer-b": {}}
	rig.s.udpMu.Lock()
	rig.s.udpFlows = make(map[serverUDPKey]*serverUDPFlow)
	for peerID, spy := range flows {
		key := serverUDPKey{peerID: peerID, flowID: 1}
		rig.s.udpFlows[key] = &serverUDPFlow{key: key, conn: spy, endpoint: udpwire.Endpoint{Host: "192.0.2.1", Port: 53}}
	}
	rig.s.udpMu.Unlock()

	if _, err := rig.s.reloadKeys(context.Background(), keysOf(ringPSKB)); err != nil {
		t.Fatalf("reloadKeys() error = %v", err)
	}

	if !flows["peer-a"].closed.Load() {
		t.Fatal("the UDP flow of a peer whose key was removed was left running")
	}
	if flows["peer-b"].closed.Load() {
		t.Fatal("the UDP flow of a peer whose key stays was ended")
	}
	rig.s.udpMu.Lock()
	defer rig.s.udpMu.Unlock()
	if _, ok := rig.s.udpFlows[serverUDPKey{peerID: "peer-a", flowID: 1}]; ok || len(rig.s.udpFlows) != 1 {
		t.Fatalf("flows left after the reload: %d, want only the kept peer's", len(rig.s.udpFlows))
	}
}

// Reloads that race with first records, restarts and closes: whatever the
// order they land in, once the last reload has returned no session is pinned
// to a key the ring it left behind lacks. Run with -race.
func TestReloadsRacingWithPairingsLeaveNoPeerOnARemovedKey(t *testing.T) {
	const (
		clients = 12
		opens   = 15
		reloads = 20
	)
	rig := newReloadRig(t, ringPSKA, ringPSKB, ringPSKC)
	psks := []string{ringPSKA, ringPSKB, ringPSKC}
	all := make([]*relayClient, clients)
	for i := range all {
		all[i] = rig.client(t, fmt.Sprintf("peer-%d", i), psks[i%len(psks)])
	}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, client := range all {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range opens {
				_, _ = client.session.OpenStream() // a record the server pairs the peer on
				goruntime.Gosched()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := range reloads {
			keys := keysOf(ringPSKA, ringPSKB, ringPSKC)
			if i%2 == 1 {
				keys = keysOf(ringPSKB, ringPSKC)
			}
			if _, err := rig.s.reloadKeys(context.Background(), keys); err != nil {
				t.Errorf("reloadKeys() error = %v", err)
				return
			}
		}
	}()
	close(start)
	wg.Wait()

	// Every client speaks once more under a ring that holds its key, so that
	// the last reload has sessions to close; then it takes the first key out.
	if _, err := rig.s.reloadKeys(context.Background(), keysOf(ringPSKA, ringPSKB, ringPSKC)); err != nil {
		t.Fatalf("reloadKeys() error = %v", err)
	}
	for _, client := range all {
		_, _ = client.session.OpenStream()
	}
	if onA := peersPinnedTo(rig.s, keyIDOfPSK(t, ringPSKA)); onA == 0 {
		t.Fatal("no peer paired under the first key: the reload below closes nothing")
	}
	if _, err := rig.s.reloadKeys(context.Background(), keysOf(ringPSKB, ringPSKC)); err != nil {
		t.Fatalf("reloadKeys() error = %v", err)
	}

	if onA := peersPinnedTo(rig.s, keyIDOfPSK(t, ringPSKA)); onA != 0 {
		t.Fatalf("%d peers are pinned to a key the ring lacks", onA)
	}
}

// peersPinnedTo counts the peer sessions whose group is pinned to the key
// with this id.
func peersPinnedTo(s *Server, keyID string) int {
	s.sessMu.RLock()
	defer s.sessMu.RUnlock()
	n := 0
	for _, peer := range s.peerSessions {
		if peer.group.KeyID() == keyID {
			n++
		}
	}
	return n
}
