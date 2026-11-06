package muxconn

import (
	"fmt"
	"sync"
	"testing"
	"time"

	cryptopkg "github.com/openlibrecommunity/olcrtc/internal/crypto"
)

// ai-generated: the whole file (a pin group pairs under the server's current
// key ring, which a reload replaces in place).

func readString(t *testing.T, conn *Conn) string {
	t.Helper()
	buf := make([]byte, 32)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read = %v", err)
	}
	return string(buf[:n])
}

// A group is built before the swap and has not paired yet: the record that
// pairs it is tried against the ring of that moment, not the ring of the
// group's birth.
func TestAGroupPairsUnderTheRingOfTheMomentOfTheRecord(t *testing.T) {
	src := NewRingSource(ringOf(t, pskA))
	group := NewPinGroupFrom(src)
	conn := NewGrouped(&stubLink{canSend: true}, group)
	defer func() { _ = conn.Close() }()
	clientB := keysFor(t, pskB, cryptopkg.Client)

	conn.Push(sealedBy(t, clientB, "too early"))
	if group.Pinned() != nil {
		t.Fatal("a key outside the ring pinned the group")
	}

	if prev := src.Swap(ringOf(t, pskB)); prev == nil || prev.Len() != 1 {
		t.Fatalf("Swap returned %v, want the ring it replaced", prev)
	}
	conn.Push(sealedBy(t, clientB, "hello"))

	if got := readString(t, conn); got != "hello" {
		t.Fatalf("Read = %q, want the record sealed under the new key", got)
	}
	if got := group.KeyID(); got != keyIDOf(t, pskB) {
		t.Fatalf("pinned key id = %s, want the new key", got)
	}
}

// Closing a peer whose key left is the server's job. The conn keeps opening
// what its pinned key seals, so a key that stays in the ring is never cut by
// the swap itself.
func TestAPinnedGroupStaysPinnedAcrossASwap(t *testing.T) {
	src := NewRingSource(ringOf(t, pskA, pskB))
	group := NewPinGroupFrom(src)
	conn := NewGrouped(&stubLink{canSend: true}, group)
	defer func() { _ = conn.Close() }()
	clientA := keysFor(t, pskA, cryptopkg.Client)

	conn.Push(sealedBy(t, clientA, "one"))
	if got := readString(t, conn); got != "one" {
		t.Fatalf("Read = %q before the swap", got)
	}
	src.Swap(ringOf(t, pskB))

	if got := group.KeyID(); got != keyIDOf(t, pskA) {
		t.Fatalf("pinned key id after the swap = %s, want the first key", got)
	}
	conn.Push(sealedBy(t, clientA, "two"))
	if got := readString(t, conn); got != "two" {
		t.Fatalf("Read = %q after the swap, want the pinned key to keep opening", got)
	}
}

func TestPinGroupOverAFixedRingIsAsItWas(t *testing.T) {
	group := NewPinGroup(ringOf(t, pskA, pskB))
	conn := NewGrouped(&stubLink{canSend: true}, group)
	defer func() { _ = conn.Close() }()
	conn.Push(sealedBy(t, keysFor(t, pskB, cryptopkg.Client), "hi"))
	if got := group.KeyID(); got != keyIDOf(t, pskB) {
		t.Fatalf("pinned key id = %s, want the second entry", got)
	}
}

// A swap that returns has seen every pin made under the ring it replaced:
// the walk that closes the peers of removed keys runs after it, so a group
// pinned a moment later to a key the new ring lacks would keep a tunnel
// nobody closes. The ring is long so that one pairing is slow enough for the
// swap to land inside it.
func TestNoGroupIsPinnedToAKeyAfterTheSwapThatRemovedIt(t *testing.T) {
	const (
		ringKeys = 3000
		groups   = 8
		attempts = 25
	)
	psks := make([]string, ringKeys)
	for i := range psks {
		psks[i] = fmt.Sprintf("%032d", i)
	}
	long := ringOf(t, psks...)
	short := ringOf(t, psks[0])
	last := keysFor(t, psks[ringKeys-1], cryptopkg.Client) // tried last, so the slowest to pair
	pinnedAtSwap := 0
	for range attempts {
		src := NewRingSource(long)
		gs, conns := make([]*PinGroup, groups), make([]*Conn, groups)
		for i := range gs {
			gs[i] = NewPinGroupFrom(src)
			conns[i] = NewGrouped(&stubLink{canSend: true}, gs[i])
		}
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range conns {
			record := sealedBy(t, last, "x")
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				conns[i].Push(record)
			}()
		}
		close(start)
		time.Sleep(time.Millisecond)
		src.Swap(short)
		atSwap := countPinned(gs)
		wg.Wait()
		if after := countPinned(gs); after != atSwap {
			t.Fatalf("%d groups were pinned to the removed key after the swap returned", after-atSwap)
		}
		pinnedAtSwap += atSwap
		for _, conn := range conns {
			_ = conn.Close()
		}
	}
	if pinnedAtSwap == 0 {
		t.Fatal("no swap landed after a pairing began: the test saw nothing")
	}
}

func countPinned(groups []*PinGroup) int {
	n := 0
	for _, g := range groups {
		if g.Pinned() != nil {
			n++
		}
	}
	return n
}
