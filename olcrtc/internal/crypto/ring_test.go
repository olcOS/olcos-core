package crypto

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func hexKey(b byte) string { return strings.Repeat(string("0123456789abcdef"[b%16]), 64) }

func decodeHex(s string) ([]byte, error) { return hex.DecodeString(s) }

func TestNewKeyRingRejectsEmptyAndBadKeys(t *testing.T) {
	if _, err := NewKeyRing(nil, Server); !errors.Is(err, ErrEmptyRing) {
		t.Fatalf("empty ring error = %v", err)
	}
	if _, err := NewKeyRing([]string{"zz"}, Server); err == nil {
		t.Fatal("bad hex accepted")
	}
	if _, err := NewKeyRing([]string{"aabb"}, Server); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("short key error = %v", err)
	}
}

func TestKeyRingTryOpenPicksTheRightKeyOfThree(t *testing.T) {
	keys := []string{hexKey(1), hexKey(2), hexKey(3)}
	ring, err := NewKeyRing(keys, Server)
	if err != nil {
		t.Fatal(err)
	}
	for i, k := range keys {
		psk, _ := decodeHex(k)
		client, err := NewKeySet(psk, Client)
		if err != nil {
			t.Fatal(err)
		}
		record, err := client.Seal([]byte("hello"), []byte("aad"))
		if err != nil {
			t.Fatal(err)
		}
		pt, entry, err := ring.TryOpen(nil, record, []byte("aad"))
		if err != nil || string(pt) != "hello" {
			t.Fatalf("key %d: TryOpen = %q, %v", i, pt, err)
		}
		if entry != &ring.Entries()[i] {
			t.Fatalf("key %d: matched entry %v, want index %d", i, entry.KeyID, i)
		}
	}
}

func TestKeyRingTryOpenRejectsUnknownKeyAndJunk(t *testing.T) {
	ring, _ := NewKeyRing([]string{hexKey(1)}, Server)
	psk, _ := decodeHex(hexKey(9))
	stranger, _ := NewKeySet(psk, Client)
	record, _ := stranger.Seal([]byte("x"), []byte("aad"))
	if _, _, err := ring.TryOpen(nil, record, []byte("aad")); !errors.Is(err, ErrNoRingMatch) {
		t.Fatalf("unknown key error = %v, want ErrNoRingMatch", err)
	}
	if _, _, err := ring.TryOpen(nil, make([]byte, WireOverhead+2), []byte("aad")); !errors.Is(err, ErrBadRecordMagic) {
		t.Fatalf("junk error = %v, want ErrBadRecordMagic", err)
	}
}

func TestKeyRingDedupesIdenticalKeys(t *testing.T) {
	ring, err := NewKeyRing([]string{hexKey(1), strings.ToUpper(hexKey(1))}, Server)
	if err != nil || ring.Len() != 1 {
		t.Fatalf("ring len = %d, err = %v; want 1 entry", ring.Len(), err)
	}
}

func TestKeyIDFromHexStableAndCaseInsensitive(t *testing.T) {
	a, err := KeyIDFromHex(hexKey(2))
	if err != nil || len(a) != KeyIDLen {
		t.Fatalf("KeyIDFromHex = %q, %v", a, err)
	}
	b, _ := KeyIDFromHex(strings.ToUpper(hexKey(2)))
	if a != b {
		t.Fatalf("key id differs by case: %s vs %s", a, b)
	}
	if _, err := KeyIDFromHex("zz"); err == nil {
		t.Fatal("bad hex accepted")
	}
}

// ai-generated: the tests below (a ring that is reloaded in place, see Reload).

func idOf(t *testing.T, keyHex string) string {
	t.Helper()
	id, err := KeyIDFromHex(keyHex)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestKeyRingHolds(t *testing.T) {
	ring, err := NewKeyRing([]string{hexKey(1), hexKey(2)}, Server)
	if err != nil {
		t.Fatal(err)
	}
	if !ring.Holds(ring.Entries()[0].Keys) || !ring.Holds(ring.Entries()[1].Keys) {
		t.Fatal("a ring does not hold its own key sets")
	}
	other, err := NewKeyRing([]string{hexKey(1)}, Server)
	if err != nil {
		t.Fatal(err)
	}
	if ring.Holds(other.Entries()[0].Keys) {
		t.Fatal("a ring holds the key set of another ring that was built from the same key")
	}
	if ring.Holds(nil) {
		t.Fatal("a ring holds no key set")
	}
}

func TestKeyRingReloadKeepsTheEntriesOfKeysThatStay(t *testing.T) {
	prev, err := NewKeyRing([]string{hexKey(1), hexKey(2)}, Server)
	if err != nil {
		t.Fatal(err)
	}
	next, err := prev.Reload([]string{hexKey(3), hexKey(2)}, Server)
	if err != nil {
		t.Fatal(err)
	}
	if next.Len() != 2 {
		t.Fatalf("reloaded ring has %d keys, want 2", next.Len())
	}
	if next.Entries()[0].KeyID != idOf(t, hexKey(3)) || next.Entries()[1].KeyID != idOf(t, hexKey(2)) {
		t.Fatal("the reloaded ring does not follow the order of the new list")
	}
	if next.Entries()[1].Keys != prev.Entries()[1].Keys {
		t.Fatal("a key that stays lost its key set, and with it its replay windows")
	}
	if next.Entries()[0].Keys == prev.Entries()[0].Keys || next.Entries()[0].Keys == prev.Entries()[1].Keys {
		t.Fatal("a new key was given the key set of another key")
	}
	if next.Holds(prev.Entries()[0].Keys) || !prev.Holds(prev.Entries()[0].Keys) {
		t.Fatal("Reload changed the ring it was called on, or kept a key that left")
	}
	if !next.Holds(prev.Entries()[1].Keys) {
		t.Fatal("a key that stays is not held by the reloaded ring")
	}
}

// A record the old ring already opened is a replay in the new one: the key
// set is the same, so the window that remembers it is too.
func TestKeyRingReloadKeepsTheReplayWindowOfAKeyThatStays(t *testing.T) {
	prev, err := NewKeyRing([]string{hexKey(1), hexKey(2)}, Server)
	if err != nil {
		t.Fatal(err)
	}
	psk, _ := decodeHex(hexKey(2))
	client, err := NewKeySet(psk, Client)
	if err != nil {
		t.Fatal(err)
	}
	record, err := client.Seal([]byte("hello"), []byte("aad"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = prev.TryOpen(nil, record, []byte("aad")); err != nil {
		t.Fatalf("the old ring did not open the record: %v", err)
	}
	next, err := prev.Reload([]string{hexKey(2), hexKey(3)}, Server)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = next.TryOpen(nil, record, []byte("aad")); !errors.Is(err, ErrReplayDuplicate) {
		t.Fatalf("a replay across the reload = %v, want ErrReplayDuplicate", err)
	}
}

func TestKeyRingReloadRejectsWhatNewKeyRingRejects(t *testing.T) {
	prev, err := NewKeyRing([]string{hexKey(1)}, Server)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = prev.Reload(nil, Server); !errors.Is(err, ErrEmptyRing) {
		t.Fatalf("empty reload error = %v, want ErrEmptyRing", err)
	}
	if _, err = prev.Reload([]string{hexKey(2), "zz"}, Server); err == nil {
		t.Fatal("bad hex accepted by a reload")
	}
	if _, err = prev.Reload([]string{"aabb"}, Server); !errors.Is(err, ErrInvalidKeySize) {
		t.Fatalf("short key reload error = %v, want ErrInvalidKeySize", err)
	}
	if prev.Len() != 1 {
		t.Fatal("a failed reload changed the ring")
	}
}

func TestKeyRingReloadDedupesIdenticalKeys(t *testing.T) {
	prev, err := NewKeyRing([]string{hexKey(1)}, Server)
	if err != nil {
		t.Fatal(err)
	}
	next, err := prev.Reload([]string{hexKey(2), strings.ToUpper(hexKey(2)), hexKey(1)}, Server)
	if err != nil || next.Len() != 2 {
		t.Fatalf("reloaded ring len = %d, err = %v; want 2 entries", next.Len(), err)
	}
}
