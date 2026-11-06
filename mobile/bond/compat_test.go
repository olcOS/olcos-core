package bond

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"testing"
	"time"
)

// Wire compatibility with the bond package as it was before the hello carried
// a failure group and a budget (ad7eeae): its server parsed the hello with
// oldReadHello, kept below as it was, and never read the lane count.

// oldHello is the old package's hello.
type oldHello struct {
	session [16]byte
	client  [8]byte
	lane    uint8
	lanes   uint8
	rejoin  bool
	unix    uint64
	target  string
}

// oldReadHello is ad7eeae's readHello.
func oldReadHello(r io.Reader, key []byte, now time.Time) (oldHello, error) {
	var h oldHello
	head := make([]byte, helloHead)
	if _, err := io.ReadFull(r, head); err != nil {
		return h, err
	}
	if string(head[:4]) != magic {
		return h, errBadHello
	}
	tlen := int(head[len(head)-1])
	rest := make([]byte, tlen+macSize)
	if _, err := io.ReadFull(r, rest); err != nil {
		return h, err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(head)
	mac.Write(rest[:tlen])
	if tlen == 0 || !hmac.Equal(mac.Sum(nil), rest[tlen:]) {
		return h, errBadHello
	}
	copy(h.session[:], head[4:20])
	copy(h.client[:], head[20:28])
	h.lane, h.lanes = head[28], head[29]&^rejoinFlag
	h.rejoin = head[29]&rejoinFlag != 0
	h.unix = binary.BigEndian.Uint64(head[30:38])
	h.target = string(rest[:tlen])
	sent := time.Unix(int64(h.unix), 0)
	if sent.Before(now.Add(-clockSkew)) || sent.After(now.Add(clockSkew)) {
		return h, errBadHello
	}
	return h, nil
}

// oldMarshal is ad7eeae's hello.marshal.
func (h oldHello) marshal(key []byte) []byte {
	lanes := min(h.lanes, rejoinFlag-1)
	if h.rejoin {
		lanes |= rejoinFlag
	}
	b := append([]byte(magic), h.session[:]...)
	b = append(b, h.client[:]...)
	b = append(b, h.lane, lanes)
	b = binary.BigEndian.AppendUint64(b, h.unix)
	b = append(b, byte(len(h.target)))
	b = append(b, h.target...)
	mac := hmac.New(sha256.New, key)
	mac.Write(b)
	return mac.Sum(b)
}

func TestAnOldServerTakesTheExtendedHello(t *testing.T) {
	now := time.Now()
	for _, rejoin := range []bool{false, true} {
		h := hello{client: [8]byte{1, 2, 3, 4, 5, 6, 7, budgetCode(4 << 20)}, lane: 2, rejoin: rejoin, ext: true, group: 1,
			unix: uint64(now.Unix()), target: "example.org:443"}
		h.session[0] = 7
		b, err := h.marshal(testKey)
		if err != nil {
			t.Fatal(err)
		}
		old, err := oldReadHello(bytes.NewReader(b), testKey, now)
		if err != nil {
			t.Fatalf("rejoin=%v: the old server refuses the hello: %v", rejoin, err)
		}
		// What the old server acts on is the same; the lane count it stores
		// and never reads is the group.
		if old.session != h.session || old.client != h.client || old.lane != h.lane || old.rejoin != rejoin || old.target != h.target {
			t.Fatalf("rejoin=%v: the old server reads %+v from %+v", rejoin, old, h)
		}
		got, err := readHello(bytes.NewReader(b), testKey, now)
		if err != nil || got != h {
			t.Fatalf("round trip: %+v, %v", got, err)
		}
		if got.budget() != 4<<20 {
			t.Fatalf("budget %d", got.budget())
		}
	}
}

func TestANewServerReadsAnOldHelloAsBefore(t *testing.T) {
	now := time.Now()
	old := oldHello{client: [8]byte{9, 9, 9, 9, 9, 9, 9, 200}, lane: 1, lanes: 3, rejoin: true,
		unix: uint64(now.Unix()), target: "example.org:443"}
	got, err := readHello(bytes.NewReader(old.marshal(testKey)), testKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.ext || got.group != 0 || got.budget() != 0 || got.lanes != 3 || !got.rejoin || got.lane != 1 || got.client != old.client {
		t.Fatalf("an old client's hello reads as %+v: no failure group and no budget may come of it", got)
	}
}
