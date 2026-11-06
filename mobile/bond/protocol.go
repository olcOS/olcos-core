// Package bond splits one TCP stream over several tunnels ("lanes") to the
// same server and joins it back there, so a single download uses the speed
// of every room and every protocol at once.
//
// The app's lanes are olcrtc tunnels, each a loopback SOCKS5 listener. For
// every connection an app opens, the client opens one sub-connection per lane
// to the bond server on the VPS (each lane's tunnel exits on that VPS and
// dials the server's public address, which is local to it), cuts the stream
// into numbered frames and hands each frame to a lane with room for it; the
// server puts the frames back in order, dials the real target once and does
// the same in the other direction.
//
// Every frame stays with its sender until the other side confirms it, so a
// lane that dies or stalls costs a resend over the others, not the stream:
// the stream ends only when every lane is gone for good.
//
// Every sub-connection opens with a hello signed by the server's tunnel key
// (HMAC-SHA256), so the public port relays nothing for anyone without it.
package bond

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	magic = "OLB1"
	// maxPayload is the largest frame body; frames are cut from what one read
	// returns, so small writes stay small.
	maxPayload = 16 * 1024
	// clockSkew is how far a hello's timestamp may be from the server's clock.
	clockSkew = 5 * time.Minute
	macSize   = sha256.Size
	frameHead = 6
	// ackMark and resetMark in a frame's length field make it an
	// acknowledgement or a reset.
	ackMark   = 0xFFFF
	resetMark = 0xFFFE
)

// Reply codes, one byte from the server after a hello.
const (
	replyOK          byte = 0
	replyUnreachable byte = 1
	replyRefused     byte = 2
)

var (
	errBadHello = errors.New("bond: bad hello")
	errBadKey   = errors.New("bond: key must be 64 hex digits")
	errBadFrame = errors.New("bond: bad frame")
)

// ParseKey decodes the tunnel key (64 hex digits, as in server.yaml).
func ParseKey(hexKey string) ([]byte, error) {
	key, err := hex.DecodeString(strings.TrimSpace(hexKey))
	if err != nil || len(key) != 32 {
		return nil, errBadKey
	}
	return key, nil
}

// hello opens every sub-connection:
//
//	magic[4] session[16] client[8] lane[1] lanes[1] unix[8] tlen[1] target[tlen] mac[32]
//
// mac = HMAC-SHA256(key, all bytes before it). The target ("host:port") rides
// in every hello, so the session can start on whichever arrives first. The
// client id (random per app session) and the lane number let the server
// carry what it learned about a lane over to the client's next stream.
//
// The top bit of lanes (rejoinFlag) marks a lane calling back a stream that
// is already open: the server must not start that session anew. A server
// from before the flag only stores lanes and never reads it, so it simply
// takes such a hello as it always did.
//
// The next bit (extFlag) says the client is one that reports its delivery
// point as soon as it has delivered all that arrived (so a sender may keep
// fewer than windowFrames frames out toward it), and that the byte carries
// the lane's failure group instead of the lane count: 0 its own, else the
// group+1 (lanes in one group, rooms on the same conference host, tend to
// fail together). The client id's last byte then is what the client asks the
// server to keep out toward it at most, every stream together, in
// budgetUnits (0: the server's default). No server reads the lane count, so
// one from before the flag takes such a hello as it always did, and keys
// what it learns by the client id, whose seven random bytes keep it apart.
// A client from before the flag counts its lanes there, far below 64.
type hello struct {
	session [16]byte
	client  [8]byte
	lane    uint8
	lanes   uint8 // below extFlag
	rejoin  bool
	ext     bool
	group   uint8 // with ext: 0 the lane's own, else group+1, below extFlag
	unix    uint64
	target  string
}

const (
	helloHead   = 4 + 16 + 8 + 2 + 8 + 1
	rejoinFlag  = 0x80
	extFlag     = 0x40
	budgetUnits = 128 << 10
)

// budget is what the client asked to have out toward it at most; 0: the
// server decides.
func (h hello) budget() int64 {
	if !h.ext {
		return 0
	}
	return int64(h.client[7]) * budgetUnits
}

// budgetCode is a budget as the client id's last byte carries it.
func budgetCode(n int64) byte {
	return byte(min(max((n+budgetUnits-1)/budgetUnits, 1), 255))
}

func (h hello) marshal(key []byte) ([]byte, error) {
	if len(h.target) == 0 || len(h.target) > 255 {
		return nil, fmt.Errorf("bond: target length %d", len(h.target))
	}
	lanes := min(h.lanes, extFlag-1)
	if h.ext {
		lanes = extFlag | min(h.group, extFlag-1)
	}
	if h.rejoin {
		lanes |= rejoinFlag
	}
	b := make([]byte, 0, helloHead+len(h.target)+macSize)
	b = append(b, magic...)
	b = append(b, h.session[:]...)
	b = append(b, h.client[:]...)
	b = append(b, h.lane, lanes)
	b = binary.BigEndian.AppendUint64(b, h.unix)
	b = append(b, byte(len(h.target)))
	b = append(b, h.target...)
	mac := hmac.New(sha256.New, key)
	mac.Write(b)
	return mac.Sum(b), nil
}

// readHello reads and verifies one hello. The key comes last so a caller can
// re-read it per connection (a rotated key takes effect at once).
func readHello(r io.Reader, key []byte, now time.Time) (hello, error) {
	var h hello
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
	h.lane, h.lanes = head[28], head[29]&^(rejoinFlag|extFlag)
	h.rejoin = head[29]&rejoinFlag != 0
	if h.ext = head[29]&extFlag != 0; h.ext {
		h.group, h.lanes = h.lanes, 0
	}
	h.unix = binary.BigEndian.Uint64(head[30:38])
	h.target = string(rest[:tlen])
	sent := time.Unix(int64(h.unix), 0)
	if sent.Before(now.Add(-clockSkew)) || sent.After(now.Add(clockSkew)) {
		return h, errBadHello
	}
	return h, nil
}

// Frames, in both directions after the reply:
//
//	data: seq[4] len[2] payload[len]   1 <= len <= maxPayload
//	end:  seq[4] 0[2]                  the direction is over; numbered like data
//	ack:  next[4] 0xFFFF[2] got[8]
//	rst:  0[4] 0xFFFE[2]               the stream failed; drop it at once
//
// An ack says that every frame below `next` reached the peer's local side, and
// that `got` bytes of data and end frames (headers included) arrived on the
// sub-connection the ack travels back on.
type frameKind uint8

const (
	kindData frameKind = iota
	kindEnd
	kindAck
	kindReset
)

type inFrame struct {
	kind    frameKind
	seq     uint32
	payload []byte
	got     int64
}

// frameSize is what a data or end frame adds to a sub-connection's tally.
func frameSize(payload []byte) int64 { return int64(frameHead + len(payload)) }

// appendFrame adds a data frame, or the end frame for an empty payload.
func appendFrame(b []byte, seq uint32, payload []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, seq)
	b = binary.BigEndian.AppendUint16(b, uint16(len(payload)))
	return append(b, payload...)
}

func appendAck(b []byte, next uint32, got int64) []byte {
	b = binary.BigEndian.AppendUint32(b, next)
	b = binary.BigEndian.AppendUint16(b, ackMark)
	return binary.BigEndian.AppendUint64(b, uint64(got))
}

func appendReset(b []byte) []byte {
	b = binary.BigEndian.AppendUint32(b, 0)
	return binary.BigEndian.AppendUint16(b, resetMark)
}

func readFrame(r io.Reader) (inFrame, error) {
	var head [frameHead]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return inFrame{}, err
	}
	f := inFrame{seq: binary.BigEndian.Uint32(head[:4])}
	switch n := int(binary.BigEndian.Uint16(head[4:])); {
	case n == ackMark:
		var got [8]byte
		if _, err := io.ReadFull(r, got[:]); err != nil {
			return inFrame{}, err
		}
		f.kind = kindAck
		f.got = int64(binary.BigEndian.Uint64(got[:]))
	case n == resetMark:
		f.kind = kindReset
	case n == 0:
		f.kind = kindEnd
	case n > maxPayload:
		return inFrame{}, errBadFrame
	default:
		f.kind = kindData
		f.payload = make([]byte, n)
		if _, err := io.ReadFull(r, f.payload); err != nil {
			return inFrame{}, err
		}
	}
	return f, nil
}
