// The access log.
//
// An operator's agent counts what the users of an exit open, to tell abuse
// from use, and for Xray it reads Xray's own access lines. A server started
// with `access_log: <path>` writes the same lines for olcRTC: one for every
// stream it opens, once the dial to the destination has succeeded, and one for
// every UDP destination a session had not used before. The line is Xray's:
//
//	<time> from olcrtc accepted <tcp|udp>:<host:port> [olcrtc-<carrier> -> direct] email: <key id>@olcrtc
//
// The key id is the one /stats counts the key under, hex(sha256(key))[:16]
// (crypto.KeyIDFromHex), never the key. The path is a FIFO the agent made and
// reads, and nothing here may ever slow the tunnel down or send a destination
// anywhere else: the FIFO is opened without waiting, a write that finds the
// pipe full drops the line, and the destination is in no log.
//
// ai-generated: the whole file (access_log).

package server

import (
	"errors"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/logger"
)

const (
	// accessLineLayout is the time layout of Xray's access lines: local time
	// to the microsecond.
	accessLineLayout = "2006/01/02 15:04:05.000000"
	// accessEmailSuffix follows the key id in the email of a line.
	accessEmailSuffix = "@olcrtc"
	// accessReopenEvery is how seldom the path is opened again once it could
	// not be, or once its reader had left.
	accessReopenEvery = 10 * time.Second
	// maxAccessLine bounds a line, newline included. A write of up to 512
	// bytes to a pipe is atomic on every system there is (Linux's PIPE_BUF is
	// 4096), so a line is there whole or not at all; a longer one is not
	// written.
	maxAccessLine = 512
	// maxAccessHost is the longest host a line names: a DNS name has at most
	// 253 characters.
	maxAccessHost = 255
	// maxUDPDestinations bounds the destinations remembered for one session.
	maxUDPDestinations = 4096
	// maxAccessSessions bounds the sessions whose destinations are remembered:
	// twice what the server holds at once.
	maxAccessSessions = 2 * maxPeerSessions
	// unknownCarrier names a carrier that is not a plain word.
	unknownCarrier = "unknown"

	accessNetworkTCP = "tcp"
	accessNetworkUDP = "udp"
)

var (
	// errAccessFull is what a write says when the pipe has no room: the line
	// is dropped and the file kept.
	errAccessFull = errors.New("access log pipe is full")
	// errNotFIFO is a path that is not a FIFO, or no longer is.
	errNotFIFO = errors.New("not a FIFO")
)

// accessFile is the write end of the access log.
type accessFile interface {
	// Write writes line whole, or writes nothing and says errAccessFull.
	Write(line []byte) (int, error)
	Close() error
}

// accessSink writes lines to the FIFO at path. It opens the FIFO when the
// first line is to be written and again, at most every accessReopenEvery, when
// that did not work or the reader left; a line it cannot write is dropped. It
// never waits.
type accessSink struct {
	path string
	now  func() time.Time
	open func(path string) (accessFile, error)

	mu      sync.Mutex
	file    accessFile
	tried   time.Time // when the path was last opened or tried
	failure string    // why the last try failed, said once while it goes on failing
	closed  bool
}

func newAccessSink(path string) *accessSink {
	return &accessSink{path: path, now: time.Now, open: openAccessFIFO}
}

// write puts line on the FIFO, or drops it.
func (s *accessSink) write(line []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || (s.file == nil && !s.reopen()) {
		return
	}
	_, err := s.file.Write(line)
	if err == nil || errors.Is(err, errAccessFull) {
		return
	}
	logger.Infof("access_log: %s: closed after a failed write: %v", s.path, err)
	_ = s.file.Close()
	s.file = nil
}

// reopen opens the path unless it was tried less than accessReopenEvery ago,
// and reports whether there is a file now. A failure is logged once, for as
// long as it stays the same. Called with mu held.
func (s *accessSink) reopen() bool {
	now := s.now()
	if !s.tried.IsZero() && now.Sub(s.tried) < accessReopenEvery {
		return false
	}
	s.tried = now
	file, err := s.open(s.path)
	if err != nil {
		if reason := err.Error(); reason != s.failure {
			s.failure = reason
			logger.Warnf("access_log: %s: %s; trying again every %s", s.path, reason, accessReopenEvery)
		}
		return false
	}
	s.file, s.failure = file, ""
	logger.Infof("access_log: writing to %s", s.path)
	return true
}

// close ends the sink: nothing is written, or opened, after it.
func (s *accessSink) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.file != nil {
		_ = s.file.Close()
		s.file = nil
	}
}

// accessLog is the server's side of access_log. A nil *accessLog is the log
// that is off: every method of it does nothing.
type accessLog struct {
	sink  *accessSink
	keyOf func(sessionID string) string
	now   func() time.Time
	// tail follows the destination in every line.
	tail string

	mu sync.Mutex
	// seen holds, per session, the UDP destinations it has used: at most
	// maxUDPDestinations of them, for at most maxAccessSessions sessions.
	seen map[string]map[string]struct{}
}

// newAccessLog is the log of a server whose carrier is carrier, writing to the
// FIFO at path, with keyOf telling the key id of a session; nil for no path.
func newAccessLog(path, carrier string, keyOf func(sessionID string) string) *accessLog {
	if path == "" {
		return nil
	}
	if !safeAccessHost(carrier) {
		carrier = unknownCarrier
	}
	return &accessLog{
		sink: newAccessSink(path), keyOf: keyOf, now: time.Now,
		tail: " [olcrtc-" + carrier + " -> direct] email: ",
		seen: make(map[string]map[string]struct{}),
	}
}

// tcp records a stream of session to host:port, whose dial succeeded.
func (a *accessLog) tcp(sessionID, host string, port int) {
	if a == nil || !safeAccessHost(host) {
		return
	}
	a.write(accessNetworkTCP, sessionID, net.JoinHostPort(host, strconv.Itoa(port)))
}

// udp records a UDP flow of session to host:port, unless the session has used
// that destination before.
func (a *accessLog) udp(sessionID, host string, port uint16) {
	if a == nil || !safeAccessHost(host) {
		return
	}
	destination := net.JoinHostPort(host, strconv.Itoa(int(port)))
	if a.firstUse(sessionID, destination) {
		a.write(accessNetworkUDP, sessionID, destination)
	}
}

// firstUse reports whether destination is new to the session, and remembers
// it. Once the session's set is full a destination it does not hold is
// reported every time, a line too many for one that was used before and never
// a line short for a new one.
func (a *accessLog) firstUse(sessionID, destination string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	used := a.seen[sessionID]
	if used == nil {
		if len(a.seen) >= maxAccessSessions {
			return true
		}
		used = make(map[string]struct{})
		a.seen[sessionID] = used
	}
	if _, ok := used[destination]; ok {
		return false
	}
	if len(used) < maxUDPDestinations {
		used[destination] = struct{}{}
	}
	return true
}

// write builds the line of a stream and hands it to the sink. A session whose
// key is not known has no email to write, and a line too long for one atomic
// write is not written.
func (a *accessLog) write(network, sessionID, destination string) {
	keyID := a.keyOf(sessionID)
	if keyID == "" {
		return
	}
	line := a.now().AppendFormat(make([]byte, 0, 160), accessLineLayout)
	line = append(line, " from olcrtc accepted "...)
	line = append(line, network...)
	line = append(line, ':')
	line = append(line, destination...)
	line = append(line, a.tail...)
	line = append(line, keyID...)
	line = append(line, accessEmailSuffix...)
	line = append(line, '\n')
	if len(line) > maxAccessLine {
		return
	}
	a.sink.write(line)
}

// forget drops what the log remembers of a session that has ended.
func (a *accessLog) forget(sessionID string) {
	if a == nil {
		return
	}
	a.mu.Lock()
	delete(a.seen, sessionID)
	a.mu.Unlock()
}

// close ends the log: the FIFO is closed and nothing is written after it.
func (a *accessLog) close() {
	if a != nil {
		a.sink.close()
	}
}

// safeAccessHost reports whether host can stand in a line as it is: a name or
// an address, made of the characters of those and nothing else. A peer chooses
// its destination, and one that carried a space or a line break would write
// lines of its own into the log.
func safeAccessHost(host string) bool {
	if host == "" || len(host) > maxAccessHost {
		return false
	}
	for i := range len(host) {
		if !accessHostByte(host[i]) {
			return false
		}
	}
	return true
}

func accessHostByte(c byte) bool {
	letter := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
	digit := c >= '0' && c <= '9'
	return letter || digit || c == '.' || c == '-' || c == '_' || c == ':'
}
