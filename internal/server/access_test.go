package server

import (
	"errors"
	"net"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/crypto"
	"github.com/openlibrecommunity/olcrtc/internal/logger"
	"github.com/openlibrecommunity/olcrtc/internal/tunnelcore"
	"github.com/openlibrecommunity/olcrtc/internal/udpwire"
)

// ai-generated: the whole file (access_log: the line, the key id, the UDP set,
// the sink that never waits, and what the log never says).

const (
	accessTestKey = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	// accessTestKeyID is hex(sha256(the 32 bytes of accessTestKey))[:16], worked
	// out outside Go; the test below holds it to crypto.KeyIDFromHex.
	accessTestKeyID = "4773d12e2371bb93"
	// accessTestKeyTextHash is hex(sha256(the 64 characters of accessTestKey))[:16]:
	// what a line must not carry, since the id /stats counts the key under is the
	// hash of its bytes.
	accessTestKeyTextHash = "2a8abfa8cb990629"
	accessTestSession     = "session-a"
	accessTestPath        = "/run/olcrtc/access.fifo"
	accessTestCarrier     = "mtslink"
	accessTestStamp       = "2026/11/03 15:04:05.123456"
	accessTestPrefix      = accessTestStamp + " from olcrtc accepted "
	accessTestSuffix      = " [olcrtc-mtslink -> direct] email: 4773d12e2371bb93@olcrtc\n"
	accessTestNetworkTCP  = "tcp"
	accessTestNetworkUDP  = "udp"
	accessTestNoReader    = "no such device or address"
	accessTestSecretHost  = "destination-nobody-may-log.test"
)

// accessTestLine is the line a stream to destination is written as, spelled
// out here and not built by the code under test.
func accessTestLine(network, destination string) string {
	return accessTestPrefix + network + ":" + destination + accessTestSuffix
}

// fakeAccessFile records the lines written to it, and answers err instead
// when it is set.
type fakeAccessFile struct {
	mu     sync.Mutex
	taken  []string
	err    error
	closed bool
}

func (f *fakeAccessFile) Write(line []byte) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return 0, f.err
	}
	f.taken = append(f.taken, string(line))
	return len(line), nil
}

func (f *fakeAccessFile) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func (f *fakeAccessFile) setErr(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err = err
}

func (f *fakeAccessFile) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// accessRig is an access log over files that record, a meter that has
// accessTestSession bound to accessTestKeyID, and two clocks: the lines are
// stamped accessTestStamp whatever happens, and clock is the sink's, which a
// test moves to make the ten seconds between two tries pass.
type accessRig struct {
	log   *accessLog
	meter *meter
	clock time.Time
	// files are the files the sink opened, in order; opens counts the tries to
	// open one, the failed ones too, and openErr is what a try says while set.
	files   []*fakeAccessFile
	opens   int
	openErr error
}

func newAccessRig(t *testing.T) *accessRig {
	t.Helper()
	stamp := time.Date(2026, time.November, 3, 15, 4, 5, 123456000, time.UTC)
	rig := &accessRig{meter: newMeter(), clock: stamp}
	rig.meter.bind(accessTestSession, accessTestKeyID)
	rig.log = newAccessLog(accessTestPath, accessTestCarrier, rig.meter.keyOf)
	if rig.log == nil {
		t.Fatal("newAccessLog() = nil for a path")
	}
	rig.log.now = func() time.Time { return stamp }
	rig.log.sink.now = func() time.Time { return rig.clock }
	rig.log.sink.open = func(string) (accessFile, error) {
		rig.opens++
		if rig.openErr != nil {
			return nil, rig.openErr
		}
		file := &fakeAccessFile{}
		rig.files = append(rig.files, file)
		return file, nil
	}
	t.Cleanup(rig.log.close)
	return rig
}

// lines is every line written to any file the sink opened.
func (r *accessRig) lines() []string {
	var all []string
	for _, file := range r.files {
		file.mu.Lock()
		all = append(all, file.taken...)
		file.mu.Unlock()
	}
	return all
}

func requireLines(t *testing.T, got, want []string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("lines written:\n%q\nwant:\n%q", got, want)
	}
}

func TestAccessLineIsXraysForm(t *testing.T) {
	rig := newAccessRig(t)
	rig.log.tcp(accessTestSession, "example.com", 443)
	rig.log.tcp(accessTestSession, "2001:db8::1", 8443)
	rig.log.udp(accessTestSession, "203.0.113.9", 6881)
	got := rig.lines()
	requireLines(t, got, []string{
		accessTestLine(accessTestNetworkTCP, "example.com:443"),
		accessTestLine(accessTestNetworkTCP, "[2001:db8::1]:8443"),
		accessTestLine(accessTestNetworkUDP, "203.0.113.9:6881"),
	})
	// The shape an Xray access line has, which the agent's reader counts.
	shape := regexp.MustCompile(`^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d\.\d{6} from \S+ accepted (tcp|udp):\S+ ` +
		`\[\S+ -> \S+\] email: \S+@\S+\n$`)
	for _, line := range got {
		if !shape.MatchString(line) {
			t.Errorf("line %q is not an Xray access line", line)
		}
	}
}

func TestAccessLineNamesTheKeyByItsIDAndNeverByTheKey(t *testing.T) {
	id, err := crypto.KeyIDFromHex(accessTestKey)
	if err != nil {
		t.Fatalf("KeyIDFromHex() error = %v", err)
	}
	if id != accessTestKeyID {
		t.Fatalf("KeyIDFromHex(%s) = %s, want the id %s the lines are tested with", accessTestKey, id, accessTestKeyID)
	}
	rig := newAccessRig(t)
	rig.log.tcp(accessTestSession, "example.com", 443)
	rig.log.udp(accessTestSession, "example.net", 53)
	lines := rig.lines()
	if len(lines) != 2 {
		t.Fatalf("lines = %q, want 2", lines)
	}
	for _, line := range lines {
		if !strings.Contains(line, " email: "+accessTestKeyID+"@olcrtc\n") {
			t.Errorf("line %q does not end with the key's id as its email", line)
		}
		for _, leak := range []string{accessTestKey, strings.ToUpper(accessTestKey), accessTestKeyTextHash} {
			if strings.Contains(line, leak) {
				t.Errorf("line %q carries %q, which is not the key's id", line, leak)
			}
		}
	}
}

// A line is written only for what it can say whole: a session with no key has
// no email, a host with anything but the characters of a name or an address
// could write lines of its own into the log, and a line longer than one atomic
// write would be torn.
func TestAccessLogWritesNothingItCannotSayWhole(t *testing.T) {
	hosts := map[string]string{
		"a space":             "a b.test",
		"a line break":        "a.test\n2026/11/03 15:04:05.123456 from olcrtc accepted tcp:b.test:1 [x -> y] email: z@olcrtc",
		"a tab":               "a\t.test",
		"a NUL":               "a\x00.test",
		"a name beyond ASCII": "пример.рф",
		"nothing":             "",
		"a zone":              "fe80::1%eth0",
		"a slash":             "a/b.test",
		"brackets":            "[::1]",
		"a very long name":    strings.Repeat("a", maxAccessHost+1),
	}
	for name, host := range hosts {
		t.Run(name, func(t *testing.T) {
			rig := newAccessRig(t)
			rig.log.tcp(accessTestSession, host, 443)
			rig.log.udp(accessTestSession, host, 443)
			requireLines(t, rig.lines(), nil)
		})
	}

	t.Run("a session with no key", func(t *testing.T) {
		rig := newAccessRig(t)
		rig.log.tcp("session-without-a-key", "example.com", 443)
		rig.log.udp("session-without-a-key", "example.com", 443)
		requireLines(t, rig.lines(), nil)
	})

	t.Run("the longest name there is fits in one write", func(t *testing.T) {
		rig := newAccessRig(t)
		rig.log.tcp(accessTestSession, strings.Repeat("h", maxAccessHost), 443)
		if got := len(rig.lines()); got != 1 {
			t.Fatalf("lines for a name of %d characters = %d, want 1", maxAccessHost, got)
		}
	})

	t.Run("a line longer than one atomic write", func(t *testing.T) {
		rig := newAccessRig(t)
		long := newAccessLog(accessTestPath, strings.Repeat("c", maxAccessHost), rig.meter.keyOf)
		long.sink = rig.log.sink
		long.tcp(accessTestSession, strings.Repeat("h", maxAccessHost), 443)
		requireLines(t, rig.lines(), nil)
	})

	t.Run("a carrier that is not a word", func(t *testing.T) {
		rig := newAccessRig(t)
		odd := newAccessLog(accessTestPath, "tele most\n", rig.meter.keyOf)
		odd.sink = rig.log.sink
		odd.now = rig.log.now
		odd.tcp(accessTestSession, "example.com", 443)
		requireLines(t, rig.lines(), []string{
			accessTestPrefix + "tcp:example.com:443 [olcrtc-" + unknownCarrier +
				" -> direct] email: " + accessTestKeyID + "@olcrtc\n",
		})
	})
}

func TestNoAccessLogPathIsNoAccessLog(t *testing.T) {
	if log := newAccessLog("", accessTestCarrier, nil); log != nil {
		t.Fatalf("newAccessLog(\"\") = %v, want nil: the log that is off", log)
	}
	var off *accessLog
	off.tcp(accessTestSession, "example.com", 443)
	off.udp(accessTestSession, "example.com", 443)
	off.forget(accessTestSession)
	off.close()
}

func TestUDPDestinationIsWrittenOncePerSession(t *testing.T) {
	rig := newAccessRig(t)
	rig.meter.bind("session-b", accessTestKeyID)
	rig.log.udp(accessTestSession, "203.0.113.9", 6881)
	rig.log.udp(accessTestSession, "203.0.113.9", 6881) // the same destination again
	rig.log.udp(accessTestSession, "203.0.113.9", 6882) // another port is another destination
	rig.log.udp(accessTestSession, "2001:db8::1", 6881)
	rig.log.udp("session-b", "203.0.113.9", 6881) // another session has its own set
	requireLines(t, rig.lines(), []string{
		accessTestLine(accessTestNetworkUDP, "203.0.113.9:6881"),
		accessTestLine(accessTestNetworkUDP, "203.0.113.9:6882"),
		accessTestLine(accessTestNetworkUDP, "[2001:db8::1]:6881"),
		accessTestLine(accessTestNetworkUDP, "203.0.113.9:6881"),
	})
}

func TestTCPStreamsAreNotDeduplicated(t *testing.T) {
	rig := newAccessRig(t)
	for range 3 {
		rig.log.tcp(accessTestSession, "example.com", 443)
	}
	if got := len(rig.lines()); got != 3 {
		t.Fatalf("lines for 3 streams to one destination = %d, want 3", got)
	}
}

// The set stops growing at maxUDPDestinations. What it cannot hold is written
// each time: a line too many for a destination used before, never a line
// short for a new one.
func TestUDPDestinationSetStopsGrowingAtItsCap(t *testing.T) {
	rig := newAccessRig(t)
	host := func(i int) string { return "h" + strconv.Itoa(i) + ".test" }
	for i := range maxUDPDestinations {
		rig.log.udp(accessTestSession, host(i), 443)
	}
	if got := len(rig.lines()); got != maxUDPDestinations {
		t.Fatalf("lines for %d destinations = %d", maxUDPDestinations, got)
	}
	if got := len(rig.log.seen[accessTestSession]); got != maxUDPDestinations {
		t.Fatalf("the set holds %d destinations, want %d", got, maxUDPDestinations)
	}

	rig.log.udp(accessTestSession, host(maxUDPDestinations), 443)
	rig.log.udp(accessTestSession, host(maxUDPDestinations), 443)
	if got := len(rig.lines()); got != maxUDPDestinations+2 {
		t.Fatalf("lines after two flows to a destination the full set does not hold = %d, want %d",
			got, maxUDPDestinations+2)
	}
	if got := len(rig.log.seen[accessTestSession]); got != maxUDPDestinations {
		t.Fatalf("the full set grew to %d", got)
	}

	rig.log.udp(accessTestSession, host(0), 443)
	if got := len(rig.lines()); got != maxUDPDestinations+2 {
		t.Fatalf("a destination the set holds was written again: %d lines", got)
	}
}

func TestSessionsRememberedAreBoundedAndForgottenWhenTheyEnd(t *testing.T) {
	rig := newAccessRig(t)
	session := func(i int) string { return "session-" + strconv.Itoa(i) }
	for i := range maxAccessSessions {
		rig.meter.bind(session(i), accessTestKeyID)
		rig.log.udp(session(i), "a.test", 1)
	}
	if got := len(rig.log.seen); got != maxAccessSessions {
		t.Fatalf("sessions remembered = %d, want %d", got, maxAccessSessions)
	}

	// A session past the bound is not remembered: each of its flows is written.
	extra := session(maxAccessSessions)
	rig.meter.bind(extra, accessTestKeyID)
	before := len(rig.lines())
	rig.log.udp(extra, "a.test", 1)
	rig.log.udp(extra, "a.test", 1)
	if got := len(rig.lines()) - before; got != 2 {
		t.Fatalf("lines for a session past the bound = %d, want both flows written", got)
	}
	if got := len(rig.log.seen); got != maxAccessSessions {
		t.Fatalf("sessions remembered grew to %d", got)
	}

	// A session that ends makes room, and the next one is remembered.
	rig.log.forget(session(0))
	rig.log.udp(extra, "a.test", 1)
	before = len(rig.lines())
	rig.log.udp(extra, "a.test", 1)
	if got := len(rig.lines()) - before; got != 0 {
		t.Fatalf("a remembered session's destination was written again (%d lines)", got)
	}
}

func TestTrackPeerCloseForgetsTheSessionsDestinations(t *testing.T) {
	rig := newAccessRig(t)
	s := &Server{access: rig.log, peerStats: map[string]peerStat{}}
	rig.log.udp(accessTestSession, "a.test", 1)
	if len(rig.log.seen) != 1 {
		t.Fatalf("sessions remembered = %d, want 1", len(rig.log.seen))
	}
	s.trackPeerClose(accessTestSession, "closed")
	if len(rig.log.seen) != 0 {
		t.Fatalf("sessions remembered after the session ended = %d, want 0", len(rig.log.seen))
	}
}

func TestAccessSinkOpensTheFIFOAtMostEveryTenSeconds(t *testing.T) {
	rig := newAccessRig(t)
	rig.openErr = errors.New(accessTestNoReader)
	rig.log.tcp(accessTestSession, "a.test", 1)
	rig.clock = rig.clock.Add(accessReopenEvery - time.Second)
	rig.log.tcp(accessTestSession, "b.test", 1)
	rig.log.tcp(accessTestSession, "c.test", 1)
	if rig.opens != 1 || len(rig.lines()) != 0 {
		t.Fatalf("after 9 s: %d opens and %d lines, want 1 open and none", rig.opens, len(rig.lines()))
	}

	rig.clock = rig.clock.Add(time.Second)
	rig.log.tcp(accessTestSession, "d.test", 1)
	if rig.opens != 2 || len(rig.lines()) != 0 {
		t.Fatalf("at 10 s: %d opens and %d lines, want 2 opens and none", rig.opens, len(rig.lines()))
	}

	// A reader has come: the next try opens, and from then on every line goes
	// through the file that is open, with no try of its own.
	rig.openErr = nil
	rig.clock = rig.clock.Add(accessReopenEvery)
	rig.log.tcp(accessTestSession, "e.test", 1)
	rig.log.tcp(accessTestSession, "f.test", 1)
	if rig.opens != 3 {
		t.Fatalf("opens = %d, want 3: the file that is open is kept", rig.opens)
	}
	requireLines(t, rig.lines(), []string{
		accessTestLine(accessTestNetworkTCP, "e.test:1"),
		accessTestLine(accessTestNetworkTCP, "f.test:1"),
	})
}

func TestAccessSinkDropsALineOnAFullPipeAndKeepsTheFile(t *testing.T) {
	rig := newAccessRig(t)
	rig.log.tcp(accessTestSession, "a.test", 1)
	rig.files[0].setErr(errAccessFull)
	rig.log.tcp(accessTestSession, "dropped.test", 1)
	if rig.opens != 1 || rig.files[0].isClosed() {
		t.Fatalf("a full pipe cost the file: %d opens, closed = %v", rig.opens, rig.files[0].isClosed())
	}
	rig.files[0].setErr(nil)
	rig.log.tcp(accessTestSession, "b.test", 1)
	requireLines(t, rig.lines(), []string{
		accessTestLine(accessTestNetworkTCP, "a.test:1"),
		accessTestLine(accessTestNetworkTCP, "b.test:1"),
	})
}

// A write that fails, as one to a pipe whose reader left does, closes the
// file; the next line opens the path again, at once if the last try was long
// ago, and no later than the ten seconds' rule says if it was not.
func TestAccessSinkOpensAgainAfterAFailedWrite(t *testing.T) {
	rig := newAccessRig(t)
	rig.log.tcp(accessTestSession, "a.test", 1)
	rig.files[0].setErr(errors.New("broken pipe"))
	rig.clock = rig.clock.Add(time.Minute)
	rig.log.tcp(accessTestSession, "lost.test", 1)
	if !rig.files[0].isClosed() {
		t.Fatal("the file whose write failed was not closed")
	}
	rig.log.tcp(accessTestSession, "b.test", 1)
	if rig.opens != 2 || len(rig.files) != 2 {
		t.Fatalf("opens = %d, files = %d, want the path opened again", rig.opens, len(rig.files))
	}
	requireLines(t, rig.lines(), []string{
		accessTestLine(accessTestNetworkTCP, "a.test:1"),
		accessTestLine(accessTestNetworkTCP, "b.test:1"),
	})
}

func TestAccessSinkWritesNothingAfterItIsClosed(t *testing.T) {
	rig := newAccessRig(t)
	rig.log.tcp(accessTestSession, "a.test", 1)
	rig.log.close()
	rig.clock = rig.clock.Add(time.Hour)
	rig.log.tcp(accessTestSession, "b.test", 1)
	if !rig.files[0].isClosed() || rig.opens != 1 {
		t.Fatalf("closed = %v, opens = %d, want the file closed and the path not opened again",
			rig.files[0].isClosed(), rig.opens)
	}
	requireLines(t, rig.lines(), []string{accessTestLine(accessTestNetworkTCP, "a.test:1")})
}

// A path that cannot be opened is said once for as long as it stays so, and
// the words say why, not where anyone went.
func TestAccessSinkSaysAFailureOnceWhileItGoesOn(t *testing.T) {
	logs := captureLog(t)
	rig := newAccessRig(t)
	rig.openErr = errors.New(accessTestNoReader)
	for range 5 {
		rig.log.tcp(accessTestSession, "a.test", 1)
		rig.clock = rig.clock.Add(accessReopenEvery)
	}
	if got := strings.Count(logs.String(), accessTestNoReader); got != 1 {
		t.Fatalf("the failure was logged %d times, want once:\n%s", got, logs.String())
	}

	rig.openErr = nil
	rig.log.tcp(accessTestSession, "a.test", 1)
	if !strings.Contains(logs.String(), "access_log: writing to "+accessTestPath) {
		t.Fatalf("a path that opened was not said to:\n%s", logs.String())
	}

	// A failure after a success is a new one, and is said again.
	rig.files[0].setErr(errors.New("broken pipe"))
	rig.log.tcp(accessTestSession, "lost.test", 1)
	rig.openErr = errors.New(accessTestNoReader)
	rig.clock = rig.clock.Add(accessReopenEvery)
	rig.log.tcp(accessTestSession, "a.test", 1)
	if got := strings.Count(logs.String(), accessTestNoReader); got != 2 {
		t.Fatalf("the failure was logged %d times in all, want twice:\n%s", got, logs.String())
	}
}

// No destination goes to a log from here, at any verbosity, in any failure the
// log has, and neither does a key.
func TestAccessLogNeverWritesADestinationOrAKeyToTheLog(t *testing.T) {
	logs := captureLog(t)
	logger.SetVerbose(true)
	rig := newAccessRig(t)
	rig.meter.bind("session-secret", accessTestKeyID)
	flows := func() {
		rig.log.tcp("session-secret", accessTestSecretHost, 4321)
		rig.log.udp("session-secret", accessTestSecretHost, 4321)
		rig.log.udp("session-secret", accessTestSecretHost, 4322)
		rig.clock = rig.clock.Add(accessReopenEvery)
	}

	rig.openErr = errors.New(accessTestNoReader) // no reader
	flows()
	rig.openErr = nil
	flows()
	rig.files[0].setErr(errAccessFull) // a reader that does not read
	flows()
	rig.files[0].setErr(errors.New("broken pipe")) // a reader that left
	flows()
	flows()

	out := logs.String()
	if !strings.Contains(out, "access_log") {
		t.Fatalf("the failures were not logged at all:\n%s", out)
	}
	for _, leak := range []string{accessTestSecretHost, ":4321", ":4322", "4321", accessTestKey} {
		if strings.Contains(out, leak) {
			t.Fatalf("the log names %q:\n%s", leak, out)
		}
	}
}

// A stream is a line only once its dial has succeeded: a target the egress
// policy refuses and a name that does not resolve have none.
func TestDispatchWritesALineOnlyForAStreamThatOpened(t *testing.T) {
	rig := newAccessRig(t)
	rig.meter.bind("log-sid", accessTestKeyID)
	lookup := &stubLookup{answers: map[string][]net.IP{
		testSecretHost: {net.IPv4(127, 0, 0, 1)},
		testPublicHost: {net.ParseIP(testPublicIP)},
	}}
	rec := &dialRecorder{}
	s := &Server{resolver: lookup, dialTarget: rec.dial, meter: rig.meter, access: rig.log}

	if ack := connectThrough(t, s, testSecretHost, testTargetPort); ack != tunnelcore.ConnectAckHostUnreachable {
		t.Fatalf("blocked target ack = 0x%02x, want unreachable", ack)
	}
	if ack := connectThrough(t, s, testNowhereHost, testTargetPort); ack != tunnelcore.ConnectAckHostUnreachable {
		t.Fatalf("unresolvable target ack = 0x%02x, want unreachable", ack)
	}
	requireLines(t, rig.lines(), nil)

	if ack := connectThrough(t, s, testPublicHost, testTargetPort); ack != tunnelcore.ConnectAckOK {
		t.Fatalf("public target ack = 0x%02x, want ok", ack)
	}
	requireLines(t, rig.lines(), []string{
		accessTestLine(accessTestNetworkTCP, testPublicHost+":"+strconv.Itoa(testTargetPort)),
	})
}

// A UDP flow is a line when it is made, for a destination the session had not
// used; a target the egress policy refuses never becomes a flow.
func TestUDPFlowIsALineWhenItIsMadeForANewDestination(t *testing.T) {
	rig := newAccessRig(t)
	s := &Server{
		maxUDPFlows: 8, udpFlows: map[serverUDPKey]*serverUDPFlow{},
		unsafeAllowPrivateTargets: true, meter: rig.meter, access: rig.log,
	}
	t.Cleanup(s.closeAllUDPFlows)
	open := func(flowID uint64, port uint16) {
		t.Helper()
		_, err := s.getOrCreateUDPFlow(serverUDPKey{peerID: testUDPPeerID, flowID: flowID},
			udpwire.Endpoint{Host: "127.0.0.1", Port: port}, accessTestSession, nil)
		if err != nil {
			t.Fatalf("getOrCreateUDPFlow(%d) error = %v", flowID, err)
		}
	}
	open(1, 40001)
	open(2, 40001) // a second flow to a destination the session used
	open(3, 40002)
	open(1, 40009) // the flow already exists: nothing is made, nothing is written
	requireLines(t, rig.lines(), []string{
		accessTestLine(accessTestNetworkUDP, "127.0.0.1:40001"),
		accessTestLine(accessTestNetworkUDP, "127.0.0.1:40002"),
	})

	refusing := &Server{maxUDPFlows: 8, udpFlows: map[serverUDPKey]*serverUDPFlow{}, meter: rig.meter, access: rig.log}
	_, err := refusing.getOrCreateUDPFlow(serverUDPKey{peerID: testUDPPeerID, flowID: 9},
		udpwire.Endpoint{Host: "127.0.0.1", Port: 40003}, accessTestSession, nil)
	if !errors.Is(err, errBlockedTarget) {
		t.Fatalf("a flow to loopback error = %v, want %v", err, errBlockedTarget)
	}
	if got := len(rig.lines()); got != 2 {
		t.Fatalf("a refused flow wrote a line: %d lines", got)
	}
}

// What a server runs with: Run reads the key of a session from the meter, so a
// session that has not been bound has no line.
func TestMeterKeyOfIsTheKeyASessionWasBoundTo(t *testing.T) {
	m := newMeter()
	m.bind("bound", accessTestKeyID)
	if got := m.keyOf("bound"); got != accessTestKeyID {
		t.Fatalf("keyOf(bound) = %q, want %q", got, accessTestKeyID)
	}
	if got := m.keyOf("unbound"); got != "" {
		t.Fatalf("keyOf(unbound) = %q, want nothing", got)
	}
	var none *meter
	if got := none.keyOf("bound"); got != "" {
		t.Fatalf("keyOf on no meter = %q, want nothing", got)
	}
}
