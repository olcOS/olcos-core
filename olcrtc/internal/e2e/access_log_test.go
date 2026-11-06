//go:build !windows

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/openlibrecommunity/olcrtc/internal/app/session"
	"github.com/openlibrecommunity/olcrtc/internal/client"
)

// ai-generated: the whole file (access_log through a real tunnel: a line for
// every stream and every new UDP destination, named by the key's id).

const (
	accessWait   = 15 * time.Second
	accessSettle = 300 * time.Millisecond
	// accessLineShape is an Xray access line, which the agent's reader counts.
	accessLineShape = `^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d\.\d{6} from olcrtc accepted (tcp|udp):\S+ ` +
		`\[olcrtc-\S+ -> direct\] email: [0-9a-f]{16}@olcrtc$`
)

// accessFIFO is a FIFO a server writes its access lines to and a reader on it
// that holds it as the agent does and keeps the lines.
type accessFIFO struct {
	path  string
	mu    sync.Mutex
	lines []string
}

func startAccessFIFO(t *testing.T) *accessFIFO {
	t.Helper()
	path := filepath.Join(t.TempDir(), "access.fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("Mkfifo() error = %v", err)
	}
	// #nosec G304 -- the FIFO this test made.
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open the FIFO for reading: %v", err)
	}
	fifo := &accessFIFO{path: path}
	done := make(chan struct{})
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			fifo.mu.Lock()
			fifo.lines = append(fifo.lines, scanner.Text())
			fifo.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = file.Close()
		<-done
	})
	return fifo
}

func (f *accessFIFO) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.lines...)
}

// count is how many lines hold part.
func (f *accessFIFO) count(part string) int {
	n := 0
	for _, line := range f.snapshot() {
		if strings.Contains(line, part) {
			n++
		}
	}
	return n
}

// await waits until at least n lines hold part.
func (f *accessFIFO) await(t *testing.T, part string, n int) {
	t.Helper()
	deadline := time.Now().Add(accessWait)
	for time.Now().Before(deadline) {
		if f.count(part) >= n {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("%d lines hold %q after %s, want %d; the FIFO gave %q", f.count(part), part, accessWait, n, f.snapshot())
}

// requireShape holds every line the FIFO gave to the form of an Xray access
// line, and none of them to carry a key or the id of a key that did not pair.
func (f *accessFIFO) requireShape(t *testing.T, unpairedID string) {
	t.Helper()
	shape := regexp.MustCompile(accessLineShape)
	for _, line := range f.snapshot() {
		if !shape.MatchString(line) {
			t.Errorf("line %q is not an Xray access line", line)
		}
		for _, leak := range []string{testKeyHex, altKeyHex, unpairedID} {
			if strings.Contains(line, leak) {
				t.Errorf("line %q carries %q", line, leak)
			}
		}
	}
}

// A server with an access FIFO writes a line for every stream it opens, and
// the email of the line is the id of the key the client paired under, the one
// /stats counts the bytes under: the second key of the ring, not the first.
func TestAccessLogLineForEveryStreamNamesThePairedKey(t *testing.T) {
	access := startAccessFIFO(t)
	echoAddr := startEchoServer(t)
	tunnel := startRingTunnel(t, ringTunnelSpec{
		ring: []string{testKeyHex, altKeyHex}, clientKey: altKeyHex, accessLog: access.path,
		readyBudget: 30 * time.Second,
	})
	if !tunnel.ready {
		t.Fatal("client holding the second ring key never became ready")
	}
	for range 3 {
		echoOnce(t, tunnel.socksAddr, echoAddr, "olcrtc-access-log")
	}

	want := " accepted tcp:" + echoAddr + " [olcrtc-" + tunnel.provider + " -> direct] email: " +
		keyID(t, altKeyHex) + "@olcrtc"
	access.await(t, want, 3)
	time.Sleep(accessSettle)
	if got := access.count(want); got != 3 {
		t.Fatalf("lines for 3 streams = %d, want 3: %q", got, access.snapshot())
	}
	access.requireShape(t, keyID(t, testKeyHex))
}

// A UDP flow is a line when it is made, for a destination the session had not
// used: a second datagram to a destination goes in the flow it already has.
func TestAccessLogLineForEveryNewUDPDestination(t *testing.T) {
	access := startAccessFIFO(t)
	echoes := []string{startUDPEchoServer(t), startUDPEchoServer(t), startUDPEchoServer(t)}
	tunnel := startRingTunnel(t, ringTunnelSpec{
		ring: []string{testKeyHex, altKeyHex}, clientKey: altKeyHex, transport: transportVP8,
		accessLog: access.path, readyBudget: 30 * time.Second,
	})
	if !tunnel.ready {
		t.Fatal("client holding the second ring key never became ready over vp8channel")
	}
	udpConn, tcpConn, relayAddr := connectViaSOCKSUDP(t, tunnel.socksAddr)
	defer func() { _ = udpConn.Close() }()
	defer func() { _ = tcpConn.Close() }()

	buf := make([]byte, 4096)
	for _, echo := range append(echoes, echoes[0]) {
		payload := []byte("olcrtc-access-udp")
		if _, err := udpConn.WriteToUDP(buildSocksUDPPacket(t, echo, payload), relayAddr); err != nil {
			t.Fatalf("write socks udp packet: %v", err)
		}
		_ = udpConn.SetReadDeadline(time.Now().Add(10 * time.Second))
		n, _, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("read socks udp echo from %s: %v", echo, err)
		}
		if from, got := parseSocksUDPPacket(t, buf[:n]); from != echo || !bytes.Equal(got, payload) {
			t.Fatalf("udp echo from %s = %q from %s", echo, got, from)
		}
	}

	tail := " [olcrtc-" + tunnel.provider + " -> direct] email: " + keyID(t, altKeyHex) + "@olcrtc"
	for _, echo := range echoes {
		access.await(t, " accepted udp:"+echo+tail, 1)
	}
	time.Sleep(accessSettle)
	for _, echo := range echoes {
		if got := access.count(" accepted udp:" + echo + tail); got != 1 {
			t.Fatalf("lines for UDP destination %s = %d, want 1: %q", echo, got, access.snapshot())
		}
	}
	if got := access.count(" accepted udp:"); got != len(echoes) {
		t.Fatalf("UDP lines = %d, want %d, one per destination: %q", got, len(echoes), access.snapshot())
	}
	access.requireShape(t, keyID(t, testKeyHex))
}

// The key a server was given as one crypto.key, not a ring, is named by its id
// as well, and the setting reaches the server from the session config the CLI
// builds out of the YAML file (session.Config.AccessLog).
func TestAccessLogReachesTheServerFromTheSessionConfig(t *testing.T) {
	access := startAccessFIFO(t)
	echoAddr := startEchoServer(t)
	providerName, room := registerMemoryProvider(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	socksAddr := freeLocalAddr(ctx, t)

	srvCfg := failoverSessionConfig(session.ModeSrv, providerName, "", 0)
	srvCfg.AccessLog = access.path
	go func() { _ = session.Run(ctx, srvCfg) }()
	room.waitConnected(t, 1)

	ready := make(chan struct{})
	go func() {
		_ = client.RunWithReady(ctx, client.Config{
			Transport: transportData, TransportOptions: e2eTransportOptions(transportData),
			Provider: providerName, RoomURL: testRoom, KeyHex: testKeyHex,
			DeviceID: testClientDeviceID, LocalAddr: socksAddr, DNSServer: localDNSServer,
		}, func() { close(ready) })
	}()
	waitForReadyWithin(t, ready, 30*time.Second)
	echoOnce(t, socksAddr, echoAddr, "olcrtc-access-log-session")

	access.await(t, " accepted tcp:"+echoAddr+" [olcrtc-"+providerName+" -> direct] email: "+keyID(t, testKeyHex)+"@olcrtc", 1)
	access.requireShape(t, keyID(t, altKeyHex))
}
