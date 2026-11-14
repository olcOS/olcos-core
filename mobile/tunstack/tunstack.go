// Package tunstack is the tun2socks layer of the system-VPN mode of both
// apps: it translates the raw IP packets the system hands the app (iOS:
// NEPacketTunnelProvider, Android: VpnService) into TCP CONNECT streams
// against the loopback SOCKS5 listener of the engine running in the same
// process (the olcrtc core or the Xray engine).
//
// It is bound by gomobile into the SAME framework as upstream's mobile
// package (see ../go.mod); gomobile prefixes its Swift/ObjC names with
// "Tunstack" (TunstackNewTunnel, TunstackTunnel, TunstackTunWriterProtocol).
//
// Design constraints:
//
//   - The engines' SOCKS5 listeners are CONNECT-only (olcrtc internal/client/
//     socks.go rejects BIND and UDP ASSOCIATE), so UDP cannot be proxied.
//     DNS is answered in this layer instead (names.go): a lookup the system
//     sends over UDP goes to a resolver as a TCP stream through the listener
//     and its reply returns as UDP. All other UDP is dropped by construction.
//   - The SOCKS listener is loopback-only. The olcrtc core requires
//     credentials only for non-loopback listeners (mobile/config.go
//     validateRuntimeConfig); NewTunnelAuth presents the ones an app sets so
//     that no other app on the phone can use the port.
//
// Outline SDK API used (verified against pkg.go.dev at v0.0.20):
//
//	socks5.NewClient(streamEndpoint transport.StreamEndpoint) (*Client, error)
//	    // *Client implements transport.StreamDialer (DialStream)
//	transport.StreamDialerEndpoint{Dialer StreamDialer; Address string}
//	transport.TCPDialer{Dialer net.Dialer}
//	network.PacketProxy // NewSession(PacketResponseReceiver) (PacketRequestSender, error)
//	lwip2transport.ConfigureDevice(sd transport.StreamDialer, pp network.PacketProxy) (network.IPDevice, error)
//	network.IPDevice // io.ReadWriteCloser + MTU() int
//
// lwip2transport's device is a PER-PROCESS SINGLETON: a second ConfigureDevice
// call closes and reconfigures the first device. NewTunnel therefore refuses
// to build a second Tunnel while one is active — always Close() the previous
// one first (the provider does this in stopTunnel).
package tunstack

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/network"
	"github.com/Jigsaw-Code/outline-sdk/network/lwip2transport"
	"github.com/Jigsaw-Code/outline-sdk/transport"
	"github.com/Jigsaw-Code/outline-sdk/transport/socks5"

	// The bind command names github.com/openlibrecommunity/olcrtc/mobile
	// alongside ./tunstack, but no file in this module would otherwise import
	// the upstream module, and `go mod tidy` would drop its require line —
	// breaking `gomobile bind`. The blank import keeps the requirement direct.
	_ "github.com/openlibrecommunity/olcrtc/mobile"

	// Same reason for the olcos-core gobind package (Xray engine, binds as
	// Olcos*): it is the third package of the single bind.
	_ "github.com/olcOS/olcos-core/olcos"

	// Keep gomobile binding dependencies reachable (same pattern as upstream's
	// mobile package) so `go mod tidy` retains the pinned golang.org/x/mobile.
	_ "golang.org/x/mobile/bind"
)

// readBufferSize covers any IP packet lwIP can hand us (>= the device MTU).
const readBufferSize = 64 * 1024

// ErrTunnelActive is returned by NewTunnel while a previous Tunnel has not
// been Closed: the underlying lwIP device is a per-process singleton and a
// second ConfigureDevice would silently kill the first tunnel.
var ErrTunnelActive = errors.New("tunstack: a tunnel is already active in this process")

// Package-level singleton guard for the lwIP device (see ErrTunnelActive).
//
//nolint:gochecknoglobals // mirrors lwip2transport's own per-process singleton
var (
	activeMu sync.Mutex
	active   *Tunnel
)

// TunWriter receives outbound IP packets read from the lwIP device. The Swift
// side implements it (gomobile: TunstackTunWriterProtocol) by forwarding each
// packet to NEPacketTunnelFlow.writePackets.
//
// WritePacket is called from a dedicated Go goroutine. The packet slice is
// freshly allocated per call on the Go side, but gomobile only guarantees the
// foreign view of a []byte argument for the duration of the call — the Swift
// implementation must copy (or synchronously enqueue a copy) before returning.
type TunWriter interface {
	WritePacket(p []byte)
}

// Tunnel pumps IP packets between the packet-tunnel flow (via TunWriter /
// WritePacket) and the engine's loopback SOCKS5 listener.
type Tunnel struct {
	dev     network.IPDevice
	names   *names // answers the phone's name lookups (names.go)
	closed  atomic.Bool
	rxBytes atomic.Int64 // device -> TunWriter (toward the OS / packetFlow.writePackets)
	txBytes atomic.Int64 // WritePacket -> device (from the OS / packetFlow.readPackets)
}

// NewTunnel wires the lwIP network stack to socks5://socksHost:socksPort
// (TCP CONNECT only, no credentials — the listener is in-process loopback)
// and starts the outbound pump goroutine that feeds w with every IP packet
// the stack emits. Callers must Close() the returned Tunnel before creating
// another one; a concurrent second call fails with ErrTunnelActive.
func NewTunnel(socksHost string, socksPort int, w TunWriter) (*Tunnel, error) {
	return newTunnel(socksHost, socksPort, "", "", w)
}

// NewTunnelAuth is NewTunnel with a SOCKS5 username and password: a loopback
// listener that asks for them is closed to every other app on the device.
func NewTunnelAuth(socksHost string, socksPort int, user, pass string, w TunWriter) (*Tunnel, error) {
	return newTunnel(socksHost, socksPort, user, pass, w)
}

func newTunnel(socksHost string, socksPort int, user, pass string, w TunWriter) (*Tunnel, error) {
	return buildTunnel(socksHost, socksPort, user, pass, w, nil, defaultTiming())
}

// buildTunnel is newTunnel with what the tests replace: the authorities an
// HTTPS resolver's certificate is checked against (nil: the system's) and the
// waits of the lookups.
func buildTunnel(socksHost string, socksPort int, user, pass string, w TunWriter,
	roots *x509.CertPool, timing namesTiming,
) (*Tunnel, error) {
	if w == nil {
		return nil, errors.New("tunstack: TunWriter is required")
	}
	if socksHost == "" || socksPort < 1 || socksPort > 65535 {
		return nil, fmt.Errorf("tunstack: invalid SOCKS address %q:%d", socksHost, socksPort)
	}

	activeMu.Lock()
	defer activeMu.Unlock()
	if active != nil {
		return nil, ErrTunnelActive
	}

	listener := net.JoinHostPort(socksHost, strconv.Itoa(socksPort))

	// socks5.NewClient(transport.StreamEndpoint) (*Client, error) — v0.0.20.
	// The *Client implements transport.StreamDialer, which is exactly what
	// lwip2transport.ConfigureDevice wants for TCP flows.
	client, err := socks5.NewClient(&transport.StreamDialerEndpoint{
		Dialer:  &transport.TCPDialer{},
		Address: listener,
	})
	if err != nil {
		return nil, fmt.Errorf("tunstack: socks5 client: %w", err)
	}
	if user != "" || pass != "" {
		if err := client.SetCredentials([]byte(user), []byte(pass)); err != nil {
			return nil, fmt.Errorf("tunstack: socks5 credentials: %w", err)
		}
	}

	// Name lookups: answered here through the same listener, over UDP and
	// over TCP to port 53 alike; every other UDP packet is dropped.
	dial, err := socksDial(listener, user, pass)
	if err != nil {
		return nil, fmt.Errorf("tunstack: socks5 client for lookups: %w", err)
	}
	lookups := newNames(dial, roots, timing)

	dev, err := lwip2transport.ConfigureDevice(&nameDialer{r: lookups, next: client}, lookups)
	if err != nil {
		lookups.close()
		return nil, fmt.Errorf("tunstack: configure lwIP device: %w", err)
	}

	t := &Tunnel{dev: dev, names: lookups}
	active = t
	go t.readPump(w)
	// The first lookups of the phone find a resolver already chosen and its
	// connection made.
	go lookups.check(lookups.t.lookup)
	return t, nil
}

// readPump moves packets lwIP -> Swift until the device is closed. IPDevice
// permits one concurrent reader alongside one writer, and this goroutine is
// the only reader.
func (t *Tunnel) readPump(w TunWriter) {
	buf := make([]byte, readBufferSize)
	for {
		n, err := t.dev.Read(buf)
		if n > 0 {
			// Fresh allocation per packet: the callback crosses the gomobile
			// boundary and must not alias the reused read buffer.
			pkt := make([]byte, n)
			copy(pkt, buf[:n])
			t.rxBytes.Add(int64(n))
			w.WritePacket(pkt)
		}
		if err != nil {
			return // io.EOF after Close, or a fatal device error
		}
	}
}

// WritePacket feeds one inbound IP packet (from packetFlow.readPackets) into
// the lwIP stack. gomobile shares the caller's bytes only for the duration of
// the call; dev.Write consumes them synchronously (lwIP copies into its own
// buffers), so no extra copy is needed here.
func (t *Tunnel) WritePacket(p []byte) error {
	if t.closed.Load() {
		return errors.New("tunstack: tunnel is closed")
	}
	if len(p) == 0 {
		return nil
	}
	n, err := t.dev.Write(p)
	if err != nil {
		return fmt.Errorf("tunstack: device write: %w", err)
	}
	t.txBytes.Add(int64(n))
	return nil
}

// RxBytes returns the total bytes delivered device -> TunWriter (traffic
// flowing toward the OS). Safe to call from any thread.
func (t *Tunnel) RxBytes() int64 { return t.rxBytes.Load() }

// TxBytes returns the total bytes written into the device via WritePacket
// (traffic flowing from the OS). Safe to call from any thread.
func (t *Tunnel) TxBytes() int64 { return t.txBytes.Load() }

// NamesAnswered returns how many name lookups of the phone a resolver has
// answered through the session. Safe to call from any thread.
func (t *Tunnel) NamesAnswered() int64 { return t.names.answered.Load() }

// NamesFailed returns how many name lookups of the phone no resolver
// answered: the phone was told "server failure". Safe to call from any thread.
func (t *Tunnel) NamesFailed() int64 { return t.names.failed.Load() }

// NamesVia returns the resolver behind the latest answer and the way it was
// asked, as a line for the log: "cloudflare-dns.com over HTTPS" or "8.8.8.8
// over TCP". Empty until the first answer.
func (t *Tunnel) NamesVia() string {
	via, _ := t.names.via.Load().(string)
	return described(via)
}

// CheckNames asks a resolver for the root's name servers through the session
// and reports whether an answer came back within timeoutMs. An answer proves
// the session carries data both ways and that the phone has names; the
// address in the settings need not be reachable for it, only one of the
// resolvers this layer asks. It blocks: call it off the packet path.
func (t *Tunnel) CheckNames(timeoutMs int) bool {
	if t.closed.Load() || timeoutMs <= 0 {
		return false
	}
	return t.names.check(time.Duration(timeoutMs) * time.Millisecond)
}

// Close ends the lookups, shuts the lwIP device down (the pump goroutine then
// exits on io.EOF) and releases the per-process singleton slot. Idempotent.
func (t *Tunnel) Close() error {
	if !t.closed.CompareAndSwap(false, true) {
		return nil
	}
	// First: a reply must not reach the stack's UDP socket after the device
	// has freed it.
	t.names.close()
	err := t.dev.Close()
	activeMu.Lock()
	if active == t {
		active = nil
	}
	activeMu.Unlock()
	if err != nil {
		return fmt.Errorf("tunstack: close device: %w", err)
	}
	return nil
}
