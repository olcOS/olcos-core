// Package engine defines the transport-agnostic contract every olcOS engine
// (olcrtc over WebRTC, Xray VLESS+REALITY, ...) implements, plus the small
// Host callback surface the platform adapter (NEPacketTunnelProvider,
// VpnService, desktop daemon) provides.
//
// This package is internal to the Go core. It is NOT exported through gobind
// directly: gobind cannot express slices of structs, maps or generics, so the
// platform-facing API lives in package mobile as a JSON string channel.
package engine

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
)

// Kind identifies an engine implementation.
type Kind string

const (
	KindOlcrtc Kind = "olcrtc"
	KindXray   Kind = "xray"
)

// ErrNotImplemented is returned by engines whose runtime integration is not
// wired yet.
var ErrNotImplemented = errors.New("engine: not implemented")

// Profile is the parsed, engine-neutral connection profile. Engine-specific
// fields live in Params (string→string, gobind-friendly when marshalled).
type Profile struct {
	Kind Kind   `json:"kind"`
	Name string `json:"name,omitempty"`
	// Host and Port are the remote endpoint. For olcrtc Host carries the
	// carrier name (jitsi/telemost) and Room the room id.
	Host string `json:"host,omitempty"`
	Port int    `json:"port,omitempty"`
	Room string `json:"room,omitempty"`
	// Secret is the client credential: olcrtc key or VLESS UUID.
	Secret string            `json:"secret,omitempty"`
	Params map[string]string `json:"params,omitempty"`
}

// Validate checks the fields shared by all engines.
func (p Profile) Validate() error {
	switch p.Kind {
	case KindOlcrtc, KindXray:
	default:
		return fmt.Errorf("engine: unknown kind %q", p.Kind)
	}
	if p.Secret == "" {
		return errors.New("engine: empty secret")
	}
	return nil
}

// Host is implemented by the platform adapter. Every method must be safe to
// call from any goroutine and must never panic across the language boundary.
type Host interface {
	// Protect excludes a socket from the VPN routing (Android VpnService.protect).
	// iOS/macOS adapters return nil without doing anything.
	Protect(fd int) error
	// TunFD returns the file descriptor of the TUN device, or -1 when the
	// adapter wants the engine to expose a local SOCKS5 listener instead.
	TunFD() int
	// Log receives engine log lines. level follows syslog-ish ordering:
	// 0 error, 1 warn, 2 info, 3 debug.
	Log(level int, msg string)
	// Notify delivers structured events (health, stats) as JSON.
	Notify(kind string, payloadJSON string)
}

// SocksPortHinter is an optional Host extension. When the adapter needs the
// SOCKS5 listener on a port it chose itself (the iOS app's proxy mode hands
// the port to every engine), it returns that port; 0 keeps the engine's own
// free-port selection. Engines must type-assert, never require it.
type SocksPortHinter interface {
	SocksPort() int
}

// Stats is the snapshot reported to the UI hero picture. The picture follows
// MEASURED throughput and prints no numbers; keep the fields raw.
type Stats struct {
	BytesUp   int64 `json:"bytes_up"`
	BytesDown int64 `json:"bytes_down"`
	RTTMillis int64 `json:"rtt_ms"`
	Connected bool  `json:"connected"`
}

// HealthEvent mirrors the olcOS HealthReason contract (docs/diagnostic-messages.md
// in olcos-ios). Reason values must stay in sync with the Swift enum; never rename.
type HealthEvent struct {
	Reason string `json:"reason"`
	Raw    string `json:"raw,omitempty"`
}

// Session is a started engine.
type Session interface {
	// SocksAddr returns "127.0.0.1:port" when the engine exposes a local
	// SOCKS5 CONNECT listener and OwnsTun is false.
	SocksAddr() string
	// OwnsTun is true when the engine reads/writes the TUN fd itself
	// (Xray native tun inbound). Then no tun2socks glue is needed.
	OwnsTun() bool
	Stats() Stats
	Health() <-chan HealthEvent
	Close() error
}

// Engine is a transport implementation.
type Engine interface {
	Kind() Kind
	Start(ctx context.Context, p Profile, h Host) (Session, error)
}

var (
	regMu    sync.RWMutex
	registry = map[Kind]Engine{}
)

// Register makes an engine available to Lookup. Called from engine packages'
// init functions; duplicate registration is a programming error.
func Register(e Engine) {
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := registry[e.Kind()]; dup {
		panic(fmt.Sprintf("engine: duplicate registration of %q", e.Kind()))
	}
	registry[e.Kind()] = e
}

// Lookup returns the registered engine for kind.
func Lookup(kind Kind) (Engine, error) {
	regMu.RLock()
	defer regMu.RUnlock()
	e, ok := registry[kind]
	if !ok {
		return nil, fmt.Errorf("engine: %q is not registered", kind)
	}
	return e, nil
}

// Kinds lists registered engines in stable order.
func Kinds() []Kind {
	regMu.RLock()
	defer regMu.RUnlock()
	out := make([]Kind, 0, len(registry))
	for k := range registry {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
