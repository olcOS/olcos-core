// Package olcos is the gobind-facing surface of olcos-core. It is deliberately
// NOT named "mobile": gobind derives the Objective-C/Java prefix from the Go
// package name, and the upstream olcrtc package bound alongside it is already
// called mobile (MobileNew, MobileRuntime…). This package binds as OlcosNew,
// OlcosRuntime, OlcosTuneForNetworkExtension.
//
// Only gobind-safe types cross the boundary: strings, ints, bools, plain
// interfaces. Everything structured travels as JSON through Invoke, the same
// pattern libXray and Outline use, because gobind cannot bind slices of
// structs, maps or generics. Nothing here may panic: every entry point
// recovers and returns an error envelope.
//
// Bind together with the olcrtc upstream `mobile` package and olcos-ios
// `tunstack` in ONE `gomobile bind` invocation.
package olcos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"runtime/debug"
	"strconv"
	"sync"
	"time"

	"github.com/olcOS/olcos-core/engine"
	_ "github.com/olcOS/olcos-core/engine/olcrtc"
	_ "github.com/olcOS/olcos-core/engine/xray"
	xraycfg "github.com/olcOS/olcos-core/engine/xray"
	"github.com/olcOS/olcos-core/profile"
)

// Version of the core API (bumped on incompatible Invoke changes).
const Version = "0.1.0"

// LogWriter is implemented by the host to receive log lines.
type LogWriter interface {
	Write(level int, msg string)
}

// Runtime is the single core instance per process.
type Runtime struct {
	mu        sync.Mutex
	log       LogWriter
	tun       int
	socksPort int
	sess      engine.Session
	starting  bool
	// stopPending records a Stop that arrived while an engine was booting;
	// start closes the new session instead of publishing it.
	stopPending bool
}

// errStoppedDuringStart is returned by an engine.start that a concurrent
// engine.stop overtook.
var errStoppedDuringStart = errors.New("engine.start: stopped before the engine finished starting")

// New creates a Runtime. Call TuneForNetworkExtension before starting any
// engine when running inside an iOS packet tunnel.
func New() *Runtime { return &Runtime{tun: -1} }

// SetLogWriter installs the host log sink.
func (r *Runtime) SetLogWriter(w LogWriter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.log = w
}

// SetTunFD hands the TUN file descriptor to the core (or -1 to use SOCKS).
func (r *Runtime) SetTunFD(fd int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tun = fd
}

// SetSocksPort pins the SOCKS5 listener port for the next engine.start
// (0 = let the engine pick a free loopback port). Ignored when a TUN fd is
// set. Also reachable through the "socks_port" field of engine.start.
func (r *Runtime) SetSocksPort(port int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.socksPort = port
}

// start boots the engine selected by p.Kind. Only one session may run at a
// time; call Stop first to switch profiles. Health events are forwarded to the
// log writer as level-1 lines prefixed with "health:" until the platform
// adapters grow a dedicated callback. Unexported on
// purpose: engine.Profile / engine.Session are not gobind-representable, so
// the bound surface is Invoke("engine.start", …).
func (r *Runtime) start(p engine.Profile) (engine.Session, error) {
	// r.mu must not be held while the engine boots: the host callbacks
	// (TunFD, Log) take it too, and eng.Start calls them synchronously.
	r.mu.Lock()
	if r.sess != nil || r.starting {
		r.mu.Unlock()
		return nil, fmt.Errorf("engine already running; call engine.stop first")
	}
	r.starting = true
	r.stopPending = false
	r.mu.Unlock()

	var sess engine.Session
	eng, err := engine.Lookup(p.Kind)
	if err == nil {
		sess, err = eng.Start(context.Background(), p, &host{rt: r})
	}
	// A Stop that came in while the engine was booting found no session to
	// close; honour it here, or the engine would keep running after the user
	// stopped it.
	r.mu.Lock()
	r.starting = false
	stopped := r.stopPending
	r.stopPending = false
	if err == nil && !stopped {
		r.sess = sess
	}
	r.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if stopped {
		_ = sess.Close()
		return nil, errStoppedDuringStart
	}
	go func(ch <-chan engine.HealthEvent) {
		for ev := range ch {
			b, _ := json.Marshal(ev)
			r.emit(1, "health:"+string(b))
		}
	}(sess.Health())
	return sess, nil
}

// Stop closes the running session, if any. During an engine.start it marks the
// start as stopped; the starting call closes the session once it exists.
func (r *Runtime) Stop() error {
	r.mu.Lock()
	sess := r.sess
	r.sess = nil
	if sess == nil && r.starting {
		r.stopPending = true
	}
	r.mu.Unlock()
	if sess == nil {
		return nil
	}
	return sess.Close()
}

func (r *Runtime) emit(level int, msg string) {
	r.mu.Lock()
	w := r.log
	r.mu.Unlock()
	if w != nil {
		w.Write(level, msg)
	}
}

// host adapts Runtime to engine.Host.
type host struct{ rt *Runtime }

func (h *host) Protect(int) error { return nil }
func (h *host) TunFD() int {
	h.rt.mu.Lock()
	defer h.rt.mu.Unlock()
	return h.rt.tun
}
func (h *host) Log(level int, msg string) { h.rt.emit(level, msg) }
func (h *host) SocksPort() int {
	h.rt.mu.Lock()
	defer h.rt.mu.Unlock()
	return h.rt.socksPort
}
func (h *host) Notify(kind, payload string) {
	h.rt.emit(2, kind+":"+payload)
}

// TuneForNetworkExtension applies the Go memory policy for the ~50 MiB iOS
// packet-tunnel budget (docs/architecture.md): soft limit plus aggressive GC.
// limitBytes <= 0 restores defaults.
func TuneForNetworkExtension(limitBytes int64) {
	if limitBytes <= 0 {
		debug.SetMemoryLimit(-1)
		debug.SetGCPercent(100)
		return
	}
	debug.SetMemoryLimit(limitBytes)
	debug.SetGCPercent(20)
}

// FreeOSMemory forces a GC and returns memory to the OS; call periodically
// from the provider while connected.
func FreeOSMemory() { debug.FreeOSMemory() }

type envelope struct {
	OK     bool            `json:"ok"`
	Error  string          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

func reply(v any, err error) string {
	var e envelope
	if err != nil {
		e.Error = err.Error()
	} else {
		b, merr := json.Marshal(v)
		if merr != nil {
			e.Error = merr.Error()
		} else {
			e.OK = true
			e.Result = b
		}
	}
	out, _ := json.Marshal(e)
	return string(out)
}

// Invoke is the JSON method channel. Methods:
//
//	core.version           -> {"version":..., "engines":[...]}
//	profile.parse          in {"link":"vless://…|olcrtc://…"}      -> Profile
//	profile.export         in Profile                              -> {"link":…}
//	profile.parse_subscription in {"body":…}                       -> {"profiles":[…],"errors":[…]}
//	xray.render_client     in {"profile":Profile,"socks_port":n,"tun_fd":n,"log_level":…} -> {"config":…}
//	xray.render_server     in xray.ServerOptions (snake_case keys) -> {"config":…}
//	engine.start           in {"profile":Profile} or {"uri":"vless://…"} [+ "socks_port":n] -> {"socks_addr":…,"owns_tun":bool}
//	engine.stop                                                     -> {}
//	engine.stats                                                    -> engine.Stats
//	engine.probe           in {"profile":Profile} or {"uri":…} [+ "timeout_ms":n] -> {"rtt_ms":n}
//	                          plain TCP reachability of host:port; says nothing about the key.
//	engine.ping            in {"profile":Profile} or {"uri":…} [+ "timeout_ms":n, "url":…] -> {"rtt_ms":n}
//	                          HTTP round trip through a temporary Xray client — the same
//	                          measurement as the olcrtc core's mobile ping; fails on a bad key.
func (r *Runtime) Invoke(method string, jsonIn string) (out string) {
	defer func() {
		if rec := recover(); rec != nil {
			out = reply(nil, fmt.Errorf("panic in %s: %v", method, rec))
		}
	}()
	switch method {
	case "core.version":
		return reply(map[string]any{"version": Version, "engines": engine.Kinds()}, nil)

	case "profile.parse":
		var in struct {
			Link string `json:"link"`
		}
		if err := json.Unmarshal([]byte(jsonIn), &in); err != nil {
			return reply(nil, err)
		}
		p, err := profile.Parse(in.Link)
		return reply(p, err)

	case "profile.export":
		var p engine.Profile
		if err := json.Unmarshal([]byte(jsonIn), &p); err != nil {
			return reply(nil, err)
		}
		link, err := profile.ExportVLESS(p)
		return reply(map[string]string{"link": link}, err)

	case "profile.parse_subscription":
		var in struct {
			Body string `json:"body"`
		}
		if err := json.Unmarshal([]byte(jsonIn), &in); err != nil {
			return reply(nil, err)
		}
		ps, errs := profile.ParseSubscriptionBody(in.Body)
		es := make([]string, 0, len(errs))
		for _, e := range errs {
			es = append(es, e.Error())
		}
		return reply(map[string]any{"profiles": ps, "errors": es}, nil)

	case "xray.render_client":
		var in struct {
			Profile   engine.Profile `json:"profile"`
			SocksPort int            `json:"socks_port"`
			TunFD     *int           `json:"tun_fd"`
			LogLevel  string         `json:"log_level"`
		}
		if err := json.Unmarshal([]byte(jsonIn), &in); err != nil {
			return reply(nil, err)
		}
		opts := xraycfg.ClientOptions{SocksPort: in.SocksPort, TunFD: -1, LogLevel: in.LogLevel}
		if in.TunFD != nil {
			opts.TunFD = *in.TunFD
		}
		cfg, err := xraycfg.RenderClientConfig(in.Profile, opts)
		return reply(map[string]string{"config": string(cfg)}, err)

	case "xray.render_server":
		var in struct {
			Port        int      `json:"port"`
			ClientUUID  string   `json:"client_uuid"`
			ClientName  string   `json:"client_name"`
			Target      string   `json:"target"`
			ServerNames []string `json:"server_names"`
			PrivateKey  string   `json:"private_key"`
			ShortIDs    []string `json:"short_ids"`
			MaxTimeDiff int      `json:"max_time_diff_ms"`
			LogLevel    string   `json:"log_level"`
		}
		if err := json.Unmarshal([]byte(jsonIn), &in); err != nil {
			return reply(nil, err)
		}
		cfg, err := xraycfg.RenderServerConfig(xraycfg.ServerOptions{
			Port: in.Port, ClientUUID: in.ClientUUID, ClientName: in.ClientName, Target: in.Target,
			ServerNames: in.ServerNames, PrivateKey: in.PrivateKey, ShortIDs: in.ShortIDs,
			MaxTimeDiffMillis: in.MaxTimeDiff, LogLevel: in.LogLevel,
		})
		return reply(map[string]string{"config": string(cfg)}, err)

	case "engine.start":
		var in struct {
			Profile   *engine.Profile `json:"profile"`
			URI       string          `json:"uri"`
			SocksPort int             `json:"socks_port"`
			// Direct lists the destinations reached directly, never through
			// the server (xraycfg.ParamDirect).
			Direct string `json:"direct"`
		}
		if err := json.Unmarshal([]byte(jsonIn), &in); err != nil {
			return reply(nil, err)
		}
		p, err := profileFromInput(in.Profile, in.URI, "engine.start")
		if err != nil {
			return reply(nil, err)
		}
		if in.Direct != "" {
			if p.Params == nil {
				p.Params = map[string]string{}
			}
			p.Params[xraycfg.ParamDirect] = in.Direct
		}
		if in.SocksPort > 0 {
			r.SetSocksPort(in.SocksPort)
		}
		sess, err := r.start(p)
		if err != nil {
			return reply(nil, err)
		}
		return reply(map[string]any{"socks_addr": sess.SocksAddr(), "owns_tun": sess.OwnsTun()}, nil)

	case "engine.probe":
		var in struct {
			Profile   *engine.Profile `json:"profile"`
			URI       string          `json:"uri"`
			TimeoutMs int             `json:"timeout_ms"`
		}
		if err := json.Unmarshal([]byte(jsonIn), &in); err != nil {
			return reply(nil, err)
		}
		p, err := profileFromInput(in.Profile, in.URI, "engine.probe")
		if err != nil {
			return reply(nil, err)
		}
		rtt, err := probeTCP(p, in.TimeoutMs)
		if err != nil {
			return reply(nil, err)
		}
		return reply(map[string]any{"rtt_ms": rtt}, nil)

	case "engine.ping":
		var in struct {
			Profile   *engine.Profile `json:"profile"`
			URI       string          `json:"uri"`
			TimeoutMs int             `json:"timeout_ms"`
			URL       string          `json:"url"`
		}
		if err := json.Unmarshal([]byte(jsonIn), &in); err != nil {
			return reply(nil, err)
		}
		p, err := profileFromInput(in.Profile, in.URI, "engine.ping")
		if err != nil {
			return reply(nil, err)
		}
		if p.Kind != engine.KindXray {
			return reply(nil, fmt.Errorf("engine.ping: unsupported kind %q", p.Kind))
		}
		timeout := in.TimeoutMs
		if timeout <= 0 {
			timeout = 10000
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Millisecond)
		defer cancel()
		rtt, err := xraycfg.Ping(ctx, p, in.URL)
		if err != nil {
			return reply(nil, err)
		}
		return reply(map[string]any{"rtt_ms": rtt}, nil)

	case "engine.stop":
		return reply(map[string]any{}, r.Stop())

	case "engine.stats":
		r.mu.Lock()
		sess := r.sess
		r.mu.Unlock()
		if sess == nil {
			return reply(engine.Stats{}, nil)
		}
		return reply(sess.Stats(), nil)
	}
	return reply(nil, fmt.Errorf("unknown method %q", method))
}

// profileFromInput resolves the {"profile":…}|{"uri":…} pair shared by the
// engine.* methods.
func profileFromInput(p *engine.Profile, uri, method string) (engine.Profile, error) {
	switch {
	case p != nil:
		return *p, nil
	case uri != "":
		return profile.Parse(uri)
	default:
		return engine.Profile{}, fmt.Errorf("%s: profile or uri required", method)
	}
}

// probeTCP measures a plain TCP connect to the profile's endpoint. It is the
// cheap reachability check behind the app's ping / checkReady rows: it does
// not run xray-core, so it cannot detect a wrong UUID or public key — those
// surface as health events on a real engine.start. timeoutMs <= 0 means 5 s.
func probeTCP(p engine.Profile, timeoutMs int) (int64, error) {
	if p.Kind != engine.KindXray {
		return 0, fmt.Errorf("engine.probe: unsupported kind %q", p.Kind)
	}
	if p.Host == "" || p.Port <= 0 {
		return 0, errors.New("engine.probe: host and port required")
	}
	if timeoutMs <= 0 {
		timeoutMs = 5000
	}
	addr := net.JoinHostPort(p.Host, strconv.Itoa(p.Port))
	started := time.Now()
	conn, err := net.DialTimeout("tcp", addr, time.Duration(timeoutMs)*time.Millisecond)
	if err != nil {
		return 0, err
	}
	_ = conn.Close()
	return time.Since(started).Milliseconds(), nil
}
