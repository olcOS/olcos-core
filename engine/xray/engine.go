package xray

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"

	applog "github.com/xtls/xray-core/app/log"
	xlog "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"

	"github.com/olcOS/olcos-core/engine"
)

// Engine implements engine.Engine for VLESS + REALITY via an embedded
// xray-core instance: core.LoadConfig("json") → core.New → Start.
//
// The trimmed feature set is registered in distro.go. Memory policy for the
// iOS packet tunnel (mobile.TuneForNetworkExtension) must be applied by the
// host BEFORE Start; this package does not touch runtime/debug itself.
type Engine struct{}

func init() {
	engine.Register(Engine{})
	// Route xray's console log handler into the active host instead of stdout.
	// Only one xray instance runs per process, so a package-level sink is enough.
	_ = applog.RegisterHandlerCreator(applog.LogType_Console,
		func(applog.LogType, applog.HandlerCreatorOptions) (xlog.Handler, error) {
			return hostLogHandler{}, nil
		})
}

var (
	sinkMu   sync.RWMutex
	logSink  engine.Host
	active   *session   // receives health events derived from xray logs
	instance sync.Mutex // serialises Start/Close; one instance per process
)

type hostLogHandler struct{}

func (hostLogHandler) Handle(msg xlog.Message) {
	sinkMu.RLock()
	h, s := logSink, active
	sinkMu.RUnlock()
	handle(h, s, msg)
}

// handle runs with the sink and session captured at entry; the session may be
// closed by the time a health event is ready, which emit tolerates.
func handle(h engine.Host, s *session, msg xlog.Message) {
	if h == nil {
		return
	}
	level := 2
	if gm, ok := msg.(*xlog.GeneralMessage); ok {
		switch gm.Severity {
		case xlog.Severity_Error:
			level = 0
		case xlog.Severity_Warning:
			level = 1
		case xlog.Severity_Debug:
			level = 3
		}
	}
	text := msg.String()
	h.Log(level, text)
	if level > 2 || s == nil {
		return
	}
	if reason, ok := classify(text); ok && s.emitter.offer(reason) {
		ev := engine.HealthEvent{Reason: reason, Raw: text}
		if !s.emit(ev) {
			return
		}
		if b, err := json.Marshal(ev); err == nil {
			h.Notify("health", string(b))
		}
	}
}

// Kind reports engine.KindXray.
func (Engine) Kind() engine.Kind { return engine.KindXray }

// Start boots xray-core for profile p. When h.TunFD() >= 0 the native tun
// inbound is used (variant A) and the fd is handed over through the process
// environment as xray-core expects; otherwise a SOCKS5 CONNECT listener is
// opened on a free 127.0.0.1 port (variant B, consumed by olcos-ios tunstack).
func (Engine) Start(ctx context.Context, p engine.Profile, h engine.Host) (engine.Session, error) {
	if h == nil {
		return nil, errors.New("xray: nil host")
	}
	// info, not warning: dial failures are info-level in xray-core (see health.go).
	opts := ClientOptions{TunFD: -1, LogLevel: "info"}
	if fd := h.TunFD(); fd >= 0 {
		opts.TunFD = fd
		if err := os.Setenv(platform.TunFdKey, strconv.Itoa(fd)); err != nil {
			return nil, fmt.Errorf("xray: %w", err)
		}
	} else {
		port := 0
		if hp, ok := h.(engine.SocksPortHinter); ok {
			port = hp.SocksPort()
		}
		if port <= 0 {
			var err error
			if port, err = freePort(); err != nil {
				return nil, err
			}
		}
		opts.SocksPort = port
	}
	raw, err := RenderClientConfig(p, opts)
	if err != nil {
		return nil, err
	}

	instance.Lock()
	defer instance.Unlock()

	cfg, err := core.LoadConfig("json", bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("xray: load config: %w", err)
	}
	inst, err := core.NewWithContext(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("xray: new instance: %w", err)
	}
	if err := inst.Start(); err != nil {
		_ = inst.Close()
		return nil, fmt.Errorf("xray: start: %w", err)
	}
	s := &session{
		inst:    inst,
		socks:   "",
		ownsTun: opts.TunFD >= 0,
		health:  make(chan engine.HealthEvent, 8),
		emitter: newHealthEmitter(5 * time.Second),
		started: time.Now(),
	}
	sinkMu.Lock()
	logSink, active = h, s
	sinkMu.Unlock()
	if !s.ownsTun {
		s.socks = net.JoinHostPort("127.0.0.1", strconv.Itoa(opts.SocksPort))
	}
	if m, ok := inst.GetFeature(stats.ManagerType()).(stats.Manager); ok {
		s.stats = m
	}
	h.Log(2, "xray: started ("+describe(p)+")")
	return s, nil
}

func describe(p engine.Profile) string {
	return fmt.Sprintf("%s:%d sni=%q fp=%q", p.Host, p.Port, p.Params[ParamSNI], p.Params[ParamFingerprint])
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("xray: no free port: %w", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

type session struct {
	inst    *core.Instance
	socks   string
	ownsTun bool
	stats   stats.Manager
	health  chan engine.HealthEvent
	emitter *healthEmitter
	started time.Time
	once    sync.Once
	closeMu sync.Mutex
	closed  bool
}

func (s *session) SocksAddr() string { return s.socks }
func (s *session) OwnsTun() bool     { return s.ownsTun }

// Stats reads the outbound "proxy" traffic counters enabled by the rendered
// policy block. Values are raw bytes; the UI must not print them.
func (s *session) Stats() engine.Stats {
	st := engine.Stats{Connected: !s.isClosed()}
	if s.stats == nil {
		return st
	}
	if c := s.stats.GetCounter("outbound>>>proxy>>>traffic>>>uplink"); c != nil {
		st.BytesUp = c.Value()
	}
	if c := s.stats.GetCounter("outbound>>>proxy>>>traffic>>>downlink"); c != nil {
		st.BytesDown = c.Value()
	}
	return st
}

func (s *session) Health() <-chan engine.HealthEvent { return s.health }

func (s *session) isClosed() bool {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	return s.closed
}

// emit queues a health event unless the session is closed. The check and the
// send share closeMu with Close, so a log line that captured this session just
// before Close can never send on the closed channel (a send on a closed
// channel panics, and inside the packet tunnel that kills the extension).
func (s *session) emit(ev engine.HealthEvent) bool {
	s.closeMu.Lock()
	defer s.closeMu.Unlock()
	if s.closed {
		return false
	}
	deliver(s.health, ev)
	return true
}

// Close stops the instance and releases the log sink. Safe to call twice.
func (s *session) Close() error {
	var err error
	s.once.Do(func() {
		s.closeMu.Lock()
		s.closed = true
		s.closeMu.Unlock()
		sinkMu.Lock()
		if active == s {
			logSink, active = nil, nil
		}
		sinkMu.Unlock()
		err = s.inst.Close()
		s.closeMu.Lock()
		close(s.health)
		s.closeMu.Unlock()
		_ = os.Unsetenv(platform.TunFdKey)
	})
	return err
}
