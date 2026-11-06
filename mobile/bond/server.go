package bond

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	helloTimeout = 15 * time.Second
	dialTimeout  = 20 * time.Second
	maxSessions  = 4096
	// spentFor keeps a finished session's id, so a lane that comes late is
	// turned away and a replayed hello (valid for clockSkew either way)
	// cannot open the same request again.
	spentFor = 2 * clockSkew
	// The log: a summary every logEvery, and at most warnBurst lines of one
	// kind a minute (the rest are counted in the summary).
	logEvery  = 5 * time.Minute
	warnBurst = 5
	// serverBudget is what the server keeps out toward one client, every
	// stream together, unless the client asks for another figure (its hello
	// says so), at most serverBudgetMax: the phone's reorder buffers live in
	// its memory, the VPN extension's ~50 MB among them.
	serverBudget    = 4 << 20
	serverBudgetMax = 64 << 20
)

var errBlockedTarget = errors.New("bond: target not allowed")

// blockedRanges is what the bond server refuses to dial for a peer: the same
// list the olcrtc core's exit refuses (internal/server/egress.go), so a
// stream joined here reaches no more of the server than a plain olcrtc
// stream does.
var blockedRanges = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/3"),
}

// Serve runs the server side: it accepts lanes on listenAddr, checks each
// hello against the tunnel key in keyPath (bare hex like ~/.olcrtc_key, or a
// server.yaml; read per hello, so a rotated key needs no restart), dials each
// session's target once and joins the stream. dns ("host:port") resolves the
// targets; empty means the system resolver. It returns when the listener
// fails.
func Serve(listenAddr, keyPath, dns string) error {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	log.Printf("bond: listening on %s", ln.Addr())
	key := func() ([]byte, error) { return readKeyFile(keyPath) }
	s := newServer(key, allowedDialer(dns))
	s.peerOK = localPeer
	return s.serve(ln)
}

type server struct {
	key  func() ([]byte, error)
	dial func(ctx context.Context, target string) (net.Conn, error)
	// peerOK says whether a connection may speak at all; nil lets anyone.
	peerOK func(net.Addr) bool

	mu       sync.Mutex
	sessions map[[16]byte]*serverSession
	active   int
	stats    map[statsKey]*laneStats
	budgets  map[[8]byte]*clientBudget

	log serverLog
}

type clientBudget struct {
	b    *memBudget
	refs int
}

// clientKey is the client id without what the hello carries in it: one
// client stays one, whatever budget it asks for.
func clientKey(h hello) [8]byte {
	k := h.client
	if h.ext {
		k[7] = 0
	}
	return k
}

type statsKey struct {
	client [8]byte
	lane   uint8
}

type serverSession struct {
	target string
	ready  chan struct{} // closed once the target dial is decided
	err    error
	stripe *stripe
}

func newServer(key func() ([]byte, error), dial func(context.Context, string) (net.Conn, error)) *server {
	return &server{key: key, dial: dial, sessions: make(map[[16]byte]*serverSession),
		stats: make(map[statsKey]*laneStats), budgets: make(map[[8]byte]*clientBudget)}
}

// budgetFor is the budget one client's streams share, taken once per
// stream (releaseBudget gives it back).
func (s *server) budgetFor(h hello) *memBudget {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := clientKey(h)
	cb, ok := s.budgets[k]
	if !ok {
		cb = &clientBudget{b: newBudget(serverBudget)}
		s.budgets[k] = cb
	}
	if n := h.budget(); n > 0 {
		cb.b.limit.Store(min(n, serverBudgetMax))
	}
	cb.refs++
	return cb.b
}

func (s *server) releaseBudget(h hello) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := clientKey(h)
	if cb, ok := s.budgets[k]; ok {
		if cb.refs--; cb.refs <= 0 {
			delete(s.budgets, k)
		}
	}
}

func (s *server) serve(ln net.Listener) error {
	stop := make(chan struct{})
	defer close(stop)
	go s.summarize(stop)
	go s.reportLanes(stop)
	for {
		c, err := ln.Accept()
		if err != nil {
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		go s.handle(c)
	}
}

func (s *server) handle(c net.Conn) {
	if s.peerOK != nil && !s.peerOK(c.RemoteAddr()) {
		_ = c.Close()
		return
	}
	key, err := s.key()
	if err != nil {
		s.log.warn("key", "bond: no key: %v", err)
		_ = c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(helloTimeout))
	h, err := readHello(c, key, time.Now())
	if err != nil {
		// Nothing for anyone without the key: no reply at all.
		_ = c.Close()
		return
	}
	_ = c.SetReadDeadline(time.Time{})
	sess, first := s.join(h)
	if sess == nil {
		if h.rejoin {
			s.log.turnedAway(h)
		} else {
			s.log.warn("full", "bond: %d sessions open; a new one was turned away", maxSessions)
		}
		_, _ = c.Write([]byte{replyRefused})
		_ = c.Close()
		return
	}
	if first {
		go s.open(h, sess)
	}
	select {
	case <-sess.ready:
	case <-time.After(dialTimeout + 5*time.Second):
		_ = c.Close()
		return
	}
	switch {
	case sess.err != nil:
		_, _ = c.Write([]byte{replyUnreachable})
		_ = c.Close()
		return
	case sess.target != h.target || sess.stripe.isOver():
		_, _ = c.Write([]byte{replyRefused})
		_ = c.Close()
		return
	}
	if _, err := c.Write([]byte{replyOK}); err != nil {
		_ = c.Close()
		return
	}
	if sess.stripe.add(int(h.lane), c, s.laneStats(h)) && h.rejoin {
		s.log.calledBack()
	}
}

// laneStats is the server's knowledge of one client's lane, shared by that
// client's streams.
func (s *server) laneStats(h hello) *laneStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := statsKey{client: clientKey(h), lane: h.lane}
	group := int(h.lane)
	if h.ext && h.group > 0 {
		group = int(h.group) - 1
	}
	if st, ok := s.stats[k]; ok {
		st.setGroup(group)
		return st
	}
	if len(s.stats) >= maxSessions {
		for k, st := range s.stats {
			if r, _ := st.load(); r == 0 {
				delete(s.stats, k)
			}
		}
	}
	st := newLaneStats(fmt.Sprintf("client %x lane %d", h.client[:2], int(h.lane)+1))
	st.setGroup(group)
	s.stats[k] = st
	return st
}

// join finds or starts the session a hello names; nil when it may not be
// joined: too many are open, or a lane calls back a stream this process
// never saw. That stream was open on a server that has since restarted;
// opening it here would dial its target a second time and splice the middle
// of one conversation onto a new one, while turning the lane away ends the
// client's stream at once so the app can retry.
func (s *server) join(h hello) (*serverSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[h.session]; ok {
		return sess, false
	}
	if h.rejoin || s.active >= maxSessions {
		return nil, false
	}
	sess := &serverSession{target: h.target, ready: make(chan struct{})}
	s.sessions[h.session] = sess
	s.active++
	return sess, true
}

func (s *server) open(h hello, sess *serverSession) {
	start := time.Now()
	s.log.started()
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	target, err := s.dial(ctx, h.target)
	cancel()
	if err != nil {
		sess.err = err
		close(sess.ready)
		s.log.failed(h.session, time.Since(start), "its target could not be reached", "")
	} else {
		sess.stripe = newStripe(target)
		sess.stripe.budget = s.budgetFor(h)
		sess.stripe.peerAcksEarly = h.ext
		close(sess.ready)
		if err := sess.stripe.run(); err != nil {
			why, detail := failure(err)
			s.log.failed(h.session, time.Since(start), why, detail)
		}
		s.releaseBudget(h)
	}
	s.mu.Lock()
	s.active--
	s.mu.Unlock()
	time.AfterFunc(spentFor, func() {
		s.mu.Lock()
		delete(s.sessions, h.session)
		s.mu.Unlock()
	})
}

// failure names why a session failed without the error's own text, which
// for the target's connection carries the target's address: why is one of a
// few reasons, which the summary counts, and detail what only the session's
// own line says (the lane and numbers of a bad frame).
func failure(err error) (why, detail string) {
	var bad *badFrameError
	switch {
	case errors.Is(err, errLanesLost):
		return "every lane was gone for " + orphanWait.String(), ""
	case errors.Is(err, errPeerReset):
		return "the client reset it", ""
	case errors.As(err, &bad):
		return "a bad frame", bad.where()
	case errors.Is(err, errBadFrame):
		return "a bad frame", ""
	default:
		return "its target connection failed (" + connFailure(err) + ")", ""
	}
}

// connFailure is the kind of error that ended the target's connection, told
// from the error's type and code, never its text.
func connFailure(err error) string {
	var ne net.Error
	switch {
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "EOF"
	case errors.Is(err, syscall.ECONNRESET):
		return "reset by peer"
	case errors.Is(err, syscall.EPIPE):
		return "broken pipe"
	case errors.Is(err, syscall.ETIMEDOUT), errors.As(err, &ne) && ne.Timeout():
		return "timed out"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(err, syscall.EHOSTUNREACH), errors.Is(err, syscall.ENETUNREACH):
		return "unreachable"
	default:
		return "other"
	}
}

// summarize logs a summary every logEvery until stop closes.
// reportLanes writes one line per client lane every reportEvery while it
// carries: from the server's side, which room moves the bytes for a client and
// which one only stalls.
func (s *server) reportLanes(stop <-chan struct{}) {
	t := time.NewTicker(reportEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			s.mu.Lock()
			stats := make([]*laneStats, 0, len(s.stats))
			for _, st := range s.stats {
				stats = append(stats, st)
			}
			s.mu.Unlock()
			for _, st := range stats {
				if line := st.report(now); line != "" {
					log.Print(line)
				}
			}
		}
	}
}

func (s *server) summarize(stop <-chan struct{}) {
	t := time.NewTicker(logEvery)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			s.mu.Lock()
			open := s.active
			s.mu.Unlock()
			if line := s.log.summary(open); line != "" {
				log.Print(line)
			}
		}
	}
}

// serverLog is what the operator sees of the sessions: why one failed and
// after how long, a lane turned away, and the counts every logEvery. It never
// names a target, a key or anything a stream carries. Lines of one kind are
// limited to warnBurst a minute, so a restart under a thousand open streams
// writes a few lines, not thousands; the summary counts the rest.
type serverLog struct {
	mu       sync.Mutex
	sessions int            // started since the last summary
	failures map[string]int // of them, those that failed, by reason
	back     int            // rejoins taken back
	refused  int            // rejoins turned away
	held     int            // lines not written
	minute   time.Time      // when the current minute of lines began
	written  map[string]int // lines of each kind written in it
}

func (l *serverLog) started() {
	l.mu.Lock()
	l.sessions++
	l.mu.Unlock()
}

func (l *serverLog) calledBack() {
	l.mu.Lock()
	l.back++
	l.mu.Unlock()
}

// failed counts a failed session under why and writes its line, which adds
// detail when there is one.
func (l *serverLog) failed(session [16]byte, took time.Duration, why, detail string) {
	l.mu.Lock()
	if l.failures == nil {
		l.failures = make(map[string]int)
	}
	l.failures[why]++
	l.mu.Unlock()
	line := why
	if detail != "" {
		line += " " + detail
	}
	l.warn(why, "bond: session %x failed after %s: %s", session[:4], took.Round(time.Millisecond), line)
}

// turnedAway counts a rejoin for a stream this server does not know and
// writes its line; lanes are counted from 1, as the app counts its rooms.
func (l *serverLog) turnedAway(h hello) {
	l.mu.Lock()
	l.refused++
	l.mu.Unlock()
	l.warn("rejoin", "bond: lane %d called back session %x, which this server does not know (it restarted since): turned away",
		int(h.lane)+1, h.session[:4])
}

// warn writes a line unless warnBurst lines of its kind were written this
// minute already.
func (l *serverLog) warn(kind, format string, args ...any) {
	now := time.Now()
	l.mu.Lock()
	if now.Sub(l.minute) >= time.Minute {
		l.minute, l.written = now, make(map[string]int)
	}
	ok := l.written[kind] < warnBurst
	if ok {
		l.written[kind]++
	} else {
		l.held++
	}
	l.mu.Unlock()
	if ok {
		log.Printf(format, args...)
	}
}

// summary is the line for the period since the last one, and starts the
// next; empty when nothing happened and nothing is open.
func (l *serverLog) summary(open int) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.sessions == 0 && l.back == 0 && l.refused == 0 && l.held == 0 && open == 0 {
		return ""
	}
	failed, reasons := 0, make([]string, 0, len(l.failures))
	for why, n := range l.failures {
		failed += n
		reasons = append(reasons, fmt.Sprintf("%s: %d", why, n))
	}
	slices.Sort(reasons)
	line := fmt.Sprintf("bond: last %s: %d sessions, %d open, %d failed", logEvery, l.sessions, open, failed)
	if failed > 0 {
		line += " (" + strings.Join(reasons, "; ") + ")"
	}
	line += fmt.Sprintf(", %d lanes called back, %d turned away, %d lines held back", l.back, l.refused, l.held)
	l.sessions, l.failures, l.back, l.refused, l.held = 0, nil, 0, 0, 0
	return line
}

// allowedDialer dials a target's first IPv4 address outside the blocked
// ranges, like the olcrtc exit.
func allowedDialer(dns string) func(context.Context, string) (net.Conn, error) {
	resolver := net.DefaultResolver
	if dns != "" {
		resolver = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, network, dns)
		}}
	}
	return func(ctx context.Context, target string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(target)
		if err != nil {
			return nil, err
		}
		var addrs []netip.Addr
		if ip, err := netip.ParseAddr(host); err == nil {
			addrs = []netip.Addr{ip}
		} else if addrs, err = resolver.LookupNetIP(ctx, "ip4", host); err != nil {
			return nil, err
		}
		var dialer net.Dialer
		lastErr := errBlockedTarget
		for _, addr := range addrs {
			addr = addr.Unmap()
			if !addr.Is4() || blocked(addr) {
				continue
			}
			conn, err := dialer.DialContext(ctx, "tcp4", net.JoinHostPort(addr.String(), port))
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}

func blocked(addr netip.Addr) bool {
	for _, p := range blockedRanges {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// localPeer lets in only connections from this machine (the lanes' exits
// dial the server's own public address) and from private ranges (an exit in
// a bridged container). From anywhere else the port says nothing at all.
func localPeer(addr net.Addr) bool {
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return false
	}
	ip := ap.Addr().Unmap()
	if ip.IsLoopback() || ip.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(ip) {
		return true
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		if p, err := netip.ParsePrefix(a.String()); err == nil && p.Addr().Unmap() == ip {
			return true
		}
	}
	return false
}

// readKeyFile reads the tunnel key: bare hex, or the `key:` line of a
// server.yaml.
func readKeyFile(path string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	text := string(raw)
	if key, err := ParseKey(text); err == nil {
		return key, nil
	}
	for _, line := range strings.Split(text, "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "key:"); ok {
			return ParseKey(strings.Trim(strings.TrimSpace(v), `"'`))
		}
	}
	return nil, errBadKey
}
