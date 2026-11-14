package tunstack

// The name lookups of the phone, answered in this layer.
//
// The engines' SOCKS5 listeners carry TCP only, so a lookup the system sends
// over UDP cannot go through as it is. It used to be answered "truncated": the
// system repeated it over TCP to the DNS address from the settings, and that
// stream went through the server like any other. A server that does not reach
// that one address left the phone without names while the session itself
// carried traffic, and a lookup that did work cost a new stream through the
// server each time.
//
// Now the lookup is answered here. It goes to a resolver through the same
// SOCKS5 listener, and the reply returns to the system as the UDP answer it
// waited for:
//
//   - over HTTPS (RFC 8484) to a resolver by its name. The server connects to
//     the name, the certificate is checked on the phone: the server does not
//     read the lookup and cannot change the answer. One connection carries
//     every lookup, so a lookup is one exchange and no new stream;
//   - then plain DNS over TCP, to public addresses and to the address the
//     system asked.
//
// The address from the settings decides who is asked first: a known one is
// asked over HTTPS at its own name, any other over TCP as it is. The next
// resolver is asked as well when the one before fails, refuses, or stays
// silent for timing.hedge; one that did so is asked last for a while.
//
// The tunnel carries IPv4 only (both apps drop IPv6 packets before this
// layer), so a lookup of IPv6 addresses gets an empty answer at once: no app
// waits for an address it cannot reach.
//
// Lookups the system sends over TCP to port 53 are answered here the same way,
// and other UDP is dropped as before.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/network"
	"github.com/Jigsaw-Code/outline-sdk/transport"
	"golang.org/x/net/dns/dnsmessage"
	"golang.org/x/net/proxy"
)

const (
	dnsPort    = 53
	headerSize = 12
	maxMessage = 65535

	// The largest answer handed back over UDP: what the asker allows, within
	// these bounds (RFC 1035 without EDNS; 1232 never needs IP fragments).
	minUDPAnswer = 512
	maxUDPAnswer = 1232

	rcodeSuccess   = 0
	rcodeServFail  = 2
	rcodeNameError = 3
	rcodeNotImp    = 4

	typeAAAA = 28
	classIN  = 1

	maxLookups   = 128 // under way at once, over every session and stream
	maxPipelined = 8   // under way at once on one TCP stream of the phone
	maxExtra     = 8   // resolvers remembered beyond the usual ones

	dnsMessageType = "application/dns-message"
)

// The resolvers asked through any server, in this order.
const (
	firstHTTPS  = "cloudflare-dns.com"
	secondHTTPS = "dns.google"
)

//nolint:gochecknoglobals // fixed tables
var (
	usualPlain = []netip.Addr{
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("9.9.9.9"),
	}

	// sameOperator names the HTTPS resolver run by the operator of a DNS
	// address: the choice made in the settings is kept, over the better path.
	sameOperator = map[netip.Addr]string{
		netip.MustParseAddr("1.1.1.1"):         firstHTTPS,
		netip.MustParseAddr("1.0.0.1"):         firstHTTPS,
		netip.MustParseAddr("8.8.8.8"):         secondHTTPS,
		netip.MustParseAddr("8.8.4.4"):         secondHTTPS,
		netip.MustParseAddr("9.9.9.9"):         "dns.quad9.net",
		netip.MustParseAddr("149.112.112.112"): "dns.quad9.net",
		netip.MustParseAddr("77.88.8.8"):       "common.dot.dns.yandex.net",
		netip.MustParseAddr("77.88.8.1"):       "common.dot.dns.yandex.net",
	}
)

var (
	errNotAnAnswer = errors.New("tunstack: the reply does not answer the lookup")
	errBusy        = errors.New("tunstack: too many lookups under way")
)

// statusError is an HTTPS resolver's refusal: the connection itself is fine.
type statusError int

func (e statusError) Error() string {
	return fmt.Sprintf("tunstack: resolver answered HTTP %d", int(e))
}

// namesTiming holds every wait of the lookups. Tests shorten them.
type namesTiming struct {
	hedge      time.Duration // a resolver's head start before the next is asked as well
	attempt    time.Duration // one resolver's time for one lookup, its connection included
	lookup     time.Duration // the whole lookup; after it the asker gets "server failure"
	setback    time.Duration // how long a resolver that failed is asked last; doubles each time
	maxSetback time.Duration
	idle       time.Duration // a UDP session or a TCP stream of the phone with nothing on it is closed
	connIdle   time.Duration // a resolver's connection nobody used is closed
	sweep      time.Duration // how often idle things are looked for
	drain      time.Duration // how long close waits for replies being handed to the stack
}

func defaultTiming() namesTiming {
	return namesTiming{
		hedge:      1500 * time.Millisecond,
		attempt:    5 * time.Second,
		lookup:     9 * time.Second,
		setback:    20 * time.Second,
		maxSetback: 10 * time.Minute,
		idle:       30 * time.Second,
		connIdle:   5 * time.Minute,
		sweep:      10 * time.Second,
		drain:      time.Second,
	}
}

type dialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// socksDial reaches an address through the engine's SOCKS5 listener. A name
// is passed on as a name: the server looks it up.
func socksDial(listener, user, pass string) (dialFunc, error) {
	var auth *proxy.Auth
	if user != "" || pass != "" {
		auth = &proxy.Auth{User: user, Password: pass}
	}
	dialer, err := proxy.SOCKS5("tcp", listener, auth, &net.Dialer{})
	if err != nil {
		return nil, err
	}
	withContext, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return nil, errors.New("tunstack: the SOCKS5 client takes no deadline")
	}
	return withContext.DialContext, nil
}

// names answers the lookups of one Tunnel.
type names struct {
	t    namesTiming
	now  func() time.Time
	dial dialFunc
	web  *http.Transport

	ctx    context.Context
	cancel context.CancelFunc
	slots  chan struct{}

	// gate lets close wait for the replies being handed to the stack: the
	// stack's UDP socket is freed with the device and must not be written
	// after that.
	gate    sync.RWMutex
	stopped atomic.Bool

	mu       sync.Mutex
	usual    []*source
	byHost   map[string]*source
	byAddr   map[netip.Addr]*source
	sessions map[*nameSession]struct{}

	answered atomic.Int64
	failed   atomic.Int64
	via      atomic.Value // string
}

// newNames builds the answerer over dial. roots are the authorities an HTTPS
// resolver's certificate is checked against; nil means the system's.
func newNames(dial dialFunc, roots *x509.CertPool, t namesTiming) *names {
	ctx, cancel := context.WithCancel(context.Background())
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true) // one connection for every lookup; HTTP/1.1 would queue them
	r := &names{
		t:      t,
		now:    time.Now,
		dial:   dial,
		ctx:    ctx,
		cancel: cancel,
		slots:  make(chan struct{}, maxLookups),
		web: &http.Transport{
			DialContext: dial,
			TLSClientConfig: &tls.Config{
				MinVersion:         tls.VersionTLS12,
				RootCAs:            roots,
				ClientSessionCache: tls.NewLRUClientSessionCache(8),
			},
			TLSHandshakeTimeout:    t.attempt,
			Protocols:              protocols,
			HTTP2:                  &http.HTTP2Config{WriteByteTimeout: t.attempt},
			DisableCompression:     true,
			MaxResponseHeaderBytes: 16 << 10,
		},
		byHost:   make(map[string]*source),
		byAddr:   make(map[netip.Addr]*source),
		sessions: make(map[*nameSession]struct{}),
	}
	r.via.Store("")
	r.usual = []*source{r.https(firstHTTPS), r.https(secondHTTPS)}
	for _, addr := range usualPlain {
		r.usual = append(r.usual, r.plain(addr))
	}
	go r.sweepLoop()
	return r
}

// https is the resolver asked over HTTPS at host. Call with r.mu held, or
// before the answerer is shared.
func (r *names) https(host string) *source {
	if s, ok := r.byHost[host]; ok {
		return s
	}
	s := &source{r: r, label: host, host: host}
	r.byHost[host] = s
	return s
}

// plain is the resolver asked over TCP at addr, port 53.
func (r *names) plain(addr netip.Addr) *source {
	if s, ok := r.byAddr[addr]; ok {
		return s
	}
	s := &source{r: r, label: addr.String(), addr: netip.AddrPortFrom(addr, dnsPort).String()}
	// An app may ask any number of addresses: only a few are remembered,
	// the rest are asked without a memory of how they did.
	if len(r.byAddr) < len(usualPlain)+len(sameOperator)+maxExtra {
		r.byAddr[addr] = s
	}
	return s
}

// askable reports whether addr can be a resolver reached through the server.
func askable(addr netip.Addr) bool {
	return addr.IsValid() && !addr.IsUnspecified() && !addr.IsLoopback() && !addr.IsMulticast()
}

// order lists the resolvers for a lookup the system sent to the address to.
func (r *names) order(to netip.Addr) []*source {
	r.mu.Lock()
	defer r.mu.Unlock()
	order := make([]*source, 0, len(r.usual)+2)
	add := func(s *source) {
		for _, have := range order {
			if have == s {
				return
			}
		}
		order = append(order, s)
	}
	host, known := sameOperator[to]
	switch {
	case known:
		add(r.https(host))
	case askable(to):
		add(r.plain(to))
	}
	for _, s := range r.usual {
		add(s)
	}
	if known {
		add(r.plain(to))
	}
	// Those that failed lately go last, the one free soonest first.
	now := r.now()
	sort.SliceStable(order, func(i, j int) bool {
		return order[i].heldUntil(now).Before(order[j].heldUntil(now))
	})
	return order
}

// asked is what a query says about itself.
type asked struct {
	end  int    // where the question section ends
	size int    // the largest answer the asker takes over UDP
	kind uint16 // the record type asked for
	in   bool   // class IN
}

// readQuery checks q is a query with one question and reads it. The question
// must be spelled out in full: a query has nothing to point back to.
func readQuery(q []byte) (asked, bool) {
	if len(q) < headerSize+5 || len(q) > maxMessage || q[2]&0x80 != 0 || binary.BigEndian.Uint16(q[4:6]) != 1 {
		return asked{}, false
	}
	off := headerSize
	for {
		if off >= len(q) {
			return asked{}, false
		}
		length := int(q[off])
		off++
		if length == 0 {
			break
		}
		if length > 63 || off+length > len(q) || off+length-headerSize > 255 {
			return asked{}, false
		}
		off += length
	}
	if off+4 > len(q) {
		return asked{}, false
	}
	a := asked{
		end:  off + 4,
		size: minUDPAnswer,
		kind: binary.BigEndian.Uint16(q[off : off+2]),
		in:   binary.BigEndian.Uint16(q[off+2:off+4]) == classIN,
	}
	// EDNS: the asker names the largest UDP answer it takes in the class field
	// of an OPT record among the additional ones.
	var p dnsmessage.Parser
	if _, err := p.Start(q); err != nil {
		return a, true
	}
	if p.SkipAllQuestions() != nil || p.SkipAllAnswers() != nil || p.SkipAllAuthorities() != nil {
		return a, true
	}
	for {
		h, err := p.AdditionalHeader()
		if err != nil {
			return a, true
		}
		if h.Type == dnsmessage.TypeOPT {
			a.size = min(max(int(h.Class), minUDPAnswer), maxUDPAnswer)
			return a, true
		}
		if p.SkipAdditional() != nil {
			return a, true
		}
	}
}

// own builds an answer of this layer's own: the asker's header and question,
// a result code, no records.
func own(q []byte, a asked, rcode byte, truncated bool) []byte {
	reply := make([]byte, a.end)
	copy(reply, q[:a.end])
	reply[2] = 0x80 | q[2]&0x79 // a response; the opcode and "recursion desired" as asked
	if truncated {
		reply[2] |= 0x02
	}
	reply[3] = 0x80 | rcode // recursion available
	for i := 6; i < headerSize; i++ {
		reply[i] = 0
	}
	return reply
}

// answers reports whether reply is a response to q: the same kind of message
// with the same question, letter case aside.
func answers(reply, q []byte, a asked) bool {
	if len(reply) < a.end || len(reply) > maxMessage || reply[2]&0x80 == 0 || (reply[2]^q[2])&0x78 != 0 {
		return false
	}
	if binary.BigEndian.Uint16(reply[4:6]) != 1 || !bytes.Equal(reply[a.end-4:a.end], q[a.end-4:a.end]) {
		return false
	}
	for i := headerSize; i < a.end-4; i++ {
		x, y := reply[i], q[i]
		if x == y {
			continue
		}
		if x|0x20 != y|0x20 || x|0x20 < 'a' || x|0x20 > 'z' {
			return false
		}
	}
	return true
}

// settled reports whether a resolver's reply ends the lookup: the name has an
// answer or does not exist. Anything else may be this resolver's own trouble.
func settled(reply []byte) bool {
	rcode := reply[3] & 0x0f
	return rcode == rcodeSuccess || rcode == rcodeNameError
}

// lookup answers one query of the phone sent to the address to. stream says
// the asker takes an answer of any size. nil: not a query, nothing to send.
func (r *names) lookup(q []byte, to netip.Addr, stream bool) []byte {
	a, ok := readQuery(q)
	if !ok {
		return nil
	}
	if q[2]&0x78 != 0 {
		return own(q, a, rcodeNotImp, false)
	}
	if a.kind == typeAAAA && a.in {
		return own(q, a, rcodeSuccess, false)
	}
	reply, via := r.ask(r.ctx, q, a, r.order(to))
	if r.ctx.Err() != nil {
		return nil
	}
	if reply == nil {
		r.failed.Add(1)
		return own(q, a, rcodeServFail, false)
	}
	r.answered.Add(1)
	r.via.Store(via)
	if !stream && len(reply) > a.size {
		// Too large for UDP: the asker repeats it over TCP, answered in full.
		return own(q, a, rcodeSuccess, true)
	}
	return reply
}

// check asks for the root's name servers and reports whether a resolver
// answered: the session carries data both ways and the phone has names.
func (r *names) check(timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(r.ctx, timeout)
	defer cancel()
	q := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1}
	q[0], q[1] = byte(r.now().UnixNano()>>8), byte(r.now().UnixNano())
	a, _ := readQuery(q)
	reply, via := r.ask(ctx, q, a, r.order(netip.Addr{}))
	if reply == nil {
		return false
	}
	r.via.Store(via)
	return true
}

// described says for the log how the resolver behind an answer was asked: a
// name is one asked over HTTPS, an address one asked over TCP.
func described(via string) string {
	if via == "" {
		return ""
	}
	if _, err := netip.ParseAddr(via); err == nil {
		return via + " over TCP"
	}
	return via + " over HTTPS"
}

// Where a resolver stands within one lookup.
const (
	notAsked = iota
	asking
	missed   // failed or timed out
	refused  // answered, but not with the name or its absence
	answered // settled the lookup
)

// ask puts q to the resolvers in order and returns the first reply that
// settles it, with the resolver's name. Without one it returns what a resolver
// did say (its "server failure" or refusal), or nil when none said anything.
func (r *names) ask(ctx context.Context, q []byte, a asked, order []*source) ([]byte, string) {
	if len(order) == 0 {
		return nil, ""
	}
	ctx, cancel := context.WithTimeout(ctx, r.t.lookup)
	defer cancel()

	type outcome struct {
		i     int
		reply []byte
		err   error
	}
	outcomes := make(chan outcome, len(order))
	state := make([]int, len(order))
	began := make([]time.Time, len(order))
	next, under := 0, 0
	launch := func() {
		i := next
		next++
		under++
		state[i] = asking
		began[i] = r.now()
		go func() {
			attempt, done := context.WithTimeout(ctx, r.t.attempt)
			defer done()
			reply, err := order[i].exchange(attempt, q, a)
			outcomes <- outcome{i, reply, err}
		}()
	}
	// silent holds back those asked a head start ago that have said nothing.
	silent := func() {
		now := r.now()
		for i := 0; i < next; i++ {
			if state[i] == asking && now.Sub(began[i]) >= r.t.hedge {
				order[i].failedNow(true)
			}
		}
	}

	launch()
	hedge := time.NewTimer(r.t.hedge)
	defer hedge.Stop()
	var spare []byte
	spareVia := ""
	for {
		select {
		case o := <-outcomes:
			under--
			s := order[o.i]
			if o.err == nil && settled(o.reply) {
				state[o.i] = answered
				s.succeeded()
				silent()
				for i := 0; i < next; i++ {
					if state[i] == refused {
						order[i].failedNow(false)
					}
				}
				return o.reply, s.label
			}
			if o.err == nil {
				state[o.i] = refused
				if spare == nil {
					spare, spareVia = o.reply, s.label
				}
			} else {
				state[o.i] = missed
				if ctx.Err() == nil {
					var status statusError
					s.failedNow(!errors.As(o.err, &status) && !errors.Is(o.err, errNotAnAnswer))
				}
			}
			switch {
			case next < len(order):
				launch()
				hedge.Reset(r.t.hedge)
			case under == 0:
				return spare, spareVia
			}
		case <-hedge.C:
			if next < len(order) {
				launch()
				hedge.Reset(r.t.hedge)
			}
		case <-ctx.Done():
			if r.ctx.Err() == nil {
				silent()
			}
			return spare, spareVia
		}
	}
}

// source is one resolver: over HTTPS at host, or over TCP at addr.
type source struct {
	r     *names
	label string
	host  string
	addr  string

	mu      sync.Mutex
	misses  int
	until   time.Time
	conn    *http.ClientConn
	used    time.Time
	dialing *dialing
}

// dialing is a connection being made, shared by the lookups waiting for it.
type dialing struct {
	done chan struct{}
	conn *http.ClientConn
	err  error
}

// heldUntil is when the resolver is asked in its turn again; the zero time
// when it is now.
func (s *source) heldUntil(now time.Time) time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Before(s.until) {
		return s.until
	}
	return time.Time{}
}

func (s *source) succeeded() {
	s.mu.Lock()
	s.misses = 0
	s.until = time.Time{}
	s.mu.Unlock()
}

// failedNow asks the resolver last for a while. Failures while it is already
// held back are the same trouble seen by other lookups and add nothing.
// suspect says its connection may be dead: the next lookup makes a new one.
func (s *source) failedNow(suspect bool) {
	now := s.r.now()
	s.mu.Lock()
	if !now.Before(s.until) {
		wait := s.r.t.maxSetback
		if s.misses < 16 {
			wait = min(s.r.t.setback<<s.misses, s.r.t.maxSetback)
		}
		s.misses++
		s.until = now.Add(wait)
	}
	var conn *http.ClientConn
	if suspect {
		conn, s.conn = s.conn, nil
	}
	s.mu.Unlock()
	if conn == nil {
		return
	}
	if conn.Err() != nil || conn.InFlight() == 0 {
		_ = conn.Close()
		return
	}
	// Other lookups may still get their replies on it.
	time.AfterFunc(s.r.t.attempt, func() { _ = conn.Close() })
}

// exchange puts q to the resolver and returns its reply, checked to answer q
// and carrying q's ID.
func (s *source) exchange(ctx context.Context, q []byte, a asked) ([]byte, error) {
	var reply []byte
	var err error
	if s.host != "" {
		reply, err = s.overHTTPS(ctx, q)
	} else {
		reply, err = s.overTCP(ctx, q)
	}
	if err != nil {
		return nil, err
	}
	if !answers(reply, q, a) {
		return nil, errNotAnAnswer
	}
	reply[0], reply[1] = q[0], q[1]
	return reply, nil
}

// connection returns the kept HTTPS connection, making one when there is none.
// Lookups that come while it is being made wait for the same one.
func (s *source) connection(ctx context.Context) (*http.ClientConn, error) {
	s.mu.Lock()
	if conn := s.conn; conn != nil {
		if conn.Err() == nil {
			s.used = s.r.now()
			s.mu.Unlock()
			return conn, nil
		}
		s.conn = nil
		defer conn.Close()
	}
	call := s.dialing
	if call == nil {
		call = &dialing{done: make(chan struct{})}
		s.dialing = call
		go s.connect(call)
	}
	s.mu.Unlock()
	select {
	case <-call.done:
		return call.conn, call.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// connect makes the HTTPS connection for call: through the server to the
// resolver's name, with the certificate checked here. It has its own time, so
// a lookup that gives up early does not waste a connection nearly made.
func (s *source) connect(call *dialing) {
	ctx, cancel := context.WithTimeout(s.r.ctx, s.r.t.attempt)
	conn, err := s.r.web.NewClientConn(ctx, "https", net.JoinHostPort(s.host, "443"))
	cancel()
	s.mu.Lock()
	s.dialing = nil
	if err == nil && s.r.ctx.Err() != nil {
		_ = conn.Close()
		conn, err = nil, network.ErrClosed
	}
	if err == nil {
		s.conn = conn
		s.used = s.r.now()
	}
	s.mu.Unlock()
	call.conn, call.err = conn, err
	close(call.done)
}

func (s *source) overHTTPS(ctx context.Context, q []byte) ([]byte, error) {
	conn, err := s.connection(ctx)
	if err != nil {
		return nil, err
	}
	// ID 0, as RFC 8484 asks: the same lookup is the same request to a cache.
	body := bytes.Clone(q)
	body[0], body[1] = 0, 0
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+s.host+"/dns-query", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", dnsMessageType)
	req.Header.Set("Accept", dnsMessageType)
	req.Header.Set("User-Agent", "") // none is sent
	resp, err := conn.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, statusError(resp.StatusCode)
	}
	reply, err := io.ReadAll(io.LimitReader(resp.Body, maxMessage+1))
	if err != nil {
		return nil, err
	}
	return reply, nil
}

func (s *source) overTCP(ctx context.Context, q []byte) ([]byte, error) {
	conn, err := s.r.dial(ctx, "tcp", s.addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	framed := make([]byte, 2+len(q))
	binary.BigEndian.PutUint16(framed, uint16(len(q)))
	copy(framed[2:], q)
	if _, err := conn.Write(framed); err != nil {
		return nil, err
	}
	var size [2]byte
	if _, err := io.ReadFull(conn, size[:]); err != nil {
		return nil, err
	}
	reply := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(conn, reply); err != nil {
		return nil, err
	}
	if len(reply) >= 2 && (reply[0] != q[0] || reply[1] != q[1]) {
		return nil, errNotAnAnswer
	}
	return reply, nil
}

// drop closes the kept connection when nobody used it since before.
func (s *source) drop(before time.Time) {
	s.mu.Lock()
	conn := s.conn
	if conn == nil || (s.used.After(before) && conn.Err() == nil) || conn.InFlight() > 0 {
		s.mu.Unlock()
		return
	}
	s.conn = nil
	s.mu.Unlock()
	_ = conn.Close()
}

func (s *source) close() {
	s.mu.Lock()
	conn := s.conn
	s.conn = nil
	s.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
}

// sweepLoop closes what nobody uses: UDP sessions of the phone (the stack
// keeps one for every port a packet came from until told otherwise) and
// resolver connections.
func (r *names) sweepLoop() {
	tick := time.NewTicker(r.t.sweep)
	defer tick.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case <-tick.C:
			r.sweep()
		}
	}
}

func (r *names) sweep() {
	now := r.now()
	var idle []*nameSession
	r.mu.Lock()
	for s := range r.sessions {
		if s.idleSince(now.Add(-r.t.idle)) {
			idle = append(idle, s)
		}
	}
	sources := r.sources()
	r.mu.Unlock()
	for _, s := range idle {
		_ = s.Close()
	}
	for _, s := range sources {
		s.drop(now.Add(-r.t.connIdle))
	}
}

// sources lists every remembered resolver. Call with r.mu held.
func (r *names) sources() []*source {
	all := make([]*source, 0, len(r.byHost)+len(r.byAddr))
	for _, s := range r.byHost {
		all = append(all, s)
	}
	for _, s := range r.byAddr {
		all = append(all, s)
	}
	return all
}

// close ends every lookup, session and connection, and returns once no reply
// is being handed to the stack any more (or timing.drain has passed: a reply
// stuck there is past the stack's socket and ends with the device).
func (r *names) close() {
	if !r.stopped.CompareAndSwap(false, true) {
		return
	}
	r.cancel()
	r.mu.Lock()
	sessions := make([]*nameSession, 0, len(r.sessions))
	for s := range r.sessions {
		sessions = append(sessions, s)
	}
	sources := r.sources()
	r.mu.Unlock()
	for _, s := range sessions {
		_ = s.Close()
	}
	for _, s := range sources {
		s.close()
	}
	r.web.CloseIdleConnections()
	deadline := time.Now().Add(r.t.drain)
	for !r.gate.TryLock() {
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	r.gate.Unlock() //nolint:staticcheck // taken only to wait for the readers
}

// take reserves room for one more lookup without waiting.
func (r *names) take() bool {
	select {
	case r.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

// takeWait reserves room for one more lookup, waiting for it until ctx ends.
func (r *names) takeWait(ctx context.Context) bool {
	select {
	case r.slots <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func (r *names) give() { <-r.slots }

// NewSession implements network.PacketProxy: one session per UDP port of the
// phone a packet came from.
func (r *names) NewSession(resp network.PacketResponseReceiver) (network.PacketRequestSender, error) {
	if resp == nil {
		return nil, errors.New("tunstack: a response receiver is required")
	}
	s := &nameSession{r: r, resp: resp, flying: make(map[string]struct{})}
	s.last.Store(r.now().UnixNano())
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped.Load() {
		return nil, network.ErrClosed
	}
	r.sessions[s] = struct{}{}
	return s, nil
}

// nameSession is the phone's side of one UDP port.
type nameSession struct {
	r      *names
	resp   network.PacketResponseReceiver
	closed atomic.Bool
	last   atomic.Int64 // when a packet last came or went, Unix nanoseconds

	mu     sync.Mutex
	flying map[string]struct{} // the queries being answered, by their bytes
}

// WriteTo implements network.PacketRequestSender. The stack may call it from
// inside its own lock and reuses p after the call: nothing here waits, and
// the lookup works on a copy.
func (s *nameSession) WriteTo(p []byte, to netip.AddrPort) (int, error) {
	if s.closed.Load() {
		return 0, network.ErrClosed
	}
	s.last.Store(s.r.now().UnixNano())
	if to.Port() != dnsPort {
		return 0, fmt.Errorf("tunstack: UDP to port %d is not carried: %w", to.Port(), network.ErrPortUnreachable)
	}
	if len(p) < headerSize || len(p) > maxMessage || p[2]&0x80 != 0 {
		return 0, errors.New("tunstack: not a DNS query")
	}
	q := string(p)
	s.mu.Lock()
	if _, repeated := s.flying[q]; repeated {
		// The system asks again while the answer is on its way.
		s.mu.Unlock()
		return len(p), nil
	}
	if !s.r.take() {
		s.mu.Unlock()
		return 0, errBusy
	}
	s.flying[q] = struct{}{}
	s.mu.Unlock()
	go s.answer(q, to)
	return len(p), nil
}

func (s *nameSession) answer(q string, to netip.AddrPort) {
	defer s.r.give()
	reply := s.r.lookup([]byte(q), to.Addr().Unmap(), false)
	s.mu.Lock()
	delete(s.flying, q)
	s.mu.Unlock()
	if reply == nil {
		return
	}
	s.r.gate.RLock()
	defer s.r.gate.RUnlock()
	if s.r.stopped.Load() || s.closed.Load() {
		return
	}
	s.last.Store(s.r.now().UnixNano())
	_, _ = s.resp.WriteFrom(reply, net.UDPAddrFromAddrPort(to))
}

// idleSince reports whether nothing came or went since before and nothing is
// being answered.
func (s *nameSession) idleSince(before time.Time) bool {
	if s.last.Load() > before.UnixNano() {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.flying) == 0
}

// Close implements network.PacketRequestSender. Closing the receiver makes the
// stack forget the port and call Close here once more, from inside its lock:
// that second call finds the session closed and takes no lock of ours.
func (s *nameSession) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return network.ErrClosed
	}
	s.r.mu.Lock()
	delete(s.r.sessions, s)
	s.r.mu.Unlock()
	_ = s.resp.Close()
	return nil
}

// nameDialer hands the phone's TCP streams to the SOCKS5 client, except those
// to port 53: they are lookups and are answered here.
type nameDialer struct {
	r    *names
	next transport.StreamDialer
}

func (d *nameDialer) DialStream(ctx context.Context, address string) (transport.StreamConn, error) {
	if to, err := netip.ParseAddrPort(address); err == nil && to.Port() == dnsPort {
		if d.r.stopped.Load() {
			return nil, network.ErrClosed
		}
		return d.r.newStream(to.Addr().Unmap()), nil
	}
	return d.next.DialStream(ctx, address)
}

// nameStream is the far end of a TCP stream the phone opened to port 53:
// queries come in through Write, answers go out through Read, each behind its
// two-byte length (RFC 1035 4.2.2). Several may be under way at once and are
// answered as they come (RFC 7766).
type nameStream struct {
	r      *names
	to     netip.Addr
	ctx    context.Context
	cancel context.CancelFunc
	room   chan struct{} // lookups under way on this stream, and answers not yet read
	wake   chan struct{}

	mu      sync.Mutex
	partial []byte   // bytes of a query not yet whole
	ready   [][]byte // framed answers waiting to be read
	reading []byte   // the answer being read
	flying  int
	ended   bool // the phone finished asking
	last    time.Time
}

func (r *names) newStream(to netip.Addr) *nameStream {
	ctx, cancel := context.WithCancel(r.ctx)
	return &nameStream{
		r:      r,
		to:     to,
		ctx:    ctx,
		cancel: cancel,
		room:   make(chan struct{}, maxPipelined),
		wake:   make(chan struct{}, 1),
		last:   r.now(),
	}
}

func (s *nameStream) signal() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

// Write takes bytes the phone sent. It waits when too many lookups are under
// way, which holds the phone back through the stream's own window.
func (s *nameStream) Write(p []byte) (int, error) {
	s.mu.Lock()
	if s.ended || s.ctx.Err() != nil {
		s.mu.Unlock()
		return 0, io.ErrClosedPipe
	}
	s.last = s.r.now()
	s.partial = append(s.partial, p...)
	var queries [][]byte
	for len(s.partial) >= 2 {
		size := int(binary.BigEndian.Uint16(s.partial))
		if size < headerSize {
			s.mu.Unlock()
			s.cancel()
			return 0, errors.New("tunstack: not a DNS query")
		}
		if len(s.partial) < 2+size {
			break
		}
		queries = append(queries, bytes.Clone(s.partial[2:2+size]))
		s.partial = s.partial[2+size:]
	}
	s.flying += len(queries)
	s.mu.Unlock()
	for i, q := range queries {
		if !s.reserve() {
			s.mu.Lock()
			s.flying -= len(queries) - i
			s.mu.Unlock()
			s.signal()
			return 0, io.ErrClosedPipe
		}
		go s.answer(q)
	}
	return len(p), nil
}

func (s *nameStream) reserve() bool {
	select {
	case s.room <- struct{}{}:
	case <-s.ctx.Done():
		return false
	}
	if !s.r.takeWait(s.ctx) {
		<-s.room
		return false
	}
	return true
}

func (s *nameStream) answer(q []byte) {
	reply := s.r.lookup(q, s.to, true)
	s.r.give()
	s.mu.Lock()
	s.flying--
	if reply == nil {
		// Not a query: the stream cannot be trusted to be in step any more.
		s.mu.Unlock()
		<-s.room
		s.cancel()
		return
	}
	framed := make([]byte, 2+len(reply))
	binary.BigEndian.PutUint16(framed, uint16(len(reply)))
	copy(framed[2:], reply)
	s.ready = append(s.ready, framed)
	s.last = s.r.now()
	s.mu.Unlock()
	s.signal()
}

// Read hands out the answers. It ends the stream once the phone has finished
// asking and has every answer, or has asked nothing for timing.idle.
func (s *nameStream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		s.mu.Lock()
		if len(s.reading) == 0 && len(s.ready) > 0 {
			s.reading, s.ready = s.ready[0], s.ready[1:]
			<-s.room // the phone takes this answer: room for one more lookup
		}
		if len(s.reading) > 0 {
			n := copy(p, s.reading)
			s.reading = s.reading[n:]
			s.mu.Unlock()
			return n, nil
		}
		wait := s.r.t.idle - s.r.now().Sub(s.last)
		if s.ctx.Err() != nil || (s.flying == 0 && (s.ended || wait <= 0)) {
			s.mu.Unlock()
			s.cancel()
			return 0, io.EOF
		}
		if s.flying > 0 {
			wait = s.r.t.idle // an answer under way wakes the reader itself
		}
		s.mu.Unlock()
		timer := time.NewTimer(wait)
		select {
		case <-s.wake:
		case <-timer.C:
		case <-s.ctx.Done():
		}
		timer.Stop()
	}
}

// CloseWrite: the phone finished asking. Answers under way are still read.
func (s *nameStream) CloseWrite() error {
	s.mu.Lock()
	s.ended = true
	s.mu.Unlock()
	s.signal()
	return nil
}

// CloseRead: nobody reads the answers any more.
func (s *nameStream) CloseRead() error {
	s.cancel()
	return nil
}

func (s *nameStream) Close() error {
	s.cancel()
	return nil
}

func (s *nameStream) LocalAddr() net.Addr { return &net.TCPAddr{} }

func (s *nameStream) RemoteAddr() net.Addr {
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(s.to, dnsPort))
}

// The stack sets no deadlines on its far ends.
func (s *nameStream) SetDeadline(time.Time) error      { return nil }
func (s *nameStream) SetReadDeadline(time.Time) error  { return nil }
func (s *nameStream) SetWriteDeadline(time.Time) error { return nil }

// Compile-time checks of the interfaces the stack uses.
var (
	_ network.PacketProxy         = (*names)(nil)
	_ network.PacketRequestSender = (*nameSession)(nil)
	_ transport.StreamDialer      = (*nameDialer)(nil)
	_ transport.StreamConn        = (*nameStream)(nil)
)
