package tunstack

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Jigsaw-Code/outline-sdk/network"
	"github.com/Jigsaw-Code/outline-sdk/transport"
	"golang.org/x/net/dns/dnsmessage"
)

// The addresses in these tests are the documentation ranges and the public
// resolvers' own; nothing leaves the machine: every stream ends in the SOCKS5
// listener of the test, which sends it to a local stand-in or refuses it.

// ---- the far side: a SOCKS5 listener and resolvers behind it ----

type world struct {
	t     *testing.T
	socks net.Listener
	user  string // asked of every client when set
	pass  string
	roots *x509.CertPool
	cert  tls.Certificate

	mu     sync.Mutex
	routes map[string]string // "name:port" or "address:port" as asked -> local listener
	asked  []string          // every target asked, a name marked "name " and an address "addr "
	conns  []net.Conn
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t, routes: make(map[string]string)}
	w.roots, w.cert = testAuthority(t, firstHTTPS, secondHTTPS, "dns.quad9.net", "common.dot.dns.yandex.net")
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	w.socks = listener
	go w.serve()
	t.Cleanup(func() {
		_ = listener.Close()
		w.mu.Lock()
		defer w.mu.Unlock()
		for _, c := range w.conns {
			_ = c.Close()
		}
	})
	return w
}

func testAuthority(t *testing.T, names ...string) (*x509.CertPool, tls.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test authority"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: names[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     names,
	}
	der, err := x509.CreateCertificate(rand.Reader, leaf, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return pool, tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func (w *world) hold(c net.Conn) {
	w.mu.Lock()
	w.conns = append(w.conns, c)
	w.mu.Unlock()
}

func (w *world) route(target, local string) {
	w.mu.Lock()
	w.routes[target] = local
	w.mu.Unlock()
}

func (w *world) unroute(target string) {
	w.mu.Lock()
	delete(w.routes, target)
	w.mu.Unlock()
}

// askedFor returns how many times target was asked of the SOCKS5 listener.
func (w *world) askedFor(target string) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := 0
	for _, a := range w.asked {
		if a == target {
			n++
		}
	}
	return n
}

func (w *world) askedList() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.asked...)
}

func (w *world) serve() {
	for {
		c, err := w.socks.Accept()
		if err != nil {
			return
		}
		w.hold(c)
		go w.handle(c)
	}
}

func (w *world) handle(c net.Conn) {
	defer c.Close()
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil || head[0] != 5 {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}
	if w.user != "" {
		if !bytes.Contains(methods, []byte{2}) {
			_, _ = c.Write([]byte{5, 0xff})
			return
		}
		_, _ = c.Write([]byte{5, 2})
		if _, err := io.ReadFull(c, head); err != nil || head[0] != 1 {
			return
		}
		user := make([]byte, head[1])
		if _, err := io.ReadFull(c, user); err != nil {
			return
		}
		size := make([]byte, 1)
		if _, err := io.ReadFull(c, size); err != nil {
			return
		}
		pass := make([]byte, size[0])
		if _, err := io.ReadFull(c, pass); err != nil {
			return
		}
		if string(user) != w.user || string(pass) != w.pass {
			_, _ = c.Write([]byte{1, 1})
			return
		}
		_, _ = c.Write([]byte{1, 0})
	} else {
		_, _ = c.Write([]byte{5, 0})
	}
	request := make([]byte, 4)
	if _, err := io.ReadFull(c, request); err != nil || request[1] != 1 {
		return
	}
	var host, kind string
	switch request[3] {
	case 1:
		raw := make([]byte, 4)
		if _, err := io.ReadFull(c, raw); err != nil {
			return
		}
		host, kind = net.IP(raw).String(), "addr "
	case 3:
		size := make([]byte, 1)
		if _, err := io.ReadFull(c, size); err != nil {
			return
		}
		raw := make([]byte, size[0])
		if _, err := io.ReadFull(c, raw); err != nil {
			return
		}
		host, kind = string(raw), "name "
	default:
		return
	}
	rawPort := make([]byte, 2)
	if _, err := io.ReadFull(c, rawPort); err != nil {
		return
	}
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(rawPort))))
	w.mu.Lock()
	w.asked = append(w.asked, kind+target)
	local, ok := w.routes[target]
	w.mu.Unlock()
	if !ok {
		_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0}) // connection refused
		return
	}
	far, err := net.Dial("tcp", local)
	if err != nil {
		_, _ = c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	w.hold(far)
	defer far.Close()
	_, _ = c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(far, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, far); done <- struct{}{} }()
	<-done
}

// resolver is a stand-in resolver. answer builds the reply to a query; nil
// means it says nothing.
type resolver struct {
	addr   string
	hits   atomic.Int64
	mu     sync.Mutex
	answer func(q []byte) []byte
	ids    []uint16 // the ID of every query as it arrived
	agents []string // the User-Agent of every HTTPS request
}

func (r *resolver) set(answer func(q []byte) []byte) {
	r.mu.Lock()
	r.answer = answer
	r.mu.Unlock()
}

func (r *resolver) reply(q []byte) []byte {
	r.hits.Add(1)
	r.mu.Lock()
	answer := r.answer
	if len(q) >= 2 {
		r.ids = append(r.ids, binary.BigEndian.Uint16(q))
	}
	r.mu.Unlock()
	if answer == nil {
		return nil
	}
	return answer(q)
}

// https starts a resolver that speaks DNS over HTTPS (HTTP/2) and routes the
// name to it.
func (w *world) https(name string, answer func(q []byte) []byte) *resolver {
	w.t.Helper()
	r := &resolver{answer: answer}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.Method != http.MethodPost || req.URL.Path != "/dns-query" ||
			req.Header.Get("Content-Type") != dnsMessageType || req.ProtoMajor != 2 || req.Host != name {
			http.Error(rw, "not a lookup", http.StatusBadRequest)
			return
		}
		q, err := io.ReadAll(req.Body)
		if err != nil {
			return
		}
		r.mu.Lock()
		r.agents = append(r.agents, req.Header.Get("User-Agent"))
		r.mu.Unlock()
		reply := r.reply(q)
		if reply == nil {
			<-req.Context().Done() // silent until the asker gives up
			return
		}
		rw.Header().Set("Content-Type", dnsMessageType)
		_, _ = rw.Write(reply)
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{Certificates: []tls.Certificate{w.cert}}
	server.StartTLS()
	w.t.Cleanup(server.Close)
	r.addr = server.Listener.Addr().String()
	w.route(name+":443", r.addr)
	return r
}

// plain starts a resolver that speaks DNS over TCP and routes the address to
// it.
func (w *world) plain(addr string, answer func(q []byte) []byte) *resolver {
	w.t.Helper()
	r := &resolver{answer: answer}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			w.hold(c)
			go func() {
				defer c.Close()
				for {
					q, err := readFramed(c)
					if err != nil {
						return
					}
					reply := r.reply(q)
					if reply == nil {
						continue
					}
					if _, err := c.Write(framed(reply)); err != nil {
						return
					}
				}
			}()
		}
	}()
	r.addr = listener.Addr().String()
	w.route(addr+":53", r.addr)
	return r
}

// deaf routes target to a listener that accepts and never says a word.
func (w *world) deaf(target string) {
	w.t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			w.hold(c)
		}
	}()
	w.route(target, listener.Addr().String())
}

func framed(m []byte) []byte {
	out := make([]byte, 2+len(m))
	binary.BigEndian.PutUint16(out, uint16(len(m)))
	copy(out[2:], m)
	return out
}

func readFramed(r io.Reader) ([]byte, error) {
	var size [2]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return nil, err
	}
	m := make([]byte, binary.BigEndian.Uint16(size[:]))
	_, err := io.ReadFull(r, m)
	return m, err
}

// ---- DNS messages ----

// query builds a lookup. edns is the UDP answer size the asker names; 0
// leaves EDNS out.
func query(t *testing.T, id uint16, name string, kind dnsmessage.Type, edns int) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, RecursionDesired: true})
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{
		Name: dnsmessage.MustNewName(name), Type: kind, Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	if edns > 0 {
		if err := b.StartAdditionals(); err != nil {
			t.Fatal(err)
		}
		var h dnsmessage.ResourceHeader
		if err := h.SetEDNS0(edns, dnsmessage.RCodeSuccess, false); err != nil {
			t.Fatal(err)
		}
		if err := b.OPTResource(h, dnsmessage.OPTResource{}); err != nil {
			t.Fatal(err)
		}
	}
	m, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// withRecords answers a query with n address records (each 192.0.2.x).
func withRecords(n int) func(q []byte) []byte {
	return func(q []byte) []byte {
		var p dnsmessage.Parser
		h, err := p.Start(q)
		if err != nil {
			return nil
		}
		question, err := p.Question()
		if err != nil {
			return nil
		}
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
			ID: h.ID, Response: true, RecursionDesired: h.RecursionDesired, RecursionAvailable: true,
		})
		_ = b.StartQuestions()
		_ = b.Question(question)
		_ = b.StartAnswers()
		for i := 0; i < n; i++ {
			_ = b.AResource(dnsmessage.ResourceHeader{
				Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 60,
			}, dnsmessage.AResource{A: [4]byte{192, 0, 2, byte(i + 1)}})
		}
		m, err := b.Finish()
		if err != nil {
			return nil
		}
		return m
	}
}

// withCode answers a query with a result code and no records.
func withCode(code dnsmessage.RCode) func(q []byte) []byte {
	return func(q []byte) []byte {
		a, ok := readQuery(q)
		if !ok {
			return nil
		}
		return own(q, a, byte(code), false)
	}
}

type parsed struct {
	header  dnsmessage.Header
	name    string
	answers int
}

func parse(t *testing.T, m []byte) parsed {
	t.Helper()
	var p dnsmessage.Parser
	h, err := p.Start(m)
	if err != nil {
		t.Fatalf("not a DNS message: %v (% x)", err, m)
	}
	out := parsed{header: h}
	if q, err := p.Question(); err == nil {
		out.name = q.Name.String()
	}
	_ = p.SkipAllQuestions()
	for {
		if _, err := p.AnswerHeader(); err != nil {
			break
		}
		out.answers++
		_ = p.SkipAnswer()
	}
	return out
}

// ---- the phone's side ----

// receiver stands for the stack's side of a UDP port. Like the stack's own,
// closing it closes the session once more from inside its lock.
type receiver struct {
	mu      sync.Mutex
	session network.PacketRequestSender
	got     chan []byte
	from    chan net.Addr
	closed  atomic.Int32
}

func newReceiver() *receiver {
	return &receiver{got: make(chan []byte, 64), from: make(chan net.Addr, 64)}
}

func (r *receiver) WriteFrom(p []byte, source net.Addr) (int, error) {
	r.got <- append([]byte(nil), p...)
	r.from <- source
	return len(p), nil
}

func (r *receiver) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed.Add(1)
	if r.session != nil {
		_ = r.session.Close()
	}
	return nil
}

func (r *receiver) wait(t *testing.T, within time.Duration) []byte {
	t.Helper()
	select {
	case m := <-r.got:
		<-r.from
		return m
	case <-time.After(within):
		t.Fatal("no answer came back to the phone")
		return nil
	}
}

func (r *receiver) none(t *testing.T, within time.Duration) {
	t.Helper()
	select {
	case m := <-r.got:
		t.Fatalf("an answer came back that should not have: % x", m)
	case <-time.After(within):
	}
}

func testTiming() namesTiming {
	return namesTiming{
		hedge:      80 * time.Millisecond,
		attempt:    time.Second,
		lookup:     3 * time.Second,
		setback:    10 * time.Second,
		maxSetback: time.Minute,
		idle:       time.Minute,
		connIdle:   time.Minute,
		sweep:      20 * time.Millisecond,
		drain:      time.Second,
	}
}

func (w *world) names(timing namesTiming) *names {
	w.t.Helper()
	dial, err := socksDial(w.socks.Addr().String(), w.user, w.pass)
	if err != nil {
		w.t.Fatal(err)
	}
	r := newNames(dial, w.roots, timing)
	w.t.Cleanup(r.close)
	return r
}

func session(t *testing.T, r *names) (network.PacketRequestSender, *receiver) {
	t.Helper()
	recv := newReceiver()
	s, err := r.NewSession(recv)
	if err != nil {
		t.Fatal(err)
	}
	recv.mu.Lock()
	recv.session = s
	recv.mu.Unlock()
	return s, recv
}

var (
	cloudflare = netip.MustParseAddrPort("1.1.1.1:53")
	google     = netip.MustParseAddrPort("8.8.8.8:53")
	quad9      = netip.MustParseAddrPort("9.9.9.9:53")
	yandex     = netip.MustParseAddrPort("77.88.8.8:53")
	custom     = netip.MustParseAddrPort("203.0.113.53:53")
)

const long = 5 * time.Second

// ---- tests ----

func TestLookupGoesOverHTTPSByName(t *testing.T) {
	w := newWorld(t)
	doh := w.https(firstHTTPS, withRecords(2))
	r := w.names(testTiming())
	s, recv := session(t, r)

	q := query(t, 0xbeef, "Example.COM.", dnsmessage.TypeA, 1232)
	if n, err := s.WriteTo(q, cloudflare); err != nil || n != len(q) {
		t.Fatalf("WriteTo = %d, %v", n, err)
	}
	reply := parse(t, recv.wait(t, long))
	if reply.header.ID != 0xbeef || !reply.header.Response || reply.answers != 2 || reply.name != "Example.COM." {
		t.Fatalf("reply = %+v", reply)
	}
	// The server was given the resolver's name, not an address: it reads no
	// lookup and the certificate is the name's.
	if got := w.askedList(); len(got) != 1 || got[0] != "name "+firstHTTPS+":443" {
		t.Fatalf("asked of the server: %q", got)
	}
	doh.mu.Lock()
	defer doh.mu.Unlock()
	if len(doh.ids) != 1 || doh.ids[0] != 0 {
		t.Fatalf("IDs the resolver saw: %v, want one zero", doh.ids)
	}
	if len(doh.agents) != 1 || doh.agents[0] != "" {
		t.Fatalf("User-Agent the resolver saw: %q, want none", doh.agents)
	}
	if r.answered.Load() != 1 || r.failed.Load() != 0 || r.via.Load() != firstHTTPS {
		t.Fatalf("answered %d, failed %d, via %v", r.answered.Load(), r.failed.Load(), r.via.Load())
	}
}

func TestOneConnectionCarriesEveryLookup(t *testing.T) {
	w := newWorld(t)
	doh := w.https(firstHTTPS, withRecords(1))
	r := w.names(testTiming())
	s, recv := session(t, r)
	for i := 0; i < 12; i++ {
		if _, err := s.WriteTo(query(t, uint16(i+1), "example.com.", dnsmessage.TypeA, 0), cloudflare); err != nil {
			t.Fatal(err)
		}
	}
	seen := make(map[uint16]bool)
	for i := 0; i < 12; i++ {
		seen[parse(t, recv.wait(t, long)).header.ID] = true
	}
	if len(seen) != 12 {
		t.Fatalf("answers for %d of 12 lookups", len(seen))
	}
	// Those that came while the connection was being made waited for it, and
	// later ones find it kept.
	for i := 0; i < 3; i++ {
		if _, err := s.WriteTo(query(t, uint16(100+i), "example.org.", dnsmessage.TypeA, 0), cloudflare); err != nil {
			t.Fatal(err)
		}
		recv.wait(t, long)
	}
	if n := w.askedFor("name " + firstHTTPS + ":443"); n != 1 {
		t.Fatalf("%d streams through the server for 15 lookups, want 1", n)
	}
	if doh.hits.Load() != 15 {
		t.Fatalf("resolver saw %d lookups", doh.hits.Load())
	}
}

func TestLoginIsPresented(t *testing.T) {
	w := newWorld(t)
	w.user, w.pass = "session-user", "session-pass"
	w.https(firstHTTPS, withRecords(1))
	r := w.names(testTiming())
	s, recv := session(t, r)
	if _, err := s.WriteTo(query(t, 7, "example.com.", dnsmessage.TypeA, 0), cloudflare); err != nil {
		t.Fatal(err)
	}
	if reply := parse(t, recv.wait(t, long)); reply.answers != 1 {
		t.Fatalf("reply = %+v", reply)
	}

	// A wrong login gets nothing through, and the phone is told so.
	wrong, err := socksDial(w.socks.Addr().String(), "session-user", "other")
	if err != nil {
		t.Fatal(err)
	}
	r2 := newNames(wrong, w.roots, testTiming())
	defer r2.close()
	s2, recv2 := session(t, r2)
	if _, err := s2.WriteTo(query(t, 8, "example.com.", dnsmessage.TypeA, 0), cloudflare); err != nil {
		t.Fatal(err)
	}
	if reply := parse(t, recv2.wait(t, long)); reply.header.RCode != dnsmessage.RCodeServerFailure {
		t.Fatalf("reply = %+v", reply)
	}
}

func TestNextResolverWhenTheFirstIsRefused(t *testing.T) {
	w := newWorld(t)
	second := w.https(secondHTTPS, withRecords(1)) // the first name has no route: refused
	r := w.names(testTiming())
	s, recv := session(t, r)

	began := time.Now()
	if _, err := s.WriteTo(query(t, 1, "example.com.", dnsmessage.TypeA, 0), cloudflare); err != nil {
		t.Fatal(err)
	}
	if reply := parse(t, recv.wait(t, long)); reply.answers != 1 {
		t.Fatalf("reply = %+v", reply)
	}
	if took := time.Since(began); took > time.Second {
		t.Fatalf("a refusal held the lookup for %v", took)
	}
	if r.via.Load() != secondHTTPS {
		t.Fatalf("via %v", r.via.Load())
	}

	// The one that failed is asked last from now on: not at all while the
	// next answers.
	before := w.askedFor("name " + firstHTTPS + ":443")
	for i := 0; i < 5; i++ {
		if _, err := s.WriteTo(query(t, uint16(10+i), "example.org.", dnsmessage.TypeA, 0), cloudflare); err != nil {
			t.Fatal(err)
		}
		recv.wait(t, long)
	}
	if after := w.askedFor("name " + firstHTTPS + ":443"); after != before {
		t.Fatalf("the failed resolver was asked %d more times", after-before)
	}
	if second.hits.Load() != 6 {
		t.Fatalf("second resolver saw %d lookups", second.hits.Load())
	}
}

func TestNextResolverWhenTheFirstIsSilent(t *testing.T) {
	w := newWorld(t)
	w.deaf(firstHTTPS + ":443")
	w.https(secondHTTPS, withRecords(1))
	timing := testTiming()
	r := w.names(timing)
	s, recv := session(t, r)

	began := time.Now()
	if _, err := s.WriteTo(query(t, 1, "example.com.", dnsmessage.TypeA, 0), cloudflare); err != nil {
		t.Fatal(err)
	}
	if reply := parse(t, recv.wait(t, long)); reply.answers != 1 {
		t.Fatalf("reply = %+v", reply)
	}
	took := time.Since(began)
	if took < timing.hedge {
		t.Fatalf("the second was asked before the first had its head start (%v)", took)
	}
	if took > timing.attempt {
		t.Fatalf("the lookup waited for the silent resolver to time out (%v)", took)
	}

	// The silent one lost with a head start: the next lookup does not wait
	// for it again.
	if first := r.order(cloudflare.Addr())[0].label; first != secondHTTPS {
		t.Fatalf("%s is asked first after it stayed silent", first)
	}
	if _, err := s.WriteTo(query(t, 2, "example.org.", dnsmessage.TypeA, 0), cloudflare); err != nil {
		t.Fatal(err)
	}
	recv.wait(t, long)
	if n := w.askedFor("name " + firstHTTPS + ":443"); n != 1 {
		t.Fatalf("the silent resolver was asked %d times", n)
	}
}

func TestSetbackEndsAndASuccessClearsIt(t *testing.T) {
	w := newWorld(t)
	w.https(secondHTTPS, withRecords(1))
	timing := testTiming()
	timing.setback = 150 * time.Millisecond
	r := w.names(timing)
	s, recv := session(t, r)
	ask := func(id uint16) string {
		t.Helper()
		if _, err := s.WriteTo(query(t, id, "example.com.", dnsmessage.TypeA, 0), cloudflare); err != nil {
			t.Fatal(err)
		}
		recv.wait(t, long)
		return r.via.Load().(string)
	}
	if via := ask(1); via != secondHTTPS {
		t.Fatalf("via %s", via)
	}
	// The first resolver comes to life; once its setback is over it is asked
	// first again and answers.
	w.https(firstHTTPS, withRecords(1))
	time.Sleep(timing.setback + 50*time.Millisecond)
	if via := ask(2); via != firstHTTPS {
		t.Fatalf("via %s after the setback", via)
	}
	if held := r.byHost[firstHTTPS].heldUntil(time.Now()); !held.IsZero() {
		t.Fatalf("still held back until %v after an answer", held)
	}
}

func TestSetbackDoublesAndFailuresInOneGoCountOnce(t *testing.T) {
	w := newWorld(t)
	r := w.names(testTiming())
	now := time.Unix(1_700_000_000, 0)
	r.now = func() time.Time { return now }
	s := r.byHost[firstHTTPS]
	s.failedNow(false)
	s.failedNow(false) // the same trouble, seen by another lookup
	if got := s.heldUntil(now).Sub(now); got != r.t.setback {
		t.Fatalf("first setback %v, want %v", got, r.t.setback)
	}
	now = now.Add(r.t.setback)
	s.failedNow(false)
	if got := s.heldUntil(now).Sub(now); got != 2*r.t.setback {
		t.Fatalf("second setback %v, want %v", got, 2*r.t.setback)
	}
	for i := 0; i < 40; i++ {
		now = now.Add(r.t.maxSetback)
		s.failedNow(false)
	}
	if got := s.heldUntil(now).Sub(now); got != r.t.maxSetback {
		t.Fatalf("setback grew to %v, past %v", got, r.t.maxSetback)
	}
	s.succeeded()
	if !s.heldUntil(now).IsZero() {
		t.Fatal("held back after an answer")
	}
}

func TestPlainDNSWhenNoNameAnswers(t *testing.T) {
	w := newWorld(t)
	tcp := w.plain("8.8.8.8", withRecords(3))
	r := w.names(testTiming())
	s, recv := session(t, r)
	if _, err := s.WriteTo(query(t, 0x1234, "example.com.", dnsmessage.TypeA, 0), cloudflare); err != nil {
		t.Fatal(err)
	}
	reply := parse(t, recv.wait(t, long))
	if reply.header.ID != 0x1234 || reply.answers != 3 {
		t.Fatalf("reply = %+v", reply)
	}
	if r.via.Load() != "8.8.8.8" {
		t.Fatalf("via %v", r.via.Load())
	}
	tcp.mu.Lock()
	defer tcp.mu.Unlock()
	if len(tcp.ids) != 1 || tcp.ids[0] != 0x1234 {
		t.Fatalf("IDs the resolver saw: %x", tcp.ids)
	}
	if w.askedFor("addr 8.8.8.8:53") != 1 {
		t.Fatalf("asked of the server: %q", w.askedList())
	}
}

func TestTheAddressAskedDecidesWhoIsFirst(t *testing.T) {
	cases := []struct {
		to    netip.AddrPort
		first string
	}{
		{cloudflare, "name " + firstHTTPS + ":443"},
		{google, "name " + secondHTTPS + ":443"},
		{quad9, "name dns.quad9.net:443"},
		{yandex, "name common.dot.dns.yandex.net:443"},
		{custom, "addr 203.0.113.53:53"},
	}
	for _, c := range cases {
		t.Run(c.to.String(), func(t *testing.T) {
			w := newWorld(t)
			for _, name := range []string{firstHTTPS, secondHTTPS, "dns.quad9.net", "common.dot.dns.yandex.net"} {
				w.https(name, withRecords(1))
			}
			w.plain("203.0.113.53", withRecords(1))
			r := w.names(testTiming())
			s, recv := session(t, r)
			if _, err := s.WriteTo(query(t, 1, "example.com.", dnsmessage.TypeA, 0), c.to); err != nil {
				t.Fatal(err)
			}
			recv.wait(t, long)
			if got := w.askedList(); len(got) != 1 || got[0] != c.first {
				t.Fatalf("asked of the server: %q, want only %q", got, c.first)
			}
		})
	}
}

func TestAnAddressOfTheSettingsThatDoesNotAnswerIsAskedLastOfAll(t *testing.T) {
	w := newWorld(t)
	r := w.names(testTiming())
	order := r.order(cloudflare.Addr())
	var labels []string
	for _, s := range order {
		labels = append(labels, s.label)
	}
	want := []string{firstHTTPS, secondHTTPS, "8.8.8.8", "9.9.9.9", "1.1.1.1"}
	if len(labels) != len(want) {
		t.Fatalf("order %q, want %q", labels, want)
	}
	for i := range want {
		if labels[i] != want[i] {
			t.Fatalf("order %q, want %q", labels, want)
		}
	}
	// A resolver that is both the settings' and a usual one is listed once.
	for _, s := range r.order(google.Addr()) {
		labels = append(labels, s.label)
	}
	seen := make(map[string]int)
	for _, s := range r.order(google.Addr()) {
		seen[s.label]++
	}
	for label, n := range seen {
		if n != 1 {
			t.Fatalf("%s listed %d times", label, n)
		}
	}
	if first := r.order(google.Addr())[0].label; first != secondHTTPS {
		t.Fatalf("first for 8.8.8.8 is %s", first)
	}
	if got := r.order(netip.Addr{}); len(got) != 4 || got[0].label != firstHTTPS {
		t.Fatalf("order without an address: %d resolvers", len(got))
	}
	if got := r.order(netip.MustParseAddr("127.0.0.1")); len(got) != 4 {
		t.Fatalf("the phone's own loopback was taken for a resolver")
	}
}

func TestARefusalIsNotTheLastWord(t *testing.T) {
	w := newWorld(t)
	first := w.https(firstHTTPS, withCode(dnsmessage.RCodeServerFailure))
	w.https(secondHTTPS, withRecords(1))
	r := w.names(testTiming())
	s, recv := session(t, r)
	if _, err := s.WriteTo(query(t, 1, "example.com.", dnsmessage.TypeA, 0), cloudflare); err != nil {
		t.Fatal(err)
	}
	if reply := parse(t, recv.wait(t, long)); reply.answers != 1 || reply.header.RCode != dnsmessage.RCodeSuccess {
		t.Fatalf("reply = %+v", reply)
	}
	// It refused what another answered: asked last now.
	if held := r.byHost[firstHTTPS].heldUntil(time.Now()); held.IsZero() {
		t.Fatal("the refusing resolver is still asked first")
	}
	if first.hits.Load() != 1 {
		t.Fatalf("first resolver saw %d lookups", first.hits.Load())
	}
}

func TestANameThatDoesNotExistIsFinal(t *testing.T) {
	w := newWorld(t)
	w.https(firstHTTPS, withCode(dnsmessage.RCodeNameError))
	second := w.https(secondHTTPS, withRecords(1))
	r := w.names(testTiming())
	s, recv := session(t, r)
	if _, err := s.WriteTo(query(t, 1, "nothing.example.", dnsmessage.TypeA, 0), cloudflare); err != nil {
		t.Fatal(err)
	}
	if reply := parse(t, recv.wait(t, long)); reply.header.RCode != dnsmessage.RCodeNameError {
		t.Fatalf("reply = %+v", reply)
	}
	if second.hits.Load() != 0 {
		t.Fatal("another resolver was asked about a name that does not exist")
	}
}

func TestWhenEveryResolverRefusesThePhoneGetsTheirWord(t *testing.T) {
	w := newWorld(t)
	w.https(firstHTTPS, withCode(dnsmessage.RCodeRefused))
	w.https(secondHTTPS, withCode(dnsmessage.RCodeServerFailure))
	w.plain("8.8.8.8", withCode(dnsmessage.RCodeServerFailure))
	w.plain("9.9.9.9", withCode(dnsmessage.RCodeServerFailure))
	w.plain("1.1.1.1", withCode(dnsmessage.RCodeServerFailure))
	r := w.names(testTiming())
	s, recv := session(t, r)
	if _, err := s.WriteTo(query(t, 9, "example.com.", dnsmessage.TypeA, 0), cloudflare); err != nil {
		t.Fatal(err)
	}
	reply := parse(t, recv.wait(t, long))
	if reply.header.ID != 9 || reply.header.RCode != dnsmessage.RCodeRefused {
		t.Fatalf("reply = %+v, want the first resolver's refusal", reply)
	}
	// A resolver spoke: the session carries, and none is held back for a name
	// nobody answers.
	if r.answered.Load() != 1 || r.failed.Load() != 0 {
		t.Fatalf("answered %d, failed %d", r.answered.Load(), r.failed.Load())
	}
	for _, s := range r.order(cloudflare.Addr()) {
		if !s.heldUntil(time.Now()).IsZero() {
			t.Fatalf("%s held back", s.label)
		}
	}
}

func TestNoResolverAtAllIsAServerFailure(t *testing.T) {
	w := newWorld(t) // nothing is routed
	r := w.names(testTiming())
	s, recv := session(t, r)
	q := query(t, 0x4242, "example.com.", dnsmessage.TypeA, 1232)
	if _, err := s.WriteTo(q, cloudflare); err != nil {
		t.Fatal(err)
	}
	reply := parse(t, recv.wait(t, long))
	if reply.header.ID != 0x4242 || reply.header.RCode != dnsmessage.RCodeServerFailure || reply.name != "example.com." {
		t.Fatalf("reply = %+v", reply)
	}
	if r.answered.Load() != 0 || r.failed.Load() != 1 || r.via.Load() != "" {
		t.Fatalf("answered %d, failed %d, via %q", r.answered.Load(), r.failed.Load(), r.via.Load())
	}
	want := []string{
		"name " + firstHTTPS + ":443", "name " + secondHTTPS + ":443",
		"addr 8.8.8.8:53", "addr 9.9.9.9:53", "addr 1.1.1.1:53",
	}
	got := w.askedList()
	if len(got) != len(want) {
		t.Fatalf("asked of the server: %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("asked of the server: %q, want %q", got, want)
		}
	}
}

func TestAReplyToAnotherQuestionIsNotTaken(t *testing.T) {
	w := newWorld(t)
	other := query(t, 0, "other.example.", dnsmessage.TypeA, 0)
	w.https(firstHTTPS, func([]byte) []byte { return withRecords(1)(other) })
	w.https(secondHTTPS, withRecords(2))
	r := w.names(testTiming())
	s, recv := session(t, r)
	if _, err := s.WriteTo(query(t, 3, "example.com.", dnsmessage.TypeA, 0), cloudflare); err != nil {
		t.Fatal(err)
	}
	reply := parse(t, recv.wait(t, long))
	if reply.name != "example.com." || reply.answers != 2 {
		t.Fatalf("reply = %+v", reply)
	}
}

func TestAnAnswerTooLargeForUDPIsRepeatedOverTCP(t *testing.T) {
	w := newWorld(t)
	w.https(firstHTTPS, withRecords(30)) // about 900 bytes
	r := w.names(testTiming())
	s, recv := session(t, r)

	// Without EDNS the asker takes 512 bytes: it is told to ask over TCP.
	q := query(t, 1, "example.com.", dnsmessage.TypeA, 0)
	if _, err := s.WriteTo(q, cloudflare); err != nil {
		t.Fatal(err)
	}
	raw := recv.wait(t, long)
	reply := parse(t, raw)
	if !reply.header.Truncated || reply.answers != 0 || reply.name != "example.com." || len(raw) > 512 {
		t.Fatalf("reply = %+v (%d bytes)", reply, len(raw))
	}

	// With EDNS and room for it the answer comes whole.
	if _, err := s.WriteTo(query(t, 2, "example.com.", dnsmessage.TypeA, 4096), cloudflare); err != nil {
		t.Fatal(err)
	}
	raw = recv.wait(t, long)
	if reply := parse(t, raw); reply.header.Truncated || reply.answers != 30 {
		t.Fatalf("reply = %+v (%d bytes)", reply, len(raw))
	}

	// The asker's size is honoured only up to what never needs IP fragments.
	w.https(firstHTTPS, withRecords(60)) // about 1.8 KB
	r2 := w.names(testTiming())
	s2, recv2 := session(t, r2)
	if _, err := s2.WriteTo(query(t, 3, "example.com.", dnsmessage.TypeA, 4096), cloudflare); err != nil {
		t.Fatal(err)
	}
	if reply := parse(t, recv2.wait(t, long)); !reply.header.Truncated {
		t.Fatalf("reply = %+v", reply)
	}

	// Over TCP the same lookup is answered in full.
	stream, err := (&nameDialer{r: r2, next: refuseAll{}}).DialStream(context.Background(), "1.1.1.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := stream.Write(framed(query(t, 4, "example.com.", dnsmessage.TypeA, 0))); err != nil {
		t.Fatal(err)
	}
	full, err := readFramed(stream)
	if err != nil {
		t.Fatal(err)
	}
	if reply := parse(t, full); reply.header.ID != 4 || reply.header.Truncated || reply.answers != 60 {
		t.Fatalf("reply = %+v", reply)
	}
}

func TestIPv6AddressesAreAnsweredEmptyAtOnce(t *testing.T) {
	w := newWorld(t)
	doh := w.https(firstHTTPS, withRecords(1))
	r := w.names(testTiming())
	s, recv := session(t, r)
	if _, err := s.WriteTo(query(t, 5, "example.com.", dnsmessage.TypeAAAA, 1232), cloudflare); err != nil {
		t.Fatal(err)
	}
	reply := parse(t, recv.wait(t, long))
	if reply.header.ID != 5 || reply.header.RCode != dnsmessage.RCodeSuccess || reply.answers != 0 ||
		!reply.header.Response || reply.header.Truncated || reply.name != "example.com." {
		t.Fatalf("reply = %+v", reply)
	}
	if doh.hits.Load() != 0 || len(w.askedList()) != 0 {
		t.Fatal("a lookup the tunnel cannot use went through the server")
	}
}

func TestARepeatedQueryIsAskedOnce(t *testing.T) {
	w := newWorld(t)
	release := make(chan struct{})
	doh := w.https(firstHTTPS, func(q []byte) []byte {
		<-release
		return withRecords(1)(q)
	})
	r := w.names(testTiming())
	s, recv := session(t, r)
	q := query(t, 77, "example.com.", dnsmessage.TypeA, 0)
	for i := 0; i < 3; i++ {
		if _, err := s.WriteTo(q, cloudflare); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(long)
	for doh.hits.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	close(release)
	recv.wait(t, long)
	recv.none(t, 100*time.Millisecond)
	if doh.hits.Load() != 1 {
		t.Fatalf("resolver saw %d lookups for one query sent three times", doh.hits.Load())
	}
	// Once answered, the same query is a new lookup.
	if _, err := s.WriteTo(q, cloudflare); err != nil {
		t.Fatal(err)
	}
	recv.wait(t, long)
}

func TestOtherUDPIsDropped(t *testing.T) {
	w := newWorld(t)
	r := w.names(testTiming())
	s, recv := session(t, r)
	_, err := s.WriteTo([]byte("a QUIC packet or anything else"), netip.MustParseAddrPort("203.0.113.9:443"))
	if !errors.Is(err, network.ErrPortUnreachable) {
		t.Fatalf("err = %v, want %v", err, network.ErrPortUnreachable)
	}
	for _, junk := range [][]byte{
		nil,
		{1, 2, 3},
		withRecords(1)(query(t, 1, "example.com.", dnsmessage.TypeA, 0)), // a response, not a query
	} {
		if _, err := s.WriteTo(junk, cloudflare); err == nil {
			t.Fatalf("% x taken for a query", junk)
		}
	}
	// A header that says "query" with no readable question gets no answer.
	if _, err := s.WriteTo([]byte{0, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1}, cloudflare); err != nil {
		t.Fatal(err)
	}
	recv.none(t, 100*time.Millisecond)
	if len(w.askedList()) != 0 {
		t.Fatalf("asked of the server: %q", w.askedList())
	}
}

func TestOtherKindsOfMessageAreNotImplemented(t *testing.T) {
	w := newWorld(t)
	r := w.names(testTiming())
	s, recv := session(t, r)
	q := query(t, 6, "example.com.", dnsmessage.TypeA, 0)
	q[2] |= 0x28 // opcode 5, UPDATE
	if _, err := s.WriteTo(q, cloudflare); err != nil {
		t.Fatal(err)
	}
	if reply := parse(t, recv.wait(t, long)); reply.header.RCode != dnsmessage.RCodeNotImplemented {
		t.Fatalf("reply = %+v", reply)
	}
}

func TestAnIdleSessionIsClosed(t *testing.T) {
	w := newWorld(t)
	w.https(firstHTTPS, withRecords(1))
	timing := testTiming()
	timing.idle = 120 * time.Millisecond
	r := w.names(timing)
	s, recv := session(t, r)
	if _, err := s.WriteTo(query(t, 1, "example.com.", dnsmessage.TypeA, 0), cloudflare); err != nil {
		t.Fatal(err)
	}
	recv.wait(t, long)
	deadline := time.Now().Add(long)
	for recv.closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if recv.closed.Load() != 1 {
		t.Fatalf("the stack was told to forget the port %d times, want 1", recv.closed.Load())
	}
	if _, err := s.WriteTo(query(t, 2, "example.com.", dnsmessage.TypeA, 0), cloudflare); !errors.Is(err, network.ErrClosed) {
		t.Fatalf("a closed session took a packet: %v", err)
	}
	r.mu.Lock()
	left := len(r.sessions)
	r.mu.Unlock()
	if left != 0 {
		t.Fatalf("%d sessions remembered", left)
	}
	// A port that only ever sent other UDP is forgotten the same way.
	s2, recv2 := session(t, r)
	_, _ = s2.WriteTo([]byte("not DNS"), netip.MustParseAddrPort("203.0.113.9:443"))
	deadline = time.Now().Add(long)
	for recv2.closed.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if recv2.closed.Load() != 1 {
		t.Fatal("a port with only dropped packets stays remembered")
	}
}

func TestAnIdleConnectionIsClosedAndMadeAgain(t *testing.T) {
	w := newWorld(t)
	w.https(firstHTTPS, withRecords(1))
	timing := testTiming()
	timing.connIdle = 100 * time.Millisecond
	r := w.names(timing)
	s, recv := session(t, r)
	if _, err := s.WriteTo(query(t, 1, "example.com.", dnsmessage.TypeA, 0), cloudflare); err != nil {
		t.Fatal(err)
	}
	recv.wait(t, long)
	source := r.byHost[firstHTTPS]
	deadline := time.Now().Add(long)
	for time.Now().Before(deadline) {
		source.mu.Lock()
		gone := source.conn == nil
		source.mu.Unlock()
		if gone {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	source.mu.Lock()
	gone := source.conn == nil
	source.mu.Unlock()
	if !gone {
		t.Fatal("the unused connection is still kept")
	}
	if _, err := s.WriteTo(query(t, 2, "example.com.", dnsmessage.TypeA, 0), cloudflare); err != nil {
		t.Fatal(err)
	}
	recv.wait(t, long)
	if n := w.askedFor("name " + firstHTTPS + ":443"); n != 2 {
		t.Fatalf("%d streams through the server, want 2", n)
	}
}

func TestAConnectionTheFarSideClosedIsMadeAgain(t *testing.T) {
	w := newWorld(t)
	w.https(firstHTTPS, withRecords(1))
	r := w.names(testTiming())
	s, recv := session(t, r)
	if _, err := s.WriteTo(query(t, 1, "example.com.", dnsmessage.TypeA, 0), cloudflare); err != nil {
		t.Fatal(err)
	}
	recv.wait(t, long)
	// The session was rebuilt under the tunnel: every stream of the old one
	// is gone.
	w.mu.Lock()
	for _, c := range w.conns {
		_ = c.Close()
	}
	w.conns = nil
	w.mu.Unlock()
	source := r.byHost[firstHTTPS]
	deadline := time.Now().Add(long)
	for time.Now().Before(deadline) {
		source.mu.Lock()
		conn := source.conn
		source.mu.Unlock()
		if conn == nil || conn.Err() != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := s.WriteTo(query(t, 2, "example.com.", dnsmessage.TypeA, 0), cloudflare); err != nil {
		t.Fatal(err)
	}
	if reply := parse(t, recv.wait(t, long)); reply.answers != 1 || r.via.Load() != firstHTTPS {
		t.Fatalf("reply = %+v via %v", reply, r.via.Load())
	}
}

func TestACertificateOfAnotherNameIsNotTrusted(t *testing.T) {
	w := newWorld(t)
	// The server answers for the first name with a stand-in of its own, under
	// a certificate the phone has no reason to trust.
	_, forged := testAuthority(t, firstHTTPS)
	impostor := &resolver{answer: withRecords(9)}
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		q, _ := io.ReadAll(req.Body)
		rw.Header().Set("Content-Type", dnsMessageType)
		_, _ = rw.Write(impostor.reply(q))
	}))
	server.EnableHTTP2 = true
	server.TLS = &tls.Config{Certificates: []tls.Certificate{forged}}
	server.StartTLS()
	defer server.Close()
	w.route(firstHTTPS+":443", server.Listener.Addr().String())
	w.https(secondHTTPS, withRecords(1))

	r := w.names(testTiming())
	s, recv := session(t, r)
	if _, err := s.WriteTo(query(t, 1, "example.com.", dnsmessage.TypeA, 0), cloudflare); err != nil {
		t.Fatal(err)
	}
	if reply := parse(t, recv.wait(t, long)); reply.answers != 1 || r.via.Load() != secondHTTPS {
		t.Fatalf("reply = %+v via %v", reply, r.via.Load())
	}
	if impostor.hits.Load() != 0 {
		t.Fatal("a lookup was sent to a resolver whose certificate did not check out")
	}
}

type refuseAll struct{}

func (refuseAll) DialStream(context.Context, string) (transport.StreamConn, error) {
	return nil, errors.New("not a lookup")
}

type countingDialer struct{ asked []string }

func (d *countingDialer) DialStream(_ context.Context, address string) (transport.StreamConn, error) {
	d.asked = append(d.asked, address)
	return nil, errors.New("not dialled in this test")
}

func TestOnlyPort53IsAnsweredHere(t *testing.T) {
	w := newWorld(t)
	r := w.names(testTiming())
	next := &countingDialer{}
	d := &nameDialer{r: r, next: next}
	for _, address := range []string{"203.0.113.9:443", "1.1.1.1:853", "[2001:db8::1]:80"} {
		if _, err := d.DialStream(context.Background(), address); err == nil {
			t.Fatalf("%s answered here", address)
		}
	}
	if len(next.asked) != 3 {
		t.Fatalf("passed on: %q", next.asked)
	}
	stream, err := d.DialStream(context.Background(), "203.0.113.53:53")
	if err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()
	if len(next.asked) != 3 {
		t.Fatalf("a stream to port 53 was passed on: %q", next.asked)
	}
	r.close()
	if _, err := d.DialStream(context.Background(), "203.0.113.53:53"); !errors.Is(err, network.ErrClosed) {
		t.Fatalf("after close: %v", err)
	}
}

func TestLookupsOverTCPFromThePhone(t *testing.T) {
	w := newWorld(t)
	w.https(firstHTTPS, withRecords(2))
	r := w.names(testTiming())
	stream, err := (&nameDialer{r: r, next: refuseAll{}}).DialStream(context.Background(), "1.1.1.1:53")
	if err != nil {
		t.Fatal(err)
	}

	// Two queries at once, cut at odd places as TCP may cut them.
	both := append(framed(query(t, 1, "one.example.", dnsmessage.TypeA, 0)),
		framed(query(t, 2, "two.example.", dnsmessage.TypeA, 0))...)
	for _, cut := range [][]byte{both[:1], both[1:7], both[7:40], both[40:]} {
		if n, err := stream.Write(cut); err != nil || n != len(cut) {
			t.Fatalf("Write = %d, %v", n, err)
		}
	}
	names := make(map[uint16]string)
	for i := 0; i < 2; i++ {
		raw, err := readFramed(stream)
		if err != nil {
			t.Fatal(err)
		}
		reply := parse(t, raw)
		if reply.answers != 2 {
			t.Fatalf("reply = %+v", reply)
		}
		names[reply.header.ID] = reply.name
	}
	if names[1] != "one.example." || names[2] != "two.example." {
		t.Fatalf("answers: %v", names)
	}

	// The phone finishes asking: the stream ends once it has every answer.
	if _, err := stream.Write(framed(query(t, 3, "three.example.", dnsmessage.TypeA, 0))); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	raw, err := readFramed(stream)
	if err != nil {
		t.Fatal(err)
	}
	if reply := parse(t, raw); reply.header.ID != 3 {
		t.Fatalf("reply = %+v", reply)
	}
	if _, err := stream.Read(make([]byte, 16)); err != io.EOF {
		t.Fatalf("after the last answer: %v, want EOF", err)
	}
	if _, err := stream.Write(framed(query(t, 4, "four.example.", dnsmessage.TypeA, 0))); err == nil {
		t.Fatal("a query was taken after the phone finished asking")
	}
	_ = stream.CloseRead()
}

func TestATCPStreamWithNothingOnItEnds(t *testing.T) {
	w := newWorld(t)
	w.https(firstHTTPS, withRecords(1))
	timing := testTiming()
	timing.idle = 100 * time.Millisecond
	r := w.names(timing)
	stream := r.newStream(cloudflare.Addr())
	began := time.Now()
	if _, err := stream.Read(make([]byte, 16)); err != io.EOF {
		t.Fatalf("Read = %v, want EOF", err)
	}
	if took := time.Since(began); took < timing.idle || took > long {
		t.Fatalf("ended after %v", took)
	}

	// Bytes that are no query end it at once.
	stream = r.newStream(cloudflare.Addr())
	if _, err := stream.Write([]byte{0, 3, 1, 2, 3}); err == nil {
		t.Fatal("three bytes taken for a query")
	}
	if _, err := stream.Read(make([]byte, 16)); err != io.EOF {
		t.Fatalf("Read = %v, want EOF", err)
	}
}

func TestATCPStreamHoldsThePhoneBackWhenItDoesNotRead(t *testing.T) {
	w := newWorld(t)
	w.https(firstHTTPS, withRecords(1))
	r := w.names(testTiming())
	stream := r.newStream(cloudflare.Addr())
	defer stream.Close()
	wrote := make(chan int, 1)
	go func() {
		n := 0
		for i := 0; i < 3*maxPipelined; i++ {
			if _, err := stream.Write(framed(query(t, uint16(i+1), "example.com.", dnsmessage.TypeA, 0))); err != nil {
				break
			}
			n++
		}
		wrote <- n
	}()
	select {
	case n := <-wrote:
		t.Fatalf("%d queries taken with no answer read", n)
	case <-time.After(300 * time.Millisecond):
	}
	stream.mu.Lock()
	waiting := len(stream.ready) + stream.flying
	stream.mu.Unlock()
	if waiting > maxPipelined+1 {
		t.Fatalf("%d answers kept for a phone that reads none", waiting)
	}
	for i := 0; i < 3*maxPipelined; i++ {
		if _, err := readFramed(stream); err != nil {
			t.Fatal(err)
		}
	}
	if n := <-wrote; n != 3*maxPipelined {
		t.Fatalf("%d queries taken", n)
	}
}

func TestCheckNames(t *testing.T) {
	w := newWorld(t)
	r := w.names(testTiming())
	if r.check(time.Second) {
		t.Fatal("no resolver is reachable, yet the check passed")
	}
	if r.answered.Load() != 0 || r.failed.Load() != 0 {
		t.Fatal("the check was counted as a lookup of the phone")
	}
	// Any word from a resolver proves the session carries: here a refusal.
	w.plain("9.9.9.9", withCode(dnsmessage.RCodeRefused))
	if !r.check(time.Second) {
		t.Fatal("a resolver answered, yet the check failed")
	}
	if r.via.Load() != "9.9.9.9" {
		t.Fatalf("via %v", r.via.Load())
	}
	w.https(secondHTTPS, withRecords(1))
	r2 := w.names(testTiming())
	if !r2.check(time.Second) || r2.via.Load() != secondHTTPS {
		t.Fatalf("check through %v failed", r2.via.Load())
	}
	// The time given bounds it.
	w2 := newWorld(t)
	for _, target := range []string{firstHTTPS + ":443", secondHTTPS + ":443", "8.8.8.8:53", "9.9.9.9:53"} {
		w2.deaf(target)
	}
	r3 := w2.names(testTiming())
	began := time.Now()
	if r3.check(150 * time.Millisecond) {
		t.Fatal("silence passed the check")
	}
	if took := time.Since(began); took > time.Second {
		t.Fatalf("the check took %v, was given 150 ms", took)
	}
}

func TestCloseEndsEverything(t *testing.T) {
	w := newWorld(t)
	w.deaf(firstHTTPS + ":443")
	w.deaf(secondHTTPS + ":443")
	r := w.names(testTiming())
	s, recv := session(t, r)
	if _, err := s.WriteTo(query(t, 1, "example.com.", dnsmessage.TypeA, 0), cloudflare); err != nil {
		t.Fatal(err)
	}
	stream := r.newStream(cloudflare.Addr())
	if _, err := stream.Write(framed(query(t, 2, "example.com.", dnsmessage.TypeA, 0))); err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	began := time.Now()
	r.close()
	r.close() // twice is once
	if took := time.Since(began); took > time.Second {
		t.Fatalf("close took %v", took)
	}
	recv.none(t, 200*time.Millisecond)
	if recv.closed.Load() != 1 {
		t.Fatalf("the stack was told to forget the port %d times", recv.closed.Load())
	}
	if _, err := stream.Read(make([]byte, 16)); err != io.EOF {
		t.Fatalf("stream after close: %v", err)
	}
	if _, err := r.NewSession(newReceiver()); !errors.Is(err, network.ErrClosed) {
		t.Fatalf("a session after close: %v", err)
	}
	if _, err := s.WriteTo(query(t, 3, "example.com.", dnsmessage.TypeA, 0), cloudflare); !errors.Is(err, network.ErrClosed) {
		t.Fatalf("a packet after close: %v", err)
	}
	if r.check(time.Second) {
		t.Fatal("a check after close passed")
	}
	deadline := time.Now().Add(long)
	for len(r.slots) != 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if len(r.slots) != 0 {
		t.Fatalf("%d lookups still under way after close", len(r.slots))
	}
}

func TestTooManyLookupsAtOnceAreDropped(t *testing.T) {
	w := newWorld(t)
	release := make(chan struct{})
	w.https(firstHTTPS, func(q []byte) []byte {
		<-release
		return withRecords(1)(q)
	})
	r := w.names(testTiming())
	s, recv := session(t, r)
	taken := 0
	for i := 0; i < maxLookups+20; i++ {
		_, err := s.WriteTo(query(t, uint16(i+1), "example.com.", dnsmessage.TypeA, 0), cloudflare)
		switch {
		case err == nil:
			taken++
		case !errors.Is(err, errBusy):
			t.Fatal(err)
		}
	}
	if taken != maxLookups {
		t.Fatalf("%d lookups taken at once, want %d", taken, maxLookups)
	}
	close(release)
	for i := 0; i < taken; i++ {
		recv.wait(t, long)
	}
	// Room again.
	if _, err := s.WriteTo(query(t, 9999, "example.com.", dnsmessage.TypeA, 0), cloudflare); err != nil {
		t.Fatal(err)
	}
	recv.wait(t, long)
}

func TestReadQuery(t *testing.T) {
	q := query(t, 1, "www.example.com.", dnsmessage.TypeA, 0)
	a, ok := readQuery(q)
	if !ok || a.end != len(q) || a.size != 512 || a.kind != 1 || !a.in {
		t.Fatalf("readQuery = %+v, %v", a, ok)
	}
	for _, c := range []struct{ edns, want int }{{512, 512}, {100, 512}, {1232, 1232}, {1400, 1232}, {4096, 1232}, {65535, 1232}} {
		a, ok := readQuery(query(t, 1, "www.example.com.", dnsmessage.TypeHTTPS, c.edns))
		if !ok || a.size != c.want || a.kind != 65 {
			t.Fatalf("EDNS %d: %+v, %v; want size %d", c.edns, a, ok, c.want)
		}
	}
	root := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1}
	if a, ok := readQuery(root); !ok || a.end != len(root) {
		t.Fatalf("the root: %+v, %v", a, ok)
	}
	bad := [][]byte{
		nil,
		q[:11],
		q[:len(q)-1], // the class cut short
		append(append([]byte(nil), q[:5]...), append([]byte{2}, q[6:]...)...), // two questions
		{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 0x0c, 0, 1, 0, 1},          // a pointer where the name should be
		{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 5, 'a', 'b', 0, 0, 1, 0, 1},      // a label longer than what is left
		withRecords(1)(q), // a response
	}
	for _, m := range bad {
		if a, ok := readQuery(m); ok {
			t.Fatalf("% x read as a query: %+v", m, a)
		}
	}
	// A name of the greatest length is a name; one byte more is not.
	label := bytes.Repeat([]byte{'a'}, 63)
	longest := []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	for i := 0; i < 3; i++ {
		longest = append(append(longest, 63), label...)
	}
	longest = append(append(longest, 61), label[:61]...)
	longest = append(longest, 0, 0, 1, 0, 1)
	if _, ok := readQuery(longest); !ok {
		t.Fatal("a 255-byte name was refused")
	}
	tooLong := append([]byte(nil), longest[:12]...)
	for i := 0; i < 4; i++ {
		tooLong = append(append(tooLong, 63), label...)
	}
	tooLong = append(tooLong, 0, 0, 1, 0, 1)
	if _, ok := readQuery(tooLong); ok {
		t.Fatal("a 257-byte name was read as a query")
	}
}

func TestAnswers(t *testing.T) {
	q := query(t, 1, "Www.Example.com.", dnsmessage.TypeA, 0)
	a, _ := readQuery(q)
	good := withRecords(1)(q)
	if !answers(good, q, a) {
		t.Fatal("a plain answer refused")
	}
	lower := withRecords(1)(query(t, 1, "www.example.com.", dnsmessage.TypeA, 0))
	if !answers(lower, q, a) {
		t.Fatal("the same name in other letter case refused")
	}
	for name, reply := range map[string][]byte{
		"another name":   withRecords(1)(query(t, 1, "wwx.example.com.", dnsmessage.TypeA, 0)),
		"another type":   withRecords(1)(query(t, 1, "Www.Example.com.", dnsmessage.TypeTXT, 0)),
		"a query":        q,
		"cut short":      good[:a.end-1],
		"no question":    own(q, a, rcodeSuccess, false)[:headerSize],
		"another opcode": func() []byte { m := append([]byte(nil), good...); m[2] |= 0x10; return m }(),
		// '@' and '`' differ only in the bit that tells letters' case apart.
		"a look-alike": func() []byte {
			m := append([]byte(nil), good...)
			m[headerSize+1] = '`'
			return m
		}(),
	} {
		if name == "a look-alike" {
			at := append([]byte(nil), q...)
			at[headerSize+1] = '@'
			if answers(reply, at, a) {
				t.Fatalf("%s taken for an answer", name)
			}
			continue
		}
		if answers(reply, q, a) {
			t.Fatalf("%s taken for an answer", name)
		}
	}
}

// ---- the whole path: packets in, packets out ----

type packets struct{ got chan []byte }

func (p *packets) WritePacket(b []byte) { p.got <- append([]byte(nil), b...) }

// udpPacket wraps payload in IPv4 and UDP headers.
func udpPacket(from, to netip.AddrPort, payload []byte) []byte {
	total := 20 + 8 + len(payload)
	p := make([]byte, total)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:], uint16(total))
	p[6] = 0x40 // do not fragment
	p[8] = 64
	p[9] = 17
	src, dst := from.Addr().As4(), to.Addr().As4()
	copy(p[12:], src[:])
	copy(p[16:], dst[:])
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(p[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(p[10:], ^uint16(sum))
	binary.BigEndian.PutUint16(p[20:], from.Port())
	binary.BigEndian.PutUint16(p[22:], to.Port())
	binary.BigEndian.PutUint16(p[24:], uint16(8+len(payload)))
	copy(p[28:], payload) // checksum 0: none, as IPv4 allows
	return p
}

// udpPayload reads a packet built like udpPacket's.
func udpPayload(t *testing.T, p []byte) (from, to netip.AddrPort, payload []byte) {
	t.Helper()
	if len(p) < 28 || p[0]>>4 != 4 || p[9] != 17 {
		t.Fatalf("not an IPv4 UDP packet: % x", p)
	}
	header := int(p[0]&0x0f) * 4
	src, _ := netip.AddrFromSlice(p[12:16])
	dst, _ := netip.AddrFromSlice(p[16:20])
	udp := p[header:]
	from = netip.AddrPortFrom(src, binary.BigEndian.Uint16(udp))
	to = netip.AddrPortFrom(dst, binary.BigEndian.Uint16(udp[2:]))
	return from, to, udp[8:binary.BigEndian.Uint16(udp[4:])]
}

func TestDescribed(t *testing.T) {
	for via, want := range map[string]string{
		"":         "",
		firstHTTPS: firstHTTPS + " over HTTPS",
		"8.8.8.8":  "8.8.8.8 over TCP",
	} {
		if got := described(via); got != want {
			t.Errorf("described(%q) = %q, want %q", via, got, want)
		}
	}
}

func TestTunnelAnswersThePhonesLookups(t *testing.T) {
	w := newWorld(t)
	w.user, w.pass = "u", "p"
	w.https(firstHTTPS, withRecords(2))
	host, rawPort, _ := net.SplitHostPort(w.socks.Addr().String())
	port, _ := strconv.Atoi(rawPort)
	out := &packets{got: make(chan []byte, 16)}
	tun, err := buildTunnel(host, port, "u", "p", out, w.roots, testTiming())
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()

	if _, err := NewTunnel(host, port, out); !errors.Is(err, ErrTunnelActive) {
		t.Fatalf("a second tunnel: %v", err)
	}

	phone := netip.MustParseAddrPort("198.18.0.1:40001")
	q := query(t, 0xabcd, "example.com.", dnsmessage.TypeA, 1232)
	if err := tun.WritePacket(udpPacket(phone, cloudflare, q)); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-out.got:
		from, to, payload := udpPayload(t, p)
		if from != cloudflare || to != phone {
			t.Fatalf("answer from %v to %v", from, to)
		}
		reply := parse(t, payload)
		if reply.header.ID != 0xabcd || reply.answers != 2 {
			t.Fatalf("reply = %+v", reply)
		}
	case <-time.After(long):
		t.Fatal("no packet came back")
	}
	if tun.NamesAnswered() != 1 || tun.NamesFailed() != 0 || tun.NamesVia() != firstHTTPS+" over HTTPS" {
		t.Fatalf("answered %d, failed %d, via %q", tun.NamesAnswered(), tun.NamesFailed(), tun.NamesVia())
	}
	if !tun.CheckNames(2000) {
		t.Fatal("CheckNames failed with a resolver answering")
	}
	if tun.CheckNames(0) {
		t.Fatal("CheckNames with no time passed")
	}
	if tun.RxBytes() == 0 || tun.TxBytes() == 0 {
		t.Fatalf("rx %d, tx %d", tun.RxBytes(), tun.TxBytes())
	}

	// Other UDP gets nothing back.
	if err := tun.WritePacket(udpPacket(netip.MustParseAddrPort("198.18.0.1:40002"),
		netip.MustParseAddrPort("203.0.113.9:443"), []byte("not a lookup"))); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-out.got:
		t.Fatalf("a packet came back for dropped UDP: % x", p)
	case <-time.After(150 * time.Millisecond):
	}

	if err := tun.Close(); err != nil {
		t.Fatal(err)
	}
	if tun.CheckNames(1000) {
		t.Fatal("CheckNames passed on a closed tunnel")
	}
	if err := tun.WritePacket(udpPacket(phone, cloudflare, q)); err == nil {
		t.Fatal("a closed tunnel took a packet")
	}

	// The slot is free again, and a tunnel whose HTTPS resolvers cannot be
	// trusted (the system's authorities do not know this test's) still gets
	// names over plain DNS.
	w.plain("8.8.8.8", withRecords(1))
	tun2, err := buildTunnel(host, port, "u", "p", out, nil, testTiming())
	if err != nil {
		t.Fatal(err)
	}
	defer tun2.Close()
	if err := tun2.WritePacket(udpPacket(phone, cloudflare, q)); err != nil {
		t.Fatal(err)
	}
	select {
	case p := <-out.got:
		_, _, payload := udpPayload(t, p)
		if reply := parse(t, payload); reply.answers != 1 {
			t.Fatalf("reply = %+v", reply)
		}
	case <-time.After(long):
		t.Fatal("no packet came back")
	}
	if tun2.NamesVia() != "8.8.8.8 over TCP" {
		t.Fatalf("via %q", tun2.NamesVia())
	}
}

func TestNewTunnelChecksItsArguments(t *testing.T) {
	out := &packets{got: make(chan []byte, 1)}
	if _, err := NewTunnel("127.0.0.1", 1080, nil); err == nil {
		t.Fatal("a tunnel without a writer")
	}
	for _, port := range []int{0, -1, 65536} {
		if _, err := NewTunnel("127.0.0.1", port, out); err == nil {
			t.Fatalf("a tunnel on port %d", port)
		}
	}
	if _, err := NewTunnelAuth("", 1080, "u", "p", out); err == nil {
		t.Fatal("a tunnel without a host")
	}
}
