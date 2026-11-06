package agent

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	maxSkew     = 300 * time.Second // |X-Olc-Time − now| must be within this
	nonceMemory = 10 * time.Minute  // a nonce cannot be reused within this
	rateWindow  = time.Minute
	rateLimit   = 20   // unauthenticated requests per source address per window
	rateMemory  = 4096 // past this many addresses, the ones outside the window are dropped
)

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// canonicalString is the exact byte sequence both sides sign:
//
//	METHOD \n path?query \n time \n nonce \n hex(sha256(body))
//
// path?query is the request URI as sent (path, plus "?"+query when present).
// The Swift client must build this identically.
func canonicalString(method, pathQuery, timeStr, nonce string, body []byte) string {
	bodyHash := sha256.Sum256(body)
	return method + "\n" + pathQuery + "\n" + timeStr + "\n" + nonce + "\n" + hex.EncodeToString(bodyHash[:])
}

// authn holds the short-lived memory the authenticator needs: seen nonces and
// a per-source rate counter for unauthenticated traffic.
type authn struct {
	mu     sync.Mutex
	nonces map[string]time.Time
	rate   map[string]*rateEntry
}

type rateEntry struct {
	count int
	since time.Time
}

func newAuthn() *authn {
	return &authn{nonces: map[string]time.Time{}, rate: map[string]*rateEntry{}}
}

// allow reports whether this source address is still under the unauthenticated
// rate limit, and counts the attempt. Called for every request that does not
// authenticate (bad path, bad signature, unknown device).
func (a *authn) allow(remoteAddr string) bool {
	ip := hostOf(remoteAddr)
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	// Every address that ever probed the port has an entry: on a public port
	// for days that is a scan's worth. Entries past the window count nothing.
	if len(a.rate) > rateMemory {
		for k, e := range a.rate {
			if now.Sub(e.since) > rateWindow {
				delete(a.rate, k)
			}
		}
	}
	e := a.rate[ip]
	if e == nil || now.Sub(e.since) > rateWindow {
		a.rate[ip] = &rateEntry{count: 1, since: now}
		return true
	}
	e.count++
	return e.count <= rateLimit
}

// seenNonce records a nonce and reports whether it was already present within
// the memory window. It also prunes expired entries opportunistically.
func (a *authn) seenNonce(nonce string, now time.Time) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.nonces) > 4096 {
		for k, exp := range a.nonces {
			if now.After(exp) {
				delete(a.nonces, k)
			}
		}
	}
	if exp, ok := a.nonces[nonce]; ok && now.Before(exp) {
		return true
	}
	a.nonces[nonce] = now.Add(nonceMemory)
	return false
}

// verify authenticates a request. It returns the device on success, or nil on
// any failure — the caller answers every failure with the camouflage 404, so
// no distinction between "bad signature", "unknown device" and "stale" ever
// leaks. body is the already-read request body.
func (a *authn) verify(cfg *Config, r *http.Request, body []byte, now time.Time) *Device {
	id := r.Header.Get("X-Olc-Device")
	timeStr := r.Header.Get("X-Olc-Time")
	nonce := r.Header.Get("X-Olc-Nonce")
	sigB64 := r.Header.Get("X-Olc-Sig")
	if id == "" || timeStr == "" || nonce == "" || sigB64 == "" {
		return nil
	}

	ts, err := strconv.ParseInt(timeStr, 10, 64)
	if err != nil {
		return nil
	}
	delta := now.Unix() - ts
	if delta < 0 {
		delta = -delta
	}
	if delta > int64(maxSkew/time.Second) {
		return nil
	}

	dev := cfg.device(id)
	if dev == nil {
		return nil
	}
	pub, err := dev.parsedKey()
	if err != nil {
		return nil
	}

	sig, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil
	}
	canon := canonicalString(r.Method, r.URL.RequestURI(), timeStr, nonce, body)
	digest := sha256.Sum256([]byte(canon))
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return nil
	}

	// Signature is valid and within skew; burn the nonce last so a replay of a
	// request that failed an earlier check is not recorded as seen.
	if a.seenNonce(nonce, now) {
		return nil
	}
	return dev
}

func hostOf(remoteAddr string) string {
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return h
	}
	return remoteAddr
}
