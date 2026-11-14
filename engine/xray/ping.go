package xray

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/xtls/xray-core/core"

	"github.com/olcOS/olcos-core/engine"
)

// The same measurement as the olcrtc core's mobile ping (mobile/ping.go):
// GET a 204 URL through the tunnel, one warm-up request, then the best of
// three samples over the warmed connection. Measuring both protocols the same
// way is what lets the app say which one is faster right now.
//
// The warm-up has more time than a sample: it sets the whole path up (the
// handshake with the server, a WebSocket upgrade behind a CDN, the handshake
// with the target), which on a mobile network takes seconds. A server that
// needs two of them is slow, not dead.
const (
	DefaultPingURL    = "https://www.google.com/generate_204"
	pingWarmupTimeout = 4 * time.Second
	pingSampleTimeout = 1500 * time.Millisecond
	pingSamples       = 3
	pingSampleDelay   = 80 * time.Millisecond
)

// ErrPingFailed is returned when no sample got an answer.
var ErrPingFailed = errors.New("xray: no answer through the tunnel")

// Ping measures the round trip of an HTTP request through a temporary Xray
// client for profile p, independent of any running session. Unlike a TCP
// connect to the server, it fails on a wrong UUID or key and on a path that
// drops the traffic after the handshake. The warm-up request carries the
// REALITY handshake; the samples measure the tunnel's round trip.
func Ping(ctx context.Context, p engine.Profile, targetURL string) (int64, error) {
	if targetURL == "" {
		targetURL = DefaultPingURL
	}
	if u, err := url.ParseRequestURI(targetURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return 0, fmt.Errorf("xray: ping URL %q is not http(s)", targetURL)
	}
	inst, port, user, pass, err := startProbe(p)
	if err != nil {
		return 0, err
	}
	defer inst.Close()

	transport := &http.Transport{
		Proxy:                 http.ProxyURL(&url.URL{Scheme: "socks5", User: url.UserPassword(user, pass), Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}),
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       10 * time.Second,
		TLSHandshakeTimeout:   pingWarmupTimeout,
		ResponseHeaderTimeout: pingWarmupTimeout,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	return measure(ctx, client, targetURL)
}

// probeStartTries is how many local ports a probe tries: several probes run
// side by side when the app looks through a list, and two of them can be
// handed the same free port.
const probeStartTries = 3

// startProbe brings up the temporary client of a ping on a free local port.
func startProbe(p engine.Profile) (inst *core.Instance, port int, user, pass string, err error) {
	for try := 0; try < probeStartTries; try++ {
		if port, err = freePort(); err != nil {
			return nil, 0, "", "", err
		}
		// loglevel none: this instance must not feed the running session's
		// log sink, where its failures would read as health events of that
		// session. Throwaway credentials: no other local client may use this
		// listener while it lives.
		user, pass = rand.Text(), rand.Text()
		var raw []byte
		raw, err = RenderClientConfig(p, ClientOptions{SocksPort: port, TunFD: -1, LogLevel: "none", SocksUser: user, SocksPass: pass})
		if err != nil {
			return nil, 0, "", "", err
		}
		var cfg *core.Config
		if cfg, err = core.LoadConfig("json", bytes.NewReader(raw)); err != nil {
			return nil, 0, "", "", fmt.Errorf("xray: load config: %w", err)
		}
		if inst, err = core.New(cfg); err != nil {
			return nil, 0, "", "", fmt.Errorf("xray: new instance: %w", err)
		}
		if err = inst.Start(); err == nil {
			return inst, port, user, pass, nil
		}
		_ = inst.Close()
		err = fmt.Errorf("xray: start: %w", err)
		if !portTaken(err) {
			break
		}
	}
	return nil, 0, "", "", err
}

// portTaken says whether a start failed because another listener took the
// port between its choice and its use.
func portTaken(err error) bool {
	return errors.Is(err, syscall.EADDRINUSE) || strings.Contains(err.Error(), "address already in use")
}

// measure is the warm-up and the samples over an HTTP client that already
// goes through the tunnel.
func measure(ctx context.Context, client *http.Client, targetURL string) (int64, error) {
	_, warmErr := pingOnce(ctx, client, targetURL, pingWarmupTimeout)
	samples := pingSamples
	if warmErr != nil {
		// Nothing answered in the time a slow path needs. One more try
		// covers a path that came up just after; three would only make a
		// dead server slower to name.
		samples = 1
	}
	var best int64
	lastErr := warmErr
	for i := 0; i < samples; i++ {
		elapsed, err := pingOnce(ctx, client, targetURL, pingSampleTimeout)
		if err != nil {
			lastErr = err
		} else if elapsed > 0 && (best == 0 || elapsed < best) {
			best = elapsed
		}
		if i < samples-1 && !sleepCtx(ctx, pingSampleDelay) {
			break
		}
	}
	if best > 0 {
		return best, nil
	}
	if lastErr != nil {
		return 0, fmt.Errorf("%w: %v", ErrPingFailed, lastErr)
	}
	return 0, ErrPingFailed
}

// sleepCtx waits d, or reports false when ctx ends first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// pingOnce returns the milliseconds until the response headers arrived.
func pingOnce(parent context.Context, client *http.Client, targetURL string, timeout time.Duration) (int64, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return 0, err
	}
	started := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	elapsed := time.Since(started).Milliseconds()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64*1024))
	_ = resp.Body.Close()
	if resp.StatusCode >= 400 {
		return 0, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	if elapsed < 1 {
		elapsed = 1
	}
	return elapsed, nil
}
