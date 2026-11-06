package xray

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/xtls/xray-core/core"

	"github.com/olcOS/olcos-core/engine"
)

// The same measurement as the olcrtc core's mobile ping (mobile/ping.go):
// GET a 204 URL through the tunnel, one warm-up request, then the best of
// three samples over the warmed connection. Measuring both protocols the same
// way is what lets the app say which one is faster right now.
const (
	DefaultPingURL    = "https://www.google.com/generate_204"
	pingWarmupTimeout = 1500 * time.Millisecond
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
	port, err := freePort()
	if err != nil {
		return 0, err
	}
	// loglevel none: this instance must not feed the running session's log
	// sink, where its failures would read as health events of that session.
	raw, err := RenderClientConfig(p, ClientOptions{SocksPort: port, TunFD: -1, LogLevel: "none"})
	if err != nil {
		return 0, err
	}
	cfg, err := core.LoadConfig("json", bytes.NewReader(raw))
	if err != nil {
		return 0, fmt.Errorf("xray: load config: %w", err)
	}
	inst, err := core.New(cfg)
	if err != nil {
		return 0, fmt.Errorf("xray: new instance: %w", err)
	}
	if err := inst.Start(); err != nil {
		_ = inst.Close()
		return 0, fmt.Errorf("xray: start: %w", err)
	}
	defer inst.Close()

	transport := &http.Transport{
		Proxy:                 http.ProxyURL(&url.URL{Scheme: "socks5", Host: net.JoinHostPort("127.0.0.1", strconv.Itoa(port))}),
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       10 * time.Second,
		TLSHandshakeTimeout:   pingSampleTimeout,
		ResponseHeaderTimeout: pingSampleTimeout,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport:     transport,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}

	_, warmErr := pingOnce(ctx, client, targetURL, pingWarmupTimeout)
	var best int64
	lastErr := warmErr
	for i := 0; i < pingSamples; i++ {
		elapsed, err := pingOnce(ctx, client, targetURL, pingSampleTimeout)
		if err != nil {
			lastErr = err
		} else if elapsed > 0 && (best == 0 || elapsed < best) {
			best = elapsed
		}
		if i < pingSamples-1 && !sleepCtx(ctx, pingSampleDelay) {
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
