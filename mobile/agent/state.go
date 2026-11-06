package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os/exec"
	"sort"
	"sync"
	"time"
)

const (
	maxOutputBytes = 32 * 1024 // cap per status output and per log tail
	safetyInterval = 60 * time.Second
)

// State is the agent's live picture of the server: the cached outputs of the
// app's named status scripts, a version counter that bumps only when those
// outputs change, and the long-poll machinery the events endpoint uses. It is
// safe for concurrent use.
type State struct {
	mu      sync.Mutex
	scripts map[string]string
	outputs map[string]string
	hash    string
	version uint64
	changed chan struct{} // closed on every version bump, then replaced
	safety  time.Duration

	// runScript runs one named status script and returns its stdout. Injected
	// so tests never touch the OS; serve() sets the real bash runner.
	runScript func(name, script string) string
	// roomAction performs a room lifecycle action (start/stop/restart).
	// Injected for the same reason.
	roomAction func(container, action string) error
}

func newState(scripts map[string]string, safety time.Duration) *State {
	return &State{
		scripts: scripts,
		outputs: map[string]string{},
		changed: make(chan struct{}),
		safety:  safety,
	}
}

// Version returns the current version counter.
func (s *State) Version() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version
}

// setOutputs replaces the cached outputs and bumps the version (waking any
// long-pollers) only when the combined content actually changed.
func (s *State) setOutputs(outputs map[string]string) {
	h := hashOutputs(outputs)
	s.mu.Lock()
	defer s.mu.Unlock()
	if h == s.hash && s.version != 0 {
		return
	}
	s.outputs = outputs
	s.hash = h
	s.version++
	close(s.changed)
	s.changed = make(chan struct{})
}

// statusOutputs returns a capped copy of the cached outputs, safe to hand out.
func (s *State) statusOutputs() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.outputs))
	for k, v := range s.outputs {
		out[k] = capBytes(v, maxOutputBytes)
	}
	return out
}

// waitForChange blocks until the version is newer than since, or timeout
// elapses, and returns the version observed. If the caller is already behind,
// it returns at once.
func (s *State) waitForChange(since uint64, timeout time.Duration) uint64 {
	s.mu.Lock()
	if s.version > since {
		v := s.version
		s.mu.Unlock()
		return v
	}
	ch := s.changed
	s.mu.Unlock()

	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-ch:
	case <-timer.C:
	}
	return s.Version()
}

// refresh re-runs every status script and updates the cache. A no-op when no
// runner is injected (unit tests drive setOutputs directly).
func (s *State) refresh() {
	if s.runScript == nil {
		return
	}
	s.mu.Lock()
	scripts := s.scripts
	s.mu.Unlock()
	out := make(map[string]string, len(scripts))
	for name, script := range scripts {
		out[name] = s.runScript(name, script)
	}
	s.setOutputs(out)
}

// setScripts swaps the status scripts and refreshes once.
func (s *State) setScripts(scripts map[string]string) {
	s.useScripts(scripts)
	s.refresh()
}

// useScripts swaps the status scripts without running them; the next
// refresh runs the new ones.
func (s *State) useScripts(scripts map[string]string) {
	s.mu.Lock()
	s.scripts = scripts
	s.mu.Unlock()
}

// watch keeps the cache fresh: it follows `podman events` and re-reads on every
// container event (debounced), with a safety refresh every safetyInterval so a
// dropped event stream can never leave the status stale for long. It returns
// when ctx is done.
func (s *State) watch(ctx context.Context) {
	s.refresh()
	safety := s.safety
	if safety <= 0 {
		safety = safetyInterval
	}
	ticker := time.NewTicker(safety)
	defer ticker.Stop()

	events := make(chan struct{}, 1)
	go s.followEvents(ctx, events)

	// Debounce: a burst of events collapses into one refresh.
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.refresh()
		case <-events:
			select {
			case <-time.After(400 * time.Millisecond):
			case <-ctx.Done():
				return
			}
			drain(events)
			s.refresh()
		}
	}
}

// followEvents streams container events and signals the channel on each one,
// reopening the stream if it ends (podman restart, etc).
func (s *State) followEvents(ctx context.Context, signal chan<- struct{}) {
	for ctx.Err() == nil {
		cmd := exec.CommandContext(ctx, "podman", "events",
			"--format", "{{.Status}}", "--filter", "type=container")
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		if err := cmd.Start(); err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		buf := make([]byte, 256)
		for {
			if _, err := stdout.Read(buf); err != nil {
				break
			}
			select {
			case signal <- struct{}{}:
			default:
			}
		}
		_ = cmd.Wait()
		if ctx.Err() == nil {
			time.Sleep(2 * time.Second)
		}
	}
}

func drain(ch chan struct{}) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func hashOutputs(outputs map[string]string) string {
	keys := make([]string, 0, len(outputs))
	for k := range outputs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{0})
		h.Write([]byte(outputs[k]))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

func capBytes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	// keep the tail — the most recent lines are the useful ones
	return s[len(s)-max:]
}
