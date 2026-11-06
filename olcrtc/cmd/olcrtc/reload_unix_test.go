//go:build !windows

package main

import (
	"bytes"
	"context"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/app/session"
)

// ai-generated: the whole file (SIGHUP reloads crypto.keys_file). These
// tests send the signal to the test process itself.

// keepAlive registers for SIGHUP for the rest of the test, so that a signal
// nothing else handles ends the test with a failure and not the process.
func keepAlive(t *testing.T) {
	t.Helper()
	guard := make(chan os.Signal, 8)
	signal.Notify(guard, syscall.SIGHUP)
	t.Cleanup(func() { signal.Stop(guard) })
}

// hangUpOnSelf sends SIGHUP to the test process and reports whether it went.
// The runs these tests stub out are on goroutines of their own, where a test
// must not end itself: a run that never returns would hang the whole test.
func hangUpOnSelf(t *testing.T) bool {
	t.Helper()
	if err := syscall.Kill(syscall.Getpid(), syscall.SIGHUP); err != nil {
		t.Errorf("send SIGHUP: %v", err)
		return false
	}
	return true
}

func TestSIGHUPAsksTheServerToReadItsKeysFileAgain(t *testing.T) {
	session.RegisterDefaults()
	keepAlive(t)
	dir := t.TempDir()
	keysFile := filepath.Join(dir, "keys.txt")
	writeKeysFile(t, keysFile, reloadTestKey1)
	configPath := filepath.Join(dir, "olcrtc.yaml")
	if err := os.WriteFile(configPath, []byte(serverYAML("  keys_file: keys.txt")), 0o600); err != nil {
		t.Fatal(err)
	}

	oldRunSession := runSession
	t.Cleanup(func() { runSession = oldRunSession })
	runSession = func(_ context.Context, cfg session.Config) error {
		if cfg.KeyReload == nil {
			t.Error("a server whose keys are in a file was started without a reload")
			return nil
		}
		writeKeysFile(t, keysFile, reloadTestKey1, reloadTestKey2)
		if !hangUpOnSelf(t) {
			return nil
		}
		select {
		case <-cfg.KeyReload.Request:
		case <-time.After(5 * time.Second):
			t.Error("SIGHUP never became a request to reload")
			return nil
		}
		got, err := cfg.KeyReload.Read()
		if err != nil || !reflect.DeepEqual(got, []string{reloadTestKey1, reloadTestKey2}) {
			t.Errorf("the reload read %v, %v, want the keys the file holds now", got, err)
		}
		return nil
	}

	if err := runWithArgs([]string{configPath}); err != nil {
		t.Fatalf("runWithArgs() error = %v", err)
	}
}

// lockedLog is a log destination the race detector accepts.
type lockedLog struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *lockedLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *lockedLog) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// Keys inline or in a single key have no file to read again. SIGHUP says so
// and the run goes on as it was.
func TestSIGHUPOfAServerWhoseKeysAreNotInAFileChangesNothing(t *testing.T) {
	session.RegisterDefaults()
	keepAlive(t)
	out := &lockedLog{}
	oldWriter, oldFlags := log.Writer(), log.Flags()
	t.Cleanup(func() {
		log.SetOutput(oldWriter)
		log.SetFlags(oldFlags)
	})

	oldRunSession := runSession
	t.Cleanup(func() { runSession = oldRunSession })
	runSession = func(ctx context.Context, cfg session.Config) error {
		if cfg.KeyReload != nil {
			t.Error("a server whose keys are not in a file was started with a reload")
			return nil
		}
		// The run sets the log up before it calls the session; listen after.
		log.SetOutput(out)
		log.SetFlags(0)
		if !hangUpOnSelf(t) {
			return nil
		}
		if !eventually(func() bool { return strings.Contains(out.String(), "SIGHUP: nothing to reload") }) {
			t.Error("SIGHUP was not answered")
			return nil
		}
		if ctx.Err() != nil {
			t.Error("SIGHUP ended the run")
		}
		return nil
	}

	path := writeYAML(t, serverYAML("  key: "+reloadTestKey1))
	if err := runWithArgs([]string{path}); err != nil {
		t.Fatalf("runWithArgs() error = %v", err)
	}
}
