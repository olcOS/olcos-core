package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/openlibrecommunity/olcrtc/internal/app/session"
)

// ai-generated: the whole file (SIGHUP reloads crypto.keys_file).

const (
	reloadTestKey1 = "0011223344556677889900112233445566778899001122334455667788990011"
	reloadTestKey2 = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
)

// serverYAML is the config of a server with the given crypto block.
func serverYAML(crypto string) string {
	return `
mode: srv
auth:
  provider: jitsi
room:
  id: https://meet.systemli.org/test
crypto:
` + crypto + `
net:
  transport: datachannel
  dns: 8.8.8.8:53
`
}

func writeKeysFile(t *testing.T, path string, keys ...string) {
	t.Helper()
	body := "# the keys of this server\n\n" + strings.Join(keys, "\n\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write keys file: %v", err)
	}
}

func TestLoadConfigGivesAServerItsKeysFileToReadAgain(t *testing.T) {
	dir := t.TempDir()
	keysFile := filepath.Join(dir, "keys.txt")
	writeKeysFile(t, keysFile, reloadTestKey1)
	configPath := filepath.Join(dir, "olcrtc.yaml")
	if err := os.WriteFile(configPath, []byte(serverYAML("  keys_file: keys.txt")), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("loadConfig() error = %v", err)
	}
	if cfg.keys == nil {
		t.Fatal("loadConfig gave a server with a keys file nothing to read it again with")
	}

	writeKeysFile(t, keysFile, reloadTestKey1, reloadTestKey2)

	got, err := cfg.keys()
	if err != nil || !reflect.DeepEqual(got, []string{reloadTestKey1, reloadTestKey2}) {
		t.Fatalf("keys() = %v, %v, want the keys the file holds now", got, err)
	}
}

func TestLoadConfigGivesNoReadToKeysThatAreNotInAFile(t *testing.T) {
	for name, crypto := range map[string]string{
		"single key":  "  key: " + reloadTestKey1,
		"inline keys": "  keys:\n    - " + reloadTestKey1 + "\n    - " + reloadTestKey2,
	} {
		t.Run(name, func(t *testing.T) {
			path := writeYAML(t, serverYAML(crypto))
			cfg, err := loadConfig(path)
			if err != nil {
				t.Fatalf("loadConfig() error = %v", err)
			}
			if cfg.keys != nil {
				t.Fatal("loadConfig gave keys that are not in a file a read")
			}
		})
	}
}

func TestWithHangupReloadGivesAServerOfAKeysFileAReloadAndNoOneElse(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	keys := func() ([]string, error) { return []string{reloadTestKey1}, nil }

	cfg, stop := withHangupReload(ctx, session.Config{Mode: session.ModeSrv}, keys)
	stop()
	if cfg.KeyReload == nil || cfg.KeyReload.Read == nil || cfg.KeyReload.Request == nil {
		t.Fatal("a server whose keys are in a file got no reload")
	}

	cfg, stop = withHangupReload(ctx, session.Config{Mode: session.ModeSrv}, nil)
	stop()
	if cfg.KeyReload != nil {
		t.Fatal("a server whose keys are not in a file got a reload")
	}

	for _, mode := range []string{session.ModeCnc, session.ModeGen} {
		cfg, stop = withHangupReload(ctx, session.Config{Mode: mode}, keys)
		stop()
		if cfg.KeyReload != nil {
			t.Fatalf("a %s run got a reload", mode)
		}
	}
}

// Signals do not queue: a SIGHUP that comes while a reload is waiting to be
// served is that reload, and the next one after it is a request of its own.
func TestHangupsBecomeOneRequestAtATime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hups := make(chan os.Signal, 3)
	requests := make(chan struct{}, 1)
	go forwardHangups(ctx, hups, requests)

	for range 3 {
		hups <- syscall.SIGHUP
	}
	waitFor(t, "the signals to be taken", func() bool { return len(hups) == 0 })
	time.Sleep(20 * time.Millisecond)
	if got := len(requests); got != 1 {
		t.Fatalf("%d requests waiting after three signals, want 1", got)
	}

	<-requests
	hups <- syscall.SIGHUP
	waitFor(t, "the next signal to be a request", func() bool { return len(requests) == 1 })
}

// eventually polls done for a few seconds and reports whether it came true.
// It never ends a test, so a goroutine other than the test's may call it.
func eventually(done func() bool) bool {
	deadline := time.Now().Add(5 * time.Second)
	for !done() {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(2 * time.Millisecond)
	}
	return true
}

func waitFor(t *testing.T, what string, done func() bool) {
	t.Helper()
	if !eventually(done) {
		t.Fatalf("timed out waiting for %s", what)
	}
}
