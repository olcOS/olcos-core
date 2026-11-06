package session

import (
	"bytes"
	"errors"
	"log"
	"reflect"
	"strings"
	"testing"

	"github.com/openlibrecommunity/olcrtc/internal/server"
)

// The server's per-stream traffic line keeps the session and the byte counts
// and drops the destination: an exit's log is no record of where its users
// go. ai-generated: the whole test (egress hardening).
func TestLogTrafficNamesNoDestination(t *testing.T) {
	var buf bytes.Buffer
	oldWriter, oldFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(oldWriter)
		log.SetFlags(oldFlags)
	})

	logTraffic("sid-1", "secret-destination.test:4321", 11, 17)

	got := buf.String()
	if got != "traffic: session=sid-1 in=11 out=17\n" {
		t.Fatalf("traffic line = %q", got)
	}
	if strings.Contains(got, "secret-destination") || strings.Contains(got, "4321") {
		t.Fatalf("traffic line names the destination: %q", got)
	}
}

// A server that starts again - a lifecycle rotation, a restart inside one
// process - starts from the keys file as it is now, not from the keys the
// process was given when it began: a key the file lost since must not come
// back.
//
// ai-generated: the whole test (reload of crypto.keys_file on SIGHUP).
func TestServerKeysAreReadAgainFromTheFileTheyCameFrom(t *testing.T) {
	cfg := Config{
		KeysHex: []string{"stale"},
		KeyReload: &server.KeyReload{
			Read: func() ([]string, error) { return []string{"fresh"}, nil },
		},
	}
	got, err := serverKeys(cfg)
	if err != nil || !reflect.DeepEqual(got, []string{"fresh"}) {
		t.Fatalf("serverKeys() = %v, %v, want the keys the file holds now", got, err)
	}
}

func TestServerKeysWithoutAFileAreTheKeysItWasGiven(t *testing.T) {
	cfg := Config{KeysHex: []string{"given"}}
	got, err := serverKeys(cfg)
	if err != nil || !reflect.DeepEqual(got, []string{"given"}) {
		t.Fatalf("serverKeys() = %v, %v, want the configured keys", got, err)
	}
}

// A file that cannot be read at a restart stops the run: a server never
// falls back to a ring its operator has replaced.
func TestServerKeysFailWhenTheFileCannotBeRead(t *testing.T) {
	errGone := errors.New("keys file: gone")
	cfg := Config{
		KeysHex:   []string{"stale"},
		KeyReload: &server.KeyReload{Read: func() ([]string, error) { return nil, errGone }},
	}
	if _, err := serverKeys(cfg); !errors.Is(err, errGone) {
		t.Fatalf("serverKeys() error = %v, want the read's error", err)
	}
}
