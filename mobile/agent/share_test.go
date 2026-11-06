package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestShareListWritesAListThePhonesCanOpen(t *testing.T) {
	dir := t.TempDir()
	cfg, _, err := Init(dir, 25113, "203.0.113.5", "", "")
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	shareDir := filepath.Join(dir, "share")
	share, err := ShareList(dir, ShareOptions{
		Name: "Home  server", Host: "203.0.113.5", SharePort: 31000,
		URIs: []string{"olcrtc://jitsi?datachannel@https://meet.example.org/room#" + strings.Repeat("ab", 32)},
		Role: "owner", Dir: shareDir,
	})
	if err != nil {
		t.Fatalf("share: %v", err)
	}
	if len(share.Token) != 32 || len(share.Key) != 32 {
		t.Fatalf("token/key: %q %d", share.Token, len(share.Key))
	}
	wantLink := "olcrtc-sub://203.0.113.5:31000/" + share.Token + "?enc=v1#"
	if !strings.HasPrefix(share.Link, wantLink) {
		t.Fatalf("link %q", share.Link)
	}
	served, err := os.ReadFile(filepath.Join(shareDir, share.Token))
	if err != nil {
		t.Fatalf("list file: %v", err)
	}
	body, err := openInvite(string(served), share.Key)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	for _, want := range []string{
		"#name: Home server\n", "#refresh: 30m\n", "#agent: 203.0.113.5:25113\n",
		"#agent-cert: " + cfg.CertSHA + "\n", "#agent-prefix: " + cfg.Prefix + "\n",
		"#agent-code: " + share.Code + "\n", "#agent-role: owner\n",
		"\nolcrtc://jitsi?datachannel@", "\n##name: Home server\n", "\n##id: ",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("list lacks %q:\n%s", want, body)
		}
	}
	// The code is live on the agent and grants the owner role.
	saved, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(saved.Invites) != 1 || saved.Invites[0].Code != share.Code || saved.Invites[0].Role != RoleOwner {
		t.Fatalf("invite not saved: %+v", saved.Invites)
	}
	if _, err := openInvite(string(served), make([]byte, 32)); err == nil {
		t.Fatal("a wrong key opened the list")
	}
}

func TestInitWithoutAnOwnerLeavesNoDevice(t *testing.T) {
	dir := t.TempDir()
	cfg, ownerID, err := Init(dir, 0, "[2001:db8::1]", "", "")
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	if ownerID != "" || len(cfg.Devices) != 0 {
		t.Fatalf("expected no device, got %q %+v", ownerID, cfg.Devices)
	}
	if inviteLink("2001:db8::1", 31000, strings.Repeat("0", 32), make([]byte, 32)) !=
		"olcrtc-sub://[2001:db8::1]:31000/"+strings.Repeat("0", 32)+"?enc=v1#"+strings.Repeat("A", 43) {
		t.Fatal("IPv6 link is not bracketed")
	}
}
