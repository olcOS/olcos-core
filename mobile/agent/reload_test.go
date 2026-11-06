package agent

import (
	"os"
	"testing"
	"time"
)

// The running agent follows config.json on disk: the phones mint and revoke
// invites with the CLI, which only rewrites the file, and serve must neither
// miss those writes nor overwrite them with the copy it started with.

// diskHandler is the handler Serve builds: it serves dir's config.json.
func diskHandler(t *testing.T, dir string) *apiHandler {
	t.Helper()
	cfg, stamp, err := loadStamped(dir)
	if err != nil {
		t.Fatal(err)
	}
	h := newHandler(cfg, testState(nil))
	h.dir, h.stamp = dir, stamp
	return h
}

func savedConfig(t *testing.T, devices ...Device) (string, *Config) {
	t.Helper()
	dir := t.TempDir()
	cfg := testConfig(devices...)
	if err := cfg.Save(dir); err != nil {
		t.Fatal(err)
	}
	return dir, cfg
}

func TestInviteMintedByTheCLIAfterStartCanBePaired(t *testing.T) {
	owner := newTestKey(t)
	dir, cfg := savedConfig(t, owner.device(RoleOwner))
	h := diskHandler(t, dir)

	// The owner's phone mints a code over SSH while the agent serves.
	inv, err := CreateInvite(dir, "member", "tablet", 30)
	if err != nil {
		t.Fatal(err)
	}
	guest := newTestKey(t)
	if rec := do(h, pairRequest(cfg, pairBody(t, inv.Code, guest, "tablet"))); rec.Code != 200 {
		t.Fatalf("pair with a code minted after start: want 200, got %d", rec.Code)
	}
	saved, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if d := saved.device(guest.id); d == nil || d.Role != RoleMember {
		t.Fatalf("the paired device is not on disk: %+v", d)
	}
	if saved.hasUsableInvite(inv.Code, time.Now()) {
		t.Fatal("the code must be burned on disk")
	}
	if rec := do(h, guest.sign(t, "GET", statusPath(cfg), nil, time.Now(), "n-reload-guest")); rec.Code != 200 {
		t.Fatalf("the paired device's signed call: want 200, got %d", rec.Code)
	}
}

func TestRevokeByTheCLIReachesTheRunningAgent(t *testing.T) {
	owner := newTestKey(t)
	dir, cfg := savedConfig(t, owner.device(RoleOwner))
	inv, err := CreateInvite(dir, "member", "tablet", 30)
	if err != nil {
		t.Fatal(err)
	}
	h := diskHandler(t, dir)
	guest := newTestKey(t)
	if rec := do(h, pairRequest(cfg, pairBody(t, inv.Code, guest, "tablet"))); rec.Code != 200 {
		t.Fatalf("pair: %d", rec.Code)
	}
	if rec := do(h, guest.sign(t, "GET", statusPath(cfg), nil, time.Now(), "n-revoke-before")); rec.Code != 200 {
		t.Fatalf("before the revoke: want 200, got %d", rec.Code)
	}

	// The owner's phone revokes the invite over SSH.
	revoked, err := RevokeInvite(dir, inv.Code)
	if err != nil || revoked != guest.id {
		t.Fatalf("RevokeInvite = %q, %v", revoked, err)
	}
	assert404(t, do(h, guest.sign(t, "GET", statusPath(cfg), nil, time.Now(), "n-revoke-after")))
	if rec := do(h, owner.sign(t, "GET", statusPath(cfg), nil, time.Now(), "n-revoke-owner")); rec.Code != 200 {
		t.Fatalf("the owner keeps access: got %d", rec.Code)
	}
}

func TestPairKeepsAnInviteTheCLIMintedAfterStart(t *testing.T) {
	owner := newTestKey(t)
	dir, cfg := savedConfig(t, owner.device(RoleOwner))
	first, err := CreateInvite(dir, "member", "tablet", 30)
	if err != nil {
		t.Fatal(err)
	}
	h := diskHandler(t, dir)
	second, err := CreateInvite(dir, "owner", "laptop", 30) // after start
	if err != nil {
		t.Fatal(err)
	}

	guest := newTestKey(t)
	if rec := do(h, pairRequest(cfg, pairBody(t, first.Code, guest, "tablet"))); rec.Code != 200 {
		t.Fatalf("pair: %d", rec.Code)
	}
	// The agent's write kept the code it never had in memory...
	saved, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !saved.hasUsableInvite(second.Code, time.Now()) {
		t.Fatalf("the pair dropped an invite minted on disk: %+v", saved.Invites)
	}
	// ...and that code still pairs.
	other := newTestKey(t)
	if rec := do(h, pairRequest(cfg, pairBody(t, second.Code, other, "laptop"))); rec.Code != 200 {
		t.Fatalf("pair with the second code: %d", rec.Code)
	}
	if d := mustLoad(t, dir).device(other.id); d == nil || d.Role != RoleOwner {
		t.Fatalf("second device: %+v", d)
	}
}

// API changes (revoke, mint) build on the file as it is now, not on the copy
// the agent started with.
func TestAPIChangesKeepCLIWrites(t *testing.T) {
	owner := newTestKey(t)
	member := newTestKey(t)
	dir, cfg := savedConfig(t, owner.device(RoleOwner), member.device(RoleMember))
	h := diskHandler(t, dir)

	added := newTestKey(t)
	if _, err := AddDevice(dir, added.device(RoleMember).PublicKey, "member", "added", time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	inv, err := CreateInvite(dir, "member", "x", 30)
	if err != nil {
		t.Fatal(err)
	}
	rec := do(h, owner.sign(t, "DELETE", "/"+cfg.Prefix+"/v1/devices/"+member.id, nil, time.Now(), "n-keep-revoke"))
	if rec.Code != 200 {
		t.Fatalf("revoke: %d %s", rec.Code, rec.Body.String())
	}
	rec = do(h, owner.sign(t, "POST", "/"+cfg.Prefix+"/v1/invites", []byte(`{"role":"member"}`), time.Now(), "n-keep-mint"))
	if rec.Code != 200 {
		t.Fatalf("mint: %d %s", rec.Code, rec.Body.String())
	}
	saved := mustLoad(t, dir)
	if saved.device(added.id) == nil || !saved.hasUsableInvite(inv.Code, time.Now()) {
		t.Fatalf("an API change dropped a CLI write: devices %+v invites %+v", saved.Devices, saved.Invites)
	}
	if saved.device(member.id) != nil || len(saved.Invites) != 2 {
		t.Fatalf("the API changes are missing: devices %+v invites %+v", saved.Devices, saved.Invites)
	}
	if rec := do(h, added.sign(t, "GET", statusPath(cfg), nil, time.Now(), "n-keep-added")); rec.Code != 200 {
		t.Fatalf("a device the CLI added: want 200, got %d", rec.Code)
	}
}

// A config.json that does not parse leaves the agent on the copy it has.
func TestAnUnreadableConfigKeepsTheLastGoodOne(t *testing.T) {
	owner := newTestKey(t)
	dir, cfg := savedConfig(t, owner.device(RoleOwner))
	h := diskHandler(t, dir)
	if err := os.WriteFile(configPath(dir), []byte("{broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	if rec := do(h, owner.sign(t, "GET", statusPath(cfg), nil, time.Now(), "n-broken")); rec.Code != 200 {
		t.Fatalf("a broken file locked the owner out: %d", rec.Code)
	}
	// A change cannot be built on a file it cannot read, and must not replace it.
	rec := do(h, owner.sign(t, "POST", "/"+cfg.Prefix+"/v1/invites", nil, time.Now(), "n-broken-mint"))
	if rec.Code == 200 {
		t.Fatal("an invite was minted on top of an unreadable config")
	}
	if data, _ := os.ReadFile(configPath(dir)); string(data) != "{broken" {
		t.Fatal("the unreadable file was overwritten")
	}
}

func mustLoad(t *testing.T, dir string) *Config {
	t.Helper()
	cfg, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
