package agent

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func pairBody(t *testing.T, code string, k testKey, name string) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]string{
		"code":       code,
		"public_key": base64.StdEncoding.EncodeToString(k.spki),
		"name":       name,
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// pairRequest is the one unsigned call the agent accepts.
func pairRequest(cfg *Config, body []byte) *http.Request {
	req := httptest.NewRequest("POST", "/"+cfg.Prefix+"/v1/pair", bytes.NewReader(body))
	req.RemoteAddr = "203.0.113.9:40000"
	return req
}

// A member invite redeemed by a new key registers that key as a member, burns
// the code, and the key then speaks to the agent like any device.
func TestPairRegistersMemberAndBurnsCode(t *testing.T) {
	owner := newTestKey(t)
	cfg := testConfig(owner.device(RoleOwner))
	inv, err := cfg.newInvite(RoleMember, "tablet", 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h := newHandler(cfg, testState(map[string]string{"readiness": "PODMAN=yes"}))

	guest := newTestKey(t)
	rec := do(h, pairRequest(cfg, pairBody(t, inv.Code, guest, "tablet")))
	if rec.Code != 200 {
		t.Fatalf("pair: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var reply struct {
		DeviceID string `json:"device_id"`
		Role     Role   `json:"role"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if reply.DeviceID != guest.id || reply.Role != RoleMember {
		t.Fatalf("pair reply %+v, want id %s member", reply, guest.id)
	}
	if d := cfg.device(guest.id); d == nil || d.Role != RoleMember || d.Name != "tablet" {
		t.Fatalf("device not registered as a member: %+v", d)
	}

	// The new key is accepted on a signed call.
	status := guest.sign(t, "GET", "/"+cfg.Prefix+"/v1/status", nil, time.Now(), "n-pair-status")
	if rec := do(h, status); rec.Code != 200 {
		t.Fatalf("status with the paired key: want 200, got %d", rec.Code)
	}
	// A member stays a member: no exec.
	exec := guest.sign(t, "POST", "/"+cfg.Prefix+"/v1/exec", []byte(`{"script":"ZWNobyBoaQ==","timeout":5}`), time.Now(), "n-pair-exec")
	assert404(t, do(h, exec))

	// The code is burned: a second device gets the camouflage.
	other := newTestKey(t)
	assert404(t, do(h, pairRequest(cfg, pairBody(t, inv.Code, other, "again"))))
}

func TestPairWithUnknownOrExpiredCodeIs404(t *testing.T) {
	owner := newTestKey(t)
	cfg := testConfig(owner.device(RoleOwner))
	expired, err := cfg.newInvite(RoleMember, "", time.Hour, time.Now().Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	h := newHandler(cfg, testState(nil))
	guest := newTestKey(t)
	assert404(t, do(h, pairRequest(cfg, pairBody(t, "no-such-code", guest, "x"))))
	assert404(t, do(h, pairRequest(cfg, pairBody(t, expired.Code, guest, "x"))))
	assert404(t, do(h, pairRequest(cfg, []byte("not json"))))
	if cfg.device(guest.id) != nil {
		t.Fatal("a failed pair must not register the key")
	}
}

func TestOwnerMintsInvitesMemberCannot(t *testing.T) {
	owner := newTestKey(t)
	member := newTestKey(t)
	cfg := testConfig(owner.device(RoleOwner), member.device(RoleMember))
	h := newHandler(cfg, testState(nil))

	assert404(t, do(h, member.sign(t, "POST", "/"+cfg.Prefix+"/v1/invites", []byte(`{"role":"owner"}`), time.Now(), "n-inv-member")))

	rec := do(h, owner.sign(t, "POST", "/"+cfg.Prefix+"/v1/invites", []byte(`{"role":"owner","name":"laptop"}`), time.Now(), "n-inv-owner"))
	if rec.Code != 200 {
		t.Fatalf("owner invites: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var reply struct {
		Code    string `json:"code"`
		Role    Role   `json:"role"`
		Expires int64  `json:"expires"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	if len(reply.Code) < 20 || reply.Role != RoleOwner || reply.Expires < time.Now().Unix()+23*3600 {
		t.Fatalf("invite reply %+v", reply)
	}
	guest := newTestKey(t)
	if rec := do(h, pairRequest(cfg, pairBody(t, reply.Code, guest, "laptop"))); rec.Code != 200 {
		t.Fatalf("pair with a minted code: want 200, got %d", rec.Code)
	}
	if d := cfg.device(guest.id); d == nil || d.Role != RoleOwner {
		t.Fatalf("an owner invite must register an owner: %+v", d)
	}
}

func TestRevokeDeviceAndKeepTheLastOwner(t *testing.T) {
	owner := newTestKey(t)
	member := newTestKey(t)
	cfg := testConfig(owner.device(RoleOwner), member.device(RoleMember))
	h := newHandler(cfg, testState(nil))

	// A member cannot revoke anyone.
	assert404(t, do(h, member.sign(t, "DELETE", "/"+cfg.Prefix+"/v1/devices/"+owner.id, nil, time.Now(), "n-rev-member")))

	rec := do(h, owner.sign(t, "DELETE", "/"+cfg.Prefix+"/v1/devices/"+member.id, nil, time.Now(), "n-rev-owner"))
	if rec.Code != 200 {
		t.Fatalf("revoke: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	assert404(t, do(h, member.sign(t, "GET", "/"+cfg.Prefix+"/v1/status", nil, time.Now(), "n-rev-after")))

	rec = do(h, owner.sign(t, "DELETE", "/"+cfg.Prefix+"/v1/devices/"+owner.id, nil, time.Now(), "n-rev-self"))
	if rec.Code == 200 || !strings.Contains(rec.Body.String(), "last owner") {
		t.Fatalf("the last owner must stay: got %d body=%s", rec.Code, rec.Body.String())
	}
	if cfg.device(owner.id) == nil {
		t.Fatal("the last owner was revoked")
	}
}

// Revoking an invite from the owner's phone also revokes the device that
// redeemed it, so "revoke the invite" takes the whole access back.
func TestRevokeInviteRevokesTheDeviceThatUsedIt(t *testing.T) {
	owner := newTestKey(t)
	cfg := testConfig(owner.device(RoleOwner))
	inv, err := cfg.newInvite(RoleOwner, "laptop", 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h := newHandler(cfg, testState(nil))
	guest := newTestKey(t)
	if rec := do(h, pairRequest(cfg, pairBody(t, inv.Code, guest, "laptop"))); rec.Code != 200 {
		t.Fatalf("pair: %d", rec.Code)
	}
	dir := t.TempDir()
	if err := cfg.Save(dir); err != nil {
		t.Fatal(err)
	}
	revoked, err := RevokeInvite(dir, inv.Code)
	if err != nil || revoked != guest.id {
		t.Fatalf("RevokeInvite = %q, %v; want %q", revoked, err, guest.id)
	}
	loaded, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.device(guest.id) != nil {
		t.Fatal("the paired device must be revoked")
	}
	if loaded.device(owner.id) == nil {
		t.Fatal("the owner must stay")
	}
	if _, err := RevokeInvite(dir, "unknown"); err == nil {
		t.Fatal("an unknown code must be an error")
	}
	// An unused invite is simply burned.
	fresh, _ := loaded.newInvite(RoleMember, "", time.Hour, time.Now())
	if err := loaded.Save(dir); err != nil {
		t.Fatal(err)
	}
	if revoked, err := RevokeInvite(dir, fresh.Code); err != nil || revoked != "" {
		t.Fatalf("burning an unused invite: %q, %v", revoked, err)
	}
	again, _ := LoadConfig(dir)
	if again.redeemInvite(fresh.Code, "x", time.Now()) != nil {
		t.Fatal("a burned invite must not redeem")
	}
}

func TestInvitesPruneAndRoundTrip(t *testing.T) {
	cfg := testConfig()
	now := time.Now()
	old, _ := cfg.newInvite(RoleMember, "", time.Hour, now.Add(-72*time.Hour))
	fresh, _ := cfg.newInvite(RoleMember, "", 24*time.Hour, now)
	cfg.pruneInvites(now)
	for _, inv := range cfg.Invites {
		if inv.Code == old.Code {
			t.Fatal("an invite expired days ago must be pruned")
		}
	}
	dir := t.TempDir()
	if err := cfg.Save(dir); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Invites) != 1 || loaded.Invites[0].Code != fresh.Code {
		t.Fatalf("invites did not round-trip: %+v", loaded.Invites)
	}
}

// pairReply decodes a successful pair answer.
func pairReply(t *testing.T, rec *httptest.ResponseRecorder) (string, Role) {
	t.Helper()
	if rec.Code != 200 {
		t.Fatalf("pair: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	var reply struct {
		DeviceID string `json:"device_id"`
		Role     Role   `json:"role"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &reply); err != nil {
		t.Fatal(err)
	}
	return reply.DeviceID, reply.Role
}

// An owner's phone that redeems a member code (its own invite link, opened on
// it) stays the owner: the code burns, and the answer says what the device holds.
func TestPairNeverLowersARegisteredDevicesRole(t *testing.T) {
	owner := newTestKey(t)
	other := newTestKey(t)
	cfg := testConfig(owner.device(RoleOwner), other.device(RoleOwner))
	inv, err := cfg.newInvite(RoleMember, "tablet", 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h := newHandler(cfg, testState(nil))

	id, role := pairReply(t, do(h, pairRequest(cfg, pairBody(t, inv.Code, owner, "tablet"))))
	if id != owner.id || role != RoleOwner {
		t.Fatalf("pair answered %s %s, want %s owner", id, role, owner.id)
	}
	if d := cfg.device(owner.id); d == nil || d.Role != RoleOwner || d.Name != "test" {
		t.Fatalf("the owner's entry changed: %+v", d)
	}
	// The owner keeps owner-only calls, and the code is burned.
	if rec := do(h, owner.sign(t, "GET", "/"+cfg.Prefix+"/v1/devices", nil, time.Now(), "n-keep-owner")); rec.Code != 200 {
		t.Fatalf("owner-only call after the pair: %d", rec.Code)
	}
	assert404(t, do(h, pairRequest(cfg, pairBody(t, inv.Code, newTestKey(t), "again"))))

	// Revoking that member code later must not revoke the owner who took it.
	dir := t.TempDir()
	if err := cfg.Save(dir); err != nil {
		t.Fatal(err)
	}
	if revoked, err := RevokeInvite(dir, inv.Code); err != nil || revoked != "" {
		t.Fatalf("RevokeInvite = %q, %v; the owner must stay", revoked, err)
	}
	if mustLoad(t, dir).device(owner.id) == nil {
		t.Fatal("revoking a member code revoked an owner")
	}
}

// A member that redeems an owner code becomes an owner; a revoked phone that
// redeems a fresh invite is admitted again with that invite's role (minting
// the invite is the owner's grant, and the phone's key outlives reinstalls).
func TestPairRaisesAMemberAndReadmitsARevokedKey(t *testing.T) {
	owner := newTestKey(t)
	member := newTestKey(t)
	gone := newTestKey(t)
	revoked := gone.device(RoleOwner)
	revoked.Revoked = true
	cfg := testConfig(owner.device(RoleOwner), member.device(RoleMember), revoked)
	up, _ := cfg.newInvite(RoleOwner, "", 24*time.Hour, time.Now())
	back, _ := cfg.newInvite(RoleMember, "", 24*time.Hour, time.Now())
	h := newHandler(cfg, testState(nil))

	if _, role := pairReply(t, do(h, pairRequest(cfg, pairBody(t, up.Code, member, "phone")))); role != RoleOwner {
		t.Fatalf("a member with an owner code: role %s", role)
	}
	if _, role := pairReply(t, do(h, pairRequest(cfg, pairBody(t, back.Code, gone, "phone")))); role != RoleMember {
		t.Fatalf("a revoked key with a member code: role %s", role)
	}
	if d := cfg.device(gone.id); d == nil || d.Role != RoleMember {
		t.Fatalf("the revoked key was not admitted again as a member: %+v", d)
	}
	if rec := do(h, gone.sign(t, "GET", statusPath(cfg), nil, time.Now(), "n-readmitted")); rec.Code != 200 {
		t.Fatalf("the readmitted key's call: %d", rec.Code)
	}
}

// An invite redeemed days ago stays listed while its device is active, so
// revoking it later still takes that device's access back.
func TestRevokingAnOldInviteStillRevokesItsDevice(t *testing.T) {
	owner := newTestKey(t)
	guest := newTestKey(t)
	cfg := testConfig(owner.device(RoleOwner))
	then := time.Now().Add(-72 * time.Hour)
	inv, err := cfg.newInvite(RoleMember, "tablet", 24*time.Hour, then)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.redeemInvite(inv.Code, guest.id, then.Add(time.Minute)) == nil {
		t.Fatal("the fresh invite did not redeem")
	}
	cfg.admit(guest.device(RoleMember), RoleMember)
	dir := t.TempDir()
	if err := cfg.Save(dir); err != nil {
		t.Fatal(err)
	}

	// Days later the owner mints another invite, and minting prunes the list.
	if _, err := CreateInvite(dir, "member", "phone", 30); err != nil {
		t.Fatal(err)
	}
	revoked, err := RevokeInvite(dir, inv.Code)
	if err != nil || revoked != guest.id {
		t.Fatalf("RevokeInvite = %q, %v; want %q", revoked, err, guest.id)
	}
	if mustLoad(t, dir).device(guest.id) != nil {
		t.Fatal("the device of the old invite is still active")
	}

	// With its device revoked, the old invite goes at the next prune.
	if _, err := CreateInvite(dir, "member", "laptop", 30); err != nil {
		t.Fatal(err)
	}
	for _, i := range mustLoad(t, dir).Invites {
		if i.Code == inv.Code {
			t.Fatal("an old invite whose device is revoked must be pruned")
		}
	}
}

// A phone whose pair answer was lost on the way back (the tunnel route
// dropped) asks again with the same code and key: it gets the same answer,
// not a 404 that would strand the access it already holds. Anyone else, and
// the same key once revoked, still meets the 404.
func TestPairRetryBySameKeyGetsTheSameAnswer(t *testing.T) {
	owner := newTestKey(t)
	cfg := testConfig(owner.device(RoleOwner))
	inv, err := cfg.newInvite(RoleMember, "tablet", 24*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	h := newHandler(cfg, testState(nil))
	guest := newTestKey(t)

	id, role := pairReply(t, do(h, pairRequest(cfg, pairBody(t, inv.Code, guest, "tablet"))))
	again, againRole := pairReply(t, do(h, pairRequest(cfg, pairBody(t, inv.Code, guest, "tablet"))))
	if id != guest.id || role != RoleMember || again != id || againRole != role {
		t.Fatalf("pair %s %s, retry %s %s", id, role, again, againRole)
	}
	if n := len(cfg.Devices); n != 2 {
		t.Fatalf("the retry registered a device twice: %d devices", n)
	}
	assert404(t, do(h, pairRequest(cfg, pairBody(t, inv.Code, newTestKey(t), "other"))))

	revoke := owner.sign(t, "DELETE", "/"+cfg.Prefix+"/v1/devices/"+guest.id, nil, time.Now(), "n-retry-revoke")
	if rec := do(h, revoke); rec.Code != 200 {
		t.Fatalf("revoke: %d", rec.Code)
	}
	assert404(t, do(h, pairRequest(cfg, pairBody(t, inv.Code, guest, "tablet"))))
}
