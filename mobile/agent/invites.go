package agent

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

const (
	inviteCodeBytes = 16             // 128-bit one-time codes
	inviteHTTPTTL   = 24 * time.Hour // an invite minted over the API (the spec's "valid 24 h")
	inviteKeepUsed  = 24 * time.Hour // how long a burned or expired invite stays listed
)

// Invite is a one-time code that lets a device register itself with a role:
// the owner's phone mints it (over SSH at invite creation, or over the API)
// and the other device redeems it with `POST pair`, after which the code is
// burned and the device talks to the agent with its own key like any other.
type Invite struct {
	Code      string `json:"code"`
	Role      Role   `json:"role"`
	Name      string `json:"name,omitempty"`
	CreatedAt int64  `json:"created_at"`
	ExpiresAt int64  `json:"expires_at"`
	UsedAt    int64  `json:"used_at,omitempty"`
	UsedBy    string `json:"used_by,omitempty"`
}

func (i Invite) usable(now time.Time) bool {
	return i.UsedAt == 0 && now.Unix() < i.ExpiresAt
}

func randomCode() string {
	b := make([]byte, inviteCodeBytes)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// newInvite adds an invite to the config (not saved) and returns it.
func (c *Config) newInvite(role Role, name string, ttl time.Duration, now time.Time) (Invite, error) {
	if role != RoleOwner {
		role = RoleMember
	}
	code := randomCode()
	if code == "" {
		return Invite{}, errors.New("no randomness for an invite code")
	}
	inv := Invite{Code: code, Role: role, Name: name, CreatedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix()}
	c.pruneInvites(now)
	c.Invites = append(c.Invites, inv)
	return inv, nil
}

// pruneInvites drops invites that were burned or expired more than a day ago,
// so the list never grows with history. A redeemed invite stays as long as
// the device that redeemed it is active: revoking the invite is how the owner
// takes that device's access back (RevokeInvite finds it through UsedBy), and
// the device's retry of a pair whose answer was lost is answered from it.
func (c *Config) pruneInvites(now time.Time) {
	kept := c.Invites[:0]
	cutoff := now.Add(-inviteKeepUsed).Unix()
	for _, inv := range c.Invites {
		holder := inv.UsedBy != "" && c.device(inv.UsedBy) != nil
		if inv.UsedAt != 0 && inv.UsedAt < cutoff && !holder {
			continue
		}
		if inv.UsedAt == 0 && inv.ExpiresAt < cutoff {
			continue
		}
		kept = append(kept, inv)
	}
	c.Invites = kept
}

// admit registers a device that redeemed an invite granting role, and returns
// the entry it now holds. A key already registered keeps its entry and never
// loses rank: an owner that takes a member code (its own invite link opened on
// the owner's phone, say) stays an owner, while the code still burns. A
// revoked key is admitted afresh with the invite's role: minting an invite is
// the owner's explicit grant, and a phone keeps its key across reinstalls, so
// a phone once revoked could otherwise never be invited again — it would pair
// and then meet the 404 on every call.
func (c *Config) admit(d Device, role Role) Device {
	if existing := c.device(d.ID); existing != nil {
		if role == RoleOwner {
			existing.Role = RoleOwner
		}
		return *existing
	}
	d.Role = role
	c.addDevice(d) // replaces a revoked entry with the same id
	return d
}

// redeemInvite burns the usable invite with this code for deviceID and
// returns it; nil when no such invite exists, which the caller answers with
// the camouflage 404.
func (c *Config) redeemInvite(code, deviceID string, now time.Time) *Invite {
	if code == "" {
		return nil
	}
	for i := range c.Invites {
		if c.Invites[i].Code == code && c.Invites[i].usable(now) {
			c.Invites[i].UsedAt = now.Unix()
			c.Invites[i].UsedBy = deviceID
			return &c.Invites[i]
		}
	}
	return nil
}

// CreateInvite mints an invite on an installed agent (the CLI's `invite`): the
// owner's phone runs it over SSH when it creates a device invite, and puts the
// code in the invited device's list. days is the validity.
func CreateInvite(dir, role, name string, days int) (Invite, error) {
	if days <= 0 {
		days = 30
	}
	var inv Invite
	err := updateConfig(dir, func(c *Config) error {
		var err error
		inv, err = c.newInvite(Role(role), name, time.Duration(days)*24*time.Hour, time.Now())
		return err
	})
	if err != nil {
		return Invite{}, err
	}
	return inv, nil
}

// RevokeInvite burns an invite and revokes the device that redeemed it, if
// any (the CLI's `revoke-invite`, run by the owner's phone when it revokes a
// device invite). The last owner is never revoked. Returns the revoked
// device id, "" when the code was never used.
func RevokeInvite(dir, code string) (string, error) {
	revoked := ""
	err := updateConfig(dir, func(cfg *Config) error {
		var inv *Invite
		for i := range cfg.Invites {
			if cfg.Invites[i].Code == code {
				inv = &cfg.Invites[i]
				break
			}
		}
		if inv == nil {
			return errors.New("no such invite")
		}
		if inv.UsedAt == 0 {
			inv.UsedAt = time.Now().Unix()
		}
		if inv.UsedBy == "" {
			return nil
		}
		owners := 0
		for _, d := range cfg.Devices {
			if d.Role == RoleOwner && !d.Revoked {
				owners++
			}
		}
		for j := range cfg.Devices {
			d := &cfg.Devices[j]
			if d.ID != inv.UsedBy || d.Revoked {
				continue
			}
			// An owner that took a member code got nothing from it (admit):
			// taking the code back must not take the owner's access with it.
			if d.Role == RoleOwner && inv.Role != RoleOwner {
				continue
			}
			if d.Role == RoleOwner && owners <= 1 {
				return errLastOwner
			}
			d.Revoked = true
			revoked = d.ID
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return revoked, nil
}

// handleInvites mints an invite over the API (owner only): {role} → {code, expires}.
func (h *apiHandler) handleInvites(w http.ResponseWriter, body []byte) {
	var req struct {
		Role string `json:"role"`
		Name string `json:"name"`
	}
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			writeError(w, "bad request")
			return
		}
	}
	var inv Invite
	err := h.change(func(c *Config) error {
		var err error
		inv, err = c.newInvite(Role(req.Role), req.Name, inviteHTTPTTL, time.Now())
		return err
	})
	switch {
	case err == nil:
		writeJSON(w, 200, map[string]any{"code": inv.Code, "role": inv.Role, "expires": inv.ExpiresAt})
	case errors.Is(err, errConfigRead), errors.Is(err, errConfigSave):
		writeError(w, "could not save")
	default:
		writeError(w, err.Error())
	}
}

// handlePair registers the caller's key with the role of a usable invite:
// {code, public_key (standard-base64 SPKI DER), name} → {device_id, role}.
// It is the one call that needs no device signature, so every failure is the
// camouflage 404 and counts against the unauthenticated rate limit.
func (h *apiHandler) handlePair(w http.ResponseWriter, r *http.Request, body []byte) {
	if !h.auth.allow(r.RemoteAddr) {
		writeCamouflage404(w)
		return
	}
	var req struct {
		Code      string `json:"code"`
		PublicKey string `json:"public_key"`
		Name      string `json:"name"`
	}
	if err := json.Unmarshal(body, &req); err != nil || req.Code == "" || req.PublicKey == "" {
		writeCamouflage404(w)
		return
	}
	now := time.Now()
	// Look in the config as it is on disk now (a code the CLI minted after
	// serve started counts), before building the device, so a bad code never
	// costs a key parse or a write.
	h.mu.Lock()
	known := h.currentLocked().canPair(req.Code, now)
	h.mu.Unlock()
	if !known {
		writeCamouflage404(w)
		return
	}
	name := req.Name
	if name == "" {
		name = "device"
	}
	probe, err := deviceFromSPKIBase64(req.PublicKey, name, RoleMember, now.Unix())
	if err != nil {
		writeCamouflage404(w)
		return
	}
	var dev Device
	err = h.change(func(c *Config) error {
		if inv := c.redeemInvite(req.Code, probe.ID, now); inv != nil {
			dev = c.admit(probe, inv.Role)
			return nil
		}
		// The same key asking again for a code it has redeemed: its answer was
		// lost on the way back (the tunnel route dropped, the phone retried
		// directly). Answer with what it holds; there is nothing to write.
		if held := c.redeemedBy(req.Code, probe.ID); held != nil {
			dev = *held
			return errAlreadyPaired
		}
		return errNoInvite // burned or revoked by the CLI a moment ago
	})
	switch {
	case err == nil, errors.Is(err, errAlreadyPaired):
		writeJSON(w, 200, map[string]any{"device_id": dev.ID, "role": dev.Role})
	case errors.Is(err, errConfigSave):
		writeError(w, "could not save")
	default:
		writeCamouflage404(w)
	}
}

// handleRevoke marks a device revoked (owner only). The last owner cannot be
// revoked: that would lock everyone out, and recovery is an SSH login away.
func (h *apiHandler) handleRevoke(w http.ResponseWriter, id string) {
	err := h.change(func(c *Config) error {
		var target *Device
		owners := 0
		for i := range c.Devices {
			d := &c.Devices[i]
			if d.Role == RoleOwner && !d.Revoked {
				owners++
			}
			if d.ID == id {
				target = d
			}
		}
		if target == nil {
			return errNoDevice
		}
		if target.Role == RoleOwner && !target.Revoked && owners <= 1 {
			return errLastOwner
		}
		target.Revoked = true
		return nil
	})
	switch {
	case err == nil:
		writeJSON(w, 200, map[string]any{"revoked": id})
	case errors.Is(err, errNoDevice), errors.Is(err, errLastOwner):
		writeError(w, err.Error())
	default:
		writeError(w, "could not save")
	}
}
