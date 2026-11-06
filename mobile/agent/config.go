// Package agent is olcos-agent: a small HTTPS service the app installs on the
// user's own VPS so the server page reads status and runs room actions over a
// pinned, signed connection instead of an SSH login on the hot path. It is
// stdlib-only on purpose — the app ships its Go sources and the server builds
// them in the Go image the install already uses, with no network and a
// generated minimal go.mod — so nothing here may import outside the standard
// library.
package agent

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Role is a device's permission level. An owner can do everything, including
// running maintenance scripts (root-equivalent); a member can read status and
// logs and start/stop/restart rooms, nothing else.
type Role string

const (
	RoleOwner  Role = "owner"
	RoleMember Role = "member"
)

// Device is one registered key. PublicKey is the standard-base64 X.509
// SubjectPublicKeyInfo (SPKI) DER of a P-256 public key — the same bytes
// CryptoKit's `publicKey.derRepresentation` produces on the app side.
type Device struct {
	ID        string `json:"id"`
	PublicKey string `json:"public_key"`
	Name      string `json:"name"`
	Role      Role   `json:"role"`
	AddedAt   int64  `json:"added_at"`
	Revoked   bool   `json:"revoked,omitempty"`
}

// parsedKey decodes the stored SPKI into an ECDSA P-256 public key.
func (d Device) parsedKey() (*ecdsa.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(d.PublicKey)
	if err != nil {
		return nil, err
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	ec, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA key")
	}
	return ec, nil
}

// Config is the agent's on-disk state: how it listens, who may talk to it, and
// the named scripts whose outputs it caches as status.
type Config struct {
	Port    int               `json:"port"`
	Prefix  string            `json:"prefix"`
	CertPEM string            `json:"cert_pem"`
	KeyPEM  string            `json:"key_pem"`
	CertSHA string            `json:"cert_sha256"`
	Devices []Device          `json:"devices"`
	Invites []Invite          `json:"invites,omitempty"`
	Scripts map[string]string `json:"scripts"`
}

func configPath(dir string) string { return filepath.Join(dir, "config.json") }

// configLockFile, next to config.json, is what lockConfig locks.
const configLockFile = "config.lock"

// updateConfig is the CLI's read-modify-write of config.json: under the lock
// serve's own changes take too (lockConfig), it reads the file, applies fn and
// writes the result back. An error from fn writes nothing.
func updateConfig(dir string, fn func(*Config) error) error {
	unlock, err := lockConfig(dir)
	if err != nil {
		return err
	}
	defer unlock()
	cfg, err := LoadConfig(dir)
	if err != nil {
		return err
	}
	if err := fn(cfg); err != nil {
		return err
	}
	return cfg.Save(dir)
}

// LoadConfig reads config.json from dir.
func LoadConfig(dir string) (*Config, error) {
	data, err := os.ReadFile(configPath(dir))
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if c.Scripts == nil {
		c.Scripts = map[string]string{}
	}
	return &c, nil
}

// Save writes config.json to dir atomically, readable only by the owner (it
// holds the TLS private key).
func (c *Config) Save(dir string) error {
	_, err := c.saveStamped(dir)
	return err
}

// configStamp names one version of config.json on disk. The CLI the phones
// run (invite, revoke-invite, add-device, set-scripts) rewrites the file
// while serve runs, and every write is a new file renamed into place, which
// changes the modification time and, nearly always, the size.
type configStamp struct {
	modNano int64
	size    int64
}

func stampOf(fi os.FileInfo) configStamp {
	return configStamp{modNano: fi.ModTime().UnixNano(), size: fi.Size()}
}

func statConfig(dir string) (configStamp, error) {
	fi, err := os.Stat(configPath(dir))
	if err != nil {
		return configStamp{}, err
	}
	return stampOf(fi), nil
}

// loadStamped reads config.json together with the stamp of the version read.
// The stamp is taken first: a rewrite between the two then reads as a changed
// stamp on the next look, never as a stale copy under a fresh stamp.
func loadStamped(dir string) (*Config, configStamp, error) {
	stamp, err := statConfig(dir)
	if err != nil {
		return nil, configStamp{}, err
	}
	cfg, err := LoadConfig(dir)
	if err != nil {
		return nil, configStamp{}, err
	}
	return cfg, stamp, nil
}

// saveStamped is Save returning the stamp of the file it wrote, read from the
// temporary file before the rename (a rename keeps it), so a write by another
// process right after this one is never taken for this one. The temporary
// file is unique, so two writers can never interleave inside one file.
func (c *Config) saveStamped(dir string) (configStamp, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return configStamp{}, err
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return configStamp{}, err
	}
	f, err := os.CreateTemp(dir, "config.json.tmp*")
	if err != nil {
		return configStamp{}, err
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp)
		return configStamp{}, errors.Join(werr, cerr)
	}
	// CreateTemp already makes the file 0600; say so for the TLS key's sake.
	if err := os.Chmod(tmp, 0o600); err != nil {
		_ = os.Remove(tmp)
		return configStamp{}, err
	}
	fi, err := os.Stat(tmp)
	if err != nil {
		_ = os.Remove(tmp)
		return configStamp{}, err
	}
	if err := os.Rename(tmp, configPath(dir)); err != nil {
		_ = os.Remove(tmp)
		return configStamp{}, err
	}
	return stampOf(fi), nil
}

// clone is a deep copy (the config is plain JSON by design), so a change can
// be built on a copy and thrown away when it cannot be saved.
func (c *Config) clone() *Config {
	data, err := json.Marshal(c)
	if err != nil {
		return nil
	}
	var out Config
	if err := json.Unmarshal(data, &out); err != nil {
		return nil
	}
	if out.Scripts == nil {
		out.Scripts = map[string]string{}
	}
	return &out
}

// hasUsableInvite reports whether an invite with this code can still be redeemed.
func (c *Config) hasUsableInvite(code string, now time.Time) bool {
	for _, inv := range c.Invites {
		if inv.Code == code && inv.usable(now) {
			return true
		}
	}
	return false
}

// canPair reports whether a pair call with this code can succeed: the code is
// still usable, or the device that redeemed it is still active and may be
// asking again (handlePair answers it with what it holds).
func (c *Config) canPair(code string, now time.Time) bool {
	if c.hasUsableInvite(code, now) {
		return true
	}
	for _, inv := range c.Invites {
		if inv.Code == code && inv.UsedAt != 0 && inv.UsedBy != "" && c.device(inv.UsedBy) != nil {
			return true
		}
	}
	return false
}

// redeemedBy returns the active device with this id when it is the one that
// redeemed the invite with this code; nil otherwise.
func (c *Config) redeemedBy(code, deviceID string) *Device {
	for _, inv := range c.Invites {
		if inv.Code == code && inv.UsedAt != 0 && inv.UsedBy != "" && inv.UsedBy == deviceID {
			return c.device(deviceID)
		}
	}
	return nil
}

// device returns the registered, non-revoked device with this id.
func (c *Config) device(id string) *Device {
	for i := range c.Devices {
		if c.Devices[i].ID == id && !c.Devices[i].Revoked {
			return &c.Devices[i]
		}
	}
	return nil
}

// addDevice registers a key, replacing any existing entry with the same id.
func (c *Config) addDevice(d Device) {
	for i := range c.Devices {
		if c.Devices[i].ID == d.ID {
			c.Devices[i] = d
			return
		}
	}
	c.Devices = append(c.Devices, d)
}

// deviceFromSPKIBase64 builds a Device from a base64 (standard) SPKI DER.
func deviceFromSPKIBase64(b64, name string, role Role, addedAt int64) (Device, error) {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return Device{}, fmt.Errorf("owner key is not valid base64: %w", err)
	}
	if _, err := x509.ParsePKIXPublicKey(der); err != nil {
		return Device{}, fmt.Errorf("owner key is not a valid public key: %w", err)
	}
	return Device{
		ID:        deviceIDFromSPKI(der),
		PublicKey: base64.StdEncoding.EncodeToString(der),
		Name:      name,
		Role:      role,
		AddedAt:   addedAt,
	}, nil
}
