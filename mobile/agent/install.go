package agent

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"time"
)

// RandomPort returns a high random port, matching the bond endpoint's range.
func RandomPort() int {
	n, err := rand.Int(rand.Reader, big.NewInt(40_000))
	if err != nil {
		return 28000
	}
	return int(n.Int64()) + 20_000 // 20000..59999
}

// randomPrefix is the 22-character (128-bit) base64url API path prefix.
func randomPrefix() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "olcosagentfallbackxx00"
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// Init creates a fresh agent config in dir: a self-signed certificate for host,
// a random API prefix, and the owner device from its base64 SPKI DER. It
// returns the saved config and the owner device id. An empty owner key leaves
// the agent without devices: the installer's invite then makes the first
// phone that redeems it the owner.
func Init(dir string, port int, host, ownerB64, name string) (*Config, string, error) {
	certPEM, keyPEM, certSHA, err := generateCert(host)
	if err != nil {
		return nil, "", fmt.Errorf("certificate: %w", err)
	}
	cfg := &Config{
		Port:    port,
		Prefix:  randomPrefix(),
		CertPEM: certPEM,
		KeyPEM:  keyPEM,
		CertSHA: certSHA,
		Devices: []Device{},
		Scripts: map[string]string{},
	}
	ownerID := ""
	if ownerB64 != "" {
		owner, err := deviceFromSPKIBase64(ownerB64, name, RoleOwner, time.Now().Unix())
		if err != nil {
			return nil, "", err
		}
		cfg.Devices = []Device{owner}
		ownerID = owner.ID
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, "", err
	}
	unlock, err := lockConfig(dir)
	if err != nil {
		return nil, "", err
	}
	defer unlock()
	if err := cfg.Save(dir); err != nil {
		return nil, "", err
	}
	return cfg, ownerID, nil
}

// AddDevice registers another device on an existing agent and returns its id.
func AddDevice(dir, keyB64, role, name string, addedAt int64) (string, error) {
	r := RoleMember
	if role == string(RoleOwner) {
		r = RoleOwner
	}
	dev, err := deviceFromSPKIBase64(keyB64, name, r, addedAt)
	if err != nil {
		return "", err
	}
	if err := updateConfig(dir, func(c *Config) error {
		c.addDevice(dev)
		return nil
	}); err != nil {
		return "", err
	}
	return dev.ID, nil
}

// SetScripts replaces the status scripts on an existing agent.
func SetScripts(dir string, scripts map[string]string) error {
	return updateConfig(dir, func(c *Config) error {
		c.Scripts = scripts
		return nil
	})
}

// SetScript stores one status script and keeps the others (the CLI's
// set-script, run by the one-command installer).
func SetScript(dir, name, script string) error {
	return updateConfig(dir, func(c *Config) error {
		c.Scripts[name] = script
		return nil
	})
}
