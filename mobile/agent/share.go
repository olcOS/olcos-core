package agent

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A device invite published from the server itself, by the one-command
// installer: the first phone scans it, gets the server's connections and
// registers itself with the agent as the owner. The list, the cipher and the
// link are exactly what the phones publish and read (InvitePayload /
// InviteCipher on iOS, Invites on Android), so nothing on the phone side is
// special about an invite the server made.
const (
	inviteCipherPrefix = "olcos1:"
	inviteCipherAAD    = "olcos-invite-v1"
	inviteRefresh      = "30m"
)

// ShareOptions describes the invite the installer hands to the first phone.
type ShareOptions struct {
	Name      string   // the server's name: #name, and ##name of every connection
	Host      string   // the address the phone reaches the server at (#agent)
	SharePort int      // the share server's port (the link)
	URIs      []string // the connection lines (olcrtc://, vless://)
	Role      string   // owner or member
	Days      int      // the pairing code's validity
	Dir       string   // the directory the share server serves
}

// Share is what the installer prints: the link carries the key, the file name
// is the token, and the code is the one the invite was minted with.
type Share struct {
	Token string
	Key   []byte
	Link  string
	Code  string
}

// ShareList mints a pairing code, writes the encrypted list into o.Dir and
// returns the link for it.
func ShareList(dir string, o ShareOptions) (Share, error) {
	if len(o.URIs) == 0 {
		return Share{}, fmt.Errorf("share: no connection to share")
	}
	if o.Host == "" || o.SharePort <= 0 || o.SharePort > 65535 {
		return Share{}, fmt.Errorf("share: a host and a share port are needed")
	}
	role := RoleMember
	if o.Role == string(RoleOwner) {
		role = RoleOwner
	}
	days := o.Days
	if days <= 0 {
		days = 30
	}
	var cfg *Config
	var inv Invite
	err := updateConfig(dir, func(c *Config) error {
		var err error
		inv, err = c.newInvite(role, "first phone", time.Duration(days)*24*time.Hour, time.Now())
		cfg = c
		return err
	})
	if err != nil {
		return Share{}, err
	}
	body := inviteBody(o.Name, o.Host, cfg, inv, o.URIs)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return Share{}, err
	}
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return Share{}, err
	}
	token := hex.EncodeToString(tokenBytes)
	served, err := sealInvite(body, key)
	if err != nil {
		return Share{}, err
	}
	if err := os.MkdirAll(o.Dir, 0o755); err != nil {
		return Share{}, err
	}
	tmp := filepath.Join(o.Dir, ".tmp-"+token)
	if err := os.WriteFile(tmp, []byte(served), 0o644); err != nil {
		return Share{}, err
	}
	if err := os.Rename(tmp, filepath.Join(o.Dir, token)); err != nil {
		return Share{}, err
	}
	return Share{
		Token: token,
		Key:   key,
		Link:  inviteLink(o.Host, o.SharePort, token, key),
		Code:  inv.Code,
	}, nil
}

// inviteBody is the list the phone decrypts: the global fields, the agent
// offer, then every connection under a record id of its own.
func inviteBody(name, host string, cfg *Config, inv Invite, uris []string) string {
	lines := []string{
		"#name: " + oneLine(name),
		"#refresh: " + inviteRefresh,
		"#agent: " + bracketHost(host) + ":" + fmt.Sprint(cfg.Port),
		"#agent-cert: " + cfg.CertSHA,
		"#agent-prefix: " + cfg.Prefix,
		"#agent-code: " + inv.Code,
		"#agent-role: " + string(inv.Role),
	}
	for _, uri := range uris {
		uri = strings.TrimSpace(uri)
		if uri == "" {
			continue
		}
		lines = append(lines, uri, "##name: "+oneLine(name), "##id: "+randomUUID())
	}
	return strings.Join(lines, "\n") + "\n"
}

// sealInvite is InviteCipher.seal: AES-256-GCM, nonce(12) ‖ ciphertext ‖ tag,
// standard base64 behind the format prefix.
func sealInvite(plaintext string, key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, nonce, []byte(plaintext), []byte(inviteCipherAAD))
	return inviteCipherPrefix + base64.StdEncoding.EncodeToString(append(nonce, sealed...)), nil
}

// openInvite reverses sealInvite (the tests, and a check of what was written).
func openInvite(served string, key []byte) (string, error) {
	text := strings.TrimSpace(served)
	if !strings.HasPrefix(text, inviteCipherPrefix) {
		return "", fmt.Errorf("not an invite list")
	}
	combined, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(text, inviteCipherPrefix))
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(combined) < gcm.NonceSize() {
		return "", fmt.Errorf("short list")
	}
	plain, err := gcm.Open(nil, combined[:gcm.NonceSize()], combined[gcm.NonceSize():], []byte(inviteCipherAAD))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// inviteLink is `olcrtc-sub://host:port/token?enc=v1#key`, the key unpadded
// base64url in the fragment, which no request carries.
func inviteLink(host string, port int, token string, key []byte) string {
	return fmt.Sprintf("olcrtc-sub://%s:%d/%s?enc=v1#%s", bracketHost(host), port, token,
		base64.RawURLEncoding.EncodeToString(key))
}

func bracketHost(host string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}

func oneLine(s string) string {
	return strings.TrimSpace(strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", " ")), " "))
}

// randomUUID is a version-4 UUID in the lowercase form the phones keep.
func randomUUID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "00000000-0000-4000-8000-000000000000"
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
