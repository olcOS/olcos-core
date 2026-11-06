// Command olcos-agent is the server side of HTTPS server management. The app
// builds it on the VPS from the sources it ships (like olcos-bond), installs
// it under /opt/olcos-agent, registers this phone as the owner, and runs it
// from a systemd unit. It speaks only to the app, over a pinned certificate
// and signed requests; to anything else it is an idle nginx.
//
// Subcommands:
//
//	init  -dir D -port P -host H -owner B64DER -name N
//	add-device -dir D -key B64DER -role owner|member -name N
//	invite -dir D -role owner|member -name N -days 30
//	revoke-invite -dir D -code C
//	set-scripts -dir D -file F        # F holds JSON {name: bash}
//	serve -dir D
//
// init prints, on stdout, the four lines the installer parses:
//
//	OLCOS_AGENT_PORT=<port>
//	OLCOS_AGENT_CERT=<hex sha256 of the certificate DER>   (the app pins this)
//	OLCOS_AGENT_PREFIX=<22-char base64url API path prefix>
//	OLCOS_AGENT_DEVICE=<owner device id>
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/openlibrecommunity/olcrtc-ios/gomobile/agent"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fail("usage: olcos-agent <init|add-device|invite|revoke-invite|set-scripts|set-script|share|show|serve> ...")
	}
	switch os.Args[1] {
	case "init":
		cmdInit(os.Args[2:])
	case "add-device":
		cmdAddDevice(os.Args[2:])
	case "invite":
		cmdInvite(os.Args[2:])
	case "revoke-invite":
		cmdRevokeInvite(os.Args[2:])
	case "set-scripts":
		cmdSetScripts(os.Args[2:])
	case "set-script":
		cmdSetScript(os.Args[2:])
	case "share":
		cmdShare(os.Args[2:])
	case "show":
		cmdShow(os.Args[2:])
	case "serve":
		cmdServe(os.Args[2:])
	default:
		fail("unknown command %q", os.Args[1])
	}
}

func cmdInit(args []string) {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", "", "agent directory")
	port := fs.Int("port", 0, "listen port (0: random 20000-59999)")
	host := fs.String("host", "", "server address for the certificate SAN")
	owner := fs.String("owner", "", "owner public key: base64 SPKI DER (empty: the first invite makes the owner)")
	name := fs.String("name", "owner", "owner device name")
	_ = fs.Parse(args)
	if *dir == "" || *host == "" {
		fail("init needs -dir and -host")
	}

	p := *port
	if p == 0 {
		p = agent.RandomPort()
	}
	cfg, ownerID, err := agent.Init(*dir, p, *host, *owner, *name)
	if err != nil {
		fail("init: %v", err)
	}
	fmt.Printf("OLCOS_AGENT_PORT=%d\n", cfg.Port)
	fmt.Printf("OLCOS_AGENT_CERT=%s\n", cfg.CertSHA)
	fmt.Printf("OLCOS_AGENT_PREFIX=%s\n", cfg.Prefix)
	fmt.Printf("OLCOS_AGENT_DEVICE=%s\n", ownerID)
}

func cmdAddDevice(args []string) {
	fs := flag.NewFlagSet("add-device", flag.ExitOnError)
	dir := fs.String("dir", "", "agent directory")
	key := fs.String("key", "", "public key: base64 SPKI DER")
	role := fs.String("role", "member", "owner or member")
	name := fs.String("name", "device", "device name")
	_ = fs.Parse(args)
	if *dir == "" || *key == "" {
		fail("add-device needs -dir and -key")
	}
	id, err := agent.AddDevice(*dir, *key, *role, *name, time.Now().Unix())
	if err != nil {
		fail("add-device: %v", err)
	}
	fmt.Printf("OLCOS_AGENT_DEVICE=%s\n", id)
}

// cmdInvite mints a one-time pairing code: the owner's phone runs it over
// SSH when it creates a device invite and puts the code in that device's list,
// so the invited device registers its own key with `POST pair`.
func cmdInvite(args []string) {
	fs := flag.NewFlagSet("invite", flag.ExitOnError)
	dir := fs.String("dir", "", "agent directory")
	role := fs.String("role", "member", "owner or member")
	name := fs.String("name", "device", "the invited device's name")
	days := fs.Int("days", 30, "validity in days")
	_ = fs.Parse(args)
	if *dir == "" {
		fail("invite needs -dir")
	}
	inv, err := agent.CreateInvite(*dir, *role, *name, *days)
	if err != nil {
		fail("invite: %v", err)
	}
	fmt.Printf("OLCOS_AGENT_INVITE=%s\n", inv.Code)
	fmt.Printf("OLCOS_AGENT_INVITE_ROLE=%s\n", inv.Role)
	fmt.Printf("OLCOS_AGENT_INVITE_EXPIRES=%d\n", inv.ExpiresAt)
}

// cmdRevokeInvite burns a pairing code and revokes the device that used it.
func cmdRevokeInvite(args []string) {
	fs := flag.NewFlagSet("revoke-invite", flag.ExitOnError)
	dir := fs.String("dir", "", "agent directory")
	code := fs.String("code", "", "the invite's code")
	_ = fs.Parse(args)
	if *dir == "" || *code == "" {
		fail("revoke-invite needs -dir and -code")
	}
	revoked, err := agent.RevokeInvite(*dir, *code)
	if err != nil {
		fail("revoke-invite: %v", err)
	}
	if revoked == "" {
		revoked = "-"
	}
	fmt.Printf("OLCOS_AGENT_REVOKED=%s\n", revoked)
}

func cmdSetScripts(args []string) {
	fs := flag.NewFlagSet("set-scripts", flag.ExitOnError)
	dir := fs.String("dir", "", "agent directory")
	file := fs.String("file", "", "JSON file: {name: bash}")
	_ = fs.Parse(args)
	if *dir == "" || *file == "" {
		fail("set-scripts needs -dir and -file")
	}
	data, err := os.ReadFile(*file)
	if err != nil {
		fail("set-scripts: %v", err)
	}
	var scripts map[string]string
	if err := json.Unmarshal(data, &scripts); err != nil {
		fail("set-scripts: bad JSON: %v", err)
	}
	if err := agent.SetScripts(*dir, scripts); err != nil {
		fail("set-scripts: %v", err)
	}
	fmt.Println("OLCOS_AGENT_SCRIPTS=ok")
}

// cmdShow reprints an installed agent's endpoint facts (port, pinned cert
// hash, API prefix) without touching the config — used when a reinstall
// rebuilds the binary but keeps the existing certificate and devices.
// cmdSetScript stores one status script from a file: the installer sets the
// three the phones read (readiness, carriers, xray) without building JSON.
func cmdSetScript(args []string) {
	fs := flag.NewFlagSet("set-script", flag.ExitOnError)
	dir := fs.String("dir", "", "agent directory")
	name := fs.String("name", "", "script name")
	file := fs.String("file", "", "script file")
	_ = fs.Parse(args)
	if *dir == "" || *name == "" || *file == "" {
		fail("set-script needs -dir, -name and -file")
	}
	text, err := os.ReadFile(*file)
	if err != nil {
		fail("set-script: %v", err)
	}
	if err := agent.SetScript(*dir, *name, string(text)); err != nil {
		fail("set-script: %v", err)
	}
	fmt.Printf("OLCOS_AGENT_SCRIPT=%s\n", *name)
}

// multiFlag collects a repeatable -uri.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

// cmdShare publishes the installer's device invite: the encrypted list with
// the connections and the agent offer, and prints the link for the phone.
func cmdShare(args []string) {
	fs := flag.NewFlagSet("share", flag.ExitOnError)
	dir := fs.String("dir", "", "agent directory")
	name := fs.String("name", "olcOS server", "the server's name on the phone")
	host := fs.String("host", "", "the address the phone reaches the server at")
	sharePort := fs.Int("share-port", 0, "the share server's port")
	shareDir := fs.String("share-dir", "/opt/olcos-share", "the directory the share server serves")
	role := fs.String("role", "owner", "owner or member")
	days := fs.Int("days", 30, "validity of the pairing code in days")
	var uris multiFlag
	fs.Var(&uris, "uri", "a connection line (repeatable)")
	_ = fs.Parse(args)
	if *dir == "" || *host == "" || *sharePort == 0 || len(uris) == 0 {
		fail("share needs -dir, -host, -share-port and at least one -uri")
	}
	share, err := agent.ShareList(*dir, agent.ShareOptions{
		Name: *name, Host: *host, SharePort: *sharePort, URIs: uris, Role: *role, Days: *days, Dir: *shareDir,
	})
	if err != nil {
		fail("share: %v", err)
	}
	fmt.Printf("OLCOS_SHARE_TOKEN=%s\n", share.Token)
	fmt.Printf("OLCOS_AGENT_INVITE=%s\n", share.Code)
	fmt.Printf("OLCOS_INVITE_LINK=%s\n", share.Link)
}

func cmdShow(args []string) {
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	dir := fs.String("dir", "", "agent directory")
	_ = fs.Parse(args)
	if *dir == "" {
		fail("show needs -dir")
	}
	cfg, err := agent.LoadConfig(*dir)
	if err != nil {
		fail("show: %v", err)
	}
	fmt.Printf("OLCOS_AGENT_PORT=%d\n", cfg.Port)
	fmt.Printf("OLCOS_AGENT_CERT=%s\n", cfg.CertSHA)
	fmt.Printf("OLCOS_AGENT_PREFIX=%s\n", cfg.Prefix)
}

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dir := fs.String("dir", "", "agent directory")
	_ = fs.Parse(args)
	if *dir == "" {
		fail("serve needs -dir")
	}
	if err := agent.Serve(*dir); err != nil {
		fail("serve: %v", err)
	}
}

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "OLCOS_AGENT_ERROR="+format+"\n", a...)
	os.Exit(1)
}
