#!/usr/bin/env python3
"""Offline runs of server/xray/install.sh, the script the apps
upload to install Xray (VLESS + REALITY) or adopt the deployment already on
a server. No SSH, server, network or real podman: podman, openssl, ss, curl,
id, chown and systemctl are mocks on PATH; bash, python3 and coreutils are real.

Run: python3 scripts/test_xray_server_script.py
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "server" / "xray" / "install.sh"
UUID = "8f3f2c1e-7a5b-4d2e-9c1a-0b6d5e4f3a21"

PODMAN = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
path = pathlib.Path(os.environ["MOCK_STATE"])
state = json.loads(path.read_text())
containers = state.setdefault("containers", {})
with open(os.environ["MOCK_LOG"], "a") as out:
    out.write(json.dumps(["podman"] + args) + "\n")
def save():
    path.write_text(json.dumps(state))
if args[0] == "ps":
    fmt = args[args.index("--format") + 1]
    for name, c in containers.items():
        if "-a" not in args and not c["running"]:
            continue
        if "{{.Status}}" in fmt:
            print(name + (" Up 2 seconds" if c["running"] else " Exited (0) 1 minute ago"))
        else:
            print(name)
elif args[0] == "inspect":
    name = args[-1]
    if name not in containers:
        sys.exit(125)
    print("true" if containers[name]["running"] else "false")
elif args[0] == "start":
    containers[args[-1]]["running"] = True
    save()
elif args[0] == "pull":
    sys.exit(1 if state.get("pull_fails") else 0)
elif args[0] == "rm":
    for name in [a for a in args[1:] if not a.startswith("-")]:
        containers.pop(name, None)
    save()
elif args[0] == "logs":
    print("mock log line")
elif args[0] == "run" and "-d" in args:
    name = args[args.index("--name") + 1]
    containers[name] = {"running": not state.get("dies_on_start")}
    save()
elif args[0] == "run":
    image = next(a for a in args if a.startswith("ghcr.io/"))
    cmd = args[args.index(image) + 1:]
    if cmd == ["uuid"]:
        print(os.environ["MOCK_UUID"])
    elif cmd == ["x25519"]:
        print("PrivateKey: PRIVKEY\nPassword (PublicKey): PUBKEY\nHash32: HASH")
    elif cmd[:2] == ["tls", "ping"]:
        if cmd[2] in state.get("tls_ok", []):
            print("Using IP:  198.51.100.4:443\nHandshake succeeded\n"
                  "TLS Version: TLS 1.3\nCertificate chain's total length: 4000 (certs count: 2)")
        else:
            print("Using IP:  198.51.100.5:443\nHandshake failure: remote error")
    elif cmd[:2] == ["run", "-test"]:
        sys.exit(1 if state.get("config_rejected") else 0)
    else:
        raise SystemExit("unexpected podman run: " + repr(args))
else:
    raise SystemExit("unexpected podman call: " + repr(args))
'''

MOCKS = {
    "podman": PODMAN,
    "openssl": "#!/bin/sh\necho 'ALPN protocol: h2'\n",
    "ss": "#!/bin/sh\nif [ -n \"$MOCK_PORT_BUSY\" ]; then echo 'LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*'; fi\n",
    "curl": "#!/bin/sh\necho 203.0.113.50\n",
    "id": "#!/bin/sh\necho \"${MOCK_UID:-0}\"\n",
    "chown": "#!/bin/sh\nexit 0\n",
    "systemctl": "#!/bin/sh\nexit 0\n",
}


class XrayInstallScriptTests(unittest.TestCase):
    def setUp(self):
        if not SCRIPT.exists():
            self.skipTest("olcos-core is not checked out")
        self.directory = Path(tempfile.mkdtemp(prefix="olcos-xray-test-"))
        self.prefix = self.directory / "opt"
        self.prefix.mkdir()
        self.bin = self.directory / "bin"
        self.bin.mkdir()
        for name, body in MOCKS.items():
            executable = self.bin / name
            executable.write_text(body)
            executable.chmod(0o700)
        self.state = self.directory / "state.json"
        self.log = self.directory / "calls.jsonl"
        self.set_state()
        self.env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}",
                        MOCK_STATE=str(self.state), MOCK_LOG=str(self.log), MOCK_UUID=UUID,
                        OLCOS_XRAY_PREFIX=str(self.prefix), OLCOS_XRAY_HOST="203.0.113.7",
                        OLCOS_XRAY_ID="test0001")

    def set_state(self, **state):
        self.state.write_text(json.dumps(state))

    def add_deployment(self, name, running, link=None, target="www.transip.nl:443"):
        state = json.loads(self.state.read_text())
        state.setdefault("containers", {})[name] = {"running": running}
        self.state.write_text(json.dumps(state))
        root = self.prefix / name
        (root / "config").mkdir(parents=True)
        (root / "config" / "10_inbound.json").write_text(
            '{"inbounds": [{"streamSettings": {"realitySettings": {"target": "%s"}}}]}' % target)
        if link is not None:
            (root / "keys").mkdir()
            (root / "keys" / "share.vless").write_text(link + "\n")

    def run_install(self, **env):
        return subprocess.run(["bash", str(SCRIPT)], env=dict(self.env, **env), text=True,
                              capture_output=True, timeout=120)

    @staticmethod
    def values(stdout):
        found = {}
        for line in stdout.splitlines():
            if line.startswith("OLCOS_XRAY_") and "=" in line:
                key, value = line.split("=", 1)
                found.setdefault(key, value)
        return found

    def podman_calls(self):
        if not self.log.exists():
            return []
        return [json.loads(line)[1:] for line in self.log.read_text().splitlines()]

    def test_fresh_install_uses_the_first_target_that_qualifies(self):
        self.set_state(tls_ok=["dl.google.com", "addons.mozilla.org"])
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        values = self.values(result.stdout)
        self.assertEqual(values["OLCOS_XRAY_TARGET"], "dl.google.com:443")
        self.assertEqual(values["OLCOS_XRAY_ADOPTED"], "0")
        self.assertEqual(values["OLCOS_XRAY_CONTAINER"], "olcos-xray-test0001")
        uri = values["OLCOS_XRAY_URI"]
        self.assertTrue(uri.startswith(f"vless://{UUID}@203.0.113.7:443?"), uri)
        for part in ("security=reality", "sni=dl.google.com", "pbk=PUBKEY",
                     "flow=xtls-rprx-vision", "type=tcp", "fp=chrome"):
            self.assertIn(part, uri)
        root = self.prefix / "olcos-xray-test0001"
        self.assertEqual((root / "keys" / "share.vless").read_text().strip(), uri)
        reality = json.loads((root / "config" / "10_inbound.json").read_text())[
            "inbounds"][0]["streamSettings"]["realitySettings"]
        self.assertEqual(reality["target"], "dl.google.com:443")
        self.assertEqual(reality["serverNames"], ["dl.google.com"])
        self.assertEqual(reality["privateKey"], "PRIVKEY")
        probed = [call[-1] for call in self.podman_calls() if call[:1] == ["run"] and "ping" in call]
        self.assertEqual(probed, ["www.transip.nl", "www.nlnet.nl", "dl.google.com"])
        started = [call for call in self.podman_calls() if call[:2] == ["run", "-d"]]
        self.assertEqual(len(started), 1)
        self.assertIn("--restart=always", started[0])

    def test_adopts_the_deployment_already_on_the_host(self):
        link = f"vless://{UUID}@203.0.113.7:443?security=reality&sni=www.transip.nl#olcOS-abc123"
        self.add_deployment("olcos-xray-abc123", running=True, link=link)
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        values = self.values(result.stdout)
        self.assertEqual(values["OLCOS_XRAY_URI"], link)
        self.assertEqual(values["OLCOS_XRAY_CONTAINER"], "olcos-xray-abc123")
        self.assertEqual(values["OLCOS_XRAY_TARGET"], "www.transip.nl:443")
        self.assertEqual(values["OLCOS_XRAY_ADOPTED"], "1")
        self.assertFalse([c for c in self.podman_calls() if c[0] in ("pull", "run", "start", "rm")])

    def test_adopting_starts_a_stopped_deployment(self):
        link = f"vless://{UUID}@203.0.113.7:443?security=reality&sni=www.transip.nl#olcOS-abc123"
        self.add_deployment("olcos-xray-abc123", running=False, link=link)
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(["start", "olcos-xray-abc123"], self.podman_calls())
        self.assertEqual(self.values(result.stdout)["OLCOS_XRAY_ADOPTED"], "1")

    def test_a_deployment_without_its_link_is_reported_not_replaced(self):
        self.add_deployment("olcos-xray-abc123", running=True, link=None)
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("share.vless", self.values(result.stdout)["OLCOS_XRAY_ERROR"])
        self.assertFalse([c for c in self.podman_calls() if c[0] in ("run", "rm", "pull")])

    def test_no_qualifying_target_is_an_error(self):
        self.set_state(tls_ok=[])
        result = self.run_install()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no camouflage site", self.values(result.stdout)["OLCOS_XRAY_ERROR"])
        self.assertFalse([c for c in self.podman_calls() if c[:2] == ["run", "-d"]])

    def test_a_busy_port_is_an_error(self):
        self.set_state(tls_ok=["dl.google.com"])
        result = self.run_install(MOCK_PORT_BUSY="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("already in use", self.values(result.stdout)["OLCOS_XRAY_ERROR"])

    def test_a_high_risk_target_is_refused_without_probing_it(self):
        self.set_state(tls_ok=["www.apple.com"])
        result = self.run_install(OLCOS_XRAY_TARGET="www.apple.com")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("www.apple.com", self.values(result.stdout)["OLCOS_XRAY_ERROR"])
        self.assertFalse([c for c in self.podman_calls() if "ping" in c])

    def test_it_needs_root(self):
        result = self.run_install(MOCK_UID="1000")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("run as root", self.values(result.stdout)["OLCOS_XRAY_ERROR"])
        self.assertEqual(self.podman_calls(), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
