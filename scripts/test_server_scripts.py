#!/usr/bin/env python3
"""Offline checks of the server side: the olcrtc patch, srv.sh and the
one-line installer.

server/olcrtc-core.patch is the olcOS work in olcrtc/ as one patch against the
upstream release in olcrtc.upstream (scripts/make-core-patch.sh writes it).
srv.sh applies it between the checkout of the pin and the build and records
its id, so the apps can tell a patched core from the bare pin. The apps'
side of that contract (upload, update script, bundling) is tested in the app
repositories.

Run: python3 scripts/test_server_scripts.py
"""
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PATCH = ROOT / "server" / "olcrtc-core.patch"


def read(relative):
    return (ROOT / relative).read_text(encoding="utf-8")


def upstream_value(key):
    for line in read("olcrtc.upstream").splitlines():
        if line.startswith(key + "="):
            return line.split("=", 1)[1]
    raise AssertionError(f"{key} missing from olcrtc.upstream")


def executable_lines(relative):
    return [line for line in read(relative).splitlines() if not line.lstrip().startswith("#")]


class CorePatch(unittest.TestCase):
    def test_it_only_modifies_existing_files(self):
        # The server update restores tracked files before re-applying, and
        # git apply refuses to create a file that already exists.
        text = PATCH.read_text(encoding="utf-8")
        self.assertNotIn("\nnew file mode", text)
        self.assertNotIn("\ndeleted file mode", text)
        self.assertNotIn("\r", text)

    def test_it_carries_the_single_packet_relay_work(self):
        self.assertIn("SinglePacketRelay", PATCH.read_text(encoding="utf-8"))

    def test_it_leaves_out_the_phone_only_files(self):
        text = PATCH.read_text(encoding="utf-8")
        self.assertNotIn("diff --git a/mobile/", text)
        self.assertNotIn("zz_olcos_", text)

    def test_it_applies_to_the_upstream_tree(self):
        squash = subprocess.run(
            ["git", "-C", str(ROOT), "log", "-1", "--format=%H", "--grep=^git-subtree-dir: olcrtc$"],
            capture_output=True, text=True, check=True).stdout.strip()
        if not squash:
            self.skipTest("no subtree history (shallow clone)")
        with tempfile.TemporaryDirectory() as tmp:
            archive = subprocess.run(["git", "-C", str(ROOT), "archive", squash],
                                     capture_output=True, check=True).stdout
            subprocess.run(["tar", "-x", "-C", tmp], input=archive, check=True)
            subprocess.run(["git", "init", "-q", tmp], check=True)
            result = subprocess.run(["git", "-C", tmp, "apply", "--check", str(PATCH)],
                                    capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


class ServerInstall(unittest.TestCase):
    def test_srv_applies_the_patch_between_checkout_and_build(self):
        srv = read("server/srv.sh")
        checkout = srv.index('git -C "$WORK_DIR" checkout -q FETCH_HEAD')
        guard = srv.index('if [ -s "${OLCRTC_CORE_PATCH:-}" ]; then')
        apply_at = srv.index('git -C "$WORK_DIR" apply "$OLCRTC_CORE_PATCH"')
        record = srv.index('printf \'%s\\n\' "${OLCRTC_CORE_PATCH_ID:-}" > "$WORK_DIR/.olcos-core-patch"')
        build = srv.index("go build -trimpath")
        self.assertLess(checkout, guard)
        self.assertLess(guard, apply_at)
        self.assertLess(apply_at, record)
        self.assertLess(record, build)

    def test_srv_builds_the_pinned_upstream_commit(self):
        srv = read("server/srv.sh")
        repo = upstream_value("OLCRTC_REPO")
        self.assertIn(f'REPO_URL="{repo}.git"', srv)
        self.assertIn('OLCRTC_PIN="${OLCRTC_PIN:-' + upstream_value("OLCRTC_COMMIT") + '}"', srv)

    def test_the_installer_reads_the_pin_and_passes_the_patch(self):
        install = read("server/install.sh")
        self.assertIn("fetch olcrtc.upstream", install)
        self.assertIn("fetch server/olcrtc-core.patch", install)
        self.assertIn('OLCRTC_CORE_PATCH="$WORK/olcrtc-core.patch" OLCRTC_CORE_PATCH_ID="$PATCH_ID"', install)
        self.assertIn("PATCH_ID=$(sha256sum \"$WORK/olcrtc-core.patch\" | cut -d' ' -f1)", install)

    def test_the_installer_fetches_files_that_exist(self):
        install = read("server/install.sh")
        sources = install.split('AGENT_SOURCES="', 1)[1].split('"', 1)[0].split()
        self.assertTrue(sources)
        for name in sources:
            self.assertTrue((ROOT / "mobile" / "agent" / name).is_file(), name)
        for status in ("readiness", "carriers", "xray"):
            self.assertTrue((ROOT / "server" / "agent-status" / f"{status}.sh").is_file(), status)


class RestartPolicy(unittest.TestCase):
    def test_new_containers_come_back_after_a_reboot(self):
        # podman-restart.service starts only restart-policy=always containers.
        for relative in ("server/srv.sh", "server/add-carrier.sh"):
            executable = executable_lines(relative)
            self.assertIn("    --restart always \\", executable, relative)
            self.assertFalse(any("unless-stopped" in line for line in executable), relative)
        self.assertIn("systemctl enable podman-restart.service", read("server/srv.sh"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
