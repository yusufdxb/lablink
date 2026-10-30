#!/usr/bin/env python3
"""Isolated installer regressions. Never install packages or alter host state.

Only operating-system metadata, install paths and temporary paths are redirected
in a copy of the production script. Network and package-manager commands use
fixtures. sha256sum, mktemp, awk and the shell itself are real. Real release and
Ubuntu installation coverage lives in the companion release/container checks.
"""

import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "scripts/install-linux.sh").read_text()
VERSION = SOURCE.split("readonly RELEASE_VERSION='")[1].split("'")[0]
PACKAGE = f"lablink_{VERSION}_amd64.deb"
PAYLOAD = b"isolated package fixture\n"
DIGEST = hashlib.sha256(PAYLOAD).hexdigest()
INSTALL_COMMAND = re.search(r"```bash\n([^\n]+)\n```", (ROOT / "README.md").read_text()).group(1)

DISPATCH = r'''
import hashlib, json, os, pathlib, signal, subprocess, sys
root = pathlib.Path(os.environ['INSTALL_FIXTURE'])
cfg = json.loads((root / 'scenario.json').read_text())
name = pathlib.Path(sys.argv[0]).name
args = sys.argv[1:]
with (root / 'events').open('a') as log:
    log.write(json.dumps([name] + args) + '\n')
version = cfg['version']
package = 'lablink_' + version + '_amd64.deb'
if name == 'uname':
    print(cfg.get('kernel', 'Linux') if args == ['-s'] else cfg.get('arch', 'x86_64'))
elif name == 'dpkg':
    if args == ['--print-architecture']:
        print(cfg.get('userland', 'amd64'))
    else:
        sys.exit(subprocess.call(['/usr/bin/dpkg'] + args))
elif name == 'dpkg-query':
    state = root / 'installed'
    if state.exists(): print('installed ' + state.read_text(), end='')
    else: sys.exit(1)
elif name == 'dpkg-deb':
    key = args[-1]
    print(cfg.get('metadata', {}).get(key, {'Package': 'lablink', 'Version': version, 'Architecture': 'amd64'}[key]))
elif name == 'curl':
    url = args[-1]
    if url == 'https://raw.githubusercontent.com/yusufdxb/lablink/main/scripts/install-linux.sh':
        mode = cfg.get('bootstrap', '')
        if mode == '404': sys.exit(22)
        if mode == 'interrupted':
            # A valid executable prefix must never run after a failed transfer.
            print('printf executed > "$INSTALL_FIXTURE/partial-executed"', flush=True)
            sys.exit(18)
        sys.stdout.write((root / 'install.sh').read_text())
        sys.exit(0)
    asset = url.rsplit('/', 1)[-1]
    assert url == 'https://github.com/yusufdxb/lablink/releases/download/v' + version + '/' + asset
    assert args[args.index('--proto') + 1] == '=https'
    assert args[args.index('--proto-redir') + 1] == '=https'
    assert '--fail' in args and '--insecure' not in args
    target = pathlib.Path(args[args.index('--output') + 1])
    mode = cfg.get('download', '')
    if mode in ('all', asset): sys.exit(22)
    if mode == 'interrupt':
        target.write_bytes(b'partial download')
        os.kill(os.getppid(), signal.SIGTERM)
        sys.exit(0)
    payload = b'isolated package fixture\n'
    if asset == 'SHA256SUMS':
        digest = hashlib.sha256(payload).hexdigest()
        default = digest + '  ./' + package + '\n'
        target.write_text(cfg.get('manifest', default))
    else:
        target.write_bytes(payload)
elif name == 'sudo':
    assert args[0] == 'apt'
    os.execv(str(root / 'tools' / 'apt'), [str(root / 'tools' / 'apt')] + args[1:])
elif name == 'apt':
    assert args[:3] == ['install', '--yes', '--no-remove']
    assert hashlib.sha256(pathlib.Path(args[-1]).read_bytes()).hexdigest() == hashlib.sha256(b'isolated package fixture\n').hexdigest()
    assert not sys.stdin.read(), 'apt must receive EOF, not piped installer source'
    if cfg.get('apt_failure'): sys.exit(100)
    if cfg.get('apt_interrupt'):
        os.kill(os.getppid(), signal.SIGTERM)
        sys.exit(0)
    (root / 'installed').write_text(cfg.get('installed_after', version))
    for binary in ('lablink', 'lablinkd', 'lablink-gui'):
        if binary == cfg.get('missing_binary'): continue
        path = root / 'binaries' / binary
        path.write_text((root / 'dispatcher').read_text())
        path.chmod(0o755)
elif name == 'lablink':
    if cfg.get('cli_failure'): sys.exit(1)
    print('lablink ' + cfg.get('cli_version', (root / 'installed').read_text()) + ' (commit fixture)')
elif name == 'lablinkd':
    if cfg.get('daemon_failure'): sys.exit(1)
    print('lablinkd ' + cfg.get('daemon_version', (root / 'installed').read_text()))
elif name == 'loader':
    assert args[0] == '--list'
    assert args[1] == str(root / 'binaries' / 'lablink-gui')
    if cfg.get('gui_failure'): sys.exit(127)
else:
    raise AssertionError('unexpected fixture command: ' + name)
'''


@unittest.skipIf(os.geteuid() == 0, "Run regressions as an unprivileged user")
class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="lablink-installer-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for name in ("tools", "binaries", "downloads", "home"):
            (self.root / name).mkdir()
        self.cfg = {"version": VERSION}
        self.os_release = self.root / "os-release"
        self.os_release.write_text('ID=ubuntu\nVERSION_ID="22.04"\n')
        self.dispatcher = f"#!{sys.executable}\n" + DISPATCH
        (self.root / "dispatcher").write_text(self.dispatcher)
        for utility in ("uname", "curl", "dpkg", "dpkg-query", "dpkg-deb", "sudo", "apt"):
            self.stub(self.root / "tools" / utility)
        for utility in ("bash", "sha256sum", "mktemp", "rm", "chmod", "awk"):
            (self.root / "tools" / utility).symlink_to(shutil.which(utility))
        self.stub(self.root / "loader")
        (self.root / "ca-certificates.crt").write_text("fixture CA presence check\n")
        source = SOURCE.replace("/etc/os-release", str(self.os_release))
        source = source.replace("/etc/ssl/certs/ca-certificates.crt", str(self.root / "ca-certificates.crt"))
        source = source.replace("/usr/bin/", str(self.root / "binaries") + "/")
        source = source.replace("/lib64/ld-linux-x86-64.so.2", str(self.root / "loader"))
        source = source.replace("/tmp/lablink-install.", str(self.root / "downloads" / "lablink-install."))
        self.script = self.root / "install.sh"
        self.script.write_text(source)
        self.env = dict(os.environ, PATH=f"{self.root}/tools:{self.root}/binaries", HOME=str(self.root / "home"), INSTALL_FIXTURE=str(self.root))
        self.sentinels = {}
        for relative in (".config/lablink/config.yaml", ".local/state/lablink/cache.db", ".local/state/lablink/known_hosts", ".ssh/id_ed25519", ".ssh/known_hosts"):
            path = self.root / "home" / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            data = b"preserve fixture " + relative.encode()
            path.write_bytes(data)
            path.chmod(0o600)
            self.sentinels[path] = (data, path.stat().st_mode)

    def stub(self, path):
        path.write_text(self.dispatcher)
        path.chmod(0o755)

    def existing(self, version=VERSION):
        (self.root / "installed").write_text(version)
        for name in ("lablink", "lablinkd", "lablink-gui"):
            self.stub(self.root / "binaries" / name)

    def run_installer(self, success=False, bootstrap=True):
        (self.root / "scenario.json").write_text(json.dumps(self.cfg))
        # Execute the literal README command, including both nested shells.
        # Only curl and the existing isolated OS/package fixtures are replaced.
        command = ["/bin/bash", "--noprofile", "--norc", "-c", INSTALL_COMMAND] if bootstrap else ["/bin/bash"]
        result = subprocess.run(command, input=None if bootstrap else self.script.read_text(),
                                text=True, capture_output=True, env=self.env, timeout=15)
        self.output = result.stdout + result.stderr
        if success:
            self.assertEqual(result.returncode, 0, self.output)
            self.assertIn("LabLink installed successfully!", self.output)
        else:
            self.assertNotEqual(result.returncode, 0, self.output)
            self.assertNotIn("LabLink installed successfully!", self.output)
        self.assertEqual(list((self.root / "downloads").iterdir()), [], self.output)
        for path, (contents, mode) in self.sentinels.items():
            self.assertEqual(path.read_bytes(), contents)
            self.assertEqual(path.stat().st_mode, mode)
        events = self.root / "events"
        self.events = [json.loads(line) for line in events.read_text().splitlines()] if events.exists() else []
        return result

    def no_install(self):
        self.assertFalse(any(event[0] in ("sudo", "apt") for event in self.events), self.events)

    def test_clean_install_checks_executables_and_preserves_config(self):
        self.run_installer(success=True)
        self.assertEqual(sum(e[0] == "apt" for e in self.events), 1)
        self.assertTrue(any(e[0] == "loader" for e in self.events))
        self.assertIn("lablink init", self.output)
        self.assertIn("lablink doctor", self.output)
        self.assertIn("lablink status", self.output)
        self.assertFalse(any(e[0] == "lablink-gui" for e in self.events))

    def test_supported_ubuntu_releases(self):
        for version in ("20.04", "22.04", "24.04"):
            with self.subTest(version=version):
                self.os_release.write_text(f'ID=ubuntu\nVERSION_ID="{version}"\n')
                self.run_installer(success=True)

    def test_reinstallation_needs_no_download_or_sudo(self):
        self.existing()
        self.run_installer(success=True)
        self.no_install()
        self.assertFalse(any(e[0] == "curl" and "/releases/download/" in e[-1] for e in self.events))

    def test_documented_command_returns_nonzero_on_http_404(self):
        self.cfg["bootstrap"] = "404"
        result = self.run_installer()
        self.assertEqual(result.returncode, 22)
        self.no_install()

    def test_documented_command_never_executes_an_interrupted_download(self):
        self.cfg["bootstrap"] = "interrupted"
        result = self.run_installer()
        self.assertEqual(result.returncode, 18)
        self.assertFalse((self.root / "partial-executed").exists())
        self.no_install()

    def test_newer_installed_release_is_not_downgraded(self):
        self.existing("99.0.0")
        self.run_installer(success=True)
        self.no_install()
        self.assertIn("99.0.0", self.output)

    def test_older_installed_release_is_upgraded(self):
        self.existing("0.1.0")
        self.run_installer(success=True)
        self.assertIn("systemctl --user restart lablinkd", self.output)

    def test_arm64_is_rejected(self):
        self.cfg["arch"] = "aarch64"
        self.run_installer()
        self.assertIn("Unsupported architecture", self.output)
        self.no_install()

    def test_other_kernel_is_rejected(self):
        self.cfg["kernel"] = "Darwin"
        self.run_installer()
        self.no_install()

    def test_non_amd64_userland_is_rejected(self):
        self.cfg["userland"] = "i386"
        self.run_installer()
        self.assertIn("amd64 Ubuntu userland", self.output)
        self.no_install()

    def test_unsupported_distribution_is_rejected(self):
        self.os_release.write_text('ID=debian\nVERSION_ID="12"\n')
        self.run_installer()
        self.assertIn("Unsupported distribution", self.output)
        self.no_install()

    def test_unsupported_ubuntu_version_is_rejected(self):
        self.os_release.write_text('ID=ubuntu\nVERSION_ID="18.04"\n')
        self.run_installer()
        self.assertIn("Unsupported Ubuntu version", self.output)
        self.no_install()

    def test_missing_os_metadata(self):
        self.os_release.unlink()
        self.run_installer()
        self.assertIn("Cannot identify", self.output)
        self.no_install()

    def test_missing_curl_has_actionable_error(self):
        (self.root / "tools" / "curl").unlink()
        self.run_installer(bootstrap=False)
        self.assertIn("Missing prerequisite: curl", self.output)
        self.assertIn("sudo apt install", self.output)
        self.no_install()

    def test_documented_command_reports_missing_curl(self):
        (self.root / "tools" / "curl").unlink()
        result = self.run_installer()
        self.assertEqual(result.returncode, 127)
        self.no_install()

    def test_missing_ca_certificates_has_actionable_error(self):
        (self.root / "ca-certificates.crt").unlink()
        self.run_installer()
        self.assertIn("Missing TLS CA certificates", self.output)
        self.no_install()

    def test_download_failure(self):
        self.cfg["download"] = "all"
        self.run_installer()
        self.assertIn("Could not download SHA256SUMS", self.output)
        self.no_install()

    def test_missing_package_asset(self):
        self.cfg["download"] = PACKAGE
        self.run_installer()
        self.assertIn("Could not download " + PACKAGE, self.output)
        self.no_install()

    def test_wrong_checksum_is_never_installed(self):
        self.cfg["manifest"] = "0" * 64 + "  ./" + PACKAGE + "\n"
        self.run_installer()
        self.assertIn("checksum mismatch", self.output)
        self.no_install()

    def test_missing_checksum_is_never_installed(self):
        self.cfg["manifest"] = DIGEST + "  another.deb\n"
        self.run_installer()
        self.assertIn("exactly one valid checksum", self.output)
        self.no_install()

    def test_duplicate_checksum_is_never_installed(self):
        self.cfg["manifest"] = (DIGEST + "  ./" + PACKAGE + "\n") * 2
        self.run_installer()
        self.assertIn("exactly one valid checksum", self.output)
        self.no_install()

    def test_malformed_checksum_is_never_installed(self):
        self.cfg["manifest"] = "z" * 64 + "  ./" + PACKAGE + "\n"
        self.run_installer()
        self.no_install()

    def test_binary_checksum_marker_is_supported(self):
        self.cfg["manifest"] = DIGEST + " *" + PACKAGE + "\n"
        self.run_installer(success=True)

    def test_incorrect_package_metadata_is_rejected(self):
        self.cfg["metadata"] = {"Package": "unrelated"}
        self.run_installer()
        self.assertIn("unexpected package metadata", self.output)
        self.no_install()

    def test_interrupt_removes_partial_download(self):
        self.cfg["download"] = "interrupt"
        self.run_installer()
        self.assertIn("interrupted", self.output)
        self.no_install()

    def test_apt_failure_cleans_downloads_and_explains_recovery(self):
        self.cfg["apt_failure"] = True
        self.run_installer()
        self.assertIn("apt installation failed", self.output)
        self.assertIn("sudo dpkg --configure -a", self.output)

    def test_interrupt_during_apt_cleans_downloads(self):
        self.cfg["apt_interrupt"] = True
        self.run_installer()
        self.assertIn("interrupted", self.output)

    def test_missing_dynamic_loader_fails_verification(self):
        (self.root / "loader").unlink()
        self.run_installer()
        self.assertIn("dynamic loader is missing", self.output)

    def test_missing_gui_executable_fails_verification(self):
        self.cfg["missing_binary"] = "lablink-gui"
        self.run_installer()
        self.assertIn("Missing executable", self.output)

    def test_cli_failure_is_reported(self):
        self.cfg["cli_failure"] = True
        self.run_installer()
        self.assertIn("CLI could not run", self.output)

    def test_cli_version_mismatch_is_reported(self):
        self.cfg["cli_version"] = "0.0.0"
        self.run_installer()
        self.assertIn("Unexpected CLI version", self.output)

    def test_daemon_version_mismatch_is_reported(self):
        self.cfg["daemon_version"] = "0.0.0"
        self.run_installer()
        self.assertIn("Unexpected daemon version", self.output)

    def test_gui_loader_failure_is_reported(self):
        self.cfg["gui_failure"] = True
        self.run_installer()
        self.assertIn("missing runtime libraries", self.output)

    def test_shadowed_tarball_install_is_not_overwritten(self):
        shadow = self.root / "tools" / "lablink"
        self.stub(shadow)
        original = shadow.read_bytes()
        self.run_installer()
        self.assertIn("would hide", self.output)
        self.assertEqual(shadow.read_bytes(), original)
        self.no_install()

    def test_wrong_installed_package_version_is_reported(self):
        self.cfg["installed_after"] = "0.0.0"
        self.run_installer()
        self.assertIn("Expected installed LabLink", self.output)


class RootPolicyTest(unittest.TestCase):
    def test_actual_script_rejects_root_without_touching_the_system(self):
        command = ["/bin/bash", str(ROOT / "scripts/install-linux.sh")]
        if os.geteuid() != 0:
            sudo = shutil.which("sudo")
            if not sudo or subprocess.run([sudo, "-n", "true"], capture_output=True).returncode:
                self.skipTest("Root rejection requires root or passwordless sudo")
            command = [sudo, "-n"] + command
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("normal user, without sudo", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
