#!/usr/bin/env python3
"""Local-only GNOME Terminal/OpenSSH regression tests. No real passwords.
Run after cargo build -p lablink-cli:
  xvfb-run -a dbus-run-session -- python3 scripts/test-onboarding-terminal.py
Every key, daemon socket, server and remote authorized_keys is disposable.
No terminal input is read, captured or automated by this harness.
"""
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / "target/debug/lablink"


def wait_for(predicate, seconds=45):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.1)
    raise AssertionError("fixture timed out")


def keygen(path):
    subprocess.run(["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(path)], check=True)


def write(path, text, mode=0o600):
    path.write_text(text)
    path.chmod(mode)


class Fixture:
    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="lablink-terminal-", dir="/tmp")
        self.dir = Path(self.tmp.name)
        self.home = self.dir / "home"
        self.home.mkdir(mode=0o700)
        (self.home / ".ssh").mkdir(mode=0o700)
        self.session = self.dir / "session"
        self.session.mkdir(mode=0o700)
        self.bin = self.dir / "bin"
        self.bin.mkdir(mode=0o700)
        self.key = self.dir / "client"
        keygen(self.key)
        self.host = self.dir / "host"
        keygen(self.host)
        self.kh = self.dir / "pinned"
        write(self.kh, "lablink.carebear.device " + self.host.with_suffix(".pub").read_text())
        fp = subprocess.check_output(["/usr/bin/ssh-keygen", "-lf", str(self.host.with_suffix(".pub"))], text=True).split()[1]
        self.plan = dict(device="carebear/device", username=pwd.getpwuid(os.getuid()).pw_name,
                         fingerprints=[fp], identity=str(self.key), generate_consent=False)
        self.resolve = dict(schema_version=1, name="device", id="carebear/device", site_name="Carebear",
                            shared_name=False, site_away=False, ip="127.0.0.1", port=22,
                            ssh_host="device", username=self.plan["username"], identity="verified",
                            color="green", network="online", host_key_alias="lablink.carebear.device",
                            known_hosts_file=str(self.kh), ssh_binary="/usr/bin/ssh", connect_timeout_s=2,
                            ssh_options={}, proxy_command=None)
        self.calls = []
        self.listener = socket.socket(socket.AF_UNIX)
        self.sock = self.dir / "daemon.sock"
        self.listener.bind(str(self.sock))
        self.sock.chmod(0o600)
        self.listener.listen()
        self.listener.settimeout(0.2)
        self.stop = False
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()
        self.children = []
        self.terminal = None
        self.env = dict(os.environ, HOME=str(self.home), PATH=f"{self.bin}:/usr/bin:/bin",
                        GDK_BACKEND="x11", LABLINK_SOCKET=str(self.sock))
        self.env.pop("SSH_ASKPASS", None)
        self.env.pop("SSH_AUTH_SOCK", None)

    def serve(self):
        while not self.stop:
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                f = conn.makefile("rwb")
                req = json.loads(f.readline())
                self.calls.append(req)
                result = self.resolve if req["method"] == "resolve" else {}
                f.write((json.dumps(dict(ok=True, result=result)) + "\n").encode())
                f.flush()

    def fake(self, name, body):
        write(self.bin / name, "#!/bin/sh\n" + body + "\n", 0o700)

    def launch(self):
        write(self.session / "request.json", json.dumps(self.plan))
        write(self.session / "progress.json", '"waiting"')
        self.terminal = subprocess.Popen(["gnome-terminal", "--wait", "--", "/usr/bin/env",
                                           *[f"{k}={v}" for k, v in self.env.items() if k in ("HOME", "PATH", "SSH_AUTH_SOCK")], str(CLI), "--socket", str(self.sock),
                                           "onboard-ssh", "--session", str(self.session)], env=self.env,
                                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return self.terminal

    def progress(self):
        try:
            return json.loads((self.session / "progress.json").read_text())
        except (FileNotFoundError, json.JSONDecodeError):
            return None

    def finish(self, expected):
        try:
            wait_for(lambda: self.progress() not in (None, "waiting", "configuring", "testing"))
            assert self.progress() == expected
        except AssertionError:
            raise AssertionError(f"expected {expected}, progress={self.progress()}, calls={self.calls}, sshd_log={(self.dir / 'sshd.log').read_text() if (self.dir / 'sshd.log').exists() else 'none'}")
        self.terminal.wait(timeout=10)
        self.assert_no_secret_state()

    def assert_no_secret_state(self):
        for p in self.session.rglob("*"):
            if p.is_file():
                assert b"PASSWORD_SENTINEL_NEVER_ENTERED" not in p.read_bytes()
        assert "password" not in json.dumps(self.calls)

    def real_server(self):
        bootstrap = self.dir / "bootstrap"
        keygen(bootstrap)
        authorized = self.dir / "authorized_keys"
        write(authorized, bootstrap.with_suffix(".pub").read_text())
        # A fixed server-side test command maps key installation to the
        # disposable authorized_keys file. No caller command is evaluated.
        remote = self.dir / "remote"
        write(remote, f'''#!/usr/bin/python3
import os, sys
command = os.environ.get("SSH_ORIGINAL_COMMAND", "")
if command in ("exit", "true"):
    sys.exit(0)
if command.startswith("exec sh -c '") and "cat >>" in command and ".ssh/authorized_keys" in command:
    data = sys.stdin.buffer.read(16384)
    with open({str(authorized)!r}, "ab") as f:
        f.write(data)
    sys.exit(0)
sys.exit(1)
''', 0o700)
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        self.resolve["port"] = port
        # sshd StrictModes rejects /tmp even when the child directory is
        # private. This setting affects only this disposable server fixture.
        cfg = self.dir / "sshd_config"
        write(cfg, f"""Port {port}
ListenAddress 127.0.0.1
HostKey {self.host}
PidFile {self.dir / 'sshd.pid'}
AuthorizedKeysFile {authorized}
StrictModes no
UsePAM no
PasswordAuthentication no
KbdInteractiveAuthentication no
PubkeyAuthentication yes
LogLevel VERBOSE
ForceCommand {remote}
AllowUsers {self.plan['username']}
""")
        server = subprocess.Popen(["/usr/sbin/sshd", "-D", "-f", str(cfg), "-E", str(self.dir / "sshd.log")])
        self.children.append(server)
        def listening():
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    return True
            except OSError:
                if server.poll() is not None:
                    raise AssertionError((self.dir / "sshd.log").read_text())
                return False
        wait_for(listening)
        agent_sock = self.dir / "agent.sock"
        agent = subprocess.Popen(["/usr/bin/ssh-agent", "-D", "-a", str(agent_sock)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.children.append(agent)
        wait_for(agent_sock.exists)
        self.env["SSH_AUTH_SOCK"] = str(agent_sock)
        subprocess.run(["/usr/bin/ssh-add", str(bootstrap)], env=self.env, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return authorized

    def close(self):
        if self.terminal and self.terminal.poll() is None:
            write(self.session / "cancel", "")
            try:
                self.terminal.wait(timeout=4)
            except subprocess.TimeoutExpired:
                self.terminal.terminate()
                self.terminal.wait(timeout=4)
        for child in self.children:
            child.terminate()
            child.wait(timeout=5)
        self.stop = True
        self.listener.close()
        self.thread.join(timeout=2)
        self.tmp.cleanup()


class TerminalTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.addCleanup(self.f.close)

    def test_real_openssh_installs_and_tests_pinned_key(self):
        f = self.f
        authorized = f.real_server()
        original_key = f.key.read_bytes()
        f.launch()
        f.finish("connected")
        self.assertIn(f.key.with_suffix(".pub").read_text().split()[1], authorized.read_text())
        self.assertEqual(f.key.read_bytes(), original_key)
        self.assertEqual(f.calls[-1]["params"]["changes"]["identity_file"], str(f.key))
        self.assertEqual(f.calls[-1]["params"]["device"], "carebear/device")

    def test_host_key_mismatch_is_rejected_by_openssh(self):
        f = self.f
        f.real_server()
        wrong = f.dir / "wronghost"
        keygen(wrong)
        write(f.kh, "lablink.carebear.device " + wrong.with_suffix(".pub").read_text())
        f.plan["fingerprints"] = [subprocess.check_output(["/usr/bin/ssh-keygen", "-lf", str(wrong.with_suffix(".pub"))], text=True).split()[1]]
        f.launch()
        f.finish("authentication_failed")
        self.assertFalse(any(r["method"] == "set" for r in f.calls))

    def test_changed_pins_fail_before_authentication(self):
        f = self.f
        f.plan["fingerprints"] = ["SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"]
        f.fake("ssh-copy-id", f"touch {f.dir / 'must-not-run'}")
        f.launch()
        f.finish("identity_failed")
        self.assertFalse((f.dir / "must-not-run").exists())

    def test_incorrect_username_with_real_openssh(self):
        f = self.f
        f.real_server()
        f.plan["username"] = "lablink-no-such-test-user"
        f.resolve["username"] = f.plan["username"]
        f.launch()
        f.finish("authentication_failed")
        self.assertFalse(any(r["method"] == "set" for r in f.calls))

    def test_password_failure_result_without_collecting_a_password(self):
        f = self.f
        # Simulates the exit status of OpenSSH after incorrect passwords.
        # Actual password typing is reserved for an approved manual test.
        f.fake("ssh-copy-id", "printf 'Permission denied (password).\\n' >&2\nexit 1")
        f.launch()
        f.finish("authentication_failed")
        self.assertFalse(any(r["method"] == "set" for r in f.calls))

    def test_password_login_disabled_with_real_openssh(self):
        f = self.f
        f.real_server()
        f.env.pop("SSH_AUTH_SOCK")
        f.launch()
        f.finish("authentication_failed")

    def test_cancel_stops_the_foreground_authentication_process(self):
        f = self.f
        f.fake("ssh-copy-id", "exec /bin/sleep 120")
        f.launch()
        wait_for(lambda: f.progress() == "configuring" and (f.session / "home").exists())
        write(f.session / "cancel", "")
        f.finish("cancelled")
        self.assertFalse(any(r["method"] == "set" for r in f.calls))

    def test_closing_the_terminal_cannot_report_a_connection(self):
        f = self.f
        f.fake("ssh-copy-id", "exec /bin/sleep 120")
        f.launch()
        wait_for(lambda: f.progress() == "configuring" and (f.session / "home").exists())
        window = subprocess.check_output(["xdotool", "search", "--class", "gnome-terminal"], text=True).splitlines()[-1]
        subprocess.run(["xdotool", "windowkill", window], check=True)
        f.terminal.wait(timeout=10)
        self.assertNotEqual(f.progress(), "connected")
        self.assertFalse(any(r["method"] == "set" for r in f.calls))

    def test_missing_key_consent_and_generation_preserve_existing_key(self):
        f = self.f
        f.fake("ssh-keygen", 'exec /usr/bin/ssh-keygen -N "" "$@"')
        f.fake("ssh-copy-id", "exit 1")
        original = f.key.read_bytes()
        f.plan.update(identity=None, generate_consent=True)
        f.launch()
        f.finish("authentication_failed")
        generated = Path((f.session / "generated_identity").read_text())
        self.assertEqual(generated.stat().st_mode & 0o777, 0o600)
        self.assertEqual(generated.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(f.key.read_bytes(), original)
        self.assertTrue(str(generated).startswith(str(f.home / ".ssh/lablink-key-")))

    def test_missing_key_without_consent_does_not_generate(self):
        f = self.f
        f.fake("ssh-keygen", f"touch {f.dir / 'must-not-run'}")
        f.plan.update(identity=None, generate_consent=False)
        f.launch()
        f.finish("key_failed")
        self.assertFalse((f.dir / "must-not-run").exists())

    def test_snapshot_survives_live_pin_file_change(self):
        f = self.f
        f.real_server()
        # Delay copy-id until its private snapshot is ready, then change the
        # live file to an unrelated key. The immutable approval still wins.
        f.fake("ssh-copy-id", '/bin/sleep 2\nexec /usr/bin/ssh-copy-id "$@"')
        f.launch()
        wait_for(lambda: f.progress() == "configuring")
        write(f.kh, "# changed after approval\n")
        f.finish("connected")

    def test_private_key_permissions_rejected_without_mutation(self):
        f = self.f
        f.key.chmod(0o644)
        f.launch()
        f.finish("key_failed")
        self.assertEqual(f.key.stat().st_mode & 0o777, 0o644)

    def test_site_or_username_drift_stops_before_open_ssh(self):
        f = self.f
        f.resolve["site_away"] = True
        f.launch()
        f.finish("identity_failed")
        self.assertFalse(any(r["method"] == "set" for r in f.calls))


if __name__ == "__main__":
    if not CLI.exists() or not shutil.which("gnome-terminal") or not os.environ.get("DISPLAY"):
        raise SystemExit("Build the development CLI and run under xvfb-run + dbus-run-session.")
    unittest.main(verbosity=2)
