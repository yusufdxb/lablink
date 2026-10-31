#!/usr/bin/env python3
"""Run only inside the disposable packaging container, never on a lab host."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import time


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs)


assert Path('/run/lablink-packaging-container').is_file(), 'container isolation is required'
assert os.getuid() != 0, 'per-user tests must run as an ordinary user'
mode, commit = sys.argv[1:]
with tempfile.TemporaryDirectory(prefix='lablink-package-') as temp:
    home = Path(temp) / 'home'
    home.mkdir(mode=0o700)
    os.environ.update(HOME=str(home), XDG_CONFIG_HOME=str(home / '.config'),
                      XDG_DATA_HOME=str(home / '.local/share'),
                      XDG_STATE_HOME=str(home / '.local/state'),
                      XDG_RUNTIME_DIR=str(home / 'runtime'),
                      LABLINK_SOCKET=str(home / 'runtime/no-daemon.sock'))
    for relative in ['.ssh/id_rsa', '.ssh/id_rsa.pub', '.ssh/config', '.ssh/known_hosts',
                     '.config/lablink/config.yaml', '.local/state/lablink/known_hosts']:
        path = home / relative
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_text('devices: []\n' if relative.endswith('config.yaml') else 'disposable preservation fixture\n')
        path.chmod(0o600)
    protected = [p for p in home.rglob('*') if p.is_file()]

    def snapshot():
        return [(str(p.relative_to(home)), hashlib.sha256(p.read_bytes()).hexdigest(),
                 p.stat().st_mode, p.stat().st_uid) for p in protected]

    before = snapshot()
    if mode == 'tar':
        artifact = next(Path('/artifacts').glob('lablink-*-x86_64-linux.tar.gz'))
        source = Path(temp) / 'source'
        source.mkdir()
        with tarfile.open(artifact) as archive:
            archive.extractall(source, filter='data')
        package = next(source.iterdir())
        run([str(package / 'install.sh')])
        prefix = home / '.local'
        cli = prefix / 'bin/lablink'
        assert snapshot() == before, 'installation changed credentials/configuration'
        desktop = prefix / 'share/applications/lablink-gui.desktop'
        assert f'Exec={prefix}/bin/lablink-gui' in desktop.read_text()
        os.environ['PATH'] = f'{prefix}/bin:' + os.environ['PATH']
        assert run(['sh', '-c', 'command -v lablink']).stdout.strip() == str(cli)
    else:
        cli = Path('/usr/bin/lablink')
        desktop = Path('/usr/share/applications/lablink-gui.desktop')
        assert 'Exec=lablink-gui' in desktop.read_text()

    assert run([str(cli), 'version']).stdout.splitlines()[0] == f'{Path("/artifacts/BUILDINFO").read_text().splitlines()[0]} (commit {commit})'
    for name in ['lablink', 'lablinkd', 'lablink-gui']:
        binary = cli.with_name(name)
        assert binary.is_file() and os.access(binary, os.X_OK)
        assert not binary.stat().st_mode & 0o6022, 'unsafe packaged executable permissions'
        assert 'not found' not in run(['ldd', str(binary)]).stdout
    for command in ['status', 'devices', 'sites', 'site', 'inspect', 'discover', 'discovered',
                    'history', 'resolve', 'ssh', 'exec', 'trust', 'set', 'adopt', 'metrics',
                    'ping', 'doctor', 'check-config', 'init', 'version', 'copy-id', 'export',
                    'import', 'support-bundle', 'install-service', 'uninstall-service',
                    'completions', 'install-completions', 'onboard-ssh']:
        run([str(cli), command, '--help'])
    status = subprocess.run([str(cli), 'status', '--json'], capture_output=True, text=True)
    assert status.returncode == 3 and 'daemon_unavailable' in status.stdout
    for binary in [cli, cli.with_name('lablink-gui')]:
        # No terminal input capture and no onboarding interaction.
        gui = subprocess.Popen([str(binary)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 15
            while True:
                window = subprocess.run(['xdotool', 'search', '--pid', str(gui.pid), '--name', '^LabLink$'],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                if window.returncode == 0:
                    break
                assert gui.poll() is None, 'GUI exited before opening a window'
                assert time.monotonic() < deadline, 'GUI did not open a window'
                time.sleep(0.1)
            assert Path(f'/proc/{gui.pid}/exe').resolve().name == 'lablink-gui'
        finally:
            if gui.poll() is None:
                gui.terminate()
            gui.wait(timeout=5)
    assert snapshot() == before, 'launch checks changed credentials/configuration'
    if mode == 'tar':
        run([str(package / 'uninstall.sh')])
        assert all(not cli.with_name(n).exists() for n in ['lablink', 'lablinkd', 'lablink-gui'])
        assert not desktop.exists()
        assert snapshot() == before, 'uninstall changed credentials/configuration or host pins'
    print(f'PASS {mode}: packaged commit, binaries, permissions, dependencies, all CLI help, '
          'bare lablink GUI, alternative GUI, credential/configuration preservation'
          + (', safe uninstall' if mode == 'tar' else ''))
