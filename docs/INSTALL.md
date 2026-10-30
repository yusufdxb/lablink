# Installing LabLink

## One-command installation

Supported: **Ubuntu 20.04, 22.04 and 24.04 LTS on x86_64 (AMD64)**.
ARM64/aarch64, other architectures and other Linux distributions are not
supported by this installer. No Rust, Cargo, Git or GitHub CLI is required.

Open a terminal as your normal user and paste:

```bash
curl -fsSL https://raw.githubusercontent.com/yusufdxb/lablink/main/scripts/install-linux.sh | bash
```

Then complete the supported onboarding process:

```bash
lablink init
lablink doctor
lablink status
```

Desktop users can open **LabLink** from their applications menu.

The installer downloads the selected official release's `.deb` and
`SHA256SUMS` directly from GitHub Releases over HTTPS. It requires exactly
one valid checksum entry for the selected package and verifies it before
installation. A missing or mismatched checksum stops installation. The
initial selected release is **v0.3.1**, a prerelease; the installer selects
that tag explicitly rather than using GitHub's latest-release endpoint.
Maintainers can select future releases without changing the command above.

Only the local package installation uses administrator privileges, through
`sudo apt install`; never run the whole installer with `sudo` or as root.
APT installs the OpenSSH client and the X11/Wayland/OpenGL libraries required
by the desktop app. The installer uses a private temporary directory and
removes its downloads on exit, including on ordinary interruption.

Installation does not initialize sites, scan networks, change SSH trust,
start or restart services, or replace configuration, SSH keys, pinned host
fingerprints or device records. `lablink init` is the explicit next step.

## Verify the installation

The installer verifies all three packaged executables. You can also check:

```bash
command -v lablink lablinkd lablink-gui
lablink version
lablinkd --version
dpkg-query -W -f='${Version}\n' lablink
```

`lablink version` reports the version and source commit. The packaged
executables are `/usr/bin/lablink`, `/usr/bin/lablinkd` and
`/usr/bin/lablink-gui`.

The v0.3.1 desktop app does not have a `--version` or `--help` mode. The
installer verifies that its executable and shared libraries load without
opening a window or entering onboarding. To verify the graphical interface,
open **LabLink** from the applications menu, or run `lablink-gui` in a desktop
terminal. A working X11 or Wayland session is required to display the app.

The package also installs:

| Path | What |
|---|---|
| `/usr/lib/systemd/user/lablinkd.service` | systemd user unit |
| `/usr/share/bash-completion/completions/lablink` | Bash completion |
| `/usr/share/applications/lablink-gui.desktop` | Applications menu entry |
| `/usr/share/icons/hicolor/scalable/apps/lablink.svg` | App icon |
| `/usr/share/doc/lablink/` | License, notices, README and example config |

## Upgrading an existing installation

Run the same one-command installer again. An older package is upgraded to
the selected release. A matching version is verified without reinstalling;
a newer installed package is retained rather than downgraded. Configuration
and state remain in your home directory.

If your daemon was already running, explicitly restart it after an upgrade:

```bash
systemctl --user restart lablinkd
lablink version
```

The installer does not restart it for you. An old daemon can remain running
after a package upgrade; security-sensitive commands may refuse to use it
until you restart it.

For a previous tarball or source installation, check `type -a lablink
lablinkd lablink-gui`. An executable in `~/.local/bin` can take precedence
over `/usr/bin`. The installer reports this instead of deleting or replacing
your existing installation. Use that installation's supported uninstaller,
keeping configuration and state, then rerun the one-command installer.

## Uninstallation

For an installation made by the one-command installer or a manual `.deb`:

```bash
systemctl --user disable --now lablinkd
sudo apt remove lablink
```

If no service was enabled, the first command may report that no unit exists;
you can still remove the package. Removal stops packaged daemon processes
and removes program files. `sudo apt purge lablink` also keeps files in
users' home directories.

Configuration and device records remain available for a later reinstall.
Only if you explicitly want to discard your LabLink sites, devices, history
and pinned fingerprints, delete your user data after removal:

```bash
rm -rf ~/.config/lablink ~/.local/state/lablink
```

If you use custom XDG locations or the overrides below, those locations must
be handled separately. Do not remove `~/.ssh`; it contains your SSH keys and
OpenSSH configuration.

## Troubleshooting

- **`curl: command not found` or missing prerequisites:** install the named
  Ubuntu packages, then rerun the command. For a minimal Ubuntu system:
  `sudo apt update && sudo apt install curl ca-certificates sudo coreutils gawk`.
  Bash, APT and dpkg must also be available. Ubuntu desktop installations
  normally already include these utilities.
- **Unsupported OS or architecture:** check `cat /etc/os-release` and
  `uname -m`. The installer accepts only the Ubuntu LTS versions and AMD64
  architecture listed above. It does not install the AMD64 package on ARM64.
- **Download error or missing release asset:** check your network, proxy and
  access to `github.com` and GitHub release download hosts, then retry. The
  installer reports the failed URL. Do not bypass TLS verification.
- **Checksum missing or mismatched:** installation is stopped. Retry with a
  fresh download. If the error persists, report it to the project; never
  install the unverified package or disable the verification.
- **APT dependency or package-index errors:** run `sudo apt update`, resolve
  the reported Ubuntu package error, and rerun the installer. APT may need
  Internet access to Ubuntu mirrors as well as GitHub.
- **APT lock held:** wait for the other package manager or unattended update
  to finish, then retry. Do not delete package-manager lock files.
- **Missing packaged executable:** follow the manual Debian package download
  and verification steps below, using `sudo apt install --reinstall
  ./lablink_0.3.1_amd64.deb` for the final command. There is no LabLink APT
  repository from which APT can download a replacement by package name.
- **Interrupted installation:** downloads are cleaned up on ordinary
  interruption. If APT reports an interrupted dpkg transaction, follow its
  recovery instruction, usually `sudo dpkg --configure -a`, then rerun the
  installer. SIGKILL or power loss cannot run shell cleanup handlers.
- **Wrong version on PATH:** inspect `type -a lablink lablinkd lablink-gui`
  and compare `/usr/bin/lablink version`. Resolve older user-installed
  executables before rerunning the installer, then run `hash -r` in an
  existing shell.
- **`doctor` or `status` says the daemon is unavailable:** finish `lablink
  init` in your normal user session. Installation alone does not start it.
- **Desktop app does not open:** launch `lablink-gui` in a desktop terminal
  to see the error. Headless SSH sessions have no graphical display. The
  installer checks library loading, not your display server or GPU driver.

## Manual installation alternatives

The [v0.3.1 release](https://github.com/yusufdxb/lablink/releases/tag/v0.3.1)
contains `lablink_0.3.1_amd64.deb`,
`lablink-0.3.1-x86_64-linux.tar.gz`, `SHA256SUMS`, `BUILDINFO` and
`lablink-0.3.1.cdx.json` (the software bill of materials).
These alternatives require downloading and verifying files yourself.

### Manual Debian package

This example uses a new download directory, retrieves the official package
and checksum manifest, and verifies the specific package before invoking
APT. Run the block as Bash:

```bash
(
    set -eu
    download_dir=$(mktemp -d)
    trap 'rm -rf "$download_dir"' EXIT
    cd "$download_dir"
    release=https://github.com/yusufdxb/lablink/releases/download/v0.3.1
    curl -fSL --proto '=https' --proto-redir '=https' -O "$release/lablink_0.3.1_amd64.deb"
    curl -fSL --proto '=https' --proto-redir '=https' -O "$release/SHA256SUMS"
    awk '$2 == "lablink_0.3.1_amd64.deb" || $2 == "./lablink_0.3.1_amd64.deb"' SHA256SUMS > package.sha256
    test "$(wc -l < package.sha256)" -eq 1
    sha256sum --check --strict package.sha256
    sudo apt install ./lablink_0.3.1_amd64.deb
)
```

Then run `lablink init`.

### Tarball without root

The tarball needs x86_64 Linux with glibc 2.31 or newer and the runtime
libraries listed above. Only the three listed Ubuntu releases are qualified.
Dependencies must already be installed; the tarball does not ask APT to
install them. Run the block as Bash:

```bash
(
    set -eu
    download_dir=$(mktemp -d)
    cd "$download_dir"
    release=https://github.com/yusufdxb/lablink/releases/download/v0.3.1
    curl -fSL --proto '=https' --proto-redir '=https' -O "$release/lablink-0.3.1-x86_64-linux.tar.gz"
    curl -fSL --proto '=https' --proto-redir '=https' -O "$release/SHA256SUMS"
    awk '$2 == "lablink-0.3.1-x86_64-linux.tar.gz" || $2 == "./lablink-0.3.1-x86_64-linux.tar.gz"' SHA256SUMS > package.sha256
    test "$(wc -l < package.sha256)" -eq 1
    sha256sum --check --strict package.sha256
    tar xzf lablink-0.3.1-x86_64-linux.tar.gz
    cd lablink-0.3.1-x86_64-linux
    ./install.sh
    printf 'Keep this directory for uninstalling: %s\n' "$PWD"
)
```

This copies binaries into `~/.local/bin`, and the menu entry, icon and Bash
completion into `~/.local/share`. Ensure `~/.local/bin` is on your PATH, then
run `lablink init`. Keep the printed extracted directory; run its
`./uninstall.sh` to remove the installation while retaining your data, or
`./uninstall.sh --purge` to remove your LabLink configuration and state too.

`lablink init` creates a systemd user unit for the tarball daemon. If the
`.deb` is also installed, it uses the packaged `/usr/bin/lablinkd` unit
instead; run `lablink init` again after removing the package to switch to
the tarball daemon.

### Optional provenance verification

For advanced verification with the GitHub CLI, before installation run this
in the directory containing the downloaded `.deb`:

```bash
gh attestation verify lablink_0.3.1_amd64.deb --repo yusufdxb/lablink \
    --signer-workflow yusufdxb/lablink/.github/workflows/ci.yml \
    --source-ref refs/tags/v0.3.1 --deny-self-hosted-runners
```

This checks that the package was built by the project's CI from the tagged
commit. The one-command installer uses the release's SHA-256 manifest and
does not require GitHub CLI or perform this optional attestation check.
See [RELEASING.md](RELEASING.md) for the build and verification process.

## Files LabLink uses

| Path | Contents |
|---|---|
| `~/.config/lablink/config.yaml` | Sites, networks, devices, checks and preferences (0600) |
| `~/.local/state/lablink/` (0700) | Device records, history, site mode and pinned `known_hosts` |
| `$XDG_RUNTIME_DIR/lablink/lablinkd.sock` | Daemon socket (0600 in a 0700 directory) |

`LABLINK_CONFIG`, `LABLINK_STATE_DIR` and `LABLINK_SOCKET` override these
locations. The installer does not read or rewrite them. Single-site
configurations from earlier builds are read as site `default`, and their
cache is migrated when the daemon next starts.

## Building from source

Building is an advanced alternative, not required for installation:

```bash
git clone https://github.com/yusufdxb/lablink.git
cd lablink
cargo build --release --workspace --locked
```

Binaries are written to `target/release/`. Release artifacts are built by
`scripts/release.sh` in the pinned Ubuntu 20.04 build container. It takes a
clean archive of the committed HEAD, enforces the glibc 2.31 baseline, and
writes `dist/`; see [RELEASING.md](RELEASING.md).
