# Local validation for 0.4.0

These are the checks run on a Linux development machine before the 0.4.0 release candidate. Each one runs locally against disposable fixtures. None of them is a hardware result.

| Check | Result |
| --- | --- |
| `cargo test --workspace` | **525 passed, 0 failed, 2 ignored**. The two ignored tests are the long-running daemon soak test and a subprocess fixture that its parent test invokes directly. |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed, no warnings. |
| `cargo fmt --all -- --check` | Passed. |
| `cargo deny check` and `cargo audit` | Passed. The three advisories that are ignored, and the reason for each, are listed in `.cargo/audit.toml`, `deny.toml` and the changelog. |
| GNOME Terminal + localhost OpenSSH suite | **13 passed**. |
| GUI workflow with fixture IPC and localhost OpenSSH | Passed. It runs from the discovered device through identity confirmation, the key test and friendly naming to the verified device card. Away sites stay away. |
| Installer tests (`scripts/test-install-linux.py`) | Passed. One test is skipped: the root-rejection check, which needs root or passwordless sudo. |
| Migration from a legacy install (`scripts/test-install-migration.sh`) | Passed in Ubuntu 20.04, 22.04 and 24.04 containers. |
| Packaging (`scripts/test-packaging.sh`) | Passed for the tarball and the Debian package. |
| Migration with a live systemd user bus (`scripts/test-install-userbus.sh`) | Passed in Ubuntu 20.04, 22.04 and 24.04 systemd containers. The 0.3-layout daemon is enabled and running under `systemctl --user` before `--migrate`; afterwards the packaged unit is enabled and active, its process runs `/usr/bin/lablinkd`, and the CLI reaches it. `restore.sh` then brings the old unit and binary back. This run found that `restore.sh` left the migration's own `default.target.wants` link behind and exited 1; fixed. |
| `shellcheck` 0.8.0 on the installer and its test scripts | No findings (`install-linux.sh`, `test-install-linux-containers.sh`, `test-install-migration.sh`, `test-install-userbus.sh`). Other helper scripts still carry style warnings. |
| Full clean room on Ubuntu 20.04 (`BASE=ubuntu:20.04 scripts/cleanroom.sh`) | **43 of 43 passed** (the binaries require glibc 2.30; 20.04 ships 2.31). |
| Clean-room GUI run (`GUI_ONLY=1 BASE=ubuntu:24.04 scripts/cleanroom.sh`) | **8 of 8 passed**. A new user in a fresh Ubuntu 24.04 container installs the `.deb` and does everything from the GUI: the setup wizard, discovery, explicit fingerprint confirmation, consented key creation, the password typed into OpenSSH's own prompt in xterm, a real login test that reaches GREEN, and a friendly name. Re-run on commit a1aca50 after the launcher change below: 8 of 8. |
| Same run with an encrypted key (`PASSPHRASE=... GUI_ONLY=1 BASE=ubuntu:24.04 scripts/cleanroom.sh`) | **9 of 9 passed**. The passphrase is typed only into OpenSSH's prompts. The GUI's key test reports Connected, but the daemon stays yellow until the key is in an agent that lablinkd can see: `ssh-add` plus `systemctl --user set-environment SSH_AUTH_SOCK=...` was not enough, a `systemctl --user restart lablinkd` was (then GREEN). See the security review's limits. |
| Same run in Konsole 23.08.5 (`TERM_APP=konsole GUI_ONLY=1 BASE=ubuntu:24.04 scripts/cleanroom.sh`) | **8 of 8 passed** on commit a1aca50: the password is typed into OpenSSH's prompt inside Konsole and the device reaches GREEN. The first Konsole run failed: Qt consumed the helper's `--session <path>` and Konsole started a plain shell. The launcher now passes `--session=<path>`. |

## How the onboarding checks run

The terminal suite runs with `xvfb-run -a dbus-run-session -- python3 scripts/test-onboarding-terminal.py`. It covers:

- real key installation and verification;
- a wrong server key;
- drift between the approved pin and the live pin;
- a wrong username;
- a server with password login disabled;
- a simulated wrong-password failure;
- cancellation and terminal closure;
- consented key generation and missing consent;
- unsafe key permissions;
- away-site and username checks.

The fixture daemon reports the same version as the build, because the CLI refuses an unversioned or mismatched daemon before it resolves or trusts anything. The tests never type, read, store or record an SSH password. The simulated wrong-password case checks how OpenSSH failure results are handled, not real password authentication.

The GUI was exercised with `scripts/capture-onboarding-gui.py`. The screenshots are real rendered egui frames of the LabLink window, using disposable fixture data and a real localhost OpenSSH connection. The fixture server had already authorized that run's temporary key, so the copy-id step detected the existing key and skipped it. The terminal suite separately verifies a real append to the fixture's `authorized_keys`. The screenshots contain no real addresses, credentials or hardware identities.

Unit tests cover:

- independent confirmation;
- empty and conflicting pins;
- state transitions and retryable failures;
- cancellation when the dialog is dropped;
- hostile usernames and paths;
- consent and protected sessions;
- rejection of the password field;
- preservation of an existing key;
- forwarding restrictions;
- public-key-only verification.

A daemon integration test covers three things: the selected key persists across a restart, sites are scoped canonically, and an invalid path is rejected without changing any pins. The existing identity-attack, SSH possession-proof and multi-site suites also pass.

`scripts/test-packaging.sh` checks freshly built artifacts in disposable Ubuntu 24.04 containers:

- installing and removing the tarball;
- installing and removing the Debian package;
- the embedded commit;
- executable permissions;
- runtime dependencies;
- the help output of every CLI subcommand;
- launching the GUI with a bare `lablink` and with the `lablink-gui` launcher;
- preserving existing credentials and configuration.

`scripts/test-install-migration.sh` installs a legacy layout, migrates it, and checks four things: configuration, state and pins are preserved; the backup is written; and the restore script returns the previous install.

## The clean-room GUI run

`scripts/cleanroom.sh` builds disposable systemd containers on private Docker networks: a desktop with Xvfb and a robot running OpenSSH with password login. The GUI is driven with `xdotool` and checked through the CLI after each step:

- the device identity stays unverified until the fingerprint box is ticked and confirmed;
- the pinned keys equal the robot's real host keys;
- no LabLink key exists before consent, and one exists after;
- the authentication terminal asks only for the new key's passphrase (empty by default) and then the robot's password, never a key filename;
- the device reaches GREEN with SSH authentication `ok`;
- the friendly name is saved.

The robot is a container, not hardware, and its password is a throwaway fixture value.

## Not covered

- No test on a production device or real hardware.
- A real wrong password typed at OpenSSH's prompt (only simulated).
- Whether a desktop session exports its SSH agent to the systemd user manager before lablinkd starts.
- No macOS build.

The isolated D-Bus session printed portal and FUSE warnings. All of the final terminal and GUI assertions still passed.
