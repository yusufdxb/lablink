# Testing on Ubuntu 24.04 radar

**Approval gate:** radar work requires Yusuf's explicit approval. On 2026-10-10 Yusuf approved replacing radar's per-user LabLink installation and checking its launchers/CLI, while leaving onboarding unconfigured. That approval does not authorize changing SSH credentials, production devices, unrelated services or installing test prerequisites. Installed LabLink on mewtwo remains untouched. The fixture procedure below is separate from deployment verification.

1. After approval, use LabLink first: `lablink doctor --json`, then `lablink status radar --json`. If radar is not known, use `lablink discover` and `lablink discovered`. Use the resolved LabLink identity and approved `lablink exec radar`/`lablink ssh radar` path. Do not guess an address or bypass an identity-security failure.
2. Use a separate development directory/account and this branch, `feature/gui-ssh-onboarding`. Keep the CLI and GUI together in the build output. For fixture testing, do not install packages, replace `/usr/bin` binaries, restart the installed daemon or change existing SSH credentials. Check that the Rust version pinned in `rust-toolchain.toml`, OpenSSH client/server, GNOME Terminal, Xvfb, D-Bus and xdotool are already available. Pillow is needed only for screenshots. Missing prerequisites require separate approval to install.
3. Set Cargo build/cache locations inside the development directory if needed. Build and run locally in that directory:

   ```bash
   cargo build -p lablink-cli -p lablink-gui -p lablink-daemon
   cargo test --workspace
   cargo clippy --workspace --all-targets -- -D warnings
   xvfb-run -a dbus-run-session -- python3 scripts/test-onboarding-terminal.py
   xvfb-run -a -s '-screen 0 1280x900x24' dbus-run-session -- python3 scripts/capture-onboarding-gui.py
   ```

   The terminal/screenshot harnesses create their own temporary HOME, config, socket, host/client keys and localhost sshd. They use a fixture IPC server; they do not contact the installed daemon or production devices. The real terminal test's fixed remote fixture only appends to a temporary authorized_keys file. Do not record or automate password entry.
4. For real **manual** password and encrypted-key tests, provision an approved disposable SSH test account/container with its own home, keys and test password. This provisioning needs explicit authorization if it changes radar or requires privileges. Run a separate development daemon/GUI with absolute `LABLINK_CONFIG`, `LABLINK_STATE_DIR`, `LABLINK_SOCKET` and an isolated HOME; never point them at production state. Keep this fixture's site as Carebear and CARES Lab as a separate away site. Never use a real production device as the onboarding target.
5. Independently obtain the fixture server's public host-key fingerprints from its console. Discover/select it or enter its private attached IPv4 address. Enter the test SSH username, compare every fingerprint, and confirm. Confirm that the GUI has no password field and cannot continue without independent identity approval.
6. Type the disposable SSH password **directly into the OpenSSH terminal prompt**. Verify installation and fresh key-only testing, then choose a friendly display name. Confirm the device is online/verified at the selected site and that CARES Lab state, credentials and pins did not change. Try `lablink --socket ABSOLUTE_TEST_SOCKET ssh SITE/DEVICE` using the displayed stable reference.
7. Repeat manually with an incorrect password, incorrect username, terminal closure, GUI cancellation, unavailable server and password-login-disabled server. Retry should retain valid pins/keys without changing the account's existing SSH configuration. Error output stays in the terminal; no terminal recording or keystroke capture is permitted.
8. Test an existing key, missing key without consent, consented new key, and an encrypted private key. OpenSSH should prompt for passphrases itself. Check new folder `0700`, private key `0600`, and byte-for-byte preservation of existing keys. Reopen the authentication step after failure and check that the just-created key is reused.
9. Replace only the **disposable fixture** host key. Onboarding and the resulting SSH connection must reject it. A new-key trust preview must show a security stop and cannot replace existing pins. Also test hostile usernames, addresses, names and shell-sensitive paths; they must be rejected without command execution.
10. Inspect only LabLink's test state/logs for the known disposable test password (without printing its value). It must not occur. Review recorded IPC metadata and verify it contains only site/device references, usernames, public fingerprints, key paths, consent and settings. Delete the isolated fixture resources afterwards; preserve the review/test report. Do not push or publish artifacts.

An encrypted-key connection may be verified and online while its unattended auth check remains yellow until the user unlocks that key in an existing agent. LabLink never stores the passphrase or enables forwarding to make this pass.
