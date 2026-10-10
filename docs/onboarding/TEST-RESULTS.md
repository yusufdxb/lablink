# Local onboarding validation

Date: 2026-10-10. Branch: `feature/gui-ssh-onboarding`.

| Check | Result |
| --- | --- |
| `cargo test --workspace` | **344 passed, 0 failed, 1 ignored**. The ignored test is the pre-existing long-running daemon soak test. |
| `cargo clippy --workspace --all-targets -- -D warnings` | Passed, no warnings. |
| `cargo fmt --all -- --check` | Passed. |
| `git diff --check` | Passed. |
| GNOME Terminal + localhost OpenSSH suite | **13 passed**, 34.049 seconds. |
| Actual GUI workflow with fixture IPC and localhost OpenSSH | Passed through bare `lablink`, from discovered device through identity confirmation, key test, friendly naming and the verified device card at Carebear. CARES Lab remained away. |
| Bare-command/CLI regression | Paired GUI dispatch, socket argument without shell interpretation, GUI exit status, missing GUI error, all existing subcommand help and invalid-command handling passed. |

The terminal suite runs with `xvfb-run -a dbus-run-session -- python3 scripts/test-onboarding-terminal.py`. It covers real key installation and verification; wrong server key; approved/live pin drift; wrong username; password-login-disabled server; simulated wrong-password failure; cancellation; terminal closure; consented generation; missing consent; unsafe key permissions; and away-site/username checks. Tests never type, read, store or record an SSH password. The simulated wrong-password case checks OpenSSH's failure-result handling, not actual password authentication.

The GUI was exercised with `scripts/capture-onboarding-gui.py`. Screenshots are actual rendered egui frames, with disposable fixture data and a real localhost OpenSSH connection. The fixture server already authorized that screenshot test's temporary key, so its copy-id step checked/skipped the existing key; the separate terminal suite validates an actual append to the fixture authorized_keys. Screenshots contain no real lab addresses, credentials or hardware identities.

Unit tests cover independent confirmation, empty/conflicting pins, state transitions, retryable failures, cancellation on dialog drop, hostile usernames and paths, consent, protected sessions, password-field rejection, existing-key preservation, forwarding restrictions and public-key-only verification. A daemon integration test covers selected-key persistence across restart, canonical site scope and invalid-path rejection without changing pins. Existing identity-attack, SSH possession-proof and multi-site suites also passed.

`scripts/test-packaging.sh` verifies freshly built artifacts in disposable Ubuntu 24.04 containers: tarball installation/removal, Debian installation/removal, embedded commit, executable permissions, runtime dependencies, every CLI subcommand's help, bare `lablink` GUI launch, the alternative `lablink-gui` launcher, and preservation of existing credentials/configuration. Run after `scripts/release.sh`; deployment evidence records the resulting checks separately from this pre-build report.

GNOME's isolated D-Bus session emitted portal/FUSE warnings in this environment; all final terminal and GUI assertions passed. No production-device test, password/passphrase-entry test, Konsole runtime test or xterm runtime test is claimed. Radar installation and launcher checks have been explicitly approved; onboarding remains unconfigured there.
