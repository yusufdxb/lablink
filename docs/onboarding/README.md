# Secure GUI SSH onboarding

Select **Connect securely…** beside a discovered device, or **Connect by IP address…**. Choose the active site and SSH username, independently verify every displayed fingerprint, and explicitly confirm identity. LabLink then opens a real terminal for system OpenSSH to install the selected public key and test a fresh key-only connection. SSH passwords and private-key passphrases are entered directly into OpenSSH. Missing keys require consent before OpenSSH creates a new key in a fresh private folder.

After success, choose a friendly display name. The GUI prominently shows that name, along with the stable logical identifier allocated during preparation. The displayed `site/device` reference remains available for CLI use. Sites are separate: onboarding uses the explicitly selected active site and never replaces an existing host identity.

- [Security review](SECURITY-REVIEW.md)
- [Test results and coverage limits](TEST-RESULTS.md)
- [GUI screenshots](screenshots/README.md)

To work on onboarding, build with `cargo build -p lablink-cli -p lablink-gui -p lablink-daemon`. Keep the built `lablink` beside `lablink-gui`; onboarding deliberately does not fall back to an unrelated installed CLI when the development CLI is absent. The isolated test and screenshot harnesses exercise the flow locally without contacting an installed LabLink or real devices. The helper is an internal CLI command, hidden from normal help.
