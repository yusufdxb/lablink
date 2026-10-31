# GUI SSH onboarding security review

This is the maintainers' implementation review of GUI onboarding for LabLink 0.4.0. It is not a third-party audit; independent review is welcome (see [SECURITY.md](../../SECURITY.md)). The controls below were validated with local fixtures and real OpenSSH, not on production devices.

## Architecture and trust boundary

The GUI selects a site and an IP/discovered device, records a validated SSH username, and uses daemon `Adopt`, `Trust` preview and confirmed `Trust` requests. The user must explicitly confirm that **every** fingerprint was independently verified. First use and existing trust both require confirmation. Onboarding never sends `replace: true`. A conflicting existing pin blocks this flow. The existing administrative replacement flow remains available outside onboarding, with its explicit independent-verification requirement.

An internal `lablink onboard-ssh --session PATH` helper runs as the foreground process of a real terminal. GNOME Terminal uses `--wait`; Konsole uses `--nofork`; xterm stays attached to its child. The GUI follows the helper's typed result rather than interpreting the emulator's exit status as SSH success. Unknown terminal argument conventions are refused for onboarding.

Each attempt has a fresh, user-owned `0700` session directory with `0600` request/status files. Requests contain a site-qualified device reference, username, approved public fingerprints, selected key path and generation consent. Unknown JSON fields are rejected. Status files contain an enum; they have no free-text authentication output or password field. A claim file prevents concurrent use of one session. Session metadata is removed after the terminal exits.

Immediately before authentication, the helper resolves the exact site-qualified device, refuses an away site, changed username, identity mismatch or gateway route, and compares the daemon's managed host-key entries with the approved fingerprints. It creates a private snapshot containing precisely those pins. All authentication and connection testing use that snapshot and alias, `StrictHostKeyChecking=yes`, `UpdateHostKeys=no`, no global host-key sources, no DNS trust and no `KnownHostsCommand`. OpenSSH performs the actual host-signature verification before receiving authentication credentials.

Implementation: [terminal helper](../../crates/lablink-setup/src/onboarding.rs), [GUI wizard](../../crates/lablink-gui/src/onboarding.rs), [terminal launcher](../../crates/lablink-gui/src/term.rs), [copy-id arguments](../../crates/lablink-ssh/src/command.rs), and [daemon identity persistence](../../crates/lablink-daemon/src/registry.rs).

## Verified controls

| Risk | Implemented control | Evidence |
| --- | --- | --- |
| Password/passphrase collection | No GUI password field. Helper does not read stdin or terminal streams. OpenSSH children inherit all terminal descriptors. Askpass is disabled. | `lablink-setup/src/onboarding.rs`, terminal fixtures and enum/schema tests |
| Automatic first-use trust | Independent-verification checkbox gates both first-use and existing-key confirmation. Exact approved fingerprints go to daemon's existing fresh-scan trust operation. | GUI confirmation tests; existing trust integration tests |
| Pin replacement or drift | No replacement in onboarding. Snapshot compares exact approved fingerprints; later changes to the live pin file cannot broaden the session's trust. | Changed-pins, live-pin-change and real OpenSSH mismatch tests |
| Shell/option injection | Program and arguments are separate. Username, device/site, IP, host alias and key paths are validated. Shell-sensitive key paths are rejected because system `ssh-copy-id` internally evaluates its public-key path. | Hostile-input tests; terminal argument-vector test |
| SSH connection reuse | Copy-id and the test disable ControlMaster/ControlPath. Onboarded device resolution also disables connection sharing for subsequent LabLink connections. | Argument assertions; daemon persistence/scoping test |
| Agent/port/X11 forwarding | Setup and test force agent/X11 forwarding off, clear forwarding, and disallow local commands. Key test uses only the selected identity and no agent. | Argument assertions; real key test |
| Existing credential damage | Existing key pairs are read-only and require owner/private permissions. Generation requires explicit consent and uses a fresh random `0700` folder; OpenSSH creates its private key with `0600`. | Existing-key, generation-consent and permission tests |
| False success | Only successful copy-id **and** a fresh public-key-only OpenSSH `true` command produce Connected. The selected key is persisted only afterwards. | Real installation/test fixture; GUI transition tests |
| Cancellation/closure | GUI cancellation signals the helper through a private marker. The helper kills its verified foreground process group, including copy-id descendants. Terminal closure cannot be interpreted as success. | Real terminal cancellation/closure tests |
| Cross-site credential updates | All requests carry canonical `site/device`; preparation checks current active site and discovered host association. The site is locked once a device is tracked. | Existing multi-site suite and selected-identity persistence test |

The real terminal fixture uses actual OpenSSH tools, a disposable localhost sshd, temporary client/host keys, an isolated ssh-agent for bootstrap, and a fixed server-side command that maps installation to a temporary authorized_keys file. It never modifies the account's actual authorized_keys. Its server disables StrictModes solely because sshd rejects the `/tmp` ancestor of fixture authorized_keys; client host verification remains strict. No server/password automation is present.

## Findings addressed during implementation

- First-use GUI trust previously permitted pinning without the independent-verification checkbox. All GUI trust now requires that checkbox.
- Existing copy-id could inherit connection sharing or forwarding settings. It now forces a fresh connection with forwarding and local commands disabled.
- Newly generated key folders initially inherited the process umask. Real-terminal tests exposed this; the helper now explicitly sets `0700` and tests it.
- A successful terminal-emulator exit is insufficient evidence. Connected depends on the helper's terminal result after installation and key-only verification.

## Limits and remaining validation

- Real incorrect-password entry is **not** automated. Its OpenSSH failure status is tested with a fixture, and actual manual password/passphrase prompts need a manual test on a real machine. No claim is made that a real wrong-password test has already passed.
- The real-emulator suite currently exercises GNOME Terminal. Konsole and xterm argument construction is unit-tested; their rendered behavior remains unverified here.
- Manual discovery uses the existing daemon's one-address IPv4 scan policy: private, directly attached addresses only. Already discovered IPv6 hosts can use onboarding. Gateway onboarding is refused rather than weakening gateway identity handling.
- SSH and key paths containing whitespace, quoting, expansion or control characters are refused. This is intentional fail-closed behavior around OpenSSH syntax and the system copy-id script.
- Friendly names are display labels. A stable, site-qualified logical device identifier is allocated during preparation and remains the CLI reference. Interrupted setup leaves a tracked device, approved pins and any completed key generation for retry; it does not roll back a remotely appended public key.
- Encrypted private keys may require passphrase prompts again. An interactive test can succeed while the daemon's unattended batch check stays yellow until the user unlocks the selected key in their own agent. LabLink does not silently cache passphrases or add keys to an agent.
- Same-UID processes, administrator-controlled configuration/programs and independently verified fingerprints are trusted inputs. Another process already running as the user can access that user's terminal/keys outside LabLink's protection. Session files prevent other-user access, not same-user compromise.
- There is no transactional rollback of the remote authorized_keys append. A failed key test retains the appended public key and explains that retry is possible. Existing keys/pins are not overwritten.

