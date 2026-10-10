# LabLink tests

Run everything with `cargo test --workspace --locked` (305 tests, 1 ignored
soak test). No test needs a robot, a lab network, root or a running LabLink:
every test uses temporary HOME, XDG, state and socket directories, and none
touches the machine's network configuration or its systemd user manager.

Kinds:

- **unit**: pure logic, no I/O beyond memory.
- **integration (simulated)**: complete daemons (real Unix socket, real SQLite,
  real task structure) run in-process against `lablink_daemon::testing::FakeNet`,
  a deterministic simulated network behind the `Prober` trait, including
  simulated gateways, gateway MACs and Wi-Fi SSIDs for site detection.
- **localhost**: touches this machine only (loopback sockets, the kernel's
  netlink tables, `/proc/net`, `ssh-keygen`, `/bin/sh`).

| Crate | Kind | Tests | What they cover |
|---|---|---|---|
| lablink-core | unit | 90 | sites: migration of the single-site layout to site `default`, mixing old and new layouts refused, two-site validation, `site/name` references, invalid site ids, names, interfaces and SSIDs; site detection: evidence strengths (host key on the site's own network, gateway MAC, device MACs, subnet, gateway IP, SSID and interface hints, a different gateway MAC counting against), confidence, ACTIVE / AWAY / UNKNOWN decisions, ties, manual override, scan permission; profiles and capabilities, explanations for every non-GREEN state (security stop never suggests SSH, AWAY suggests switching site), YAML writer round trip, the shipped example config, CIDR parsing, allowlist, /8 /12 /16 and public-range rejection, attachment rule, config validation (unknown keys, duplicates within a site, malformed YAML with line numbers, ssh options and binaries that could weaken checks, oversized files), hysteresis, port debounce, identity classification, color rules (AWAY is GRAY, mismatch always RED), IPC wire format and tolerance of missing params, client-side socket peer check |
| lablink-ssh | unit | 19 | copy-id uses the pinned options and refuses unpinned targets, host-key options first and extras cannot weaken them, exec is BatchMode with the command as one argument, ProxyCommand through a pinned gateway, exit-code preservation, timeout kills the process group, 16 MiB capture cap, ssh failure classification, login probe and exec share identity options |
| lablink-ssh | localhost | 2 | fingerprints equal `ssh-keygen -lf` for ed25519/ecdsa/rsa; known_hosts lookups through hashed entries and `[host]:port` |
| lablink-platform | unit | 3 | `/proc/net/route` default gateways, `/proc/net/arp` parsing, no SSID for a wired or nonexistent interface |
| lablink-discovery | unit + localhost | 11 | netlink parsing incl. truncated/garbage input, a real kernel netlink dump, TCP open/refused/timeout on loopback, unprivileged ICMP to loopback (skips if not permitted), bounded sweep concurrency, cancellation |
| lablink-daemon | unit + localhost | 13 | SQLite roundtrip, corrupt and truncated database recovery, retention, /proc stats, gateway probe snippet run in a real `sh`, ssh/exec refused through an unverified gateway, MISMATCH survives losing the address, symlinked socket directory refused |
| lablink-daemon | integration (simulated) | 25 (+1 soak, ignored) | adopt never pins; located/verified/GREEN; IP change found by scan + host key; host-key mismatch RED and never accepted; intermittent loss never OFFLINE; history records transitions only; restart restores identity and history; corrupt cache; graceful shutdown; second daemon refused; no runaway tasks or fds; scans only touch allowlisted attached networks; reassigned DHCP addresses; password-only server YELLOW; explicit trust incl. key change between preview and confirm; malformed/oversized IPC requests; gateways |
| lablink-daemon | integration (simulated) | 6 (sites) | the other site is AWAY, never probed and never a failure; manual override and return to Auto; the same name at two sites and ambiguity errors; gateway MAC evidence and a changed gateway MAC; a host-key tie resolved by learning; migration of a single-site cache (bare device keys become `default/<name>`) |
| lablink-cli | unit | 14 | table alignment with ANSI codes, completion candidates |
| lablink-cli | integration (simulated + localhost) | 28 (cli 11, complete 6, setup 7, sites 4) | the real `lablink` binary against an in-process daemon and a fake `ssh`: exit codes 0/3/4/5/6/7/8/10/11/12/124, JSON error shape, status JSON keys, exec passthrough, pinned host-key arguments, timeouts, offline/mismatch refused before ssh starts; `init` from empty dirs (never selects a network by itself, refuses public/oversized scans); export/import without secrets (pins and commands dropped by default); `sites`, `site use/add/rename`, `--site`/`--all`, AWAY refusal with the switch command, ambiguous names (exit 8) and `site/name` completion |
| lablink-gui | unit | 29 | wizard selects nothing by default and scans only with both ticks on an allowed range, settings and site management validation, device-edit diffs, adopt form (site choice), lifecycle steps, terminal argument shapes, color/indicator mapping, worker JSON shapes against a fake socket |
| lablink-doctor | unit | 17 | check planning, script generation and parsing, verdict and exit codes (AWAY devices ignored), network-only devices, profile check selection, site scope |
| lablink-setup | unit + localhost | 23 | interface classification with the daemon scan rule, config writes (0700 directory, 0600 exclusive temp file, validate, backup, atomic), init with a site and merging a site into an existing config, export/import hardening, support-bundle redaction (adversarial: IPv4/IPv6, MACs, fingerprints, `.local` names, home paths, tokens, names inside dotted host-key aliases), the bundle never clobbers files, the packaged unit equals the generated one, service actions refused when the systemd user manager belongs to another configuration |

## Security regression tests

Every confirmed security issue has a deterministic test that failed before
its fix. Run them all with the normal suite, or by area:

```bash
cargo test --workspace --locked                                  # everything
cargo test -p lablink-daemon --test identity_attacks             # LAN identity attacks
cargo test -p lablink-ssh --test openssh_tools                   # against real OpenSSH (sshd, ssh-keygen; skipped if absent)
cargo test -p lablink-cli --test cli unpinned                    # no TOFU behind the user's back
```

| Area | Tests |
|---|---|
| Authentication and credentials | `key_proof_sends_no_credentials_and_never_multiplexes`, `key_proof_against_a_real_sshd` (throwaway sshd on 127.0.0.1; no auth attempt in its log), `auth_probe_never_creates_master` (no agent/X11/port forwarding), `copy_id_uses_the_pinned_options_and_refuses_unpinned`, clean-room "password isolation" |
| Trust and identity | `replayed_public_key_is_never_verified`, `replayed_host_key_fails_the_possession_proof`, `key_proof_needs_openssh_s_own_denial_line`, `forged_mdns_cannot_move_a_verified_pinned_device`, `contradicting_key_at_a_name_claimed_address_is_a_mismatch`, `key_verified_sighting_displaces_a_squatter`, `forged_mdns_cannot_import_an_ip_keyed_known_hosts_entry`, `known_hosts_entry_keyed_by_ip_alone_is_not_enough_for_a_history_only_address`, `revoked_key_is_never_taken_from_another_line`, `host_key_mismatch_is_red_and_never_accepted`, `trust_requires_confirmation_when_not_interactive`, `unpinned_devices_need_trust_or_an_explicit_opt_in` |
| Discovery and sites | `name_answers_cannot_point_outside_the_lab_or_inject_names`, `a_foreign_device_mac_cannot_flip_the_site`, `fuzz_parse_datagram` (50,000 netlink datagrams), `fuzz_keyscan_and_known_hosts_parsers` (20,000), `active_scans_only_touch_allowlisted_attached_networks`, `ambiguous_name_is_refused_until_one_site_is_confident` |
| Configuration, import, filesystem | `code_loading_forwarding_and_env_options_rejected`, `import_never_takes_ssh_options_even_with_replace`, `imported_checks_are_listed_with_their_parameters`, `deeply_nested_yaml_is_refused_quickly`, `notes_with_terminal_escapes_are_refused`, `fuzz_import_parse_and_plan` (5,000 hostile files), `config_is_private_and_a_planted_temp_symlink_is_not_followed` (and private backups), `socket_directory_is_created_private_and_must_be_a_directory`, `symlinked_socket_directory_is_refused`, `adversarial_bundle_leaks_nothing` |
| Commands | `exec_is_batch_and_command_is_single_argument`, `verified_device_pins_host_key_first`, `ssh_binaries_and_options_cannot_inject`, `exec_start_is_one_quoted_word_and_never_a_new_directive`, `proxy_command_escapes_percent_outside_the_tokens`, `control_characters_are_shown_not_executed` |
| Release | clean-room steps "artifacts" (SHA256SUMS), "package privileges", "hostile import", "other local user", "remove .deb", tarball install/uninstall; CI jobs `dependencies` (cargo-deny, cargo-audit) and `secrets` (gitleaks); two `scripts/release.sh` runs with identical `SHA256SUMS` |

Static and dependency scans used before a release (containers, nothing
installed on the host):

```bash
cargo deny check && cargo audit --deny warnings
docker run --rm -v "$PWD":/src:ro ghcr.io/google/osv-scanner:v1.9.2 --lockfile /src/Cargo.lock
docker run --rm -v "$PWD":/src:ro -w /src semgrep/semgrep:1.99.0 semgrep scan --metrics=off \
    --config p/rust --config p/secrets --config p/github-actions --config p/command-injection
docker run --rm -v "$PWD":/repo:ro zricethezav/gitleaks:v8.21.2 git /repo --log-opts=--all --config /repo/.gitleaks.toml
docker run --rm -v "$PWD":/repo:ro -w /repo rhysd/actionlint:1.7.7
```

A clean scan does not prove the absence of vulnerabilities; it only rules
out the classes those tools know.

Soak tests (not run by default):

```bash
# simulated churn (devices appear/disappear, IP changes, SSH flaps, discovery)
LABLINK_SOAK_SECS=600 cargo test -p lablink-daemon --release --test daemon soak -- --ignored --nocapture
# real network, idle: samples resource usage every 60 s
scripts/soak.sh ~/.config/lablink/config.yaml /tmp/lablink-soak 1800 60
```

## Clean-room install test (`scripts/cleanroom.sh`)

A reproducible fresh-user run of the release artifacts, no lab hardware.
`scripts/release.sh` builds `dist/`; then

```bash
BASE=ubuntu:20.04 scripts/cleanroom.sh OUT_DIR   # also ubuntu:22.04, ubuntu:24.04
```

starts privileged containers on three private Docker networks:

- **desktop**: Ubuntu `$BASE` with systemd and a user `tester`. No Rust, no
  LabLink, no SSH client. Xvfb, xdotool and xwd only drive and capture the GUI.
- **robot-a** (network A, Site Alpha) and **robot-b** (network B, Site Beta):
  OpenSSH servers with their own host keys (user `robot`, password used once
  by `copy-id`).

Every step is recorded as PASS/FAIL with evidence in `OUT_DIR/results.md`;
any FAIL makes the script exit non-zero.

1. artifacts: `SHA256SUMS` verifies, `BUILDINFO` version and commit
2. fresh machine: no `cargo`, `rustc`, `ssh` or `lablink`
3. `apt install ./lablink_*.deb` (pulls the OpenSSH client); version and
   commit, user unit, desktop entry, icon, completion, copyright
4. GUI with no config shows the setup wizard (screenshot)
5. `lablink init` answered on stdin: site name, network by number, active
   scanning, service, completion
6. systemd user service active; `lablink ping`; shell completion
7. site detection: the only site is ACTIVE
8. `lablink discover`, `adopt`, `trust` (preview pins nothing, fingerprint
   compared with `ssh-keygen -lf` on the robot, then `--yes`)
9. YELLOW authentication explanation; `copy-id` (password via
   `SSH_ASKPASS`); GREEN; `exec` (output, exit code) and interactive `ssh`
10. `lablink doctor`; GUI screenshots of the managed device
11. `export` / `import` (no secrets), `support-bundle` (no addresses, MACs,
    fingerprints, user or device names)
12. two sites: the desktop moves from network A to network B; Site Alpha is
    AWAY (GRAY, exit 12, `exec` refused with exit 5, never probed), `site add` creates Site Beta and Auto
    selects it from network signals; active scanning only on the active
    site's network; the same device name at both sites; ambiguous names
    (exit 8, both candidates listed) and `site/name` references; manual
    override with `site use` and back to Auto; moving back to network A makes
    Site Alpha ACTIVE again; GUI site header and All Sites view
13. security stop: robot-a's host keys are regenerated; RED MISMATCH;
    `exec` and `ssh` refused with exit 6
14. daemon RSS and threads after the run
15. `apt remove`: binaries gone, configuration and pinned keys kept
16. GUI only, a second fresh user: wizard (nothing preselected), Discover,
    Inspect/Adopt, Trust (explicit pin), SSH Setup in a terminal, robot GREEN,
    all by clicks and keystrokes; verified through the CLI afterwards
17. tarball, a third fresh user without root: checksum, `./install.sh` into
    `~/.local`, `init`, daemon, discover; `./uninstall.sh` keeps user data,
    `./uninstall.sh --purge` removes it

The GUI steps click fixed coordinates in a 900x700 window; a layout change
can make them miss, which shows up as a FAIL with the screenshots to look at.
CI runs the same script on Ubuntu 20.04, 22.04 and 24.04
(`.github/workflows/ci.yml`, job `cleanroom`).

Clean-room output contains the containers' host-key fingerprints and the
Docker host's bridge address; keep it out of the repository.
