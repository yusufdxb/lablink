# LabLink tests

Run everything with `cargo test --workspace --locked` (including an opt-in soak test). The ordinary suite needs no robot, lab network or running LabLink.
Additional foreign-user and kernel permission probes require root in a
disposable container (see below). All tests isolate state and socket
directories. The hostile SSH configuration
tests are opt-in and rewrite the test user's SSH config, so run them only in
disposable containers. Root-only foreign-user tests drop a child UID inside
the container; ordinary runs explicitly skip those probes. No test changes
network configuration or the systemd user manager.

Kinds:

- **unit**: pure logic, no I/O beyond memory.
- **integration (simulated)**: complete daemons (real Unix socket, real SQLite,
  real task structure) run in-process against `lablink_daemon::testing::FakeNet`,
  a deterministic simulated network behind the `Prober` trait, including
  simulated gateways, gateway MACs and Wi-Fi SSIDs for site detection.
- **localhost**: touches this machine only (loopback sockets, the kernel's
  netlink tables, `/proc/net`, `ssh-keygen`, `/bin/sh`).

| Crate | Kind | What they cover |
|---|---|---|
| lablink-core | unit | sites: migration of the single-site layout to site `default`, mixing old and new layouts refused, two-site validation, `site/name` references, invalid site ids, names, interfaces and SSIDs; site detection: evidence strengths (host key on the site's own network, gateway MAC, device MACs, subnet, gateway IP, SSID and interface hints, a different gateway MAC counting against), confidence, ACTIVE / AWAY / UNKNOWN decisions, ties, manual override, scan permission; profiles and capabilities, explanations for every non-GREEN state (security stop never suggests SSH, AWAY suggests switching site), YAML writer round trip, the shipped example config, CIDR parsing, allowlist, /8 /12 /16 and public-range rejection, attachment rule, config validation (unknown keys, duplicates within a site, malformed YAML with line numbers, ssh options and binaries that could weaken checks, oversized files), hysteresis, port debounce, identity classification, color rules (AWAY is GRAY, mismatch always RED), IPC wire format and tolerance of missing params, client-side socket peer check, default paths never in /tmp or relative to the current directory, files other users could change (POSIX ACLs included, and paths the kernel would refuse), programs never taken from relative `PATH` entries |
| lablink-ssh | unit | copy-id uses the pinned options and refuses unpinned targets, host-key options first and extras cannot weaken them, exec is BatchMode with the command as one argument, ProxyCommand through a pinned gateway, exit-code preservation, timeout kills the process group, 16 MiB capture cap, ssh failure classification, login probe and exec share identity options |
| lablink-ssh | localhost | fingerprints equal `ssh-keygen -lf` for ed25519/ecdsa/rsa; known_hosts lookups through hashed entries and `[host]:port`; the possession proof against a real `sshd`, directly and through a gateway: replayed public keys, printed text and exit codes, forged disconnects and KEXINIT offers never prove; a hostile `~/.ssh/config` cannot vouch for a key or turn a failure into a security stop (these two rewrite the real `~/.ssh/config`, so they run only with `LABLINK_TEST_HOSTILE_SSH_CONFIG=1`, in disposable containers) |
| lablink-ssh | localhost | the possession proof releases every descriptor and process it opened, even when the gateway command leaves a detached process behind |
| lablink-ssh | localhost | an `ssh` planted in the current directory is never run by `run_captured`, the possession proof or a gateway hop's shell, with `.` and empty `PATH` entries first |
| lablink-platform | unit | `/proc/net/route` default gateways, `/proc/net/arp` parsing, no SSID for a wired or nonexistent interface |
| lablink-discovery | unit + localhost | netlink parsing incl. truncated/garbage input, a real kernel netlink dump, TCP open/refused/timeout on loopback, unprivileged ICMP to loopback (skips if not permitted), bounded sweep concurrency, cancellation |
| lablink-daemon | unit + localhost | SQLite roundtrip, corrupt and truncated database recovery, retention, /proc stats, gateway probe snippet run in a real `sh`, ssh/exec refused through an unverified gateway, MISMATCH survives losing the address, symlinked socket directory refused |
| lablink-daemon | localhost | the real `lablinkd` refuses a state directory other users can rearrange, a world-writable configuration and a configuration on a pipe (`--config /dev/stdin`) |
| lablink-daemon | unit (simulated) | identity attacks from the LAN through the registry: forged mDNS/DNS answers, replayed keys and foreign MAC sightings never move or verify a pinned device, import a `known_hosts` entry, point outside the lab or flip the site; a contradicting key is a mismatch; a key-verified sighting displaces a squatter |
| lablink-daemon | integration (simulated) | adopt never pins; located/verified/GREEN; IP change found by scan + host key; host-key mismatch RED and never accepted; intermittent loss never OFFLINE; history records transitions only; restart restores identity and history; corrupt cache; graceful shutdown; second daemon refused; no runaway tasks or fds; scans only touch allowlisted attached networks; reassigned DHCP addresses; password-only server YELLOW; explicit trust incl. key change between preview and confirm; malformed/oversized IPC requests; gateways |
| lablink-daemon | integration (simulated) | the other site is AWAY, never probed and never a failure; manual override and return to Auto; the same name at two sites and ambiguity errors; gateway MAC evidence and a changed gateway MAC; a host-key tie resolved by learning; migration of a single-site cache (bare device keys become `default/<name>`) |
| lablink-cli | unit | table alignment with ANSI codes, completion candidates |
| lablink-cli | integration (simulated + localhost) | the real `lablink` binary against an in-process daemon and a fake `ssh`: exit codes 0/3/4/5/6/7/8/10/11/12/124, JSON error shape, status JSON keys, exec passthrough, pinned host-key arguments, timeouts, offline/mismatch refused before ssh starts; `init` from empty dirs (never selects a network by itself, refuses public/oversized scans); export/import without secrets (pins and commands dropped by default); `sites`, `site use/add/rename`, `--site`/`--all`, AWAY refusal with the switch command, ambiguous names (exit 8) and `site/name` completion |
| lablink-gui | unit | wizard selects nothing by default and scans only with both ticks on an allowed range, settings and site management validation, device-edit diffs, adopt form (site choice), lifecycle steps, terminal argument shapes, color/indicator mapping, worker JSON shapes against a fake socket |
| lablink-doctor | unit | check planning, script generation and parsing, verdict and exit codes (AWAY devices ignored), network-only devices, profile check selection, site scope |
| lablink-setup | unit + localhost | interface classification with the daemon scan rule, config writes (0700 directory, 0600 exclusive temp file, validate, backup, atomic), init with a site and merging a site into an existing config, export/import hardening, support-bundle redaction (adversarial: IPv4/IPv6, MACs, fingerprints, `.local` names, home paths, tokens, names inside dotted host-key aliases), the bundle never clobbers files, the packaged unit equals the generated one, service actions refused when the systemd user manager belongs to another configuration |
| lablink-daemon | integration (simulated) | Field Network overlay: a pinned device visiting the roaming site keeps its home record (no duplicate); hotspot clients claiming a visitor's name or MAC never move it or mark it failed |
| lablink-fieldnet | unit (scripted fake) | every OS call goes through a scripted `System` fake (no radio, root or NetworkManager): host-fact parsers (`nmcli` terse output, `iw`, `/proc/net/tcp` and `tcp6` including IPv4-mapped rows, `SSH_CONNECTION`); preflight blockers and warnings (own or inbound SSH session over the adapter, a tunnel or an unknown interface, isolation that cannot be guaranteed (priority-0 rules, stacked interfaces, bridges, XDP, ingress qdiscs), DNS relay without the drop-in, sharing-mode warnings for uplinks and routed networks, equipment over the adapter, WPA3 unverifiable, subnet conflicts with sites, VPN routes and bridges, missing NetworkManager or polkit permission, single vs second adapter, already running); start creates a WPA2 profile with the password only on stdin; a blocked or unconfirmed preflight changes nothing; failed activation restores the previous connection; checkpoint guards activation; an insecure profile, or one visible to other users, read back is refused and never activated; nothing is created without a plain login name; restart, password read-back, forget refused while running; stop and restart refused while an SSH session rides on the adapter; start stops the hotspot when the kernel rules cannot be verified; the `lablinkd` watchdog (idle, verified, stopped, stop failed); status out of sync, isolation and DNS state, and late uplinks and routes in sharing mode (VPN tables included); only a key verdict names a client; passwords (length, alphabet, randomness) and SSIDs that cannot inject editor lines; state file private and secret-free; real child processes scrub the secret from stderr and time out; macOS guidance never claims a hotspot |
| lablink-ros | unit (fake remote) | environment from shell files, session and processes (and their consensus), domain/RMW/distro/path validators, Cyclone and Fast DDS XML (interfaces, peers, discovery, garbage input), `ip` and graph parsers; phase-1 script is read-only, phase 2 uses `--no-daemon`, timeouts and validated parameters; the twelve checks and levels over canned devices (healthy pair reaches level 3 and never 4 without the probe, one-way discovery, domain mismatch, shell vs nodes, Cyclone bound to a missing or wrong interface, Humble ignoring the discovery range, QoS conflicts, active results driving levels 1 and 4, missing `ip`); active probe scripts bounded, on their own topic, subscriber on `--no-daemon`, and a new `ros2 daemon` reported as a leftover; `check` request validation; graph snapshots; DDS Security private keys, passwords and PINs redacted from reports, text and JSON |
| lablink-ros | container (opt-in) | `docker_ros`: real ROS 2 Humble and Jazzy containers on one Docker network, driven through `docker exec` instead of SSH: inspection, graph queries, dds-check of same-distribution and mixed pairs, and the active probe with leftover check. Simulation: no robot, Wi-Fi or SSH. `cargo test -p lablink-ros --test docker_ros -- --ignored --nocapture` (needs Docker and the `ros:humble-ros-base` and `ros:jazzy-ros-base` images; the test installs iproute2 and ping, which those images lack) |
| lablink-cli | integration (simulated + fake programs) | `hotspot`: feature off by default and gating every change while `status` and `stop` stay available, stop refused while an SSH session rides on the hotspot, `feature list/enable/disable`, `capabilities` read-only and ungated, insecure or invalid requests are usage errors before anything runs, preflight refusals exit 7 and change nothing, start/clients/password/stop/forget end to end against fake `nmcli`; `ros`: off by default, argument validation before anything runs, daemon down is exit 3 with no connection, help states the level-4 rule |
| lablink-gui | unit | Field Network tab: start needs a check of the same settings with every warning accepted (an accepted warning whose text changed must be accepted again), blockers cannot be accepted, stale preflights are dropped, shown passwords are forgotten; Robotics tab: the default check is passive, the active test needs a peer and a second confirmation; the worker refuses Field Network and robotics commands while their feature is off, except stopping a running hotspot |

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
| Trust and identity | `replayed_public_key_is_never_verified`, `replayed_host_key_fails_the_possession_proof`, `text_never_proves_possession`, `printed_text_and_exit_status_never_prove_possession`, `replayed_public_key_over_a_real_key_exchange_is_refused`, `key_proof_through_a_real_gateway`, `newkeys_found_only_as_a_packet_type_in_any_split`, `forged_pre_kex_disconnect_is_never_a_key_proof`, `forged_kexinit_offer_is_never_a_key_proof`, `forged_mdns_cannot_move_a_verified_pinned_device`, `contradicting_key_at_a_name_claimed_address_is_a_mismatch`, `key_verified_sighting_displaces_a_squatter`, `forged_mdns_cannot_import_an_ip_keyed_known_hosts_entry`, `known_hosts_entry_keyed_by_ip_alone_is_not_enough_for_a_history_only_address`, `revoked_key_is_never_taken_from_another_line`, `host_key_mismatch_is_red_and_never_accepted`, `trust_requires_confirmation_when_not_interactive`, `unpinned_devices_need_trust_or_an_explicit_opt_in` |
| Discovery and sites | `name_answers_cannot_point_outside_the_lab_or_inject_names`, `a_foreign_device_mac_cannot_flip_the_site`, `fuzz_parse_datagram` (50,000 netlink datagrams), `fuzz_keyscan_and_known_hosts_parsers` (20,000), `active_scans_only_touch_allowlisted_attached_networks`, `ambiguous_name_is_refused_until_one_site_is_confident` |
| Configuration, import, filesystem | `code_loading_forwarding_and_env_options_rejected`, `import_never_takes_ssh_options_even_with_replace`, `imported_checks_are_listed_with_their_parameters`, `deeply_nested_yaml_is_refused_quickly`, `notes_with_terminal_escapes_are_refused`, `fuzz_import_parse_and_plan` (5,000 hostile files), `config_is_private_and_a_planted_temp_symlink_is_not_followed` (and private backups), `socket_directory_is_created_private_and_must_be_a_directory`, `symlinked_socket_directory_is_refused`, `adversarial_bundle_leaks_nothing`, `a_missing_or_relative_home_is_never_a_shared_or_relative_directory`, `files_other_users_could_change_are_named`, `every_link_and_directory_on_the_way_is_judged`, `what_the_kernel_would_not_open_is_not_approved`, `an_acl_that_lets_another_user_write_is_refused`, `a_pipe_is_not_a_path_that_can_be_checked`, `the_private_group_is_the_primary_group_of_the_account`, `a_state_dir_others_can_rearrange_is_refused`, `a_configuration_others_can_change_is_refused`, `a_configuration_on_a_pipe_is_refused`, `only_a_trusted_absolute_lablink_is_run`, `relative_path_entries_never_select_a_program`, `a_program_in_the_current_directory_is_never_run` |
| Commands | `exec_is_batch_and_command_is_single_argument`, `verified_device_pins_host_key_first`, `ssh_binaries_and_options_cannot_inject`, `exec_start_is_one_quoted_word_and_never_a_new_directive`, `proxy_command_escapes_percent_outside_the_tokens`, `control_characters_are_shown_not_executed` |
| Field Network and Robotics | `a_profile_visible_to_other_users_is_refused`, `without_a_plain_login_name_nothing_is_created`, `only_plain_login_names_are_used`, `an_insecure_profile_is_refused_and_never_activated`, `own_ssh_session_over_the_adapter_is_refused_without_override`, `stop_is_refused_while_an_ssh_session_rides_on_the_hotspot`, `routes_to_other_networks_block_unless_routing_is_explicit`, `status_reports_out_of_sync_when_stopped_elsewhere` (late uplink and VPN route), `hotspot_clients_claiming_a_name_or_mac_never_move_or_condemn_a_visitor`, `bidi_and_invisible_characters_are_escaped`, `dds_security_secrets_never_reach_output`, `remote_details_cannot_control_the_terminal` |
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

Simulated Wi-Fi (manual, not automated): `tests/hwsim/run.sh OUT_DIR
[SCENARIO...]` runs real NetworkManager 1.36, `wpa_supplicant`, `dnsmasq`
and polkit 0.105 (`tests/hwsim/Dockerfile`, Ubuntu 22.04) on Linux
`mac80211_hwsim` radios, each moved into its own network-isolated
container: the hotspot host (with a simulated Ethernet uplink and lab LAN
managed by NetworkManager), two clients, and a "wan" container that plays
the uplink, the internet, the LAN and a WireGuard VPN and counts every
probe packet that reaches it in its raw table. No physical interface is
touched; the script snapshots the host's links, addresses, rules, routes
and loaded modules before and after and fails if they differ. It needs
root (Docker and `modprobe`), so it is not part of the suite or CI.

| Scenario | What it shows |
|---|---|
| `raw_control` | Without the rules, shared mode forwards probes to every network behind the host (proves the harness sees a leak) |
| `raw_isolated` | With the rules: host reachable, client to client works, zero probes out, rules gone after deactivation |
| `raw_late_changes` | A WireGuard VPN with a policy rule, new routes and tables, hostile priority-0 rules, sysctl toggles and blanket MASQUERADE after activation leak nothing; deleting the rules (negative control) does |
| `raw_nm_restart` | NetworkManager stopped (SIGTERM) and killed (SIGKILL) under a running hotspot, and restarted |
| `raw_window` | The rules are in the kernel before the access point accepts clients (repeated activations, flood from a client) |
| `raw_dns` | The hotspot's dnsmasq forwards queries upstream without the `no-resolv` drop-in and refuses them with it |
| `lablink_permissions` | As an unprivileged user: preflight blocks without polkit grants and passes with the four-action `.pkla`; checkpoint created; another user cannot see or stop the hotspot |
| `lablink_isolated` | `lablink hotspot start` as that user: the same probes, DNS and late changes as the raw scenarios, `status`, sharing mode as a positive control, stop |
| `lablink_monitor` | The real `lablinkd` watchdog stops the hotspot after the IPv4 rule, the IPv6 rule is deleted or an ingress qdisc is attached, with the time it took and the packets forwarded meanwhile |

Results and their limits are in
[FIELD_NETWORK.md](FIELD_NETWORK.md#simulated-validation).

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
