# LabLink threat model

Scope: `lablinkd`, `lablink`, `lablink-gui` running as an unprivileged user on
a Linux workstation or laptop that moves between sites (labs, offices,
workshops), managing SSH access to robots and edge computers on their
networks.

## Assets

| Asset | Why it matters |
|---|---|
| SSH credentials (keys, agent, ControlMaster sockets) | Access to robots that can move. LabLink never reads or stores them; OpenSSH uses them. |
| Correct device identity | Sending commands or credentials to the wrong machine (or an impostor) is the main risk LabLink introduces or removes. |
| Pinned host keys (`known_hosts` in the state dir) | Integrity decides whether `ssh`/`exec` connect. |
| The lab networks themselves | Indiscriminate scanning disrupts other users and can look like an attack. |
| The cache and history | Integrity matters for diagnosis; contains IPs, MACs, hostnames, no secrets. |

## Trust boundaries

1. **Local user boundary.** The daemon, CLI and GUI run as the same user. The
   IPC socket sits in a 0700 directory, is 0600, and every connection's peer
   UID is checked with `SO_PEERCRED`; other local users cannot query or
   control the daemon. The CLI and GUI check the daemon's UID the same way
   before believing its answers (which choose the `ssh` binary and options
   they run). Root can, by design.
2. **Network boundary.** Everything learned from the network (neighbor
   entries, mDNS answers, scan results, host keys, `hostname` output) is
   untrusted input. It is parsed defensively (length-checked netlink parser,
   key blobs validated against their declared type, mDNS and hostnames
   validated before being learned) and never executed or interpolated into a
   shell, with one exception noted below.
3. **Gateway boundary.** For devices behind a gateway (`via:`), LabLink runs a
   fixed command on the gateway over SSH. Only an `IpAddr` and a `u16` port
   (both typed, never strings from the network or config) are interpolated.
4. **Config boundary.** The config file is trusted (it is the user's own
   file), but validated strictly (and import files are not trusted: T21): unknown keys are rejected so a typo cannot
   silently disable a safety setting, and options that weaken host-key
   checking (`StrictHostKeyChecking`, `UserKnownHostsFile`, `HostKeyAlias`,
   `ProxyCommand`, ...) are refused in `ssh.options`. Usernames and `ssh_host`
   are validated so they cannot inject ssh options (no leading `-`), and ssh is
   invoked with `--` before the host argument.

## Threats and mitigations

| # | Threat | Mitigation | Verified by |
|---|---|---|---|
| T1 | Impostor answers at a device's address (ARP spoofing, rogue DHCP, reinstalled machine) | Host-key pinning. A key that contradicts the pin while MAC/hostname/static IP match is a MISMATCH: RED, logged at warn, recorded once, `resolve`/`ssh`/`exec`/service checks/login checks refuse. Nothing is re-pinned automatically. Losing the address does not clear a MISMATCH; only a verified pinned key or `lablink trust --replace` does. | `host_key_mismatch_is_red_and_never_accepted`, `offline_and_mismatch_are_refused_before_ssh_runs`, `identity::tests::*` |
| T2 | DHCP gives a device's old address to another host | Recognised as address reuse (only historical-IP evidence + different key), the address is released without a security alarm and without connecting to the newcomer. | `unknown_host_at_old_dhcp_address_releases_it`, `reassigned_ip_moves_to_the_device_whose_key_it_presents` |
| T3 | IP change makes `ssh` hit known_hosts prompts and users learn to type "yes" | Pinned devices are connected with `HostKeyAlias=lablink.<site>.<name>` against LabLink's known_hosts and `StrictHostKeyChecking=yes`, so the pin follows the device across addresses and no prompt appears. | `exec_preserves_exit_code_output_and_pins_host_key` |
| T4 | Trust-on-first-use pins an attacker's key | No silent TOFU. A key is pinned only if it is in the config, already trusted in the user's own `~/.ssh/known_hosts` (entries keyed by the bare IP count only when the address has current evidence beyond history: configured static IP, resolved from a configured hostname within the last 10 minutes, MAC or hostname match, adoption), or explicitly confirmed with `lablink trust` (preview first; the confirm call must list exactly the fingerprints shown, and a fresh scan must still return exactly those). | `unpinned_device_trusted_from_user_known_hosts_or_explicit_trust`, `trust_requires_confirmation_when_not_interactive`, `known_hosts_entry_keyed_by_ip_alone_is_not_enough_for_a_history_only_address` |
| T5 | User extras or config weaken host-key checking | LabLink's host-key options are placed first (OpenSSH takes the first value). `ssh.options` refuses host-key and addressing options (`StrictHostKeyChecking`, `UserKnownHostsFile`, `GlobalKnownHostsFile`, `HostKeyAlias`, `CheckHostIP`, `UpdateHostKeys`, `HostName`, `KnownHostsCommand`, `VerifyHostKeyDNS`, `ProxyCommand`, `ProxyJump`, `ControlPath`, `ControlMaster`, `LocalCommand`, `PermitLocalCommand`, `RemoteCommand`). The user's own `~/.ssh/config` is outside LabLink's control; only options LabLink sets itself on the command line override it. | `verified_device_pins_host_key_first`, `ssh_uses_interactive_mode_with_pinned_identity`, `weakening_ssh_options_rejected`, `host_key_bypass_options_rejected` |
| T6 | Credentials sent to an unidentified host by background checks | Login checks and service checks run only after the host key is verified. Unpinned hosts get no automated logins or commands. `lablink ssh`/`exec` to a device behind a gateway are refused unless the gateway's host key is verified against a pin, so the hop always runs with `StrictHostKeyChecking=yes`. | `service_checks_report_per_service_and_only_run_on_verified_hosts`, `resolve_refuses_tunnel_through_unverified_gateway`, `follow_up` logic |
| T7 | Password capture or storage | LabLink never asks for, stores or logs passwords. Background SSH uses `BatchMode=yes`. Interactive prompts happen only in the user's terminal, handled by OpenSSH. | code review: no password field exists in config, protocol or cache |
| T8 | Secrets in logs | Logs contain device names, IPs, MACs, fingerprints (public), state transitions and ssh error classifications. Remote command output is not logged; private keys are never read. | code review |
| T9 | Scanning networks the user did not intend | Active scans only for `active_scan: true` networks of the ACTIVE site (never an AWAY or UNKNOWN site, nor one chosen only by a subnet another site shares) that are private (RFC 1918 or link-local), IPv4, at most `max_scan_hosts` (default 1024, hard ceiling 4096, so /8, /12, /16 are refused), and contained in a directly attached subnet (overlap is not enough). Addresses of configured devices (expected IPs, resolved configured hostnames, known history) are probed individually by their monitors, never as ranges. One-time scans (`discover --scan-cidr`) apply the same rules except the allowlist. Refusals are logged and recorded with the reason. Devices behind a gateway are never probed from this host. | `large_networks_rejected`, `hard_ceiling_cannot_be_raised`, `public_and_v6_rejected`, `active_scans_only_touch_allowlisted_attached_networks`, `device_behind_gateway_is_checked_through_it_never_directly` |
| T10 | Probe traffic triggers remote defences (sshd log noise, fail2ban) | Liveness uses ICMP; TCP/22 at most every 30 s per device; host-key scans on transitions or every 10 min; login checks on transitions or every 5 min. Scans TCP-probe unmatched hosts at most once per 10 min. | `history_records_transitions_not_heartbeats`, soak counters in PERFORMANCE.md |
| T11 | Local DoS of the daemon via IPC | 64 KiB request limit, 32 connections, 30 s idle timeout, bounded discovery queue, bounded scan workers. | `malformed_and_oversized_requests_are_rejected`, `no_runaway_task_creation` |
| T12 | Corrupt or tampered cache | Unreadable database moved aside, fresh cache created, event recorded. Individual records that fail to decode are skipped. Pins in the cache are only as trustworthy as the user's account; config pins always apply. | `corrupt_cache_is_recovered`, `corrupt_file_is_moved_aside`, `truncated_database_recovered` |
| T13 | Two daemons fighting over one state dir | `flock` on `lablinkd.lock`; a second daemon refuses to start. | `second_daemon_on_same_state_dir_is_refused` |
| T14 | First-run setup enables scanning the user did not choose | `lablink init` and the GUI wizard list attached networks with nothing selected; active scanning is a separate yes per network and is offered only where the daemon's own scan rule (T9) allows it. `init --yes` without `--scan`/`--network` allows no network. | `init_never_selects_networks_by_itself`, `nothing_is_selected_or_scanned_by_default`, `scanning_needs_both_ticks_and_an_allowed_range` |
| T15 | Installing an SSH key sends the user's password to an impostor | `lablink copy-id` (and the GUI's SSH Setup, which runs it in a terminal) refuses devices without a pinned host key and passes LabLink's pinned host-key options to `ssh-copy-id`, so the password prompt can only be answered by the verified machine. The password is typed into OpenSSH; LabLink and the GUI never see it. | `copy_id_goes_through_the_pinned_identity_only`, `copy_id_uses_the_pinned_options_and_refuses_unpinned`, clean-room step "SSH setup" |
| T16 | Imported configuration silently trusts keys | `lablink import` drops pinned fingerprints from the file unless `--trust-pins` is given, lists every key it would trust when it is, shows all changes and asks before writing; conflicting entries are skipped unless `--replace`. | `import_merges_drops_pins_by_default_and_respects_conflicts`, `adopt_export_import_round_trip_without_secrets` |
| T17 | Diagnostics leak lab details | `lablink support-bundle` replaces IPv4/IPv6 and MAC addresses, fingerprints, `.local` names, usernames, hostnames, labels, device and site names, network names, Wi-Fi names, home directories (any `/home/<user>`), private-key blocks and `password=`/`token=`/`Bearer` values with placeholders; drops notes and service-check commands; never collects ssh-agent contents, shell history, known_hosts or other files; uploads nothing. | `redacts_addresses_fingerprints_and_registered_words`, `redacts_ipv6_local_names_secrets_and_other_homes`, `adversarial_bundle_leaks_nothing`, `support_bundle_is_redacted`, clean-room step "support bundle" |
| T18 | Settings edits break or weaken the config | The GUI and `import` write only configs that pass the same validation as the daemon, atomically, keeping the previous file as a backup. The `ssh:` section is not editable in the GUI. | `write_validates_backs_up_and_round_trips`, `edits_are_validated_before_saving` |
| T19 | A changed host key goes unnoticed between identity checks | A login check that fails because the server presented a different key triggers an immediate identity re-check, which turns the device RED (MISMATCH) within seconds instead of at the next periodic check. | `changed_key_seen_by_the_login_check_is_reverified_at_once`, clean-room step "security stop" |
| T20 | Another local user serves a fake daemon at the socket path (possible with the `/tmp/lablink-<uid>` fallback when `$XDG_RUNTIME_DIR` is unset) and returns its own `ssh` binary or `ProxyCommand` | Clients refuse a socket whose peer UID (SO_PEERCRED) is not theirs. The daemon refuses a socket directory owned by another user or that is a symlink. | `only_a_daemon_of_this_user_is_believed`, `peer_uid_of_a_local_socket_is_ours`, `symlinked_socket_directory_is_refused` |
| T21 | A malicious export file (`lablink import`) runs commands, swaps programs or adds scans | Service-check commands are dropped unless `--allow-commands` (and are listed either way); client preferences (the terminal the app launches) and OpenSSH program paths are never imported; pins are dropped unless `--trust-pins`; every network that would be scanned is listed; files over 1 MiB and YAML alias bombs are refused; nothing is written without confirmation. | `import_never_takes_commands_preferences_or_program_paths_silently`, `bad_files_are_rejected` |
| T22 | Spoofed site signals (subnet, gateway MAC, Wi-Fi name) | Site detection only decides which devices are probed and which approved networks may be scanned; it never pins, unpins or accepts a host key, and adopts nothing. Scans still need an approved, private, attached, size-limited network. Gateway signatures are learned only while host keys confirm the site. | `site::tests::*`, `gateway_mac_and_host_keys_pick_the_right_same_subnet_site` |
| T23 | A bare device name runs a command on the same-named device of another site | A bare name resolves only when unique, or when exactly one match is at a site LabLink is confident about (host key or gateway MAC evidence, or chosen by hand); otherwise `ambiguous` (exit 8) lists the `site/name` choices. When a shared name was resolved, the CLI says which device it used. `ssh`/`exec` to a device of an AWAY site are refused without `--force`. | `ambiguous_name_is_refused_until_one_site_is_confident`, `ambiguous_name_message_and_exit_code`, `sites_status_scopes_and_away_semantics` |
| T24 | Symlink or race attacks on files LabLink writes | Config is written through a fresh `O_EXCL` temporary file (0600, directory 0700) and renamed; support bundles are assembled in a private random directory and never replace an existing file; the state directory is 0700. | `config_is_private_and_a_planted_temp_symlink_is_not_followed`, `bundle_without_daemon_is_private_and_never_clobbers` |
| T25 | A sandboxed or test process (different `HOME`) installs, restarts or stops the real user's service | Service control only acts when the systemd user manager's `HOME`/`XDG_CONFIG_HOME` match the caller's. | `foreign_home_never_drives_the_real_user_manager` |

## Known limitations

- **Existing ControlMaster connections.** When the user already has an open
  OpenSSH master for the target address (e.g. `ControlMaster auto` in
  `~/.ssh/config`), OpenSSH multiplexes over it and does not re-check the host
  key; the guarantee then rests on the check made when the master connected.
  Background checks reuse such masters by default (needed for password-only
  servers); `ssh.reuse_control_master: false` forces them onto fresh
  connections (`ControlPath=none`). Interactive `lablink ssh`/`exec` follow
  the user's own ControlMaster settings.
- **Password-only servers.** LabLink cannot verify login non-interactively on
  a server that only accepts passwords; it reports `ssh_auth: failed` with the
  reason "server only accepts password authentication". The fix is a key, or
  an open ControlMaster session (`lablink ssh <device>` with `ControlPersist`).
- **Cloned images** that share host keys are distinguishable only with other
  signals (MAC, hostname, static IP); otherwise sightings are "ambiguous".
- **MAC and hostname are spoofable.** They only associate addresses; they
  never override a pinned host key.
- **Root on this machine** can read the cache and talk to the socket.
- **Site signals are not authenticated.** Anyone on a network can imitate a
  subnet, a gateway MAC or a Wi-Fi name. This can make LabLink believe it is
  at a site (and so probe that site's device addresses and scan its
  approved ranges); it cannot make LabLink trust a host.
