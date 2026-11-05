# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `lablink scp [-r] [-p] [-C] [--limit KBIT] [--legacy] SOURCE... DEST`:
  copy files to or from one device with the system scp through the same
  address and pinned host key as `lablink ssh` (`device:path` names the
  device side). Unpinned devices, device-to-device and local-only copies are
  refused. See `docs/SSH_IDENTITY.md`.

### Fixed

- lablinkd no longer fails every start when the desktop app created its
  state directory first: saving Files preferences (for example changing the
  appearance) before the daemon had ever run created
  `~/.local/state/lablink` with the umask's mode (0775 under Ubuntu's usual
  umask of 002), lablinkd refused it ("must belong to you with mode 0700"),
  exited before creating its socket, and systemd restarted it every 5 s. The
  desktop app now creates the directory 0700, and lablinkd tightens one that
  no other user could have written (0755, or 0775 for the user's private
  group). One another user could have written is still refused, untouched,
  and the error names the fix.
- A service start is reported as successful only once the daemon answers a
  ping. `lablink init`, `lablink install-service`, the desktop app's Start
  and Install buttons, and the restarts after a configuration change watch
  the service: a daemon that exits during startup is reported at once with
  its own last message, one that runs but never answers is reported with
  its state and socket path, and a socket path that differs between the
  session and the user manager is named. The desktop app said
  "service: start done" while the daemon was crash-looping.
- "lablinkd is not running" errors from the CLI and the desktop app now
  include the service state and the daemon's last message.

## [0.4.2] - 2026-11-04

Makes upgrading one command. Configuration and state are unchanged; the
installer now restarts the daemon for you.

### Added

- `lablink update` upgrades to the latest release with the official
  installer (checksum verified, package installed with apt, daemon
  restarted); `lablink update --check` only reports and exits 10 when a
  newer release exists; `--migrate` moves an older per-user installation
  aside, as the installer's `--migrate` does.

### Changed

- The installer restarts a running `lablinkd` user service after a package
  upgrade, so the CLI and daemon builds match without a manual restart. A
  stopped service stays stopped; a failed restart prints the manual command.
- After an upgrade, the installer says the configuration, devices and pins
  were kept and suggests `lablink status` / `lablink doctor`, instead of
  `lablink init` (which would only offer to replace the configuration).
- Dependencies: tokio 1.54.1, tokio-util 0.7.20, serde_json 1.0.154.

### Fixed

- **lablinkd no longer refuses to start after an upgrade on hosts whose
  accounts can come from a directory service** (`sss` in
  `/etc/nsswitch.conf`, common on Ubuntu 24.04 desktops). Earlier releases
  created `lablinkd.lock` with the umask's mode (0664 under umask 002); since
  the user's group cannot be proven private there, every later start was
  refused ("writable by group ... (chmod g-w)") and systemd restarted it in
  a loop. The lock is now created 0600, and an existing lock is tightened
  instead of refused (it holds no data). Every other state file is checked
  as before. Found upgrading a real 0.3.0 tarball installation.
- The installer no longer reports "lablinkd was restarted" when the daemon
  did not stay up: it checks that the daemon answers, and otherwise prints
  its last log message and the fix, and exits non-zero.
- Completion and init tests no longer fail on a machine that has the
  package installed (they assumed no system-wide completion script).

## [0.4.1] - 2026-11-03

Fixes found by auditing 0.4.0 as a new user, on a clean Ubuntu container and
on a real device over Wi-Fi. No configuration or state changes; upgrade and
restart the daemon (`systemctl --user restart lablinkd`).

### Fixed

- While a device is not answering, its explanation no longer lists "SSH
  server: accepting connections", "SSH login: works" or "answers
  intermittently" as working now; those are shown as results of the last
  successful check (seen on hardware: every check failing, YELLOW, with
  those lines next to "TCP/22 timed out").
- `lablink adopt` given a hostname (`radar.local`) says what it resolves to
  and the exact `lablink adopt <ip> <name>` command, instead of only
  "'radar.local' is not an IP address".
- A device whose old address was taken by another SSH host (DHCP reuse, a
  different machine, or the device reinstalled on new hardware) no longer
  loops: the daemon re-located it at that address and released it again on
  every check, about every 5 seconds, adding four history events each time.
  The address is now left out of the device's checks for 10 minutes;
  discovery still finds the device there at once if it comes back with its
  pinned key. The host now at that address stays listed in
  `lablink discovered` ("previously used by ... (different host key)")
  instead of being hidden as the device's old address.
- An unmatched host whose link-layer address changes is port- and key-scanned
  again on the next discovery, instead of keeping the previous machine's keys
  for up to the recheck interval. A device that returns to an address it had
  lost is therefore recognized by its pinned key right away.
- Such a device is reported as "Searching for it" with the address it lost
  (also once it turns RED), instead of "Not checked yet: the daemon just
  started" or "stopped answering at its last address".
- An offline device no longer shows `SSH OPEN` and "SSH server: accepting
  connections" from before it went down; its port is checked again when it
  returns.
- Files workspace: copying a folder could fail at random with "Destination
  directory is busy" while other SSH work ran, because a process forked at
  that moment briefly kept the just-released lock of the previous item. The
  lock is now retried for up to half a second; a real concurrent writer is
  still refused.
- `lablink` without a subcommand, or `lablink-gui`, in a session without a
  display (for example over SSH) prints a short message pointing to the CLI
  and exits 2, instead of the windowing library's raw error.

## [0.4.0] - 2026-10-31

The desktop app can now take a new Ubuntu user from install to a verified
device without a terminal: create or pick a site, find or add a device,
confirm its host key, set up key login and test it. Every step that trusts a
host, creates a key, scans a network or changes SSH configuration still asks
first. Upgrading from 0.3.x keeps the configuration, state and pinned host
keys; restart the daemon afterwards with `systemctl --user restart lablinkd`.

### Added

- Guided SSH onboarding in the desktop app: the host key fingerprint is shown
  for explicit confirmation, a key is created only with consent (never
  overwriting an existing one), the public key is installed through OpenSSH's
  own password prompt in a terminal, and key login is tested before the device
  is shown as ready. LabLink never sees, stores or logs the password.
- `lablink remove` and a Remove device action in the app. Removal only changes
  this computer: nothing is sent to the device. Adopted devices are deleted by
  the daemon; configured devices are deleted from `config.yaml` with a backup
  of the previous file. It is separate from forget (reset trust), turning
  monitoring off and dismissing a discovery result.
- Add a device by hostname, Tailscale name or routed IP address. Nothing is
  scanned or trusted when the device is added; its host key is verified
  afterwards like any other device.
- The Discovered tab says how devices were found. Passive discovery is the
  default; a one-time scan is offered only for networks already approved in
  the configuration that this computer is directly connected to, and only
  after confirmation. Results never claim a complete inventory.
- Files workspace: a two-pane SFTP browser for copying files to and from a
  device. Each session opens a fresh SSH connection that requires the
  device's verified, pinned host key.
- True Black, Light and System Default themes.
- `lablink-gui --version` and `--help`, which work without a display.
- `scripts/install-linux.sh --migrate`, `--dry-run` and `--package FILE`.
  An older tarball or source installation in your home folder is moved into
  a timestamped backup with a manifest and a `restore.sh`; configuration,
  state, pinned keys and `~/.ssh` are never touched.

### Changed

- One logo source, the black LabLink app icon (`packaging/app-icon.png`, the
  same file as the macOS app icon), generates every icon, window icon and
  version display, so every build shows the same mark. The 0.3 scalable SVG
  logo is no longer shipped, and installing removes it.
- The installer checks every tool it uses before changing anything, verifies
  the desktop app by running `lablink-gui --version`, and always prints the
  command-line next steps.

### Security

- Files transfers use SFTP version 3, which cannot open a file without
  following symlinks or publish one atomically. A process that can write to
  the remote or local folders while a transfer runs can redirect it. See
  `SECURITY.md`.
- `cargo audit` and `cargo deny` ignore RUSTSEC-2026-0370, RUSTSEC-2026-0371
  and RUSTSEC-2026-0372: unmaintained (not vulnerable) crates pulled in by the
  GUI toolkit's accessibility layer, with no maintained replacement available
  yet. The reasons are recorded in `.cargo/audit.toml` and `deny.toml`.

## [0.3.1] - 2026-10-10

Installing 0.3.1 over an earlier 0.3.0 build is no longer a same-version no-op.
The package does not restart per-user daemons: after upgrading run
`systemctl --user restart lablinkd` (`lablink version` shows a daemon/CLI
version difference until you do). When the running daemon is a different
build, `resolve`, `ssh`, `exec`, `trust`, `forget`, `set`, `adopt`, `discover`,
`doctor` and `copy-id` (and the matching GUI actions) are refused with exit 7
and the restart command, because an old daemon lacks the security fixes in
this build; `status`, `devices` and `inspect` print a stderr warning instead.
Nothing is restarted, so open SSH sessions are untouched. Reading the configuration retries a swap during its safety check
(an atomic save by another LabLink process) instead of failing.

### Security

- Refuse shared or foreign state paths and executables; directory-service
  account lookups disable the private-group exception.
- Restrict pinned SSH master reuse to LabLink-owned device, key and route
  scopes, and harden gateway sessions and key trust confirmation.
- Preserve cached trust after transient storage errors and persist identity
  mismatches until a successful proof or explicit trust change.
- Prevent cross-site automatic pin imports and stale gateway-proof reuse.
- Write pinned keys through exclusive no-follow temporary files.
- Remove arbitrary remote output from support bundles, redact additional
  address and secret forms, and omit local archive owner names.
- Pass LabLink's known_hosts path to OpenSSH as one quoted word, and refuse
  a state directory whose path OpenSSH would expand or re-quote (`%`, `$`,
  `"`, `\`, control characters). Before, a space in the path made OpenSSH
  read two other files, one relative to the working directory.
- Refuse a state file or journal with more than one link.
- A gateway hop of a batch `exec`, `doctor` or app action never prompts.
- Error messages show control characters in paths escaped, so a crafted
  path cannot forge an `OK` line or send terminal escape sequences.
- Installers refuse a prefix containing `=`; `uninstall --purge` leaves a
  custom `LABLINK_STATE_DIR` in place.

### Fixed

- `exec` interrupted by Ctrl-C or SIGTERM says that the local ssh was stopped
  and the remote command may still be running (JSON `status` `interrupted`,
  `remote_may_still_run`). LabLink cannot prove the remote command stopped:
  `exec` runs without a terminal.
- A state directory path containing `"`, `%`, `$` or `\` is reported as a
  refusal (exit 7), not as a host key mismatch (exit 6), and `doctor` no
  longer reports a false identity mismatch for it.
- The daemon `ready` log line escapes control characters in paths.
- Reading `config.yaml` while another LabLink process replaces it is retried
  instead of failing with "the file was replaced while it was being checked".
- Partial key scans leave a device unverified and retry without a false
  identity-mismatch alarm.
- Configuration edits are serialized and stale GUI/import snapshots refused.
- Support bundles handle Unicode login text and configurations with quoted
  bracket-heavy commands can be saved back.
- Foreground command interrupts clean up SSH subprocesses and retain signal
  exit status; changed-host-key errors give security advice and recheck.
- The GUI wraps device details and requires trust before terminal access.
- Per-user installers quote desktop launch paths, honor absolute XDG paths,
  and uninstall only the selected prefix.
- Version diagnostics include the daemon build and warn about stale builds.
- Removed devices are forgotten; `lablink forget` clears runtime trust.
- Adopted devices at different sites use distinct default SSH Host names.
- The login check of a device with a username override checks only that
  user, the one `ssh` and `exec` use.
- `exec --timeout` says that the local ssh was stopped and the remote command
  may still be running, instead of claiming it was killed.
- Concurrent known_hosts writes land in order; at most 20 configuration
  backups are kept per file.
- Without `XDG_RUNTIME_DIR`, the daemon creates the directories above its
  socket private, so its own default state directory is not refused later.
- A device last seen at an address now held by another site's machine no
  longer stops that machine from being scanned and identified.
- INSTALL.md says that a tarball install next to the `.deb` uses the
  packaged daemon unit, and how to switch back after removing the package.

## [0.3.0] - 2026-10-10

First public release.

### Added

- **Sites.** Devices and networks belong to sites (labs, offices,
  workshops). LabLink detects the site you are at from attached subnets,
  interfaces, the default gateway and its MAC, the Wi-Fi name (a hint), known
  device MACs on the local link and pinned host keys presented on the site's
  networks; reports ACTIVE / AWAY / UNKNOWN with a confidence; learns a
  site's gateway signature once host keys confirm it.
  - Devices of AWAY sites are not probed and are reported GRAY, never RED.
  - Active scans run only for the active site's approved networks.
  - Manual override (`lablink site use <site>`, the app's site selector) and
    `auto`; the choice persists.
  - Canonical `site/name` references; a bare name that is ambiguous between
    sites is refused with exit code 8 and lists the `site/name` choices.
  - `lablink sites`, `lablink site`, `lablink site add|rename|use`,
    `--site` and `--all` for `status`, `devices` and `doctor`,
    `adopt --site`, `init --site`.
  - The app: site selector, current-site header with READY / DEGRADED /
    NOT READY, Other Sites, an All Sites view, and a Sites tab to create and
    rename sites, choose networks and scanning, toggle detection and see the
    detection signals.
  - Single-site configurations and caches are migrated to a `default` site
    automatically.
- First-run setup (`lablink init` and an app wizard), `lablink version`,
  `copy-id` through the pinned identity, export/import, a sanitized support
  bundle, device profiles and capabilities, plain-language explanations of
  every non-GREEN state, the app's device lifecycle, Settings and Health
  pages, and bash completion.
- `lablink doctor`: read-only health checks (SSH, disk, NVIDIA and Jetson
  GPU, temperature, ROS 2, DDS, reachability) chosen by device profile or
  configured per device.
- Devices reached through a gateway device, checked and connected through
  the gateway's pinned identity.
- `.deb` and tarball packages built on Ubuntu 20.04 (glibc 2.31) for
  Ubuntu 20.04, 22.04 and 24.04, with SHA256SUMS.

### Security

Hardening from an adversarial security review before the first public
release (details: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) T26-T36).

- A device is *verified* only after the host proves it holds the pinned
  private key (credential-free OpenSSH key exchange, decided from the bytes
  LabLink's own ssh sends, never from printed text); a replayed public key is
  a security stop. Client config files cannot vouch for a key, hide the
  proof's options or steer it to unpinned key types. Scan sightings never
  verify by themselves.
- Forged mDNS/DNS answers or MAC sightings can no longer move a verified
  device on one missed probe, select `~/.ssh/known_hosts` entries to pin, or
  point probes at public addresses; a key contradicting the pin at an
  address claimed by name is a mismatch.
- A device sighting cannot make another site ACTIVE unless one of its
  networks is attached.
- `lablink ssh`/`exec` refuse devices without a pin (`--unpinned` to let
  OpenSSH decide); `lablink resolve` prints only verified addresses
  (`--force`); doctor and app actions never run on unpinned devices.
- `ssh.options` is an allowlist (no code-loading, forwarding or environment
  options) and is never imported; automated sessions never forward the
  agent, X11 or ports; pinned connections disable `KnownHostsCommand` and
  `VerifyHostKeyDNS`.
- Imports refuse deeply nested YAML and list doctor checks with their
  parameters; notes reject terminal escape sequences and the CLI escapes
  text from devices; keys revoked in `~/.ssh/known_hosts` are never pinned.
- Support bundles also redact unknown login names before addresses and
  `ssh.options` values.
- Systemd unit `ExecStart` is quoted and validated; config backups are
  private; the socket directory is created 0700 and checked with `lstat`;
  bash completion takes candidates literally.
- Supply chain: CI actions pinned by SHA, pinned audit tools, gitleaks job,
  dependabot, job timeouts; reproducible `.deb`/tarball; CycloneDX SBOM;
  build provenance attestations on tags; checksum-verified toolchain
  installer.
- LabLink never takes its configuration, pins or programs from a place
  another user or the current directory controls: with `HOME` unset it uses
  the home directory from the password database instead of /tmp (where
  another user could plant a configuration naming the ssh program, or own
  the directory holding the pins); relative `HOME`, `XDG_*` and `LABLINK_*`
  paths are ignored with a warning; a configuration, state directory or
  `~/.ssh/known_hosts` that another user could change (owned by them,
  writable by everyone or by a group other than your private group,
  granted to another user or group by a POSIX ACL, or
  reached through their directory or through their link anywhere in a
  chain of links) is refused, and so is a path that cannot be resolved to a
  file, such as `/dev/stdin` on a pipe; `ssh` and the other programs LabLink
  starts are looked up only in absolute `PATH` directories, so an `ssh` in
  the current directory is never run; and the app runs only an absolute,
  trusted `lablink` in the terminal, never a bare name.

Earlier in the 0.3.0 cycle:

- The CLI and the app refuse a daemon socket served by another user.
- `lablink import` drops service-check commands unless `--allow-commands`,
  never imports client preferences or OpenSSH program paths, lists every
  network that would be scanned, and refuses oversized files.
- The support bundle also redacts IPv6 addresses, `.local` names, device
  and site names, Wi-Fi names, other users' home directories, private-key
  blocks and `password=`/`token=`-style values; it is written through a
  private temporary directory and never replaces an existing file.
- `config.yaml` and exports are written with mode 0600; config writes use a
  fresh temporary file.
- The daemon refuses a symlinked socket directory.
- `ssh.options` values and the OpenSSH program paths are validated.
- LabLink no longer starts, restarts or stops a systemd user service whose
  manager runs with a different home or config directory.

[0.4.2]: https://github.com/yusufdxb/lablink/releases/tag/v0.4.2
[0.4.1]: https://github.com/yusufdxb/lablink/releases/tag/v0.4.1
[0.4.0]: https://github.com/yusufdxb/lablink/releases/tag/v0.4.0
[0.3.1]: https://github.com/yusufdxb/lablink/releases/tag/v0.3.1
[0.3.0]: https://github.com/yusufdxb/lablink/releases/tag/v0.3.0
