# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.3.1] - 2026-10-10

Installing 0.3.1 over an earlier 0.3.0 build is no longer a same-version no-op.
The package does not restart per-user daemons: after upgrading run
`systemctl --user restart lablinkd` (`lablink version` shows a daemon/CLI
version difference until you do).

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

[0.3.1]: https://github.com/yusufdxb/lablink/releases/tag/v0.3.1
[0.3.0]: https://github.com/yusufdxb/lablink/releases/tag/v0.3.0
