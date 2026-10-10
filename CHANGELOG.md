# Changelog

All notable changes are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Optional remote access over Tailscale (`docs/REMOTE_ACCESS.md`): a
  device's `remote: tailscale:` block lets `lablink ssh`/`exec` fall back to
  its tailnet address when the LAN does not answer, verifying the same pinned
  host key on both paths. `--transport auto|lan|tailscale`,
  `lablink remote status` and `lablink remote setup` (read-only). Works
  without the daemon for configured devices (daemon-less clients).

### Changed

- `lablink ssh/exec --force` on a device with `remote:` whose LAN is offline
  now tries the tailnet; `--transport lan --force` keeps the old behaviour.

## [0.3.0] - Unreleased

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
