# Portability

LabLink is built, packaged and tested for Linux: Ubuntu 20.04, 22.04 and
24.04 on x86_64 (the `.deb`, the installer and `lablink update`), and the
CLI and daemon also build for aarch64 Linux. **macOS runs LabLink but is not
packaged**: the CLI and daemon build and run from source, and CI builds and
tests them on macOS (the `macos` job), with the gaps listed below. This page
says what works on macOS today, what does not, and where the line runs
between the generic core and the platform layer.

## macOS today

CI (`macos` job, macOS 15 on Apple silicon) builds `lablink-core`,
`lablink-ssh`, `lablink-files`, `lablink-cli` and `lablink-daemon` with all
targets and runs their tests. macOS has its own code for the private-path
check (`core/paths.rs`, ACLs) and atomic no-replace renames
(`files/fs.rs`, `renameatx_np`).

**Works** (the tests for these pass on macOS in CI): configuration and its
validation, sites, host-key pinning and trust, identity-attack handling,
`status`, `devices`, `inspect`, `resolve`, `ssh`, `exec` (including piped
stdin), `trust`, `forget`, `doctor`, `version`, and the daemon's
monitoring, scanning and startup on the networks you allow. The security
model is the same as on Linux: it lives in the generic code. **Not yet
verified:** file transfers (the SFTP test binary aborts on macOS, see
below).

**Does not work, or works partly:**

| Area | On macOS | Why |
|---|---|---|
| Installation and upgrade | no package, `lablink update` refuses ("supports Linux (Ubuntu) only"), the installer refuses | the `.deb` and `install-linux.sh` are Linux-only |
| Service management | `lablink install-service`, `lablink init` service step and the desktop app's Start button need systemd; nothing installs a launchd agent | `lablink-setup::service` is systemd only |
| Discovery: network changes | no rtnetlink: no interface/address snapshot and no change events, so the daemon falls back to periodic discovery | `lablink-discovery::netlink` is Linux-only |
| Discovery: site hints | no Wi-Fi SSID and no gateway MAC from `/proc`; site detection has fewer signals and may stay UNKNOWN where Linux would be ACTIVE | `lablink-platform` reads `/proc` and wireless extensions |
| Daemon metrics | `lablink metrics` has no process CPU/memory figures | read from `/proc/self` |
| Desktop app | not built or tested by CI on macOS; "Open in terminal" knows only Linux terminals | `lablink-gui::term` |
| Completion | bash completion is generated, but its end-to-end test fails with macOS bash 3.2 | see below |

**Known test failures on macOS** (first run of the `macos` job; these are
reported, not hidden, and each needs its own fix):

- `lablink-cli`: four `update_*` tests (they expect the Linux updater; on
  macOS `lablink update` refuses by design), `bash_script_end_to_end`
  (completion under the system bash 3.2), and
  `exec_with_a_terminal_stdin_does_not_forward_or_hang` (a test helper that
  is not installed on macOS).
- `lablink-daemon`: `metrics::tests::proc_stats_readable` and
  `no_runaway_task_creation` (`/proc`), `via_command_runs_in_a_real_shell`
  (the gateway command exits 127 on macOS), and
  `a_configuration_on_a_pipe_is_refused` (a pipe on macOS is group-writable
  by group 20, so `lablinkd --config /dev/stdin` is refused by the
  trusted-path check: configuration on a pipe does not work on macOS).
- `lablink-files`: `changed_trust_and_daemon_ambiguity_stop_transfers`
  aborts the SFTP test binary on a `WouldBlock` socket error (on macOS an
  accepted socket inherits the listener's non-blocking mode), so the rest of
  that binary does not run.
- `lablink-ssh`: `a_hop_that_leaves_a_process_behind_leaks_nothing` and
  `signals_to_parent_kill_the_owned_group_and_preserve_status`.

## Installing and upgrading on macOS

There is no macOS package. Build the CLI and daemon from a release tag
(Rust from [rustup](https://rustup.rs); `rust-toolchain.toml` selects the
compiler):

```bash
git clone https://github.com/yusufdxb/lablink && cd lablink
git checkout v0.4.4                      # the release you want, never an untagged main
cargo build --release --locked -p lablink-cli -p lablink-daemon
install -m 755 target/release/lablink target/release/lablinkd ~/.local/bin/
```

To upgrade: stop the running `lablinkd`, check out the new tag, build and
install the same way, start `lablinkd` again, and check that
`lablink version` shows the same version and commit for the CLI and the
daemon. Configuration, devices and pinned keys stay in
`~/.config/lablink` and `~/.local/state/lablink` (the XDG layout, the same
as on Linux). Read the CHANGELOG's `Behaviour changes` first
([COMPATIBILITY.md](COMPATIBILITY.md)); a machine that must stay on a
version simply is not rebuilt (and, where `lablink update` is used, see
`lablink update --hold`). The daemon is not started at login unless you add
a launchd agent yourself.

## Generic (no OS assumptions)

| Crate / module | What |
|---|---|
| `lablink-core::config` | YAML configuration, sites, validation, migration of the single-site layout |
| `lablink-core::site` | site detection: evidence, confidence, ACTIVE / AWAY / UNKNOWN decisions, scan permission. Pure functions over [`LocalSignals`](../crates/lablink-core/src/site.rs); it never calls the OS |
| `lablink-core::identity`, `health`, `model`, `explain` | identity matching, hysteresis, the device model, explanations |
| `lablink-core::net` | the network allowlist and scan limits |
| `lablink-core::protocol`, `client` | the IPC protocol (JSON lines) and the client (Unix domain sockets; the peer check uses `SO_PEERCRED` on Linux and `getpeereid` elsewhere) |
| `lablink-ssh` | OpenSSH argument construction, `known_hosts` handling, fingerprints, running `ssh` with timeouts |
| `lablink-doctor` | read-only check scripts (POSIX `sh` on the remote device) and their evaluation |
| `lablink-daemon` (registry, monitors, discovery stages, store, IPC server) | the daemon's logic, behind the `Prober` trait, which isolates every network operation |

The security model (host-key pinning, explicit trust, scan permission,
local-only IPC, sites never changing trust) lives entirely in the generic
part.

## Platform-specific (Linux implementation; macOS status above)

| Concern | Where | Linux implementation | What another OS needs |
|---|---|---|---|
| Interfaces, addresses, neighbor table, change events | `lablink-discovery::netlink` | rtnetlink dumps and multicast monitor | e.g. `getifaddrs`, routing sockets (`PF_ROUTE`), the ARP/NDP table via `sysctl` |
| Default gateways | `lablink-platform::default_routes` | `/proc/net/route` | routing table via `sysctl` / routing socket |
| Gateway and neighbor MACs | `lablink-platform::arp_mac`, netlink neighbors | `/proc/net/arp`, rtnetlink | ARP table via `sysctl` |
| Wi-Fi SSID (a site hint) | `lablink-platform::ssid` | `SIOCGIWESSID` (cfg80211 wireless extensions) | CoreWLAN or equivalent; may need location permission |
| Unprivileged ICMP | `lablink-discovery::probe` | `SOCK_DGRAM`/`IPPROTO_ICMP` (`net.ipv4.ping_group_range`) | also available on macOS; IPv6 handled like IPv4 |
| mDNS | `lablink-discovery::mdns` (`mdns-sd`) | portable | portable |
| Service management | `lablink-setup::service` | systemd user units (`systemctl --user`) | launchd agents (`~/Library/LaunchAgents`) |
| Local network list for setup | `lablink-setup::ifaces` | `getifaddrs` + `/sys/class/net` | `getifaddrs` + OS interface metadata |
| Terminal launching | `lablink-gui::term` | `x-terminal-emulator`, GNOME Terminal, Konsole, ... | `open -a Terminal` / AppleScript |
| File locations | `lablink-core::paths` | XDG directories, `$XDG_RUNTIME_DIR`, private state-directory socket fallback | `~/Library/Application Support`, `~/Library/Caches`, a per-user socket directory |
| Packaging | `scripts/package.sh`, `packaging/` | `.deb`, tarball, desktop entry | app bundle / Homebrew formula |

The daemon's `Prober` trait (`crates/lablink-daemon/src/probe.rs`) is the
seam: the real implementation calls the platform crates; the tests use a
simulated network, which is why the whole daemon is tested without root or
a real network.

## Not portable by design

- The daemon assumes it runs as the same user whose SSH keys it uses. It
  never needs root on Linux and should not on any OS.
- Scanning is IPv4 only (IPv6 ranges are too large to sweep); IPv6 devices
  are found passively.
