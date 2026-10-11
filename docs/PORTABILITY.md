# Portability

LabLink 0.3 supports Linux only (tested on Ubuntu 20.04, 22.04 and 24.04,
x86_64; the CLI and daemon also build for aarch64 Linux). macOS is not
supported yet. This page draws the line between the generic core, which
should not need changes for another OS, and the platform layer, which would
be reimplemented.

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

## Platform-specific (Linux today)

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
| Field Network hotspot (optional) | `lablink-fieldnet::nm`, `host` | NetworkManager via `nmcli`, polkit permissions, `/proc/net/*`, `ip` | macOS: capability detection and guided Internet Sharing only (`lablink-fieldnet::macos`), no hotspot creation; other OSes: unsupported |
| Field Network clients (optional) | `lablink-fieldnet::clients` | `ip neigh` (or `/proc/net/arp`) and NetworkManager's dnsmasq leases | the ARP table via `sysctl`; macOS Internet Sharing's own leases |
| Packaging | `scripts/package.sh`, `packaging/` | `.deb`, tarball, desktop entry | app bundle / Homebrew formula |

The daemon's `Prober` trait (`crates/lablink-daemon/src/probe.rs`) is the
seam: the real implementation calls the platform crates; the tests use a
simulated network, which is why the whole daemon is tested without root or
a real network.

Robotics mode (`lablink-ros`) runs nothing locally beyond OpenSSH: its
scripts run on the device, and expect a Linux device with `/proc` and
ROS 2 under `/opt/ros`. The local OS only matters for SSH.

## Not portable by design

- The daemon assumes it runs as the same user whose SSH keys it uses. It
  never needs root on Linux and should not on any OS.
- Scanning is IPv4 only (IPv6 ranges are too large to sweep); IPv6 devices
  are found passively.
