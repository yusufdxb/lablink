# Security policy

## Reporting a vulnerability

Please report security problems privately, not in public issues: use the
repository's **Security -> Report a vulnerability** form (GitHub private
vulnerability reporting). Include the LabLink version (`lablink version`),
what you did, what happened, and what you expected. A sanitized
`lablink support-bundle` is welcome; review it before attaching.

Reports are acknowledged as soon as possible. Fixes are released as a new
version with a CHANGELOG entry that credits you unless you prefer otherwise.

## Supported versions

| Version | Supported |
|---|---|
| 0.3.x | yes |
| older | no (never released publicly) |

## What LabLink guarantees

These properties are enforced in code and covered by tests; a way to break
any of them is a vulnerability:

- **No stored secrets.** LabLink never stores SSH passwords or private keys.
  It uses your OpenSSH client, keys, ssh-agent and `~/.ssh/config`.
- **No automatic host-key acceptance.** A host key is pinned only by an
  explicit `lablink trust` (or the app's **Pin** button) after the
  fingerprint was shown, by a fingerprint written in the config, or by an
  entry already in your own `~/.ssh/known_hosts` for that device's name (or
  its address, when the address itself is backed by a static IP, MAC or
  current name resolution).
- **No host-key mismatch bypass.** A changed key is a RED security stop.
  `ssh`, `exec`, `copy-id`, login checks and health checks refuse until the
  pin is replaced by hand (`lablink trust <device> --replace`). Every SSH
  invocation uses `StrictHostKeyChecking=yes` against LabLink's own
  `known_hosts`; options that would weaken this are rejected in the config.
- **No automatic adoption.** Discovered hosts are listed; only you adopt
  them.
- **No scanning of unapproved networks.** Active scans run only on networks
  you allowed with `active_scan: true`, that are private (RFC 1918 or
  link-local), within the size limit (default /22, never above /20),
  directly attached, and belong to the site you are at. A one-time
  `lablink discover --scan-cidr` obeys the same limits.
- **No network listener.** The daemon serves a Unix socket only (mode 0600
  in a 0700 directory), checks every client's UID (SO_PEERCRED), caps
  request size (64 KiB) and concurrent connections, and times out idle ones.
  Clients refuse a socket served by another UID.
- **No privileges.** The daemon runs as you, as a systemd user service.
  ICMP uses unprivileged datagram sockets.
- **Sites never change trust.** Which site is active decides only which
  devices are probed and how they are reported.

## Known limitations

- The first time LabLink sees a device you decide whether its key is the
  right one. Compare the fingerprint with the device's console; LabLink
  cannot do that for you.
- `ssh.reuse_control_master: true` (the default) lets background checks ride
  an OpenSSH ControlMaster connection you opened yourself; such a connection
  was verified by OpenSSH when it was opened, not by LabLink. Set it to
  `false` to force LabLink-verified connections only.
- Service checks (`services:` in the config) run the shell commands you
  configure on your devices. `lablink import` drops them unless you pass
  `--allow-commands`.
- Site detection uses signals anyone on the local network could imitate
  (subnet, gateway MAC, Wi-Fi name). Imitating them can at most make LabLink
  probe or scan that network's approved range; it can never make LabLink
  trust a host.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full threat model.
