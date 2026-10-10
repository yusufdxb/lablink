# Security policy

## Reporting a vulnerability

Please report security problems privately, not in public issues, through
GitHub private vulnerability reporting:
<https://github.com/yusufdxb/lablink/security/advisories/new> (**Security ->
Report a vulnerability** on the repository page). If that form is not
available, open a public issue that only asks for a private contact, without
details. Include the LabLink version (`lablink version`), what you did, what
happened, and what you expected. A sanitized `lablink support-bundle` is
welcome; review it before attaching.

What to expect:

| Step | Target |
|---|---|
| Acknowledgement | within 7 days |
| Assessment (confirmed or not, severity) | within 30 days |
| Fix or published mitigation for confirmed issues | within 90 days, sooner for critical ones |

Fixes are released as a new version with a CHANGELOG `Security` entry that
credits you unless you prefer otherwise. Please give us that time before
publishing details.

## Supported versions

| Version | Supported |
|---|---|
| latest release | yes |
| older | no (upgrade) |

## What LabLink guarantees

These properties are enforced in code and covered by regression tests (see
[docs/TESTING.md](docs/TESTING.md#security-regression-tests)); a way to break
any of them is a vulnerability.

- **No stored secrets.** LabLink never asks for, stores or logs SSH passwords
  and never reads private keys. It uses your OpenSSH client, keys, ssh-agent
  and `~/.ssh/config`; passwords are typed into OpenSSH, never into LabLink.
- **Identity is the pinned host key, proven.** A key is pinned only by an
  explicit `lablink trust` (or the app's **Pin** button) after the
  fingerprint was shown, by a fingerprint written in the config, or by an
  entry already in your own `~/.ssh/known_hosts` under the device's
  configured name (or under its address, when that address is a configured
  static IP or where you adopted the device). A device is reported
  *verified* at an address only after the host there proved it holds the
  pinned private key (a credential-free OpenSSH key exchange); presenting the
  public key, which anyone can copy, is not enough. The proof never reads
  text: LabLink carries the connection and counts it only when its own ssh
  sends `NEWKEYS`, which OpenSSH does only after the pinned key's signature
  verified. The connection ends there, before any authentication.
- **No silent trust on first use.** `lablink ssh` and `lablink exec` refuse a
  device without a pin (exit 7) unless you pass `--unpinned`, which hands the
  decision to OpenSSH's own known_hosts prompt. The doctor, the app's
  actions, login checks and service checks never connect to an unpinned
  device.
- **No host-key mismatch bypass.** A changed key, or a host that presents the
  pinned key but cannot prove it holds it, is a RED security stop. `ssh`,
  `exec`, `resolve`, `copy-id`, login checks and health checks refuse until
  you replace the pin by hand (`lablink trust <device> --replace`). Every
  pinned connection uses `StrictHostKeyChecking=yes` against LabLink's own
  known_hosts with `HostKeyAlias`, `UpdateHostKeys=no` and (OpenSSH 8.5+)
  `KnownHostsCommand=none`, placed before any option from the config or the
  command line.
- **Network claims are not identity.** IP addresses, MAC addresses, mDNS and
  DNS answers and discovery results only say where to look. None of them can
  pin a key, move a verified device to another address on a single missed
  probe, or make a site ACTIVE without one of its networks being attached.
- **No automatic adoption.** Discovered hosts are listed; only you adopt
  them.
- **No scanning of unapproved networks.** Active scans run only on networks
  you allowed with `active_scan: true`, that are private (RFC 1918 or
  link-local), within the size limit (default /22, never above /20),
  directly attached, and belong to the site you are at. A one-time
  `lablink discover --scan-cidr` obeys the same limits. Name answers that
  point at public addresses outside your networks are ignored.
- **Limited OpenSSH options.** `ssh.options` accepts only an allowlist of
  connection-tuning and authentication options; options that weaken
  host-key checking, change addressing, load code (`PKCS11Provider`,
  `SecurityKeyProvider`), forward your agent, display or ports, or send local
  environment are refused. Sessions LabLink starts on its own (login checks,
  service checks, doctor, app actions) never forward the agent, X11 or ports
  and never run a `LocalCommand`, whatever `~/.ssh/config` says.
- **Imports cannot run or weaken anything silently.** `lablink import` never
  takes OpenSSH program paths, `ssh.options` or client preferences from a
  file; drops service-check commands unless `--allow-commands` and pins
  unless `--trust-pins`; lists every network it would scan and every check
  with its parameters; refuses files over 1 MiB, YAML alias bombs and
  brackets nested deeper than 64 levels; and writes nothing without
  confirmation.
- **No network control interface.** The daemon is controlled only through a
  Unix socket (mode 0600 in a 0700 directory checked with `lstat`), checks
  every client's UID (SO_PEERCRED), caps request size (64 KiB) and concurrent
  connections, and times out idle ones. Clients refuse a socket served by
  another UID. The only traffic it receives from the network unsolicited is
  mDNS (UDP 5353, passive browsing; it announces nothing; `daemon.mdns:
  false` turns it off). It opens no TCP listener.
- **No privileges.** The daemon runs as you, as a systemd user service with
  `NoNewPrivileges=yes`. ICMP uses unprivileged datagram sockets. The package
  installs no setuid files and its maintainer scripts start nothing.
- **Sanitized diagnostics.** Support bundles replace addresses, MACs,
  fingerprints, names, usernames (including `user@` in OpenSSH errors), home
  paths, `ssh.options` values, private-key blocks and token-like values with
  placeholders, and never collect known_hosts, agent contents or history.
  Text from devices or the network is shown with control characters escaped.

## What LabLink relies on

LabLink is a policy layer over OpenSSH and the operating system:

- **OpenSSH** performs the key exchange, checks host-key signatures and does
  all authentication. LabLink's guarantees assume an uncompromised `ssh`
  binary and that options given on the command line take precedence over
  configuration files (true for OpenSSH).
- **The operating system** separates users. Root, and anyone who can act as
  your user, can read LabLink's state, edit its pins and talk to its socket.
- **You** decide the first time whether a key is right: compare the
  fingerprint with the device's console or a channel you trust. LabLink
  cannot do that for you.

## Known limitations

- `ssh.reuse_control_master: true` (the default) lets background checks ride
  an OpenSSH ControlMaster connection you opened yourself; such a connection
  was verified by OpenSSH when it was opened, not by LabLink. Set it to
  `false` to force LabLink-verified connections only. Interactive
  `lablink ssh`/`exec` follow your own ControlMaster settings.
- Service checks (`services:` in the config) run the shell commands you
  configure on your devices.
- Site detection uses signals anyone on the local network could imitate
  (subnet, gateway MAC, Wi-Fi name). Imitating them can at most make LabLink
  probe or scan that site's approved ranges, or report the wrong site; it can
  never make LabLink trust a host.
- A key you mark `@revoked` in `~/.ssh/known_hosts` after LabLink pinned it
  is not removed from LabLink's pins automatically; remove or replace it with
  `lablink trust <device> --replace`.
- Devices configured with `ssh: false` (for example a robot reached through
  its computer) are identified only by spoofable signals (address, MAC);
  their status is a reachability indication, not an identity.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the threat model and
[docs/SSH_IDENTITY.md](docs/SSH_IDENTITY.md) for how device identity works.
