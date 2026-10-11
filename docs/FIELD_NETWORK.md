# Field Network

The Field Network is a temporary WPA2 (or WPA3) Wi-Fi network that LabLink
starts on this machine, so a laptop, Jetsons and robots can reach each other
where there is no usable network: a field test, a demo hall, a basement, a
lab whose Wi-Fi blocks client-to-client traffic. It works fully offline.

It is an optional feature and is off by default. Nothing in this document
applies until you turn it on.

- **Linux with NetworkManager:** LabLink creates, starts, stops and
  monitors the hotspot through NetworkManager's own polkit-checked
  interface (`nmcli`).
- **macOS:** LabLink detects what the Mac can do and walks you through
  Internet Sharing. It does not create a hotspot itself ([macOS](#macos)).
- **Other systems:** not supported. `lablink hotspot capabilities` says so.

## What has and has not been proven

| Area | Evidence |
|---|---|
| Preflight, start, stop, restore, rollback, password handling, client classification, profile verification | Unit and integration tests against a scripted fake of `nmcli`, `ip` and `/proc` (`crates/lablink-fieldnet/src/tests.rs`, `crates/lablink-cli/tests/hotspot.rs`) |
| Visiting devices recognized by pinned host key only | Daemon integration tests on a simulated network (`crates/lablink-daemon/tests/field_network.rs`) |
| `capabilities` and `preflight` on a real Linux host (NetworkManager, one Wi-Fi adapter, Ethernet uplink, a VPN and Docker) | Run read-only. Output matched the host: AP and WPA2 reported, WPA3 "cannot verify" without `iw`, start refused because Ethernet would be NATed |
| Starting a hotspot on real hardware, a real client joining, real DHCP leases, real rollback | **Not tested.** No hotspot has been started on a real adapter during development |
| macOS | **Not tested on a Mac.** Only the parsers and guidance are tested, against recorded command output |

Treat the Field Network as experimental until you have run the
[example](#example-a-laptop-a-jetson-and-a-second-ros-machine) on your own
hardware.

## Requirements (Linux)

- NetworkManager running, with `nmcli` on a trusted `PATH` directory.
- A Wi-Fi adapter whose driver supports access-point mode and WPA2
  (`lablink hotspot capabilities` lists each adapter's support for access
  point, WPA2, WPA3, 2.4 GHz and 5 GHz). WPA3
  needs SAE in AP mode, which LabLink can only verify when `iw` is
  installed.
- Polkit permission for your user to control networking
  (`org.freedesktop.NetworkManager.network-control`) and, the first time,
  to create a system connection profile (`settings.modify.system`). A
  desktop session's user normally has both. LabLink never asks for root,
  never runs `sudo`, and never installs a privileged helper. If polkit
  says `auth` (would prompt), preflight refuses and tells you which
  permission is missing.
- Optional: the `checkpoint-rollback` permission. With it, NetworkManager
  itself undoes the change if activation does not complete within 120 s
  (see [Restoring the previous network](#restoring-the-previous-network)).

## Turning it on

```bash
lablink feature enable field-network
lablink feature list
```

Or tick **Field Network** under **Settings** in the app. Turning it off
deletes nothing: the profile, its password and the `field-network` site
stay until you run `lablink hotspot forget`.

`lablink hotspot capabilities` works with the feature off, because it only
reads.

## Commands

| Command | What it does | Changes |
|---|---|---|
| `lablink hotspot capabilities` | Adapters, AP/WPA2/WPA3 support, NetworkManager permissions; on macOS, the Internet Sharing steps | nothing |
| `lablink hotspot preflight [opts]` | Everything start would check, and what starting would disconnect | nothing |
| `lablink hotspot start [opts]` | Runs preflight, asks you to accept its warnings, then starts | NetworkManager profile, adapter, LabLink config (site) |
| `lablink hotspot status` | Whether it runs (NetworkManager's word, not LabLink's record), settings, forwarding, other uplinks, clients. Works with the feature off | nothing |
| `lablink hotspot clients` | Who is on it and what LabLink knows about each | nothing |
| `lablink hotspot password [--rotate \| --stdin]` | Print the password (read from NetworkManager), or store a new generated one (`--rotate`) or one read from stdin | profile secret (with an option) |
| `lablink hotspot restart` | Re-apply the running hotspot after a password change | adapter |
| `lablink hotspot stop [--no-restore]` | Stop it and reconnect the network the adapter had before. Works with the feature off, so turning the feature off never strands a running hotspot. Refused while an SSH session depends on the adapter | adapter |
| `lablink hotspot forget` | Delete LabLink's profile and password. Refused while running | NetworkManager profile |

Start and preflight options: `--interface`, `--ssid`, `--subnet` (private
IPv4, /22 to /28), `--security wpa2|wpa3`, `--allow-internet-sharing`,
`--allow-routing`.
`start` also takes `--yes` (accept warnings without asking; blockers are
never accepted), `--password-stdin` and `--no-site`. Every command takes
`--json`. Exit codes follow the rest of LabLink: 0 success, 1 failure, 2
usage, 7 refused (a preflight blocker, the feature is off, the findings
changed while you were answering the prompt, or `stop`/`restart` would cut
an SSH session).

In the app, the **Field Network** tab shows the same capabilities, status
and clients. **Check** runs preflight for the settings in the form;
**Start** is enabled only after a check of exactly those settings found no
blocker and you ticked every warning. The **Internet sharing** and
**Routing** boxes are the two overrides. The app checks again just before
starting and refuses if any warning's text changed. With the feature off,
the tab still shows a running hotspot's status and a **Stop** button.

## What start does

1. **Preflight** (read-only). Blockers stop here; warnings must be accepted.
2. **Profile.** LabLink creates one NetworkManager profile, "LabLink Field
   Network" (autoconnect off), or updates the one it made before. Mode
   `ap`; key management `wpa-psk` (WPA2, CCMP) or `sae` (WPA3, PMF
   required); IPv4 `shared`, IPv6 disabled.
3. **Password.** A generated 24-character password (120 bits from the OS
   random source, no look-alike characters), or one you pipe in with
   `--password-stdin`. It goes to `nmcli connection edit` on stdin, never
   on a command line, and is stored in NetworkManager's root-only secret
   store. LabLink keeps only the profile's UUID.
4. **Verify.** The profile is read back. Anything other than WPA2/WPA3 with
   a password (open, WEP, a missing key) is refused and never activated.
5. **Record.** `fieldnet.json` (mode 0600, in LabLink's state directory)
   notes the previous connection on the adapter, the subnet and whether
   IPv4 forwarding was on.
6. **Checkpoint** (when polkit allows it without a prompt).
7. **Activate** with a bounded wait, then confirm the profile is active on
   the adapter with the gateway address up. On failure, the checkpoint is
   rolled back, or LabLink reconnects the previous connection itself.
8. **Site.** The `field-network` site in your config is added or updated
   with the hotspot's subnet (skip with `--no-site`).

DHCP comes from NetworkManager's own dnsmasq instance, bound to the hotspot
only. LabLink runs no DHCP server, opens no port, and starts no service.

## Preflight findings

Each finding has a level (`block`, `warn`, `info`) and a stable code that
`--json` reports.

| Code | Level | Meaning |
|---|---|---|
| `unsupported-os` | block | macOS (use Internet Sharing) or an OS without NetworkManager support |
| `networkmanager` | block | NetworkManager or `nmcli` missing or not running |
| `permission` | block | Polkit would need administrator authorization |
| `adapter` | block / info | No capable adapter, the named one cannot host WPA2, or which of several is used |
| `security` | block / warn | WPA3 requested on an adapter without SAE (block) or where it cannot be verified (warn) |
| `ssid` | block | An SSID that is empty, too long, or has characters NetworkManager's editor would misread |
| `remote-session` | block / info | An SSH session (this command's, or any inbound connection to port 22 or this session's SSH port, read from `/proc/net/tcp` and `tcp6`) arrives through the adapter, through a tunnel or other virtual interface, or through an interface LabLink cannot identify. No override. Info when it arrives over another physical adapter |
| `disconnect` | warn | The adapter leaves its current network while the hotspot runs |
| `uplink` | warn | That network is this machine's only internet uplink |
| `internet-sharing` | block / warn | Another uplink exists, so shared mode would NAT clients onto it. Blocked unless `--allow-internet-sharing` |
| `forwarding` | block / info | Shared mode enables IPv4 forwarding and this machine routes to other networks (VPN, Docker, LAN). Blocked unless `--allow-routing` |
| `sessions` | info | Other (non-SSH) TCP connections that arrive over the adapter and will drop |
| `equipment` | warn | Registered devices this machine reaches over the adapter (from the daemon), or the daemon is not running so this is unknown |
| `subnet` | block | The requested subnet overlaps an attached network, a route in any table, a container bridge, the CGNAT range, or another LabLink site; or no free default exists |

The default subnet is the first free `10.77.x.0/24` to `10.79.x.0/24`.

### Remote sessions

Starting, stopping or restarting the hotspot changes the adapter, and an
SSH session that rides on it would drop, possibly the one you would need to
undo the change. An SSH connection is not a rollback path, so LabLink
refuses, with no override, when:

- this command runs over SSH (`SSH_CONNECTION`) and that session arrives
  through the adapter;
- that session, or any established inbound SSH connection (port 22, or
  this session's server port, from `/proc/net/tcp` and `/proc/net/tcp6`),
  arrives through a tunnel, VPN, bridge or other virtual interface, which
  may itself ride on the adapter;
- LabLink cannot tell which interface carries it.

A session over another physical adapter (Ethernet, a second Wi-Fi) is
noted, not refused. Run the command at the machine itself. LabLink does not
offer a timed confirm-and-roll-back mode for remote use.

Not detected: sessions over UDP (mosh), and SSH servers on a port other
than 22 unless this command itself runs over that session.

### Internet sharing and forwarding

NetworkManager's shared mode turns on IPv4 forwarding and masquerades the
hotspot subnet. LabLink does not change firewall rules or sysctls itself,
so:

- With another uplink (Ethernet, a second Wi-Fi), clients could reach the
  internet through this machine. That is a blocker unless you pass
  `--allow-internet-sharing` (the **Internet sharing** box in the app).
- With other routed networks (a VPN, Docker bridges, a lab LAN), clients
  could reach them unless your firewall blocks forwarding from the hotspot
  interface. That is a blocker, naming the routes, unless you pass
  `--allow-routing` (the **Routing** box in the app).
- `start` and `status` report whether forwarding was off before and is on
  now. NetworkManager may leave it on after the hotspot stops; `status`
  shows it, and turning it off is your decision.
- If another uplink appears while the hotspot runs (you plug in Ethernet),
  NetworkManager's NAT may start sharing it. `status` prints a warning
  naming it.

## Clients and device states

`lablink hotspot clients` reads the kernel neighbor table for the hotspot
interface, plus NetworkManager's DHCP leases when your user can read them
(they are root-only on many systems). It sends no probes and scans
nothing.

| State | Meaning |
|---|---|
| `discovered-untrusted` | Something with an address on the hotspot. LabLink knows nothing about it and grants it nothing |
| `registered` | A registered device, proven by its pinned host key, whose SSH state is not known yet. Without a key verdict from the daemon, a client stays `discovered-untrusted` even if its name or address matches |
| `ssh-available` | Registered, identity verified, SSH port open |
| `ssh-authenticated` | Registered, identity verified, your SSH login works |
| `ssh-unreachable` | Registered, SSH port closed or filtered |
| `identity-mismatch` | Its host key contradicts the pin: a security stop, as anywhere else in LabLink |
| `disconnected` | A registered device that visited the Field Network and is not there now |

A client becomes a registered device only through the daemon's verdict,
which rests on the device's pinned SSH host key. A matching hostname, MAC
or address never does, and an unknown client is never pinned or trusted
automatically. To register a new device, use `lablink trust` as usual and
compare the fingerprint.

`address_changed` is set when the daemon recorded an address change for the
device since the hotspot started. An address is never a device's identity.

## The `field-network` site

Starting adds a roaming site called `field-network` (or updates the one
roaming site you already have). While it is the active site, devices of
your other sites that have a provable pinned key are "visiting": LabLink
looks for them on the hotspot only, matches them by host key alone, shows
them GRAY rather than RED when absent, and does not count them as evidence
for their home site. They keep their home site, history and trust. No
duplicate entries are created, and nothing new is trusted.

Switching sites never erases devices or pins.

## Restoring the previous network

`lablink hotspot stop` takes the hotspot down and reconnects the connection
the adapter had before (recorded at start). `--no-restore` leaves the
adapter idle. The profile and its password stay for the next start.

If activation fails: with a NetworkManager checkpoint, NetworkManager
restores the adapter itself, even if LabLink is killed mid-way; without
one, LabLink reconnects the previous connection. `start` says which
applied.

If something else stops the hotspot, `status` reports that LabLink's record
and NetworkManager disagree, and believes NetworkManager.

## One adapter or two

LabLink never assumes a second adapter. With one Wi-Fi adapter, starting
disconnects it from its current network for as long as the hotspot runs
(preflight warns, and warns again if that was your only internet uplink).
With two capable adapters, LabLink prefers the free one and nothing drops;
`--interface` chooses explicitly. A USB Wi-Fi adapter with AP support is
the simplest way to keep your normal connection.

## Using it with robots and other machines

- **Jetson (or any Linux robot computer):** join it to the SSID like any
  Wi-Fi network (for example `nmcli device wifi connect <SSID> --ask` on
  the device). If it is already registered and pinned, LabLink recognizes
  it on the hotspot by its host key. LabLink does not configure the
  device for you.
- **MacBook as a client:** join the SSID from the Wi-Fi menu. To register
  it, enable Remote Login and use `lablink trust`.
- **MacBook as the host:** see [macOS](#macos).
- **Several ROS 2 machines:** with all of them on the hotspot, use
  [Robotics mode](ROBOTICS.md) (`lablink ros dds-check <a> --peer <b>`) to
  see whether DDS discovery and data flow work across it. LabLink does not ask
  NetworkManager to isolate clients, but some drivers and adapters do;
  `dds-check --active` shows whether unicast and multicast cross.

Stopping the hotspot cuts every device off from this machine. LabLink does
not assume a robot behaves safely when its network drops. Make sure no
robot is moving or depending on the link before you start or stop it.

## macOS

LabLink does not create a hotspot on macOS. There is no supported public
interface for it, and private frameworks or GUI scripting would be fragile
and would claim support that is not there. `lablink hotspot capabilities`
reads `networksetup -listallhardwareports`, `ifconfig` and the Internet
Sharing preferences, then tells you:

- whether the Mac has a second network port to share from (Internet
  Sharing over Wi-Fi needs one, such as Ethernet, a USB adapter, or an
  iPhone hotspot), and
- the steps in System Settings > General > Sharing > Internet Sharing,
  including choosing WPA2/WPA3 Personal and a password.

Two macOS limits that LabLink cannot change: Internet Sharing always
shares the Mac's internet connection with every client (NAT), so it cannot
run offline-only; and its subnet is fixed by macOS (192.168.2.0/24 by
default), which may collide with a site network.

`preflight` and `start` refuse on macOS (exit 7) with the same guidance.
Clients that join a Mac's Internet Sharing network can still be checked
with `lablink status` and `lablink ros` from either machine.

## Privileges and security

- No root, no `sudo`, no setuid helper, no new daemon or listening port.
  Every change is a NetworkManager call that polkit checks for your user.
- The password never appears in a process argument list, a log, LabLink's
  files, `--json` output, support bundles or error messages. It is shown
  only on an explicit `lablink hotspot password` (or **Show password** in
  the app, which forgets it after the next action).
- WEP and open networks are refused at the command line and again after
  reading the profile back.
- Internet sharing is off unless you ask. LabLink does not change firewall
  rules, sysctls or routes.
- Hotspot clients get nothing from LabLink: there is no API to talk to,
  and an unknown client is never trusted. A client can still reach any
  service this machine exposes on all interfaces (SSH, for example), as
  on any network you join. Check what listens before you start.

The full threat model is in [THREAT_MODEL.md](THREAT_MODEL.md#field-network-and-robotics-mode).

## Limitations

- Linux needs NetworkManager. Hosts that use only systemd-networkd,
  ConnMan or `wpa_supplicant` directly are not supported.
- Many laptop Wi-Fi chips support AP mode only on some channels, or not
  while also connected as a client. A second adapter avoids both.
- WPA3 support often cannot be verified before activation; WPA2 is the
  default for that reason. Some older clients cannot join WPA3.
- Client discovery is passive. A client that has not sent traffic yet may
  not appear for a few seconds.
- The remote-session guard does not see UDP sessions (mosh) or SSH
  servers on a non-standard port that this command does not run over.
- Older LabLink builds reject a config written by this one (the new
  `features` and roaming-site keys). Downgrading needs those keys removed.
- DHCP lease details (hostnames) appear only when your user can read
  NetworkManager's lease file.
- Forwarding that NetworkManager enables may stay enabled after stop.

## Example: a laptop, a Jetson and a second ROS machine

This is the intended flow. The steps are not a recorded session; run them
yourself and keep what you observe.

1. On the laptop, check what it can do:
   `lablink hotspot capabilities`. Look for an adapter with `access point yes`
   and `WPA2 yes`.
2. Turn the feature on: `lablink feature enable field-network`.
3. Make sure no robot is moving or depending on the laptop's current
   network.
4. Run `lablink hotspot preflight` at the laptop (not over SSH). Read every
   warning. If it refuses because of another uplink, unplug it or decide
   to pass `--allow-internet-sharing`.
5. Start it: `lablink hotspot start`. Accept the warnings you understand.
   Note the SSID and subnet it prints.
6. Show the password with `lablink hotspot password` and join the Jetson
   and the second machine to the SSID.
7. Watch them arrive: `lablink hotspot clients`. Registered, pinned
   devices show as `ssh-available` or `ssh-authenticated`; anything else
   stays `discovered-untrusted`.
8. Connect by name as usual: `lablink ssh jetson-a`.
9. With [Robotics mode](ROBOTICS.md) on, check ROS 2 across the hotspot:
   `lablink ros dds-check jetson-a --peer workstation`, and add `--active`
   when nothing is moving and you want proof that data flows.
10. Stop it and get your network back: `lablink hotspot stop`. Check that
    `lablink hotspot status` says it is stopped and shows the forwarding
    state.

## Troubleshooting

| Symptom | Check |
|---|---|
| `permission` blocker | `nmcli general permissions`: `network-control` and `settings.modify.system` must say `yes` |
| Activation fails or times out | The adapter may not support AP mode on the chosen band while connected; try a second adapter, or stop the client connection first |
| Clients cannot join a WPA3 hotspot | Use the default `--security wpa2` |
| Clients join but get no address | `journalctl -u NetworkManager` for dnsmasq errors; another DHCP server on the machine may hold port 67 |
| A registered device stays `discovered-untrusted` | Its pin is not provable yet. `lablink status <name>` and `lablink doctor <name>` explain why |
| `status` says out of sync | Something else stopped or started the profile; `lablink hotspot stop` reconciles |
