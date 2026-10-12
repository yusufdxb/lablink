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
| `capabilities` and `preflight` on a real Linux host (NetworkManager, one Wi-Fi adapter, Ethernet uplink, a VPN and Docker) | Run read-only with an earlier build, which refused to start because Ethernet would be NATed. The isolated default replaced that refusal; preflight with this build has not been run on that host |
| Start, WPA2 and WPA3 authentication, DHCP, client-to-host and client-to-client traffic, stop and restore, restart, password rotation, activation failure with and without a checkpoint, NetworkManager rolling a checkpoint back after LabLink was killed, isolation (IPv4 and IPv6, against a simulated Ethernet uplink, LAN and VPN, including routes, rules and a VPN added after start), DNS refusal, the `lablinkd` watchdog, NetworkManager stopped or killed under a running hotspot, unprivileged use with polkit grants, `forget`, downgrade | **Simulation only.** Real NetworkManager, `wpa_supplicant`, `hostapd`, `dnsmasq` and polkit driving simulated radios (Linux `mac80211_hwsim`) inside network-isolated containers, with simulated LAN, internet and VPN networks behind the host. See [Simulated validation](#simulated-validation) and [Isolation evidence](#isolation-evidence) |
| Starting a hotspot on a real adapter, a real client joining, real DHCP leases, real rollback, isolation on real hardware | **Not tested.** No hotspot has been started on a real adapter during development. Simulated radios do not show driver, firmware, channel or regulatory limits |
| macOS | **Not tested on a Mac.** Only the parsers and guidance are tested, against recorded command output |

Treat the Field Network as experimental until you have run the
[example](#example-a-laptop-a-jetson-and-a-second-ros-machine) on your own
hardware. The simulated runs do not change that.

## Requirements (Linux)

- NetworkManager running, with `nmcli` on a trusted `PATH` directory.
- A Wi-Fi adapter whose driver supports access-point mode and WPA2
  (`lablink hotspot capabilities` lists each adapter's support for access
  point, WPA2, WPA3, 2.4 GHz and 5 GHz). WPA3
  needs SAE in AP mode, which LabLink can only verify when `iw` is
  installed.
- Polkit permissions for your user, below. LabLink never asks for root,
  never runs `sudo`, and never installs a privileged helper. If polkit
  says `auth` (would prompt) or `no`, preflight refuses and names the
  missing permission.
- For isolated mode (the default): a one-time dnsmasq drop-in installed by
  an administrator, and `lablinkd` running ([Isolation](#isolation)).

### Permissions

| NetworkManager polkit action | Needed for | Default for a local active session |
|---|---|---|
| `org.freedesktop.NetworkManager.network-control` | Bringing the hotspot (and the previous connection) up and down; `lablinkd` stopping it | yes (also inactive sessions; `auth_admin` with no session) |
| `org.freedesktop.NetworkManager.settings.modify.own` | Creating or changing a profile restricted to your user (first start, password changes) | yes (`auth_self_keep` with no session) |
| `org.freedesktop.NetworkManager.wifi.share.protected` | Activating a WPA2/WPA3 access point | yes (`no` for inactive sessions or none) |
| `org.freedesktop.NetworkManager.checkpoint-rollback` | Optional: NetworkManager's own rollback if activation does not complete | `auth_admin_keep` (so LabLink skips it) |

`nmcli general permissions` shows what your user has. A user at the
machine's desktop normally has the first three. `lablinkd` as a systemd
user service gets the same answers while that desktop session is active.
Over SSH, or with no session, polkit uses the stricter "any" column and
preflight refuses.

To also get the checkpoint, grant just that action to just your user. On
polkit 0.105 (Ubuntu 22.04 and older), as root, in
`/etc/polkit-1/localauthority/50-local.d/50-lablink-field-network.pkla`:

    [LabLink Field Network checkpoint for alice]
    Identity=unix-user:alice
    Action=org.freedesktop.NetworkManager.checkpoint-rollback
    ResultAny=no
    ResultInactive=no
    ResultActive=yes

On polkit 0.106 and later (JavaScript rules: Fedora, Arch, Debian 12, Ubuntu 23.10 and later), in
`/etc/polkit-1/rules.d/50-lablink-field-network.rules`:

    polkit.addRule(function (action, subject) {
        if (action.id == "org.freedesktop.NetworkManager.checkpoint-rollback" &&
            subject.user == "alice" && subject.local && subject.active) {
            return polkit.Result.YES;
        }
    });

The simulated runs exercised the `.pkla` form (with all four actions, as
`ResultAny`, because the test container has no login sessions); the
JavaScript form has not been tested.

Do not grant `settings.modify.system`, do not add your user to a group
with blanket NetworkManager rights, and do not run the app as root: none
of that is needed. Checkpoint rollback covers every device listed in the
checkpoint, which LabLink limits to the hotspot adapter.

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
`--allow-dns-relay`.
`start` also takes `--yes` (accept warnings without asking; blockers are
never accepted), `--password-stdin` and `--no-site`. Every command takes
`--json`. Exit codes follow the rest of LabLink: 0 success, 1 failure, 2
usage, 7 refused (a preflight blocker, the feature is off, the findings
changed while you were answering the prompt, or `stop`/`restart` would cut
an SSH session).

In the app, the **Field Network** tab shows the same capabilities, status
and clients. **Check** runs preflight for the settings in the form;
**Start** is enabled only after a check of exactly those settings found no
blocker and you ticked every warning. The **Internet sharing** box
switches to the sharing mode; **DNS relay** accepts the DNS relay
blocker. The app checks again just before
starting and refuses if any warning's text changed. With the feature off,
the tab still shows a running hotspot's status and a **Stop** button.

## What start does

1. **Preflight** (read-only). Blockers stop here; warnings must be accepted.
2. **Profile.** LabLink creates one NetworkManager profile, "LabLink Field
   Network" (autoconnect off), or updates the one it made before. Mode
   `ap`; key management `wpa-psk` (WPA2, CCMP) or `sae` (WPA3, PMF
   required); IPv4 `shared`, IPv6 disabled. Unless you chose internet
   sharing, the profile also carries two routing rules,
   `priority 0 iif <adapter> prohibit` for IPv4 and for IPv6
   ([Isolation](#isolation)). The profile belongs to your
   user (`connection.permissions user:<you>`): other local users cannot
   see, activate, edit or read the password of it, and creating it needs
   polkit's `settings.modify.own`, not `settings.modify.system`. LabLink
   refuses to start if it cannot read a plain login name for your user.
3. **Password.** A generated 24-character password (120 bits from the OS
   random source, no look-alike characters), or one you pipe in with
   `--password-stdin`. It goes to `nmcli connection edit` on stdin, never
   on a command line, and is stored in NetworkManager's root-only secret
   store. LabLink keeps only the profile's UUID.
4. **Verify.** The profile is read back. Anything other than WPA2/WPA3 with
   a password (open, WEP, a missing key), a password not kept in
   NetworkManager's own store, a profile visible to anyone but you
   (no permissions, or other users listed), or missing or different
   isolation rules is refused and never activated.
5. **Record.** `fieldnet.json` (mode 0600, in LabLink's state directory)
   notes the previous connection on the adapter, the subnet and whether
   IPv4 forwarding was on.
6. **Checkpoint** (when polkit allows it without a prompt).
7. **Activate** with a bounded wait, then confirm the profile is active on
   the adapter with the gateway address up, and (isolated mode) that the
   kernel holds both isolation rules first in line. On failure, the
   checkpoint is rolled back, or LabLink stops the hotspot and reconnects
   the previous connection itself.
8. **Site.** The `field-network` site in your config is added or updated
   with the hotspot's subnet (skip with `--no-site`).

DHCP comes from NetworkManager's own dnsmasq instance, bound to the hotspot
only. LabLink runs no DHCP server, opens no port, and starts no service.
While the hotspot runs, `lablinkd` re-checks the isolation every two
seconds ([Isolation](#isolation)).

## Preflight findings

Each finding has a level (`block`, `warn`, `info`) and a stable code that
`--json` reports.

| Code | Level | Meaning |
|---|---|---|
| `unsupported-os` | block | macOS (use Internet Sharing) or an OS without NetworkManager support |
| `networkmanager` | block | NetworkManager or `nmcli` missing or not running |
| `permission` | block | Polkit would need administrator authorization for `network-control`, `settings.modify.own` (first start) or `wifi.share.protected` |
| `adapter` | block / info | No capable adapter, the named one cannot host WPA2, or which of several is used |
| `security` | block / warn | WPA3 requested on an adapter without SAE (block) or where it cannot be verified (warn) |
| `ssid` | block | An SSID that is empty, too long, or has characters NetworkManager's editor would misread |
| `remote-session` | block / info | An SSH session (this command's, or any inbound connection to port 22 or this session's SSH port, read from `/proc/net/tcp` and `tcp6`) arrives through the adapter, through a tunnel or other virtual interface, or through an interface LabLink cannot identify. No override. Info when it arrives over another physical adapter |
| `disconnect` | warn | The adapter leaves its current network while the hotspot runs |
| `uplink` | warn | That network is this machine's only internet uplink |
| `isolation` | block / info | Block: the isolation cannot be guaranteed (another priority-0 routing rule, unreadable rules, an interface stacked on the adapter, the adapter in a bridge, an XDP program or a tc ingress/clsact qdisc on it, or unreadable qdiscs). No override. Info: the networks the rule keeps clients off |
| `dns-relay` | block / warn | The hotspot's DNS server would forward clients' queries to this machine's resolvers (no `no-resolv` drop-in), or the drop-ins cannot be read. Blocked unless `--allow-dns-relay` |
| `internet-sharing` | warn | Sharing mode only: clients will reach the internet through the named uplinks |
| `forwarding` | warn / info | Sharing mode: every routed network (VPN, Docker, LAN) is reachable. Isolated mode: shared mode will turn IPv4 forwarding on (warn when it was off; it stays on after stop) |
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

### Isolation

Isolated mode is the default. Hotspot clients reach this machine and each
other, and nothing else: not the internet, the LAN, a VPN or a container
network behind this machine, whether it existed at start or appears later.

How. NetworkManager's shared mode still provides DHCP (its own dnsmasq)
and still turns on IPv4 forwarding and NAT. The profile adds two routing
rules that NetworkManager installs when it activates the hotspot and
removes when it deactivates it:

    priority 0 iif <adapter> prohibit      (IPv4)
    priority 0 iif <adapter> prohibit      (IPv6)

The kernel consults routing rules in priority order, and `0: lookup local`
(this machine's own addresses) comes first. A packet that arrives from the
hotspot and is for this machine is delivered by `lookup local`. Any other
packet from the hotspot hits the `prohibit` rule before any routing table
is read, so it cannot be forwarded: the sender gets an ICMP "administratively
prohibited" error. This happens in routing, before the firewall's FORWARD
chain and NAT, so firewall rule order, a firewall that accepts all
forwarding, `MASQUERADE` rules, `ip_forward=1` and new routes in any table
do not matter. A rule added later at the same priority sorts after
LabLink's. IPv6 is also disabled on the adapter (the IPv6 rule is the
guarantee; that is a second layer).

What LabLink checks and when:

- **Preflight** refuses (no override) if the isolation cannot be
  guaranteed: an existing priority-0 rule other than `lookup local`
  (it would sort before LabLink's), rules it cannot read, an interface
  stacked on the adapter (macvlan, VLAN), the adapter in a bridge, an XDP
  program or a tc ingress/clsact qdisc on it, or qdiscs it cannot read.
- **Start, restart** read the profile back (the rules must be exactly
  LabLink's) and, after activation, the kernel's rules: each family's rule
  must be the first rule after `lookup local`. Otherwise LabLink stops the
  hotspot (or NetworkManager rolls back the checkpoint) and reports a
  failure.
- **While it runs**, `lablinkd` repeats the check every two seconds and
  stops the hotspot (`nmcli connection down`) when it fails, logging why.
  It does not spare SSH sessions over the hotspot: isolation comes first.
  Without a running `lablinkd`, nothing watches; `status` still checks
  when you run it.
- **`status`** reports `isolation verified` and the networks kept off, or
  `ISOLATION NOT VERIFIED` with the reason.

DNS. NetworkManager's dnsmasq for the hotspot forwards client queries to
this machine's resolvers by default, which is a path to the outside
(queries and answers, so also a covert channel). LabLink refuses an
isolated start unless a NetworkManager drop-in stops that. Install it once,
as an administrator (it applies to every NetworkManager shared connection
on this machine):

    echo no-resolv | sudo tee /etc/NetworkManager/dnsmasq-shared.d/lablink-no-upstream.conf

It takes effect at the next activation. Clients then get `REFUSED` for
names on the outside. `--allow-dns-relay` accepts forwarding instead.

What it does not cover:

- Clients reach every address of this machine, not just the hotspot
  gateway (`lookup local` includes the Ethernet, VPN and Docker
  addresses). Any service listening on all interfaces is reachable from
  the hotspot, as on any network you join.
- IPv4 forwarding stays on after the hotspot stops if shared mode turned
  it on; `start` and `status` say so.
- Root can delete the rules. `lablinkd` then stops the hotspot within
  about two seconds plus the time `nmcli` takes; packets sent in that
  window are forwarded (the simulated runs measured it, see below).
- When NetworkManager stops cleanly it removes the rules and tears the
  hotspot down. In one simulated run 2 small TCP segments (40 bytes, from
  connections already open) were forwarded during that teardown; a second
  run forwarded none. If NetworkManager is killed, the rules and the
  access point stay and isolation holds; restarting NetworkManager then
  may fail to bring the hotspot back while its orphaned dnsmasq holds the
  address (reboot or stop that dnsmasq as root).

### Internet sharing

`--allow-internet-sharing` (the **Internet sharing** box in the app) is a
separate mode: no isolation rules, NetworkManager's NAT onto every uplink,
and clients can reach every network this machine routes to. Preflight
warns, naming the uplinks and routed networks, and `status` warns about
routes that appear later. LabLink does not add firewall rules in this mode.

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

A client known only from a DHCP lease, with no current neighbor entry, is
marked "DHCP lease only: may have left". Leases outlive the client.

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
and NetworkManager disagree, and believes NetworkManager. The same report
appears when a start was interrupted before LabLink recorded it; with a
checkpoint, NetworkManager restores the adapter within about two minutes.

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
- The profile is restricted to your user, so other local accounts cannot
  list it, bring it up or down, or read its password through
  NetworkManager. Root can.
- Hotspot clients are isolated unless you ask for internet sharing: the
  only change beyond the hotspot itself is two routing rules carried by
  LabLink's NetworkManager profile, which NetworkManager adds and removes
  with it. LabLink does not change firewall rules or sysctls.
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
  `features` and roaming-site keys). See
  [Downgrading and recovery](#downgrading-and-recovery).
- DHCP lease details (hostnames) appear only when your user can read
  NetworkManager's lease file.
- Forwarding that NetworkManager enables may stay enabled after stop.
- Isolated mode needs a root-installed dnsmasq drop-in once
  ([Isolation](#isolation)), and `lablinkd` running to watch the rules.

## Simulated validation

These results come from simulated radios (Linux `mac80211_hwsim`), not a
real Wi-Fi adapter. They exercise the real NetworkManager, `wpa_supplicant`,
`hostapd` and `dnsmasq` code paths, but not drivers, firmware, channels,
regulatory rules, radio range or interference. They do not make the Field
Network proven on hardware.

The setup: NetworkManager 1.36 with LabLink in one network-isolated
container owning one simulated radio; a client (`wpa_supplicant` and a DHCP
client) in a second container owning the other; a third container
simulating a LAN, the internet and a VPN behind the host. No physical
interface was touched.

| Behavior | Observed |
|---|---|
| Start | WPA2 profile created and verified (CCMP, PMF off for older clients, password only in NetworkManager's root-only keyfile), owned by the starting user |
| Authentication | A wrong password was rejected by the access point; the right one joined |
| DHCP and client to host | Client leased an address from the hotspot subnet; ping and TCP to this machine worked |
| Client to client | Two clients exchanged TCP and UDP through the access point; a capture showed the frames relayed and encrypted |
| Stop, restart, password rotation | Stop reconnected the previous network. Restart kept the password and the client rejoined. After `password --rotate` and a restart, the old password was rejected and the new one accepted |
| Activation failure | With a checkpoint, NetworkManager restored the previous network. Without one, LabLink reconnected it |
| LabLink killed after activation | NetworkManager rolled the checkpoint back by itself, in under two minutes |
| Remote-session guard | `stop` refused while an SSH session arrived over the hotspot |
| Isolation | See [Isolation evidence](#isolation-evidence) |
| WPA3 | A WPA3 (SAE, PMF required) hotspot accepted a WPA3 client; a WPA2-only client could not join |
| Another local user | Could not list the profile or read its password |
| `forget` | Refused without `--yes`; deleted the profile after stop |

### Isolation evidence

Same simulated setup, run with `tests/hwsim/run.sh` (see
[TESTING.md](TESTING.md)) on 2026-10-12. The host side of the simulation
is NetworkManager-managed: an Ethernet uplink with a default route (IPv4
and IPv6), a lab LAN, and, where noted, a WireGuard VPN added later with a
policy rule. A container behind those networks counts, in its raw table,
every probe packet that reaches it. Each probe round is TCP and ICMP from a
hotspot client to seven addresses: the uplink gateway, an internet host,
the LAN, the VPN peer, and three IPv6 equivalents. The script compared
the host's links, addresses, rules, routes and modules before and after
every run; they were identical each time.

| Case | Probe packets that reached other networks |
|---|---|
| Shared mode without the rules (positive control, proves the counter sees a leak) | 37 (IPv4); 55 with IPv6 enabled |
| Rules in place, raw NetworkManager profile | 0 |
| After a WireGuard VPN with a policy rule appeared | 0 |
| After new routes (more specific, other table, new default) | 0 |
| After hostile priority-0 rules were added | 0 |
| After toggling forwarding sysctls and re-enabling IPv6 on the hotspot | 0 |
| After a blanket `MASQUERADE` rule | 0 |
| Rules deleted by root (negative control) | 55 |
| `lablink hotspot start` as an unprivileged user (default, isolated) | 0 |
| Same, after a VPN, new routes, a new table and a hostile priority-0 rule | 0 |
| `lablink hotspot start --allow-internet-sharing` (positive control) | 37 |
| NetworkManager stopped (SIGTERM): hotspot torn down, rules removed | 0 (2 TCP segments in an earlier run) |
| NetworkManager killed (SIGKILL): rules and access point stay; clients get ICMP "administratively prohibited" | 0, and 0 after the restart |

In the isolated cases the client still reached this machine (on the
hotspot gateway and on its uplink address) and the other client (ICMP,
TCP and IPv6 link-local), and DNS queries for outside names got `REFUSED`
with the drop-in. Without the drop-in, the client resolved an outside name
through the host, which is why `start` requires it. After `stop`, no
`prohibit` rule was left.

`lablinkd`'s watchdog, with a client sending about 100 IPv4 UDP packets a
second to the uplink, after root broke isolation:

| Breach | Hotspot down after | Flood packets forwarded meanwhile |
|---|---|---|
| IPv4 rule deleted | 1.87 s | 142 |
| IPv6 rule deleted | 1.18 s | 0 (the flood was IPv4 only, so this says nothing about IPv6 leakage) |
| tc ingress qdisc added on the adapter | 1.18 s | 0 |

Activation window: eight activations of the isolated profile while a
client tried to flood. NetworkManager installed both rules about 16 ms
after activation started. No client packet reached the host or another
network in any run, but the client also never got a packet to the host
during an activation, so these runs do not prove that the rules beat the
first client packet. The first activation failed ("IP configuration could
not be reserved") because the dnsmasq orphaned by the SIGKILL case still
held the address.

Permissions, as an unprivileged user under polkit 0.105: without grants,
`network-control`, `settings.modify.own` and `checkpoint-rollback` needed
authentication and `wifi.share.protected` was refused, and preflight
listed them as blockers (exit 7). With the four-action `.pkla` in
[Permissions](#permissions), preflight passed, `start` created a
checkpoint and verified isolation, another user saw no profile and could
not stop the hotspot (`uid 1001 has no permission`), and `stop` then
`forget --yes` left no LabLink profile.

## Downgrading and recovery

A LabLink build without the Field Network (0.3.1 and earlier) refuses a
config file that has the new keys, with an error such as
``preferences: unknown field `features` `` or
``sites[2]: unknown field `roaming` ``, and its daemon does not start.
Nothing else needs migrating: no daemon database or cache format changed,
and the old build ignores `fieldnet.json`.

Before installing the older build:

1. Stop the hotspot and get your network back: `lablink hotspot stop`.
2. If you will not use it again, delete the profile and its password from
   NetworkManager: `lablink hotspot forget --yes`. (This needs the feature
   on, so do it before step 3. Afterwards,
   `nmcli connection delete "LabLink Field Network"` does the same.)
3. Turn the features off, which removes the `features` key when none is
   left on: `lablink feature disable field-network` and
   `lablink feature disable robotics`.
4. Remove the roaming site: delete the `field-network` site from
   `config.yaml`, or at least its `roaming: true` line. LabLink keeps no
   other roaming state.
5. Check the file with the older build before relying on it:
   `lablinkd --check-config`.

Alternatively, restore a backup. Every time LabLink rewrites `config.yaml`
it saves the previous version next to it as `config.yaml.bak-<UTC time>`;
the oldest backup written after upgrading is the file the older build last
accepted. Copy it over `config.yaml`, check it, and redo any later edits by
hand.

`fieldnet.json` in LabLink's state directory can be left or deleted; the
older build does not read it. A NetworkManager profile that you did not
`forget` stays in NetworkManager, usable only by your user, and can be
deleted with `nmcli` at any time.

If an older daemon already refuses to start, do steps 3 and 4 by editing
`config.yaml` (remove the `features:` lines under `preferences:` and the
roaming site), or restore the backup, then restart it.

Upgrading again needs nothing: the newer build reads the older config.
If you removed only the `roaming: true` line, put it back (or delete the
site) before the next `lablink hotspot start`, which refuses to reuse a
`field-network` site that is not roaming.

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
   warning. Another uplink (Ethernet) stays up and stays off limits to
   clients; pass `--allow-internet-sharing` only if you want clients on it.
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
| `permission` blocker | `nmcli general permissions`: `network-control`, `settings.modify.own` and `wifi.share.protected` must say `yes`. NetworkManager's default policy grants `wifi.share.protected` only to a local, active session; see [Permissions](#permissions) |
| Activation fails or times out | The adapter may not support AP mode on the chosen band while connected; try a second adapter, or stop the client connection first |
| Clients cannot join a WPA3 hotspot | Use the default `--security wpa2` |
| Clients join but get no address | `journalctl -u NetworkManager` for dnsmasq errors; another DHCP server on the machine may hold port 67 |
| A registered device stays `discovered-untrusted` | Its pin is not provable yet. `lablink status <name>` and `lablink doctor <name>` explain why |
| `status` says out of sync | Something else stopped or started the profile, or a start was interrupted; `lablink hotspot stop` reconciles |
| `isolation` blocker | Preflight names the cause: remove the other priority-0 rule, the stacked interface, bridge, XDP program or ingress qdisc, or use the sharing mode knowingly |
| `dns-relay` blocker | Install the `no-resolv` drop-in ([Isolation](#isolation)) |
| `lablinkd` stopped the hotspot | Its log names the failed check. Something removed a rule or attached a bypass; find out what before starting again |
| `status` warns that clients can be routed somewhere | Sharing mode only: a VPN, container network or uplink appeared after start. Stop the hotspot, or block forwarding from the hotspot interface in your firewall |
