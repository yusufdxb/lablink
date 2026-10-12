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
- For isolated mode (the default): the field filter, a NetworkManager
  dispatcher script that an administrator installs once (it needs `nft`),
  a Wi-Fi adapter named `wl*`, and `lablinkd` running
  ([Isolation](#isolation)).

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
IPv4, /22 to /28), `--security wpa2|wpa3`, `--allow-internet-sharing`.
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
switches to the sharing mode. The app checks again just before
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
7. **Arm** (isolated mode): disconnect the adapter if it is in use and
   wait up to five seconds for the field filter to arm it. An adapter
   that is not armed is never turned into an access point.
8. **Activate** with a bounded wait, then confirm the profile is active on
   the adapter with the gateway address up, and (isolated mode) that the
   adapter is still armed and the kernel holds both isolation rules first
   in line. On failure, the
   checkpoint is rolled back, or LabLink stops the hotspot and reconnects
   the previous connection itself.
9. **Site.** The `field-network` site in your config is added or updated
   with the hotspot's subnet (skip with `--no-site`).

DHCP comes from NetworkManager's own dnsmasq instance, bound to the hotspot
only (its DNS port is refused by the field filter). LabLink runs no DHCP
server, opens no port, and starts no service. While the hotspot runs,
`lablinkd` re-checks the isolation every two seconds
([Isolation](#isolation)).

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
| `isolation` | block / info | Block: the isolation cannot be guaranteed (the field filter not installed, not loaded or not checkable, an adapter not named `wl*`, another priority-0 routing rule, unreadable rules, an interface stacked on the adapter, the adapter in a bridge, an XDP program or a tc ingress/clsact qdisc on it, or unreadable qdiscs). No override. Info: the networks kept off |
| `exposure` | info | What clients can reach on this machine: the hotspot address, for DHCP, ICMP and the filter's services |
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

Isolated mode is the default. Hotspot clients reach each other and, on
this machine, only the hotspot address and a short list of services:
DHCP, ICMP, SSH (TCP 22), mDNS (UDP 5353) and ROS 2 DDS for domain 0 (UDP
7400-7649). Nothing is forwarded: not to the internet, the LAN, a VPN or a
container network behind this machine, whether it existed at start or
appears later.

Two independent layers do this. Both are kernel state, so both stay in
force when NetworkManager, `lablinkd` or LabLink stop or crash.

**1. The field filter** (prevention). A NetworkManager dispatcher script
that an administrator installs once
([packaging/networkmanager/90-lablink-field-filter](../packaging/networkmanager/90-lablink-field-filter)).
It keeps one nftables table, `inet lablink_field`, with hooks at priority
-300 (before NAT and the usual firewall tables). Every Wi-Fi interface
(name `wl*`) is *armed* unless NetworkManager runs an ordinary connection
on it. Armed means:

- nothing is forwarded from or to it, IPv4 or IPv6 (a `drop` in a
  netfilter hook is final, whatever other tables accept);
- this machine accepts from it only packets addressed to that interface's
  own address, its broadcast or a multicast group (the kernel's `fib`
  lookup, so the Ethernet, VPN and Docker addresses of this machine are
  dropped), and of those only established replies, ICMP, IGMP, DHCP and
  the listed services. Everything else is refused with ICMP
  "administratively prohibited", DNS included.

The script opens an interface at `pre-up` of a connection without
LabLink's isolation rule (joining an ordinary Wi-Fi network) and arms it
again at `pre-down` and `down`. So the adapter is armed while
NetworkManager disconnects it before the hotspot starts, while the access
point accepts its first clients, the whole time it runs, through
`restart`, and after it stops. `lablink hotspot start` checks that the
adapter is armed before it asks NetworkManager to start the access point
and refuses otherwise, so a hotspot never runs on an open adapter.

**2. Routing rules** (prevention, independent of the firewall). The
profile carries `priority 0 iif <adapter> prohibit` for IPv4 and IPv6,
which NetworkManager installs at activation and removes at deactivation.
A packet from the hotspot for any other network hits the rule before any
routing table is read. The rules sit at priority 0 on purpose: a rule
added later without a priority (as `wg-quick` does) lands just before
the second rule in the list, so at any other priority it would sort
ahead of LabLink's. A rule added later at priority 0 sorts after it.
Preflight refuses if another priority-0 rule already exists. If the
`lookup local` rule is moved off priority 0, the prohibit rule comes
first and blocks clients from this machine too: that fails closed. IPv6
is also disabled on the adapter.

LabLink runs unprivileged and cannot read nftables, so it probes the
filter: a UDP datagram to 192.0.0.8 port 47977 from a socket bound to the
adapter is dropped by the filter's output chain while the adapter is
armed (`send` fails with `EPERM` before anything leaves), and a control
datagram to port 47976 must go out. The same pair on the loopback
interface tells whether the table is loaded. While `lablinkd` watches,
the control datagram is a real packet on the hotspot every two seconds (an
ARP request for 192.0.0.8, an address nothing answers). The probe proves
that the table is loaded and the adapter armed; it cannot prove that root
has not edited the table's other rules.

Install the filter once, as an administrator:

    sudo install -o root -g root -m 755 packaging/networkmanager/90-lablink-field-filter /etc/NetworkManager/dispatcher.d/
    sudo ln -sf ../90-lablink-field-filter /etc/NetworkManager/dispatcher.d/pre-up.d/
    sudo ln -sf ../90-lablink-field-filter /etc/NetworkManager/dispatcher.d/pre-down.d/
    sudo /etc/NetworkManager/dispatcher.d/90-lablink-field-filter load

It needs `nft` (nftables) and only adds its own table, so it leaves
iptables, Docker and Tailscale rules alone (in simulation it ran beside
iptables NAT and FORWARD rules and a Docker-style published port). It
does not restart NetworkManager. It must be loaded again after a reboot: the next
NetworkManager event on any interface loads it, and LabLink refuses to
start while it is not loaded. To change the allowed services, edit
`FIELD_TCP` and `FIELD_UDP` at the top of the installed script and run it
with `load`. ROS 2 DDS uses UDP 7400 + 250 x domain and the 250 ports after
it, so domain 67 needs `24150-24399`. Remove it with `unload`, then delete
the file and both links.

What LabLink checks and when:

- **Preflight** refuses (no override) if the filter is not installed or
  not loaded, the adapter's name does not start with `wl`, or the rules
  cannot be guaranteed: an existing priority-0 rule other than `lookup
  local`, rules it cannot read, an interface stacked on the adapter
  (macvlan, VLAN), the adapter in a bridge, an XDP program or a tc
  ingress/clsact qdisc on it, or qdiscs it cannot read. When nothing is
  wrong it states the exposure: the hotspot address and the filter's
  services.
- **Start** disconnects the adapter first if it is in use, waits up to
  five seconds for the filter to arm it, and only then activates the
  hotspot. After activation it requires the profile active, the adapter
  armed and each family's rule first after `lookup local`. Otherwise
  NetworkManager rolls the checkpoint back, or LabLink stops the hotspot
  and reconnects the previous network, and `start` fails.
- **Restart** checks the same after re-activation.
- **While it runs**, `lablinkd` repeats the check every two seconds and
  stops the hotspot (`nmcli connection down`) when it fails, logging why.
  That is recovery, not prevention: it notices a removed filter or rule
  seconds later. The filter and the rules are what keep packets in.
  Without a running `lablinkd`, nothing watches; `status` still checks
  when you run it.
- **`status`** reports `isolated: field filter armed, IPv4 and IPv6 rules
  verified` or `ISOLATION NOT VERIFIED` with the reason.

| Failure | What keeps clients in | Recovery |
|---|---|---|
| `lablinkd` crashes, or the user logs out | The filter and the rules (kernel state) | None until `lablinkd` runs again; `status` checks when run |
| NetworkManager stops cleanly | It tears the hotspot down; the filter stays armed | None needed |
| NetworkManager is killed | The access point, the filter and the rules stay | Restarting NetworkManager may not bring the hotspot back while the orphaned dnsmasq holds the address; stop that dnsmasq as root |
| Root deletes a rule | The filter | `lablinkd` stops the hotspot |
| Root unloads the filter | The rules | `lablinkd` stops the hotspot |
| Root deletes both | Nothing: packets are forwarded until `lablinkd` stops the hotspot | `lablinkd`, about two seconds plus the time `nmcli` takes |
| A VPN, route, interface or Docker network appears later | The filter and the rules | Not needed |

DNS. NetworkManager's dnsmasq for the hotspot would forward client queries
to this machine's resolvers (a path to the outside, and a covert channel).
The filter refuses port 53 from the hotspot, so clients get no DNS at
all; use addresses or mDNS `.local` names. An earlier build asked for a
`no-resolv` file in `/etc/NetworkManager/dnsmasq-shared.d/`. That
directory is read by the dnsmasq of *every* NetworkManager shared
connection on the machine, including ones LabLink did not make, so the
file changed them too. It is no longer needed; delete it if you installed
it and nothing else wants it.

What it does not cover:

- The listed services are reachable from every hotspot client, and SSH
  then is exactly as exposed as on any network you join. Keep password
  logins off. Remove a service from the script if you do not need it.
- Root can edit or remove the filter and the rules. The probe shows the
  table is loaded and the adapter armed, not that its rules are intact.
- An adapter whose name does not start with `wl` is not covered;
  preflight refuses it.
- IPv4 forwarding stays on after the hotspot stops if shared mode turned
  it on; `start` and `status` say so. The filter keeps the adapter armed
  regardless.
- Client-to-client traffic is relayed by the access point in the driver
  and never reaches the filter, by design.

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
- Hotspot clients are isolated unless you ask for internet sharing. The
  field filter is the one root-installed piece; LabLink itself only adds
  two routing rules to its NetworkManager profile, which NetworkManager
  adds and removes with the hotspot. LabLink does not change firewall
  rules or sysctls.
- Hotspot clients get nothing from LabLink: there is no API to talk to,
  and an unknown client is never trusted. On this machine they reach only
  the hotspot address, and there only DHCP, ICMP and the filter's
  services (SSH, mDNS, DDS domain 0 by default). Services that listen on
  all interfaces but are not listed (a database, a web UI, Tailscale's
  port) are refused.

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
- Isolated mode needs the field filter installed once by an
  administrator ([Isolation](#isolation)), and `lablinkd` running to
  recover from a filter or rule that root removed.
- Clients get no DNS from the hotspot.
- Once installed, the filter arms every Wi-Fi interface named `wl*` that
  NetworkManager does not run an ordinary connection on, including one
  managed by another tool (`wpa_supplicant` by hand, `iwd` without
  NetworkManager). Interfaces with other names are not covered.
- The probe needs the adapter up: on an adapter that is down, LabLink
  cannot tell whether it is armed and refuses to start.
- `start` can report success when a `stop` from another terminal lands in
  its last moments; `status` shows the real state.
- After NetworkManager is killed, its dnsmasq stays behind and blocks the
  next start until it is stopped (see [Isolation](#isolation)).

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

In the isolated cases the client still reached this machine and the
other client (ICMP, TCP and IPv6 link-local). After `stop`, no `prohibit`
rule was left. The rows above ran before the field filter existed (rules
only); DNS without the filter is in `raw_dns`: the hotspot's dnsmasq
resolved outside names through the host, which is why the filter refuses
port 53.

**Continuous traffic with both layers** (`lablink_leak`, run `leak3`,
2026-10-12, 266.2 s). A static client (10.77.0.50, 2001:db8:77::50) sent
the whole time: IPv4 ping at 100/s to six destinations (uplink gateway,
internet, LAN, a VPN-style 100.64.0.1, a Docker-style container
172.17.0.2, a new interface's network), IPv6 ping at 100/s to the
internet, UDP every 10 ms to three networks and repeated TCP connects to
the uplink and to a published Docker port; the uplink side pinged and sent
UDP to the client at 100/s. The host side had a wg-quick-style full-tunnel
policy (`lookup main suppress_prefixlength 0` at 49, `not fwmark lookup
200` at 50), a Docker-style bridge with a published port (DNAT 8080 to
172.17.0.2:7080) and NetworkManager-managed Ethernet uplink and LAN.
Counted per phase: client packets that reached the host (raw table on the
hotspot interface), packets that reached the uplink, internet, LAN or VPN
(raw counters there), packets that reached the container namespace (raw
counter, excluding the uplink's own positive control), replies injected
back to the client from those networks, and an independent `tcpdump` on
the uplink and LAN interfaces. `rejoin` phases wait until the client has
re-associated, so every breach ran under traffic.

| Phase | Duration (s) | Client packets at the host | Reached uplink/internet, LAN, VPN (counter) | Reached Docker namespace | Captured on uplink, LAN | Hotspot after |
|---|---|---|---|---|---|---|
| armed-idle | 6.0 | 0 | 0 | 0 | 0, 0 | down |
| activation | 4.7 | 0 | 0 | 0 | 0, 0 | up |
| operation | 4.0 | 76 | 0 | 0 | 0, 0 | up |
| operation-exposure | 32.7 | 26909 | 0 | 0 | 0, 0 | up |
| operation-steady | 20.0 | 16475 | 0 | 0 | 0, 0 | up |
| rejoin | 0.2 | 236 | 0 | 0 | 0, 0 | up |
| restart | 4.8 | 258 | 0 | 0 | 0, 0 | up |
| rejoin | 14.3 | 175 | 0 | 0 | 0, 0 | up |
| rules-deleted | 8.0 | 1491 | 0 | 0 | 0, 0 | down |
| recovery-1 | 4.8 | 0 | 0 | 0 | 0, 0 | up |
| rejoin | 2.4 | 133 | 0 | 0 | 0, 0 | up |
| filter-unloaded | 8.0 | 681 | 0 | 0 | 0, 0 | down |
| recovery-2 | 4.8 | 0 | 0 | 0 | 0, 0 | up |
| rejoin | 1.4 | 116 | 0 | 0 | 0, 0 | up |
| no-pref-rule+new-if | 10.0 | 8316 | 0 | 0 | 0, 0 | up |
| if-state-change | 12.1 | 10009 | 0 | 0 | 0, 0 | up |
| rejoin | 0.2 | 237 | 0 | 0 | 0, 0 | up |
| lablinkd-killed | 8.0 | 6633 | 0 | 0 | 0, 0 | up |
| user-procs-killed | 6.0 | 4980 | 0 | 0 | 0, 0 | up |
| rejoin | 0.2 | 232 | 0 | 0 | 0, 0 | up |
| nm-sigterm | 11.0 | 125 | 0 | 0 | 0, 0 | down |
| nm-restart-1 | 12.5 | 0 | 0 | 0 | 0, 0 | down |
| recovery-3 | 4.8 | 3300 | 0 | 0 | 0, 0 | up |
| rejoin | 0.2 | 234 | 0 | 0 | 0, 0 | up |
| nm-sigkill | 11.0 | 9126 | 0 | 0 | 0, 0 | down |
| nm-restart-2 | 12.5 | 38 | 0 | 0 | 0, 0 | down |
| recovery-4 | 5.9 | 0 | 0 | 0 | 0, 0 | up |
| stop-during-start | 12.5 | 0 | 0 | 0 | 0, 0 | down |
| recovery-5 | 5.8 | 0 | 0 | 0 | 0, 0 | up |
| rejoin | 9.3 | 102 | 0 | 0 | 0, 0 | up |
| NEGATIVE-CONTROL | 8.0 | 2107 | 1709 | 349 | 1314, 395 | down |
| recovery-6 | 5.8 | 0 | 0 | 0 | 0, 0 | up |
| rejoin | 1.8 | 109 | 0 | 0 | 0, 0 | up |
| shutdown | 6.5 | 261 | 0 | 0 | 0, 0 | down |
| armed-idle-after | 6.0 | 0 | 0 | 0 | 0, 0 | down |

Replies from other networks back to the client: 0 in every phase except
the negative control (672). In total, outside the negative control: 258.2 s,
90,252 client packets at the host, **0** packets on any other network by
counter or capture. The negative control (both rules deleted and the
filter unloaded while the hotspot ran; `lablinkd` stopped it 2.4 s after the phase began) leaked 1,709 packets to the uplink,
internet, LAN and VPN (1,314 + 395 captured) and 349 to the container, which
shows the counters and captures see leaks. Phases with 0 client packets
(`activation`, `nm-restart-1`, the recoveries, `stop-during-start`) carry
no leakage evidence of their own: the client re-associates a few seconds
after each start. The activation ordering is shown separately by
`raw_filter_events`: sampling every 10 ms while NetworkManager switched the adapter from an
ordinary Wi-Fi connection to the hotspot, the interface was armed more
than 100 ms before it first appeared in AP mode and was never open in AP
mode;
`recovery-3` (a start, 3,300 client packets as the client rejoined) and the
`rejoin` phases cover the first seconds of client traffic after
activation.

What each failure did, with both layers:

| Event | Hotspot | Leaked | Which layer held |
|---|---|---|---|
| Normal stop (`shutdown`), `restart` | stopped / restarted | 0 | both, then the filter (re-armed at `pre-down`) |
| IPv4 and IPv6 rules deleted by root | stopped by `lablinkd` 2.0 s after the phase began | 0 (was 142 with rules only) | filter |
| Filter table removed by root | stopped by `lablinkd` 1.1 s after the phase began | 0 | rules |
| A new interface, a new table and a priority-less wg-quick-style rule | up | 0 | both |
| Ethernet uplink and LAN disconnected, link down and up, reconnected | up | 0 | both |
| `lablinkd` killed | up, unwatched | 0 | both (no recovery until it restarts) |
| All of the user's processes killed (stand-in for a logout) | up | 0 | both |
| NetworkManager SIGTERM, then restarted | torn down | 0 (was 2 TCP segments with rules only) | filter |
| NetworkManager SIGKILL, then restarted | access point stays up without NetworkManager, then torn down | 0 | both, then the filter |
| `stop` 1.5 s after `start` began | stopped; `start` still reported success | 0 (no client yet) | both |

Before the field filter existed, `lablinkd`'s watchdog was the only
recovery after a rule was deleted. With a client sending about 100 IPv4
UDP packets a second to the uplink (rules only, no filter):

| Breach | Hotspot down after | Flood packets forwarded meanwhile |
|---|---|---|
| IPv4 rule deleted | 1.87 s | 142 |
| IPv6 rule deleted | 1.18 s | 0 (the flood was IPv4 only, so this says nothing about IPv6 leakage) |
| tc ingress qdisc added on the adapter | 1.18 s | 0 |

Activation window, rules only (before the filter): eight activations of
the isolated profile while a client tried to flood. NetworkManager
installed both rules about 16 ms after activation started; no client
packet reached the host or another network, but the client never got a
packet through during an activation either, so those runs did not prove
the ordering. The filter closes that question: it is armed before the
access point exists. After a NetworkManager SIGKILL its dnsmasq is left
behind and holds the hotspot address, so the next start fails ("IP
configuration could not be reserved") until it is killed.

Host services a client reached (`lablink_leak`, exposure check, from a
second client that joined with DHCP and got 10.77.0.65):

| Target | Result |
|---|---|
| 10.77.0.1 TCP 22 (listed) | connected |
| 10.77.0.1 TCP 2222, 8080 (a published Docker port), 53 | refused (ICMP admin-prohibited, seen as "No route to host") |
| DNS query to 10.77.0.1 | refused (ICMP admin-prohibited, `dig`: host unreachable) |
| The host's uplink address 192.0.2.2, TCP 22 and 2222, ICMP | no answer (dropped) |
| The container 172.17.0.2:7080 | refused |
| Same ports from the uplink side (positive control) | 8080 reached the container, 2222 the host service |
| ICMP to 10.77.0.1 | reply |
| mDNS (224.0.0.251:5353) and DDS SPDP (239.255.0.1:7400) from a client | host 3 of 3 each; the other client 3 of 3 each |
| DDS-style unicast client to host (7410), host to client (7411) | 3 of 3; 1 of 1 |
| Client to client: ICMP, TCP, UDP, IPv6 link-local | all answered |

DHCP (the second client's lease) and ARP (its neighbour entry for the
hotspot address) worked with the filter armed.

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
| `isolation` blocker | Preflight names the cause: install or load the field filter ([Isolation](#isolation)), remove the other priority-0 rule, the stacked interface, bridge, XDP program or ingress qdisc, or use the sharing mode knowingly |
| `start` says the adapter is not armed | The filter is loaded but has opened the adapter (an ordinary connection was still on it). Disconnect it and start again; if it persists, run the script with `load` as root |
| A ROS 2 machine on the hotspot cannot discover this one | The filter allows DDS domain 0 only by default; add the domain's ports to `FIELD_UDP` ([Isolation](#isolation)) |
| `lablinkd` stopped the hotspot | Its log names the failed check. Something removed a rule or attached a bypass; find out what before starting again |
| `status` warns that clients can be routed somewhere | Sharing mode only: a VPN, container network or uplink appeared after start. Stop the hotspot, or block forwarding from the hotspot interface in your firewall |
