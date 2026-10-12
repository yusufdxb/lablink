# Field Network and Robotics mode: hardware validation report

Branch `feat/field-network` at `6af72f8` (base: public v0.3.1, `ffde75c`,
unchanged). Campaign date: 2026-10-11. Nothing was merged, pushed, tagged
or published.

Evidence categories used throughout:

| Category | Meaning |
|---|---|
| VERIFIED ON PHYSICAL HARDWARE | Run on the real machine, real radio, real peer, with output kept |
| VERIFIED IN SIMULATION | Real NetworkManager, `wpa_supplicant`, `hostapd` and `dnsmasq` on Linux `mac80211_hwsim` radios inside network-isolated containers |
| VERIFIED IN CONTAINERS | Real ROS 2 in Docker containers |
| VERIFIED BY UNIT TESTS | `cargo test` with scripted fakes |
| NOT TESTED | No run of any kind |
| FAILED | Run, and the result was wrong |

## 1. Executive verdict

**The physical campaign stopped at Stage A: BLOCKED.** No hotspot was
started on physical hardware, no MacBook joined one, and the Jetson was not
reached. The Linux machine's adapter can host a WPA2 access point
(capability read from the driver), but five conditions block a safe
physical test from a remote session (section 15). Every physical step is
written out in section 11 for an operator at the machine.

| Gate | Verdict | Why |
|---|---|---|
| 1. Linux Field Network | **NO-GO** for a hardware-support claim | Capability and preflight read on the real machine; start, clients, isolation, stop and recovery verified only in simulation |
| 2. MacBook client | **NO-GO** | Not tested: no hotspot to join |
| 3. Robotics (Jetson ROS 2/DDS) | **NO-GO** | Not tested on hardware: the Jetson was offline (LabLink red). Container tests only |

NO-GO here means "hardware support cannot be claimed", not "the code is
known to be broken". No gate can become GO from simulation alone.

## 2. Machines

| Machine | Role | State during the campaign |
|---|---|---|
| Linux workstation | Hotspot host, LabLink CLI/GUI/daemon | Reachable. Ubuntu 22.04.5 LTS, x86_64. One Wi-Fi adapter connected to the home network, one wired 2.5 GbE (`igc`) uplink to the lab network, a Tailscale tunnel, a Docker bridge |
| MacBook Pro 2021 (M1 Pro) | SSH client to the workstation; intended hotspot client | Connected to the workstation only through the Tailscale tunnel. macOS version, Remote Login state and Wi-Fi details were not collected (no remote change to the Mac was authorized) |
| Jetson Orin NX 16 GB (on the GO2) | Robotics mode target | LabLink `status`: red, network offline, discovery searching. Not reached |

The workstation runs an older LabLink install (0.1.0, systemd user
service). Its configuration contains a `wake:` section that the branch
rejects (`unknown field 'wake'`). Public v0.3.1 rejects it too (its
top-level `RawConfig` is `deny_unknown_fields` with no `wake` field; by
source inspection, not by running v0.3.1), so this is an existing upgrade
problem, not a branch regression. The live install, its configuration and
`~/.ssh/known_hosts` were not modified; branch tests used a copy of the
configuration, a separate state directory and a socket path that no daemon
listened on.

## 3. Wi-Fi hardware

| Item | Value | Category |
|---|---|---|
| Adapter | MediaTek MT7925 (PCI `14c3:7925`), driver `mt7925e` | VERIFIED ON PHYSICAL HARDWARE (read-only) |
| Firmware | MT7925 patch/RAM build `20231227` | VERIFIED ON PHYSICAL HARDWARE (kernel log) |
| Interface modes | managed, AP, AP/VLAN, monitor, P2P-client, P2P-GO | VERIFIED ON PHYSICAL HARDWARE (`iw phy info`) |
| Combinations | `#{managed, P2P-client} <= 2, #{AP, P2P-GO} <= 1, total <= 2, #channels <= 2` | VERIFIED ON PHYSICAL HARDWARE (`iw phy info`) |
| Bands | 2.4, 5 and 6 GHz listed | VERIFIED ON PHYSICAL HARDWARE (`iw phy info`) |
| Ciphers | CCMP-128 and GCMP-128 among others | VERIFIED ON PHYSICAL HARDWARE (`iw phy info`) |
| WPA2-Personal AP | Supported per NetworkManager capability flags | Capability only; no AP was started |
| WPA3-Personal (SAE) AP | `iw` reports "SAE with AUTHENTICATE command" (a station-side feature). AP-mode SAE is **unverified** | NOT TESTED on hardware; VERIFIED IN SIMULATION |
| Concurrent AP + station | Allowed by the combination limits, but LabLink hosts on one interface, so the adapter's current connection drops | Capability only |

`iw` is not installed on the host. The `iw` output above came from the
validation container image run with the host network namespace
(read-only). LabLink's own capability check reports WPA3 as "unverified"
without `iw`.

## 4. Operating system and driver versions

| Component | Version |
|---|---|
| OS | Ubuntu 22.04.5 LTS |
| Kernel | 6.8.0-138-generic |
| NetworkManager | 1.36.6 |
| polkit | 0.105 |
| Wi-Fi driver | `mt7925e` (in-kernel), firmware build `20231227` |
| Host firewall | ufw service active (rules need root; not read) |
| LabLink under test | `feat/field-network` debug build, `6af72f8` |
| LabLink installed | 0.1.0 (not modified) |

NetworkManager permissions for the normal user (`nmcli general permissions`,
local session):

| Permission | Result | Needed for |
|---|---|---|
| `network-control` | yes | Activating and deactivating |
| `settings.modify.own` | yes | Creating LabLink's own profile |
| `settings.modify.system` | yes | Not needed by LabLink |
| `wifi.share.protected` | yes | Protected hotspot |
| `checkpoint-rollback` | auth (would prompt) | Optional NetworkManager checkpoint |

## 5. Linux hotspot (Stage B)

| Step | Physical hardware | Simulation | Unit tests |
|---|---|---|---|
| A: capabilities | VERIFIED (read-only): can host, one adapter, in use | n/a | VERIFIED |
| A: preflight | VERIFIED (read-only): refused, exit 7, 3 blockers | VERIFIED | VERIFIED |
| B1: create profile, start | NOT TESTED | VERIFIED | VERIFIED |
| B2: WPA2 auth, wrong password refused | NOT TESTED | VERIFIED | n/a |
| B2: password rotation | NOT TESTED | VERIFIED | VERIFIED |
| B2: WPA3 (SAE) | NOT TESTED | VERIFIED | VERIFIED |
| B3: client to host | NOT TESTED | VERIFIED | n/a |
| B3: isolation from other networks | NOT TESTED | VERIFIED (isolated only without another uplink; with shared mode opted in, clients were NATed) | VERIFIED |
| B4: stop and restore previous network | NOT TESTED | VERIFIED | VERIFIED |
| B4: restart, recovery after LabLink killed | NOT TESTED | VERIFIED (checkpoint rollback) | VERIFIED |
| B4: NetworkManager restart or kill | NOT TESTED (not run on a production machine by rule) | NOT TESTED | n/a |
| B5: GUI | See section 9 | | |

Preflight on the workstation (read-only, branch build, copy of the
configuration) refused to start with three blockers:

1. An inbound SSH session arrives through the Tailscale tunnel, which may
   ride on the Wi-Fi adapter. No override exists, by design.
2. The wired interface is another internet uplink; NetworkManager's shared
   mode would NAT hotspot clients onto it (`--allow-internet-sharing`).
3. Shared mode enables IPv4 forwarding, and the machine routes to the
   tunnel, the lab LAN and the Docker bridge (`--allow-routing`).

It also warned that the adapter would leave the home network and that no
daemon could say which registered devices use the link, and noted that
IPv4 forwarding was already on (another service) and that other TCP
connections over the adapter would drop.

## 6. macOS (Stage C)

| Step | Result |
|---|---|
| C1: MacBook joins the hotspot | NOT TESTED (no hotspot) |
| C2: SSH from the MacBook over the hotspot | NOT TESTED. Remote Login state unknown; not changed |
| C3: discovery by SSH identity, site records preserved | NOT TESTED on hardware; daemon roaming and record preservation VERIFIED BY UNIT TESTS |
| C4: file transfer with SHA-256 | NOT TESTED. The separate Files feature branch was not merged or used |
| C5: native LabLink on macOS | NOT SUPPORTED: LabLink 0.3 supports Linux only (`docs/PORTABILITY.md`). macOS guidance code VERIFIED BY UNIT TESTS only; no macOS build was attempted |

## 7. Jetson (Stage D)

| Step | Result |
|---|---|
| D1: connectivity over the hotspot | NOT TESTED. LabLink: red, offline, before any network change |
| D2: ROS environment inspection | NOT TESTED on hardware; VERIFIED IN CONTAINERS |
| D3: levels 1 to 4, unique probe topic | NOT TESTED on hardware; VERIFIED IN CONTAINERS (Humble pair reached level 4, no leftover processes) |
| D4: failure diagnostics | NOT TESTED on hardware; VERIFIED IN CONTAINERS and BY UNIT TESTS |

No robot command, locomotion node, safety setting or DDS configuration was
touched.

## 8. ROS 2 and DDS

| Item | Category |
|---|---|
| Twelve checks, connectivity levels, `--active` probe on `/lablink_probe_<hex>` with `--no-daemon` and leftover check | VERIFIED IN CONTAINERS (Humble; Humble and Jazzy mixed does not discover, as documented) |
| DDS secret redaction (PEM keys, passwords, PKCS#11 PINs) in text and JSON | VERIFIED BY UNIT TESTS |
| Same on a real Jetson with real Cyclone or Fast DDS settings | NOT TESTED |
| Behavior through a real access point (multicast, client isolation, fragmentation) | NOT TESTED |

## 9. GUI

| Item | Category |
|---|---|
| Field Network tab renders, reads real capabilities, runs a real preflight as the normal user | VERIFIED ON PHYSICAL HARDWARE, read-only, in a virtual X display (Xvfb). The GUI process ran as the normal user, not root. It showed the same three refusals as the CLI and kept **Start Field Network** disabled |
| Accepting warnings, stale preflight dropped, password forgotten after the next action | VERIFIED BY UNIT TESTS |
| Starting, stopping or rotating from the GUI on hardware | NOT TESTED |
| GUI on the physical desktop session (Wayland or X11) | NOT TESTED |

An earlier screenshot taken before the inbound-SSH guard was added
(`dca60ad`) showed no remote-session refusal. The current build shows it.

## 10. Security findings

No new vulnerability was found in this campaign's code change (section 13;
a refactor of status text plus tests). Findings and limits that stand:

| ID | Finding | Status |
|---|---|---|
| T50 to T52 | Profile visible to other users, bidi text, DDS secrets in output | Fixed in `1431b14`, VERIFIED IN SIMULATION and BY UNIT TESTS |
| F1 | NetworkManager shared mode always enables forwarding and NAT. With another uplink or routed network, hotspot clients can reach it unless a firewall blocks forwarding from the hotspot interface. LabLink refuses by default and does not read or change firewall rules | By design; operator decision (section 15) |
| F2 | Without `checkpoint-rollback`, recovery after a crash mid-start depends on LabLink staying alive to reconnect; otherwise the operator runs `lablink hotspot stop` or reconnects with `nmcli` | Documented; narrow polkit rule proposed (section 11.1) |
| F3 | The session guard sees TCP SSH sessions. It does not see mosh or other UDP sessions, or sshd on a port other than 22 unless the command runs over it | Documented residual |
| F4 | IPv4 forwarding was already on before any test (another service). `status` reports the before and after value | Observation |

No Wi-Fi password, private key, token or DDS secret appears in this report
or in the kept evidence. The simulation password was generated per run,
read from stdin, and deleted afterwards.

## 11. Recovery and the local-console test plan

These steps are for an operator **at the workstation's own keyboard**,
with no SSH session that depends on the Wi-Fi adapter. Each disruptive
step needs explicit approval before it runs.

### 11.1 Before the session

1. Record the current state:
   `nmcli -t -f NAME,UUID,DEVICE connection show --active > before-active.txt`,
   `ip route > before-routes.txt`, `cat /proc/sys/net/ipv4/ip_forward`.
2. Confirm that the wired connection stays up and is the management path;
   never disable it.
3. Close every SSH session that arrives over the Tailscale tunnel (the
   preflight refuses while one exists; there is no override).
4. Optional, for a checkpoint: a polkit rule for one user, nothing broader
   (polkit 0.105 uses `.pkla` files), in
   `/etc/polkit-1/localauthority/50-local.d/50-lablink-checkpoint.pkla`:

   ```ini
   [LabLink NetworkManager checkpoint for one user]
   Identity=unix-user:<your-login>
   Action=org.freedesktop.NetworkManager.checkpoint-rollback
   ResultAny=no
   ResultInactive=no
   ResultActive=yes
   ```

   This grants only checkpoint create/rollback to that user in an active
   local session. It is a proposal: not installed. Check afterwards with
   `nmcli general permissions | grep checkpoint`.
5. Decide on the wired uplink (section 15, blocker 3).
6. Use branch binaries with a copy of the configuration (without `wake:`),
   a separate `LABLINK_STATE_DIR` and `LABLINK_SOCKET`, and the branch
   `lablinkd` in the foreground, so the installed daemon and its records
   are untouched.

### 11.2 Linux (B1 to B5)

```bash
lablink feature enable field-network --config "$CFG"
lablink hotspot capabilities
lablink hotspot preflight --config "$CFG"           # read every line
lablink hotspot start --config "$CFG"               # B1; only with approval
lablink hotspot status
lablink hotspot password                            # read it on screen only
# B2: join with a phone or the MacBook; also try a wrong password (must fail)
lablink hotspot password --rotate && lablink hotspot restart   # clients rejoin
# B3: from a client: reach the host (ssh), and try the lab LAN, the tunnel
#     range and the internet; record each result (expected: blocked unless
#     the flags were accepted)
lablink hotspot stop                                # B4: reconnects the home network
nmcli -t -f NAME,DEVICE connection show --active | diff before-active.txt -
lablink hotspot start --security wpa3               # B2 WPA3 only if the client supports SAE
```

B5: repeat start, status, stop and rotation from the **Field Network** tab
of `lablink-gui`, started as the normal user from the desktop session.

**If the network does not come back** after `stop`:

1. `lablink hotspot stop` again (idempotent).
2. `nmcli connection up "<home network name>"`.
3. `nmcli connection down "LabLink Field Network"`.
4. The wired connection was never changed, so management stays up
   throughout. Do not restart or kill NetworkManager on this machine.

### 11.3 MacBook (C1 to C5), at the MacBook

1. Join the hotspot from the Wi-Fi menu; note the address
   (`ipconfig getifaddr en0`) and `networksetup -getairportnetwork en0`.
2. SSH from the Mac to the workstation's hotspot address (`10.77.x.1`).
   Compare the host-key fingerprint with the one already trusted; stop if
   it differs.
3. Only if the operator chooses to enable Remote Login on the Mac: run
   `lablink hotspot clients` on the workstation, `lablink inspect <ip>`,
   verify the fingerprint at the Mac (`ssh-keygen -lf
   /etc/ssh/ssh_host_ed25519_key.pub`), then `lablink adopt <ip> <name>`
   and `lablink trust <name> --fingerprint SHA256:<verified>` (never
   `--yes`, never `--replace`). Check that existing site records are
   unchanged afterwards (`lablink sites`, `lablink devices`).
4. File transfer: create a test file, record `shasum -a 256` on the Mac,
   copy it with `scp`, compare `sha256sum` on the workstation.
5. Native LabLink on macOS is not supported in 0.3; nothing to run.

### 11.4 Jetson (D1 to D4), only with approval and with the robot not moving

1. Join the Jetson to the hotspot only with explicit approval of the change
   to its networking, with a wired or console path back.
2. `lablink status orin --json` (expect exit 0), then
   `lablink ros inspect orin`, `lablink ros nodes orin`,
   `lablink ros topics orin`.
3. `lablink ros dds-check orin --peer <second ROS machine> --details`
   (passive), then with approval `--active` (about 50 s, probe topic only,
   leftover check). Record level, RMW, domain, interfaces, each check
   result and leftovers.
4. D4: note what each failing check says. Do not change DDS settings to
   make a check pass.

## 12. Regressions

| Check | Result |
|---|---|
| `cargo fmt --all -- --check` | pass |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | pass, 0 warnings |
| `cargo test --workspace --locked` | 39 suites: 533 passed, 0 failed, 3 ignored |
| Status wording (the restore line only while running) | VERIFIED BY UNIT TESTS (a mutation that removed the guard failed the test) and VERIFIED IN SIMULATION against real NetworkManager 1.36.6: running status listed the restore line, status after `stop` did not, JSON still recorded the previous network |
| Host state after the simulation | Active connections, links, routes and `ip_forward` identical before and after; simulated radios unloaded |
| Installed LabLink 0.1.0, its configuration, `known_hosts` | Not modified |

## 13. Code changes and commits

| Commit | Change |
|---|---|
| `1431b14` | Hotspot profile restricted to its user; bidi text escaped; DDS secrets redacted; restore line only while running |
| `15b2e77` | Documentation of simulated validation, permissions and downgrade recovery |
| `6af72f8` | Status text moved into `status_text()` and covered by unit tests; no behavior change |
| this report | `docs/validation/FIELD_NETWORK_HARDWARE_REPORT.md` |

No new features. Commits are on `feat/field-network` only.

## 14. Exact untested capabilities

- Any hotspot start, client join, DHCP lease, traffic, stop, restore,
  rotation or WPA3 on the physical adapter.
- WPA3 (SAE) in AP mode on the MT7925.
- Isolation of hotspot clients from the lab LAN, the tunnel and the
  internet on the real machine, with the real ufw rules.
- NetworkManager checkpoint rollback on the real machine (permission is
  `auth`).
- Concurrent AP and station operation (LabLink does not use it).
- MacBook joining, SSH, discovery, adoption and file transfer.
- Native LabLink on macOS (not supported).
- Jetson connectivity, ROS 2 inspection, levels 1 to 4 and failure
  diagnostics on hardware; DDS redaction on real device settings.
- GUI start, stop and rotation on hardware; GUI on the physical desktop.
- NetworkManager restart or crash during a running hotspot.
- Upgrading the workstation's install to the branch (configuration
  migration of the `wake:` section).

## 15. Blockers

1. **Authorization.** The campaign requires explicit approval for every
   disruptive network step; none was given for a physical start.
2. **Remote session.** The operator's only session reaches the workstation
   through the Tailscale tunnel, which can ride on the Wi-Fi adapter.
   LabLink refuses with no override. The test needs the local console.
3. **Wired uplink.** An isolated hotspot cannot start while the wired
   interface is an internet uplink, and the wired interface must not be
   disabled. Options: (a) accept `--allow-internet-sharing --allow-routing`
   and test exposure as it is; (b) add an operator-owned firewall rule that
   drops forwarding from the hotspot interface (LabLink cannot verify it,
   and NetworkManager inserts its own forwarding rules); (c) run at a site
   where the workstation has no wired uplink. Each is the operator's
   decision.
4. **Single adapter.** The Wi-Fi adapter carries the home network, which
   drops while the hotspot runs.
5. **No checkpoint.** `checkpoint-rollback` needs administrator
   authorization; recovery uses LabLink's reconnect (section 11.1 has the
   narrow rule).
6. **Jetson offline.** Stage D cannot start until LabLink reports it
   reachable, and its networking must not change without approval.
7. **MacBook state unknown.** Remote Login and macOS version were not
   collected; nothing on the Mac may be changed remotely.

## 16. Release recommendation

Do not describe Field Network or Robotics mode as hardware-verified. The
branch is suitable for review as **simulation-verified, hardware pending**:
the code, unit tests, container tests and simulation runs pass, and the
physical adapter reports the needed capabilities. Before any release that
claims hardware support:

1. Run section 11.2 at the workstation's console and record results under
   VERIFIED ON PHYSICAL HARDWARE or FAILED.
2. Run section 11.3 with the MacBook.
3. Run section 11.4 when the Jetson is reachable and approved.
4. Re-issue the three gates from that evidence.
