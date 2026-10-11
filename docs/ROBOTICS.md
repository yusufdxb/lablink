# Robotics mode

Robotics mode answers "why can't these two ROS 2 machines see each other?"
without installing anything on them. It reads a registered device's ROS 2
setup over the same pinned-key SSH path LabLink already uses, runs twelve
DDS checks, and tells you which connectivity level two devices reach, with
the evidence for every verdict.

It is an optional feature and is off by default. This machine needs no ROS
installation.

```bash
lablink feature enable robotics
lablink ros inspect jetson-a
lablink ros dds-check jetson-a --peer workstation
```

In the app, tick **Robotics mode** under **Settings**; a **Robotics** tab
appears.

## What it will and will not do

- **Read-only by default.** `inspect` reads files and `/proc`: it starts no
  ROS process and joins no DDS domain. `nodes`, `topics` and `dds-check`
  (unless `--no-graph`) briefly join the device's domain as a hidden `ros2`
  CLI node, with `--no-daemon` so no `ros2 daemon` is started, under a
  bounded `timeout`. They publish nothing.
- **Active tests only when you ask** (`--active`, or the second
  confirmation in the app). See [Active tests](#active-tests).
- **Never** rewrites DDS XML, shell startup files or environment
  variables, restarts nodes, changes firewall rules, or touches robot
  topics or motion. Where a fix is needed, LabLink tells you what to change
  and you change it.
- **Agentless.** The remote scripts are fixed templates; the few
  parameters they take (distribution, domain, RMW, file paths, topic
  names) are validated and shell-quoted. Remote output is treated as
  untrusted text and shown with control characters escaped.
- **Pinned devices only.** Commands go through the daemon's `resolve`, so
  an unknown, unpinned, AWAY or identity-mismatched device is refused
  before any SSH connection, with the usual exit codes.

## Status and proof limits

| Area | Evidence |
|---|---|
| Parsers (environment, DDS XML, `ip`, graph listings, QoS), the twelve checks and the level rules | Unit tests on recorded output (`crates/lablink-ros/src`) |
| End to end against real ROS 2 Humble and Jazzy installations | Docker containers (`ros:humble-ros-base`, `ros:jazzy-ros-base`, with iproute2 and ping added) driven through `docker exec` instead of SSH (`crates/lablink-ros/tests/docker_ros.rs`, run with `--ignored`). This is simulation: no robot, no Wi-Fi, no real SSH |
| CLI argument checks, feature gate, daemon-down behavior | `crates/lablink-cli/tests/ros.rs` |
| Real OpenSSH, a real daemon and config-pinned host keys | One manual run (not an automated test) against two ROS 2 Humble containers running `sshd`, with a named publisher and subscriber: both devices VERIFIED by possession proof; `inspect`, `nodes`, `topics` correct; passive `dds-check` level 2 (discovery seen one way), level 3 on a rerun; `--active` level 4, all six probes PASS, no probe process left, the existing nodes kept running. This run predates the `--no-daemon` subscriber and the daemon leftover check, which are unit-tested and checked in a shell but not re-run end to end |
| A real robot computer (Jetson), real Wi-Fi or a Field Network | **Not tested** |

## Requirements on the device

- A registered LabLink device with a pinned host key, whose SSH login works
  without a prompt (key or agent; LabLink runs batch mode).
- ROS 2 under `/opt/ros/<distro>` (Humble and Jazzy are supported; other
  distributions are inspected but not specifically judged).
- `sh`, `timeout` (coreutils) and `/proc`. `bash` is used to source the ROS
  setup for graph queries.
- `ip` (iproute2) for interface, binding, multicast and routing checks.
  Without it those checks say UNAVAILABLE rather than failing. Minimal
  container images often lack it.
- `ping` for the active reachability test.

## Commands

| Command | What it does |
|---|---|
| `lablink ros inspect <device>` | Distribution, RMW, domain, localhost-only and discovery settings (from running nodes, shell startup files and the SSH session, side by side), DDS config files, interfaces, addresses, routes, firewall service |
| `lablink ros nodes <device>` | The ROS graph as the device's nodes see it |
| `lablink ros topics <device>` | Topics and their types, same view |
| `lablink ros dds-check <device> [--peer <device>]` | The twelve checks; with `--peer`, the connectivity level |

`dds-check` options: `--active`, `--qos-topic <topic>` (up to 5),
`--no-graph`, `--spin <1-10 s>`, `--details` (method, endpoints,
interfaces, timeout and evidence for each check), `--timeout <5-300 s>`,
`--json`. Exit 0 when no check fails, 1 when one does, and the usual
daemon codes (3 daemon down, 4 unknown device, 5 unreachable, 6 identity
mismatch, 7 refused).

### Which environment counts

ROS settings live in three places that often disagree: the shell startup
files (what a new terminal gets), the SSH session's environment, and the
running ROS processes (what the nodes actually use). `inspect` shows all
three. Checks and graph queries use the running nodes' environment when
there are nodes, then the shell files, then the session, and say which
they used. A disagreement between the shell files and the running nodes is
a warning of its own: the next node you start from a terminal may not join
the others.

## Connectivity levels

| Level | Means | Proven by |
|---|---|---|
| 1 | IP reachability | The active ping, both ways. LabLink reaching both devices over SSH does not prove they reach each other |
| 2 | Compatible configuration | No configuration check failed |
| 3 | Discovery | Each side's graph query saw the other side |
| 4 | Data exchange | The active pub/sub probe delivered messages |

Level 4 is reported only from the active probe. A `ros2 node list` that
shows the other machine's nodes proves discovery, not that data flows:
QoS, fragmentation, multicast-only paths and firewalls can still stop
messages. Without `--active`, level 1 and level 4 say NOT TESTED.

## The twelve checks

| Check | Looks at | Typical failure |
|---|---|---|
| ROS domain | `ROS_DOMAIN_ID` of both sides | Different domains never discover each other |
| DDS interface binding | Interfaces named in Cyclone `NetworkInterface` / Fast DDS `interfaceWhiteList`, against `ip link` / `ip addr` | Bound to an interface that does not exist, or to one that cannot reach the peer |
| Multicast | `MULTICAST` flag, the route for 239.255.0.1, `AllowMulticast`; with `--active`, `ros2 multicast send/receive` | Multicast disabled or filtered by the access point |
| Client isolation | With `--active` only: whether the two devices reach each other directly | Wi-Fi client isolation (common on campus and guest networks) |
| Discovery restrictions | `ROS_AUTOMATIC_DISCOVERY_RANGE`, `ROS_DISCOVERY_SERVER`, `FASTDDS_BUILTIN_TRANSPORTS`, Fast DDS discovery protocol | `LOCALHOST`/`OFF` range, a discovery server only one side uses |
| Host firewall | Whether ufw, firewalld or nftables is active (rules need root and are not read) | An active firewall that may drop DDS ports |
| Routing and subnet | Addresses and routes of both devices | Different subnets without multicast routing |
| RMW implementation | `RMW_IMPLEMENTATION` (or the distribution default) against installed `librmw_*_cpp.so` | RMW not installed; different RMWs; Humble and Jazzy mixed |
| Localhost only | `ROS_LOCALHOST_ONLY` | Set on one side |
| Static peers | `ROS_STATIC_PEERS` and DDS XML peer lists, against the other device's addresses and hostname | A peer list that omits the other device |
| QoS compatibility | Endpoint QoS of the `--qos-topic` topics | Reliable subscriber with a best-effort publisher; durability mismatch |
| Cached graph (ros2 daemon) | A running `ros2 daemon`'s domain and RMW (from its command line; LabLink never queries it) | A daemon started with other settings serves `ros2 node list` a stale view |

Each check reports PASS, WARN, FAIL, NOT TESTED or UNAVAILABLE (the app
shows OK, WARNING, FAILED, NOT TESTED and UNSUPPORTED), a one-line summary,
a fix hint where there is one, and with `--details` the method, the
devices and interfaces involved, the timeout and the raw evidence.

### Humble and Jazzy

- `ROS_AUTOMATIC_DISCOVERY_RANGE` and `ROS_STATIC_PEERS` exist from Iron
  on. Humble ignores them; setting them on Humble is a warning.
- `ROS_LOCALHOST_ONLY` is deprecated on Jazzy in favor of the discovery
  range; LabLink still honors and reports it, with that hint.
- Mixing distributions across machines is not supported by ROS 2 and is
  reported as a warning. In the container test, Humble and Jazzy (both on
  their default Fast DDS) did not discover each other.

## Active tests

`dds-check <a> --peer <b> --active` sends a little traffic of its own and
nothing else:

- three pings each way,
- one `ros2 multicast` packet each way,
- a pub/sub probe: three `std_msgs/msg/String` messages at 2 Hz on a topic
  no robot uses, `/lablink_probe_<random hex>`, in the devices' own domain
  and RMW.

Every command runs under `timeout -k`; the subscriber runs with
`--no-daemon` (`ros2 topic echo` would otherwise start a `ros2 daemon`).
Afterwards LabLink checks both devices for leftover probe processes, and
for a `ros2 daemon` that was not running before the probe, and reports any
it finds. The probe
never reads or writes an existing topic and never starts, stops or
commands a robot. It does join the robot's DDS domain for a few seconds, so
run it when nothing safety-relevant depends on the network being quiet.
A full active run takes about 50 seconds.

## Caveats

- **Discovery is timing-dependent.** Level 3 rests on each side's graph
  query seeing the other side's query node (or its named nodes) within the
  spin window. A busy device or a slow network can miss that window and
  report a discovery failure that a longer `--spin` would not. Re-run
  before concluding.
- **Firewall rules are not read** (they need root). An active firewall is a
  warning, not a verdict.
- **No `ip` on the device** means interface, binding, multicast and
  routing checks are UNAVAILABLE.
- **Wi-Fi client isolation** is detected only with `--active`.
- **DDS XML is read for Cyclone DDS and Fast DDS only.** Other RMWs are
  checked for domain, installation, localhost and discovery-range
  settings, but their own configuration files are not interpreted.

## Using it across a Field Network

With the laptop hosting a [Field Network](FIELD_NETWORK.md) and both robot
computers joined to it, `dds-check` tells you whether the hotspot carries
DDS discovery (multicast) and data. If discovery fails only on the
hotspot, check client isolation with `--active`, and consider unicast
discovery (`ROS_STATIC_PEERS` on Jazzy, DDS peer lists on Humble).

## Future: graph visualization

`lablink_ros::graph::GraphSource` is the interface a future graph view would
consume (nodes, topics and endpoints with the device each came from). It
has no implementation yet. See [ARCHITECTURE.md](ARCHITECTURE.md#robotics-mode).
