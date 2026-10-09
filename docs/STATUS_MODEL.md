# LabLink status model

A device's health is not one boolean. Each device has independent states,
combined into a traffic-light color with human-readable reasons.

## Per-check states (JSON values in `snake_case`)

| Field | Values | Meaning |
|---|---|---|
| `discovery` | `never_seen`, `located`, `searching` | Has LabLink ever found it; does it have a current, answering address. |
| `network` | `unknown`, `online`, `degraded`, `offline` | Reachability of the current address, with hysteresis. |
| `ssh_port` | `unknown`, `open`, `closed`, `filtered`, `disabled` | TCP/22 (or `ssh_port`): `closed` = connection refused (host up), `filtered` = no answer while the host answers ICMP, `disabled` = `ssh: false`. |
| `ssh_auth` | `unknown`, `ok`, `failed`, `unavailable`, `disabled` | Last BatchMode login check. `unavailable` = could not be checked (network or host-key problem). `disabled` = `auth_check: false` or no SSH. |
| `identity` | `unknown`, `unverified`, `verified`, `mismatch` | Host key at the current address: not observed yet / observed but not pinned / matches a pin / contradicts a pin (security). |
| `services[]` | `ok`, `degraded`, `failed`, `unknown`, `disabled` | Optional per-service checks (extension point). They do not change the color. |
| `site_state` | `active`, `away`, `unknown` | Whether you are at the device's site (see [ARCHITECTURE.md](ARCHITECTURE.md#sites)). AWAY devices are not probed. |

Each device also reports `id` (`site/name`, unique), `name` (may repeat
across sites), `site` and `site_name`.

## Hysteresis

Defaults (`daemon:` section, all configurable): `degraded_after: 2`,
`offline_after: 4`, `recover_after: 2`, `check_interval_s: 5`.

| From | Event | To |
|---|---|---|
| unknown | 1 success | online |
| unknown | `offline_after` consecutive failures | offline |
| online | `degraded_after` consecutive failures | degraded |
| degraded | 1 success | online |
| degraded / online | `offline_after` consecutive failures | offline |
| offline | `recover_after` consecutive successes | online (confirmed recovery) |

One dropped probe never changes the state. Intermittent loss of single probes
never leaves ONLINE; repeated pairs of failures show DEGRADED but never
OFFLINE (`intermittent_packet_loss_never_goes_offline`,
`health::tests::*`). A check round succeeds if the host answers ICMP, or
answers TCP (connection accepted or refused).

The SSH port state is debounced similarly: `open` is reported immediately;
leaving `open` needs `degraded_after` identical observations.

While a device is not reachable its checks back off exponentially from
`check_interval_s` to `offline_backoff_max_s` (30 s).

## Color

Evaluated in this order (`lablink_core::model::compute_color`):

| Color | Condition |
|---|---|
| GRAY | monitoring disabled |
| RED | identity `mismatch` (security error, regardless of reachability or site) |
| GRAY | `site_state: away`: you are at another site (or none); the device is not checked and never counted as failed |
| GRAY | network `offline` while `site_state: unknown`: unreachable, but the site is not confirmed, so not a failure |
| GRAY | never located (`discovery: never_seen`) |
| GRAY | network `unknown` (not checked yet since daemon start, or the gateway of a `via:` device is unusable; the reason says which) |
| RED | network `offline`: expected (seen before) but unavailable after the failure threshold |
| GREEN | network `online`, and for SSH devices: port `open`, identity `verified`, and login `ok` (unless `auth_check: false`) |
| YELLOW | anything else: located but degraded, port closed or filtered, identity unpinned or unknown, login failed or not yet checked |

Devices with `ssh: false` (e.g. a robot base reached through its onboard
computer) are GREEN on reachability alone. Each non-green status carries `reasons`, e.g.
`"SSH login as ops failed: server only accepts password authentication; ..."`.

## Examples

```json
{"id": "site-alpha/jetson-a", "name": "jetson-a", "site_state": "active", "color": "green",
 "network": "online", "ssh_port": "open", "ssh_auth": "ok", "identity": "verified",
 "latency_ms": 2, "last_seen_ms": 3647}
{"id": "site-alpha/robot-a", "name": "robot-a", "site_state": "active", "color": "green",
 "network": "online", "ssh_port": "disabled", "via": "jetson-a", "latency_ms": 1}
{"id": "site-alpha/jetson-b", "name": "jetson-b", "site_state": "active", "color": "red",
 "network": "offline", "reasons": ["unreachable after failure threshold"], "last_seen_ms": 240000}
{"id": "site-beta/jetson", "name": "jetson", "site_state": "away", "color": "gray",
 "network": "unknown", "reasons": ["site 'Site Beta' is away: not checked while you are at Site Alpha"]}
```

`lablink status <device>` exits 0 for GREEN, 10 YELLOW, 11 RED and 12 GRAY
(which includes AWAY). `lablink status` without a device lists the sites you
are at; `--site <id>` and `--all` widen it.

## History

Only transitions are recorded: located, IP changed, network online/degraded/
offline/recovered, port reachable/closed/not answering, identity verified/
unpinned/mismatch, key pinned, MAC learned, MAC changed at the current address,
login ok/failed, service state changes, gateway unavailable, settings changed,
scans refused, site active/away/unknown and site-mode changes, daemon
start/stop, cache recovery. Successful repeated checks
add nothing (`history_records_transitions_not_heartbeats`).
