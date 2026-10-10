# Using LabLink from scripts and AI agents

LabLink exists so that a script or an AI coding agent (Claude Code, Codex,
...) never has to rediscover lab machines, guess IP addresses, or retry SSH by
hand. The daemon already knows which site you are at, where every device is,
whether its identity is verified, and whether SSH login works.

## Recommended workflow

0. **Start lab diagnostics with the doctor** (one read-only pass over every
   device that has checks; see [Doctor](#doctor-lablink-doctor)):

   ```bash
   lablink doctor --json; echo "exit=$?"
   ```

   Use the per-device `status` / `exec` / `ssh` commands below only for what
   the doctor report leaves open.

1. **Before any SSH-related work, ask LabLink:**

   ```bash
   lablink status jetson-a --json; echo "exit=$?"
   ```

   - exit `0` (GREEN): reachable, host key verified, login works. Proceed.
   - exit `10` (YELLOW): read `reasons`; usually still usable for `exec`
     (e.g. port open but login not yet checked). Do not retry blindly.
   - exit `11` (RED): offline after the failure threshold, or a host-key
     MISMATCH (security). Stop and tell the user; do not work around it.
   - exit `12` (GRAY): never located, not monitored, or its site is AWAY
     (`site_state: "away"`). For AWAY: the user is at another site; report
     it, do not work around it. Otherwise run `lablink discover` once, then
     re-check. Still GRAY (or `lablink resolve` exits 5) means LabLink
     explicitly cannot resolve the target: manual fallback is allowed (see
     [Manual fallback](#manual-fallback-only-two-cases)).
   - exit `3`: the daemon is not running. Manual fallback is allowed; tell the
     user `systemctl --user start lablinkd`.
   - exit `4`: unknown device or site. Run `lablink devices --all` to see the names.
   - exit `8`: the bare name exists at several sites and LabLink will not
     guess. Use one of the `site/name` references from `error.candidates`
     (`lablink sites` shows which site is active).

   Device arguments accept `site/name` (`site-alpha/jetson-a`) everywhere;
   it always resolves exactly.

2. **Run commands with `exec`, not raw `ssh`:**

   ```bash
   lablink exec jetson-a "hostname" --json --timeout 30
   ```

   The JSON result contains `exit_code` (the remote command's own exit code),
   `stdout`, `stderr`, `status` (`ok` | `remote_error` | `ssh_error` |
   `timeout`), `duration_ms`, and `identity_pinned`.

   `--timeout`, Ctrl-C and SIGTERM stop LabLink's local ssh. `exec` runs
   the command without a terminal, so the device does not signal it when
   the connection closes: a command that does not write output may keep
   running there. Bound long commands on the device itself, for example
   `lablink exec jetson-a "timeout 25 ./job.sh" --timeout 30`.

3. **Need an address for scp/rsync?**

   ```bash
   scp file.txt "ops@$(lablink resolve jetson-a):/tmp/"
   ```

   `resolve` prints the address only while the device's identity is
   verified there (exit 7 otherwise, 5 for an AWAY device). Prefer
   `lablink exec` where possible: `resolve` gives only the address, not
   LabLink's pinned host-key options.

4. **Interactive sessions are for humans:** `lablink ssh jetson-a`.

Never: re-run `nmap`/ping sweeps while the daemon is up, edit
`~/.ssh/known_hosts` to "fix" a mismatch, pass `StrictHostKeyChecking=no`, or
store passwords. If a device is behind a gateway (`via` in the status), LabLink
already tunnels through it.

### Manual fallback (only two cases)

Manual SSH or discovery (raw `ssh`/`scp`, ping, `arp`, `ip neigh`, `nmap`,
mDNS, remembered IPs) is allowed only when:

1. LabLink is unavailable: exit `3`, or the `lablink` binary is missing; or
2. LabLink explicitly cannot resolve or discover the target: still GRAY (and
   not AWAY), or `lablink resolve` exits `5` for a device whose site is not
   AWAY, after one `lablink discover`.

Say which LabLink result justified the fallback.

Never a fallback trigger: a host-key mismatch (exit `6`, identity `mismatch`,
RED with a mismatch reason) or a policy refusal (exit `7`). These are hard
stops: report and wait. Do not switch to raw ssh, edit known_hosts, run
`lablink trust --replace`, or pass `StrictHostKeyChecking=no`. RED offline
(exit `11` without a mismatch), an AWAY site and an ambiguous name (exit `8`)
are not fallback triggers either: report them.

## Exit-code contract

| Code | Meaning | Commands |
|---|---|---|
| 0 | Success. For `status <device>`: GREEN | all |
| 1 | Internal or protocol failure | all |
| 2 | Usage error or invalid configuration | all |
| 3 | Daemon not running / socket unreachable | all that query the daemon |
| 4 | Unknown device or site | device commands, `--site` |
| 5 | Device has no usable address, is offline, or belongs to an AWAY site (pass `--force` to `ssh`/`exec`/`resolve` to try anyway) | `ssh`, `exec`, `resolve`, `trust` |
| 6 | SSH host key does not match the pinned identity (never overridable by flags) | `ssh`, `exec`, `resolve` |
| 7 | Refused by policy: scan outside limits, trust or forget not confirmed, device has no pinned host key (`ssh`/`exec`; `--unpinned` to let OpenSSH decide), address not identity-verified (`resolve`; `--force` prints it anyway) | `discover --scan-cidr`, `trust`, `forget`, `adopt`, `ssh`, `exec`, `resolve` |
| 8 | Ambiguous device name: it exists at several sites; use `site/name` | device commands |
| 10 / 11 / 12 | `status <device>` is YELLOW / RED / GRAY (GRAY includes AWAY) | `status <device>`, `doctor` |
| 124 | `exec --timeout` expired; the local ssh was stopped (the remote command may still be running, see below) | `exec` |
| 255 | The OpenSSH client failed (connection, authentication, host key) | `exec`, `ssh` |
| anything else | For `exec` and `ssh`: the remote command's own exit code, passed through unchanged | `exec`, `ssh` |

`lablink status` without a device always exits 0 when the daemon answered.
It lists the devices of the sites you are at (`--site <id>` for one site,
`--all` for every site); `sites` in the same JSON summarizes every site.

Because `exec` passes remote exit codes through, a remote command that itself
exits with 3-7 is indistinguishable from a LabLink error by exit code alone.
Use `--json`: LabLink errors always have `"status": "lablink_error"` and an
`error.code` string; remote results never do.

## JSON shapes (schema_version 1)

All `--json` outputs carry `"schema_version": 1`. Fields are only ever added.

`lablink status --json`:

```json
{
  "schema_version": 1,
  "daemon": {"version": "0.3.0", "pid": 4242, "uptime_s": 24},
  "devices": [
    {
      "name": "jetson-a", "id": "site-alpha/jetson-a", "site": "site-alpha",
      "site_name": "Site Alpha", "site_state": "active",
      "label": "Jetson A", "color": "green",
      "ip": "192.168.50.18", "discovery": "located",
      "network": "online", "ssh_port": "open", "ssh_auth": "ok",
      "identity": "verified", "latency_ms": 2, "last_seen_ms": 3647,
      "username": "ops", "interface": "eth1", "network_name": "robot_net",
      "via": null, "monitoring": true, "reasons": [], "services": [],
      "profile": "jetson", "capabilities": ["network", "ssh", "gpu", "jetson"]
    }
  ],
  "site_mode": {"mode": "auto"},
  "sites": [{"id": "site-alpha", "name": "Site Alpha", "state": "active", "confidence": "high", "...": "..."}]
}
```

Enumerations: `color` green|yellow|red|gray; `network`
unknown|online|degraded|offline; `ssh_port` unknown|open|closed|filtered|disabled;
`ssh_auth` unknown|ok|failed|unavailable|disabled; `identity`
unknown|unverified|verified|mismatch; `discovery` never_seen|located|searching;
`site_state` active|away|unknown. `profile` is
`generic_linux`|`jetson`|`gpu_workstation`|`ros2_host`|`network_only`|null and
`capabilities` a subset of `network`, `ssh`, `gpu`, `ros2`, `jetson`,
`gateway`. A test (`status_json_schema_is_stable`) pins the exact key set. `lablink inspect --json` also carries `overrides` (runtime label, username, monitoring, profile, ssh).

For a non-GREEN device, `lablink status <device>` (human output) adds an explanation: what failed, what still works, the likely cause and the next step. It is derived from the same JSON fields, so agents can rely on `reasons` and the exit code.

`lablink exec jetson-a "uname -a" --json`:

```json
{
  "schema_version": 1, "device": "jetson-a", "id": "site-alpha/jetson-a", "ip": "192.168.50.18",
  "user": "ops", "command": "uname -a", "status": "ok", "exit_code": 0,
  "timed_out": false, "duration_ms": 41, "stdout": "Linux ...\n", "stderr": "",
  "stdout_truncated": false, "stderr_truncated": false, "ssh_error": null,
  "advice": null, "identity_pinned": true
}
```

When OpenSSH itself fails (exit 255), `ssh_error` classifies it and `advice`
(added in 0.3.0) gives the safest next step, for example installing a key
with `lablink copy-id` after an authentication failure, or the security stop
for a changed host key.

Errors from any `--json` command:

```json
{"schema_version": 1, "status": "lablink_error", "exit_code": 3,
 "error": {"code": "daemon_unavailable", "message": "lablinkd is not running ..."}}
```

`error.code` is one of `daemon_unavailable`, `device_not_found`, `unreachable`,
`identity_mismatch`, `refused`, `conflict`, `busy`, `bad_request`, `internal`,
`protocol`, `invalid_config`, `ambiguous`. For `ambiguous`,
`error.candidates` lists `{"id", "site_name", "name"}` for every match.

`lablink sites --json` and `lablink site --json` report the site mode
(`{"mode": "auto"}` or `{"mode": "manual", "site": "<id>"}`), every site's
`state`, `confidence` (`none`|`low`|`medium`|`high`|`manual`), `evidence`,
networks and device counts, and the local signals.

## Doctor (`lablink doctor`)

`lablink doctor [DEVICE...] [--site ID | --all] [--json] [--timeout S] [--config PATH]` runs read-only health checks (SSH, GPU, thermal, disk, ROS 2 install, CycloneDDS interface, reachability) and prints a one-screen verdict. By default it checks the devices of the site(s) you are at. Checks come from the `checks:` section of each site in the config (see `config/example.yaml`); a device without an entry gets its profile's default checks (see the README), and otherwise its implicit checks (`ssh`, reach-via-gateway for `ssh: false` devices behind a gateway, or a `network` check from the daemon's state for directly attached `ssh: false` devices). Each device uses one batch SSH session through the same path as `lablink exec` (identity mismatch is a security stop: nothing is run). The checks are fixed command templates; no config value is ever run as a command.

Exit codes: 0 all devices GREEN (`ready`), 10 worst is YELLOW (`degraded`), 12 worst is GRAY (not located), 11 any RED (`not_ready`; red outranks gray), 3 daemon unavailable, 4 unknown device, 8 ambiguous name. Devices of AWAY sites (`--all`) are reported with `"away": true` and never count toward the verdict or the exit code.

```json
{"schema_version": 1, "verdict": "ready|degraded|not_ready", "scope": "Site Alpha",
 "devices": [{"name": "jetson-a", "id": "site-alpha/jetson-a", "site": "site-alpha", "away": false,
   "color": "green", "ip": "192.168.10.71", "via": null,
   "checks": [{"id": "ssh", "kind": "ssh", "label": "SSH", "status": "ok|warn|fail|skip", "detail": "host key pinned"}],
   "duration_ms": 812}]}
```

Devices are sorted by site and name, and checks keep their configured order (`ssh` first); keys are in a fixed order. Only measured values (`duration_ms`, and live readings such as GPU utilization, temperatures, disk use and rtt inside `detail`) change between runs; compare on `verdict`, `color` and `status`. A `skip` never degrades a device; GRAY devices and failed sessions skip their remaining checks.

## Suggested agent instructions

For an agent's instruction file (for example `CLAUDE.md` or `AGENTS.md`):

```markdown
## Lab machines
- Use LabLink for every robot/Jetson/workstation connection. Do not scan or guess IPs.
- Start lab diagnostics with `lablink doctor --json` (read-only; exit 0 = the current site is ready).
- Per device: `lablink status <device> --json` (exit 0 = ready, 10 yellow, 11 red, 12 gray or away, 3 = daemon down, 8 = ambiguous name).
- Use `site/name` when a name exists at several sites; `lablink sites` shows where the user is.
- Run commands with `lablink exec <device> "<cmd>" --json --timeout <s>`; remote exit code is preserved.
- A host-key mismatch (exit 6 / identity "mismatch") is a security stop: report it, never bypass.
- Manual discovery/SSH only if LabLink is unavailable (exit 3 / binary missing) or explicitly cannot resolve the target (still gray and not away, or `resolve` exits 5, after one `lablink discover`).
- A host-key mismatch, an AWAY site, an ambiguous name or another refusal never triggers the fallback.
```
