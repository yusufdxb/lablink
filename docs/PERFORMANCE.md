# LabLink performance and resource audit

All numbers below were measured on the developers' workstation (x86_64,
Ubuntu 22.04, kernel 6.8) on 2026-10-06 with release builds of LabLink 0.2,
before sites existed; the per-device check path and the discovery engine
measured here are unchanged in 0.3 (site detection adds one evaluation per
network event). Nothing here was measured on a Jetson.

## Binary sizes (release, thin LTO, stripped)

| Binary | Size |
|---|---|
| `lablinkd` | 5.4 MB (includes bundled SQLite and mDNS) |
| `lablink` | 1.5 MB |
| `lablink-gui` | 8.9 MB |

## Startup

`lablinkd` logs `startup_ms` (process start to socket ready): 0-19 ms observed
(11 ms with 3 devices and a fresh cache on the lab network; 0 ms with no
config under systemd).

## Real-network idle soak (30 minutes)

`scripts/soak.sh`, 60 s sampling, release build, mDNS on, rtnetlink on,
`scan_interval_s: 120` (a full ICMP sweep of the attached allowlisted /24
every 2 minutes, which is the dominant cost).

Environment, recorded as found: the workstation on the lab Wi-Fi
(192.168.10.0/24) and a wired LAN; the robot cable network
(192.168.50.0/24) was not attached during this run, so it was correctly
skipped as "not directly attached". Devices: `jetson-a` (a Jetson on the
robot, reachable over Wi-Fi, SSH login via an existing ControlMaster), `robot-a`
(not reachable from the workstation; this run predates `via:` support),
`jetson-b` (absent).

| t (s) | RSS (KiB) | threads | fds | CPU total (ms) | tokio tasks | device checks | ICMP | TCP | keyscans | logins | discoveries | cache writes | history events |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| 0 | 7724 | 5 | 22 | 0 | 17 | 3 | 1 | 0 | 0 | 0 | 1 | 0 | 0 |
| 300 | 8808 | 3 | 21 | 130 | 17 | 129 | 826 | 21 | 1 | 1 | 3 | 3 | 10 |
| 600 | 9044 | 3 | 21 | 270 | 17 | 257 | 1396 | 33 | 1 | 2 | 5 | 4 | 10 |
| 900 | 9172 | 3 | 21 | 420 | 17 | 386 | 1967 | 45 | 2 | 3 | 7 | 5 | 11 |
| 1200 | 9296 | 4 | 53 | 570 | 49 | 517 | 2793 | 57 | 2 | 4 | 10 | 6 | 11 |
| 1500 | 9312 | 3 | 21 | 720 | 17 | 646 | 3363 | 71 | 3 | 5 | 12 | 7 | 11 |
| 1801 | 7972 | 3 | 21 | 880 | 17 | 776 | 3934 | 83 | 3 | 6 | 14 | 8 | 11 |

Findings:

- **CPU**: 880 ms over 1801 s, about **0.05 % of one core**, including the
  periodic scans. Without background scans the cost is the 5 s check of each
  reachable device.
- **Memory**: 7.7 MB at start, peak 9.4 MB, 8.0 MB at the end. No upward trend.
- **Threads**: 3 steady (main runtime thread, mdns-sd, one blocking-pool
  worker that comes and goes).
- **File descriptors**: 21 steady; 53 only in samples taken during a scan
  (32 concurrent ICMP sockets), back to 21 afterwards.
- **Tasks**: 17 steady (IPC accept, coordinator, persistence, netlink,
  network-change debouncer, 3 monitors, mDNS consumer and browse tasks, the
  signal handler, the IPC handler answering the sample); 49 only during scans
  (bounded by `scan_concurrency` 32).
- **Disk**: 8 batched cache writes in 30 minutes.
- **History**: 11 events, all real transitions (including jetson-a's flaky
  Wi-Fi: two failed checks -> DEGRADED -> recovered 12 s later, never OFFLINE).
- **Probe rates for one reachable device**: ICMP every 5 s, TCP/22 about every
  30 s (83 TCP probes in 30 min across all devices), host-key scan 3 times,
  login check 6 times.
- **netlink events** (7630) are almost entirely ARP state changes caused by the
  scans themselves; each costs one parse and a hash-map update.

## Simulated churn soak

`soak_churn_resources_bounded` (ignored by default): 5 devices on the simulated
network; every 1.5 s one of them goes up/down, flips its SSH port, moves to a
different IP, or a full discovery runs. Release build, same process as the
test harness.

| Run | Duration | Steps | Tasks start/end/peak | fds start/end | RSS start -> end (KiB) |
|---|---|---|---|---|---|
| 1 (harness recording every probe) | 600 s | 308 | 9 / 9 / 9 | 17 / 17 | 7700 -> 9868 |
| 2 (harness recording off) | 300 s | 155 | 9 / 9 / 9 | 17 / 17 | 7708 -> 8244 |
| 3 (harness recording off) | 1800 s | 924 | 9 / 9 / 9 | 17 / 17 | 7720 -> 8656 |

Run 1's growth was mostly the test harness's own probe log (up to 100k
strings in the test process); with it disabled (run 2) growth fell to about
35 KiB/minute and was decelerating. Run 3 (30 minutes): +936 KiB in total, slowing from about 22 KiB/min early to
about 11 KiB/min in the last 5 minutes, with the history ring already full
(1000 events) after about 18 minutes. The curve had not fully flattened when
the run ended, so boundedness is not proven. ASSUMPTION: the remainder is
SQLite's per-connection page cache (default cap about 2 MB) filling as the
events table grows toward its 10 000-row retention, plus allocator
fragmentation; a longer run (or `PRAGMA cache_size`) would settle it. The
real-network idle soak showed no upward trend. All devices
converged back to GREEN at their final addresses after each run, and task and
descriptor counts never moved.

## Memory attribution soaks (accelerated, instrumented)

After the 30-minute run above left growth unexplained, `lablink metrics` gained
attribution gauges (glibc heap via `mallinfo2`, `sqlite3_memory_used`, SQLite row
counts and file sizes, and the size of every long-lived registry collection),
and the churn soak was run about 2x faster (steps paced at 200 ms; measured
about 650 ms per step including the work, about 2.6 history events per second).

Soak A: `history_retention: 2000`, 60 minutes, 5528 churn steps.

| t (s) | heap in use (B) | glibc arena (B) | SQLite heap (B) | event rows | history ring | tasks | fds |
|---|---|---|---|---|---|---|---|
| 0 | 412752 | 1310720 | 125032 | 0 | 31 | 9 | 17 |
| 529 | 995856 | n/a | 299768 | 1447 | 1000 | 9 | 17 |
| 904 | 1089600 | 1748992 | 374024 | 2000 | 1000 | 9 | 17 |
| 1811 | 1103408 | 1769472 | 374024 | 2000 | 1000 | 9 | 17 |
| 2748 | 1116032 | 1781760 | 374024 | 2000 | 1000 | 9 | 17 |
| 3592 | 1119056 | 1785856 | 374024 | 2000 | 1000 | 9 | 17 |

Growth tracked the SQLite events table until it reached its retention cap
(t = 904 s); for the remaining 45 minutes SQLite's heap stayed byte-identical,
every registry collection stayed at its bound, and the glibc heap moved by
29 KB in total (allocator noise). The WAL file plateaued near 4.1 MB (SQLite
auto-checkpoint, 1000 pages); the main database stayed at 274 KB. Conclusion:
**bounded**; the earlier creep was the history table filling toward
`history_retention`. Process RSS is not a reliable trend signal here: both
long runs showed RSS dropping from about 8.6 MB to 5.7 MB mid-run while the
heap counters were unchanged (pages reclaimed by the kernel).

One structure was unbounded in principle and is now capped: the set that
rate-limits "ambiguous" history events (keyed by address and reason; spoofed
mDNS from many addresses could grow it). It is capped at 1024 entries with a
regression test.

Soak B (`history_retention` default 10000, 90 minutes, 8292 churn steps): the
events table reached its 10 000-row cap at t = 3749 s (heap in use 2029616 B,
SQLite heap 1280248 B). Over the remaining 27 minutes heap in use moved +14.5
KiB and SQLite heap +8.7 KiB (the database file grew 48 KiB as freed pages were
reused), and both were flat across the last 15 samples (heap about 2.04 MB,
SQLite 1288984 B). Tasks 9 and fds 17 throughout. Same conclusion at the
production setting: **bounded**, with a steady-state daemon heap of about
2 MB once the history table is full.

## How to reproduce

```bash
cargo build --release
scripts/soak.sh ~/.config/lablink/config.yaml /tmp/lablink-soak 1800 60
LABLINK_SOAK_SECS=600 cargo test -p lablink-daemon --release --test daemon soak -- --ignored --nocapture
lablink metrics            # live counters of a running daemon
```

## Not measured

- Any run on a Jetson (the daemon and CLI build for
  aarch64 in CI as a compile check only).
- The GUI's idle CPU (it repaints every 2 s; not instrumented).
- A soak with the robot cable network attached (a second /24 swept every 2 min).

## 0.3.0 public-release changes: resource impact (2026-10-09)

Same machine, same config (one allowed /24, one monitored SSH device in a
local Docker container, no scanning), daemon and GUI both running, GUI under
Xvfb with software rendering (llvmpipe), 10 s warm-up, then CPU time over
120 s from `/proc/<pid>/stat`:

| | daemon RSS | daemon threads | daemon CPU | GUI RSS | GUI CPU |
|---|---|---|---|---|---|
| before (97e1fb8) | 7284 KiB | 2 | 0.008 % | 106296 KiB | 1.11 % |
| after (0.3.0) | 7468 KiB | 2 | 0.008 % | 103844 KiB | 1.08 % |

The daemon grew by about 180 KiB (profile and override fields per device);
its idle CPU is unchanged. Nothing new polls: the GUI still repaints once per
2 s status poll, the systemd service state is queried only when the Settings
tab opens or the daemon becomes unreachable, and doctor checks run only when
asked. The GUI CPU figure is dominated by software rendering in Xvfb and is
not representative of a GPU-accelerated desktop. In the clean-room container
the daemon used 8.2 MB RSS and 2 threads after the full first-run workflow.
