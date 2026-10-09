#!/usr/bin/env bash
# Resource soak for lablinkd. Starts a daemon (or attaches to a running one),
# samples resource usage and activity counters every INTERVAL seconds for
# DURATION seconds, and writes a CSV plus the daemon log.
#
# usage: scripts/soak.sh <config.yaml> <out-dir> [duration_s=1800] [interval_s=60]
# env:   LABLINKD / LABLINK  paths to the binaries (default: target/release)
set -euo pipefail
cfg=${1:?config}; out=${2:?out dir}; dur=${3:-1800}; int=${4:-60}
bin_d=${LABLINKD:-target/release/lablinkd}; bin_c=${LABLINK:-target/release/lablink}
mkdir -p "$out"
sock="$out/s/d.sock"; export LABLINK_SOCKET="$sock"
"$bin_d" --config "$cfg" --socket "$sock" --state-dir "$out/state" --no-color >"$out/daemon.log" 2>&1 &
pid=$!
trap 'kill -TERM $pid 2>/dev/null; wait $pid 2>/dev/null || true' EXIT
for _ in $(seq 50); do [ -S "$sock" ] && break; sleep 0.1; done
hz=$(getconf CLK_TCK)
echo "t_s,rss_kib,threads,fds,cpu_ms_total,tokio_tasks,device_checks,icmp_probes,tcp_probes,keyscans,auth_checks,discoveries,scan_hosts_probed,netlink_events,persist_writes,history_events,ipc_requests" >"$out/samples.csv"
start=$(date +%s)
while :; do
  now=$(date +%s); t=$((now - start))
  read -r ut st < <(awk '{print $14, $15}' /proc/$pid/stat)
  cpu=$(( (ut + st) * 1000 / hz ))
  rss=$(awk '/VmRSS/{print $2}' /proc/$pid/status)
  thr=$(awk '/Threads/{print $2}' /proc/$pid/status)
  fds=$(ls /proc/$pid/fd | wc -l)
  m=$("$bin_c" metrics --json)
  get() { printf '%s' "$m" | grep -o "\"$1\": *[0-9]*" | grep -o '[0-9]*$'; }
  echo "$t,$rss,$thr,$fds,$cpu,$(get tokio_alive_tasks),$(get device_checks),$(get icmp_probes),$(get tcp_probes),$(get keyscans),$(get auth_checks),$(get discoveries),$(get scan_hosts_probed),$(get netlink_events),$(get persist_writes),$(get history_events),$(get ipc_requests)" >>"$out/samples.csv"
  [ "$t" -ge "$dur" ] && break
  sleep "$int"
done
"$bin_c" status >"$out/final_status.txt" || true
"$bin_c" history --limit 200 >"$out/history.txt" || true
echo "done: $out/samples.csv"
