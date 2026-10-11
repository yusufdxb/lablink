#!/usr/bin/env bash
# Upgrade test: a user with a working 0.3.0 install (sites, adopted devices,
# pinned host keys, an SSH key, an open SSH session) installs the 0.3.1 .deb
# over it, with the old daemon still running.
#
#   0.3.0: init, adopt + trust + copy-id two robots, open a long SSH session
#   -> install the 0.3.1 .deb over the running 0.3.0 daemon
#   -> state untouched on disk, open session untouched
#   -> security-sensitive commands refuse the old daemon (exit 7), status warns
#   -> restart the daemon -> new client and daemon agree, both robots GREEN,
#      exec works, a new device can be adopted and trusted
#
# Synthetic credentials only (a throwaway key and password inside disposable
# containers on private Docker networks).
#
# Usage: BASE=ubuntu:20.04 scripts/upgrade-test.sh OLD_DEB [OUT_DIR]
#   OLD_DEB   the previous release's lablink_<ver>_amd64.deb
#   dist/     the new release (scripts/release.sh)
set -euo pipefail
cd "$(dirname "$0")/.."

old_deb=${1:?usage: upgrade-test.sh OLD_DEB [OUT_DIR]}
base=${BASE:-ubuntu:24.04}
tag=${base#ubuntu:}
out=${2:-/tmp/lablink-upgrade-$(date -u +%Y%m%d-%H%M%S)-$tag}
id=$$
r=$((RANDOM % 150 + 20))
sub=10.234.$r.0/24; pre=10.234.$r
net=lablink-up-net-$id
desk=lablink-up-desktop-$id
robots=("lablink-up-r1-$id" "lablink-up-r2-$id" "lablink-up-r3-$id")
deb=$(ls dist/lablink_*_amd64.deb | head -1)
new_version=$(sed -n 's/^lablink //p' dist/BUILDINFO | head -1)
new_sha=$(sed -n 's/^commit: //p' dist/BUILDINFO)
old_version=$(dpkg-deb -f "$old_deb" Version)
[ "$old_version" != "$new_version" ] || { echo "old and new versions are both $old_version"; exit 1; }
mkdir -p "$out"
results="$out/results.md"
{ echo "# LabLink upgrade $old_version -> $new_version ($base, $(date -u +%FT%TZ))"; echo
  echo "| # | step | result | evidence |"; echo "|---|---|---|---|"; } > "$results"
n=0
xfer=/var/tmp

cleanup() {
    local rc=$?
    if [ $rc -ne 0 ] && ! grep -q "| FAIL |" "$results" 2>/dev/null; then
        echo "FAIL  aborted (exit $rc) at: $BASH_COMMAND"
        echo "| - | aborted | FAIL | exit $rc at: $BASH_COMMAND |" >> "$results"
    fi
    docker rm -f "$desk" "${robots[@]}" >/dev/null 2>&1 || true
    docker network rm "$net" >/dev/null 2>&1 || true
}
trap cleanup EXIT

pass() { n=$((n + 1)); echo "| $n | $1 | PASS | $2 |" >> "$results"; echo "PASS  $1  ($2)"; }
fail() {
    n=$((n + 1)); echo "| $n | $1 | FAIL | $2 |" >> "$results"; echo "FAIL  $1  ($2)"
    as_tester 'journalctl --user -u lablinkd --no-pager -n 300' > "$out/lablinkd.log" 2>&1 || true
    as_tester 'cat ~/.config/lablink/config.yaml' > "$out/config-at-failure.yaml" 2>&1 || true
    exit 1
}
as_tester() {
    docker exec -u tester -w /home/tester -e HOME=/home/tester -e USER=tester \
        -e XDG_RUNTIME_DIR=/run/user/1000 \
        -e DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus \
        "$desk" bash -c "$1"
}
as_tester_in() { docker exec -i -u tester -w /home/tester -e HOME=/home/tester -e USER=tester \
    -e XDG_RUNTIME_DIR=/run/user/1000 -e DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus \
    "$desk" bash -c "$1"; }
out_of() { as_tester "$1" 2>&1 || true; }
code_of() { local c=0; as_tester "$1" >/dev/null 2>&1 || c=$?; echo "$c"; }
wait_for() {
    local deadline=$((SECONDS + $1))
    until as_tester "$2" >/dev/null 2>&1; do
        [ $SECONDS -lt $deadline ] || return 1
        sleep 1
    done
}
# Everything the user would lose if an upgrade damaged it: configuration,
# pinned host keys, daemon state, the SSH key.
state_hash() {
    as_tester 'cd ~; find .config/lablink .local/state/lablink .ssh -type f ! -name "cache.db*" ! -name "*.lock" ! -name known_hosts.old -print0 2>/dev/null | sort -z | xargs -0 sha256sum'
}

echo "== images and network"
docker build -q -t "lablink-cr-desktop:$tag" --build-arg BASE="$base" -f tests/cleanroom/desktop.Dockerfile tests/cleanroom >/dev/null
docker build -q -t lablink-cr-robot -f tests/cleanroom/robot.Dockerfile tests/cleanroom >/dev/null
docker network create --subnet "$sub" "$net" >/dev/null
for i in 0 1 2; do
    docker run -d --name "${robots[$i]}" --hostname "robot-up-$((i + 1))" --network "$net" --ip "$pre.$((20 + i))" lablink-cr-robot >/dev/null
    # The image bakes one set of host keys: every robot is its own machine.
    docker exec "${robots[$i]}" bash -c 'rm -f /etc/ssh/ssh_host_* && ssh-keygen -A >/dev/null && kill -HUP 1'
done
docker run -d --name "$desk" --hostname lab-desktop --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
    --network "$net" --ip "$pre.10" "lablink-cr-desktop:$tag" >/dev/null
wait_for 90 'systemctl --user is-system-running 2>/dev/null | grep -Eq "running|degraded"' \
    || fail "fresh machine" "systemd user session did not start"
pass "fresh machine" "$base with the previous release's prerequisites, three synthetic robots"

# ---- the old release ---------------------------------------------------------
docker cp "$old_deb" "$desk:$xfer/old.deb"
docker cp "$deb" "$desk:$xfer/new.deb"
docker exec "$desk" bash -c "apt-get update -qq && apt-get install -y -qq $xfer/old.deb" > "$out/apt-install-old.log" 2>&1 \
    || fail "install old" "apt-get install failed, see apt-install-old.log"
[ "$(out_of 'lablink version 2>/dev/null' | head -1 | awk '{print $2}')" = "$old_version" ] || fail "install old" "wrong version"
pass "install old" "$(basename "$old_deb") via apt"

as_tester 'ping -c 1 -W 1 '"$pre"'.1 >/dev/null 2>&1 || true'
printf 'Site Alpha\n1\ny\ny\nn\n' | as_tester_in 'lablink init' > "$out/init.txt" 2>&1 || fail "old: init" "see init.txt"
wait_for 30 'lablink ping' || fail "old: daemon" "daemon not answering"
as_tester 'ssh-keygen -q -t ed25519 -N "" -f ~/.ssh/id_ed25519 && printf "#!/bin/sh\necho robot-pass-1\n" > ~/askpass && chmod 700 ~/askpass'
for i in 1 2; do
    name=robot$i; ip=$pre.$((19 + i))
    as_tester "lablink adopt $ip $name --user robot --profile generic_linux --label 'Bench $i'" > "$out/adopt-$name.txt" 2>&1 \
        || fail "old: adopt $name" "$(cat "$out/adopt-$name.txt")"
    wait_for 60 "lablink status $name --json | grep -q \"\\\"ip\\\": \\\"$ip\\\"\"" || fail "old: $name address" "never resolved"
    as_tester "lablink trust $name --yes" > "$out/trust-$name.txt" 2>&1 || { as_tester "lablink status $name --json; lablink devices --json" > "$out/debug-$name.txt" 2>&1; fail "old: trust $name" "$(cat "$out/trust-$name.txt")"; }
    as_tester "SSH_ASKPASS=\$HOME/askpass SSH_ASKPASS_REQUIRE=force DISPLAY=:0 setsid -w lablink copy-id $name </dev/null" \
        > "$out/copy-id-$name.txt" 2>&1 || fail "old: copy-id $name" "$(tail -3 "$out/copy-id-$name.txt")"
    wait_for 40 "lablink status $name --json | grep -q '\"color\": \"green\"'" || fail "old: $name green" "never GREEN"
done
[ "$(out_of 'lablink exec robot1 hostname')" = robot-up-1 ] || fail "old: exec" "robot1 hostname"
pass "old install in use" "site, two devices adopted, host keys pinned, SSH key installed, both GREEN"

# A long SSH session the upgrade must not disturb.
as_tester 'nohup lablink exec robot1 "sleep 900" >/tmp/long-session.log 2>&1 &'
sleep 3
docker exec "${robots[0]}" pgrep -f "sleep 900" >/dev/null || fail "old: open session" "remote sleep did not start"

state_hash > "$out/state-before.sha256"
as_tester 'lablink export -o ~/before.yaml' >/dev/null 2>&1 || fail "old: export" "failed"
as_tester 'cat ~/.config/lablink/config.yaml' > "$out/config-before.yaml"
old_pid=$(out_of 'systemctl --user show lablinkd -p MainPID --value')

# ---- upgrade over the running old daemon -----------------------------------------
docker exec "$desk" bash -c "apt-get install -y -qq $xfer/new.deb" > "$out/apt-install-new.log" 2>&1 \
    || fail "upgrade" "apt-get install of the new .deb failed, see apt-install-new.log"
v=$(out_of 'lablink version 2>/dev/null'); echo "$v" > "$out/version-after-upgrade.txt"   # stdout only: the stale-daemon warning goes to stderr
[ "$(head -1 <<<"$v" | awk '{print $2}')" = "$new_version" ] || fail "upgrade" "client is not $new_version: $(head -1 <<<"$v")"
pass "upgrade" "apt installed $(basename "$deb") over the running $old_version daemon; client now $new_version"

state_hash > "$out/state-after-install.sha256"
diff "$out/state-before.sha256" "$out/state-after-install.sha256" > "$out/state-diff-install.txt" \
    || fail "state preserved (install)" "files changed by the package install, see state-diff-install.txt"
[ "$(out_of 'systemctl --user show lablinkd -p MainPID --value')" = "$old_pid" ] \
    && as_tester 'systemctl --user is-active lablinkd' >/dev/null || fail "no disruption" "old daemon was restarted or stopped by the install"
docker exec "${robots[0]}" pgrep -f "sleep 900" >/dev/null || fail "no disruption" "open SSH session died during the install"
pass "state preserved, no disruption" "config, pinned keys, SSH key byte-identical after install; old daemon (pid $old_pid) and the open SSH session untouched"

# ---- the new client against the old daemon --------------------------------------
for cmd in "exec robot1 true" "ssh robot1 -q </dev/null" "resolve robot1" "trust robot1" "forget robot2 --yes" \
           "set robot1 --recheck" "discover" "doctor" "copy-id robot1 </dev/null"; do
    c=$(code_of "lablink $cmd")
    msg=$(out_of "lablink $cmd")
    { [ "$c" -eq 7 ] && grep -q "systemctl --user restart lablinkd" <<<"$msg"; } \
        || fail "refuses old daemon" "'lablink $cmd' exit $c (expected 7 with the restart command): $msg"
done
for cmd in "status" "devices" "version"; do
    [ "$(code_of "lablink $cmd")" -ne 7 ] || fail "read-only commands" "'lablink $cmd' was refused"
done
out_of 'lablink status' | grep -qiE 'older|different|restart' || fail "read-only commands" "status gives no warning about the old daemon"
state_hash > "$out/state-after-refusals.sha256"
diff -q "$out/state-before.sha256" "$out/state-after-refusals.sha256" >/dev/null || fail "refusals" "a refused command changed state"
pass "refuses old daemon" "exec, ssh, resolve, trust, forget, set, discover, doctor, copy-id exit 7 with the restart command; status/devices/version still answer and warn; nothing changed"

# ---- restart, recover --------------------------------------------------------
as_tester 'systemctl --user restart lablinkd'
wait_for 30 'lablink ping' || fail "restart" "new daemon not answering"
new_pid=$(out_of 'systemctl --user show lablinkd -p MainPID --value')
[ "$new_pid" != "$old_pid" ] || fail "restart" "daemon pid unchanged"
vv=$(out_of 'lablink version 2>&1'); echo "$vv" > "$out/version-after-restart.txt"
grep -q "commit $new_sha" <<<"$vv" && grep -qE "lablinkd $new_version .*running|running" <<<"$vv" || fail "restart" "version output: $vv"
! grep -qiE 'older|different' <<<"$vv" || fail "restart" "still reports a mismatch: $vv"
pass "restart" "new daemon pid $new_pid, commit ${new_sha:0:12}; client and daemon agree"

for name in robot1 robot2; do
    wait_for 60 "lablink status $name --json | grep -q '\"color\": \"green\"'" || fail "recovered: $name" "not GREEN: $(out_of "lablink status $name")"
    as_tester "lablink status $name --json" | grep -q '"identity": "verified"' || fail "recovered: $name" "identity not verified"
done
[ "$(out_of 'lablink exec robot1 hostname')" = robot-up-1 ] && [ "$(out_of 'lablink exec robot2 hostname')" = robot-up-2 ] \
    || fail "recovered: exec" "hostname through exec failed"
[ "$(code_of 'lablink exec robot1 "exit 7"')" -eq 7 ] || fail "recovered: exec" "remote exit code lost"
as_tester 'lablink export -o ~/after.yaml' >/dev/null 2>&1 || fail "recovered: export" "failed"
for want in "name: robot1" "name: robot2" "id: site-alpha" "Bench 1" "Bench 2"; do
    grep -q "$want" <(as_tester 'cat ~/after.yaml') || fail "recovered: configuration" "'$want' missing after upgrade"
done
state_hash > "$out/state-after-restart.sha256"
diff "$out/state-before.sha256" "$out/state-after-restart.sha256" > "$out/state-diff-restart.txt" \
    || echo "(informational) files changed by the new daemon's first start: see state-diff-restart.txt" >> "$out/notes.txt"
as_tester 'cat ~/.config/lablink/config.yaml' > "$out/config-after.yaml"
docker exec "${robots[0]}" pgrep -f "sleep 900" >/dev/null || fail "no disruption" "open SSH session died"
pass "devices recovered" "robot1, robot2 GREEN with identity verified, exec works, configuration complete; the SSH session opened before the upgrade is still alive on robot1"

# ---- trust and adoption still work ----------------------------------------------
as_tester "lablink adopt $pre.22 robot3 --user robot --profile generic_linux" > "$out/adopt-robot3.txt" 2>&1 \
    || fail "new device" "adopt: $(cat "$out/adopt-robot3.txt")"
wait_for 60 "lablink status robot3 --json | grep -q \"\\\"ip\\\": \\\"$pre.22\\\"\"" || fail "new device" "robot3 address never resolved"
[ "$(code_of 'lablink trust robot3 --json >/dev/null')" -eq 7 ] || fail "new device" "trust preview did not exit 7"
as_tester 'lablink trust robot3 --yes' > "$out/trust-robot3.txt" 2>&1 || fail "new device" "trust: $(cat "$out/trust-robot3.txt")"
wait_for 30 'lablink status robot3 --json | grep -q "\"identity\": \"verified\""' || fail "new device" "robot3 identity not verified"
as_tester "SSH_ASKPASS=\$HOME/askpass SSH_ASKPASS_REQUIRE=force DISPLAY=:0 setsid -w lablink copy-id robot3 </dev/null" \
    > "$out/copy-id-robot3.txt" 2>&1 || fail "new device" "copy-id: $(tail -3 "$out/copy-id-robot3.txt")"
wait_for 40 "lablink status robot3 --json | grep -q '\"color\": \"green\"'" || fail "new device" "robot3 never GREEN"
# And the security stop still stops: new host key on robot2 -> refused with 6.
docker exec "${robots[1]}" bash -c 'rm -f /etc/ssh/ssh_host_* && ssh-keygen -A >/dev/null && kill -HUP 1'
sleep 1
as_tester 'lablink set robot2 --recheck >/dev/null'
wait_for 30 'lablink status robot2 --json | grep -q "\"identity\": \"mismatch\""' || fail "security stop" "mismatch not detected after upgrade"
[ "$(code_of 'lablink exec robot2 true')" -eq 6 ] || fail "security stop" "exec not refused with 6"
pass "new work after upgrade" "robot3 adopted, trusted (preview exit 7, then --yes), copy-id, GREEN; a changed host key on robot2 is a RED MISMATCH and exec exits 6"

echo "all upgrade checks passed ($old_version -> $new_version on $base)"
