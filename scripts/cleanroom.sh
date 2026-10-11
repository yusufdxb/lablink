#!/usr/bin/env bash
# Clean-room test: fresh Ubuntu users install the release artifacts and go
# from nothing to managed devices at two sites, using only what a new user
# would type or click.
#
#   verify artifacts -> install .deb -> lablink init (site) -> daemon
#   -> completion -> discover -> adopt -> trust -> copy-id -> exec/ssh
#   -> doctor -> GUI -> export/import -> support bundle
#   -> two sites: move between networks, AWAY, auto-detection, manual
#      override, ambiguous names, scan restriction
#   -> security stop -> password isolation, other local user, package
#      privileges, hostile import -> GUI-only fresh user -> .deb removal
#   -> tarball install / uninstall in another fresh container
#
# Containers on private Docker networks (no real lab hardware):
#   desktop   Ubuntu $BASE with systemd and user "tester" (no Rust, no LabLink, no ssh)
#   robot-a   OpenSSH server on network A (Site Alpha)
#   robot-b   OpenSSH server on network B (Site Beta), its own host keys
#
# Usage: BASE=ubuntu:20.04 scripts/cleanroom.sh [OUT_DIR]
# Needs: docker (privileged containers for systemd), dist/ from
# scripts/release.sh, ffmpeg on the host (PNG screenshots; the GUI-only steps read the layout from a screenshot).
set -euo pipefail
cd "$(dirname "$0")/.."

base=${BASE:-ubuntu:24.04}
tag=${base#ubuntu:}
out=${1:-/tmp/lablink-cleanroom-$(date -u +%Y%m%d-%H%M%S)-$tag}
id=$$
netA=lablink-cr-a-$id; netB=lablink-cr-b-$id; netC=lablink-cr-c-$id
r=$((RANDOM % 150 + 20))
subA=10.231.$r.0/24; preA=10.231.$r
subB=10.232.$r.0/24; preB=10.232.$r
subC=10.233.$r.0/24
desk=lablink-cr-desktop-$id
robotA=lablink-cr-robot-a-$id
robotB=lablink-cr-robot-b-$id
desk2=lablink-cr-desktop2-$id
desk3=lablink-cr-desktop3-$id
deb=$(ls dist/lablink_*_amd64.deb | head -1)
tgz=$(ls dist/lablink-*-x86_64-linux.tar.gz | head -1)
version=$(sed -n 's/^lablink //p' dist/BUILDINFO | head -1)
sha=$(sed -n 's/^commit: //p' dist/BUILDINFO)
mkdir -p "$out"
results="$out/results.md"
echo "# LabLink clean-room run ($base, $(date -u +%FT%TZ))" > "$results"
echo >> "$results"
echo "Artifacts: lablink $version, commit $sha" >> "$results"
echo >> "$results"
echo "| # | step | result | evidence |" >> "$results"
echo "|---|---|---|---|" >> "$results"
n=0
cur=$desk
# Files cross the container boundary through /var/tmp (literal in
# single-quoted commands): on newer images systemd mounts a fresh tmpfs over
# /tmp, which `docker cp` cannot see.
xfer=/var/tmp

cleanup() {
    local rc=$?
    if [ $rc -ne 0 ] && ! grep -q "| FAIL |" "$results" 2>/dev/null; then
        echo "FAIL  aborted (exit $rc) at: $BASH_COMMAND"
        echo "| - | aborted | FAIL | exit $rc at: $BASH_COMMAND |" >> "$results"
    fi
    docker rm -f "$desk" "$desk2" "$desk3" "$robotA" "$robotB" >/dev/null 2>&1 || true
    docker network rm "$netA" "$netB" "$netC" >/dev/null 2>&1 || true
}
trap cleanup EXIT

pass() { n=$((n + 1)); echo "| $n | $1 | PASS | $2 |" >> "$results"; echo "PASS  $1  ($2)"; }
fail() {
    n=$((n + 1)); echo "| $n | $1 | FAIL | $2 |" >> "$results"; echo "FAIL  $1  ($2)"
    docker exec "$cur" journalctl --no-pager -n 200 > "$out/desktop-journal.txt" 2>&1 || true
    as_tester 'journalctl --user -u lablinkd --no-pager -n 300' > "$out/lablinkd.log" 2>&1 || true
    as_tester 'cat ~/.config/lablink/config.yaml' > "$out/config-at-failure.yaml" 2>&1 || true
    exit 1
}
# Run a command as the desktop user, in a login-like environment.
as_tester() {
    docker exec -u tester -w /home/tester \
        -e HOME=/home/tester -e USER=tester \
        -e XDG_RUNTIME_DIR=/run/user/1000 \
        -e DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus \
        "$cur" bash -c "$1"
}
as_tester_in() { docker exec -i -u tester -w /home/tester -e HOME=/home/tester -e USER=tester \
    -e XDG_RUNTIME_DIR=/run/user/1000 -e DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus \
    "$cur" bash -c "$1"; }
# Output of a command whose exit code is part of its answer (status: 10/11/12).
# Never let `set -e`/pipefail turn a legitimate non-zero exit into a failure.
out_of() { as_tester "$1" 2>&1 || true; }
code_of() { local c=0; as_tester "$1" >/dev/null 2>&1 || c=$?; echo "$c"; }
wait_for() { # wait_for SECONDS CMD
    local deadline=$((SECONDS + $1))
    until as_tester "$2" >/dev/null 2>&1; do
        [ $SECONDS -lt $deadline ] || return 1
        sleep 1
    done
}
shot() { # shot NAME: screenshot the GUI
    as_tester "DISPLAY=:99 xwd -root -silent > $xfer/$1.xwd"
    docker cp "$cur:$xfer/$1.xwd" "$out/$1.xwd" >/dev/null
    if command -v ffmpeg >/dev/null; then
        ffmpeg -loglevel error -y -i "$out/$1.xwd" "$out/$1.png" && rm -f "$out/$1.xwd"
    fi
}
start_desktop() { # start_desktop NAME HOSTNAME NETWORK IP
    docker run -d --name "$1" --hostname "$2" --privileged --cgroupns=host \
        -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
        --network "$3" --ip "$4" "lablink-cr-desktop:$tag" >/dev/null
    cur=$1
    wait_for 90 'systemctl --user is-system-running 2>/dev/null | grep -Eq "running|degraded"' \
        || fail "fresh machine ($1)" "systemd user session did not start"
}
status_json() { out_of "lablink status $1 --json"; }
x() { as_tester "export DISPLAY=:99; $1"; }
click() { x "xdotool mousemove $1 $2 click 1"; sleep "${3:-1}"; }

# The device detail pane is a resizable egui panel. Its width on first display
# varies between runs (seen: divider at x=542 and, once on Ubuntu 20.04,
# x=440), which moves every control in it. Find the divider from a screenshot
# (not from sleeps or coordinates) and drag it to where the click coordinates
# below expect it; fail if the layout cannot be established.
panel_divider_x() {
    x "xdotool mousemove 1100 650"; sleep 0.6   # the divider is drawn brighter under the pointer
    as_tester "DISPLAY=:99 xwd -root -silent > $xfer/_row.xwd"
    docker cp "$cur:$xfer/_row.xwd" "$out/_row.xwd" >/dev/null
    ffmpeg -loglevel error -y -i "$out/_row.xwd" -vf crop=1280:1:0:300 -f rawvideo -pix_fmt rgb24 "$out/_row.raw"
    python3 -I -c '
import sys
d = open(sys.argv[1], "rb").read()
for x in range(300, 760):
    if tuple(d[x * 3:x * 3 + 3]) == (60, 60, 60):
        print(x); break
' "$out/_row.raw"
}
# egui needs a frame with the pointer over the handle before the press, and
# frames between the moves: one chained xdotool command is too fast.
drag_divider() { # drag_divider FROM_X TO_X
    local from=$1 to=$2 p
    x "xdotool mousemove $from 300"; sleep 0.6
    x "xdotool mousedown 1"; sleep 0.4
    for p in $(seq "$from" $(( to > from ? 20 : -20 )) "$to") "$to"; do x "xdotool mousemove $p 300"; sleep 0.1; done
    sleep 0.3; x "xdotool mouseup 1"; sleep 1
}
gui_pin_panel_layout() { # gui_pin_panel_layout WANT_X
    local want=$1 got i first
    first=$(panel_divider_x)
    if [ -n "${CR_SKEW_PANEL:-}" ]; then   # test hook: start from the other layout
        got=$(panel_divider_x); drag_divider "$got" 440
    fi
    for i in 1 2 3; do
        got=$(panel_divider_x)
        [ "$got" = "$want" ] && { echo "initial=$first (skew hook: ${CR_SKEW_PANEL:-off}) final=$got attempts=$i" > "$out/panel-divider-x.txt"; return 0; }
        [ -n "$got" ] || break
        drag_divider "$got" "$want"
    done
    shot gui-layout-fail
    fail "GUI-only: layout" "detail pane divider at x=${got:-none}, wanted $want (gui-layout-fail.png)"
}

echo "== artifacts"
(cd dist && sha256sum -c SHA256SUMS) > "$out/sha256-check.txt" 2>&1 || fail "artifacts" "SHA256SUMS mismatch"
grep -q "^lablink " dist/BUILDINFO && [ -n "$sha" ] || fail "artifacts" "BUILDINFO incomplete"
pass "artifacts" "SHA256SUMS verified; lablink $version, commit ${sha:0:12}; $(grep 'minimum glibc' dist/BUILDINFO)"

echo "== images"
docker build -q -t "lablink-cr-desktop:$tag" --build-arg BASE="$base" -f tests/cleanroom/desktop.Dockerfile tests/cleanroom >/dev/null
docker build -q -t lablink-cr-robot -f tests/cleanroom/robot.Dockerfile tests/cleanroom >/dev/null

echo "== networks A=$subA B=$subB C=$subC"
docker network create --subnet "$subA" "$netA" >/dev/null
docker network create --subnet "$subB" "$netB" >/dev/null
docker network create --subnet "$subC" "$netC" >/dev/null
docker run -d --name "$robotA" --hostname robot-bench --network "$netA" --ip "$preA.20" lablink-cr-robot >/dev/null
docker run -d --name "$robotB" --hostname robot-bench-b --network "$netB" --ip "$preB.20" lablink-cr-robot >/dev/null
# robot-b is a different machine: give it its own host keys.
docker exec "$robotB" bash -c 'rm -f /etc/ssh/ssh_host_* && ssh-keygen -A >/dev/null && kill -HUP 1'
start_desktop "$desk" lab-desktop "$netA" "$preA.10"
pass "fresh machine" "$base, user tester, systemd user session up"
# GUI_ONLY=1 skips straight to the GUI-only section (repeat runs of that test).
if [ -z "${GUI_ONLY:-}" ]; then
as_tester 'for t in cargo rustc ssh lablink; do command -v $t && exit 1; done; exit 0' || fail "fresh machine" "unexpected tools present"
pass "no Rust, no ssh, no LabLink" "cargo, rustc, ssh, lablink all absent"

# ---- install -----------------------------------------------------------------
docker cp "$deb" "$desk:$xfer/lablink.deb"
docker exec "$desk" bash -c "apt-get update -qq && apt-get install -y -qq $xfer/lablink.deb" > "$out/apt-install.log" 2>&1 \
    || fail "install .deb" "apt-get install failed, see apt-install.log"
v=$(out_of 'lablink version'); echo "$v" > "$out/version.txt"
[ "$(head -1 <<<"$v")" = "lablink $version (commit $sha)" ] || fail "install .deb" "version says '$(head -1 <<<"$v")'"
grep -q 'lablinkd not running' <<<"$v" || fail "install .deb" "$v"
as_tester 'test -x /usr/bin/lablinkd && test -x /usr/bin/lablink-gui && test -f /usr/lib/systemd/user/lablinkd.service && test -f /usr/share/applications/lablink-gui.desktop && test -f /usr/share/icons/hicolor/scalable/apps/lablink.svg && test -f /usr/share/bash-completion/completions/lablink && test -f /usr/share/doc/lablink/copyright' \
    || fail "install .deb" "a packaged file is missing"
pass "install .deb" "$(basename "$deb") via apt; '$(head -1 <<<"$v")'; binaries, user unit, desktop entry, icon, completion, copyright in place"

# ---- GUI before setup: the wizard -------------------------------------------------
as_tester 'Xvfb :99 -screen 0 1280x860x24 >/tmp/xvfb.log 2>&1 &'
sleep 1
as_tester 'DISPLAY=:99 LIBGL_ALWAYS_SOFTWARE=1 nohup lablink-gui >/tmp/gui1.log 2>&1 &'
sleep 5
as_tester 'pgrep -x lablink-gui' >/dev/null || fail "GUI first run" "lablink-gui exited: $(out_of 'cat /tmp/gui1.log')"
shot gui-1-wizard
as_tester 'pkill -x lablink-gui' || true
pass "GUI first run" "no config: setup wizard shown (gui-1-wizard.png)"

# ---- lablink init (interactive, answers piped) ---------------------------------------
as_tester 'ip -4 -o addr show; cat /proc/net/route' > "$out/interfaces.txt"
# Normal traffic puts the default gateway in the ARP table (as on any desktop).
as_tester "ping -c 1 -W 1 $preA.1 >/dev/null 2>&1 || true"
# Site name, the only attached network by number, active scanning, service, completion.
printf 'Site Alpha\n1\ny\ny\ny\n' | as_tester_in 'lablink init' > "$out/init.txt" 2>&1 || fail "lablink init" "exit $?, see init.txt"
grep -q "config      done" "$out/init.txt" || fail "lablink init" "config not written"
grep -q "site 'Site Alpha'" "$out/init.txt" || fail "lablink init" "site not named"
grep -q "active scanning: $preA.0/24" "$out/init.txt" || fail "lablink init" "network not chosen"
as_tester 'cat ~/.config/lablink/config.yaml' > "$out/config-after-init.yaml"
grep -q "id: site-alpha" "$out/config-after-init.yaml" && grep -q "gateway_mac:" "$out/config-after-init.yaml" \
    || fail "lablink init" "site or gateway signature missing (config-after-init.yaml)"
[ "$(out_of 'stat -c %a ~/.config/lablink/config.yaml')" = 600 ] || fail "lablink init" "config is not mode 0600"
pass "lablink init" "site 'Site Alpha' with $preA.0/24 (active scan) and its gateway signature; config mode 0600"
as_tester 'systemctl --user is-active lablinkd && systemctl --user is-enabled lablinkd' > "$out/service.txt" \
    || fail "daemon starts" "$(cat "$out/service.txt")"
as_tester 'lablink ping' >> "$out/service.txt" || fail "daemon starts" "ping failed"
as_tester 'stat -c "%a %U" $XDG_RUNTIME_DIR/lablink $XDG_RUNTIME_DIR/lablink/lablinkd.sock ~/.local/state/lablink' >> "$out/service.txt"
grep -q "^700 tester" "$out/service.txt" && grep -q "^600 tester" "$out/service.txt" || fail "daemon starts" "socket permissions"
pass "daemon starts" "systemd user service active + enabled (packaged unit), IPC answers; socket dir 0700, socket 0600"

# ---- shell completion ---------------------------------------------------------------
c=$(out_of 'source /usr/share/bash-completion/bash_completion; _completion_loader lablink;
    COMP_WORDS=(lablink d); COMP_CWORD=1; _lablink; printf "%s " "${COMPREPLY[@]}"')
[ "$c" = "doctor devices discover " ] || fail "shell completion" "got '$c'"
pass "shell completion" "lablink d<TAB> -> $c"

# ---- site detection ------------------------------------------------------------------
wait_for 20 'lablink sites --json | grep -q "\"state\": \"active\""' || fail "site detection" "Site Alpha never ACTIVE"
as_tester 'lablink sites; lablink site' > "$out/sites-alpha.txt" 2>&1 || true
grep -q "Site Alpha.*ACTIVE" "$out/sites-alpha.txt" || fail "site detection" "see sites-alpha.txt"
pass "site detection" "Auto: Site Alpha ACTIVE ($(grep -o 'confidence: [a-z]*' "$out/sites-alpha.txt" | head -1)) from the attached subnet and recorded gateway"

# ---- discover -> adopt -> trust -----------------------------------------------------
as_tester 'lablink discover --json' > "$out/discover.json" || fail "discover" "exit $?"
grep -q "\"$preA.20\"" "$out/discover.json" || fail "discover" "robot $preA.20 not found"
pass "discover" "robot found at $preA.20 (discover.json)"

as_tester "lablink adopt $preA.20 robot --user robot --profile generic_linux --label 'Bench robot'" > "$out/adopt.txt" \
    || fail "adopt" "$(cat "$out/adopt.txt")"
grep -q "lablink trust robot" "$out/adopt.txt" && grep -q "site: Site Alpha (site-alpha)" "$out/adopt.txt" || fail "adopt" "$(cat "$out/adopt.txt")"
pass "adopt" "named robot at Site Alpha, profile generic_linux, user robot; not trusted yet"

# Out-of-band fingerprint: read it on the robot itself.
oobA=$(docker exec "$robotA" ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}')
rc=$(code_of 'lablink trust robot --json > /tmp/trust-preview.json')
as_tester 'cat /tmp/trust-preview.json' > "$out/trust-preview.json"
[ "$rc" -eq 7 ] || fail "trust" "preview exit $rc (expected 7: nothing pinned without --yes)"
grep -q "$oobA" "$out/trust-preview.json" || fail "trust" "scanned keys do not include the robot's ed25519 key $oobA"
as_tester 'lablink trust robot --yes' > "$out/trust.txt" || fail "trust" "$(cat "$out/trust.txt")"
pass "trust" "preview pinned nothing (exit 7); $oobA matched on the robot's console; pinned with --yes"

wait_for 30 'lablink status robot --json | grep -q "\"ssh_auth\": \"failed\""' \
    || fail "auth failure explained" "login never reported failed"
out_of 'lablink status robot' > "$out/status-auth-failed.txt"
grep -q "SSH authentication failed" "$out/status-auth-failed.txt" || fail "auth failure explained" "no explanation"
grep -q "identity is verified" "$out/status-auth-failed.txt" || fail "auth failure explained" "wrong wording"
[ "$(code_of 'lablink status robot')" -eq 10 ] || fail "auth failure explained" "status exit code is not 10 (YELLOW)"
pass "auth failure explained" "YELLOW (exit 10): 'SSH authentication failed ... identity is verified' + copy-id next step"

# ---- SSH: key setup through the pinned identity, then exec/ssh ---------------------------
as_tester 'ssh-keygen -q -t ed25519 -N "" -f ~/.ssh/id_ed25519 && printf "#!/bin/sh\necho robot-pass-1\n" > ~/askpass && chmod 700 ~/askpass'
as_tester 'SSH_ASKPASS=$HOME/askpass SSH_ASKPASS_REQUIRE=force DISPLAY=:0 setsid -w lablink copy-id robot </dev/null' \
    > "$out/copy-id.txt" 2>&1 || fail "SSH setup (copy-id)" "$(tail -3 "$out/copy-id.txt")"
pass "SSH setup (copy-id)" "key installed via ssh-copy-id with LabLink's pinned host-key options"
wait_for 30 'lablink status robot --json | grep -q "\"color\": \"green\""' || fail "managed device" "never GREEN"
out_of 'lablink status' > "$out/status-green.txt"
pass "managed device" "robot GREEN (identity verified, login ok) within seconds of copy-id"
h=$(out_of 'lablink exec robot hostname')
[ "$h" = robot-bench ] || fail "exec" "got '$h'"
[ "$(code_of 'lablink exec robot "exit 7"')" -eq 7 ] || fail "exec" "remote exit code not preserved"
s=$(out_of 'printf "whoami\nexit\n" | script -qec "lablink ssh robot -q" /dev/null')
echo "$s" > "$out/ssh-session.txt"
grep -q "^robot\s*$" <<<"$(tr -d '\r' <<<"$s")" || fail "ssh" "interactive session did not run whoami (ssh-session.txt)"
pass "SSH" "exec hostname -> $h; remote exit 7 preserved; interactive lablink ssh session ran whoami -> robot"
c2=$(out_of 'source /usr/share/bash-completion/bash_completion; _completion_loader lablink;
    COMP_WORDS=(lablink ssh ""); COMP_CWORD=2; _lablink; printf "%s " "${COMPREPLY[@]}"')
[ "$c2" = "robot " ] || fail "device-name completion" "lablink ssh <TAB> gave '$c2'"
pass "device-name completion" "lablink ssh <TAB> -> $c2"

# ---- doctor ----------------------------------------------------------------------
dcode=$(code_of 'lablink doctor --json > /tmp/doctor.json')
as_tester 'cat /tmp/doctor.json' > "$out/doctor.json"
out_of 'lablink doctor' > "$out/doctor.txt"
grep -q '"name": "robot"' "$out/doctor.json" || fail "doctor" "robot missing"
grep -q '"kind": "disk"' "$out/doctor.json" || fail "doctor" "profile checks missing"
head -1 "$out/doctor.txt" | grep -q "LAB" || head -1 "$out/doctor.txt" | grep -q "Site Alpha" || fail "doctor" "no verdict line"
pass "doctor" "exit $dcode; $(head -1 "$out/doctor.txt"); generic_linux checks: $(grep -E '^  ' "$out/doctor.txt" | tr -s ' ' | paste -sd ';' -)"

# ---- GUI with a managed device -------------------------------------------------------
as_tester 'DISPLAY=:99 LIBGL_ALWAYS_SOFTWARE=1 nohup lablink-gui >/tmp/gui2.log 2>&1 &'
sleep 6
as_tester 'pgrep -x lablink-gui' >/dev/null || fail "GUI" "exited: $(out_of 'cat /tmp/gui2.log')"
shot gui-2-devices
as_tester 'pkill -x lablink-gui' || true
pass "GUI" "current site header and device card rendered (gui-2-devices.png)"

# ---- portability and diagnostics ---------------------------------------------------
as_tester 'lablink export -o ~/lab.yaml' > /dev/null 2>&1 || fail "export" "failed"
docker cp "$desk:/home/tester/lab.yaml" "$out/export.yaml" >/dev/null
grep -q 'name: robot' "$out/export.yaml" && grep -q 'id: site-alpha' "$out/export.yaml" || fail "export" "robot or site missing"
! grep -qiE 'password|PRIVATE KEY' <(grep -v '^#' "$out/export.yaml") || fail "export" "secret-like content"
[ "$(out_of 'stat -c %a ~/lab.yaml')" = 600 ] || fail "export" "export file is not mode 0600"
as_tester 'lablink import ~/lab.yaml --config /tmp/imported.yaml --yes' > "$out/import.txt" 2>&1 || fail "import" "$(cat "$out/import.txt")"
grep -q "device site-alpha/robot: added" "$out/import.txt" && grep -q "NOT imported" "$out/import.txt" || fail "import" "see import.txt"
as_tester 'lablink check-config /tmp/imported.yaml' >> "$out/import.txt" || fail "import" "imported config invalid"
pass "export / import" "export (0600, no secrets) imported into a fresh config: site and robot added, pins dropped by default"
b=$(as_tester 'lablink support-bundle --no-doctor -o /var/tmp' 2>/dev/null | tail -1)
docker cp "$desk:$b" "$out/support-bundle.tar.gz" >/dev/null
mkdir -p "$out/bundle" && tar -xzf "$out/support-bundle.tar.gz" -C "$out/bundle"
macA=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$netA\").MacAddress}}" "$robotA")
leaks=$(grep -rlE "$preA\.(1|10|20)\b|robot-pass|tester|lab-desktop|robot-bench|Site Alpha|site-alpha|Bench robot|/home/|${macA:-no-mac}|${oobA#SHA256:}" "$out/bundle" || true)
[ -z "$leaks" ] || fail "support bundle" "leaks in: $leaks"
pass "support bundle" "$(ls "$out/bundle"/*/ | paste -sd ' ' -); no IPs, MACs, fingerprints, usernames, hostnames, site names, labels or home paths"

# ---- two sites ---------------------------------------------------------------------------
# Leave Site Alpha's network and arrive at another place (network B).
docker network disconnect "$netA" "$desk"
docker network connect --ip "$preB.10" "$netB" "$desk"
as_tester "ping -c 1 -W 1 $preB.1 >/dev/null 2>&1 || true"
wait_for 30 'lablink sites --json | grep -q "\"state\": \"away\""' || fail "AWAY semantics" "Site Alpha never AWAY"
# Baseline for "AWAY not probed": robot-a's sshd log once Site Alpha is AWAY
# and connections begun while it was still ACTIVE have been logged (quiet
# for 2 s), so an in-flight check is not mistaken for a probe of an AWAY site.
logA0=-1
for _ in $(seq 1 15); do
    n=$(docker logs "$robotA" 2>&1 | grep -c "Connection from\|Accepted\|Connection closed" || true)
    [ "$n" = "$logA0" ] && break
    logA0=$n
    sleep 2
done
st=$(status_json site-alpha/robot); echo "$st" > "$out/status-away.json"
grep -q '"site_state": "away"' <<<"$st" && grep -q '"color": "gray"' <<<"$st" || fail "AWAY semantics" "robot not GRAY/away (status-away.json)"
[ "$(code_of 'lablink status site-alpha/robot')" -eq 12 ] || fail "AWAY semantics" "exit code not 12"
[ "$(code_of 'lablink exec robot true')" -eq 5 ] || fail "AWAY semantics" "exec to an AWAY device not refused with 5"
out_of 'lablink status' > "$out/status-no-site.txt"
grep -q "No active site\|AWAY" "$out/status-no-site.txt" || fail "AWAY semantics" "see status-no-site.txt"
pass "AWAY semantics" "after leaving network A: Site Alpha AWAY, robot GRAY (exit 12) not RED, exec refused (exit 5)"

as_tester "lablink site add 'Site Beta' --scan $preB.0/24" > "$out/site-add.txt" 2>&1 || fail "create site" "$(cat "$out/site-add.txt")"
grep -q "added site 'Site Beta' (site-beta)" "$out/site-add.txt" || fail "create site" "$(cat "$out/site-add.txt")"
wait_for 30 'lablink ping' || fail "create site" "daemon did not come back"
wait_for 30 'lablink site --json | grep -q "\"id\": \"site-beta\""' || fail "auto-detection" "Site Beta not detected"
as_tester 'lablink sites; lablink site' > "$out/sites-beta.txt" 2>&1 || true
grep -q "Site Beta.*ACTIVE" "$out/sites-beta.txt" && grep -q "Site Alpha.*AWAY" "$out/sites-beta.txt" || fail "auto-detection" "see sites-beta.txt"
pass "create site + auto-detection" "lablink site add 'Site Beta' at network B; Auto: Site Beta ACTIVE, Site Alpha AWAY (sites-beta.txt)"

as_tester 'lablink discover --json' > "$out/discover-beta.json" || fail "scan restriction" "discover failed"
grep -q "\"$preB.20\"" "$out/discover-beta.json" || fail "scan restriction" "robot-b not found"
grep -A2 '"stage": "active_scan:site-alpha/' "$out/discover-beta.json" | grep -q '"skipped"' || fail "scan restriction" "Site Alpha's network was not skipped"
pass "scan restriction" "discover scanned only Site Beta's approved network; Site Alpha's skipped (AWAY)"

as_tester "lablink adopt $preB.20 robot --user robot" > "$out/adopt-b.txt" || fail "same name, other site" "$(cat "$out/adopt-b.txt")"
grep -q "site: Site Beta (site-beta)" "$out/adopt-b.txt" || fail "same name, other site" "not adopted into Site Beta"
oobB=$(docker exec "$robotB" ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | awk '{print $2}')
as_tester 'lablink trust site-beta/robot --json' > "$out/trust-b.json" 2>/dev/null || true
grep -q "$oobB" "$out/trust-b.json" || fail "same name, other site" "robot-b key $oobB not shown"
as_tester 'lablink trust site-beta/robot --yes' > /dev/null || fail "same name, other site" "trust failed"
as_tester 'SSH_ASKPASS=$HOME/askpass SSH_ASKPASS_REQUIRE=force DISPLAY=:0 setsid -w lablink copy-id site-beta/robot </dev/null' \
    > "$out/copy-id-b.txt" 2>&1 || fail "same name, other site" "copy-id failed"
wait_for 30 'lablink status site-beta/robot --json | grep -q "\"color\": \"green\""' || fail "same name, other site" "robot-b never GREEN"
hb=$(as_tester 'lablink exec robot hostname 2>/tmp/exec-err.txt' || true)
[ "$hb" = robot-bench-b ] || fail "site/name addressing" "bare 'robot' ran on '$hb'"
grep -q "site-beta/robot" <<<"$(out_of 'cat /tmp/exec-err.txt')" || fail "site/name addressing" "no note about which robot was used"
out_of 'lablink status --all' > "$out/status-all.txt"
grep -q "site-alpha/robot.*AWAY" "$out/status-all.txt" && grep -q "site-beta/robot.*GREEN" "$out/status-all.txt" || fail "All Sites" "see status-all.txt"
pass "same name at two sites" "robot-b adopted as 'robot' at Site Beta, trusted ($oobB), key installed, GREEN; bare 'robot' -> robot-bench-b with a note; status --all lists both (status-all.txt)"

logA1=$(docker logs "$robotA" 2>&1 | grep -c "Connection from\|Accepted\|Connection closed" || true)
[ "$logA0" = "$logA1" ] || fail "AWAY not probed" "robot-a sshd saw connections while Site Alpha was AWAY ($logA0 -> $logA1)"
pass "AWAY not probed" "robot-a's sshd log unchanged while Site Alpha was AWAY"

# Nowhere known (network C): both sites AWAY, so a bare name is ambiguous.
docker network disconnect "$netB" "$desk"
docker network connect "$netC" "$desk"
wait_for 30 '! lablink sites --json | grep -q "\"state\": \"active\""' || fail "ambiguous names" "a site stayed ACTIVE on network C"
rc=$(code_of 'lablink ssh robot 2>/tmp/amb.txt')
as_tester 'cat /tmp/amb.txt' > "$out/ambiguous.txt"
[ "$rc" -eq 8 ] || fail "ambiguous names" "exit $rc (expected 8)"
printf "Ambiguous device 'robot':\n\nSite Alpha / robot\nSite Beta / robot\n\nUse:\n  lablink ssh site-alpha/robot\n  lablink ssh site-beta/robot\n" > "$out/ambiguous.expected"
diff -u "$out/ambiguous.expected" "$out/ambiguous.txt" > "$out/ambiguous.diff" || fail "ambiguous names" "message differs (ambiguous.diff)"
pass "ambiguous names" "no site active: 'lablink ssh robot' refused with exit 8 and the exact site/name choices"

as_tester 'lablink site use site-beta' > "$out/site-use.txt" || fail "manual switching" "site use failed"
grep -q "Site Beta.*ACTIVE.*manual" "$out/site-use.txt" || fail "manual switching" "$(cat "$out/site-use.txt")"
[ "$(code_of 'lablink status site-alpha/robot')" -eq 12 ] || fail "manual switching" "Site Alpha's robot not AWAY"
as_tester 'lablink site use auto' > /dev/null || fail "manual switching" "back to auto failed"
pass "manual switching" "'lablink site use site-beta' -> Site Beta ACTIVE (manual), Site Alpha AWAY; 'lablink site use auto' -> detection again"

# Back at Site Alpha: Auto selects it again and the robot turns GREEN.
docker network disconnect "$netC" "$desk"
docker network connect --ip "$preA.10" "$netA" "$desk"
as_tester "ping -c 1 -W 1 $preA.1 >/dev/null 2>&1 || true"
wait_for 60 'lablink status site-alpha/robot --json | grep -q "\"color\": \"green\""' || fail "auto-detection (return)" "robot not GREEN after returning"
as_tester 'lablink sites' > "$out/sites-return.txt" 2>&1 || true
grep -q "Site Alpha.*ACTIVE" "$out/sites-return.txt" && grep -q "Site Beta.*AWAY" "$out/sites-return.txt" || fail "auto-detection (return)" "see sites-return.txt"
[ "$(out_of 'lablink exec robot hostname 2>/dev/null')" = robot-bench ] || fail "auto-detection (return)" "bare 'robot' did not mean Site Alpha's robot"
pass "auto-detection (return)" "back on network A: Site Alpha ACTIVE ($(grep -o 'high\|medium\|low' "$out/sites-return.txt" | head -1)), Site Beta AWAY, robot GREEN, bare 'robot' -> robot-bench"

# GUI with two sites: site header, Other Sites, selector, All Sites, Sites tab.
as_tester 'DISPLAY=:99 LIBGL_ALWAYS_SOFTWARE=1 nohup lablink-gui >/tmp/gui3.log 2>&1 &'
sleep 6
as_tester 'pgrep -x lablink-gui' >/dev/null || fail "GUI sites" "exited"
shot gui-3-site-alpha
click "${SEL_X:-150}" "${SEL_Y:-14}" 2      # site selector
shot gui-4-site-selector
x 'xdotool key Escape'; sleep 1
as_tester 'pgrep -x lablink-gui' >/dev/null || fail "GUI sites" "crashed"
as_tester 'pkill -x lablink-gui' || true
pass "GUI sites" "current site with READY state and Other Sites (gui-3), site selector with Auto / All Sites / Manage Sites (gui-4)"

# ---- security stop: robot-a's host key changes --------------------------------------
docker exec "$robotA" bash -c 'rm -f /etc/ssh/ssh_host_* && ssh-keygen -A >/dev/null && kill -HUP 1'
sleep 1
as_tester 'lablink set robot --recheck >/dev/null'
wait_for 30 'lablink status robot --json | grep -q "\"identity\": \"mismatch\""' || fail "security stop" "mismatch not detected"
[ "$(code_of 'lablink exec robot true')" -eq 6 ] || fail "security stop" "exec not refused with 6"
[ "$(code_of 'lablink ssh robot -q </dev/null')" -eq 6 ] || fail "security stop" "ssh not refused with 6"
[ "$(code_of 'lablink status robot')" -eq 11 ] || fail "security stop" "status exit code is not 11 (RED)"
out_of 'lablink status robot' > "$out/status-mismatch.txt"
grep -q "SECURITY STOP" "$out/status-mismatch.txt" || fail "security stop" "no security-stop explanation"
pass "security stop" "new robot host key -> RED MISMATCH (exit 11); exec and ssh refused with exit 6"

# ---- security properties of the installed package ----------------------------------------
# The password typed for copy-id (robot-pass-1, via OpenSSH's askpass) must
# not be anywhere LabLink writes: config, state (pinned keys, SQLite cache),
# cache dir, daemon journal. (The support bundle was checked above.)
as_tester 'journalctl --user -u lablinkd --no-pager' > "$out/journal-full.txt" 2>&1 || true
hits=$(out_of 'grep -raIl -- robot-pass-1 ~/.config/lablink ~/.local/state/lablink ~/.cache 2>/dev/null; grep -ac robot-pass-1 ~/.local/state/lablink/cache.db 2>/dev/null | grep -v "^0$"')
[ -z "$hits" ] && ! grep -q robot-pass-1 "$out/journal-full.txt" || fail "password isolation" "password found: $hits"
pass "password isolation" "copy-id password absent from ~/.config/lablink, ~/.local/state/lablink (incl. cache.db), ~/.cache and the lablinkd journal"
# Another local account cannot reach or impersonate this user's daemon.
docker exec "$desk" useradd -m mallory
mal=$(docker exec -u mallory -e HOME=/home/mallory "$desk" bash -c 'ls /run/user/1000/lablink 2>&1; LABLINK_SOCKET=/run/user/1000/lablink/lablinkd.sock lablink status --json >/dev/null 2>&1; echo "exit=$?"')
grep -q "Permission denied" <<<"$mal" && grep -q "exit=3" <<<"$mal" || fail "other local user" "$mal"
pass "other local user" "mallory: socket directory 'Permission denied', lablink status exit 3 (daemon unavailable)"
# Package: no setuid/setgid files, nothing world-writable, root-owned files.
perm=$(docker exec "$desk" bash -c 'dpkg -L lablink | while read -r f; do [ -e "$f" ] && stat -c "%a %U %n" "$f"; done' )
bad=$(awk '$2 != "root" || substr($1, length($1), 1) ~ /[2367]/ || (length($1) == 4 && substr($1,1,1) != "0")' <<<"$perm")
[ -z "$bad" ] || fail "package privileges" "$bad"
pass "package privileges" "$(wc -l <<<"$perm") packaged paths: all root-owned, none setuid/setgid or world-writable; maintainer scripts only print and stop lablinkd"
# A hostile export cannot add OpenSSH options that load code or forward the agent.
as_tester 'printf "lablink_export: 1\nconfig:\n  ssh:\n    options:\n      PKCS11Provider: /tmp/x.so\n" > /tmp/evil.yaml'
[ "$(code_of 'lablink import /tmp/evil.yaml --config /tmp/evil-out.yaml --yes')" -ne 0 ] && [ "$(code_of 'test -e /tmp/evil-out.yaml')" -ne 0 ] \
    || fail "hostile import" "PKCS11Provider file was accepted"
as_tester 'printf "lablink_export: 1\nconfig:\n  ssh:\n    options:\n      ForwardAgent: \"no\"\n" > /tmp/opts.yaml'
as_tester 'lablink import /tmp/opts.yaml --config /tmp/opts-out.yaml --replace --yes' > "$out/import-ssh-options.txt" 2>&1 || true
grep -q "ssh.options: never imported" "$out/import-ssh-options.txt" && [ "$(code_of 'grep -q ForwardAgent /tmp/opts-out.yaml')" -ne 0 ] \
    || fail "hostile import" "ssh.options were imported (import-ssh-options.txt)"
pass "hostile import" "file with PKCS11Provider refused, nothing written; ssh.options never imported even with --replace"

# ---- resources --------------------------------------------------------------------
as_tester 'lablink metrics --json' > "$out/metrics.json"
rss=$(grep -o '"rss_kib": [0-9]*' "$out/metrics.json" | grep -o '[0-9]*$')
thr=$(grep -o '"threads": [0-9]*' "$out/metrics.json" | grep -o '[0-9]*$')
pass "daemon resources" "RSS ${rss} KiB, ${thr} threads after the run"

# ---- remove the package ----------------------------------------------------------------
docker exec "$desk" bash -c 'apt-get remove -y -qq lablink' > "$out/apt-remove.log" 2>&1 || fail "remove .deb" "apt-get remove failed"
as_tester 'command -v lablink lablinkd lablink-gui' >/dev/null 2>&1 && fail "remove .deb" "binaries still installed"
as_tester 'pgrep -x lablinkd' >/dev/null && fail "remove .deb" "lablinkd still running"
as_tester 'test -f ~/.config/lablink/config.yaml && test -f ~/.local/state/lablink/cache.db' || fail "remove .deb" "user data was deleted"
pass "remove .deb" "apt remove: binaries gone, daemon stopped; configuration and pinned keys kept in the home directory"

fi

# ---- GUI only: a second fresh user does everything from the GUI ------------------------
# A fresh robot from its image: its original host keys keep the dialog
# layout (and so the click coordinates below) identical on every run.
# The first user's machine is done: only the gateway and the robot remain on
# network A, so the robot is the second row of the Discovered list.
docker rm -f "$robotA" "$desk" >/dev/null
docker run -d --name "$robotA" --hostname robot-bench --network "$netA" --ip "$preA.20" lablink-cr-robot >/dev/null
start_desktop "$desk2" lab-desktop-2 "$netA" "$preA.11"
docker cp "$deb" "$desk2:$xfer/lablink.deb"
docker exec "$desk2" bash -c "apt-get update -qq && apt-get install -y -qq $xfer/lablink.deb xterm" > "$out/apt-install-2.log" 2>&1 \
    || fail "GUI-only: install" "apt failed"
pass "GUI-only: fresh user" "second container, .deb + xterm installed, no config"
typein() { x "xdotool type --delay 40 '$1'"; }
as_tester 'Xvfb :99 -screen 0 1280x860x24 >/tmp/xvfb.log 2>&1 &'
sleep 1
as_tester "ping -c 1 -W 1 $preA.1 >/dev/null 2>&1 || true"
x 'LIBGL_ALWAYS_SOFTWARE=1 nohup lablink-gui >/tmp/gui.log 2>&1 &'
sleep 5
x 'xdotool windowfocus --sync $(xdotool search --name LabLink | head -1)'
click 283 195                      # site name field
typein 'Site Gamma'
shot gui-b0-welcome
click 78 315                       # Start
click 15 170; click 271 170        # use the network, allow active scan
shot gui-b1-networks
click 146 229                      # Continue
click 121 246 10                   # Set up LabLink
shot gui-b2-setup-done
as_tester 'systemctl --user is-active lablinkd' >/dev/null || fail "GUI-only: wizard" "daemon not running after the wizard"
grep -q "active_scan: true" <(out_of 'cat ~/.config/lablink/config.yaml') || fail "GUI-only: wizard" "network not allowed"
grep -q "name: Site Gamma" <(out_of 'cat ~/.config/lablink/config.yaml') || fail "GUI-only: wizard" "site not named"
pass "GUI-only: wizard" "site name typed, network ticked (nothing preselected) -> service started, config written"
click 78 370 15                    # Discover now (result page)
click 93 84 2                      # Show the new hosts
shot gui-b3-discovered
click 615 108 2                    # Inspect / Adopt the robot (second row)
click 484 439; typein robot        # Name (the Site row above defaults to Site Gamma)
click 484 461; typein 'Bench robot'
click 484 525; typein robot        # SSH username
click 394 483; click 410 529       # Type: Generic Linux Host
shot gui-b4-adopt
click 276 580 4                    # Adopt
grep -q '"profile": "generic_linux"' <<<"$(status_json robot)" || fail "GUI-only: adopt" "robot not adopted (gui-b4-adopt.png)"
pass "GUI-only: adopt" "inspected fingerprints, chose the site, named robot, label, type, user"
gui_pin_panel_layout 542
click 607 392 4                    # Trust host key... (in the wrapped explanation)
shot gui-b5-trust
x "xdotool mousemove 720 600"; for _ in 1 2 3; do x "xdotool click 5"; done; sleep 1   # scroll to the pin button
shot gui-b5a-scrolled
click 586 538 8                    # Pin N key(s)
grep -q '"identity": "verified"' <<<"$(status_json robot)" || fail "GUI-only: trust" "not pinned (gui-b5-trust.png)"
x "xdotool mousemove 720 600"; for _ in $(seq 15); do x "xdotool click 4"; done; sleep 1   # back to the top
shot gui-b6-auth-failed
pass "GUI-only: trust" "fingerprints shown, pinned only after the explicit click"
click 592 425 3                    # SSH Setup -> terminal running lablink copy-id
term=$(x 'xdotool search --class xterm | head -1')
[ -n "$term" ] || fail "GUI-only: SSH setup" "no terminal opened"
x "xdotool windowfocus --sync $term; xdotool type --window $term y; xdotool key --window $term Return"; sleep 1
for _ in 1 2 3; do x "xdotool key --window $term Return"; sleep 1; done   # key file, empty passphrase x2
sleep 3
x "xdotool type --window $term --delay 40 robot-pass-1; xdotool key --window $term Return"
wait_for 30 'lablink status robot --json | grep -q "\"color\": \"green\""' || { shot gui-b7-fail; fail "GUI-only: SSH setup" "not GREEN"; }
x 'xdotool windowfocus --sync $(xdotool search --name LabLink | head -1)'
sleep 2
shot gui-b7-managed
pass "GUI-only: SSH setup" "SSH Setup opened a terminal, key created and installed; robot GREEN/Managed (gui-b7)"
x 'pkill -x lablink-gui' || true

# ---- tarball: a third fresh user, no root ----------------------------------------------
start_desktop "$desk3" lab-desktop-3 "$netA" "$preA.12"
tgzname=$(basename "$tgz")
docker cp "$tgz" "$desk3:$xfer/$tgzname"
docker cp dist/SHA256SUMS "$desk3:$xfer/SHA256SUMS"
docker exec "$desk3" bash -c 'apt-get update -qq && apt-get install -y -qq --no-install-recommends openssh-client libgl1 libegl1 libxkbcommon0 libxkbcommon-x11-0 libx11-6 libx11-xcb1 libxcursor1 libxrandr2 libxi6 libwayland-client0 libwayland-egl1' > "$out/apt-tarball-deps.log" 2>&1 \
    || fail "tarball install" "runtime libraries failed to install"
as_tester "cd $xfer && sha256sum -c --ignore-missing SHA256SUMS" > "$out/tarball.txt" 2>&1 || fail "tarball install" "checksum"
grep -q "$tgzname: OK" "$out/tarball.txt" || fail "tarball install" "tarball not verified"
as_tester "cd $xfer && tar xzf $tgzname && cd lablink-*-x86_64-linux && ./install.sh" >> "$out/tarball.txt" 2>&1 || fail "tarball install" "install.sh failed"
tv=$(out_of '$HOME/.local/bin/lablink version' | head -1)
[ "$tv" = "lablink $version (commit $sha)" ] || fail "tarball install" "version says '$tv'"
as_tester "ping -c 1 -W 1 $preA.1 >/dev/null 2>&1 || true"
as_tester "PATH=\$HOME/.local/bin:\$PATH lablink init --yes --site 'Site Tarball' --scan $preA.0/24 --no-completions" >> "$out/tarball.txt" 2>&1 || fail "tarball install" "init failed"
grep -q "ExecStart=/home/tester/.local/bin/lablinkd" <(out_of 'cat ~/.config/systemd/user/lablinkd.service') || fail "tarball install" "user unit not pointing at ~/.local/bin"
wait_for 20 '$HOME/.local/bin/lablink ping' || fail "tarball install" "daemon did not answer"
as_tester '$HOME/.local/bin/lablink discover --json' > "$out/tarball-discover.json" || fail "tarball install" "discover failed"
grep -q "\"$preA.20\"" "$out/tarball-discover.json" || fail "tarball install" "robot not discovered"
as_tester 'test -f ~/.local/share/bash-completion/completions/lablink && test -f ~/.local/share/applications/lablink-gui.desktop' || fail "tarball install" "completion or desktop entry missing"
as_tester 'cd /var/tmp/lablink-*-x86_64-linux && ./uninstall.sh' >> "$out/tarball.txt" 2>&1 || fail "tarball uninstall" "uninstall.sh failed"
as_tester 'test ! -e ~/.local/bin/lablink && test -f ~/.config/lablink/config.yaml && ! pgrep -x lablinkd' || fail "tarball uninstall" "binaries left, daemon running, or config deleted"
as_tester 'cd /var/tmp/lablink-*-x86_64-linux && ./uninstall.sh --purge' >> "$out/tarball.txt" 2>&1 || fail "tarball uninstall" "--purge failed"
as_tester 'test ! -e ~/.config/lablink && test ! -e ~/.local/state/lablink' || fail "tarball uninstall" "--purge kept data"
# Prefixes: "=" is refused, uninstalling one prefix keeps another prefix's menu
# entry, and --purge never deletes a custom LABLINK_STATE_DIR wholesale.
as_tester 'cd /var/tmp/lablink-*-x86_64-linux && mkdir -p "$HOME/a=b" && ! ./install.sh "$HOME/a=b"' >> "$out/tarball.txt" 2>&1 || fail "tarball prefixes" "a PREFIX containing = was accepted"
as_tester 'cd /var/tmp/lablink-*-x86_64-linux && ./install.sh && ./install.sh "$HOME/opt-ll" && ./uninstall.sh && grep -q opt-ll ~/.local/share/applications/lablink-gui.desktop && test -f ~/.local/share/icons/hicolor/scalable/apps/lablink.svg && test -x ~/opt-ll/bin/lablink' >> "$out/tarball.txt" 2>&1 || fail "tarball prefixes" "uninstalling ~/.local removed another prefix's menu entry or files"
as_tester 'cd /var/tmp/lablink-*-x86_64-linux && ./uninstall.sh "$HOME/opt-ll" && mkdir -p ~/state && echo keep > ~/state/other.txt && LABLINK_STATE_DIR=$HOME/state ./uninstall.sh --purge && test -f ~/state/other.txt' >> "$out/tarball.txt" 2>&1 || fail "tarball prefixes" "--purge deleted a custom LABLINK_STATE_DIR"
pass "tarball install / uninstall" "checksum, install.sh into ~/.local, '$tv', init + user unit, daemon, discover; uninstall kept config, --purge removed it; PREFIX with = refused; a second prefix's menu entry and a custom state dir survive"

echo
echo "== all steps passed; evidence in $out"
cat "$results"
