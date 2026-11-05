#!/usr/bin/env bash
# Daemon startup under a real systemd user manager, for a second account
# (uid 1001) with Ubuntu's usual umask of 002: reproduces the 0.4.2 field
# failure ("lablinkd did not answer within 10 s", no socket, GUI said
# "start done") and checks the fix, in a throwaway privileged container.
#
#   OLD_DEB  the release to reproduce with (e.g. dist of v0.4.2)
#   NEW_DEB  the candidate .deb (scripts/package.sh)
#   LIVE_TEST  optional: the compiled lablink-setup `systemd_live` test
#              binary (the GUI Start button's code path)
#
# Usage: OLD_DEB=... NEW_DEB=... [LIVE_TEST=...] [BASE=ubuntu:24.04] \
#        scripts/test-daemon-startup-systemd.sh
# Needs docker and the clean-room desktop image (tests/cleanroom).
set -euo pipefail
cd "$(dirname "$0")/.."
base=${BASE:-ubuntu:24.04}
tag=${base#ubuntu:}
c=lablink-startup-$$
: "${OLD_DEB:?}" "${NEW_DEB:?}"
fails=0
pass() { echo "PASS  $1"; }
fail() { echo "FAIL  $1"; fails=$((fails + 1)); }
cleanup() { docker rm -f "$c" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker build -q -t "lablink-cr-desktop:$tag" --build-arg BASE="$base" \
    -f tests/cleanroom/desktop.Dockerfile tests/cleanroom >/dev/null
docker run -d --name "$c" --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /run/lock \
    "lablink-cr-desktop:$tag" >/dev/null
for _ in $(seq 60); do
    docker exec "$c" systemctl is-system-running 2>/dev/null | grep -Eq 'running|degraded' && break
    sleep 1
done
# A second account, as on a shared workstation: uid 1001, private group.
docker exec "$c" useradd -m -u 1001 -s /bin/bash lab2
docker exec "$c" loginctl enable-linger lab2
for _ in $(seq 60); do docker exec "$c" test -S /run/user/1001/bus && break; sleep 1; done
# As lab2 in a login-like environment with umask 002 (pam_umask usergroups;
# docker exec bypasses PAM, so set it explicitly).
as_lab2() {
    docker exec -u lab2 -w /home/lab2 -e HOME=/home/lab2 -e USER=lab2 \
        -e XDG_RUNTIME_DIR=/run/user/1001 \
        -e DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1001/bus \
        "$c" bash -c "umask 002; $1"
}
out_of() { as_lab2 "$1" 2>&1 || true; }
install_deb() {
    docker cp "$1" "$c:/var/tmp/lablink.deb"
    docker exec -e DEBIAN_FRONTEND=noninteractive "$c" bash -c \
        '{ [ -e /var/tmp/.apt-updated ] || { apt-get update -qq && touch /var/tmp/.apt-updated; }; } && apt-get install -y -qq --reinstall --allow-downgrades /var/tmp/lablink.deb >/dev/null'
}
# What the 0.4.2 desktop app did when Files preferences were saved before
# the daemon first ran: create_dir_all() of the state dir under umask 002.
gui_made_state_dir() { as_lab2 'mkdir -p ~/.local/state/lablink && stat -c %a ~/.local/state/lablink'; }
init() { out_of 'lablink init --yes --site lab --network 10.99.0.0/24 2>&1'; }
sock=/run/user/1001/lablink/lablinkd.sock

echo "== 1. reproduce with $(basename "$OLD_DEB")"
install_deb "$OLD_DEB"
echo "   state dir mode after the GUI step: $(gui_made_state_dir)"
r=$(init)
echo "$r" | sed 's/^/   | /'
if echo "$r" | grep -q 'did not answer within 10 s'; then pass "old: init reports the field message"; else fail "old: field message not reproduced"; fi
if as_lab2 "test -S $sock"; then fail "old: socket exists"; else pass "old: no socket at $sock"; fi
# The daemon's own last line (systemd's lines about the unit only say it exited).
j=$(out_of 'journalctl --user _SYSTEMD_USER_UNIT=lablinkd.service -n 1 -o cat --no-pager')
echo "   journal: $j"
echo "$j" | grep -q 'mode 0700' && pass "old: daemon refuses its state dir (crash loop)" || fail "old: journal does not show the state-dir refusal"
d=$(out_of 'lablink discover 2>&1'); echo "   discover: $d"

echo "== 2. upgrade to $(basename "$NEW_DEB") with the broken state dir in place"
install_deb "$NEW_DEB"
r=$(out_of 'systemctl --user restart lablinkd; lablink install-service 2>&1')
echo "$r" | sed 's/^/   | /'
echo "$r" | grep -q 'answers on' && pass "new: install-service reports a daemon that answers" || fail "new: daemon did not answer"
m=$(as_lab2 'stat -c %a ~/.local/state/lablink')
[ "$m" = 700 ] && pass "new: state dir tightened to 0700" || fail "new: state dir mode $m"
as_lab2 "test -S $sock" && pass "new: socket at $sock" || fail "new: no socket"
d=$(out_of 'lablink discover 2>&1; lablink ping 2>&1'); echo "$d" | sed 's/^/   | /'
echo "$d" | grep -qi 'not running' && fail "new: discover/ping cannot reach the daemon" || pass "new: discover and ping reach the daemon"
cfg_before=$(as_lab2 'sha256sum ~/.config/lablink/config.yaml')

echo "== 3. a daemon that cannot start: failure is reported fast, with its reason"
as_lab2 'systemctl --user stop lablinkd; chmod 777 ~/.local/state/lablink'
t0=$SECONDS
r=$(out_of 'lablink install-service 2>&1'); t1=$SECONDS
echo "$r" | sed 's/^/   | /'
echo "$r" | grep -q 'did not start' && echo "$r" | grep -q 'mode 0700' \
    && pass "new: failed start names the daemon's reason (in about $((t1 - t0)) s)" \
    || fail "new: failed start not reported with its reason"
if [ -n "${LIVE_TEST:-}" ]; then
    docker cp "$LIVE_TEST" "$c:/var/tmp/systemd_live"
    docker exec "$c" chmod 755 /var/tmp/systemd_live
    r=$(out_of 'LABLINK_LIVE_SYSTEMD=1 LABLINK_LIVE_EXPECT="fail:mode 0700" /var/tmp/systemd_live --nocapture 2>&1')
    echo "$r" | grep -E '^(start|restart|status):|test result' | sed 's/^/   | /'
    echo "$r" | grep -q 'test result: ok. 1 passed' && pass "new: Start button (run_verified) reports the failure" || fail "new: Start button failure state"
fi

echo "== 4. recovery after the cause is fixed; config and history kept"
as_lab2 'chmod 700 ~/.local/state/lablink'
if [ -n "${LIVE_TEST:-}" ]; then
    r=$(out_of 'LABLINK_LIVE_SYSTEMD=1 LABLINK_LIVE_EXPECT=ok /var/tmp/systemd_live --nocapture 2>&1')
    echo "$r" | grep -E '^(start|restart):|test result' | sed 's/^/   | /'
    echo "$r" | grep -q 'test result: ok. 1 passed' && pass "new: Start button reports success once the daemon answers" || fail "new: Start button success state"
else
    as_lab2 'systemctl --user restart lablinkd'
fi
d=$(out_of 'lablink ping 2>&1 && lablink history 2>&1 | head -5'); echo "$d" | sed 's/^/   | /'
echo "$d" | grep -q 'daemon_started\|started' && pass "new: daemon answers after restart; history present" || fail "new: no history after restart"
[ "$(as_lab2 'sha256sum ~/.config/lablink/config.yaml')" = "$cfg_before" ] && pass "new: config.yaml unchanged" || fail "new: config.yaml changed"

echo
[ $fails -eq 0 ] && echo "ALL PASS" || { echo "$fails FAILED"; exit 1; }
