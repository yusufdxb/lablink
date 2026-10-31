#!/usr/bin/env bash
# Migration from the 0.3 per-user opt layout with a LIVE systemd user bus:
# the old lablinkd is enabled and running under systemctl --user before
# install-linux.sh --migrate, using the clean-room desktop image (systemd,
# lingering user session), then restore.sh puts the old layout back.
# Usage: scripts/test-install-userbus.sh [20.04|22.04|24.04]
# Needs: docker (privileged container for systemd) and dist/ from scripts/release.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
tag=${1:-24.04}
docker image inspect "lablink-cr-desktop:$tag" >/dev/null 2>&1 \
    || docker build -q -t "lablink-cr-desktop:$tag" --build-arg BASE="ubuntu:$tag" -f tests/cleanroom/desktop.Dockerfile tests/cleanroom >/dev/null
deb=$(ls dist/lablink_*_amd64.deb); tarball=$(ls dist/lablink-*-x86_64-linux.tar.gz)
version=$(sed -n 's/^ *readonly RELEASE_VERSION=.\(.*\).$/\1/p' scripts/install-linux.sh)
c=lablink-userbus-$tag-$$
trap 'docker rm -f $c >/dev/null 2>&1 || true' EXIT
docker run -d --name "$c" --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    --tmpfs /run --tmpfs /run/lock --mount "type=bind,src=$PWD,dst=/src,readonly" \
    "lablink-cr-desktop:$tag" >/dev/null
docker exec "$c" bash -c "printf 'tester ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/tester; chmod 0440 /etc/sudoers.d/tester; apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends curl >/dev/null"
t() { docker exec -i -u tester -w /home/tester -e HOME=/home/tester -e USER=tester \
    -e XDG_RUNTIME_DIR=/run/user/1000 -e DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus \
    -e DEB="/src/$deb" -e TARBALL="/src/$tarball" -e VERSION="$version" "$c" bash -s; }
for _ in $(seq 90); do
    echo 'systemctl --user is-system-running 2>/dev/null | grep -Eq "running|degraded"' | t && break; sleep 1
done
t <<'TEST'
set -euo pipefail
export PATH="$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin"
pass() { printf 'PASS %s\n' "$*"; }
die() { printf 'FAIL %s\n' "$*"; exit 1; }
systemctl --user show-environment >/dev/null || die 'no user bus'
pass "user bus up ($(. /etc/os-release; echo "$VERSION_ID"), $(systemctl --version | head -1))"
mkdir -p ~/.config/lablink ~/.local/state/lablink ~/.ssh; chmod 700 ~/.ssh ~/.config/lablink ~/.local/state/lablink
printf 'pinned-host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleOnlyNotARealKey\n' > ~/.local/state/lablink/known_hosts
printf 'not a real key\n' > ~/.ssh/id_ed25519; chmod 600 ~/.ssh/id_ed25519
printf 'x\n' > ~/.config/lablink/notes.txt
# State files (cache.db, known_hosts) belong to the running daemon, which
# regenerates them; only files LabLink never writes are compared byte for byte.
user_data() { find ~/.config/lablink ~/.ssh -type f -print0 | sort -z | xargs -0 sha256sum; }
# Legacy 0.3 opt layout (tarball binaries stand in for the old ones).
mkdir -p /tmp/legacy && tar -xzf "$TARBALL" -C /tmp/legacy
src=$(find /tmp/legacy -name lablinkd -printf '%h\n' | head -1)
v=0.3.1-dev-test; o=~/.local/opt/lablink
mkdir -p $o/$v ~/.local/bin ~/.config/systemd/user ~/.local/share/applications
cp -a "$src"/. $o/$v/
if [[ ! -e $o/$v/lablink-cli ]]; then
    mv $o/$v/lablink $o/$v/lablink-cli
    printf '#!/bin/sh\nexec "$(dirname -- "$(readlink -f -- "$0")")/lablink-cli" "$@"\n' > $o/$v/lablink; chmod +x $o/$v/lablink
fi
ln -s $v $o/current
for b in lablink lablinkd lablink-gui; do ln -s $o/current/$b ~/.local/bin/$b; done
printf '[Unit]\nDescription=LabLink daemon\n[Service]\nExecStart=%s/.local/opt/lablink/current/lablinkd --no-color\n[Install]\nWantedBy=default.target\n' "$HOME" > ~/.config/systemd/user/lablinkd.service
printf '[Desktop Entry]\nType=Application\nName=LabLink\nExec=%s/.local/bin/lablink-gui\n' "$HOME" > ~/.local/share/applications/lablink-gui.desktop
systemctl --user daemon-reload
systemctl --user enable --now lablinkd 2>/dev/null
sleep 2
systemctl --user is-active --quiet lablinkd || { journalctl --user -u lablinkd --no-pager | tail -5; die 'legacy daemon not running'; }
exe() { readlink -f /proc/$(systemctl --user show -p MainPID --value lablinkd)/exe; }
old_exe=$(exe); [[ $old_exe == $HOME/.local/opt/lablink/* ]] || die "legacy daemon runs $old_exe"
user_data > /tmp/user-data
pass "legacy daemon enabled + active under systemctl --user, running $old_exe"

bash /src/scripts/install-linux.sh --migrate --package "$DEB" > /tmp/migrate.log 2>&1 || { tail -15 /tmp/migrate.log; die 'migration failed'; }
grep -q 'lablinkd was restarted from /usr/bin.' /tmp/migrate.log || { tail -15 /tmp/migrate.log; die 'no restart note'; }
! grep -q 'No systemd user session was found' /tmp/migrate.log || die 'installer missed the user bus'
systemctl --user is-active --quiet lablinkd || die 'daemon not active after migration'
systemctl --user is-enabled --quiet lablinkd || die 'daemon not enabled after migration'
frag=$(systemctl --user show -p FragmentPath --value lablinkd)
[[ $frag == /usr/lib/systemd/user/lablinkd.service ]] || die "unit after migration: $frag"
new_exe=$(exe); [[ $new_exe == /usr/bin/lablinkd ]] || die "daemon after migration runs $new_exe"
[[ $(lablinkd --version) == "lablinkd $VERSION" ]] || die 'version'
lablink status --json >/dev/null 2>&1; rc=$?; [[ $rc != 3 ]] || die 'CLI cannot reach the restarted daemon (exit 3)'
sha256sum --quiet -c /tmp/user-data || die 'user data changed'
[[ $(stat -c %a ~/.local/state/lablink) == 700 && -f ~/.local/state/lablink/cache.db ]] || die 'state dir'
pass "after --migrate: packaged unit $frag enabled + active, MainPID runs $new_exe, CLI reaches it (status exit $rc), user data unchanged"

restore=$(sed -n 's/.*\(\/home\/tester\/[^ ]*\/restore\.sh\).*/\1/p' /tmp/migrate.log | head -1)
"$restore" > /tmp/restore.log 2>&1 || { cat /tmp/restore.log; die 'restore failed'; }
grep -q 'Restart the old daemon when ready' /tmp/restore.log || die 'restore did not see the user bus'
frag=$(systemctl --user show -p FragmentPath --value lablinkd)
[[ $frag == $HOME/.config/systemd/user/lablinkd.service ]] || die "unit after restore: $frag"
systemctl --user restart lablinkd; sleep 2
back_exe=$(exe); [[ $back_exe == $old_exe ]] || die "daemon after restore runs $back_exe"
sha256sum --quiet -c /tmp/user-data || die 'user data changed by restore'
pass "restore.sh: daemon-reload picked up $frag; after restart MainPID runs $back_exe again"
TEST
echo "ALL PASS ($tag)"
