#!/usr/bin/env bash
# Upgrade and migration tests for scripts/install-linux.sh, in disposable
# Ubuntu containers. Installs the locally built dist/ package with --package
# and never touches LabLink on the workstation running this script.
#
# Usage: scripts/test-install-migration.sh [LEGACY_DIR]
#   LEGACY_DIR  a directory laid out like ~/.local/opt/lablink/<version>
#               (lablink wrapper, lablink-cli, lablinkd, lablink-gui,
#               lablink.svg), mounted read-only. Without it the opt-layout
#               scenario uses the tarball binaries in place of older ones.
#   BASE=ubuntu:24.04 selects the image (20.04, 22.04 or 24.04).
set -euo pipefail
cd "$(dirname "$0")/.."
base=${BASE:-ubuntu:22.04}
case "$base" in ubuntu:20.04|ubuntu:22.04|ubuntu:24.04) ;; *) echo 'Unsupported test BASE' >&2; exit 2 ;; esac
legacy=${1:-}
deb=$(ls dist/lablink_*_amd64.deb)
tarball=$(ls dist/lablink-*-x86_64-linux.tar.gz)
(cd dist && sha256sum -c --quiet SHA256SUMS)
version=$(sed -n 's/^ *readonly RELEASE_VERSION=.\(.*\).$/\1/p' scripts/install-linux.sh)
[[ $(basename "$deb") == "lablink_${version}_amd64.deb" ]] || { echo "dist/ is not $version" >&2; exit 1; }

image="lablink-migration-test:${base#ubuntu:}"
work=$(mktemp -d)
containers=()
cleanup() {
    for c in "${containers[@]}"; do docker rm -f "$c" >/dev/null 2>&1 || true; done
    rm -rf "$work"
}
trap cleanup EXIT
cat > "$work/Dockerfile" <<'EOF'
ARG BASE=ubuntu:22.04
FROM ${BASE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates sudo \
    && (userdel -r ubuntu 2>/dev/null || true) \
    && useradd --create-home --uid 12345 --shell /bin/bash tester \
    && printf 'tester ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/tester \
    && chmod 0440 /etc/sudoers.d/tester
EOF
docker build -q --build-arg "BASE=$base" -t "$image" "$work" >/dev/null

mounts=(--mount "type=bind,src=$PWD,dst=/src,readonly")
[[ -z $legacy ]] || mounts+=(--mount "type=bind,src=$(cd "$legacy" && pwd -P),dst=/legacy,readonly")

# Each scenario runs as tester in a fresh container.
run() {
    local name=$1 c
    c=$(docker run -d "${mounts[@]}" "$image" sleep infinity)
    containers+=("$c")
    echo "== $name ($base)"
    docker exec -i -u tester -w /home/tester -e HOME=/home/tester -e SCENARIO="$name" \
        -e VERSION="$version" -e DEB="/src/$deb" -e TARBALL="/src/$tarball" \
        "$c" bash -s <<'TEST'
set -euo pipefail
export PATH="$HOME/.local/bin:$HOME/bin:/usr/local/bin:/usr/bin:/bin"
installer=/src/scripts/install-linux.sh
pass() { printf 'PASS %s: %s\n' "$SCENARIO" "$*"; }
die() { printf 'FAIL %s: %s\n' "$SCENARIO" "$*" >&2; exit 1; }

# User data that must survive every step byte for byte.
mkdir -p ~/.config/lablink ~/.local/state/lablink ~/.ssh
chmod 700 ~/.ssh
printf 'sites:\n  - id: alpha\n    name: Alpha\n    devices:\n      - name: jetson\n        expected_ips: [192.0.2.10]\n' > ~/.config/lablink/config.yaml
printf 'pinned-host ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleOnlyNotARealKey\n' > ~/.local/state/lablink/known_hosts
head -c 4096 /dev/urandom > ~/.local/state/lablink/cache.db
printf 'not a real key\n' > ~/.ssh/id_ed25519; chmod 600 ~/.ssh/id_ed25519
user_data() { find ~/.config/lablink ~/.local/state/lablink ~/.ssh -type f -print0 | sort -z | xargs -0 sha256sum; }
user_data > /tmp/user-data
# Everything else in the home directory, to prove refusals change nothing.
# Directory mtimes are left out: moving a file away and back changes them.
home_tree() {
    (cd ~ && find . \( -path ./.cache -o -path ./.local/share/lablink-migration \) -prune \
        -o \( -type d -printf '%p directory %m\n' \) -o \( ! -type d -printf '%p %y %m %s %T@ %l\n' \) | sort)
}

expect_versions() {
    hash -r
    [[ $(command -v lablink) == /usr/bin/lablink ]] || die "lablink resolves to $(command -v lablink)"
    [[ $(lablink version) == "lablink $VERSION (commit "* ]] || die "cli: $(lablink version)"
    [[ $(lablinkd --version) == "lablinkd $VERSION" ]] || die "daemon: $(lablinkd --version)"
    [[ $(lablink-gui --version </dev/null) == "lablink-gui $VERSION (commit "* ]] || die "gui: $(lablink-gui --version)"
    pass "cli, daemon and gui all report $VERSION from /usr/bin"
}

refuses_without_migrate() {
    home_tree > /tmp/tree-before
    if bash "$installer" --package "$DEB" > /tmp/refuse.log 2>&1; then die 'installed without --migrate'; fi
    grep -q 'Rerun with --migrate' /tmp/refuse.log || { cat /tmp/refuse.log; die 'no --migrate hint'; }
    home_tree | diff -q /tmp/tree-before - >/dev/null || die 'refusal changed the home directory'
    ! dpkg -s lablink >/dev/null 2>&1 || die 'package installed on refusal'
    pass 'refuses without --migrate and changes nothing'
    bash "$installer" --dry-run --package "$DEB" > /tmp/dry.log 2>&1 || { cat /tmp/dry.log; die 'dry run failed'; }
    grep -q 'Dry run: nothing was changed.' /tmp/dry.log || die 'dry run message missing'
    home_tree | diff -q /tmp/tree-before - >/dev/null || die 'dry run changed the home directory'
    pass 'dry run lists the migration and changes nothing'
}

migrate_and_restore() {
    home_tree > /tmp/tree-before
    bash "$installer" --migrate --package "$DEB" > /tmp/migrate.log 2>&1 || { tail -20 /tmp/migrate.log; die 'migration failed'; }
    expect_versions
    sha256sum --quiet -c /tmp/user-data || die 'user data changed by migration'
    pass 'configuration, state, pins and SSH files unchanged'
    grep -q 'No graphical session detected' /tmp/migrate.log \
        || { tail -12 /tmp/migrate.log; die 'no headless note'; }
    pass 'headless note shown'
    restore=$(sed -n 's/.*\(\/home\/tester\/[^ ]*\/restore\.sh\).*/\1/p' /tmp/migrate.log | head -1)
    [[ -x $restore ]] || { tail -12 /tmp/migrate.log; die 'no restore script reported'; }
    for p in "$@"; do [[ ! -e $p && ! -L $p ]] || die "$p still in place after migration"; done
    pass "older files moved to $(dirname "$restore")"
    # A second run is a no-op upgrade check, not another migration.
    bash "$installer" --package "$DEB" > /tmp/again.log 2>&1 || { tail -12 /tmp/again.log; die 'rerun failed'; }
    pass 'rerun after migration succeeds without --migrate'
    sh "$restore" > /tmp/restore.log 2>&1 || { cat /tmp/restore.log; die 'restore failed'; }
    home_tree > /tmp/tree-after
    diff /tmp/tree-before /tmp/tree-after || die 'restore did not bring back the same files'
    sha256sum --quiet -c /tmp/user-data || die 'user data changed by restore'
    pass 'restore.sh puts every moved file back as it was'
}

case $SCENARIO in
fresh)
    home_tree > /tmp/tree-before
    bash "$installer" --dry-run --package "$DEB" > /tmp/dry.log 2>&1 || { cat /tmp/dry.log; die 'dry run failed'; }
    ! dpkg -s lablink >/dev/null 2>&1 || die 'dry run installed the package'
    pass 'dry run on a clean system installs nothing'
    bash "$installer" --package "$DEB" > /tmp/install.log 2>&1 || { tail -20 /tmp/install.log; die 'install failed'; }
    expect_versions
    sha256sum --quiet -c /tmp/user-data || die 'user data changed'
    pass 'configuration, state, pins and SSH files unchanged'
    grep -q 'No graphical session detected' /tmp/install.log \
        || { tail -8 /tmp/install.log; die 'no headless note'; }
    pass 'headless note shown'
    ;;
opt-layout)
    # The per-user layout the 0.3 developer installs used.
    src=/legacy; [[ -d $src ]] || { mkdir -p /tmp/legacy && tar -xzf "$TARBALL" -C /tmp/legacy; src=$(find /tmp/legacy -name lablinkd -printf '%h\n' | head -1); }
    v=0.3.1-dev-test
    mkdir -p ~/.local/opt/lablink/$v ~/.local/bin ~/.config/systemd/user/default.target.wants \
        ~/.local/share/applications ~/.local/share/bash-completion/completions
    cp -a "$src"/. ~/.local/opt/lablink/$v/
    if [[ ! -e ~/.local/opt/lablink/$v/lablink-cli ]]; then
        mv ~/.local/opt/lablink/$v/lablink ~/.local/opt/lablink/$v/lablink-cli
        printf '#!/bin/sh\nexec "$(dirname -- "$(readlink -f -- "$0")")/lablink-cli" "$@"\n' > ~/.local/opt/lablink/$v/lablink
        chmod +x ~/.local/opt/lablink/$v/lablink
    fi
    ln -s $v ~/.local/opt/lablink/current
    for b in lablink lablinkd lablink-gui; do ln -s ~/.local/opt/lablink/current/$b ~/.local/bin/$b; done
    printf '[Unit]\nDescription=LabLink daemon\n[Service]\nExecStart=%s/.local/opt/lablink/current/lablinkd --no-color\n[Install]\nWantedBy=default.target\n' "$HOME" > ~/.config/systemd/user/lablinkd.service
    ln -s ../lablinkd.service ~/.config/systemd/user/default.target.wants/lablinkd.service
    printf '[Desktop Entry]\nType=Application\nName=LabLink\nExec=%s/.local/bin/lablink-gui\nIcon=%s/.local/opt/lablink/current/lablink.svg\n' "$HOME" "$HOME" > ~/.local/share/applications/lablink-gui.desktop
    printf 'complete -F _lablink lablink\n' > ~/.local/share/bash-completion/completions/lablink
    hash -r; [[ $(command -v lablink) == "$HOME/.local/bin/lablink" ]] || die 'legacy layout not on PATH'
    refuses_without_migrate
    grep -q 'lablinkd.service' /tmp/dry.log || die 'dry run did not list the user unit'
    migrate_and_restore ~/.local/bin/lablink ~/.local/opt/lablink ~/.config/systemd/user/lablinkd.service \
        ~/.local/share/applications/lablink-gui.desktop
    ;;
tarball-layout)
    mkdir -p /tmp/t && tar -xzf "$TARBALL" -C /tmp/t
    sh "$(find /tmp/t -name install.sh | head -1)" > /tmp/tar-install.log 2>&1 || { cat /tmp/tar-install.log; die 'tarball install failed'; }
    hash -r; [[ $(command -v lablink) == "$HOME/.local/bin/lablink" ]] || die 'tarball install not on PATH'
    refuses_without_migrate
    migrate_and_restore ~/.local/bin/lablink ~/.local/bin/lablinkd ~/.local/bin/lablink-gui ~/.local/share/lablink/data-dir
    ;;
unknown-shadow)
    mkdir -p ~/.local/bin
    printf '#!/bin/sh\necho "some other tool"\n' > ~/.local/bin/lablink; chmod +x ~/.local/bin/lablink
    home_tree > /tmp/tree-before
    for args in '' '--migrate' '--dry-run'; do
        if bash "$installer" $args --package "$DEB" > /tmp/shadow.log 2>&1 && [[ $args != --dry-run ]]; then die "installed over an unknown program ($args)"; fi
        grep -q "$HOME/.local/bin/lablink" /tmp/shadow.log || { cat /tmp/shadow.log; die 'unknown program not named'; }
    done
    home_tree | diff -q /tmp/tree-before - >/dev/null || die 'unknown program was touched'
    [[ $(cat ~/.local/bin/lablink | tail -1) == 'echo "some other tool"' ]] || die 'unknown program changed'
    ! dpkg -s lablink >/dev/null 2>&1 || die 'package installed over an unknown program'
    pass 'an unrecognized lablink on PATH is named, never moved, and nothing is installed'
    ;;
esac
TEST
}

for s in fresh opt-layout tarball-layout unknown-shadow; do run "$s"; done
echo "ALL PASS ($base)"
