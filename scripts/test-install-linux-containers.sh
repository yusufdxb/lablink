#!/usr/bin/env bash
# Real release installation in a fresh disposable Ubuntu container.
# --local substitutes only the bootstrap response; release downloads are real.
# BASE=ubuntu:22.04 scripts/test-install-linux-containers.sh
# After publishing main, add --published to exercise the exact README command.
set -euo pipefail
cd "$(dirname "$0")/.."
base=${BASE:-ubuntu:22.04}
mode=${1:---local}
case "$mode" in --local|--branch|--published) ;; *) echo 'Usage: test-install-linux-containers.sh [--local|--branch|--published]' >&2; exit 2 ;; esac
case "$base" in ubuntu:20.04|ubuntu:22.04|ubuntu:24.04) ;; *) echo 'Unsupported test BASE' >&2; exit 2 ;; esac
command -v docker >/dev/null
work_dir=$(mktemp -d)
container=''
image="lablink-installer-test-${base#ubuntu:}-$$"
cleanup() {
    if [[ -n "$container" ]]; then docker rm -f "$container" >/dev/null 2>&1 || true; fi
    docker image rm "$image" >/dev/null 2>&1 || true
    rm -rf "$work_dir"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cat > "$work_dir/Dockerfile" <<'DOCKER'
ARG BASE=ubuntu:22.04
FROM ${BASE}
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates sudo \
    && useradd --create-home --uid 12345 --shell /bin/bash tester \
    && useradd --create-home --uid 12346 --shell /bin/bash denied \
    && printf 'tester ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/tester \
    && chmod 0440 /etc/sudoers.d/tester
USER tester
WORKDIR /home/tester
DOCKER
docker build --build-arg "BASE=$base" -t "$image" "$work_dir"
container=$(docker run -d --mount "type=bind,src=$PWD,dst=/src,readonly" "$image" sleep infinity)
docker exec -u root "$container" bash -c '
    if output=$(bash /src/scripts/install-linux.sh 2>&1); then
        echo "FAIL: installer accepted root" >&2; exit 1
    fi
    [[ $output == *"Run this installer as your normal user"* ]] || { echo "$output" >&2; exit 1; }
    echo "PASS: entire installer refuses root"
'
docker exec -i "$container" bash -s -- "$mode" <<'TEST'
set -euo pipefail
mode=$1
# Run exactly the first command documented in README, in a normal shell that
# does not inherit this harness's pipefail option.
install_command=$(awk '/^```bash$/ { getline; print; exit }' /src/README.md)
mkdir -m 0755 /tmp/bootstrap-bin
cat > /tmp/bootstrap-bin/curl <<'CURL'
#!/usr/bin/env bash
url=${!#}
if [[ $url == https://raw.githubusercontent.com/yusufdxb/lablink/main/scripts/install-linux.sh ]]; then
    case "$BOOTSTRAP_MODE" in
        --local) cat /src/scripts/install-linux.sh; exit ;;
        --branch)
            arguments=("$@")
            arguments[${#arguments[@]}-1]=https://raw.githubusercontent.com/yusufdxb/lablink/feat/linux-one-command-installer/scripts/install-linux.sh
            exec /usr/bin/curl "${arguments[@]}"
            ;;
        404)
            exec /usr/bin/curl -fsSL https://raw.githubusercontent.com/yusufdxb/lablink/main/.installer-bootstrap-missing-test
            ;;
    esac
fi
exec /usr/bin/curl "$@"
CURL
chmod 0755 /tmp/bootstrap-bin/curl
export PATH="/tmp/bootstrap-bin:$PATH" BOOTSTRAP_MODE="$mode"
install_lablink() {
    env -u SHELLOPTS /bin/bash --noprofile --norc -c "$install_command"
}
! command -v lablink
! dpkg-query -W lablink 2>/dev/null
for utility in rustc cargo git gh; do ! command -v "$utility"; done
set +e
BOOTSTRAP_MODE=404 install_lablink
bootstrap_status=$?
set -e
[[ $bootstrap_status == 22 ]]
printf 'PASS: exact README command returns 22 for real HTTP 404\n'
# A real sudo denial, before the first successful install. No mock APT or
# package data: this user cannot obtain administrator privileges.
set +e
sudo -u denied env HOME=/home/denied PATH="$PATH" BOOTSTRAP_MODE="$mode" \
    /bin/bash --noprofile --norc -c "$install_command" > /tmp/denied-install.log 2>&1
denied_status=$?
set -e
[[ $denied_status != 0 ]]
grep -q 'apt installation failed' /tmp/denied-install.log
! dpkg-query -W lablink 2>/dev/null
! find /tmp -maxdepth 1 -name 'lablink-install.*' | grep .
printf 'PASS: exact README command returns nonzero on denied sudo; no package installed\n'
install_lablink
printf 'PASS: clean installation of the official release\n'
for binary in lablink lablinkd lablink-gui; do
    test "$(command -v "$binary")" = "/usr/bin/$binary"
done
lablink version
lablinkd --version
/lib64/ld-linux-x86-64.so.2 --list /usr/bin/lablink-gui
! test -e "$HOME/.config/lablink"
! test -e "$HOME/.local/state/lablink"
! test -e "$HOME/.ssh"
! test -e "$HOME/.config/systemd/user"
! find /tmp -maxdepth 1 -name 'lablink-install.*' | grep .
printf 'PASS: no automatic setup, trust changes or leftover downloads\n'
# Synthetic user data. Deliberately do not invoke onboarding or a daemon.
mkdir -p "$HOME/.config/lablink" "$HOME/.local/state/lablink" "$HOME/.ssh"
printf 'existing site and device configuration\n' > "$HOME/.config/lablink/config.yaml"
printf 'existing device records\n' > "$HOME/.local/state/lablink/cache.db"
printf 'existing pinned fingerprints\n' > "$HOME/.local/state/lablink/known_hosts"
printf 'existing private key\n' > "$HOME/.ssh/id_ed25519"
printf 'existing SSH host trust\n' > "$HOME/.ssh/known_hosts"
find "$HOME/.config/lablink" "$HOME/.local/state/lablink" "$HOME/.ssh" -type f -exec sha256sum {} + | sort > /tmp/user-data-before
install_lablink
sha256sum --check /tmp/user-data-before
printf 'PASS: repeated installation preserves configuration, devices, keys and trust\n'
# Exercise apt again with existing user data, rather than only the no-op path.
sudo apt remove --yes lablink
install_lablink
sha256sum --check /tmp/user-data-before
printf 'PASS: removal and fresh package installation preserve existing user data\n'
# A real GUI launch, using an isolated HOME so its first-run wizard cannot
# touch the preservation fixtures. Xvfb is installed only after the installer
# has already resolved the release package's own runtime dependencies.
sudo apt install --yes --no-install-recommends xvfb xauth x11-utils libgl1-mesa-dri
mkdir -p /tmp/gui-home /tmp/gui-runtime
chmod 0700 /tmp/gui-runtime
HOME=/tmp/gui-home XDG_CONFIG_HOME=/tmp/gui-home/config \
    XDG_STATE_HOME=/tmp/gui-home/state XDG_DATA_HOME=/tmp/gui-home/data \
    XDG_RUNTIME_DIR=/tmp/gui-runtime LIBGL_ALWAYS_SOFTWARE=1 \
    xvfb-run -a bash -c '
        set -euo pipefail
        lablink-gui > /tmp/lablink-gui.log 2>&1 &
        gui_pid=$!
        trap '\''kill "$gui_pid" 2>/dev/null || true; wait "$gui_pid" 2>/dev/null || true'\'' EXIT
        for attempt in {1..30}; do
            if xwininfo -root -tree | grep -q '\''"LabLink"'\''; then
                printf "PASS: installed GUI opened a LabLink window under Xvfb\n"
                exit 0
            fi
            if ! kill -0 "$gui_pid" 2>/dev/null; then cat /tmp/lablink-gui.log; exit 1; fi
            sleep 0.5
        done
        cat /tmp/lablink-gui.log
        echo "GUI did not open a window" >&2
        exit 1
    '
sha256sum --check /tmp/user-data-before
! find /tmp -maxdepth 1 -name 'lablink-install.*' | grep .
printf 'PASS: all real installation checks\n'
TEST
