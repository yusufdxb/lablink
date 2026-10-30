#!/usr/bin/env bash
# Install an official release. Update this only after that release's assets
# are published; the public main/scripts/install-linux.sh URL stays unchanged.
# The documented bootstrap downloads the complete script before execution.
main() (
    set -Eeuo pipefail
    umask 077

    readonly RELEASE_VERSION='0.3.1'
    readonly RELEASE_URL="https://github.com/yusufdxb/lablink/releases/download/v${RELEASE_VERSION}"
    readonly PACKAGE="lablink_${RELEASE_VERSION}_amd64.deb"
    local work_dir='' phase='checking prerequisites'

    fail() { printf 'LabLink installer: %s\n' "$*" >&2; exit 1; }
    # Invoked indirectly by the EXIT trap.
    # shellcheck disable=SC2317
    cleanup() { if [[ -n "$work_dir" ]]; then rm -rf -- "$work_dir"; fi; }
    trap cleanup EXIT
    trap 'printf "LabLink installer: interrupted; temporary downloads will be removed.\n" >&2; exit 130' INT
    trap 'printf "LabLink installer: interrupted; temporary downloads will be removed.\n" >&2; exit 143' TERM
    trap 'printf "LabLink installer: failed while %s (exit %s).\n" "$phase" "$?" >&2' ERR

    [[ $EUID -ne 0 ]] || fail 'Run this installer as your normal user, without sudo. Only the package installation requests administrator privileges.'
    local utility
    for utility in uname curl sha256sum mktemp rm chmod awk dpkg dpkg-query dpkg-deb apt sudo; do
        command -v "$utility" >/dev/null 2>&1 || fail "Missing prerequisite: $utility. On Ubuntu run: sudo apt update && sudo apt install curl ca-certificates coreutils mawk dpkg apt sudo"
    done
    [[ -s /etc/ssl/certs/ca-certificates.crt ]] || fail 'Missing TLS CA certificates. Run: sudo apt update && sudo apt install ca-certificates'
    [[ $(uname -s) == Linux ]] || fail 'Only Ubuntu Linux 20.04, 22.04 and 24.04 LTS is supported.'
    local machine
    machine=$(uname -m)
    case "$machine" in
        x86_64|amd64) ;;
        *) fail "Unsupported architecture: $machine. Official Linux packages are for x86_64/AMD64 only; ARM64/aarch64 (including Jetson) is not supported by this installer." ;;
    esac
    [[ $(dpkg --print-architecture) == amd64 ]] || fail 'An amd64 Ubuntu userland is required, even on an x86_64 kernel.'
    [[ -r /etc/os-release ]] || fail 'Cannot identify this distribution: /etc/os-release is missing.'
    local ID='' VERSION_ID=''
    # Ubuntu's system-owned distribution metadata.
    # shellcheck source=/dev/null
    . /etc/os-release
    [[ $ID == ubuntu ]] || fail "Unsupported distribution: ${ID:-unknown}. Use Ubuntu 20.04, 22.04 or 24.04 LTS (x86_64)."
    case "$VERSION_ID" in
        20.04|22.04|24.04) ;;
        *) fail "Unsupported Ubuntu version: ${VERSION_ID:-unknown}. Supported: 20.04, 22.04 and 24.04 LTS." ;;
    esac

    # Do not silently install a package that the user's existing PATH hides.
    local binary resolved
    for binary in lablink lablinkd lablink-gui; do
        resolved=$(command -v "$binary" || true)
        if [[ -n "$resolved" && ! "$resolved" -ef "/usr/bin/$binary" ]]; then
            fail "Existing $binary at $resolved would hide /usr/bin/$binary. Put /usr/bin before its directory in PATH and rerun. Keep your configuration, state and SSH files. See docs/INSTALL.md for tarball migration."
        fi
    done

    local installed='' expected="$RELEASE_VERSION" install_needed=1
    installed=$(dpkg-query -W -f='${db:Status-Status} ${Version}' lablink 2>/dev/null || true)
    if [[ $installed == 'installed '* ]]; then
        installed=${installed#installed }
        printf 'Found LabLink %s. Installer target: %s.\n' "$installed" "$RELEASE_VERSION"
        if dpkg --compare-versions "$installed" ge "$RELEASE_VERSION"; then
            expected=$installed
            install_needed=0
            printf 'Keeping the installed version; no downgrade or package changes needed.\n'
        fi
    fi

    if [[ $install_needed == 1 ]]; then
        phase='creating a temporary download directory'
        # Use a system temporary directory, never an untrusted relative TMPDIR.
        work_dir=$(mktemp -d /tmp/lablink-install.XXXXXXXXXX)
        download() {
            local name=$1
            printf 'Downloading %s from the official v%s release...\n' "$name" "$RELEASE_VERSION"
            curl --disable --fail --show-error --silent --location \
                --proto '=https' --proto-redir '=https' \
                --connect-timeout 20 --max-time 300 --retry 2 \
                --output "$work_dir/$name" "$RELEASE_URL/$name" || \
                fail "Could not download $name from $RELEASE_URL. Check your connection and the release assets, then rerun. Nothing has been installed."
        }
        phase='downloading the release'
        download SHA256SUMS
        download "$PACKAGE"
        phase='verifying the package checksum'
        # Accept the release workflow's ./ prefix and sha256sum's text/binary
        # markers. Require exactly one valid entry for this exact filename.
        local checksum
        checksum=$(awk -v name="$PACKAGE" '
            { file=$2; sub(/^\*/, "", file); sub(/^\.\//, "", file) }
            file == name {
                count++
                if (NF != 2 || length($1) != 64 || $1 ~ /[^0-9a-fA-F]/) bad=1
                hash=$1
            }
            END { if (count != 1 || bad) exit 1; print hash }
        ' "$work_dir/SHA256SUMS") || fail "SHA256SUMS must contain exactly one valid checksum for $PACKAGE. Nothing has been installed."
        (cd "$work_dir"; printf '%s  %s\n' "$checksum" "$PACKAGE" | sha256sum --check --strict -) || \
            fail 'Package checksum mismatch. Nothing has been installed. Do not install the downloaded package; rerun later or report the release.'
        [[ $(dpkg-deb -f "$work_dir/$PACKAGE" Package) == lablink && \
           $(dpkg-deb -f "$work_dir/$PACKAGE" Version) == "$RELEASE_VERSION" && \
           $(dpkg-deb -f "$work_dir/$PACKAGE" Architecture) == amd64 ]] || \
            fail 'Verified archive has unexpected package metadata. Nothing has been installed.'
        # Allow apt's _apt user to read the public package, while only this
        # user can write the securely created directory and verified file.
        chmod 0711 "$work_dir"
        chmod 0644 "$work_dir/$PACKAGE"
        phase='installing the verified package with apt'
        printf 'Installing verified LabLink %s. sudo may request your password.\n' "$RELEASE_VERSION"
        # sudo reads passwords from the terminal. apt must not consume the
        # piped script or need stdin for its confirmation prompt.
        sudo apt install --yes --no-remove "$work_dir/$PACKAGE" </dev/null || \
            fail 'apt installation failed. Review the error above. For stale package indexes run sudo apt update, then rerun the installer. For an interrupted dpkg transaction run sudo dpkg --configure -a first.'
    fi

    phase='verifying the installed executables'
    local actual
    actual=$(dpkg-query -W -f='${db:Status-Status} ${Version}' lablink)
    [[ $actual == "installed $expected" ]] || fail "Expected installed LabLink $expected; dpkg reports: $actual"
    for binary in lablink lablinkd lablink-gui; do
        [[ -x /usr/bin/$binary ]] || fail "Missing executable /usr/bin/$binary. See docs/INSTALL.md to reinstall the verified local .deb with apt --reinstall."
        resolved=$(command -v "$binary" || true)
        [[ -n "$resolved" && "$resolved" -ef /usr/bin/$binary ]] || fail "Your PATH does not resolve $binary to /usr/bin/$binary. Add /usr/bin to PATH before using LabLink."
    done
    local reported daemon_version
    reported=$(/usr/bin/lablink version) || fail 'Installed CLI could not run.'
    [[ $reported == "lablink $expected (commit "* ]] || fail "Unexpected CLI version: $reported"
    daemon_version=$(/usr/bin/lablinkd --version) || fail 'Installed daemon could not run.'
    [[ $daemon_version == "lablinkd $expected" ]] || fail "Unexpected daemon version: $daemon_version"
    # v0.3.1 has no GUI --version/--help mode. Validate it with the system
    # dynamic loader without opening a window, starting a daemon or setup.
    [[ -x /lib64/ld-linux-x86-64.so.2 ]] || fail 'Cannot verify GUI runtime: the x86_64 dynamic loader is missing.'
    /lib64/ld-linux-x86-64.so.2 --list /usr/bin/lablink-gui >/dev/null || \
        fail 'The GUI has missing runtime libraries. Review apt errors and repair the package dependencies.'

    printf '\nLabLink installed successfully!\n%s\n\nNext steps:\n\n  lablink init\n  lablink doctor\n  lablink status\n\nDesktop users can open LabLink from their applications menu.\n' "$reported"
    if [[ $install_needed == 1 && -n "$installed" ]]; then
        printf '\nIf your LabLink daemon was already running, restart it when ready:\n  systemctl --user restart lablinkd\n'
    fi
)

main "$@"
