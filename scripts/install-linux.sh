#!/usr/bin/env bash
# Install an official release. Update this only after that release's assets
# are published; the public main/scripts/install-linux.sh URL stays unchanged.
# The documented bootstrap downloads the complete script before execution.
#
# Options (pass after `bash -s --` when piping):
#   --dry-run        report what would be installed or migrated; change nothing
#   --migrate        move an older per-user LabLink (tarball, source or
#                    ~/.local/opt build) aside into a restorable backup so the
#                    package's /usr/bin programs are the ones that run
#   --package FILE   install a local .deb instead of downloading; FILE's
#                    directory must hold the release SHA256SUMS
main() (
    set -Eeuo pipefail
    umask 077

    readonly RELEASE_VERSION='0.4.0'
    readonly RELEASE_URL="https://github.com/yusufdxb/lablink/releases/download/v${RELEASE_VERSION}"
    readonly PACKAGE="lablink_${RELEASE_VERSION}_amd64.deb"
    readonly BINARIES='lablink lablinkd lablink-gui'
    local work_dir='' phase='checking prerequisites' dry_run=0 migrate=0 local_package=''

    fail() { printf 'LabLink installer: %s\n' "$*" >&2; exit 1; }
    # Invoked indirectly by the EXIT trap.
    # shellcheck disable=SC2317
    cleanup() { if [[ -n "$work_dir" ]]; then rm -rf -- "$work_dir"; fi; }
    trap cleanup EXIT
    trap 'printf "LabLink installer: interrupted; temporary downloads will be removed.\n" >&2; exit 130' INT
    trap 'printf "LabLink installer: interrupted; temporary downloads will be removed.\n" >&2; exit 143' TERM
    trap 'printf "LabLink installer: failed while %s (exit %s).\n" "$phase" "$?" >&2' ERR

    while [[ $# -gt 0 ]]; do
        case $1 in
            --dry-run) dry_run=1 ;;
            --migrate) migrate=1 ;;
            --package)
                [[ $# -ge 2 ]] || fail '--package needs the path of a lablink .deb file.'
                local_package=$2; shift ;;
            -h|--help)
                printf 'Usage: install-linux.sh [--dry-run] [--migrate] [--package FILE]\nSee docs/INSTALL.md.\n'; return 0 ;;
            *) fail "Unknown option: $1. Use --dry-run, --migrate or --package FILE." ;;
        esac
        shift
    done

    [[ $EUID -ne 0 ]] || fail 'Run this installer as your normal user, without sudo. Only the package installation requests administrator privileges.'
    local utility
    for utility in uname curl sha256sum mktemp rm mv chmod awk timeout readlink dpkg dpkg-query dpkg-deb apt sudo; do
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

    # ---- Older per-user installations -------------------------------------
    # Only files that are recognisably LabLink's are ever moved, and only into
    # a backup with a restore script. Configuration (~/.config/lablink), state
    # (~/.local/state/lablink) and ~/.ssh are never touched.
    local data config_home
    case ${XDG_DATA_HOME:-} in /*) data=$XDG_DATA_HOME ;; *) data=$HOME/.local/share ;; esac
    case ${XDG_CONFIG_HOME:-} in /*) config_home=$XDG_CONFIG_HOME ;; *) config_home=$HOME/.config ;; esac
    local -a legacy=() blockers=()
    local legacy_service=0
    add_legacy() {
        local p=$1 q
        for q in "${legacy[@]+"${legacy[@]}"}"; do [[ $q != "$p" ]] || return 0; done
        legacy+=("$p")
    }
    # True when $1 is a LabLink program other than the packaged one.
    is_lablink_program() {
        local path=$1 name=$2 target out
        target=$(readlink -f -- "$path" 2>/dev/null || true)
        [[ -n $target && -f $target ]] || return 1
        case $target in "$HOME"/.local/opt/lablink/*) return 0 ;; esac
        [[ -f $(dirname -- "$(dirname -- "$path")")/share/lablink/data-dir ]] && return 0
        case $name in
            lablink) out=$(timeout 10 "$path" version 2>/dev/null </dev/null || true); [[ $out == 'lablink '* ]] ;;
            lablinkd) out=$(timeout 10 "$path" --version 2>/dev/null </dev/null || true); [[ $out == 'lablinkd '* ]] ;;
            # Never start an old GUI (it opens a window); look for its daemon socket name.
            lablink-gui) LC_ALL=C grep -qaF 'lablinkd' -- "$target" ;;
            *) return 1 ;;
        esac
    }
    local binary resolved candidate
    hash -r
    for binary in $BINARIES; do
        for candidate in "$HOME/.local/bin/$binary" "$HOME/bin/$binary" "$HOME/.cargo/bin/$binary"; do
            if [[ -e $candidate || -L $candidate ]] && is_lablink_program "$candidate" "$binary"; then
                add_legacy "$candidate"
            fi
        done
        resolved=$(command -v "$binary" || true)
        if [[ -n "$resolved" && ! "$resolved" -ef "/usr/bin/$binary" ]]; then
            case $resolved in
                "$HOME"/*)
                    if is_lablink_program "$resolved" "$binary"; then add_legacy "$resolved"
                    else blockers+=("$resolved is not a LabLink program but would hide /usr/bin/$binary. Rename it or put /usr/bin before its directory in PATH.")
                    fi ;;
                *) blockers+=("$resolved would hide /usr/bin/$binary and is outside your home directory. Remove it with the tool that installed it, or put /usr/bin first in PATH.") ;;
            esac
        fi
    done
    [[ ! -d $HOME/.local/opt/lablink ]] || add_legacy "$HOME/.local/opt/lablink"
    [[ ! -f $HOME/.local/share/lablink/data-dir ]] || add_legacy "$HOME/.local/share/lablink/data-dir"
    local unit="$config_home/systemd/user/lablinkd.service"
    if [[ -f $unit ]] && ! grep -qx 'ExecStart=/usr/bin/lablinkd.*' "$unit"; then
        legacy_service=1
        add_legacy "$unit"
        [[ ! -L $config_home/systemd/user/default.target.wants/lablinkd.service ]] || \
            add_legacy "$config_home/systemd/user/default.target.wants/lablinkd.service"
    fi
    local entry="$data/applications/lablink-gui.desktop"
    if [[ -f $entry ]] && ! grep -qx 'Exec=lablink-gui' "$entry"; then add_legacy "$entry"; fi
    for candidate in "$data"/icons/hicolor/*/apps/lablink.png "$data"/icons/hicolor/*/apps/lablink.svg \
                     "$data/bash-completion/completions/lablink"; do
        [[ ! -f $candidate ]] || add_legacy "$candidate"
    done

    if [[ ${#blockers[@]} -gt 0 ]]; then
        printf 'LabLink installer: these programs would run instead of the installed package:\n' >&2
        printf '  - %s\n' "${blockers[@]}" >&2
        fail 'Nothing has been changed. Your configuration, state and SSH files are untouched.'
    fi
    if [[ ${#legacy[@]} -gt 0 ]]; then
        printf 'Found an older per-user LabLink installation:\n'
        printf '  %s\n' "${legacy[@]}"
        printf 'With --migrate these are moved (not deleted) into a backup with a restore script.\n'
        printf 'Kept as they are: ~/.config/lablink, ~/.local/state/lablink, ~/.ssh and your device pins.\n'
        if [[ $dry_run == 0 && $migrate == 0 ]]; then
            fail 'Rerun with --migrate to move it aside and use the package, or remove it yourself. Nothing has been changed.'
        fi
    fi

    local installed='' expected="$RELEASE_VERSION" install_needed=1
    installed=$(dpkg-query -W -f='${db:Status-Status} ${Version}' lablink 2>/dev/null || true)
    if [[ $installed == 'installed '* ]]; then
        installed=${installed#installed }
        printf 'Found LabLink %s package. Installer target: %s.\n' "$installed" "$RELEASE_VERSION"
        if dpkg --compare-versions "$installed" ge "$RELEASE_VERSION"; then
            expected=$installed
            install_needed=0
            printf 'Keeping the installed version; no downgrade or package changes needed.\n'
        fi
    else
        installed=''
    fi
    if [[ $dry_run == 1 ]]; then
        if [[ $install_needed == 1 ]]; then printf 'Dry run: would install the LabLink %s package.\n' "$RELEASE_VERSION"; fi
        if [[ ${#legacy[@]} -gt 0 ]]; then printf 'Dry run: would move the %s path(s) above into a backup.\n' "${#legacy[@]}"; fi
        printf 'Dry run: nothing was changed.\n'
        return 0
    fi

    if [[ $install_needed == 1 ]]; then
        phase='creating a temporary download directory'
        # Use a system temporary directory, never an untrusted relative TMPDIR.
        work_dir=$(mktemp -d /tmp/lablink-install.XXXXXXXXXX)
        if [[ -n $local_package ]]; then
            phase='copying the local package'
            [[ -f $local_package && -f $(dirname -- "$local_package")/SHA256SUMS ]] || \
                fail "--package needs an existing $PACKAGE with SHA256SUMS beside it. Nothing has been installed."
            [[ $(basename -- "$local_package") == "$PACKAGE" ]] || fail "--package must be $PACKAGE. Nothing has been installed."
            cp -- "$local_package" "$(dirname -- "$local_package")/SHA256SUMS" "$work_dir/"
        else
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
        fi
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

    # ---- Move the older installation aside --------------------------------
    local backup='' have_systemd=0 was_enabled=0 was_active=0
    if [[ ${#legacy[@]} -gt 0 ]]; then
        phase='moving the older installation into a backup'
        if command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
            have_systemd=1
        fi
        if [[ $legacy_service == 1 && $have_systemd == 1 ]]; then
            if systemctl --user is-enabled --quiet lablinkd 2>/dev/null; then was_enabled=1; fi
            if systemctl --user is-active --quiet lablinkd 2>/dev/null; then was_active=1; fi
            # Stop the old daemon before its program files move.
            if [[ $was_active == 1 ]]; then systemctl --user stop lablinkd; fi
        elif [[ -L $config_home/systemd/user/default.target.wants/lablinkd.service ]]; then
            was_enabled=1
        fi
        backup="$data/lablink-migration/$(date -u +%Y%m%dT%H%M%SZ)"
        mkdir -p -- "$backup/files"
        : > "$backup/manifest"
        write_restore
        local p dest
        for p in "${legacy[@]}"; do
            dest="$backup/files$p"
            mkdir -p -- "$(dirname -- "$dest")"
            if ! mv -T -- "$p" "$dest"; then
                printf 'LabLink installer: could not move %s; putting back what was moved.\n' "$p" >&2
                "$backup/restore.sh" >&2 || true
                fail "Migration stopped. Your older installation is back in place; see $backup."
            fi
            # Record each move as it happens, so an interruption can always
            # be undone with restore.sh.
            printf '%s\n' "$p" >> "$backup/manifest"
        done
        if [[ $have_systemd == 1 ]]; then
            systemctl --user daemon-reload
            if [[ $was_enabled == 1 ]]; then systemctl --user enable lablinkd; fi
            if [[ $was_active == 1 ]]; then systemctl --user start lablinkd; fi
        fi
        printf 'Moved the older installation into %s\n' "$backup"
    fi

    phase='verifying the installed executables'
    hash -r
    local actual
    actual=$(dpkg-query -W -f='${db:Status-Status} ${Version}' lablink)
    [[ $actual == "installed $expected" ]] || fail "Expected installed LabLink $expected; dpkg reports: $actual"
    for binary in $BINARIES; do
        [[ -x /usr/bin/$binary ]] || fail "Missing executable /usr/bin/$binary. See docs/INSTALL.md to reinstall the verified local .deb with apt --reinstall."
        resolved=$(command -v "$binary" || true)
        [[ -n "$resolved" && "$resolved" -ef /usr/bin/$binary ]] || fail "Your PATH does not resolve $binary to /usr/bin/$binary (found ${resolved:-nothing}). Add /usr/bin to PATH before using LabLink."
    done
    local reported daemon_version gui_version
    reported=$(/usr/bin/lablink version) || fail 'Installed CLI could not run.'
    [[ $reported == "lablink $expected (commit "* ]] || fail "Unexpected CLI version: $reported"
    daemon_version=$(/usr/bin/lablinkd --version) || fail 'Installed daemon could not run.'
    [[ $daemon_version == "lablinkd $expected" ]] || fail "Unexpected daemon version: $daemon_version"
    # Answers without a display, so this also checks headless machines.
    gui_version=$(/usr/bin/lablink-gui --version </dev/null) || \
        fail 'The desktop app could not start (missing runtime libraries?). Review apt errors and repair the package dependencies.'
    [[ $gui_version == "lablink-gui $expected"* ]] || fail "Unexpected desktop app version: $gui_version"

    printf '\nLabLink installed successfully!\n%s\n%s\n%s\n' "$reported" "$daemon_version" "$gui_version"
    if [[ -n $backup ]]; then
        printf '\nYour older installation was moved to %s.\nTo go back to it:  %s/restore.sh\n' "$backup" "$backup"
        if [[ $was_active == 1 ]]; then printf 'lablinkd was restarted from /usr/bin.\n'; fi
        if [[ $legacy_service == 1 && $have_systemd == 0 ]]; then
            printf 'No systemd user session was found; when you log in to a desktop run:\n  systemctl --user daemon-reload && systemctl --user enable --now lablinkd\n'
        fi
    elif [[ $install_needed == 1 && -n "$installed" ]]; then
        printf '\nIf your LabLink daemon was already running, restart it when ready:\n  systemctl --user restart lablinkd\n'
    fi
    if [[ -z ${DISPLAY:-} && -z ${WAYLAND_DISPLAY:-} ]]; then
        printf '\nNo graphical session detected. The command line is ready now:\n  lablink init\n  lablink status\nOpen LabLink from the applications menu once you log in to a desktop.\n'
    else
        printf '\nOpen LabLink from your applications menu (or run lablink-gui) to set up your site and devices.\n'
    fi
)

# The restore script written next to a migration backup. Reads the manifest
# and moves every file back unless something new now occupies its place.
# Called from main's subshell, which shares this definition.
write_restore() {
    cat > "$backup/restore.sh" <<'RESTORE'
#!/bin/sh
# Put back the LabLink installation that install-linux.sh --migrate moved here.
# The lablink package stays installed; remove it with: sudo apt remove lablink
set -eu
here=$(cd "$(dirname "$0")" && pwd)
status=0
while IFS= read -r p; do
    if [ -e "$p" ] || [ -L "$p" ]; then
        echo "Kept $p: something new is there; the old copy is in $here/files$p" >&2
        status=1
        continue
    fi
    mkdir -p "$(dirname "$p")"
    mv "$here/files$p" "$p" && echo "Restored $p"
done < "$here/manifest"
if command -v systemctl >/dev/null 2>&1 && systemctl --user show-environment >/dev/null 2>&1; then
    systemctl --user daemon-reload
    echo "Restart the old daemon when ready: systemctl --user restart lablinkd"
fi
exit $status
RESTORE
    chmod 755 "$backup/restore.sh"
}

main "$@"
