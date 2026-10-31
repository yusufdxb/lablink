#!/bin/sh
# Remove a tarball install of LabLink.
# Usage: ./uninstall.sh [--purge] [PREFIX]   (default PREFIX: ~/.local)
# Configuration and pinned state are kept unless --purge is passed.
set -eu
purge=no
if [ "${1:-}" = "--purge" ]; then purge=yes; shift; fi
prefix=${1:-"$HOME/.local"}
if [ -d "$prefix" ]; then prefix=$(cd "$prefix" && pwd -P); else
    case $prefix in /*) ;; *) prefix=$PWD/$prefix ;; esac
fi
case ${XDG_DATA_HOME:-} in /*) data=$XDG_DATA_HOME ;; *) data=$HOME/.local/share ;; esac
case ${XDG_CONFIG_HOME:-} in /*) config=$XDG_CONFIG_HOME ;; *) config=$HOME/.config ;; esac
case ${XDG_STATE_HOME:-} in /*) state=$XDG_STATE_HOME ;; *) state=$HOME/.local/state ;; esac
if [ -f "$prefix/share/lablink/data-dir" ]; then
    IFS= read -r recorded_data < "$prefix/share/lablink/data-dir" || true
    case ${recorded_data:-} in /*) data=$recorded_data ;; esac
fi
# Only remove a service whose ExecStart belongs to this installation. The CLI
# generates the same systemd quoting used when it installed the user unit.
unit=$config/systemd/user/lablinkd.service
if [ -x "$prefix/bin/lablink" ] && [ -f "$unit" ]; then
    expected=$("$prefix/bin/lablink" install-service --print --daemon-path "$prefix/bin/lablinkd" 2>/dev/null | sed -n '/^ExecStart=/p') || expected=
    actual=$(sed -n '/^ExecStart=/p' "$unit")
    if [ -n "$expected" ] && [ "$actual" = "$expected" ]; then
        "$prefix/bin/lablink" uninstall-service 2>/dev/null || true
    fi
fi
# A daemon started by hand also belongs to a specific prefix, not merely a name.
uid=$(id -u)
for proc in /proc/[0-9]*; do
    [ "$(stat -c %u "$proc" 2>/dev/null || true)" = "$uid" ] || continue
    exe=$(readlink "$proc/exe" 2>/dev/null || true)
    case $exe in "$prefix/bin/lablinkd"|"$prefix/bin/lablinkd (deleted)") kill "${proc##*/}" 2>/dev/null || true ;; esac
done
# The last installed prefix owns the shared menu entry. Preserve another prefix.
exec_word=$(printf '%s\n' "$prefix/bin/lablink-gui" | awk '
{
    out=""
    for (i=1; i<=length($0); i++) {
        c=substr($0,i,1)
        if (c=="%") out=out "%%"
        else if (c=="\\" || c=="\"" || c=="$" || c=="`") out=out "\\" c
        else out=out c
    }
    encoded=""
    for (i=1; i<=length(out); i++) {
        c=substr(out,i,1)
        if (c=="\\") encoded=encoded "\\"
        encoded=encoded c
    }
    print "\"" encoded "\""
}')
entry=$data/applications/lablink-gui.desktop
if [ -f "$entry" ]; then
    actual=$(sed -n '/^Exec=/p' "$entry")
    if [ "$actual" = "Exec=/usr/bin/env $exec_word" ] || [ "$actual" = "Exec=$exec_word" ] || [ "$actual" = "Exec=$prefix/bin/lablink-gui" ]; then
        rm -f "$entry" "$data/icons/hicolor/scalable/apps/lablink.svg" "$data/bash-completion/completions/lablink"
        for s in 16 24 32 48 64 128 256 512; do rm -f "$data/icons/hicolor/${s}x$s/apps/lablink.png"; done
    fi
fi
rm -f "$prefix/bin/lablink" "$prefix/bin/lablinkd" "$prefix/bin/lablink-gui" "$prefix/share/lablink/data-dir"
# Under the default prefix these are the shared entries kept above.
[ "$prefix/share/applications/lablink-gui.desktop" -ef "$entry" ] || rm -f "$prefix/share/applications/lablink-gui.desktop"
[ "$prefix/share/icons/hicolor/scalable/apps/lablink.svg" -ef "$data/icons/hicolor/scalable/apps/lablink.svg" ] || rm -f "$prefix/share/icons/hicolor/scalable/apps/lablink.svg"
if [ "$purge" = yes ]; then
    case ${LABLINK_CONFIG:-} in /*) rm -f "$LABLINK_CONFIG" ;; *) rm -rf "$config/lablink" ;; esac
    # A custom state directory may hold other files: never delete it wholesale.
    case ${LABLINK_STATE_DIR:-} in
        /*) echo "LABLINK_STATE_DIR is set; delete $LABLINK_STATE_DIR yourself if it holds only LabLink state." >&2
            echo "Removed LabLink from $prefix and deleted its configuration (state kept in $LABLINK_STATE_DIR)." ;;
        *) rm -rf "$state/lablink"
            echo "Removed LabLink from $prefix and deleted its configuration and state." ;;
    esac
else
    echo "Removed LabLink from $prefix (configuration and state kept; --purge deletes them)."
fi
