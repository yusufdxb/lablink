#!/bin/sh
# Remove a tarball install of LabLink.
# Usage: ./uninstall.sh [--purge] [PREFIX]   (default PREFIX: ~/.local)
# Your configuration (~/.config/lablink) and state (~/.local/state/lablink:
# pinned host keys, history) are kept unless you pass --purge.
set -eu
purge=no
if [ "${1:-}" = "--purge" ]; then purge=yes; shift; fi
prefix=${1:-"$HOME/.local"}
data=${XDG_DATA_HOME:-"$HOME/.local/share"}
if [ -x "$prefix/bin/lablink" ]; then
    "$prefix/bin/lablink" uninstall-service 2>/dev/null || true
fi
pkill -x -u "$(id -u)" lablinkd 2>/dev/null || true
rm -f "$prefix/bin/lablink" "$prefix/bin/lablinkd" "$prefix/bin/lablink-gui" \
      "$prefix/share/applications/lablink-gui.desktop" \
      "$prefix/share/icons/hicolor/scalable/apps/lablink.svg" \
      "$data/bash-completion/completions/lablink"
if [ "$purge" = yes ]; then
    rm -rf "${XDG_CONFIG_HOME:-$HOME/.config}/lablink" "${XDG_STATE_HOME:-$HOME/.local/state}/lablink"
    echo "Removed LabLink from $prefix and deleted its configuration and state."
else
    echo "Removed LabLink from $prefix (configuration and state kept; --purge deletes them)."
fi
