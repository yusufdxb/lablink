#!/bin/sh
# Install LabLink from this release tarball for the current user (no root).
# Usage: ./install.sh [PREFIX]   (default PREFIX: ~/.local)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
prefix=${1:-"$HOME/.local"}
data=${XDG_DATA_HOME:-"$HOME/.local/share"}
mkdir -p "$prefix/bin" "$prefix/share/applications" "$prefix/share/icons/hicolor/scalable/apps" \
    "$data/bash-completion/completions"
for b in lablink lablinkd lablink-gui; do
    install -m 755 "$here/bin/$b" "$prefix/bin/$b"
done
install -m 644 "$here/share/applications/lablink-gui.desktop" "$prefix/share/applications/"
install -m 644 "$here/share/icons/hicolor/scalable/apps/lablink.svg" "$prefix/share/icons/hicolor/scalable/apps/"
install -m 644 "$here/share/bash-completion/completions/lablink" "$data/bash-completion/completions/lablink"
# Desktop entry: point Exec at the installed binary in case PREFIX/bin is not on PATH.
sed -i "s|^Exec=lablink-gui|Exec=$prefix/bin/lablink-gui|" "$prefix/share/applications/lablink-gui.desktop"
echo "Installed lablink, lablinkd and lablink-gui to $prefix/bin (bash completion for your user)"
case ":$PATH:" in
    *":$prefix/bin:"*) ;;
    *) echo "Note: $prefix/bin is not on your PATH; add it, or run $prefix/bin/lablink" ;;
esac
command -v ssh >/dev/null 2>&1 || echo "Note: LabLink uses the OpenSSH client; install it with: sudo apt install openssh-client"
echo
echo "Next: run 'lablink init' (or open LabLink from your applications menu)."
