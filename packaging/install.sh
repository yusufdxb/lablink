#!/bin/sh
# Install LabLink from this release tarball for the current user (no root).
# Usage: ./install.sh [PREFIX]   (default PREFIX: ~/.local)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
prefix=${1:-"$HOME/.local"}
# Desktop entries cannot represent control characters in the executable path.
clean_prefix=$(printf '%s' "$prefix" | LC_ALL=C tr -d '[:cntrl:]')
if [ "$clean_prefix" != "$prefix" ]; then
    echo "PREFIX must not contain control characters" >&2; exit 1
fi
case ${XDG_DATA_HOME:-} in /*) data=$XDG_DATA_HOME ;; *) data=$HOME/.local/share ;; esac
mkdir -p "$prefix"
prefix=$(cd "$prefix" && pwd -P)
# Escape once for Exec's quoted word, then again for Desktop Entry strings.
# Percent signs are literal, never desktop field codes. A fixed env executable
# also lets GLib validate paths containing percent signs before field expansion.
exec_lines=$(printf '%s\n' "$prefix/bin/lablink-gui" | awk '
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
    print "Exec=/usr/bin/env \"" encoded "\""
    raw=""
    for (i=1; i<=length($0); i++) {
        c=substr($0,i,1)
        if (c=="\\") raw=raw "\\"
        raw=raw c
    }
    print "TryExec=" raw
}')
mkdir -p "$prefix/bin" "$prefix/share/lablink" "$data/applications"     "$data/icons/hicolor/scalable/apps" "$data/bash-completion/completions"
desktop_tmp=
marker_tmp=
cleanup() {
    [ -z "$desktop_tmp" ] || rm -f -- "$desktop_tmp"
    [ -z "$marker_tmp" ] || rm -f -- "$marker_tmp"
}
trap cleanup 0
trap 'exit 1' HUP INT TERM
desktop_tmp=$(mktemp "$data/applications/.lablink-gui.XXXXXX")
marker_tmp=$(mktemp "$prefix/share/lablink/.data-dir.XXXXXX")
# Construct the desktop entry without interpolating a path into a sed program.
while IFS= read -r line; do
    case $line in Exec=*) printf '%s\n' "$exec_lines" ;; *) printf '%s\n' "$line" ;; esac
done < "$here/share/applications/lablink-gui.desktop" > "$desktop_tmp"
printf '%s\n' "$data" > "$marker_tmp"
chmod 644 "$desktop_tmp" "$marker_tmp"
for b in lablink lablinkd lablink-gui; do
    install -m 755 "$here/bin/$b" "$prefix/bin/$b"
done
install -m 644 "$here/share/icons/hicolor/scalable/apps/lablink.svg" "$data/icons/hicolor/scalable/apps/"
install -m 644 "$here/share/bash-completion/completions/lablink" "$data/bash-completion/completions/lablink"
# Rename complete files in their destination directories. Replace existing links
# rather than writing through them, and do not inherit an old writable mode.
mv -Tf -- "$desktop_tmp" "$data/applications/lablink-gui.desktop"
desktop_tmp=
mv -Tf -- "$marker_tmp" "$prefix/share/lablink/data-dir"
marker_tmp=
echo "Installed lablink, lablinkd and lablink-gui to $prefix/bin (applications menu and bash completion for your user)"
case ":$PATH:" in
    *":$prefix/bin:"*) ;;
    *) echo "Note: $prefix/bin is not on your PATH; add it, or run $prefix/bin/lablink" ;;
esac
command -v ssh >/dev/null 2>&1 || echo "Note: LabLink uses the OpenSSH client; install it with: sudo apt install openssh-client"
echo
echo "Next: run 'lablink init' (or open LabLink from your applications menu)."
