#!/usr/bin/env bash
# Render every LabLink icon from the one logo source, packaging/lablink.svg.
#
#   scripts/build-icons.sh          regenerate packaging/icons/
#   scripts/build-icons.sh --check  fail if packaging/icons/ is out of date
#
# Outputs: hicolor PNGs (Linux launcher, taskbar), the window/header PNG the
# GUI embeds, and a macOS .iconset (turn it into .icns with
# `iconutil -c icns packaging/icons/LabLink.iconset` on a Mac). To change the
# logo, replace packaging/lablink.svg and rerun; never edit the PNGs.
set -euo pipefail
cd "$(dirname "$0")/.."
src=packaging/lablink.svg
out=packaging/icons
if [ "${1:-}" = --check ]; then
    # The committed PNGs must have been rendered from the current SVG.
    want=$(sha256sum "$src" | awk '{print $1"  lablink.svg"}')
    [ "$want" = "$(cat "$out/SOURCE.sha256" 2>/dev/null)" ] \
        || { echo "build-icons: $out was rendered from a different $src; run scripts/build-icons.sh" >&2; exit 1; }
    echo "build-icons: $out matches $src"
    exit 0
fi
command -v rsvg-convert >/dev/null || { echo "build-icons: rsvg-convert is required (apt install librsvg2-bin)" >&2; exit 2; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/LabLink.iconset"
for s in 16 24 32 48 64 128 256 512; do
    rsvg-convert -w $s -h $s "$src" -o "$tmp/lablink-$s.png"
done
for s in 16 32 128 256 512; do
    cp "$tmp/lablink-$s.png" "$tmp/LabLink.iconset/icon_${s}x${s}.png"
    rsvg-convert -w $((s * 2)) -h $((s * 2)) "$src" -o "$tmp/LabLink.iconset/icon_${s}x${s}@2x.png"
done
sha256sum "$src" | awk '{print $1"  lablink.svg"}' > "$tmp/SOURCE.sha256"
rm -rf "$out"; mkdir -p "$out"; cp -r "$tmp"/. "$out"/
echo "build-icons: wrote $(find "$out" -name '*.png' | wc -l) PNGs to $out from $src"
