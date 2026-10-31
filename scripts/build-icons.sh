#!/usr/bin/env bash
# Build every LabLink icon from the one logo source, packaging/app-icon.png.
#
#   scripts/build-icons.sh          regenerate packaging/icons/
#   scripts/build-icons.sh --check  fail if packaging/icons/ is out of date
#
# The source is the 512x512 default app icon of the eframe 0.36.2 crate
# (data/icon.png, MIT OR Apache-2.0), byte-identical to the macOS app icon.
# Sizes are only ever downsampled from it, never redrawn or upscaled.
#
# Outputs: hicolor PNGs (Linux launcher, taskbar), the window/header PNG the
# GUI embeds, and a macOS .iconset up to 512 px (turn it into .icns with
# `iconutil -c icns packaging/icons/LabLink.iconset` on a Mac). To change the
# logo, replace packaging/app-icon.png and rerun; never edit the PNGs.
set -euo pipefail
cd "$(dirname "$0")/.."
src=packaging/app-icon.png
out=packaging/icons
if [ "${1:-}" = --check ]; then
    # The committed PNGs must have been built from the current source.
    want=$(sha256sum "$src" | awk '{print $1"  app-icon.png"}')
    [ "$want" = "$(cat "$out/SOURCE.sha256" 2>/dev/null)" ] \
        || { echo "build-icons: $out was built from a different $src; run scripts/build-icons.sh" >&2; exit 1; }
    echo "build-icons: $out matches $src"
    exit 0
fi
python3 -c 'import PIL' 2>/dev/null || { echo "build-icons: Python Pillow is required (apt install python3-pil)" >&2; exit 2; }
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
python3 - "$src" "$tmp" <<'PY'
import os, shutil, sys
from PIL import Image
src, out = sys.argv[1], sys.argv[2]
img = Image.open(src).convert("RGBA")
if img.size != (512, 512):
    sys.exit(f"build-icons: {src} must be 512x512, got {img.size}")
def save(size, path):
    if size == 512:  # the source itself, byte for byte
        shutil.copyfile(src, path)
    else:
        img.resize((size, size), Image.LANCZOS).save(path, optimize=True)
for s in (16, 24, 32, 48, 64, 128, 256, 512):
    save(s, os.path.join(out, f"lablink-{s}.png"))
iconset = os.path.join(out, "LabLink.iconset")
os.mkdir(iconset)
for s in (16, 32, 128, 256, 512):
    save(s, os.path.join(iconset, f"icon_{s}x{s}.png"))
    if s * 2 <= 512:  # no @2x for 512: the source has no 1024 px detail
        save(s * 2, os.path.join(iconset, f"icon_{s}x{s}@2x.png"))
PY
sha256sum "$src" | awk '{print $1"  app-icon.png"}' > "$tmp/SOURCE.sha256"
rm -rf "$out"; mkdir -p "$out"; cp -r "$tmp"/. "$out"/
echo "build-icons: wrote $(find "$out" -name '*.png' | wc -l) PNGs to $out from $src"
