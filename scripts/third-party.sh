#!/usr/bin/env bash
# Regenerate THIRD_PARTY_LICENSES.md for the current Cargo.lock.
# Needs: cargo-about (`cargo install --locked cargo-about --features cli`).
set -euo pipefail
cd "$(dirname "$0")/.."
out=THIRD_PARTY_LICENSES.md
fonts=$(cargo metadata --format-version 1 --locked | python3 -c '
import json,sys,os
m=json.load(sys.stdin)
p=[x for x in m["packages"] if x["name"]=="epaint_default_fonts"][0]
print(os.path.join(os.path.dirname(p["manifest_path"]),"fonts"))')
{
    cargo about generate --locked --workspace -c about.toml packaging/about/about.hbs
    echo "## Fonts embedded in lablink-gui"
    echo
    echo "The egui toolkit (crate epaint_default_fonts) embeds these fonts in the GUI binary."
    for f in "Ubuntu-Light (Ubuntu Font Licence 1.0):UFL.txt" \
             "Hack-Regular (MIT and Bitstream Vera licenses):Hack-Regular.txt" \
             "Noto Emoji (SIL Open Font License 1.1):OFL.txt" \
             "emoji-icon-font (MIT):emoji-icon-font-mit-license.txt"; do
        echo
        echo "### ${f%%:*}"
        echo
        echo '```text'
        cat "$fonts/${f##*:}"
        echo '```'
    done
    echo
    echo "<!-- Cargo.lock sha256: $(sha256sum Cargo.lock | cut -d' ' -f1) -->"
} > "$out"
echo "wrote $out ($(wc -l < "$out") lines)"
