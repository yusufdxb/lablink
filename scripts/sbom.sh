#!/usr/bin/env bash
# Write a CycloneDX SBOM of everything compiled into the binaries (the crates
# in Cargo.lock) to dist/lablink-<version>.cdx.json and add it to
# dist/SHA256SUMS. Uses syft in a container pinned by digest; no host install.
#
# Usage: scripts/sbom.sh   (after scripts/release.sh or scripts/package.sh)
set -euo pipefail
cd "$(dirname "$0")/.."
syft=anchore/syft:v1.18.1@sha256:b8c170b8e51bfc4779ec3ef4399942c57290f5ce76a9c3af564c9d00d4946a6b
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
test -f dist/SHA256SUMS || { echo "sbom: build dist/ first (scripts/release.sh)" >&2; exit 1; }
out=dist/lablink-$version.cdx.json
docker run --rm -v "$PWD/Cargo.lock:/src/Cargo.lock:ro" "$syft" \
    scan file:/src/Cargo.lock --source-name lablink --source-version "$version" \
    -o cyclonedx-json > "$out"
n=$(python3 -c "import json,sys; print(len(json.load(open(sys.argv[1]))['components']))" "$out")
[ "$n" -gt 0 ] || { echo "sbom: no components in $out" >&2; exit 1; }
(
    cd dist
    grep -v " ./$(basename "$out")$" SHA256SUMS > SHA256SUMS.new || true
    sha256sum "./$(basename "$out")" >> SHA256SUMS.new
    mv SHA256SUMS.new SHA256SUMS
)
echo "== SBOM: $out ($n components)"
