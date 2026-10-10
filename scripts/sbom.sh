#!/usr/bin/env bash
# Write a CycloneDX dependency inventory of all crates in Cargo.lock
# (including optional, development and platform-only dependencies) to dist/lablink-<version>.cdx.json and add it to
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
# Deterministic SBOM: syft stamps a random serial number and the current
# time; use the commit time and a serial derived from commit + Cargo.lock,
# so rebuilding a commit gives a byte-identical file.
epoch=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct HEAD)}
commit=$(sed -n 's/^commit: //p' dist/BUILDINFO)
n=$(python3 - "$out" "$epoch" "$commit" <<'PY'
import hashlib, json, sys, time, uuid
path, epoch, commit = sys.argv[1], int(sys.argv[2]), sys.argv[3]
doc = json.load(open(path))
lock = hashlib.sha256(open("Cargo.lock", "rb").read()).hexdigest()
doc["serialNumber"] = "urn:uuid:" + str(uuid.uuid5(uuid.NAMESPACE_URL, f"lablink:{commit}:{lock}"))
doc.setdefault("metadata", {})["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))
with open(path, "w") as f:
    json.dump(doc, f, indent=2, sort_keys=True)
    f.write("\n")
print(len(doc["components"]))
PY
)
[ "$n" -gt 0 ] || { echo "sbom: no components in $out" >&2; exit 1; }
(
    cd dist
    grep -v " ./$(basename "$out")$" SHA256SUMS > SHA256SUMS.new || true
    sha256sum "./$(basename "$out")" >> SHA256SUMS.new
    mv SHA256SUMS.new SHA256SUMS
)
echo "== SBOM: $out ($n components)"
