#!/usr/bin/env bash
# Build the release artifacts for the committed HEAD, reproducibly:
#   - from a clean `git archive` of HEAD (never the working tree),
#   - in the pinned Ubuntu 20.04 container (packaging/build.Dockerfile) with
#     the Rust toolchain from rust-toolchain.toml,
#   - with the full commit SHA embedded (`lablink version`).
# Output: dist/ (.deb, tarball, CycloneDX SBOM, SHA256SUMS, BUILDINFO).
#
# Usage: scripts/release.sh
#   LABLINK_MAINTAINER="Name <email>"   Debian Maintainer field (optional)
#   LABLINK_HOMEPAGE=https://...        Debian Homepage field (optional)
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -n "$(git status --porcelain)" ]; then
    echo "release: the working tree has uncommitted changes; commit first" >&2
    exit 1
fi
sha=$(git rev-parse HEAD)
toolchain=$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)
img=lablink-build:ubuntu20.04-rust$toolchain

echo "== builder image $img"
docker build -q -t "$img" --build-arg RUST_TOOLCHAIN="$toolchain" \
    -f packaging/build.Dockerfile packaging >/dev/null

work=$(mktemp -d)
trap 'docker run --rm -v "$work:/w" "$img" rm -rf /w/src >/dev/null 2>&1 || true; rm -rf "$work"' EXIT
mkdir -p "$work/src"
git archive --format=tar HEAD | tar -x -C "$work/src"

echo "== building $sha in Ubuntu 20.04"
docker run --rm \
    -v "$work/src:/src" \
    -v lablink-cargo-registry:/root/.cargo/registry \
    -e LABLINK_GIT_SHA="$sha" \
    -e LABLINK_MAINTAINER="${LABLINK_MAINTAINER:-}" \
    -e LABLINK_HOMEPAGE="${LABLINK_HOMEPAGE:-}" \
    -e LABLINK_BASE_IMAGE="$(sed -n 's/^FROM //p' packaging/build.Dockerfile)" \
    "$img" bash -c "scripts/package.sh && chown -R $(id -u):$(id -g) dist"

rm -rf dist
cp -r "$work/src/dist" dist
scripts/sbom.sh
echo "== release artifacts for $sha"
cat dist/SHA256SUMS
