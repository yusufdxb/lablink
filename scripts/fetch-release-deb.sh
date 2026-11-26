#!/usr/bin/env bash
# Download a published release's .deb and verify it before any test uses it:
#   1. SHA256SUMS is fetched over HTTPS and must match the pinned hash given
#      here (a replaced or re-uploaded release asset is caught);
#   2. the .deb must match its line in that SHA256SUMS;
#   3. the package metadata must name the expected version.
# Nothing is installed.
#
# Usage: scripts/fetch-release-deb.sh VERSION SHA256SUMS_SHA256 OUT_DIR
set -euo pipefail

version=${1:?usage: fetch-release-deb.sh VERSION SHA256SUMS_SHA256 OUT_DIR}
sums_sha=${2:?usage: fetch-release-deb.sh VERSION SHA256SUMS_SHA256 OUT_DIR}
out=${3:?usage: fetch-release-deb.sh VERSION SHA256SUMS_SHA256 OUT_DIR}
base=${LABLINK_RELEASE_BASE:-https://github.com/yusufdxb/lablink/releases/download}
deb=lablink_${version}_amd64.deb

[[ $version =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "fetch-release-deb: bad version: $version" >&2; exit 2; }
[[ $sums_sha =~ ^[0-9a-f]{64}$ ]] || { echo "fetch-release-deb: bad SHA-256: $sums_sha" >&2; exit 2; }
mkdir -p "$out"
fetch() {
    curl --disable --fail --show-error --silent --location --proto '=https' --proto-redir '=https' \
        --retry 3 --connect-timeout 20 --max-time 300 -o "$out/$1" "$base/v$version/$1"
}
fetch SHA256SUMS
echo "$sums_sha  $out/SHA256SUMS" | sha256sum -c --quiet - \
    || { echo "fetch-release-deb: SHA256SUMS of v$version does not match the pinned hash" >&2; exit 1; }
fetch "$deb"
line=$(grep -E "^[0-9a-f]{64}  (\./)?${deb//./\\.}\$" "$out/SHA256SUMS") \
    || { echo "fetch-release-deb: $deb is not listed in SHA256SUMS" >&2; exit 1; }
[ "$(wc -l <<<"$line")" -eq 1 ] || { echo "fetch-release-deb: $deb is listed more than once" >&2; exit 1; }
(cd "$out" && echo "${line%% *}  $deb" | sha256sum -c --quiet -) \
    || { echo "fetch-release-deb: $deb does not match SHA256SUMS" >&2; exit 1; }
[ "$(dpkg-deb -f "$out/$deb" Version)" = "$version" ] \
    || { echo "fetch-release-deb: $deb does not name version $version" >&2; exit 1; }
echo "fetch-release-deb: verified $out/$deb (v$version, SHA256SUMS pinned)"
