#!/usr/bin/env bash
# Compare two builds of the same commit byte for byte: every file in the two
# dist/ directories must exist in both and be identical (.deb, tarball, SBOM,
# BUILDINFO, SHA256SUMS). On a difference, name the files and show what differs
# inside the archives so it can be classified as expected or a defect.
#
# Usage: scripts/reproduce-check.sh DIST_A DIST_B
set -uo pipefail
a=${1:?usage: reproduce-check.sh DIST_A DIST_B}; b=${2:?usage: reproduce-check.sh DIST_A DIST_B}
bad=0
for f in $( (cd "$a" && ls; cd "$b" && ls) | sort -u); do
    if [ ! -f "$a/$f" ] || [ ! -f "$b/$f" ]; then echo "MISSING   $f"; bad=1
    elif cmp -s "$a/$f" "$b/$f"; then echo "IDENTICAL $f  $(sha256sum < "$a/$f" | cut -c1-16)"
    else
        echo "DIFFERS   $f"; bad=1
        case $f in
            *.deb) diff <(dpkg-deb -c "$a/$f") <(dpkg-deb -c "$b/$f") | head -20 || true
                   diff <(dpkg-deb -I "$a/$f") <(dpkg-deb -I "$b/$f") | head -20 || true ;;
            *.tar.gz) diff <(tar tvzf "$a/$f") <(tar tvzf "$b/$f") | head -20 || true ;;
            *) diff "$a/$f" "$b/$f" | head -20 || true ;;
        esac
    fi
done
[ $bad -eq 0 ] && echo "reproducible: every artifact is byte-identical" || { echo "NOT reproducible"; exit 1; }
