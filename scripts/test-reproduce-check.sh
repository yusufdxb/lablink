#!/usr/bin/env bash
# Regression test for scripts/reproduce-check.sh: both directories are
# listed whether they are given as relative or absolute paths, so a file
# present in only one build is always reported.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
check=$PWD/scripts/reproduce-check.sh
mkdir -p "$t/a" "$t/b"
echo same > "$t/a/SHA256SUMS"; echo same > "$t/b/SHA256SUMS"
fail=0
expect() { # expect RC NEEDLE -- args...
    local want=$1 needle=$2; shift 3
    out=$(cd "$t" && "$check" "$@" 2>&1); rc=$?
    if [ "$rc" -ne "$want" ] || ! grep -q "$needle" <<<"$out"; then
        echo "FAIL: reproduce-check.sh $* (exit $rc, want $want, expected '$needle')"; echo "$out"; fail=1
    else echo "ok: reproduce-check.sh $* -> exit $rc, '$needle'"; fi
}
expect 0 'every artifact is byte-identical' -- a b
echo extra > "$t/b/only-in-second.deb"
for args in "a b" "$t/a b" "a $t/b" "$t/a $t/b"; do
    # shellcheck disable=SC2086
    expect 1 'MISSING   only-in-second.deb' -- $args
done
rm "$t/b/only-in-second.deb"; echo extra > "$t/a/only-in-first.deb"
expect 1 'MISSING   only-in-first.deb' -- "$t/a" b
exit $fail
