#!/usr/bin/env bash
# Fresh installer tests, entirely in disposable containers; never uninstall
# or start/stop LabLink on the workstation running this script.
set -euo pipefail
cd "$(dirname "$0")/.."
(cd dist && sha256sum -c SHA256SUMS)
commit=$(sed -n 's/^commit: //p' dist/BUILDINFO)
docker build -q -t lablink-packaging-test:ubuntu24.04 tests/packaging
for mode in tar deb; do
    docker run --rm --network none \
        -v "$PWD/dist:/artifacts:ro" -v "$PWD/tests/packaging:/tests:ro" \
        -e TEST_MODE="$mode" -e TEST_COMMIT="$commit" \
        lablink-packaging-test:ubuntu24.04 bash -eu -c '
            touch /run/lablink-packaging-container
            if [ "$TEST_MODE" = deb ]; then dpkg -i /artifacts/lablink_*_amd64.deb; fi
            runuser -u tester -- xvfb-run -a dbus-run-session -- \
                python3 /tests/verify.py "$TEST_MODE" "$TEST_COMMIT"
            if [ "$TEST_MODE" = deb ]; then
                dpkg -r lablink
                test ! -e /usr/bin/lablink
                test ! -e /usr/bin/lablinkd
                test ! -e /usr/bin/lablink-gui
                echo "PASS deb: package removal"
            fi
        '
done
