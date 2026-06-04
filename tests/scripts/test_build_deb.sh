#!/usr/bin/env bash
# Smoke-test for scripts/build-deb.sh. Confirms it errors out cleanly when
# preconditions are missing. The actual full build is exercised via
# install-and-test.sh and CI.

set -euo pipefail

SCRIPT="$(cd "$(dirname "$0")/../.." && pwd)/scripts/build-deb.sh"

# --help must work everywhere.
"$SCRIPT" --help | grep -q "Usage:" || { echo "FAIL: no --help" >&2; exit 1; }

# Refuse on missing required tools (simulate by overriding PATH).
# On Linux build hosts with everything installed, --check-only succeeds; on
# macOS dev hosts dpkg-buildpackage / fakeroot / lintian are missing and the
# script must error out cleanly with exit 70.
set +e
PATH=/usr/bin:/bin "$SCRIPT" --check-only >/tmp/build-deb-check.out 2>&1
rc=$?
set -e
if [[ $rc -eq 0 ]]; then
    echo "ok: tooling present (skipping missing-tool branch)"
elif [[ $rc -eq 70 ]] && grep -qE "(missing|not found)" /tmp/build-deb-check.out; then
    echo "ok: detected missing tooling"
else
    echo "FAIL: --check-only returned rc=$rc with output:" >&2
    cat /tmp/build-deb-check.out >&2
    exit 1
fi

echo "ok: build-deb.sh smoke"
