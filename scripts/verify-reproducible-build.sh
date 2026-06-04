#!/usr/bin/env bash
# verify-reproducible-build.sh — build the .deb twice on a clean tree and
# confirm both builds produce the byte-identical .deb (SHA-256 of both must
# match). Run on the v1.0.0 git tag (or any later tag).
#
# Usage:
#   scripts/verify-reproducible-build.sh
#
# Exit codes:
#   0 — both builds produced identical SHA-256.
#   1 — hashes diverged. The script extracts both .deb's into /tmp/repro-A
#       and /tmp/repro-B and prints `diff -r` for the operator.
#   2 — build environment is missing (dpkg-buildpackage / fakeroot / etc.).
#   3 — repository is dirty (refuse to run on uncommitted changes).
#
# Assumptions:
#   - $SOURCE_DATE_EPOCH is honoured by debian/rules (see Stage 7).
#   - scripts/build-deb.sh is the canonical build entry point.
#   - The output .deb lands in artifacts/release/.

set -euo pipefail
IFS=$'\n\t'

# 0. Tooling guard.
for cmd in dpkg-buildpackage fakeroot dpkg-deb sha256sum; do
    if ! command -v "${cmd}" >/dev/null 2>&1; then
        echo "ERROR: missing required command '${cmd}'" >&2
        echo "       This script must run on a Debian/Ubuntu/Astra build host" >&2
        exit 2
    fi
done

# 1. Tree-cleanliness guard. The reproducibility check is meaningless when
#    untracked files leak into dpkg-source's source-tarball view.
if [[ -n "$(git status --porcelain)" ]]; then
    echo "ERROR: working tree has uncommitted changes; refusing to run." >&2
    git status --short >&2
    exit 3
fi

# 2. Determine SOURCE_DATE_EPOCH from the latest committed timestamp,
#    matching Stage 7 default.
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --pretty=%ct)}"
echo "info: SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}"

# 3. Build #1 — clean & build.
git clean -fdx artifacts/release || true
./scripts/build-deb.sh

DEB_PATH=$(ls -1 artifacts/release/tessera_*_amd64.deb 2>/dev/null | head -n 1)
if [[ -z "${DEB_PATH}" ]]; then
    echo "ERROR: build did not produce a .deb in artifacts/release/" >&2
    exit 2
fi

HASH_A=$(sha256sum "${DEB_PATH}" | awk '{print $1}')
echo "info: build A: ${HASH_A}  ${DEB_PATH}"

mkdir -p /tmp/repro-A
dpkg-deb -R "${DEB_PATH}" /tmp/repro-A
cp "${DEB_PATH}" "/tmp/repro-A.deb"

# 4. Build #2 — clean & rebuild.
git clean -fdx artifacts/release
./scripts/build-deb.sh

DEB_PATH=$(ls -1 artifacts/release/tessera_*_amd64.deb 2>/dev/null | head -n 1)
HASH_B=$(sha256sum "${DEB_PATH}" | awk '{print $1}')
echo "info: build B: ${HASH_B}  ${DEB_PATH}"

mkdir -p /tmp/repro-B
dpkg-deb -R "${DEB_PATH}" /tmp/repro-B
cp "${DEB_PATH}" "/tmp/repro-B.deb"

# 5. Compare.
if [[ "${HASH_A}" != "${HASH_B}" ]]; then
    echo "REPRODUCIBLE BUILD FAILED:"
    echo "  build A: ${HASH_A}"
    echo "  build B: ${HASH_B}"
    echo
    echo "diff -r /tmp/repro-A /tmp/repro-B:"
    diff -r /tmp/repro-A /tmp/repro-B || true
    exit 1
fi

echo "REPRODUCIBLE: ${HASH_A}"
