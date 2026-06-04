#!/usr/bin/env bash
# verify-reproducible.sh - build tessera twice and compare.
#
# Runs `scripts/build-deb.sh --skip-lintian --allow-dirty` twice from a
# clean cargo state, captures the produced .deb files, and compares
# their SHA-256. If they differ, runs `diffoscope` (when available) to
# print the offending bytes. Linux only; pre-requisite tooling
# (dpkg-buildpackage, fakeroot, cargo) must be installed.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$PROJECT_ROOT"

OUT1="$(mktemp -d "${TMPDIR:-/tmp}/repro1.XXXXXX")"
OUT2="$(mktemp -d "${TMPDIR:-/tmp}/repro2.XXXXXX")"
trap 'rm -rf "$OUT1" "$OUT2"' EXIT

build_into() {
    local dest="$1"
    cargo clean
    rm -f ../tessera_*.deb ../tessera_*.changes ../tessera_*.buildinfo
    scripts/build-deb.sh --skip-lintian --allow-dirty
    cp ../tessera_*.deb "$dest"/
}

build_into "$OUT1"
build_into "$OUT2"

DEB1="$(ls "$OUT1"/*.deb)"
DEB2="$(ls "$OUT2"/*.deb)"

S1=$(sha256sum "$DEB1" | awk '{print $1}')
S2=$(sha256sum "$DEB2" | awk '{print $1}')

if [[ "$S1" == "$S2" ]]; then
    echo "ok: reproducible (sha256 = $S1)"
    exit 0
fi

echo "FAIL: builds differ" >&2
echo "  $DEB1 sha256 = $S1" >&2
echo "  $DEB2 sha256 = $S2" >&2
if command -v diffoscope >/dev/null 2>&1; then
    diffoscope "$DEB1" "$DEB2" || true
fi
exit 1
