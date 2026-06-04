#!/usr/bin/env bash
# verify-checksums.sh — verify SHA-256 (and Streebog-256 when gost-engine
# is available) for a tessera Debian package and every file packed
# inside it, against a checksums.txt produced by generate-checksums.sh.
#
# Usage:
#   scripts/verify-checksums.sh <deb-path> [<checksums.txt>]
#
# Exit codes:
#   0 — every checksum matches.
#   1 — at least one checksum mismatches.
#   2 — bad arguments / missing inputs.
#   3 — gost-engine missing on a checksums.txt that contains a streebog256
#       section (cannot verify ГОСТ-suмs without engine).

set -euo pipefail
IFS=$'\n\t'

DEB="${1:-}"
CHECKSUMS="${2:-checksums/checksums.txt}"

if [[ -z "${DEB}" || ! -f "${DEB}" ]]; then
    echo "usage: $0 <deb-path> [<checksums.txt>]" >&2
    exit 2
fi

if [[ ! -f "${CHECKSUMS}" ]]; then
    echo "error: checksums file not found: ${CHECKSUMS}" >&2
    exit 2
fi

DEB_BASENAME="$(basename "${DEB}")"

TMPDIR_LOCAL="$(mktemp -d)"
trap 'rm -rf "${TMPDIR_LOCAL}"' EXIT

if command -v dpkg-deb >/dev/null 2>&1; then
    dpkg-deb -R "${DEB}" "${TMPDIR_LOCAL}"
else
    (
        cd "${TMPDIR_LOCAL}"
        ar x "${OLDPWD}/${DEB}" 2>/dev/null || ar x "${DEB}"
        for tar in data.tar.* control.tar.*; do
            [[ -f "${tar}" ]] || continue
            mkdir -p "$(basename "${tar%.tar.*}")"
            tar -xf "${tar}" -C "$(basename "${tar%.tar.*}")"
            rm -f "${tar}"
        done
        rm -f debian-binary
    )
fi

sha256_for() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1" | awk '{print $1}'
    else
        shasum -a 256 "$1" | awk '{print $1}'
    fi
}

streebog_for() {
    openssl dgst -engine gost -md_gost12_256 -hex "$1" 2>/dev/null \
        | awk '{print $NF}'
}

has_gost_engine() {
    openssl engine gost -t 2>/dev/null | grep -q '\[ available \]'
}

current_alg=""
fail_count=0
ok_count=0
streebog_present=0

while IFS= read -r line || [[ -n "${line}" ]]; do
    case "${line}" in
        \#*algorithm:*sha256*)
            current_alg="sha256"
            continue
            ;;
        \#*algorithm:*streebog256*)
            current_alg="streebog256"
            streebog_present=1
            continue
            ;;
        \#*|"")
            continue
            ;;
    esac

    expected_hash="${line%%  *}"
    relpath="${line#*  }"

    if [[ "${relpath}" == "${DEB_BASENAME}" ]]; then
        target="${DEB}"
    else
        target="${TMPDIR_LOCAL}/${relpath#./}"
    fi

    if [[ ! -f "${target}" ]]; then
        echo "FAIL ${current_alg}  missing: ${relpath}"
        fail_count=$((fail_count + 1))
        continue
    fi

    case "${current_alg}" in
        sha256)
            actual=$(sha256_for "${target}")
            ;;
        streebog256)
            if ! has_gost_engine; then
                echo "ERROR: streebog256 expected but gost-engine missing" >&2
                exit 3
            fi
            actual=$(streebog_for "${target}")
            ;;
        *)
            echo "ERROR: unknown algorithm section in checksums.txt: ${current_alg}" >&2
            exit 2
            ;;
    esac

    if [[ "${actual}" == "${expected_hash}" ]]; then
        ok_count=$((ok_count + 1))
    else
        printf 'FAIL %s  %s\n  expected: %s\n  actual:   %s\n' \
            "${current_alg}" "${relpath}" "${expected_hash}" "${actual}"
        fail_count=$((fail_count + 1))
    fi
done < "${CHECKSUMS}"

if [[ "${streebog_present}" -eq 0 ]]; then
    echo "note: checksums.txt has no streebog256 section (sha256-only verification)"
fi

if [[ "${fail_count}" -gt 0 ]]; then
    echo "FAIL: ${fail_count} mismatch(es), ${ok_count} OK"
    exit 1
fi

echo "OK: ${ok_count} checksum(s) verified"
