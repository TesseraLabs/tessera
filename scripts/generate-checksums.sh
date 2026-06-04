#!/usr/bin/env bash
# generate-checksums.sh — produce SHA-256 + Streebog-256 checksums for the
# tessera Debian package and every file packed inside it.
#
# Usage:
#   scripts/generate-checksums.sh <deb-path> [<output-dir>]
#
# Output:
#   <output-dir>/checksums.txt                     # combined, both algorithms
#   <output-dir>/<deb-name>.sha256                 # standalone SHA-256
#   <output-dir>/<deb-name>.streebog256            # standalone Streebog-256
#
# Determinism:
#   - Files are listed in C-locale lexicographic order.
#   - Timestamp written to the header is taken from $SOURCE_DATE_EPOCH if set,
#     else from `date -u +%s` at run time.
#
# Streebog-256 (ГОСТ Р 34.11-2012-256) requires gost-engine to be available
# to OpenSSL. On Astra Linux SE 1.7+ this is the default. On Debian/Ubuntu
# without gost-engine the Streebog-256 section is skipped with a warning
# (the SHA-256 output is still produced).

set -euo pipefail
IFS=$'\n\t'

DEB="${1:-}"
OUT_DIR="${2:-checksums}"

if [[ -z "${DEB}" || ! -f "${DEB}" ]]; then
    echo "usage: $0 <deb-path> [<output-dir>]" >&2
    exit 2
fi

DEB_BASENAME="$(basename "${DEB}")"

# Deterministic timestamp: SOURCE_DATE_EPOCH wins.
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(date -u +%s)}"
TIMESTAMP="$(date -u -d "@${SOURCE_DATE_EPOCH}" +%FT%TZ 2>/dev/null \
    || date -u -r "${SOURCE_DATE_EPOCH}" +%FT%TZ)"

mkdir -p "${OUT_DIR}"

TMPDIR_LOCAL="$(mktemp -d)"
trap 'rm -rf "${TMPDIR_LOCAL}"' EXIT

# Extract the .deb into a flat tree so we can checksum every file.
if command -v dpkg-deb >/dev/null 2>&1; then
    dpkg-deb -R "${DEB}" "${TMPDIR_LOCAL}"
else
    # Fallback: extract via ar + tar. This branch is for dev hosts (macOS)
    # where dpkg-deb is unavailable. The set of files is the same.
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

# Helper: stable file listing within $TMPDIR_LOCAL.
list_files() {
    (cd "${TMPDIR_LOCAL}" && LC_ALL=C find . -type f | LC_ALL=C sort)
}

# Helper: pick a SHA-256 binary that prints `<hex>  <path>` lines.
sha256_one() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1"
    else
        # macOS fallback.
        printf '%s  %s\n' "$(shasum -a 256 "$1" | awk '{print $1}')" "$1"
    fi
}

# Helper: detect whether gost-engine is available.
has_gost_engine() {
    openssl engine gost -t 2>/dev/null | grep -q '\[ available \]'
}

CHECKSUMS_FILE="${OUT_DIR}/checksums.txt"

# --- SHA-256 section ---------------------------------------------------------
{
    echo "# tessera checksums"
    echo "# generated: ${TIMESTAMP}"
    echo "# algorithm: sha256"
    sha256_one "${DEB}" | awk -v name="${DEB_BASENAME}" '{print $1"  "name}'
    while IFS= read -r relpath; do
        # relpath comes as "./control/control" — keep the leading "./" so the
        # verifier can use it as a path inside the extracted tree.
        sha256_one "${TMPDIR_LOCAL}/${relpath#./}" \
            | awk -v rel="${relpath}" '{print $1"  "rel}'
    done < <(list_files)
} > "${CHECKSUMS_FILE}"

# Standalone .sha256 file (used by `sha256sum -c`).
# Record only the basename so that `sha256sum -c <file>.sha256` works
# from the directory the artifact lives in (the verifier looks up the
# path verbatim, and a relative path like `artifacts/release/...` would
# fail when the .deb + .sha256 pair is published side-by-side).
sha256_one "${DEB}" \
    | awk -v name="${DEB_BASENAME}" '{print $1"  "name}' \
    > "${OUT_DIR}/${DEB_BASENAME}.sha256"

# --- Streebog-256 section ----------------------------------------------------
if has_gost_engine; then
    {
        echo "# algorithm: streebog256"
        # OpenSSL prints lines as: `GOST R 34.11-2012(<file>)= <hex>` with -hex.
        deb_hash=$(openssl dgst -engine gost -md_gost12_256 -hex "${DEB}" \
            2>/dev/null | awk '{print $NF}')
        printf '%s  %s\n' "${deb_hash}" "${DEB_BASENAME}"
        while IFS= read -r relpath; do
            file_hash=$(openssl dgst -engine gost -md_gost12_256 -hex \
                "${TMPDIR_LOCAL}/${relpath#./}" 2>/dev/null | awk '{print $NF}')
            printf '%s  %s\n' "${file_hash}" "${relpath}"
        done < <(list_files)
    } >> "${CHECKSUMS_FILE}"

    # Standalone Streebog-256 file.
    deb_hash=$(openssl dgst -engine gost -md_gost12_256 -hex "${DEB}" \
        2>/dev/null | awk '{print $NF}')
    printf '%s  %s\n' "${deb_hash}" "${DEB_BASENAME}" \
        > "${OUT_DIR}/${DEB_BASENAME}.streebog256"
else
    cat >&2 <<'EOF'
warning: gost-engine not available; the Streebog-256 section is omitted.
         Run this script on Astra Linux SE 1.7+ (or any host with the
         gost-engine OpenSSL provider installed) to produce a complete
         checksums.txt with both SHA-256 and Streebog-256.
EOF
fi

echo "checksums written to ${OUT_DIR}/"
