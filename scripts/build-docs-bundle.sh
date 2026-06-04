#!/usr/bin/env bash
# build-docs-bundle.sh — pack the user-facing documentation set into a
# reproducible tarball, compute SHA-256 + Streebog-256 sums, and (if the
# operator supplies signing keys) detach-sign the tarball with GPG and
# ГОСТ.
#
# Usage:
#   scripts/build-docs-bundle.sh [version]
#
# Environment:
#   SOURCE_DATE_EPOCH — pin tar mtime; defaults to git's HEAD timestamp
#                       or 1735689600 if not in a git tree.
#   GPG_KEY           — fingerprint or key id; if set, the tarball is
#                       detach-signed (ASCII-armored .asc file).
#   GOST_KEY          — path to a ГОСТ private-key file; if set, the
#                       tarball is detach-signed via openssl + gost-engine
#                       (.gost-sig file).
#
# Output (in artifacts/release/):
#   tessera-docs-<version>.tar.gz
#   tessera-docs-<version>.tar.gz.sha256
#   tessera-docs-<version>.tar.gz.streebog256   (if gost-engine present)
#   tessera-docs-<version>.tar.gz.asc           (if GPG_KEY set)
#   tessera-docs-<version>.tar.gz.gost-sig      (if GOST_KEY set)
#
# Determinism:
#   GNU tar's --sort=name --owner=0 --group=0 --numeric-owner --mtime
#   options are used to make the archive byte-stable. Re-running the script
#   on a clean tree must produce an identical SHA-256.

set -euo pipefail
IFS=$'\n\t'

VERSION="${1:-1.0.0}"
OUT_DIR="artifacts/release"
OUT="${OUT_DIR}/tessera-docs-${VERSION}.tar.gz"

if command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
    DEFAULT_EPOCH="$(git log -1 --pretty=%ct)"
else
    DEFAULT_EPOCH="1735689600"
fi
SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-${DEFAULT_EPOCH}}"
export SOURCE_DATE_EPOCH

mkdir -p "${OUT_DIR}"

# 1. Pack documentation.
TAR_PATHS=(README.md README.en.md SECURITY.md docs)
for p in "${TAR_PATHS[@]}"; do
    if [[ ! -e "${p}" ]]; then
        echo "ERROR: missing path '${p}' (run from repository root)" >&2
        exit 2
    fi
done

# Pick a deterministic tar invocation. GNU tar (Linux production) supports
# the full reproducibility flags. BSD tar (macOS dev hosts) does not, so
# fall back to a less-deterministic invocation that still produces a valid
# tarball; reproducibility is then enforced only on Linux build hosts.
if tar --help 2>&1 | grep -q -- '--sort'; then
    tar --sort=name --owner=0 --group=0 --numeric-owner \
        --mtime="@${SOURCE_DATE_EPOCH}" \
        -czf "${OUT}" \
        "${TAR_PATHS[@]}"
else
    echo "warning: GNU tar not available; producing a non-reproducible archive." >&2
    echo "warning: reproducibility verification must be run on a Linux host." >&2
    LC_ALL=C tar -czf "${OUT}" "${TAR_PATHS[@]}"
fi

echo "info: bundle: ${OUT}"

# 2. SHA-256.
# Record only the basename so that `sha256sum -c <bundle>.sha256` works
# when run from the directory the artifact lives in (publishers ship the
# .tar.gz + .sha256 pair side-by-side; an embedded relative path like
# `artifacts/release/...` would fail at verification time).
OUT_BASENAME="$(basename -- "${OUT}")"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum -- "${OUT}" \
        | awk -v name="${OUT_BASENAME}" '{print $1"  "name}' \
        > "${OUT}.sha256"
else
    printf '%s  %s\n' "$(shasum -a 256 "${OUT}" | awk '{print $1}')" \
        "${OUT_BASENAME}" > "${OUT}.sha256"
fi
echo "info: sha256:    ${OUT}.sha256"

# 3. Streebog-256 (best-effort — needs gost-engine).
if openssl engine gost -t 2>/dev/null | grep -q '\[ available \]'; then
    deb_hash=$(openssl dgst -engine gost -md_gost12_256 -hex "${OUT}" \
        2>/dev/null | awk '{print $NF}')
    printf '%s  %s\n' "${deb_hash}" "$(basename "${OUT}")" \
        > "${OUT}.streebog256"
    echo "info: streebog: ${OUT}.streebog256"
else
    echo "warning: gost-engine not available; skipping Streebog-256." >&2
    echo "warning: run on Astra Linux SE 1.7+ for full Streebog-256 output." >&2
fi

# 4. GPG sign (open-source distribution).
if [[ -n "${GPG_KEY:-}" ]]; then
    gpg --batch --yes --detach-sign --armor \
        --local-user "${GPG_KEY}" "${OUT}"
    echo "info: gpg sig:  ${OUT}.asc"
else
    echo "info: GPG_KEY not set; skipping detached GPG signature."
    echo "info: to sign, run:"
    echo "      GPG_KEY=<fingerprint> $0 ${VERSION}"
fi

# 5. ГОСТ sign. This is a TEMPLATE — the actual key material is
#    operator-supplied; the repository never contains keys.
if [[ -n "${GOST_KEY:-}" ]]; then
    if openssl engine gost -t 2>/dev/null | grep -q '\[ available \]'; then
        openssl dgst -engine gost -sign "${GOST_KEY}" -md_gost12_256 \
            -out "${OUT}.gost-sig" "${OUT}"
        echo "info: gost sig: ${OUT}.gost-sig"
    else
        echo "ERROR: GOST_KEY set but gost-engine missing." >&2
        exit 3
    fi
else
    echo "info: GOST_KEY not set; skipping ГОСТ signature."
    echo "info: to sign, run on Astra Linux SE 1.7+:"
    echo "      GOST_KEY=/path/to/gost.key $0 ${VERSION}"
fi
