#!/usr/bin/env bash
# build-deb.sh - reproducible .deb build wrapper for tessera.
#
# Usage:
#   scripts/build-deb.sh [--allow-dirty] [--check-only] [--skip-lintian]
#
# Outputs ../tessera_<ver>_amd64.deb, ../tessera_<ver>_amd64.changes,
# and ../tessera_<ver>_amd64.buildinfo.

set -euo pipefail

usage() {
    cat <<'EOF'
Usage: build-deb.sh [options]

Options:
  --allow-dirty   Build despite uncommitted changes.
  --check-only    Verify tooling and exit.
  --skip-lintian  Do not run lintian after build.
  -h, --help      Show this help.
EOF
}

allow_dirty=0
check_only=0
skip_lintian=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --allow-dirty)  allow_dirty=1 ;;
        --check-only)   check_only=1 ;;
        --skip-lintian) skip_lintian=1 ;;
        -h|--help)      usage; exit 0 ;;
        *) echo "unknown arg: $1" >&2; usage; exit 64 ;;
    esac
    shift
done

PROJECT_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

# --- Pre-flight checks -------------------------------------------------------
require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "error: required command '$1' not found in PATH" >&2
        return 1
    fi
}

check_tooling() {
    local missing=0
    require_cmd dpkg-buildpackage || missing=1
    require_cmd fakeroot          || missing=1
    require_cmd cargo             || missing=1
    require_cmd rustc             || missing=1
    require_cmd git               || missing=1
    require_cmd dpkg-parsechangelog || missing=1
    if [[ $skip_lintian -eq 0 ]]; then
        require_cmd lintian || missing=1
    fi
    return $missing
}

if ! check_tooling; then
    if [[ $check_only -eq 1 ]]; then
        exit 70
    fi
    echo "error: tooling check failed; refusing to build" >&2
    exit 70
fi

if [[ $check_only -eq 1 ]]; then
    echo "ok: all required tooling present"
    exit 0
fi

# --- Working-tree cleanliness ------------------------------------------------
# With 3.0 (quilt) source format, untracked files inside the tree can be
# picked up by dpkg-source and shipped in the resulting source package.
# Fail on uncommitted *or* untracked files unless --allow-dirty is set.
if [[ $allow_dirty -eq 0 ]]; then
    if ! git diff --quiet || ! git diff --cached --quiet; then
        echo "error: working tree has uncommitted changes (use --allow-dirty to override)" >&2
        exit 1
    fi
    if [[ -n "$(git ls-files --others --exclude-standard)" ]]; then
        echo "error: working tree has untracked files (use --allow-dirty to override):" >&2
        git ls-files --others --exclude-standard | sed 's/^/    /' >&2
        exit 1
    fi
fi

# --- Reproducibility env -----------------------------------------------------
SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct HEAD)"
export SOURCE_DATE_EPOCH

# Stable umask for predictable file modes.
umask 022

# Stable locale.
export LC_ALL=C.UTF-8
export TZ=UTC

# Pin Rust flags for determinism (codegen-units already pinned in workspace).
export CARGO_NET_OFFLINE="${CARGO_NET_OFFLINE:-false}"

iso_date() {
    if date -u -d "@$1" +%FT%TZ 2>/dev/null; then
        return
    fi
    # BSD/macOS fallback (used in dev hosts; CI is GNU/Linux).
    date -u -r "$1" +%FT%TZ
}

echo "info: SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH ($(iso_date "$SOURCE_DATE_EPOCH"))"
echo "info: cargo: $(cargo --version)"
echo "info: rustc: $(rustc --version)"

# --- Build -------------------------------------------------------------------
# Optional extra cargo flags (e.g. --features astra-mac) propagated to the
# in-tree cargo invocation here AND through dpkg-buildpackage to the
# debian/rules override_dh_auto_build via DEB_CARGO_EXTRA_OPTIONS. The env
# var is preserved so dpkg-buildpackage's restricted child env still sees it.
DEB_CARGO_EXTRA_OPTIONS="${DEB_CARGO_EXTRA_OPTIONS:-}"
export DEB_CARGO_EXTRA_OPTIONS
if [[ -n "$DEB_CARGO_EXTRA_OPTIONS" ]]; then
    echo "info: DEB_CARGO_EXTRA_OPTIONS=$DEB_CARGO_EXTRA_OPTIONS"
fi

# --- Package -----------------------------------------------------------------
# dpkg-buildpackage drives the build through debian/rules:
#   override_dh_auto_clean: rm -rf target debian/cargo_home
#   override_dh_auto_build: cargo build --release --workspace --offline
#                              || cargo build --release --workspace
# So a pre-build here just duplicates work — debian/rules wiped target/
# and rebuilt anyway. Letting dpkg-buildpackage own the build cuts the
# release-build step from ~2× to 1×. The offline→online fallback in
# debian/rules handles the network/registry warm-up that the pre-build
# used to provide.
dpkg-buildpackage -us -uc -b --no-sign

# --- Lintian -----------------------------------------------------------------
if [[ $skip_lintian -eq 0 ]]; then
    VER="$(dpkg-parsechangelog -SVersion)"
    DEB="../tessera_${VER}_amd64.deb"
    if [[ ! -f "$DEB" ]]; then
        echo "error: expected $DEB not found" >&2
        exit 1
    fi
    echo "info: running lintian on $DEB"
    if ! lintian -i -I --no-tag-display-limit --fail-on error "$DEB"; then
        echo "error: lintian reported errors" >&2
        exit 1
    fi
fi

echo "done: built ../tessera_$(dpkg-parsechangelog -SVersion)_amd64.deb"
