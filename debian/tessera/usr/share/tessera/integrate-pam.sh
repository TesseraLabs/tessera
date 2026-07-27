#!/usr/bin/env bash
# integrate-pam.sh — insert "@include <snippet>" + session-line into a PAM service.
#
# Usage:
#   sudo integrate-pam.sh [--mode=2fa|optional|cert-only] <pam.d-file>
#   sudo integrate-pam.sh --unintegrate <pam.d-file>
#
# Modes (canonical interface, --mode=...):
#   2fa        snippet=tessera          (default; cert + password, classic 2FA)
#   optional   snippet=tessera-optional (cert OR password; phased rollout)
#   cert-only  snippet=tessera-only     (cert is sole factor — LOCKOUT-STRICT)
#
# Deprecated aliases (still accepted for BC, emit deprecation note on stderr):
#   --strict     ≡ --mode=2fa
#   --optional   ≡ --mode=optional
#
# Behaviour (two-include pattern, 0.3.12+):
#   1. Refuses to run if the target file does not exist.
#   2. Inserts "@include <snippet>" (auth + account phases) into the auth
#      block. Placement:
#        - if file contains `auth ... pam_parsec_mac.so` → AFTER it
#          (avoids success=done jump skipping pam_parsec_mac, which
#          breaks account-phase on Astra SE with МКЦ enabled);
#        - else → BEFORE the first `auth` line.
#      Idempotent: line already present ⇒ skipped.
#   3. Additionally inserts `session required pam_tessera.so` AFTER
#      `@include common-session` (or after the last session-phase line
#      if common-session is absent), so our session-phase runs AFTER
#      `pam_systemd.so` has populated `XDG_SESSION_ID` in the PAM
#      environment. Without this, monitord cannot bind USB-removal
#      actions (Lock/Logout) to the user's logind session.
#      Idempotent: line already present ⇒ skipped.
#   4. Backs up to <target>.bak.<UTC-timestamp> before any edit (single
#      backup per invocation even if both insertions run).
#
# --unintegrate:
#   * Removes both `@include tessera*` and the explicit
#     `session required pam_tessera.so` line. Idempotent.

set -euo pipefail

snippet="tessera"
mode_op="integrate"

mode_to_snippet() {
    case "$1" in
        2fa)        echo "tessera" ;;
        optional)   echo "tessera-optional" ;;
        cert-only)  echo "tessera-only" ;;
        *)
            echo "error: unknown --mode value: $1 (expected 2fa|optional|cert-only)" >&2
            exit 64
            ;;
    esac
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --mode=*)
            snippet="$(mode_to_snippet "${1#--mode=}")"
            shift
            ;;
        --mode)
            if [[ $# -lt 2 ]]; then
                echo "error: --mode requires an argument (2fa|optional|cert-only)" >&2
                exit 64
            fi
            snippet="$(mode_to_snippet "$2")"
            shift 2
            ;;
        --optional)
            echo "warning: --optional is deprecated, use --mode=optional" >&2
            snippet="tessera-optional"
            shift
            ;;
        --strict)
            echo "warning: --strict is deprecated, use --mode=2fa" >&2
            snippet="tessera"
            shift
            ;;
        --unintegrate)
            mode_op="unintegrate"
            shift
            ;;
        --)
            shift
            break
            ;;
        --*)
            echo "error: unknown flag: $1" >&2
            exit 64
            ;;
        *)
            break
            ;;
    esac
done

if [[ $# -ne 1 ]]; then
    echo "usage: $0 [--mode=2fa|optional|cert-only] [--unintegrate] <pam.d-file>" >&2
    echo "       --mode=cert-only is the lockout-strict mode (no password fallback)" >&2
    exit 64
fi

target="$1"

# Regex for the session-phase tessera line we manage. Lenient on whitespace,
# strict on module name; matches lines like:
#   session  required  pam_tessera.so
#   session required pam_tessera.so
SESSION_LINE_RE='^[[:space:]]*session[[:space:]]+required[[:space:]]+pam_tessera\.so[[:space:]]*$'
SESSION_LINE_CANONICAL='session    required   pam_tessera.so'

# Copy permissions+owner from a reference file to a tmpfile.
preserve_attrs() {
    local ref="$1"
    local tmp="$2"
    if chmod --reference="$ref" "$tmp" 2>/dev/null; then
        :
    else
        local perms
        perms="$(stat -c '%a' "$ref" 2>/dev/null || stat -f '%Lp' "$ref" 2>/dev/null || echo 644)"
        chmod "$perms" "$tmp"
    fi
    chown --reference="$ref" "$tmp" 2>/dev/null || true
}

# -----------------------------------------------------------------------------
# --unintegrate: strip both @include tessera* and session required pam_tessera.
# -----------------------------------------------------------------------------
if [[ "$mode_op" == "unintegrate" ]]; then
    if [[ ! -f "$target" ]]; then
        echo "info: $target does not exist (no-op)"
        exit 0
    fi
    has_include=0
    has_session=0
    if grep -qE '^[[:space:]]*@include[[:space:]]+tessera(-optional|-only)?[[:space:]]*$' "$target"; then
        has_include=1
    fi
    if grep -qE "$SESSION_LINE_RE" "$target"; then
        has_session=1
    fi
    if [[ $has_include -eq 0 && $has_session -eq 0 ]]; then
        echo "info: $target has no tessera lines (no-op)"
        exit 0
    fi
    ts="$(date -u +%Y%m%dT%H%M%SZ)"
    backup="${target}.bak.${ts}"
    cp -p "$target" "$backup"
    echo "info: backup written to $backup"
    tmpfile="$(mktemp "${target}.XXXXXX")"
    sed -E \
        -e '/^[[:space:]]*@include[[:space:]]+tessera(-optional|-only)?[[:space:]]*$/d' \
        -e '/^[[:space:]]*session[[:space:]]+required[[:space:]]+pam_tessera\.so[[:space:]]*$/d' \
        "$target" > "$tmpfile"
    preserve_attrs "$target" "$tmpfile"
    mv "$tmpfile" "$target"
    echo "info: $target updated (tessera lines removed)"
    exit 0
fi

if [[ ! -f "$target" ]]; then
    echo "error: $target does not exist" >&2
    exit 66
fi

include_line="@include ${snippet}"

# Decide which actions are still needed (for idempotence + backup-skip).
need_include=1
if grep -qxF "$include_line" "$target"; then
    need_include=0
fi
need_session=1
if grep -qE "$SESSION_LINE_RE" "$target"; then
    need_session=0
fi

if [[ $need_include -eq 0 && $need_session -eq 0 ]]; then
    echo "info: $target already integrated (no-op)"
    exit 0
fi

ts="$(date -u +%Y%m%dT%H%M%SZ)"
backup="${target}.bak.${ts}"
cp -p "$target" "$backup"
echo "info: backup written to $backup"

tmpfile="$(mktemp "${target}.XXXXXX")"

# -----------------------------------------------------------------------------
# Pass 1: insert @include for auth/account, if needed.
# -----------------------------------------------------------------------------
if [[ $need_include -eq 1 ]]; then
    if grep -qE '^[[:space:]]*auth[[:space:]].*pam_parsec_mac\.so' "$target"; then
        insert_mode="after-parsec-mac"
    else
        insert_mode="before-first-auth"
    fi

    inserted=0
    while IFS= read -r line || [[ -n "$line" ]]; do
        if [[ $inserted -eq 0 && "$insert_mode" == "before-first-auth" \
              && "$line" =~ ^[[:space:]]*auth[[:space:]] ]]; then
            printf '%s\n' "$include_line" >> "$tmpfile"
            inserted=1
        fi
        printf '%s\n' "$line" >> "$tmpfile"
        if [[ $inserted -eq 0 && "$insert_mode" == "after-parsec-mac" \
              && "$line" =~ ^[[:space:]]*auth[[:space:]].*pam_parsec_mac\.so ]]; then
            printf '%s\n' "$include_line" >> "$tmpfile"
            inserted=1
        fi
    done < "$target"

    if [[ $inserted -eq 0 ]]; then
        # No anchor line present — append at end. (Rare: file with no
        # `auth` phase at all.)
        printf '%s\n' "$include_line" >> "$tmpfile"
    fi
else
    cp "$target" "$tmpfile"
fi

# -----------------------------------------------------------------------------
# Pass 2: insert `session required pam_tessera.so` after @include common-session
# (or after the last session-phase line if common-session is absent).
#
# Anchor priority:
#   1. last line matching `^[[:space:]]*@include[[:space:]]+common-session`
#   2. last line matching `^[[:space:]]*session[[:space:]]` (any module)
#   3. append at EOF
# -----------------------------------------------------------------------------
if [[ $need_session -eq 1 ]]; then
    tmpfile2="$(mktemp "${target}.XXXXXX")"

    # Find anchor line number (1-based). Use grep -n to be deterministic.
    anchor_line=""
    if anchor_line=$(grep -nE '^[[:space:]]*@include[[:space:]]+common-session([[:space:]]|$)' \
                        "$tmpfile" | tail -1 | cut -d: -f1) && [[ -n "$anchor_line" ]]; then
        :
    elif anchor_line=$(grep -nE '^[[:space:]]*session[[:space:]]' \
                        "$tmpfile" | tail -1 | cut -d: -f1) && [[ -n "$anchor_line" ]]; then
        :
    else
        anchor_line=""
    fi

    if [[ -n "$anchor_line" ]]; then
        current=0
        while IFS= read -r line || [[ -n "$line" ]]; do
            current=$((current + 1))
            printf '%s\n' "$line" >> "$tmpfile2"
            if [[ "$current" -eq "$anchor_line" ]]; then
                printf '%s\n' "$SESSION_LINE_CANONICAL" >> "$tmpfile2"
            fi
        done < "$tmpfile"
    else
        cp "$tmpfile" "$tmpfile2"
        printf '%s\n' "$SESSION_LINE_CANONICAL" >> "$tmpfile2"
    fi

    mv "$tmpfile2" "$tmpfile"
fi

preserve_attrs "$target" "$tmpfile"
mv "$tmpfile" "$target"

msg_parts=()
[[ $need_include -eq 1 ]] && msg_parts+=("${snippet}")
[[ $need_session -eq 1 ]] && msg_parts+=("session-line")
echo "info: $target updated (${msg_parts[*]})"
