#!/usr/bin/env bash
# Test harness for dist/scripts/integrate-pam.sh.
# Builds fake /etc/pam.d/* files in $TMPDIR and verifies:
#   - @include is added once, in the right position;
#   - session required pam_tessera.so is added AFTER @include common-session;
#   - both lines are idempotent;
#   - --unintegrate removes both, idempotently;
#   - Astra SE placement: include after pam_parsec_mac, session after common-session;
#   - Debian/Astra sudo-style stacks: session-line lands after
#     @include common-session-noninteractive, and @include tessera* lands
#     before @include common-auth (not at EOF) when there is no literal
#     `auth` line at all.

set -euo pipefail

HELPER="$(cd "$(dirname "$0")/../.." && pwd)/dist/scripts/integrate-pam.sh"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/integrate-pam-test.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

# Helper: return line number (1-based) of the first match, or empty.
line_of() {
    local re="$1" file="$2"
    grep -nE "$re" "$file" | head -1 | cut -d: -f1
}

# -----------------------------------------------------------------------------
# Case 1: simple sudo stack (no common-session, no parsec_mac).
# -----------------------------------------------------------------------------
cat > "$WORK/sudo" <<'EOF'
auth       required   pam_unix.so
account    required   pam_unix.so
session    required   pam_unix.so
EOF

"$HELPER" "$WORK/sudo"
ls "$WORK"/sudo.bak.* >/dev/null 2>&1 || { echo "FAIL: no backup created" >&2; exit 1; }
grep -q '^@include tessera$' "$WORK/sudo" \
    || { echo "FAIL: @include not added" >&2; exit 1; }
grep -qE '^session[[:space:]]+required[[:space:]]+pam_tessera\.so' "$WORK/sudo" \
    || { echo "FAIL: session line not added" >&2; exit 1; }

# Session line must come AFTER the existing pam_unix session line
# (anchor = "last session-phase line" when no common-session).
unix_ses=$(line_of '^session[[:space:]]+required[[:space:]]+pam_unix\.so' "$WORK/sudo")
cert_ses=$(line_of '^session[[:space:]]+required[[:space:]]+pam_tessera\.so' "$WORK/sudo")
test -n "$unix_ses" && test -n "$cert_ses" && [ "$cert_ses" -gt "$unix_ses" ] \
    || { echo "FAIL: tessera session ($cert_ses) must come after pam_unix session ($unix_ses)" >&2; exit 1; }

SHA_AFTER_FIRST=$(shasum -a 256 "$WORK/sudo" | awk '{print $1}')

# Second run: must be no-op (already integrated). No new backup, no SHA change.
BACKUPS_BEFORE=$(find "$WORK" -maxdepth 1 -name 'sudo.bak.*' | wc -l | tr -d ' ')
"$HELPER" "$WORK/sudo"
BACKUPS_AFTER=$(find "$WORK" -maxdepth 1 -name 'sudo.bak.*' | wc -l | tr -d ' ')
test "$BACKUPS_BEFORE" = "$BACKUPS_AFTER" \
    || { echo "FAIL: idempotence — extra backup" >&2; exit 1; }
SHA_AFTER_SECOND=$(shasum -a 256 "$WORK/sudo" | awk '{print $1}')
test "$SHA_AFTER_FIRST" = "$SHA_AFTER_SECOND" \
    || { echo "FAIL: idempotence — file changed" >&2; exit 1; }

# @include lands BEFORE the first auth line in this (no-parsec) shape.
first_match=$(grep -nE '^(auth[[:space:]]|@include tessera$)' "$WORK/sudo" | head -1 | awk -F: '{print $2}')
test "$first_match" = "@include tessera" \
    || { echo "FAIL: @include not before first auth: $first_match" >&2; exit 1; }

echo "ok: integrate-pam.sh handles idempotence + backups + session-line placement"

# -----------------------------------------------------------------------------
# Case 2: --unintegrate round-trip removes BOTH lines.
# -----------------------------------------------------------------------------
"$HELPER" --unintegrate "$WORK/sudo"
if grep -qE '^@include tessera(-optional|-only)?$' "$WORK/sudo"; then
    echo "FAIL: --unintegrate did not remove @include" >&2
    exit 1
fi
if grep -qE '^[[:space:]]*session[[:space:]]+required[[:space:]]+pam_tessera\.so' "$WORK/sudo"; then
    echo "FAIL: --unintegrate did not remove session line" >&2
    exit 1
fi

# Second --unintegrate: no-op.
SHA_AFTER_UNINT=$(shasum -a 256 "$WORK/sudo" | awk '{print $1}')
"$HELPER" --unintegrate "$WORK/sudo"
SHA_AFTER_UNINT2=$(shasum -a 256 "$WORK/sudo" | awk '{print $1}')
test "$SHA_AFTER_UNINT" = "$SHA_AFTER_UNINT2" \
    || { echo "FAIL: --unintegrate not idempotent" >&2; exit 1; }

# Re-integrate optional flavour, then unintegrate.
"$HELPER" --optional "$WORK/sudo"
grep -q '^@include tessera-optional$' "$WORK/sudo" \
    || { echo "FAIL: --optional did not add line" >&2; exit 1; }
grep -qE '^[[:space:]]*session[[:space:]]+required[[:space:]]+pam_tessera\.so' "$WORK/sudo" \
    || { echo "FAIL: --optional did not add session line" >&2; exit 1; }
"$HELPER" --unintegrate "$WORK/sudo"
if grep -qE '^@include tessera(-optional|-only)?$' "$WORK/sudo"; then
    echo "FAIL: --unintegrate did not remove optional line" >&2; exit 1
fi
if grep -qE '^[[:space:]]*session[[:space:]]+required[[:space:]]+pam_tessera\.so' "$WORK/sudo"; then
    echo "FAIL: --unintegrate did not remove optional session line" >&2; exit 1
fi

# --unintegrate on a missing file is a no-op (exit 0).
"$HELPER" --unintegrate "$WORK/nonexistent" \
    || { echo "FAIL: --unintegrate on missing file should be no-op" >&2; exit 1; }

echo "ok: integrate-pam.sh --unintegrate strips @include + session-line"

# -----------------------------------------------------------------------------
# Case 3: Astra SE placement — @include after pam_parsec_mac,
#         session-line after @include common-session.
# -----------------------------------------------------------------------------
cat > "$WORK/login_astra" <<'EOF'
auth required pam_parsec_mac.so
auth requisite pam_nologin.so
@include common-auth
account required pam_parsec_mac.so
@include common-account
@include common-session
session required pam_parsec_cap.so
session required pam_parsec_mac.so
EOF
"$HELPER" --mode=cert-only "$WORK/login_astra"

parsec_auth=$(line_of '^auth[[:space:]]+.*pam_parsec_mac\.so' "$WORK/login_astra")
include=$(line_of '^@include tessera-only$' "$WORK/login_astra")
common_ses=$(line_of '^@include[[:space:]]+common-session([[:space:]]|$)' "$WORK/login_astra")
cert_ses=$(line_of '^session[[:space:]]+required[[:space:]]+pam_tessera\.so' "$WORK/login_astra")

test -n "$parsec_auth" && test -n "$include" && [ "$include" -gt "$parsec_auth" ] \
    || { echo "FAIL: @include ($include) must come AFTER pam_parsec_mac ($parsec_auth)" >&2; exit 1; }
test -n "$common_ses" && test -n "$cert_ses" && [ "$cert_ses" -gt "$common_ses" ] \
    || { echo "FAIL: session line ($cert_ses) must come AFTER @include common-session ($common_ses)" >&2; exit 1; }

echo "ok: integrate-pam.sh inserts after pam_parsec_mac AND after common-session on Astra SE stacks"

# -----------------------------------------------------------------------------
# Case 4: common-session-noninteractive (real /etc/pam.d/sudo shape on
#         Astra Linux / Debian-family systems) — the anchor-1 regex must
#         match this sibling include too, not just plain common-session,
#         so the session-line lands AFTER it (not after the earlier
#         pam_limits.so session line).
# -----------------------------------------------------------------------------
cat > "$WORK/sudo_noninteractive" <<'EOF'
account requisite pam_sudo.so

# Set up user limits from /etc/security/limits.conf.
session    required   pam_limits.so

@include common-auth
@include common-account
@include common-session-noninteractive
EOF
"$HELPER" --mode=cert-only "$WORK/sudo_noninteractive"

limits_ses=$(line_of '^session[[:space:]]+required[[:space:]]+pam_limits\.so' "$WORK/sudo_noninteractive")
common_ses_ni=$(line_of '^@include[[:space:]]+common-session-noninteractive$' "$WORK/sudo_noninteractive")
cert_ses=$(line_of '^session[[:space:]]+required[[:space:]]+pam_tessera\.so' "$WORK/sudo_noninteractive")

test -n "$limits_ses" && test -n "$common_ses_ni" && test -n "$cert_ses" \
    || { echo "FAIL: expected anchor lines missing in sudo_noninteractive fixture" >&2; exit 1; }
[ "$common_ses_ni" -gt "$limits_ses" ] \
    || { echo "FAIL: fixture invariant broken — common-session-noninteractive ($common_ses_ni) must come after pam_limits ($limits_ses)" >&2; exit 1; }
test "$cert_ses" -gt "$common_ses_ni" \
    || { echo "FAIL: session line ($cert_ses) must come AFTER @include common-session-noninteractive ($common_ses_ni)" >&2; exit 1; }

echo "ok: integrate-pam.sh inserts after @include common-session-noninteractive (Astra/Debian sudo stack)"

# -----------------------------------------------------------------------------
# Case 5: Debian/Astra sudo-style stack with NO literal `auth` line at all —
#         the entire auth phase is delivered via `@include common-auth`.
#         The before-first-auth anchor must recognize that include, so
#         `@include tessera-only` lands BEFORE it, not after common-auth
#         (which would let pam_unix prompt for a password first) and not
#         appended at EOF (which would land it after the session-line too).
# -----------------------------------------------------------------------------
cat > "$WORK/sudo_authinclude" <<'EOF'
#%PAM-1.0

account requisite pam_sudo.so

# Set up user limits from /etc/security/limits.conf.
session    required   pam_limits.so

@include common-auth
@include common-account
@include common-session-noninteractive
EOF
"$HELPER" --mode=cert-only "$WORK/sudo_authinclude"

include_ln=$(line_of '^@include[[:space:]]+tessera-only$' "$WORK/sudo_authinclude")
common_auth_ln=$(line_of '^@include[[:space:]]+common-auth$' "$WORK/sudo_authinclude")
total_lines=$(wc -l < "$WORK/sudo_authinclude" | tr -d ' ')

test -n "$include_ln" && test -n "$common_auth_ln" \
    || { echo "FAIL: expected anchor lines missing in sudo_authinclude fixture" >&2; exit 1; }
test "$include_ln" -lt "$common_auth_ln" \
    || { echo "FAIL: @include tessera-only ($include_ln) must come BEFORE @include common-auth ($common_auth_ln)" >&2; exit 1; }
test "$include_ln" -ne "$total_lines" \
    || { echo "FAIL: @include tessera-only landed at EOF (line $include_ln of $total_lines) instead of before common-auth" >&2; exit 1; }

echo "ok: integrate-pam.sh inserts @include before @include common-auth when no literal auth line exists"

# -----------------------------------------------------------------------------
# Case 6: mode switch on an already-integrated file must be EXCLUSIVE — the
#         old @include tessera* variant must be replaced, not left alongside
#         the newly requested one (M1 regression: --mode=2fa then
#         --mode=cert-only on the same file used to leave BOTH
#         `@include tessera` and `@include tessera-only` present, silently
#         defeating cert-only's lockout semantics).
# -----------------------------------------------------------------------------
cat > "$WORK/switch" <<'EOF'
auth       required   pam_unix.so
account    required   pam_unix.so
session    required   pam_unix.so
EOF
"$HELPER" --mode=2fa "$WORK/switch"
grep -q '^@include tessera$' "$WORK/switch" \
    || { echo "FAIL: --mode=2fa did not add @include tessera" >&2; exit 1; }

"$HELPER" --mode=cert-only "$WORK/switch"

family_count=$(grep -cE '^[[:space:]]*@include[[:space:]]+tessera(-optional|-only)?[[:space:]]*$' "$WORK/switch")
test "$family_count" -eq 1 \
    || { echo "FAIL: expected exactly one @include tessera* line after mode switch, found $family_count" >&2; exit 1; }
grep -q '^@include tessera-only$' "$WORK/switch" \
    || { echo "FAIL: @include tessera-only missing after switch to --mode=cert-only" >&2; exit 1; }
if grep -qx '@include tessera' "$WORK/switch"; then
    echo "FAIL: stale @include tessera (2fa) line survived the switch to cert-only" >&2
    exit 1
fi
grep -qE '^session[[:space:]]+required[[:space:]]+pam_tessera\.so' "$WORK/switch" \
    || { echo "FAIL: session line lost/broken across mode switch" >&2; exit 1; }

echo "ok: integrate-pam.sh switches from --mode=2fa to --mode=cert-only exclusively (no duplicate @include lines)"

# Reverse direction: cert-only -> 2fa must be equally exclusive (not
# directionally asymmetric).
cat > "$WORK/switch_reverse" <<'EOF'
auth       required   pam_unix.so
account    required   pam_unix.so
session    required   pam_unix.so
EOF
"$HELPER" --mode=cert-only "$WORK/switch_reverse"
grep -q '^@include tessera-only$' "$WORK/switch_reverse" \
    || { echo "FAIL: --mode=cert-only did not add @include tessera-only" >&2; exit 1; }

"$HELPER" --mode=2fa "$WORK/switch_reverse"

family_count_rev=$(grep -cE '^[[:space:]]*@include[[:space:]]+tessera(-optional|-only)?[[:space:]]*$' "$WORK/switch_reverse")
test "$family_count_rev" -eq 1 \
    || { echo "FAIL: expected exactly one @include tessera* line after reverse mode switch, found $family_count_rev" >&2; exit 1; }
grep -q '^@include tessera$' "$WORK/switch_reverse" \
    || { echo "FAIL: @include tessera missing after switch to --mode=2fa" >&2; exit 1; }
if grep -qx '@include tessera-only' "$WORK/switch_reverse"; then
    echo "FAIL: stale @include tessera-only (cert-only) line survived the switch to 2fa" >&2
    exit 1
fi
grep -qE '^session[[:space:]]+required[[:space:]]+pam_tessera\.so' "$WORK/switch_reverse" \
    || { echo "FAIL: session line lost/broken across reverse mode switch" >&2; exit 1; }

echo "ok: integrate-pam.sh switches from --mode=cert-only to --mode=2fa exclusively (no duplicate @include lines, not directionally asymmetric)"
