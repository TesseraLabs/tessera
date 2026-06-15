#!/usr/bin/env bash
# vagrant/scripts/test-roles.sh
#
# Phase 11 E2E — role-format (pam_cert_allowed_roles + role store) scenarios
# on the Astra SE 1.8.4 / Ubuntu 22.04 proxy VM.
#
# Validated end-to-end on Astra SE 1.8.4 (2026-06-15): all five scenarios
# (R1–R5) reproduce as asserted below. See vagrant/scripts/README-roles-e2e.md.
#
# Runs inside the VM after the role fixtures are generated on the build host
# (tests/fixtures/roles/gen-role-certs.sh) and uploaded, and the .so + CLI are
# installed (see vagrant/scripts/README-roles-e2e.md).
#
# How the credential reaches the module
# -------------------------------------
# The production PAM module discovers the leaf as a PKCS#12 at the configured
# pkcs12_path_pattern (default `certs/user.p12`) on a USB block device found
# via udev (ID_BUS=usb, block subsystem). The VM has no real USB, so we
# EMULATE one with a loopback FAT image + a udev rule that forces ID_BUS=usb
# on loop* devices (setup_usb below). The image carries certs/user.p12; per
# scenario we mount the loop, swap that one file for the scenario's p12, and
# unmount — the loop device stays attached and udev-announced throughout.
#
# Each scenario:
#   1. Drops a config.toml carrying a [roles] section (enforce + dir) into
#      /etc/tessera/config.toml.
#   2. Deploys the role store (serv.toml) into the configured roles dir.
#   3. Swaps certs/user.p12 on the loop USB for the scenario's leaf p12 so the
#      verified leaf carries the chosen pam_cert_allowed_roles list.
#   4. Drives the PAM AUTH phase through a DEDICATED throwaway service
#      (/etc/pam.d/tessera-roletest — never sshd/login/sudo) via pamtester,
#      with the login string `<user>+<role>` so the suffix parser selects the
#      role. The PIN (the p12 export password) is fed on stdin to the single
#      PAM_PROMPT_ECHO_OFF the module raises.
#   5. Asserts the expected pamtester exit code AND the expected role.audit
#      event in journald.
#
# Why AUTH (not open_session): role resolve + coverage runs in the auth phase
# (crates/pam_tessera/src/flow.rs::resolve_role_stage, invoked from the auth
# flow). A coverage/resolve failure denies AUTH. Group application
# (setgroups for service+wheel) is a LATER session/daemon phase and is NOT
# exercised by the open-build auth path — R1 therefore asserts the
# role_session_open audit event (which records role + version + ttl), not live
# group membership. See the R1 comment.
#
# monitord: the base config sets monitor_fail_mode="permissive", so the auth
# flow logs `monitord call failed (permissive mode, ignoring)` and proceeds —
# tessera.service does NOT have to be running for the auth phase.
#
# Scenarios (canonical 6.3 set, all PASSED on Astra SE 1.8.4 2026-06-15):
#   R1. ivanov+serv, leaf allowed_roles=[serv], serv in store, require
#                                       -> SUCCESS, role_session_open(serv).
#   R2. ivanov+serv, leaf allowed_roles=[oper] (serv absent), require
#                                       -> DENY, role_deny reason=not_covered.
#   R3. ivanov+serv, leaf allowed_roles=[serv], serv MISSING from store, require
#                                       -> DENY, role_deny reason=not_found.
#   R4. ivanov+serv, leaf MALFORMED allowed_roles ext, require
#                                       -> DENY, cert_allowed_roles_parse_failed
#                                          + role_deny reason=not_covered.
#   R5. ivanov+serv, roles.enforce=false (migration default)
#                                       -> SUCCESS, role selection skipped.
#
# Pre-conditions on VM:
#   - /lib/security/pam_tessera.so installed; `tessera` CLI on PATH.
#   - /etc/pam.d/tessera-roletest present (created by this script if missing).
#   - /etc/tessera/ca/bundle.pem = the CA that signed the role leaves
#     (tests/fixtures/roles/ca.crt.pem).
#   - Scenario leaf PKCS#12 bundles staged at $LEAVES/<name>.p12 (the export
#     password is $PIN; the .crt/.key PEMs are not needed at runtime).
#   - losetup / mkfs.vfat / udevadm available (util-linux + dosfstools + udev).
#   - tessera >= 0.4.0 with the role-format change compiled in.
#
# Manual run — VM access required. NOT wired into CI.
set -euo pipefail

readonly TEST_DIR=/etc/tessera/test
readonly LEAVES=$TEST_DIR/roles/leaves
readonly STORE_SRC=$TEST_DIR/roles/store
readonly ROLES_DIR=/var/lib/tessera/roles
readonly CFG=/etc/tessera/config.toml
readonly BASE_CFG=$TEST_DIR/roles/base-config.toml
readonly PAM_SERVICE=tessera-roletest
readonly PAM_FILE=/etc/pam.d/$PAM_SERVICE
readonly LOGIN_USER=ivanov          # canonical account; login string adds +role
readonly LOGIN_ROLE=serv

# PIN = the PKCS#12 export password baked into the staged leaf bundles. The
# module raises one PAM_PROMPT_ECHO_OFF for it; we feed it on stdin.
readonly PIN=${PIN:-123456}

# Loop-USB emulation knobs (override via env if the VM differs).
readonly USB_IMG=${USB_IMG:-/var/lib/tessera/usbtok.img}
readonly USB_MNT=${USB_MNT:-/mnt/tessera-roletest-usb}
readonly USB_RULE=${USB_RULE:-/etc/udev/rules.d/99-tessera-roletest.rules}
readonly P12_REL=${P12_REL:-certs/user.p12}   # = pkcs12_path_pattern (default)
LOOP_DEV=""                                    # set by setup_usb

# pam_cert_allowed_roles extension OID — locked, see
# crates/tessera_core/src/x509/oids.rs (ALLOWED_ROLES_OID).
readonly ALLOWED_ROLES_OID=2.25.185305973969816596290730578528098241367

failures=0
log()  { printf '[test-roles] %s\n' "$*" >&2; }
ok()   { printf '[test-roles] PASS: %s\n' "$*" >&2; }
miss() { printf '[test-roles] FAIL: %s\n' "$*" >&2; failures=$((failures + 1)); }

# ---------------------------------------------------------------------------
# USB emulation (loopback FAT image announced as ID_BUS=usb via udev)
# ---------------------------------------------------------------------------

setup_usb() {
    # Provision ONCE: build a 16 MiB FAT image seeded with the R1 leaf at
    # certs/user.p12, install a udev rule that forces ID_BUS=usb on loop*
    # block devices, attach the image via losetup and announce it so the
    # module's USB discovery path enumerates it.
    command -v losetup    >/dev/null || { log "losetup missing (util-linux)"; exit 2; }
    command -v mkfs.vfat  >/dev/null || { log "mkfs.vfat missing (dosfstools)"; exit 2; }
    command -v udevadm    >/dev/null || { log "udevadm missing (udev)"; exit 2; }

    log "building FAT image $USB_IMG (16 MiB)"
    install -d -m 0755 "$(dirname "$USB_IMG")"
    dd if=/dev/zero of="$USB_IMG" bs=1M count=16 status=none
    mkfs.vfat "$USB_IMG" >/dev/null

    # Seed the image with the default (R1) leaf at certs/user.p12.
    install -d -m 0755 "$USB_MNT"
    mount -o loop "$USB_IMG" "$USB_MNT"
    install -d -m 0755 "$USB_MNT/$(dirname "$P12_REL")"
    install -m 0644 "$LEAVES/role-serv.p12" "$USB_MNT/$P12_REL"
    umount "$USB_MNT"

    log "installing udev rule $USB_RULE (force ID_BUS=usb on loop*)"
    cat > "$USB_RULE" <<'EOF'
# Throwaway rule for the role-format E2E (test-roles.sh): make the loopback
# token look like a real USB stick to the module's udev discovery path.
SUBSYSTEM=="block", KERNEL=="loop*", ENV{ID_BUS}="usb", ENV{ID_VENDOR_ID}="dead", ENV{ID_MODEL_ID}="beef", ENV{ID_SERIAL_SHORT}="TESSERATEST01"
EOF
    udevadm control --reload-rules

    log "attaching loop device + announcing add event"
    LOOP_DEV=$(losetup --find --show "$USB_IMG")
    udevadm trigger --action=add "$LOOP_DEV"
    udevadm settle

    # Verify the emulation took: ID_BUS=usb and a vfat filesystem.
    if udevadm info --query=property "$LOOP_DEV" | grep -q '^ID_BUS=usb$' \
       && udevadm info --query=property "$LOOP_DEV" | grep -q '^ID_FS_TYPE=vfat$'; then
        log "loop USB ready: $LOOP_DEV (ID_BUS=usb, vfat)"
    else
        log "loop USB emulation did NOT take effect on $LOOP_DEV:"
        udevadm info --query=property "$LOOP_DEV" | grep -E '^ID_BUS=|^ID_FS_TYPE=' >&2 || true
        exit 2
    fi
}

teardown_usb() {
    # Best-effort cleanup; never fail the run on teardown.
    umount "$USB_MNT" 2>/dev/null || true
    if [[ -n "$LOOP_DEV" ]]; then
        losetup -d "$LOOP_DEV" 2>/dev/null || true
    else
        # Detach any loop still backed by our image (e.g. after a crash).
        losetup -j "$USB_IMG" 2>/dev/null | cut -d: -f1 | while read -r d; do
            [[ -n "$d" ]] && losetup -d "$d" 2>/dev/null || true
        done
    fi
    rm -f "$USB_RULE"
    udevadm control --reload-rules 2>/dev/null || true
    rmdir "$USB_MNT" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Setup helpers
# ---------------------------------------------------------------------------

ensure_pam_service() {
    # A dedicated throwaway service that runs ONLY the tessera auth module —
    # we never touch sshd/login/sudo. `config=` points the module at $CFG.
    if [[ ! -f "$PAM_FILE" ]]; then
        log "creating $PAM_FILE (throwaway role-test service)"
        cat > "$PAM_FILE" <<EOF
# Throwaway PAM service for role-format E2E (test-roles.sh). Auth-only.
auth     required   pam_tessera.so config=$CFG
account  required   pam_permit.so
EOF
        chmod 0644 "$PAM_FILE"
    fi
}

write_config() {
    # $1 = enforce mode ("false" | "warn" | "require")
    local enforce=$1
    if [[ ! -f "$BASE_CFG" ]]; then
        log "missing base config $BASE_CFG (needed for the USB/p12 + trust plumbing)"
        exit 2
    fi
    # Start from the working base config, append the [roles] section.
    # The base must NOT already contain a [roles] section.
    {
        cat "$BASE_CFG"
        printf '\n[roles]\n'
        printf 'enforce = "%s"\n' "$enforce"
        printf 'dir = "%s"\n' "$ROLES_DIR"
        printf 'default_session_ttl_seconds = 43200\n'
    } > "$CFG"
    install -d -m 0755 -o root -g root "$ROLES_DIR"
    chmod 0640 "$CFG"
    chown root:tessera "$CFG" 2>/dev/null || chown root:root "$CFG"
}

deploy_store_with_serv() {
    install -d -m 0755 -o root -g root "$ROLES_DIR"
    rm -f "$ROLES_DIR"/*.toml
    install -m 0644 -o root -g root "$STORE_SRC/serv.toml" "$ROLES_DIR/serv.toml"
    # Sanity: the CLI must agree the slice loads (lenient list).
    if ! tessera role list --dir "$ROLES_DIR" --os linux | grep -q '^serv	'; then
        log "WARN: 'tessera role list' did not report serv — store deploy may be wrong"
    fi
}

deploy_store_empty() {
    install -d -m 0755 -o root -g root "$ROLES_DIR"
    rm -f "$ROLES_DIR"/*.toml
}

stage_leaf() {
    # $1 = leaf base name under $LEAVES (e.g. role-serv). Swaps the scenario's
    # p12 in for certs/user.p12 on the attached loop USB. The loop device stays
    # attached + udev-announced; only the file on the FAT filesystem changes, so
    # the module re-reads the new leaf on the next auth without re-triggering
    # udev. Idempotent.
    local name=$1
    local src="$LEAVES/$name.p12"
    if [[ ! -f "$src" ]]; then
        log "missing leaf bundle $src (run gen-role-certs.sh + upload .p12)"
        return 1
    fi
    [[ -n "$LOOP_DEV" ]] || { log "loop USB not attached (setup_usb not run)"; return 1; }

    log "staging leaf $name -> $P12_REL on $LOOP_DEV"
    mount "$LOOP_DEV" "$USB_MNT"
    install -d -m 0755 "$USB_MNT/$(dirname "$P12_REL")"
    install -m 0644 "$src" "$USB_MNT/$P12_REL"
    sync
    umount "$USB_MNT"
    return 0
}

journal_since() {
    date -u -d "30 sec ago" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
        || date -u -v-30S +%Y-%m-%dT%H:%M:%SZ
}

expect_event() {
    # $1 = event name (role.audit `event` field), $2 = since timestamp.
    # The PAM module logs via syslog auth facility (ident pam_tessera) using
    # tracing's compact formatter, so the journal line carries event=<name>.
    # Match both quoted and unquoted renderings to be formatter-robust.
    local ev=$1 since=$2
    journalctl --since "$since" -t pam_tessera --no-pager 2>/dev/null \
        | grep -Eq "event=\"?${ev}\"?"
}

expect_reason() {
    # $1 = reason value, $2 = since timestamp. Pairs with a role_deny event.
    local reason=$1 since=$2
    journalctl --since "$since" -t pam_tessera --no-pager 2>/dev/null \
        | grep -Eq "reason=\"?${reason}\"?"
}

run_auth() {
    # Drive the AUTH phase with the `<user>+<role>` login string, feeding the
    # PIN on stdin to the single PAM_PROMPT_ECHO_OFF the module raises. Returns
    # pamtester's exit status; stderr captured to $1.
    local errfile=$1
    printf '%s\n' "$PIN" \
        | pamtester "$PAM_SERVICE" "${LOGIN_USER}+${LOGIN_ROLE}" authenticate 2>"$errfile"
}

# ---------------------------------------------------------------------------
# R1 — happy path: allowed_roles=[serv], serv in store, require -> SUCCESS.
# ---------------------------------------------------------------------------
r1_serv_covered_succeeds() {
    local tag=R1
    write_config require
    deploy_store_with_serv
    stage_leaf role-serv || { miss "[$tag] could not stage role-serv leaf"; return; }
    local since; since=$(journal_since)
    if run_auth /tmp/roles.r1.err; then
        ok "[$tag] auth succeeded for ivanov+serv"
    else
        miss "[$tag] auth failed: $(cat /tmp/roles.r1.err 2>/dev/null)"
        return
    fi
    if expect_event role_session_open "$since"; then
        ok "[$tag] role_session_open audit observed (role+version+ttl recorded)"
    else
        miss "[$tag] role_session_open audit missing"
    fi
    # NOTE: role_session_open records ttl=14400 — the store's
    # session.max_ttl_seconds caps the config default_session_ttl_seconds
    # (43200). Group application (supplementary groups service+wheel) is a
    # later session/daemon phase, not the auth path. Asserting live `id ivanov`
    # group membership requires the session phase (drive `open_session` against
    # a session-aware service) — out of scope for this auth-phase harness.
}

# ---------------------------------------------------------------------------
# R2 — allowed_roles=[oper] (serv NOT listed) -> DENY, not_covered.
# ---------------------------------------------------------------------------
r2_serv_not_covered_denies() {
    local tag=R2
    write_config require
    deploy_store_with_serv
    stage_leaf role-oper || { miss "[$tag] could not stage role-oper leaf"; return; }
    local since; since=$(journal_since)
    if run_auth /tmp/roles.r2.err; then
        miss "[$tag] expected DENY, auth succeeded"
    else
        ok "[$tag] auth denied as expected (serv not in cert allowed_roles)"
    fi
    if expect_event role_deny "$since" && expect_reason not_covered "$since"; then
        ok "[$tag] role_deny reason=not_covered observed"
    else
        miss "[$tag] role_deny/not_covered audit missing"
    fi
}

# ---------------------------------------------------------------------------
# R3 — serv MISSING from store, require -> DENY, not_found.
# ---------------------------------------------------------------------------
r3_serv_not_in_store_denies() {
    local tag=R3
    write_config require
    deploy_store_empty        # store has no serv.toml
    stage_leaf role-serv || { miss "[$tag] could not stage role-serv leaf"; return; }
    local since; since=$(journal_since)
    if run_auth /tmp/roles.r3.err; then
        miss "[$tag] expected DENY, auth succeeded"
    else
        ok "[$tag] auth denied as expected (serv not in store)"
    fi
    if expect_event role_deny "$since" && expect_reason not_found "$since"; then
        ok "[$tag] role_deny reason=not_found observed"
    else
        miss "[$tag] role_deny/not_found audit missing"
    fi
}

# ---------------------------------------------------------------------------
# R4 — MALFORMED allowed_roles ext, require -> DENY + parse-failed audit.
# ---------------------------------------------------------------------------
r4_malformed_ext_denies() {
    local tag=R4
    write_config require
    deploy_store_with_serv
    stage_leaf role-malformed || { miss "[$tag] could not stage role-malformed leaf"; return; }
    local since; since=$(journal_since)
    if run_auth /tmp/roles.r4.err; then
        miss "[$tag] expected DENY, auth succeeded"
    else
        ok "[$tag] auth denied as expected (malformed ext = no roles, fail-closed)"
    fi
    if expect_event cert_allowed_roles_parse_failed "$since"; then
        ok "[$tag] cert_allowed_roles_parse_failed audit observed"
    else
        miss "[$tag] cert_allowed_roles_parse_failed audit missing"
    fi
    # Malformed ext is treated as "no roles" -> coverage fails -> not_covered.
    if expect_event role_deny "$since" && expect_reason not_covered "$since"; then
        ok "[$tag] role_deny reason=not_covered observed"
    else
        miss "[$tag] role_deny/not_covered audit missing"
    fi
}

# ---------------------------------------------------------------------------
# R5 — migration default: enforce=false -> SUCCESS, role selection skipped.
# ---------------------------------------------------------------------------
r5_enforce_false_skips() {
    local tag=R5
    write_config false
    deploy_store_with_serv     # store present but must be ignored under false
    stage_leaf role-oper || { miss "[$tag] could not stage leaf"; return; }
    local since; since=$(journal_since)
    if run_auth /tmp/roles.r5.err; then
        ok "[$tag] auth succeeded with enforce=false (pre-role behaviour)"
    else
        miss "[$tag] auth failed under enforce=false: $(cat /tmp/roles.r5.err 2>/dev/null)"
        return
    fi
    # Under Disabled the resolve/coverage stage returns early — no role_deny
    # and no role_session_open should appear for this attempt.
    if expect_event role_deny "$since"; then
        miss "[$tag] unexpected role_deny audit under enforce=false"
    else
        ok "[$tag] no role_deny under enforce=false (selection skipped)"
    fi
    if expect_event role_session_open "$since"; then
        miss "[$tag] unexpected role_session_open under enforce=false"
    else
        ok "[$tag] no role_session_open under enforce=false (selection skipped)"
    fi
}

main() {
    [[ $EUID -eq 0 ]] || { log "must run as root (PAM auth + /etc writes + losetup)"; exit 2; }
    [[ -d "$LEAVES"    ]] || { log "missing $LEAVES (run gen-role-certs.sh + upload)"; exit 2; }
    [[ -d "$STORE_SRC" ]] || { log "missing $STORE_SRC (upload tests/fixtures/roles/store/)"; exit 2; }
    command -v pamtester >/dev/null || { log "pamtester not installed"; exit 2; }
    command -v tessera   >/dev/null || { log "tessera CLI not on PATH"; exit 2; }

    # Clean up the loop USB + udev rule on any exit. Never touches sshd/login.
    trap teardown_usb EXIT

    ensure_pam_service
    setup_usb

    log "ALLOWED_ROLES_OID = $ALLOWED_ROLES_OID"
    log "PAM service       = $PAM_SERVICE ($PAM_FILE)"
    log "login string      = ${LOGIN_USER}+${LOGIN_ROLE}"
    log "loop USB          = $LOOP_DEV (p12 at $P12_REL, PIN via stdin)"

    r1_serv_covered_succeeds
    r2_serv_not_covered_denies
    r3_serv_not_in_store_denies
    r4_malformed_ext_denies
    r5_enforce_false_skips

    if (( failures > 0 )); then
        log "$failures scenarios failed"
        exit 1
    fi
    log "all role-format scenarios passed"
}

main "$@"
