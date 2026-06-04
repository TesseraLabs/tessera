#!/usr/bin/env bash
# finish-bootstrap.sh — flip tessera from bootstrap to production layout.
#
# Designed for cloned device images:
#   1. The golden image ships with `[host_identity].sources = ["override"]`
#      so the bootstrap cert (issued for host_id="installation") is valid
#      everywhere out of the box.
#   2. First boot on real hardware: the operator runs this script. It:
#        a. Rewrites config.toml atomically:
#           - `sources = ["override"]` → `sources = [<production list>]`
#           - `override = "..."`        → `# override = "..."` (commented)
#        b. Validates the new config (`tessera check`).
#        c. Restarts `tessera.service` and waits for it to become
#           active.
#        d. Dumps the per-host identity TSV to a USB stick (with retries)
#           or to `/var/lib/tessera/` as a fallback.
#   3. The operator carries the TSV to the CA admin to mint a per-host
#      cert.
#
# Idempotent: re-running on an already-flipped config detects "no
# override section, nothing to do" and exits 0.
#
# OFFLINE: this script never reaches the network. It only inspects local
# files, restarts a local service, and reads from a local USB stick.

set -euo pipefail
umask 0077

CONFIG=/etc/tessera/config.toml
HOSTNAME_VAL="$(hostname -s 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown)"
UTC_STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
DEFAULT_SOURCES='["dmi_board_serial", "machine_id"]'

# CLI flags
NON_INTERACTIVE=0
DO_RESTART=1
DO_DUMP=1
SOURCES_OVERRIDE=""

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Flip tessera config from bootstrap to production layout and dump the
per-host identity TSV. Must be run as root.

Options:
  --non-interactive       Skip the y/N confirmation (for ansible).
  --no-restart            Skip the systemctl restart (dry-run).
  --no-dump               Skip the host-id dump step.
  --sources LIST          Comma-separated production sources list
                          (default: "dmi_board_serial,machine_id").
                          Also accepted via env POST_INSTALL_SOURCES.
  -h, --help              Show this help.

Environment:
  POST_INSTALL_SOURCES    Comma-separated sources list (overridden by
                          --sources when both are present).
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --non-interactive) NON_INTERACTIVE=1 ;;
        --no-restart)      DO_RESTART=0 ;;
        --no-dump)         DO_DUMP=0 ;;
        --sources)         SOURCES_OVERRIDE="${2:-}"; shift ;;
        --sources=*)       SOURCES_OVERRIDE="${1#--sources=}" ;;
        -h|--help)         usage; exit 0 ;;
        *) echo "ERROR: unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

# Pick the sources list. Precedence: --sources > POST_INSTALL_SOURCES > default.
RAW_SOURCES="${SOURCES_OVERRIDE:-${POST_INSTALL_SOURCES:-}}"
if [ -n "$RAW_SOURCES" ]; then
    # Normalize: split on commas, trim, re-emit as JSON-ish TOML array.
    IFS=',' read -r -a _arr <<<"$RAW_SOURCES"
    _items=""
    for item in "${_arr[@]}"; do
        # trim leading/trailing whitespace + surrounding quotes
        trimmed="$(printf '%s' "$item" | sed -E 's/^[[:space:]]*"?//; s/"?[[:space:]]*$//')"
        [ -z "$trimmed" ] && continue
        if [ -z "$_items" ]; then
            _items="\"$trimmed\""
        else
            _items="$_items, \"$trimmed\""
        fi
    done
    if [ -z "$_items" ]; then
        echo "ERROR: --sources resolved to an empty list" >&2
        exit 2
    fi
    NEW_SOURCES="[$_items]"
else
    NEW_SOURCES="$DEFAULT_SOURCES"
fi

# Root check.
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: must be run as root (try: sudo $0)" >&2
    exit 1
fi

# Config presence.
if [ ! -f "$CONFIG" ]; then
    echo "ERROR: $CONFIG not found — is tessera installed?" >&2
    exit 1
fi

# Detect current layout.
# We look for an UNcommented `sources = ["override"]` line (allowing
# whitespace variations) and any `override = "..."` line.
has_override_sources() {
    grep -Eq '^[[:space:]]*sources[[:space:]]*=[[:space:]]*\[[[:space:]]*"override"[[:space:]]*\][[:space:]]*$' "$CONFIG"
}
has_override_value() {
    grep -Eq '^[[:space:]]*override[[:space:]]*=[[:space:]]*"' "$CONFIG"
}

if ! has_override_sources; then
    # Already flipped or never had bootstrap layout.
    if has_override_value; then
        echo "NOTE: 'sources = [\"override\"]' not found, but an uncommented 'override = \"...\"' line is present."
        echo "      Config does not look like bootstrap layout — nothing to flip."
    else
        echo "Config $CONFIG already in production layout (no bootstrap override section)."
        echo "Nothing to do."
    fi
    exit 0
fi

if ! has_override_value; then
    echo "ERROR: $CONFIG has 'sources = [\"override\"]' but no 'override = \"...\"' value." >&2
    echo "       Refusing to flip — config is not a coherent bootstrap layout." >&2
    exit 1
fi

# Show plan and confirm.
echo "==> Detected bootstrap layout in $CONFIG."
echo "    Planned changes:"
echo "      - sources = [\"override\"]   →   sources = $NEW_SOURCES"
echo "      - override = \"...\"          →   # override = \"...\"   (commented out)"
echo "    Backup: $CONFIG.bak.$UTC_STAMP"
echo

if [ "$NON_INTERACTIVE" -eq 0 ]; then
    printf 'Proceed? [yes/NO]: '
    read -r answer
    case "$answer" in
        yes|YES|Yes) : ;;
        *) echo "Aborted by operator."; exit 1 ;;
    esac
fi

# Backup (preserve attrs).
BACKUP="$CONFIG.bak.$UTC_STAMP"
cp -a "$CONFIG" "$BACKUP"
echo "==> Backed up to $BACKUP"

# Atomic rewrite via tmpfile in the same directory.
TMP="$(mktemp "$CONFIG.tmp.XXXXXX")"
# Make sure tmp gets cleaned up on early exit.
trap 'rm -f "$TMP"' EXIT

# sed: in-place edit on the COPY; never mutate the original directly.
# Replace `sources = ["override"]` line and comment `override = "..."` line.
sed -E \
    -e "s|^([[:space:]]*)sources[[:space:]]*=[[:space:]]*\\[[[:space:]]*\"override\"[[:space:]]*\\][[:space:]]*\$|\\1sources = $NEW_SOURCES|" \
    -e 's|^([[:space:]]*)(override[[:space:]]*=[[:space:]]*"[^"]*"[[:space:]]*)$|\1# \2  # disabled after first-boot flip|' \
    "$CONFIG" > "$TMP"

# Sanity-check the rewrite actually flipped both lines.
if grep -Eq '^[[:space:]]*sources[[:space:]]*=[[:space:]]*\[[[:space:]]*"override"[[:space:]]*\]' "$TMP"; then
    echo "ERROR: rewrite failed — bootstrap sources line still present in $TMP" >&2
    exit 1
fi
if grep -Eq '^[[:space:]]*override[[:space:]]*=[[:space:]]*"' "$TMP"; then
    echo "ERROR: rewrite failed — uncommented override value still present in $TMP" >&2
    exit 1
fi

# Preserve perms/ownership from the original.
chmod --reference="$CONFIG" "$TMP" 2>/dev/null || chmod 0644 "$TMP"
chown --reference="$CONFIG" "$TMP" 2>/dev/null || true

mv "$TMP" "$CONFIG"
trap - EXIT
echo "==> Rewrote $CONFIG."

# Validate.
echo "==> Validating new config (tessera check)..."
if ! tessera check --config "$CONFIG"; then
    echo "ERROR: tessera check failed on new config." >&2
    echo "       Restoring backup from $BACKUP" >&2
    cp -a "$BACKUP" "$CONFIG"
    echo "       Backup restored. Daemon NOT restarted." >&2
    exit 1
fi
echo "    Config validates."

# Restart daemon.
if [ "$DO_RESTART" -eq 1 ]; then
    echo "==> Restarting tessera.service..."
    systemctl restart tessera.service
    # Wait up to 30s for active state.
    WAITED=0
    while [ "$WAITED" -lt 30 ]; do
        state="$(systemctl is-active tessera.service 2>/dev/null || true)"
        if [ "$state" = "active" ]; then
            echo "    Daemon is active."
            break
        fi
        sleep 1
        WAITED=$((WAITED + 1))
    done
    if [ "$state" != "active" ]; then
        echo "ERROR: tessera.service did not become active within 30s (current: ${state:-unknown})." >&2
        echo "       Investigate with: journalctl -u tessera.service -n 100" >&2
        exit 1
    fi
else
    echo "==> Skipping daemon restart (--no-restart)."
fi

# Dump host-id.
DUMP_LOCATION=""
if [ "$DO_DUMP" -eq 1 ]; then
    echo "==> Dumping host identity. Plug in a USB stick now if you have one ready."
    # Try --usb with retries up to 60s, polling every 5s.
    WAITED=0
    USB_OK=0
    while [ "$WAITED" -lt 60 ]; do
        if tessera dump-host-id --usb 2>/tmp/tessera-dump.err; then
            USB_OK=1
            break
        fi
        # Don't spam: only print on the first attempt.
        if [ "$WAITED" -eq 0 ]; then
            echo "    No USB partition detected yet. Will retry every 5s for up to 60s."
        fi
        sleep 5
        WAITED=$((WAITED + 5))
    done

    if [ "$USB_OK" -eq 1 ]; then
        # `dump-host-id --usb` already prints `wrote <path> on <dev>` to stderr.
        DUMP_LOCATION="USB stick (see 'wrote ... on /dev/...' line above)"
        rm -f /tmp/tessera-dump.err
    else
        echo "    No USB stick after 60s; falling back to local file."
        mkdir -p /var/lib/tessera
        FALLBACK="/var/lib/tessera/host-ids-${HOSTNAME_VAL}-${UTC_STAMP}.tsv"
        if ! tessera dump-host-id --output "$FALLBACK"; then
            echo "ERROR: dump-host-id --output failed." >&2
            cat /tmp/tessera-dump.err >&2 2>/dev/null || true
            rm -f /tmp/tessera-dump.err
            exit 1
        fi
        rm -f /tmp/tessera-dump.err
        DUMP_LOCATION="$FALLBACK"
    fi
else
    echo "==> Skipping host-id dump (--no-dump)."
fi

# Final operator summary.
echo
echo "================================================================"
echo " tessera: bootstrap flip complete"
echo "================================================================"
echo "  config:        $CONFIG"
echo "  backup:        $BACKUP"
echo "  new sources:   $NEW_SOURCES"
echo "  daemon:        $([ "$DO_RESTART" -eq 1 ] && echo "restarted" || echo "NOT restarted (--no-restart)")"
if [ "$DO_DUMP" -eq 1 ]; then
    echo "  host-id dump:  $DUMP_LOCATION"
fi
echo
echo "Next steps:"
echo "  1. Carry the TSV dump to the CA admin."
echo "  2. CA admin reads the active_under_current_config=yes row and"
echo "     mints a per-host cert bound to its host_id_hash."
echo "  3. Bring the per-host cert/.p12 back on the same USB stick."
echo "================================================================"
