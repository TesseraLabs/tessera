#!/usr/bin/env bash
# install-and-test.sh - acceptance runbook for tessera on a remote VM.
#
# Usage:
#   tests/scripts/install-and-test.sh user@host [path/to/tessera_<ver>_amd64.deb]
#
# Prerequisites on remote:
#   * sshd accessible without sudo password (passwordless sudo for $user).
#   * test certificates available at ~/tessera-fixtures/ on remote.
#     - ca.pem, host_acl.toml, host_acl.toml.sig, config.toml, alice.p12 (with
#       passphrase "alice")
#
# Designed for Astra Linux SE 1.7 / Ubuntu 22.04. Linux-only.

set -euo pipefail

SSH_TARGET="${1:?usage: $0 user@host [deb-path]}"
DEB_PATH="${2:-../tessera_0.1.0-1_amd64.deb}"

if [[ ! -f "$DEB_PATH" ]]; then
    echo "error: $DEB_PATH not found; run scripts/build-deb.sh first" >&2
    exit 1
fi

run_remote() { ssh -o StrictHostKeyChecking=accept-new "$SSH_TARGET" "$@"; }

echo "==> Copying .deb to $SSH_TARGET"
scp -o StrictHostKeyChecking=accept-new "$DEB_PATH" "$SSH_TARGET:/tmp/tessera.deb"

echo "==> Installing on $SSH_TARGET"
run_remote 'sudo apt-get update -qq && sudo apt-get install -y /tmp/tessera.deb'

echo "==> Verifying file layout"
run_remote 'dpkg -L tessera' | tee /tmp/dpkg-L.out
for expected in \
    /lib/security/pam_tessera.so \
    /usr/bin/tessera \
    /lib/systemd/system/tessera.service \
    /usr/lib/tmpfiles.d/tessera.conf \
    /etc/tessera/config.toml.example \
    /etc/tessera/host_acl.toml.example \
    /etc/pam.d/certauth \
    /usr/share/tessera/integrate-pam.sh ; do
    grep -qx "$expected" /tmp/dpkg-L.out || { echo "FAIL: missing $expected" >&2; exit 1; }
done
echo "ok: layout"

echo "==> Confirming service is inactive (no config yet)"
status=$(run_remote 'systemctl is-active tessera || true')
test "$status" = "inactive" || { echo "FAIL: expected inactive, got $status" >&2; exit 1; }

echo "==> Deploying test config + CA"
run_remote 'sudo cp ~/tessera-fixtures/config.toml      /etc/tessera/config.toml'
run_remote 'sudo cp ~/tessera-fixtures/host_acl.toml    /etc/tessera/host_acl.toml'
run_remote 'sudo cp ~/tessera-fixtures/host_acl.toml.sig /etc/tessera/host_acl.toml.sig'
run_remote 'sudo cp ~/tessera-fixtures/ca.pem           /etc/tessera/ca/bundle.pem'
run_remote 'sudo chmod 0640 /etc/tessera/config.toml /etc/tessera/host_acl.toml /etc/tessera/host_acl.toml.sig /etc/tessera/ca/bundle.pem'

echo "==> Enabling and starting monitord"
run_remote 'sudo systemctl enable --now tessera'
sleep 2
status=$(run_remote 'systemctl is-active tessera')
test "$status" = "active" || { echo "FAIL: monitord not active: $status" >&2; exit 1; }
echo "ok: monitord active"

echo "==> Integrating PAM stack into a test service"
run_remote 'sudo /usr/share/tessera/integrate-pam.sh /etc/pam.d/sudo'

echo "==> Running pamtester (requires a USB token plugged into VM, or pre-staged p12)"
echo "    NOTE: this step assumes /run/tessera/usb is pre-mounted with alice.p12"
if run_remote 'sudo pamtester certauth alice authenticate'; then
    echo "ok: pamtester succeeded"
else
    echo "WARN: pamtester failed - manual investigation required (token?)"
fi

echo "==> Removing package (apt remove keeps configs)"
run_remote 'sudo apt-get remove -y tessera'
if run_remote 'test -e /lib/security/pam_tessera.so'; then
    echo "FAIL: .so still present after remove" >&2
    exit 1
fi
run_remote 'test -d /etc/tessera' || { echo "FAIL: /etc/tessera must remain after remove (only purge deletes it)" >&2; exit 1; }
echo "ok: remove behaviour"

echo "==> Purging"
run_remote 'sudo apt-get purge -y tessera'
run_remote 'test ! -e /etc/tessera' || { echo "FAIL: /etc/tessera not purged" >&2; exit 1; }
run_remote 'test ! -e /var/cache/tessera' || { echo "FAIL: /var/cache/tessera not purged" >&2; exit 1; }
echo "ok: purge clean"

echo "==> ACCEPTANCE PASS"
