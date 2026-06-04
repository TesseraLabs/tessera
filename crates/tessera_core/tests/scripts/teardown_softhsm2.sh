#!/usr/bin/env bash
#
# Teardown counterpart to setup_softhsm2.sh.  Removes the entire
# $TESTDIR (token store + softhsm2.conf).  Idempotent — running on a
# host that was never set up just prints a message.

set -euo pipefail

TESTDIR="${TESTDIR:-$HOME/.tessera_test/softhsm2}"

if [[ -d "$TESTDIR" ]]; then
    echo "removing softhsm2 testdir: $TESTDIR" >&2
    rm -rf "$TESTDIR"
    echo "done." >&2
else
    echo "no softhsm2 testdir at $TESTDIR — nothing to remove." >&2
fi
