#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
UNIT="$HERE/tessera.service"
if ! command -v systemd-analyze >/dev/null; then
  echo "skip: systemd-analyze missing on this host"
  exit 0
fi
systemd-analyze verify "$UNIT"
