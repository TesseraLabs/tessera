#!/usr/bin/env bash
# Public-core minimum only. Full platform/feature/package validation stays manual/local.
set -euo pipefail
[ "$#" = 0 ] || { echo "usage: bash scripts/check-pr-smoke.sh" >&2; exit 2; }
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" CARGO_TERM_COLOR=never
report="${TESSERA_SMOKE_REPORT:-$(mktemp -d "${TMPDIR:-/tmp}/tessera-core-smoke.XXXXXX")}"
mkdir -p "$report"
rm -f "$report/passed.txt"
cargo fmt --all -- --check
for spec in 'tessera_codes_contract|lib|' 'tessera_hashchain|test|chain' 'tessera_core|test|role_catalogue' 'tessera_core|test|client_auth_tbs' 'tessera_core|test|work_authorisation_v2'; do
    IFS='|' read -r package kind target <<< "$spec"
    args=(--lib); [ "$kind" = lib ] || args=(--test "$target")
    log="$report/$package-${target:-lib}.log"
    cargo test --locked --color never -p "$package" "${args[@]}" -- --color never 2>&1 | tee "$log"
    python3 - "$log" <<'PY'
import re, sys
from pathlib import Path
summaries = re.findall(r'^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;', Path(sys.argv[1]).read_text(), re.M)
if len(summaries) != 1 or int(summaries[0][0]) == 0 or summaries[0][1:] != ('0', '0'):
    raise SystemExit('smoke must execute a nonempty target with no failures/ignored tests')
PY
    echo "$package $kind $target" >> "$report/passed.txt"
done
echo 'Public core smoke passed: 5/5 targets; no platform/package conformance claimed.'
