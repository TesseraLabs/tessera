#!/usr/bin/env bash
# vagrant/scripts/bench-mac.sh
#
# Phase 10.2 — Performance bench for the MAC integrity hot path.
#
# Measures the wall-clock overhead of:
#   * IntegrityLabel DER decode (per cert)
#   * MacOrchestrator.compute_effective_label() (per open_session)
#   * libpdp ipdp_set_label_*() on /run/tessera/sessions.json
#
# Runs N=1000 open_session/close_session pairs back-to-back via the
# test helper binary, splits journald entries by F_event, and prints
# p50 / p95 / p99 latency.
#
# Run manually on a strict Astra VM; CI captures only a smoke iteration.
set -euo pipefail

readonly N=${BENCH_N:-1000}
readonly TAG=bench-mac
readonly OUT=${BENCH_OUT:-/var/log/tessera/bench-mac.csv}

log() { printf '[%s] %s\n' "$TAG" "$*" >&2; }

require_helper() {
    if ! command -v tessera-test >/dev/null 2>&1; then
        log "tessera-test helper binary missing — bench requires it"
        log "TODO(helper-binary): build crates/tessera_cli with --features bench-helper"
        exit 2
    fi
}

main() {
    require_helper
    mkdir -p "$(dirname "$OUT")"
    : > "$OUT"
    echo "iteration,total_us,decode_us,orchestrator_us,libpdp_us" >> "$OUT"

    local i
    for ((i = 0; i < N; i++)); do
        tessera-test bench-open-close --csv >> "$OUT" || {
            log "iteration $i failed"
            exit 1
        }
    done

    log "wrote $N samples to $OUT"
    # Quick summary — assumes total_us is column 2.
    awk -F, 'NR>1 {a[NR-1]=$2} END {
        n=NR-1; asort(a);
        printf "p50=%.0fus  p95=%.0fus  p99=%.0fus  n=%d\n",
            a[int(n*0.50)], a[int(n*0.95)], a[int(n*0.99)], n
    }' "$OUT"
}

main "$@"
