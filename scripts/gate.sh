#!/usr/bin/env bash
# The full gate, with exit codes that actually propagate.
#
# WHY THIS FILE EXISTS
# Every gate run in this project was written as `python -m pytest -q | tail -2`.
# A pipeline's exit status is the status of its LAST command, so `tail` succeeding
# masked pytest failing. A commit went out with a failing test and the gate
# reported success, because the only thing checked was whether `tail` worked.
#
# Runs everything, reports each result, exits non-zero if any failed.
set -uo pipefail
cd "$(dirname "$0")/.."
status=0
run() {
    local name="$1"; shift
    if "$@" > /tmp/gate.$$.log 2>&1; then
        printf '  ok    %s\n' "$name"
    else
        printf '  FAIL  %s\n' "$name"
        tail -25 /tmp/gate.$$.log | sed 's/^/        /'
        status=1
    fi
    rm -f /tmp/gate.$$.log
}
run "ruff"   python -m ruff check src tests scripts
run "mypy"   python -m mypy src/qresp
run "pytest" python -m pytest tests -q
exit "$status"
