"""The benchmark write-up must agree with the JSON that produced it.

This runs `scripts/bench/check_docs.py` under pytest so the agreement is
re-established on every test run rather than at the moment someone remembers to
invoke the script.

That distinction is not hypothetical here. The FIPS 204 conformance check lived
in a standalone script for months, was run once, and was cited thereafter --
during which time it silently validated round-3 Dilithium rather than ML-DSA.
Evidence that is not re-checked is not evidence; it is a claim with a
provenance story.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "scripts" / "bench" / "check_docs.py"
RESULTS = ROOT / "results"


def _run() -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CHECKER)],
        capture_output=True, text=True, cwd=ROOT,
    )


@pytest.mark.skipif(
    not (RESULTS / "bench.json").exists() or not (RESULTS / "randomness.json").exists(),
    reason="benchmark results not present; run scripts/bench/latency.py first",
)
def test_the_document_matches_the_recorded_run() -> None:
    result = _run()
    assert result.returncode == 0, (
        "docs/BENCHMARKS.md no longer matches results/.\n"
        "Either re-run the benchmarks and update the document, or fix the "
        "figure that drifted. Do not adjust the tolerance.\n\n" + result.stdout
    )


@pytest.mark.skipif(not (RESULTS / "bench.json").exists(), reason="no results")
def test_the_checker_actually_checks_something() -> None:
    """A checker that verifies nothing exits 0 just as loudly as one that passes.

    `check_docs.py` distinguishes the two -- exit 2 means 'could not check' --
    but that only helps if the count of checked figures is non-trivial. If a
    refactor of BENCHMARKS.md renamed every table header, every lookup would
    return None, every check would be skipped, and the suite would go green on
    an empty verification.
    """
    result = _run()
    checked = [line for line in result.stdout.splitlines() if "figures checked" in line]
    assert checked, f"checker produced no summary line:\n{result.stdout}"
    count = int(checked[0].split()[0])
    assert count > 80, (
        f"only {count} figures were verified, down from 115. A table header or "
        f"row label has probably changed, so most checks are silently skipping."
    )


@pytest.mark.skipif(not (RESULTS / "bench.json").exists(), reason="no results")
def test_the_recorded_run_has_no_invariant_violations() -> None:
    """`latency.py` refuses to report impossible results. Confirm it didn't have to.

    The specific impossibility this guards against was observed: an early
    harness measured the hybrid as four times *faster* than the ML-DSA signature
    it contains, because each configuration was timed over a different message
    and ML-DSA's cost depends on the message.
    """
    bench = json.loads((RESULTS / "bench.json").read_text(encoding="utf-8"))
    assert bench.get("invariant_violations") == [], (
        f"the committed benchmark run violates its own invariants: "
        f"{bench.get('invariant_violations')}"
    )


@pytest.mark.skipif(not CHECKER.exists(), reason="checker missing")
def test_the_checker_fails_when_a_figure_is_wrong(tmp_path: Path) -> None:
    """Prove the checker can fail. An always-green check is worse than none.

    Corrupt one figure in a copy of the document, point the checker at it, and
    require a non-zero exit. Without this, a regex that stopped matching would
    turn the test above into a permanent pass.
    """
    doc = ROOT / "docs" / "BENCHMARKS.md"
    if not doc.exists():
        pytest.skip("BENCHMARKS.md missing")

    original = doc.read_text(encoding="utf-8")

    # Find any signature-size cell to corrupt, rather than naming one. The
    # literal "**2,420 B**" was hardcoded here and silently stopped matching
    # when the default moved to ML-DSA-87 and the bolding moved with it -- so
    # this test skipped, and the proof that the checker can fail quietly
    # stopped running. A test whose job is to detect a silent no-op must not
    # itself become one.
    sizes = {"2,420": "2,410", "4,627": "4,617", "3,309": "3,299"}
    target = next((k for k in sizes if f"**{k} B**" in original), None)
    if target is None:
        target = next((k for k in sizes if f"| {k} B |" in original), None)
        if target is None:
            pytest.fail(
                "no signature-size cell found in BENCHMARKS.md to corrupt; this "
                "test can no longer prove the checker detects size drift"
            )
        before, after = f"| {target} B |", f"| {sizes[target]} B |"
    else:
        before, after = f"**{target} B**", f"**{sizes[target]} B**"

    backup = tmp_path / "BENCHMARKS.md.orig"
    backup.write_text(original, encoding="utf-8")
    try:
        doc.write_text(original.replace(before, after, 1), encoding="utf-8")
        result = _run()
        assert result.returncode != 0, (
            f"the checker passed a document whose {target}-byte signature "
            f"size had been altered. It is not checking sizes."
        )
        assert "exact" in result.stdout, (
            "a signature size drifted but was not reported as an exact-value "
            f"failure:\n{result.stdout}"
        )
    finally:
        doc.write_text(original, encoding="utf-8")
