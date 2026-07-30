"""Assert every number in BENCHMARKS.md still matches the results JSON.

WHY THIS EXISTS
===============
BENCHMARKS.md was written by transcribing figures out of `results/*.json` by
hand. Twice during that transcription a search-and-replace silently failed to
match, leaving a stale number in prose that read as authoritative. Nothing
caught it: the file is Markdown, so it always "builds", and the wrong figure
looks exactly like the right one.

A benchmark document whose numbers have drifted from the run that produced them
is worse than no benchmark document, because it invites a reviewer to cite a
figure the artefacts do not support. This script re-derives every claim from the
JSON and fails loudly on any mismatch.

    python scripts/bench/check_docs.py

Exit codes:
    0  every checked figure matches
    1  at least one figure has drifted
    2  could not check -- a results file or an expected passage is missing

Note 2 is distinct from 1 on purpose. "The numbers are right" and "I could not
find the numbers" must never be reported the same way; a checker that returns
success when it checked nothing is the failure mode it is meant to prevent.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
DOC = ROOT / "docs" / "BENCHMARKS.md"
BENCH = ROOT / "results" / "bench.json"
RANDOM = ROOT / "results" / "randomness.json"

# How close a figure in prose must be to the JSON. Prose rounds; that is fine.
# What is not fine is prose describing a different run.
TOLERANCE = 0.02  # 2% relative


class Report:
    def __init__(self) -> None:
        self.checked = 0
        self.problems: list[str] = []
        self.unavailable: list[str] = []

    def figure(self, label: str, doc_value: float, json_value: float,
               shown: str | None = None, *, exact: bool = False) -> None:
        """Compare a figure in prose against the recorded run.

        Two ways to agree, because prose rounds and rounding is not drift:
        1.9 ms quoted for 1.923 ms is correct reporting, but a 2% relative
        tolerance would reject it. So a value also passes if it is what the
        JSON rounds to at the precision the document actually displays.

        `exact` turns all of that off. Key and signature sizes are fixed by
        FIPS 204 -- they are not measurements and they do not have error bars,
        so 2,410 where the specification says 2,420 is simply wrong. A relative
        tolerance let exactly that mutation through when this checker was first
        tested against deliberate corruption.
        """
        self.checked += 1
        if exact:
            if doc_value != json_value:
                self.problems.append(
                    f"{label}: document says {doc_value:g}, specification and "
                    f"results say {json_value:g} (this quantity is exact)"
                )
            return
        if json_value == 0:
            ok = doc_value == 0
        else:
            ok = abs(doc_value - json_value) / abs(json_value) <= TOLERANCE
        if not ok and shown is not None:
            digits = re.search(r"\d+\.(\d+)", shown)
            decimals = len(digits.group(1)) if digits else 0
            ok = round(json_value, decimals) == round(doc_value, decimals)
        if not ok:
            self.problems.append(
                f"{label}: document says {doc_value:g}, results say {json_value:g}"
            )

    def missing(self, what: str) -> None:
        self.unavailable.append(what)


def _find(doc: str, pattern: str, report: Report, label: str) -> re.Match[str] | None:
    """Locate a passage, recording its absence rather than crashing.

    A passage that has been reworded is not a drifted number -- it is a check
    that no longer applies, and it must be reported as 'could not verify', not
    quietly skipped and not counted as a pass.
    """
    match = re.search(pattern, doc)
    if match is None:
        report.missing(f"{label} (passage not found -- reworded?)")
    return match


def _clean(cell: str) -> str:
    return cell.replace("*", "").replace("`", "").strip()


def _tables(doc: str) -> list[list[list[str]]]:
    """Split the document into Markdown tables, each a list of cell-rows."""
    tables, current = [], []
    for line in doc.splitlines():
        stripped = line.strip()
        if stripped.startswith("|"):
            cells = [c.strip() for c in stripped.strip("|").split("|")]
            if not all(set(c) <= set("-: ") for c in cells):  # skip separators
                current.append(cells)
        elif current:
            tables.append(current)
            current = []
    if current:
        tables.append(current)
    return tables


def _table_with(doc: str, *header_fragments: str) -> list[list[str]] | None:
    """Find the one table whose header row contains all these fragments.

    Selecting tables by their first column was the original approach and it was
    wrong: section 5 has two tables that both begin with the source name, so a
    lookup for 'ANU QRNG' returned p-values where min-entropy was wanted and
    reported thirteen false drifts. Identify a table by what it measures.
    """
    for table in _tables(doc):
        header = " ".join(_clean(c).lower() for c in table[0])
        if all(f.lower() in header for f in header_fragments):
            return table
    return None


def _row_in(table: list[list[str]] | None, name: str) -> list[str] | None:
    if table is None:
        return None
    for cells in table[1:]:
        if cells and _clean(cells[0]) == name:
            return cells
    return None


def _row(doc: str, name: str) -> list[str] | None:
    """Cells of the first table row anywhere in the document starting with `name`."""
    for table in _tables(doc):
        if (found := _row_in(table, name)) is not None:
            return found
    return None


def _num(cell: str) -> float | None:
    """Pull the first number out of a table cell, ignoring units and markup.

    Returns None for anything that is not a number -- a tick, a 'yes', an empty
    cell. `[\\d,]+` will happily match a bare comma, so the digit check after
    stripping separators is load-bearing, not defensive noise.
    """
    match = re.search(r"-?[\d,]+\.?\d*", cell.replace("*", "").replace("`", ""))
    if match is None:
        return None
    text = match.group().replace(",", "")
    return float(text) if re.search(r"\d", text) else None


DOC_NAME = {"ed25519": "Ed25519", "ml-dsa-44": "ML-DSA-44",
            "ml-dsa-65": "ML-DSA-65", "ml-dsa-87": "ML-DSA-87"}


def _median(measurement: Any) -> float:
    """Every timing in bench.json is a distribution, never a scalar.

    The document quotes medians. Quoting a mean here instead would silently
    change what the tables say, because ML-DSA's rejection sampling makes the
    two differ by a wide margin -- which is the point of section 1.
    """
    return float(measurement["median_ms"])


def check_primitives(doc: str, bench: dict[str, Any], report: Report) -> None:
    """The per-algorithm table, and the headline ratio derived from it."""
    primitives = bench.get("primitives")
    if not primitives:
        report.missing("results/bench.json has no 'primitives' section")
        return

    table = _table_with(doc, "keygen", "sign", "verify", "signature")
    if table is None:
        report.missing("the primitives table (header changed?)")
    for key, entry in primitives.items():
        name = DOC_NAME.get(key, key)
        cells = _row_in(table, name)
        if cells is None:
            report.missing(f"primitives row for {name}")
            continue
        # columns: name | keygen | sign | verify | signature | pk | sk
        for index, field, label in (
            (1, "keygen", "keygen"),
            (2, "sign", "sign"),
            (3, "verify", "verify"),
        ):
            if index < len(cells) and field in entry:
                value = _num(cells[index])
                if value is None:
                    report.missing(f"{name} {label} cell is not numeric")
                else:
                    report.figure(f"{name} {label}", value,
                                  _median(entry[field]), cells[index])
        for index, field, label in (
            (4, "signature_bytes", "signature size"),
            (5, "public_key_bytes", "public key size"),
            (6, "secret_key_bytes", "secret key size"),
        ):
            if index < len(cells) and field in entry:
                value = _num(cells[index])
                if value is not None:
                    report.figure(f"{name} {label}", value,
                                  float(entry[field]), cells[index], exact=True)

    # The headline compares Ed25519 against the SHIPPED DEFAULT parameter set,
    # not against -44. Hardcoding -44 here made the checker report a false drift
    # the moment the default moved to -87 -- it was checking a claim the
    # document no longer makes. Take the level from the run itself.
    level = bench.get("hybrid_overhead", {}).get("hybrid_level", "ml-dsa-44")
    ed, ml = primitives.get("ed25519"), primitives.get(level)
    if ed and ml:
        speed = _find(doc, r"signs \*?\*?([\d.]+)[x×] faster", report, "headline speed claim")
        if speed:
            report.figure("headline speed ratio", float(speed.group(1)),
                          _median(ml["sign"]) / _median(ed["sign"]))
        size = _find(doc, r"signature ([\d.]+)[x×] smaller", report, "headline size claim")
        if size:
            report.figure("headline size ratio", float(size.group(1)),
                          ml["signature_bytes"] / ed["signature_bytes"])

    # The spread claim. ML-DSA's max/min must stay far above Ed25519's, or the
    # rejection-sampling argument in section 1 has lost its control.
    spreads = {}
    spread_table = _table_with(doc, "p25", "median", "p75")
    if spread_table is None:
        report.missing("the timing-spread table (header changed?)")
    for key, entry in primitives.items():
        sign = entry.get("sign")
        if not sign:
            continue
        spreads[key] = sign["max_ms"] / sign["min_ms"]
        cells = _row_in(spread_table, DOC_NAME.get(key, key))
        if cells is None:
            continue
        for index, expected in ((1, sign["p25_ms"]), (2, sign["median_ms"]),
                                (3, sign["p75_ms"]), (4, spreads[key])):
            if index < len(cells) and (value := _num(cells[index])) is not None:
                report.figure(f"{DOC_NAME.get(key, key)} sign col{index}",
                              value, float(expected), cells[index])

    if "ed25519" in spreads and "ml-dsa-44" in spreads:
        report.checked += 1
        if spreads["ml-dsa-44"] < spreads["ed25519"] * 3:
            report.problems.append(
                f"section 1 argues ML-DSA-44's timing spread ({spreads['ml-dsa-44']:.1f}x) "
                f"stands out against Ed25519's control ({spreads['ed25519']:.1f}x). "
                f"On this run it does not, so the rejection-sampling claim is "
                f"no longer supported by the data."
            )


def check_scaling(doc: str, bench: dict[str, Any], report: Report) -> None:
    """The 'signature cost is flat' result, and the 7 GB extrapolation."""
    scaling = bench.get("scaling")
    if not scaling:
        report.missing("results/bench.json has no 'scaling' section")
        return

    label_for = {"1MB": "1 MiB", "10MB": "10 MiB", "100MB": "100 MiB"}
    signature_costs = []
    for key, entry in scaling.items():
        if not isinstance(entry, dict):     # "signed_with" marker
            continue
        cells = _row_in(_table_with(doc, "artefact", "digest", "throughput"),
                        label_for.get(key, key))
        signature_costs.append(entry["signature_only_ms"])
        if cells is None:
            report.missing(f"scaling row for {key}")
            continue
        # artefact | digest | total sign | signature only | digest share | throughput
        pairs = [(1, _median(entry["digest"])), (2, _median(entry["sign_total"])),
                 (3, entry["signature_only_ms"]), (4, entry["digest_share_pct"]),
                 (5, entry["throughput_mb_s"])]
        for index, expected in pairs:
            if index < len(cells) and (value := _num(cells[index])) is not None:
                report.figure(f"scaling {key} col{index}", value,
                              float(expected), cells[index])

    # "flat at 19-20 ms" -- if a re-run makes it grow with size, the central
    # claim of section 2 is wrong and no amount of re-rounding fixes it.
    if len(signature_costs) >= 2:
        report.checked += 1
        if max(signature_costs) / min(signature_costs) > 1.5:
            report.problems.append(
                f"section 2 claims the signature cost is flat across artefact "
                f"size, but it ranges {min(signature_costs):.1f}-"
                f"{max(signature_costs):.1f} ms on this run."
            )

    # The 7 GB extrapolation, recomputed from the 100 MiB throughput.
    hundred = scaling.get("100MB")
    if hundred:
        throughput = hundred["throughput_mb_s"]
        signature_s = hundred["signature_only_ms"] / 1000
        digest_s = 7 * 1024 / throughput
        match = _find(doc, r"\*\*7 GB\*\* \| \*\*([\d.]+) s\*\*", report, "7 GB digest time")
        if match:
            report.figure("7 GB digest", float(match.group(1)), digest_s)
        match = _find(doc, r"\*\*7 GB\*\*.*?\| \*\*([\d.]+)%\*\*", report, "7 GB signature share")
        if match:
            report.figure("7 GB signature share",
                          float(match.group(1)), 100 * signature_s / (digest_s + signature_s))


def check_hybrid(doc: str, bench: dict[str, Any], report: Report) -> None:
    """The claim the paper leans on: the Ed25519 half is nearly free."""
    hybrid = bench.get("hybrid_overhead")
    if not hybrid:
        report.missing("results/bench.json has no 'hybrid_overhead' section")
        return

    combined = hybrid.get("hybrid")
    ml_only = hybrid.get("ml_dsa_only")
    ed_only = hybrid.get("ed25519_only")
    if not (combined and ml_only and ed_only):
        report.missing("hybrid comparison rows")
        return

    # The ML-DSA-only row is labelled with whichever parameter set was
    # benchmarked. Hardcoding "-44" here would silently stop checking that row
    # the moment the default moved, which is exactly the failure this file
    # exists to prevent.
    level = hybrid.get("hybrid_level", "ml-dsa-44")
    ml_label = f"{DOC_NAME.get(level, level)} only"
    for label, entry in (("Ed25519 only", ed_only), ("hybrid", combined),
                         (ml_label, ml_only)):
        cells = _row_in(_table_with(doc, "configuration", "sign", "verify"), label)
        if cells is None:
            report.missing(f"hybrid table row for {label}")
            continue
        for index, expected in ((1, _median(entry["sign"])), (2, _median(entry["verify"])),
                                (3, float(entry["total_signature_bytes"]))):
                # column 3 is a byte count; sizes are exact, timings are not
            if index < len(cells) and (value := _num(cells[index])) is not None:
                report.figure(f"hybrid table {label} col{index}", value,
                              expected, cells[index], exact=(index == 3))

    overhead = hybrid.get("overhead", {})
    match = _find(doc, r"costs \*\*([\d.]+) ms \(([\d.]+)[x×]\)", report, "hybrid-vs-Ed25519 delta")
    if match:
        if "absolute_ms" in overhead:
            report.figure("hybrid over Ed25519", float(match.group(1)), overhead["absolute_ms"])
        if "multiple" in overhead:
            report.figure("hybrid/Ed25519 multiple", float(match.group(2)), overhead["multiple"])

    match = _find(doc, r"only ([\d.]+) ms\s+more than ML-DSA alone", report,
                  "hybrid-vs-ML-DSA delta")
    if match:
        report.figure("hybrid over ML-DSA alone", float(match.group(1)),
                      _median(combined["sign"]) - _median(ml_only["sign"]))

    # A composition cannot be cheaper than the more expensive of its parts.
    # latency.py asserts this at measure time; restating it here means a stale
    # bench.json cannot slip an impossible figure into the document.
    report.checked += 1
    if _median(combined["sign"]) < _median(ml_only["sign"]) * 0.97:
        report.problems.append(
            "IMPOSSIBLE: the hybrid is measured faster than ML-DSA alone, which "
            "it contains. Re-run; do not publish these figures."
        )

    if bench.get("invariant_violations"):
        report.problems.append(
            f"latency.py recorded invariant violations in this run: "
            f"{bench['invariant_violations']}"
        )


def check_cli(doc: str, bench: dict[str, Any], report: Report) -> None:
    cli = bench.get("cli")
    if not cli:
        report.missing("results/bench.json has no 'cli' section")
        return
    for label, key in (("interpreter startup (`python -c pass`)", "interpreter_startup"),
                       ("`qresp sign`", "sign"), ("`qresp verify`", "verify")):
        if key not in cli:
            continue
        cells = _row(doc, label.replace("`", ""))
        if cells is None:
            report.missing(f"CLI row for {key}")
            continue
        if len(cells) > 1 and (value := _num(cells[1])) is not None:
            report.figure(f"CLI {key}", value, _median(cli[key]), cells[1])


def check_entropy(doc: str, results: list[dict[str, Any]], report: Report) -> None:
    """Both entropy tables, plus the control's inverted ranking."""
    label_for = {
        "ANU QRNG": "anu",
        "NIST beacon": "beacon",
        "os.urandom": "system",
        "repeating block (control)": "BROKEN CONTROL",
    }
    by_source = {}
    for entry in results:
        name = entry["source"]
        for doc_label, key in label_for.items():
            if name.startswith(key):
                by_source[doc_label] = entry

    missing = set(label_for) - set(by_source)
    for name in sorted(missing):
        report.missing(f"randomness results for {name}")

    p_table = _table_with(doc, "monobit", "runs", "cusum")
    h_table = _table_with(doc, "per bit", "per byte")
    if p_table is None:
        report.missing("the SP 800-22 p-value table (header changed?)")
    if h_table is None:
        report.missing("the min-entropy table (header changed?)")

    test_columns = [
        "monobit", "frequency_block", "runs",
        "cumulative_sums_forward", "cumulative_sums_backward",
    ]
    for doc_label, entry in by_source.items():
        cells = _row_in(p_table, doc_label)
        if cells is None:
            report.missing(f"p-value row for {doc_label}")
        else:
            tests = entry["sp800_22"]["tests"]
            for index, test in enumerate(test_columns, start=1):
                if index >= len(cells) or test not in tests:
                    continue
                if (value := _num(cells[index])) is not None:
                    report.figure(f"{doc_label} {test} p", value,
                                  tests[test]["p_value"], cells[index])
            # the verdict column must agree with the count of passing tests
            passed = sum(1 for t in tests.values() if t["passed"])
            verdict = _clean(cells[-1])
            if "/" in verdict:
                report.checked += 1
                claimed = int(verdict.split("/")[0])
                if claimed != passed:
                    report.problems.append(
                        f"{doc_label}: document claims {claimed}/5 tests pass, "
                        f"results show {passed}"
                    )

        cells = _row_in(h_table, doc_label)
        if cells is None:
            report.missing(f"min-entropy row for {doc_label}")
            continue
        for index, expected in (
            (1, entry["sp800_90b_mcv_bitwise"]["min_entropy_per_bit"]),
            (2, entry["sp800_90b_mcv_bytewise"]["min_entropy_per_symbol"]),
            (3, entry["chi_square_bytewise"]["p_value"]),
        ):
            if index < len(cells) and (value := _num(cells[index])) is not None:
                report.figure(f"{doc_label} col{index}", value,
                              float(expected), cells[index])

    # The document's central entropy argument is that the BROKEN control scores
    # HIGHER than the real sources. If a re-run ever inverts that, the prose is
    # no longer describing the data and must be rewritten, not re-rounded.
    control = by_source.get("repeating block (control)")
    real = [v for k, v in by_source.items() if k != "repeating block (control)"]
    if control and real:
        control_h = control["sp800_90b_mcv_bytewise"]["min_entropy_per_symbol"]
        best_real = max(r["sp800_90b_mcv_bytewise"]["min_entropy_per_symbol"] for r in real)
        report.checked += 1
        if control_h <= best_real:
            report.problems.append(
                f"the document argues the broken control scores HIGHER "
                f"min-entropy than every real source, but the control is "
                f"{control_h:.4f} against a real best of {best_real:.4f}. "
                f"Rewrite section 5 -- do not adjust the numbers."
            )
        # ... and that exactly one test catches it.
        caught = [n for n, t in control["sp800_22"]["tests"].items() if not t["passed"]]
        report.checked += 1
        if caught != ["frequency_block"]:
            report.problems.append(
                f"the document says only frequency_block catches the control, "
                f"but these did: {caught or 'none'}"
            )


def main() -> int:
    report = Report()

    if not DOC.exists():
        print(f"cannot check: {DOC} is missing", file=sys.stderr)
        return 2
    doc = DOC.read_text(encoding="utf-8")

    if BENCH.exists():
        bench = json.loads(BENCH.read_text(encoding="utf-8"))
        check_primitives(doc, bench, report)
        check_scaling(doc, bench, report)
        check_hybrid(doc, bench, report)
        check_cli(doc, bench, report)
    else:
        report.missing(f"{BENCH.relative_to(ROOT)} (run scripts/bench/latency.py)")

    if RANDOM.exists():
        check_entropy(doc, json.loads(RANDOM.read_text(encoding="utf-8")), report)
    else:
        report.missing(f"{RANDOM.relative_to(ROOT)} (run scripts/bench/randomness.py)")

    for problem in report.problems:
        print(f"DRIFT   {problem}")
    for item in report.unavailable:
        print(f"UNKNOWN {item}")

    print(f"\n{report.checked} figures checked against results/.")

    if report.problems:
        print(f"{len(report.problems)} disagree with the recorded run.")
        return 1
    if report.unavailable:
        print(f"{len(report.unavailable)} could not be checked -- this is not a pass.")
        return 2
    print("All figures in BENCHMARKS.md match the JSON that produced them.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
