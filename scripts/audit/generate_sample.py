"""Generate a sample audit dataset from the test fixtures.

Useful for showing reviewers what the output looks like without requiring
HuggingFace API access.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Make tests/ importable so we can reuse the fixtures
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.fake_client import FakeHfClient  # noqa: E402
from tests.fixtures_models import ALL_FIXTURES  # noqa: E402

from qresp.audit.scanner import run_audit  # noqa: E402


def main() -> None:
    out = Path(__file__).resolve().parent.parent / "data" / "sample.jsonl"
    out.parent.mkdir(parents=True, exist_ok=True)
    if out.exists():
        out.unlink()  # start fresh for sample generation

    client = FakeHfClient(ALL_FIXTURES)
    records = list(run_audit(client, n=len(ALL_FIXTURES), out_path=out, resume=False))
    print(f"Wrote {len(records)} records to {out}")
    for r in records:
        print(f"  {r.q_label.value:11s}  {r.sig_algorithm.value:14s}  {r.model_id}")


if __name__ == "__main__":
    main()
