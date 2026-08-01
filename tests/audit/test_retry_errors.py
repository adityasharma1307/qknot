"""A re-run must retry `error` records, because the runner tells the user it will.

run_*_audit.py prints "Re-run to retry them" for error records, but already_done
counted those rows as recorded, so a resume skipped exactly what it promised to
retry. `error` means reached-but-unclassified -- the retry is how a transient
failure, or a record from before a classifier fix, gets a second chance.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _runner(name: str):
    spec = importlib.util.spec_from_file_location(
        name, ROOT / "scripts" / "audit" / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("runner_name", ["run_npm_audit", "run_pypi_audit"])
class TestErrorsAreNotDone:
    def test_a_usable_record_is_done(self, runner_name, tmp_path):
        runner = _runner(runner_name)
        path = tmp_path / "o.jsonl"
        path.write_text(json.dumps(
            {"project": "a", "q_label": "unsigned", "has_signature": False,
             "audit_ts": "t"}) + "\n")
        assert "a" in runner.already_done(path)

    def test_an_error_record_is_retried(self, runner_name, tmp_path):
        runner = _runner(runner_name)
        path = tmp_path / "o.jsonl"
        path.write_text(json.dumps(
            {"project": "b", "q_label": "error", "has_signature": False,
             "audit_ts": "t"}) + "\n")
        assert "b" not in runner.already_done(path), (
            "an error record must be retried on resume, which is exactly what "
            "the runner's closing message promises")

    def test_a_success_after_an_error_makes_it_done(self, runner_name, tmp_path):
        """Once retried and resolved, it must not be retried forever."""
        runner = _runner(runner_name)
        path = tmp_path / "o.jsonl"
        path.write_text(
            json.dumps({"project": "c", "q_label": "error",
                        "has_signature": False, "audit_ts": "t0"}) + "\n"
            + json.dumps({"project": "c", "q_label": "signed",
                          "has_signature": True, "audit_ts": "t1"}) + "\n")
        assert "c" in runner.already_done(path)
