"""Format detection must not use names the data can contain.

`"rows" in data` was the discriminator between a finished ranking and an
in-flight partial. `rows` is also a real npm package with 82 downloads/month,
so once the run's alphabetical frontier passed `r`, the same command against
the same file started crashing with `TypeError: 'int' object is not iterable`.

`metric`, `generated` and `measured` are npm packages too -- every marker in
the manifest schema is also a name the ranking may hold.
"""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "check_ranking", ROOT / "scripts" / "audit" / "check_ranking.py")
assert _spec and _spec.loader
check_ranking = importlib.util.module_from_spec(_spec)
sys.modules["check_ranking"] = check_ranking
_spec.loader.exec_module(check_ranking)

COLLIDING = ["rows", "metric", "generated", "measured", "candidate_count"]


class TestAPartialContainingSchemaNames:
    def test_a_package_named_rows_does_not_break_loading(self, tmp_path):
        path = tmp_path / "partial.json"
        path.write_text(json.dumps({"lodash": 500, "rows": 82}))
        assert check_ranking.load(path) == {"lodash": 500, "rows": 82}

    @pytest.mark.parametrize("name", COLLIDING)
    def test_every_manifest_key_is_safe_as_a_package_name(self, name, tmp_path):
        path = tmp_path / "partial.json"
        path.write_text(json.dumps({name: 7, "chalk": 900}))
        loaded = check_ranking.load(path)
        assert loaded[name] == 7
        assert loaded["chalk"] == 900

    def test_a_finished_ranking_still_parses(self, tmp_path):
        path = tmp_path / "ranking.json"
        path.write_text(json.dumps({
            "generated": "2026-07-31T00:00:00+00:00",
            "rows": [{"project": "lodash", "download_count": 500}]}))
        assert check_ranking.load(path) == {"lodash": 500}

    def test_a_ranking_whose_rows_is_a_list_wins_over_a_flat_read(self, tmp_path):
        """Shape decides, so the two formats can never be confused."""
        path = tmp_path / "ranking.json"
        path.write_text(json.dumps({
            "rows": [{"project": "a", "download_count": 1}], "measured": 1}))
        assert check_ranking.load(path) == {"a": 1}


class TestItReportsItsOwnFailuresUsefully:
    def test_a_missing_file_points_at_the_partial(self, tmp_path):
        (tmp_path / "r.partial.json").write_text(json.dumps({"a": 1}))
        with pytest.raises(SystemExit) as caught:
            check_ranking.load(tmp_path / "r.json")
        assert "partial IS present" in str(caught.value)

    def test_truncated_json_names_the_resume(self, tmp_path):
        path = tmp_path / "r.json"
        path.write_text('{"a": 1, "b":')
        with pytest.raises(SystemExit) as caught:
            check_ranking.load(path)
        assert "resumes" in str(caught.value)
