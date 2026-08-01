"""Tests for the statistical inference in stats.py.

The intervals and the test statistic go into the paper, so they are checked
against known values rather than against themselves.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "src" / "qresp" / "audit" / "stats.py"
spec = importlib.util.spec_from_file_location("qresp_stats", SCRIPT)
st = importlib.util.module_from_spec(spec)
spec.loader.exec_module(st)


class TestWilson:
    def test_reproduces_published_phase_i_interval(self):
        """2/1000 -> [0.055%, 0.726%] as published in the Phase I report."""
        lo, hi = st.wilson_ci(2, 1000)
        assert round(100 * lo, 3) == 0.055
        assert round(100 * hi, 3) == 0.726

    def test_reproduces_published_unsigned_interval(self):
        lo, hi = st.wilson_ci(998, 1000)
        assert round(100 * lo, 2) == 99.27
        assert round(100 * hi, 2) == 99.95

    def test_zero_count_gives_zero_lower_bound(self):
        lo, hi = st.wilson_ci(0, 1000)
        assert lo == 0.0
        assert round(100 * hi, 2) == 0.38  # published PQ-safe upper bound

    def test_interval_is_bounded_to_the_unit_interval(self):
        for k, n in [(0, 1), (1, 1), (0, 10), (10, 10), (5, 10)]:
            lo, hi = st.wilson_ci(k, n)
            assert 0.0 <= lo <= hi <= 1.0

    def test_interval_narrows_as_n_grows(self):
        widths = [st.wilson_ci(n // 100, n)[1] - st.wilson_ci(n // 100, n)[0]
                  for n in (100, 1_000, 10_000)]
        assert widths[0] > widths[1] > widths[2]


class TestFisherExact:
    @pytest.mark.parametrize(
        "table,expected",
        [
            # Cross-checked two ways: exact rational arithmetic over math.comb,
            # and scipy.stats.fisher_exact. Both agree to full precision.
            ((1, 9, 11, 3), 0.0027594561852200836),
            ((5, 5, 5, 5), 1.0),
            ((20, 9_980, 0, 10_000), 1.8892970983884717e-06),
            ((2, 9_998, 0, 10_000), 0.4999749987499375),
        ],
    )
    def test_matches_exact_reference_values(self, table, expected):
        assert st.fisher_exact_two_sided(*table) == pytest.approx(expected, rel=1e-9)

    def test_symmetric_table_is_not_significant(self):
        assert st.fisher_exact_two_sided(5, 5, 5, 5) == pytest.approx(1.0)

    def test_p_value_is_a_probability(self):
        for table in [(2, 998, 0, 1000), (0, 10, 0, 10), (10, 0, 0, 10), (1, 1, 1, 1)]:
            p = st.fisher_exact_two_sided(*table)
            assert 0.0 <= p <= 1.0

    def test_empty_table_returns_one(self):
        assert st.fisher_exact_two_sided(0, 0, 0, 0) == 1.0

    def test_detects_a_real_head_tail_difference(self):
        """20/10000 in the head against 0/10000 in the tail should register."""
        assert st.fisher_exact_two_sided(20, 9_980, 0, 10_000) < 0.05

    def test_does_not_manufacture_significance_from_tiny_counts(self):
        """2/10000 vs 0/10000 is too little evidence to call."""
        assert st.fisher_exact_two_sided(2, 9_998, 0, 10_000) > 0.05


class TestNewcombeDiff:
    def test_zero_difference_interval_spans_zero(self):
        lo, hi = st.newcombe_diff_ci(5, 1000, 5, 1000)
        assert lo < 0 < hi

    def test_interval_is_bounded(self):
        lo, hi = st.newcombe_diff_ci(1000, 1000, 0, 1000)
        assert -1.0 <= lo <= hi <= 1.0

    def test_both_zero_gives_an_interval_containing_zero(self):
        lo, hi = st.newcombe_diff_ci(0, 10_000, 0, 10_000)
        assert lo <= 0 <= hi


class TestLoad:
    def _write(self, path: Path, rows: list[dict]) -> None:
        path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

    def _row(self, model_id: str, ts: str, label: str = "unsigned") -> dict:
        return {
            "model_id": model_id,
            "audit_ts": ts,
            "has_signature": label not in ("unsigned",),
            "q_label": label,
        }

    def test_duplicates_are_deduped_to_latest(self, tmp_path: Path, capsys):
        path = tmp_path / "a.jsonl"
        self._write(path, [
            self._row("a/b", "2026-01-01T00:00:00Z", "unsigned"),
            self._row("a/b", "2026-02-01T00:00:00Z", "vulnerable"),
            self._row("c/d", "2026-01-01T00:00:00Z", "unsigned"),
        ])
        records = st.load(path)
        assert len(records) == 2
        assert {r["model_id"]: r["q_label"] for r in records}["a/b"] == "vulnerable"
        assert "deduped" in capsys.readouterr().out

    def test_counts_cover_every_label(self, tmp_path: Path):
        path = tmp_path / "a.jsonl"
        self._write(path, [
            self._row("a/1", "2026-01-01T00:00:00Z", "unsigned"),
            self._row("a/2", "2026-01-01T00:00:00Z", "vulnerable"),
            self._row("a/3", "2026-01-01T00:00:00Z", "safe"),
            self._row("a/4", "2026-01-01T00:00:00Z", "mixed"),
            self._row("a/5", "2026-01-01T00:00:00Z", "error"),
        ])
        c = st.counts(st.load(path))
        assert c["n"] == 5
        assert (c["unsigned"], c["vulnerable"], c["safe"], c["mixed"], c["error"]) == \
               (1, 1, 1, 1, 1)
        assert c["signed"] == 4

    def test_missing_file_exits(self, tmp_path: Path):
        with pytest.raises(SystemExit):
            st.load(tmp_path / "nope.jsonl")


class TestStratifiedWeighting:
    def test_combined_estimate_is_dominated_by_the_larger_stratum(self, capsys):
        """With a tail population far larger than the head, the combined
        estimate must sit close to the tail rate, not midway between."""
        head = {"n": 10_000, "signed": 1_000, "unsigned": 9_000,
                "vulnerable": 1_000, "safe": 0, "mixed": 0, "error": 0}
        tail = {"n": 10_000, "signed": 0, "unsigned": 10_000,
                "vulnerable": 0, "safe": 0, "mixed": 0, "error": 0}
        st.print_combined(head, tail, tail_population=2_000_000)
        out = capsys.readouterr().out
        # tail_population IS the whole registry, so N = 2,000,000, N_h = 10,000,
        # N_t = 1,990,000. head weight = 10k / 2M = 0.005 exactly; combined
        # signed rate = 0.005 * 0.10 = 0.050%. If N_t were the raw registry
        # size (the double-count bug), N would be 2,010,000 and the weight
        # 0.004975 -- a different number.
        assert "0.050%" in out
        assert "census" in out or "no sampling" in out

    def test_head_and_tail_partition_the_registry(self, capsys):
        """The bug this replaces: N_t used the full frame while the tail was
        drawn from frame - head, double-counting the head's 10,000 in both
        strata. The reported registry N must equal the frame size, not
        frame + head.
        """
        head = {"n": 10_000, "signed": 100, "unsigned": 9_900,
                "vulnerable": 100, "safe": 0, "mixed": 0, "error": 0}
        tail = {"n": 10_000, "signed": 0, "unsigned": 10_000,
                "vulnerable": 0, "safe": 0, "mixed": 0, "error": 0}
        st.print_combined(head, tail, tail_population=4_290_079)
        out = capsys.readouterr().out
        assert "4,290,079" in out, "registry N must be the frame size exactly"
        assert "4,300,079" not in out, "frame + head is the double-count bug"

    def test_a_partial_head_census_is_flagged(self, capsys):
        """The broken npm run audited only 7,030 of the 10,000-package head.
        The 'no sampling variance' claim assumes a full census; a short head
        must warn rather than silently understate the head's variance.
        """
        head = {"n": 7_030, "signed": 100, "unsigned": 6_930,
                "vulnerable": 100, "safe": 0, "mixed": 0, "error": 0}
        tail = {"n": 10_000, "signed": 0, "unsigned": 10_000,
                "vulnerable": 0, "safe": 0, "mixed": 0, "error": 0}
        st.print_combined(head, tail, tail_population=4_290_079)
        out = capsys.readouterr().out
        assert "WARNING" in out and "7,030" in out

    def test_zero_counts_report_a_one_sided_bound(self, capsys):
        head = {"n": 10_000, "signed": 0, "unsigned": 10_000,
                "vulnerable": 0, "safe": 0, "mixed": 0, "error": 0}
        tail = dict(head)
        st.print_combined(head, tail, tail_population=1_000_000)
        out = capsys.readouterr().out
        assert "one-sided" in out

    def test_contrast_reports_the_difference_and_a_test(self, capsys):
        head = {"n": 10_000, "signed": 40, "unsigned": 9_960,
                "vulnerable": 40, "safe": 0, "mixed": 0, "error": 0}
        tail = {"n": 10_000, "signed": 1, "unsigned": 9_999,
                "vulnerable": 1, "safe": 0, "mixed": 0, "error": 0}
        st.print_contrast(head, tail)
        out = capsys.readouterr().out
        assert "difference" in out
        assert "Fisher exact p" in out
        assert "significant" in out
        assert "No post-quantum signatures in either stratum" in out


class TestLoadWorksAcrossEcosystems:
    """stats.load keyed on model_id alone, so it KeyError'd on PyPI and npm.

    That means it had never successfully run on the package ecosystems -- the
    cross-ecosystem comparison the paper rests on could not have been produced
    through this function until now.
    """

    def test_project_keyed_records_load(self, tmp_path):
        path = tmp_path / "npm.jsonl"
        path.write_text(
            '{"project": "lodash", "q_label": "unsigned", '
            '"has_signature": false, "audit_ts": "2026-08-01T00:00:00"}\n')
        recs = st.load(path)
        assert len(recs) == 1 and recs[0]["project"] == "lodash"

    def test_model_id_keyed_records_still_load(self, tmp_path):
        path = tmp_path / "hf.jsonl"
        path.write_text(
            '{"model_id": "org/model", "q_label": "unsigned", '
            '"has_signature": false, "audit_ts": "2026-08-01T00:00:00"}\n')
        assert st.load(path)[0]["model_id"] == "org/model"

    def test_an_error_superseded_by_a_retry_dedups_to_the_success(self, tmp_path):
        """The retry path depends on this: a re-run appends, latest wins."""
        path = tmp_path / "r.jsonl"
        path.write_text(
            '{"project": "p", "q_label": "error", "has_signature": false, '
            '"audit_ts": "2026-08-01T00:00:00"}\n'
            '{"project": "p", "q_label": "signed", "has_signature": true, '
            '"audit_ts": "2026-08-01T09:00:00"}\n')
        recs = st.load(path)
        assert len(recs) == 1 and recs[0]["q_label"] == "signed"
