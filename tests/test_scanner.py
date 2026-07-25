"""End-to-end scanner tests using the FakeHfClient and fixture data."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from qresp.model import ModelRecord, QLabel, SigAlgorithm, SigFormat
from qresp.scanner import audit_model, run_audit
from tests.fake_client import FakeHfClient
from tests.fixtures_models import (
    ALL_FIXTURES,
    FIXTURE_BROKEN,
    FIXTURE_GPG_ED25519,
    FIXTURE_IN_TOTO,
    FIXTURE_SIGSTORE_FULCIO,
    FIXTURE_SIGSTORE_RSA,
    FIXTURE_UNSIGNED,
)


@pytest.fixture
def client() -> FakeHfClient:
    return FakeHfClient(ALL_FIXTURES)


# ---------------------------------------------------------------------------
# Per-fixture behaviour
# ---------------------------------------------------------------------------
class TestPerFixture:
    def test_unsigned_model(self, client: FakeHfClient):
        summary, _ = FIXTURE_UNSIGNED
        record = audit_model(client, summary)
        assert record.q_label == QLabel.UNSIGNED
        assert record.sig_algorithm == SigAlgorithm.NONE
        assert record.sig_format == SigFormat.NONE
        assert record.has_signature is False
        assert record.candidate_files == []

    def test_sigstore_fulcio_model(self, client: FakeHfClient):
        summary, _ = FIXTURE_SIGSTORE_FULCIO
        record = audit_model(client, summary)
        assert record.q_label == QLabel.VULNERABLE
        assert record.sig_algorithm == SigAlgorithm.ECDSA_P256
        assert record.sig_format == SigFormat.SIGSTORE
        assert record.has_signature is True
        assert record.candidate_files == ["model.sig"]

    def test_sigstore_rsa_model(self, client: FakeHfClient):
        summary, _ = FIXTURE_SIGSTORE_RSA
        record = audit_model(client, summary)
        assert record.q_label == QLabel.VULNERABLE
        assert record.sig_algorithm == SigAlgorithm.RSA_2048
        assert record.sig_format == SigFormat.SIGSTORE
        assert record.key_size_bits is not None
        assert 2000 <= record.key_size_bits <= 2080

    def test_gpg_ed25519_model(self, client: FakeHfClient):
        summary, _ = FIXTURE_GPG_ED25519
        record = audit_model(client, summary)
        assert record.q_label == QLabel.VULNERABLE
        assert record.sig_algorithm == SigAlgorithm.ED25519
        assert record.sig_format == SigFormat.GPG

    def test_in_toto_model(self, client: FakeHfClient):
        summary, _ = FIXTURE_IN_TOTO
        record = audit_model(client, summary)
        assert record.q_label == QLabel.VULNERABLE
        assert record.sig_algorithm == SigAlgorithm.ECDSA_P256
        assert record.sig_format == SigFormat.IN_TOTO

    def test_sigstore_fulcio_note_is_preserved(self, client: FakeHfClient):
        """Regression test: a successfully-classified algorithm must not cause
        its diagnostic note to be silently dropped. Previously, audit_model()
        only accumulated `notes_accum` on the branch where the algorithm was
        UNKNOWN/NONE, so a resolved-but-heuristic result like the Fulcio
        ECDSA-P256 inference ended up with notes=None in the published record
        even though parse_sigstore() had attached a note explaining the
        heuristic. Both signed models in every top-1,000 snapshot to date were
        affected; see data/DATASETS.md for which model_ids those are per
        snapshot (they differ between the 2026-05-21 and 2026-07-06 scans)."""
        summary, _ = FIXTURE_SIGSTORE_FULCIO
        record = audit_model(client, summary)
        assert record.notes is not None
        assert "fulcio" in record.notes.lower()

    def test_in_toto_note_is_preserved(self, client: FakeHfClient):
        summary, _ = FIXTURE_IN_TOTO
        record = audit_model(client, summary)
        assert record.notes is not None
        assert "fulcio" in record.notes.lower()

    def test_broken_signature_yields_error_label(self, client: FakeHfClient):
        summary, _ = FIXTURE_BROKEN
        record = audit_model(client, summary)
        assert record.q_label == QLabel.ERROR
        assert record.sig_algorithm == SigAlgorithm.UNKNOWN
        assert record.has_signature is True
        # The notes field should capture some diagnostic context
        assert record.notes is not None


# ---------------------------------------------------------------------------
# Full bulk run, JSONL output, resume
# ---------------------------------------------------------------------------
class TestBulkRun:
    def test_full_run_writes_jsonl(self, client: FakeHfClient, tmp_path: Path):
        out = tmp_path / "audit.jsonl"
        records = list(run_audit(client, n=len(ALL_FIXTURES), out_path=out))
        assert len(records) == len(ALL_FIXTURES)
        # File should contain one valid JSON object per line
        lines = out.read_text().splitlines()
        assert len(lines) == len(ALL_FIXTURES)
        for line in lines:
            obj = json.loads(line)
            # Re-validate against the schema by re-instantiating ModelRecord
            ModelRecord.model_validate(obj)

    def test_resume_skips_already_audited(self, client: FakeHfClient, tmp_path: Path):
        out = tmp_path / "audit.jsonl"
        # First run: audit two models
        first_run = list(run_audit(client, n=2, out_path=out))
        assert len(first_run) == 2

        # Second run: ask for all models, expect to skip the first two
        second_run = list(run_audit(client, n=len(ALL_FIXTURES), out_path=out))
        assert len(second_run) == len(ALL_FIXTURES) - 2
        first_ids = {r.model_id for r in first_run}
        second_ids = {r.model_id for r in second_run}
        assert first_ids.isdisjoint(second_ids)

    def test_no_resume_truncates_instead_of_duplicating(
        self, client: FakeHfClient, tmp_path: Path
    ):
        """Regression test: resume=False must reset the output file, not just
        skip the skip-check while still appending. Previously run_audit()
        always opened out_path in "a" mode, so a resume=False rerun over a
        file that already had a prior run's rows in it doubled every row
        (each model_id appeared twice) -- this is what produced a corrupted
        n=2000 full.jsonl (with every label count exactly doubled) from what
        should have been a clean n=1000 rerun."""
        out = tmp_path / "audit.jsonl"
        first_run = list(run_audit(client, n=len(ALL_FIXTURES), out_path=out))
        assert len(first_run) == len(ALL_FIXTURES)

        # Rerun with resume=False over the same file: should replace, not append.
        second_run = list(run_audit(client, n=len(ALL_FIXTURES), out_path=out, resume=False))
        assert len(second_run) == len(ALL_FIXTURES)

        lines = out.read_text().splitlines()
        assert len(lines) == len(ALL_FIXTURES)
        model_ids = [json.loads(line)["model_id"] for line in lines]
        assert len(model_ids) == len(set(model_ids)), "no duplicate model_ids after a no-resume rerun"

    def test_summary_distribution_matches_fixtures(
        self, client: FakeHfClient, tmp_path: Path
    ):
        out = tmp_path / "audit.jsonl"
        records = list(run_audit(client, n=len(ALL_FIXTURES), out_path=out))
        counts = {label: 0 for label in QLabel}
        for r in records:
            counts[r.q_label] += 1
        # Of 6 fixtures: 1 unsigned, 4 vulnerable, 1 error
        assert counts[QLabel.UNSIGNED] == 1
        assert counts[QLabel.VULNERABLE] == 4
        assert counts[QLabel.ERROR] == 1
        assert counts[QLabel.SAFE] == 0
