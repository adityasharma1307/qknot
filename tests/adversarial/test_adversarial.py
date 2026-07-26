"""Adversarial scenarios: attempts to make the audit lie.

Every test here is an attack. The question is not "does the code work" but
"can a hostile or careless input make this project report something false".
Three outcomes would count as a finding:

  1. A vulnerable repo reported as safe, or as anything other than vulnerable.
  2. A repo reported as unsigned when it was never actually inspected.
  3. An inferred attribution presented as though it had been parsed.

The first two overstate the security of the registry. The third overstates the
strength of our own evidence. All three are the kinds of error a reviewer will
probe, so they are probed here first.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from qresp.audit.detect import detect_signature_files
from qresp.audit.hf_client import ModelSummary, is_transient
from qresp.audit.model import QLabel, SigAlgorithm, SigFormat, classify_algorithm, reconcile_labels
from qresp.audit.parse import parse_gpg, parse_raw_signature, parse_signature
from qresp.audit.scanner import audit_model, run_audit_ids
from qresp.signing.entropy import (
    EntropyAttestation,
    OnFailure,
    QrngUnavailable,
    commit,
    get_entropy,
)

from ..audit.test_resilience import FlakyClient, _rate_limit_error, _rows


# ===========================================================================
# 1. Can a vulnerable signature be hidden?
# ===========================================================================
class TestVulnerabilityCannotBeMasked:
    """The label rules must never let a confirmed weak signature disappear."""

    def test_unparseable_sibling_cannot_bury_a_vulnerable_finding(self):
        assert reconcile_labels([QLabel.VULNERABLE, QLabel.ERROR]) == QLabel.VULNERABLE

    def test_many_errors_cannot_outvote_one_vulnerable(self):
        assert reconcile_labels(
            [QLabel.ERROR] * 50 + [QLabel.VULNERABLE]
        ) == QLabel.VULNERABLE

    def test_unsigned_siblings_cannot_dilute_a_vulnerable_finding(self):
        assert reconcile_labels(
            [QLabel.UNSIGNED] * 20 + [QLabel.VULNERABLE]
        ) == QLabel.VULNERABLE

    def test_vulnerable_never_becomes_safe(self):
        """The single worst outcome. Try every combination that includes one."""
        from itertools import combinations_with_replacement
        pool = [QLabel.SAFE, QLabel.ERROR, QLabel.UNSIGNED, QLabel.MIXED]
        for r in range(1, 4):
            for combo in combinations_with_replacement(pool, r):
                labels = [QLabel.VULNERABLE, *combo]
                assert reconcile_labels(labels) != QLabel.SAFE, (
                    f"{labels} reported as SAFE despite a vulnerable signature"
                )

    def test_safe_plus_vulnerable_is_never_reported_as_safe(self):
        assert reconcile_labels([QLabel.SAFE, QLabel.VULNERABLE]) == QLabel.MIXED
        assert reconcile_labels([QLabel.SAFE] * 10 + [QLabel.VULNERABLE]) == QLabel.MIXED

    def test_error_beside_safe_alone_stays_error(self):
        """Safety must be shown, not assumed around an unknown."""
        assert reconcile_labels([QLabel.SAFE, QLabel.ERROR]) == QLabel.ERROR

    @pytest.mark.parametrize("algo", [
        SigAlgorithm.RSA_2048, SigAlgorithm.RSA_4096, SigAlgorithm.ECDSA_P256,
        SigAlgorithm.ECDSA_P384, SigAlgorithm.ED25519, SigAlgorithm.ED448,
        SigAlgorithm.RSA_OTHER, SigAlgorithm.ECDSA_OTHER,
    ])
    def test_no_classical_algorithm_is_ever_safe(self, algo):
        assert classify_algorithm(algo) == QLabel.VULNERABLE


# ===========================================================================
# 2. Can absence of evidence become evidence of absence?
# ===========================================================================
class TestUnobservedIsNeverUnsigned:
    def test_vanished_repo_is_not_counted_as_unsigned(self, tmp_path: Path):
        out = tmp_path / "a.jsonl"
        list(run_audit_ids(FlakyClient(n_models=0), ["gone/x"], out_path=out))
        assert _rows(out)[0]["q_label"] == QLabel.ERROR.value

    def test_rate_limited_repo_is_not_written_at_all(self, tmp_path: Path):
        out = tmp_path / "a.jsonl"
        client = FlakyClient(n_models=3, signed_at={0, 1, 2},
                             raise_on_fetch_for={"org1/model1"},
                             exc=_rate_limit_error())
        list(run_audit_ids(client, ["org0/model0", "org1/model1", "org2/model2"],
                           out_path=out, max_consecutive_transient=10))
        ids = {r["model_id"] for r in _rows(out)}
        assert "org1/model1" not in ids, (
            "a rate-limited repo must leave no record, so resume retries it"
        )

    def test_a_repo_with_zero_files_is_never_unsigned(self, tmp_path: Path):
        """Zero files means we never saw the tree. Every real HuggingFace repo
        has at least .gitattributes."""
        out = tmp_path / "a.jsonl"
        list(run_audit_ids(FlakyClient(n_models=0), [f"gone/{i}" for i in range(5)],
                           out_path=out))
        for row in _rows(out):
            assert row["file_count"] == 0
            assert row["q_label"] != QLabel.UNSIGNED.value

    def test_empty_file_list_from_a_live_repo_is_unsigned_not_error(self):
        """Distinguish 'we looked and there was nothing' from 'we never looked'.
        A live repo that genuinely lists files, none of them signatures, is
        legitimately unsigned."""
        summary = ModelSummary(
            model_id="a/b", publisher="a", downloads=1,
            last_modified=datetime(2026, 1, 1, tzinfo=timezone.utc),
            filenames=["config.json", "README.md"],
        )
        record = audit_model(FlakyClient(n_models=1), summary)
        assert record.q_label == QLabel.UNSIGNED
        assert record.file_count == 2


# ===========================================================================
# 3. Can an inference pass itself off as a parse?
# ===========================================================================
class TestProvenanceCannotBeForged:
    def test_fulcio_convention_is_always_marked_inferred(self):
        bundle = json.dumps({
            "verificationMaterial": {
                "x509CertificateChain": {"certificates": [{"rawBytes": "ZmFrZQ=="}]}
            }
        }).encode()
        result = parse_signature(bundle, SigFormat.SIGSTORE)
        assert result.algorithm == SigAlgorithm.ECDSA_P256
        assert "inferred" in (result.notes or ""), (
            "a convention-derived attribution must never look like a parse"
        )

    def test_length_heuristic_is_always_marked_inferred(self):
        for size in (64, 256, 512, 2420, 3309):
            result = parse_raw_signature(b"\x00" * size)
            assert "inferred" in (result.notes or "")

    def test_a_real_parse_says_so_positively(self):
        """Previously a direct parse recorded nothing, so 'parsed' and 'note
        lost' were indistinguishable in the data."""
        from ..audit.test_parse_raw_and_pgp import v4_signature_packet
        result = parse_gpg(v4_signature_packet(pubkey_algo=1, hash_algo=8))
        assert "parsed_from_openpgp_packet" in (result.notes or "")
        assert "inferred" not in (result.notes or "")

    def test_every_resolved_algorithm_carries_some_note(self):
        """No resolved algorithm may be silent about its provenance."""
        from ..audit.test_parse_raw_and_pgp import v4_signature_packet
        cases = [
            parse_gpg(v4_signature_packet(1)),
            parse_gpg(v4_signature_packet(19)),
            parse_raw_signature(b"\x00" * 512),
            parse_signature(json.dumps({
                "verificationMaterial": {
                    "x509CertificateChain": {"certificates": [{"rawBytes": "eA=="}]}}
            }).encode(), SigFormat.SIGSTORE),
        ]
        for result in cases:
            if result.algorithm not in (SigAlgorithm.UNKNOWN, SigAlgorithm.NONE):
                assert result.notes, f"{result.algorithm} resolved with no provenance note"

    def test_parse_takes_precedence_over_length_guess(self):
        """A guess must never override evidence."""
        from ..audit.test_parse_raw_and_pgp import v4_signature_packet
        base = v4_signature_packet(23)
        packet = base + b"\x00" * (512 - len(base))
        assert len(packet) == 512, "sized to collide with the RSA-4096 heuristic"
        result = parse_signature(packet, SigFormat.CUSTOM)
        assert result.algorithm == SigAlgorithm.ED25519
        assert "inferred_from_raw_signature_length" not in (result.notes or "")


# ===========================================================================
# 4. Malformed and hostile input
# ===========================================================================
class TestMalformedInputNeverCrashesOrLies:
    HOSTILE = [
        b"", b"\x00", b"\xff" * 10_000, b"{", b"[]", b"null",
        b'{"verificationMaterial": null}',
        b'{"verificationMaterial": {"x509CertificateChain": {}}}',
        b'{"verificationMaterial": {"publicKey": {"rawBytes": "!!!not-base64!!!"}}}',
        b"-----BEGIN PGP SIGNATURE-----\n\ngarbage\n=AAAA\n-----END PGP SIGNATURE-----",
        b"\xc2\x00",
        b"\x89\xff\xff",
        "🔐".encode() * 100,
    ]

    @pytest.mark.parametrize("fmt", list(SigFormat))
    def test_no_format_parser_raises_on_hostile_bytes(self, fmt):
        for raw in self.HOSTILE:
            result = parse_signature(raw, fmt)
            assert isinstance(result.algorithm, SigAlgorithm)

    def test_hostile_bytes_never_yield_a_post_quantum_claim(self):
        """The most damaging false positive this project could produce."""
        for fmt in SigFormat:
            for raw in self.HOSTILE:
                result = parse_signature(raw, fmt)
                assert classify_algorithm(result.algorithm) != QLabel.SAFE, (
                    f"{raw[:20]!r} as {fmt} produced a post-quantum claim"
                )

    def test_random_bytes_of_pqc_length_are_only_a_length_inference(self):
        """2420 random bytes will classify as ML-DSA-44 by length alone. That
        is by design, but it must be flagged, because it is the one route by
        which noise could become the project's headline finding."""
        result = parse_raw_signature(b"\x00" * 2420)
        assert result.algorithm == SigAlgorithm.ML_DSA_44
        assert "inferred_from_raw_signature_length" in (result.notes or ""), (
            "a post-quantum claim from length alone must be conspicuously marked"
        )

    def test_detector_survives_pathological_filenames(self):
        names = ["", ".", "..", "/", "a" * 5000, "x.sig" * 100,
                 "../../etc/passwd.sig", "model.sig\x00.txt", "🔐.sig"]
        result = detect_signature_files(names)
        assert isinstance(result, list)


# ===========================================================================
# 5. The entropy attestation under attack
# ===========================================================================
class TestAttestationCannotBeForged:
    def test_prng_fallback_can_never_claim_quantum(self):
        class Dead:
            name, is_quantum = "anu", True

            def get_bytes(self, n):
                raise QrngUnavailable("down")

            def describe(self):
                return {"endpoint": "x", "authenticated": True}

        att = get_entropy(32, on_failure=OnFailure.FALLBACK, interactive=False,
                          max_attempts=1, _backend_obj=Dead(),
                          _sleep=lambda _: None).attestation
        assert att.is_quantum is False
        assert att.fallback_used is True

    def test_claiming_a_quantum_backend_name_is_not_enough(self):
        """is_quantum must reflect what served the bytes, not a label anyone
        can set. A hand-built attestation naming a quantum backend while
        recording a fallback must still read as non-quantum."""
        forged = EntropyAttestation(
            backend="anu", requested_backend="anu", fallback_used=True,
            n_bytes=32, timestamp="2026-01-01T00:00:00+00:00",
            commitment=commit(b"\x00" * 32),
        )
        assert forged.is_quantum is False

    def test_commitment_detects_substituted_entropy(self):
        result = get_entropy(32, backend="system")
        assert result.attestation.verify_commitment(result.raw)
        assert not result.attestation.verify_commitment(b"\xff" * 32)
        flipped = bytes([result.raw[0] ^ 1]) + result.raw[1:]
        assert not result.attestation.verify_commitment(flipped), (
            "a single flipped bit must break the commitment"
        )

    def test_attestation_cannot_be_edited_after_the_fact(self):
        import dataclasses
        att = get_entropy(32, backend="system").attestation
        for field_name in ("backend", "fallback_used", "commitment"):
            with pytest.raises(dataclasses.FrozenInstanceError):
                setattr(att, field_name, "tampered")

    def test_abort_policy_cannot_be_silently_downgraded(self):
        class Dead:
            name, is_quantum = "anu", True

            def get_bytes(self, n):
                raise QrngUnavailable("down")

            def describe(self):
                return {}

        with pytest.raises(QrngUnavailable):
            get_entropy(32, on_failure=OnFailure.ABORT, interactive=False,
                        _backend_obj=Dead(), _sleep=lambda _: None)


# ===========================================================================
# 6. Transient-vs-permanent classification
# ===========================================================================
class TestFailureClassification:
    @pytest.mark.parametrize("status,expected_transient", [
        (429, True), (500, True), (502, True), (503, True), (504, True),
        (400, False), (401, False), (403, False), (404, False), (410, False),
    ])
    def test_http_status_routing(self, status, expected_transient):
        import requests
        from huggingface_hub.utils import HfHubHTTPError
        response = requests.Response()
        response.status_code = status
        assert is_transient(HfHubHTTPError(str(status), response=response)) is expected_transient

    def test_a_404_is_a_finding_not_a_retry(self):
        """Retrying a genuinely absent file forever would stall the scan; worse,
        treating it as transient would drop a real observation."""
        import requests
        from huggingface_hub.utils import HfHubHTTPError
        response = requests.Response()
        response.status_code = 404
        assert not is_transient(HfHubHTTPError("404", response=response))

    def test_a_bad_token_is_not_retried(self):
        """401 means misconfiguration. Retrying hides it behind a slow scan."""
        import requests
        from huggingface_hub.utils import HfHubHTTPError
        response = requests.Response()
        response.status_code = 401
        assert not is_transient(HfHubHTTPError("401", response=response))


# ===========================================================================
# 7. Statistical invariants
# ===========================================================================
class TestStatisticalClaimsCannotBeInflated:
    def _stats(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "qresp_stats", Path(__file__).resolve().parents[2] / "src" / "qresp" / "audit" / "stats.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_wilson_upper_bound_never_reaches_zero_on_a_null_result(self):
        """Reporting a zero-width interval around 0 would overclaim certainty."""
        st = self._stats()
        lo, hi = st.wilson_ci(0, 10_000)
        assert lo == 0.0
        assert hi > 0.0, "a null result still has an upper bound"

    def test_pooling_the_strata_is_measurably_wrong(self):
        """Concatenating the two files inflates the signed rate. The weighting
        exists precisely to prevent this."""
        n_head = n_tail = 10_000
        k_head, k_tail = 39, 10
        tail_population = 2_928_107
        w_head = n_head / (n_head + tail_population)
        weighted = w_head * (k_head / n_head) + (1 - w_head) * (k_tail / n_tail)
        pooled = (k_head + k_tail) / (n_head + n_tail)
        assert pooled > 2 * weighted, (
            "pooling should be visibly wrong, so that anyone who does it by "
            "accident gets a number that does not match the published one"
        )

    def test_fisher_does_not_manufacture_significance_from_nothing(self):
        st = self._stats()
        assert st.fisher_exact_two_sided(0, 10_000, 0, 10_000) == pytest.approx(1.0)
        assert st.fisher_exact_two_sided(1, 9_999, 0, 10_000) > 0.05

    def test_label_partition_holds_on_the_real_datasets(self):
        st = self._stats()
        for name in ("head_10k_2026-07-25", "longtail_10k_2026-07-25"):
            path = Path(__file__).resolve().parents[2] / "data" / f"{name}.jsonl"
            if not path.exists():
                pytest.skip(f"{name} not present")
            c = st.counts(st.load(path))
            assert c["signed"] + c["unsigned"] + c["unavailable"] == c["n"]
            assert (c["vulnerable"] + c["safe"] + c["mixed"] + c["unparseable"]
                    == c["signed"])
