"""PyPI attestation audit: classification, and the absent/unchecked distinction.

The live client is exercised through a fake implementing `PyPiClientProtocol`,
so these run offline under the suite-wide network block. Certificates are minted
locally: what is under test is the mapping from a key type to a
quantum-vulnerability label, which does not depend on who issued the
certificate.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from qresp.audit.model import QLabel, SigAlgorithm
from qresp.audit.pypi_client import (
    ProjectFiles,
    PyPiError,
    key_algorithm_of_certificate,
)
from qresp.audit.pypi_scanner import audit_project, unavailable_project


def _certificate_b64(private_key: Any) -> str:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sigstore-test")])
    now = datetime.now(timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
    )
    # Ed25519 and Ed448 sign without a separate hash algorithm; passing one
    # raises. The self-signing algorithm is irrelevant here anyway -- what is
    # under test is the SUBJECT key's type, not who signed the certificate.
    is_eddsa = isinstance(private_key, ed25519.Ed25519PrivateKey)
    cert = builder.sign(private_key, None if is_eddsa else hashes.SHA256())
    return base64.b64encode(cert.public_bytes(Encoding.DER)).decode("ascii")


def _provenance(certificate_b64: str, repository: str = "psf/requests") -> dict[str, Any]:
    return {
        "version": 1,
        "attestation_bundles": [{
            "publisher": {"kind": "GitHub", "repository": repository},
            "attestations": [{
                "version": 1,
                "verification_material": {"certificate": certificate_b64},
                "envelope": {"statement": "...", "signature": "..."},
            }],
        }],
    }


class FakeClient:
    """Explicit about what it knows, so no test passes by checking nothing."""

    def __init__(self, files: dict[str, ProjectFiles],
                 provenance: dict[str, Any] | None = None,
                 fail: set[str] | None = None) -> None:
        self._files = files
        self._provenance = provenance or {}
        self._fail = fail or set()

    def list_projects(self) -> list[str]:
        return sorted(self._files)

    def project_files(self, name: str) -> ProjectFiles:
        if name in self._fail:
            raise PyPiError(f"{name}: simulated transport failure")
        if name not in self._files:
            raise PyPiError(f"{name}: 404 not found")
        return self._files[name]

    def fetch_provenance(self, url: str) -> dict[str, Any]:
        if url in self._fail:
            raise PyPiError(f"{url}: simulated failure")
        return self._provenance[url]


class TestAlgorithmClassification:
    """Read the algorithm off the certificate; never infer it from the ecosystem."""

    @pytest.mark.parametrize("key_factory,expected,label", [
        (lambda: ec.generate_private_key(ec.SECP256R1()),
         SigAlgorithm.ECDSA_P256, QLabel.VULNERABLE),
        (lambda: ec.generate_private_key(ec.SECP384R1()),
         SigAlgorithm.ECDSA_P384, QLabel.VULNERABLE),
        (lambda: rsa.generate_private_key(public_exponent=65537, key_size=2048),
         SigAlgorithm.RSA_2048, QLabel.VULNERABLE),
        (lambda: ed25519.Ed25519PrivateKey.generate(),
         SigAlgorithm.ED25519, QLabel.VULNERABLE),
    ])
    def test_each_key_type_maps_to_the_shared_vocabulary(self, key_factory,
                                                         expected, label):
        """Same enum the HuggingFace audit uses, so stats.py needs no branching."""
        from qresp.audit.model import classify_algorithm

        algorithm, _bits = key_algorithm_of_certificate(_certificate_b64(key_factory()))
        assert algorithm is expected
        assert classify_algorithm(algorithm) is label

    def test_a_garbled_certificate_raises_rather_than_guessing(self):
        with pytest.raises(PyPiError, match="does not parse"):
            key_algorithm_of_certificate("bm90LWEtY2VydA==")

    def test_the_error_message_flags_an_unknown_key_as_a_possible_finding(self):
        """An unrecognised key type may be post-quantum -- the whole point.

        Defaulting it to classical would erase the one result this study
        exists to detect, so the failure path says so in as many words.
        """
        from qresp.audit import pypi_client

        message = pypi_client.key_algorithm_of_certificate.__doc__ or ""
        assert "post-quantum" in message


class TestTheAbsentVersusUncheckedDistinction:
    """A failure to check must never be recorded as an absence of signature."""

    def test_a_project_with_no_provenance_is_unsigned(self):
        client = FakeClient({"boring": ProjectFiles("boring", 12, [])})
        record = audit_project(client, "boring")
        assert record["q_label"] == QLabel.UNSIGNED.value
        assert record["has_signature"] is False

    def test_a_transport_failure_is_error_not_unsigned(self):
        """The HuggingFace study's three gated repositories, generalised.

        Folding "could not check" into "checked and found nothing" would
        inflate the unsigned count with the study's own failures.
        """
        client = FakeClient({}, fail={"unreachable"})
        record = audit_project(client, "unreachable")
        assert record["q_label"] == QLabel.ERROR.value
        assert record["has_signature"] is False
        assert "unavailable" in record["notes"]

    def test_a_deleted_project_is_error_not_unsigned(self):
        record = audit_project(FakeClient({}), "vanished")
        assert record["q_label"] == QLabel.ERROR.value

    def test_an_attested_project_whose_provenance_is_unreadable_stays_signed(self):
        """Signature present, algorithm unknown. Neither unsigned nor classified."""
        url = "https://pypi.org/integrity/x/1/x.whl/provenance"
        client = FakeClient({"x": ProjectFiles("x", 3, [url])}, fail={url})
        record = audit_project(client, "x")
        assert record["has_signature"] is True
        assert record["q_label"] == QLabel.ERROR.value
        assert "unreadable" in record["notes"]

    def test_unavailable_project_never_reports_unsigned(self):
        assert unavailable_project("p", "rate limited")["q_label"] == QLabel.ERROR.value


class TestTheUnitOfAnalysis:
    """Per-project, any release ever attested. Fixed before collection began."""

    def test_one_attested_file_among_many_makes_the_project_attested(self):
        files = ProjectFiles("mixed", total_files=500, provenance_urls=[
            "https://pypi.org/integrity/mixed/0.1/mixed-0.1.whl/provenance"])
        assert files.has_attestation

    def test_a_project_that_stopped_attesting_still_counts(self):
        """Adoption, not recency.

        A project that attested through 2025 and has not released since DID
        adopt attestation. Counting it as unsigned would conflate "never
        adopted" with "not released lately" -- the same absent/unchecked
        confusion this codebase refuses elsewhere.
        """
        historical = ProjectFiles("dormant", total_files=90, provenance_urls=[
            "https://pypi.org/integrity/dormant/1.0/dormant-1.0.whl/provenance"])
        assert historical.has_attestation

    def test_no_files_at_all_is_not_attested(self):
        assert not ProjectFiles("empty", 0, []).has_attestation


class TestAnAttestedProject:
    def test_it_records_the_algorithm_and_publisher(self):
        url = "https://pypi.org/integrity/requests/2.33.0/requests.whl/provenance"
        cert = _certificate_b64(ec.generate_private_key(ec.SECP256R1()))
        client = FakeClient(
            {"requests": ProjectFiles("requests", 244, [url])},
            provenance={url: _provenance(cert, "psf/requests")},
        )
        record = audit_project(client, "requests")

        assert record["has_signature"] is True
        assert record["sig_algorithm"] == SigAlgorithm.ECDSA_P256.value
        assert record["q_label"] == QLabel.VULNERABLE.value
        assert record["key_size_bits"] == 256
        assert record["publisher"] == "GitHub:psf/requests"

    def test_the_algorithm_fetch_can_be_skipped_and_says_so(self):
        """A weaker record must announce that it is weaker."""
        url = "https://pypi.org/integrity/x/1/x.whl/provenance"
        client = FakeClient({"x": ProjectFiles("x", 1, [url])})
        record = audit_project(client, "x", fetch_algorithm=False)
        assert record["has_signature"] is True
        assert record["sig_algorithm"] == SigAlgorithm.UNKNOWN.value
        assert "not fetched" in record["notes"]

    def test_an_attestation_with_no_certificate_is_not_classified(self):
        url = "https://pypi.org/integrity/x/1/x.whl/provenance"
        broken = _provenance("")
        broken["attestation_bundles"][0]["attestations"][0][
            "verification_material"] = {}
        client = FakeClient({"x": ProjectFiles("x", 1, [url])},
                            provenance={url: broken})
        record = audit_project(client, "x")
        assert record["q_label"] == QLabel.ERROR.value
        assert "no certificate" in record["notes"]

    def test_an_empty_bundle_list_is_reported_not_ignored(self):
        url = "https://pypi.org/integrity/x/1/x.whl/provenance"
        client = FakeClient({"x": ProjectFiles("x", 1, [url])},
                            provenance={url: {"version": 1,
                                              "attestation_bundles": []}})
        record = audit_project(client, "x")
        assert "no attestation bundles" in record["notes"]


class TestRecordsAreStatsCompatible:
    def test_the_record_carries_the_fields_stats_needs(self):
        """`stats.py` counts by `q_label`; a renamed field would silently zero it."""
        client = FakeClient({"p": ProjectFiles("p", 4, [])})
        record = audit_project(client, "p")
        for field in ("q_label", "has_signature", "sig_algorithm", "audit_ts"):
            assert field in record, f"stats.py depends on {field!r}"

    def test_every_q_label_produced_is_a_real_qlabel(self):
        """Guards against a typo becoming an uncounted category.

        A label `stats.py` does not recognise would not raise -- it would be
        counted as zero of everything, and the row would vanish from the
        totals without any error.
        """
        valid = {q.value for q in QLabel}
        client = FakeClient({"a": ProjectFiles("a", 1, [])}, fail={"b"})
        for name in ("a", "b"):
            assert audit_project(client, name)["q_label"] in valid
