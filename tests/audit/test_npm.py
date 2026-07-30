"""npm attestation audit.

Same three-outcome discipline as PyPI, plus the one thing npm has that PyPI
does not: two attestations per version, only one of which carries a
certificate.
"""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from qresp.audit.model import QLabel, SigAlgorithm
from qresp.audit.npm_client import (
    BULK_LIMIT,
    NpmClient,
    NpmError,
    PackageVersions,
    is_scoped,
    predicate_types,
    provenance_certificate,
)
from qresp.audit.npm_scanner import audit_package, unavailable_package

WORKFLOW = "https://github.com/acme/lib/.github/workflows/release.yml@refs/heads/main"


def _certificate_b64() -> str:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sigstore")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName(
            [x509.UniformResourceIdentifier(WORKFLOW)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return base64.b64encode(cert.public_bytes(Encoding.DER)).decode("ascii")


def _attestations(certificate: str | None = None,
                  publish_only: bool = False) -> dict[str, Any]:
    """Mirror the real shape: a publish attestation plus, usually, a SLSA one."""
    out: list[dict[str, Any]] = [{
        "predicateType": "https://github.com/npm/attestation/tree/main/specs/publish/v0.1",
        "bundle": {"verificationMaterial": {"publicKey": {"hint": "SHA256:abc"}}},
    }]
    if not publish_only:
        out.append({
            "predicateType": "https://slsa.dev/provenance/v1",
            "bundle": {"verificationMaterial": {
                "certificate": {"rawBytes": certificate or _certificate_b64()}}},
        })
    return {"attestations": out}


class FakeNpm:
    def __init__(self, versions: dict[str, PackageVersions],
                 attestations: dict[str, Any] | None = None,
                 fail: set[str] | None = None) -> None:
        self._versions = versions
        self._attestations = attestations or {}
        self._fail = fail or set()

    def package_versions(self, name: str) -> PackageVersions:
        if name in self._fail:
            raise NpmError(f"{name}: simulated failure")
        if name not in self._versions:
            raise NpmError(f"{name}: 404 not found")
        return self._versions[name]

    def fetch_attestations(self, name: str, version: str) -> dict[str, Any]:
        if f"{name}@{version}" in self._fail:
            raise NpmError("simulated failure")
        return self._attestations[f"{name}@{version}"]

    def bulk_downloads(self, names: list[str]) -> dict[str, int | None]:
        return {n: 1 for n in names}


class TestScopedPackages:
    """`@scope/name` is where npm differs from PyPI mechanically."""

    def test_scoped_names_are_recognised(self):
        assert is_scoped("@babel/core")
        assert not is_scoped("express")

    def test_bulk_downloads_refuses_scoped_names_loudly(self):
        """Silently dropping them would bias the head towards unscoped packages.

        `@babel/*` and `@types/*` are a large share of the most popular
        packages, so a ranking that quietly excluded scoped names would not be
        a ranking by popularity at all.
        """
        with pytest.raises(NpmError, match="rejects scoped"):
            NpmClient().bulk_downloads(["express", "@babel/core"])

    def test_bulk_downloads_enforces_the_128_limit(self):
        with pytest.raises(NpmError, match="bulk limit"):
            NpmClient().bulk_downloads([f"p{i}" for i in range(BULK_LIMIT + 1)])

    def test_an_empty_batch_is_not_a_request(self):
        assert NpmClient().bulk_downloads([]) == {}


class TestTwoAttestationsPerVersion:
    """Only the SLSA one carries a certificate. That distinction must survive."""

    def test_the_provenance_certificate_is_found_among_both(self):
        assert provenance_certificate(_attestations()) is not None

    def test_predicate_types_lists_both(self):
        types = predicate_types(_attestations())
        assert len(types) == 2
        assert any("slsa.dev" in t for t in types)
        assert any("npm/attestation" in t for t in types)

    def test_publish_only_yields_no_certificate(self):
        """npm's publish attestation names its key by ID, not by certificate."""
        assert provenance_certificate(_attestations(publish_only=True)) is None

    def test_a_publish_only_package_is_attested_but_unclassified(self):
        """Genuinely signed, genuinely not classifiable. Neither unsigned nor classical.

        Recording it as unsigned would undercount npm's signing; recording it
        as classical would assert an algorithm nothing in the bundle states.
        """
        client = FakeNpm(
            {"p": PackageVersions("p", 3, ["1.0.0"])},
            {"p@1.0.0": _attestations(publish_only=True)},
        )
        record = audit_package(client, "p")
        assert record["has_signature"] is True
        assert record["sig_algorithm"] == SigAlgorithm.UNKNOWN.value
        assert record["q_label"] == QLabel.ERROR.value
        assert "not determinable" in record["notes"]


class TestClassification:
    def test_an_attested_package_records_algorithm_and_workflow(self):
        client = FakeNpm({"lib": PackageVersions("lib", 9, ["1.0.0", "2.0.0"])},
                         {"lib@2.0.0": _attestations()})
        record = audit_package(client, "lib")
        assert record["sig_algorithm"] == SigAlgorithm.ECDSA_P256.value
        assert record["q_label"] == QLabel.VULNERABLE.value
        assert record["publisher"] == WORKFLOW
        assert record["attested_version_count"] == 2

    def test_the_most_recent_attested_version_is_the_one_classified(self):
        """The algorithm in use now, not the one used in 2023."""
        client = FakeNpm({"lib": PackageVersions("lib", 9, ["1.0.0", "9.9.9"])},
                         {"lib@9.9.9": _attestations()})
        assert audit_package(client, "lib")["sig_algorithm"] == \
            SigAlgorithm.ECDSA_P256.value

    def test_an_unattested_package_is_unsigned(self):
        client = FakeNpm({"express": PackageVersions("express", 288, [])})
        record = audit_package(client, "express")
        assert record["q_label"] == QLabel.UNSIGNED.value
        assert record["has_signature"] is False


class TestTheAbsentVersusUncheckedDistinction:
    def test_a_missing_package_is_error_not_unsigned(self):
        record = audit_package(FakeNpm({}), "gone")
        assert record["q_label"] == QLabel.ERROR.value

    def test_a_transport_failure_is_error_not_unsigned(self):
        record = audit_package(FakeNpm({}, fail={"x"}), "x")
        assert record["q_label"] == QLabel.ERROR.value
        assert "unavailable" in record["notes"]

    def test_unreadable_attestations_leave_the_package_signed(self):
        client = FakeNpm({"p": PackageVersions("p", 2, ["1.0.0"])},
                         fail={"p@1.0.0"})
        record = audit_package(client, "p")
        assert record["has_signature"] is True
        assert record["q_label"] == QLabel.ERROR.value
        assert "unreadable" in record["notes"]

    def test_unavailable_package_never_reports_unsigned(self):
        assert unavailable_package("p", "429")["q_label"] == QLabel.ERROR.value


class TestCrossEcosystemComparability:
    def test_npm_records_use_the_same_labels_as_pypi(self):
        """Three ecosystems, one vocabulary, so stats.py needs no branching."""
        valid = {q.value for q in QLabel}
        client = FakeNpm({"a": PackageVersions("a", 1, [])}, fail={"b"})
        for name in ("a", "b"):
            assert audit_package(client, name)["q_label"] in valid

    def test_the_record_carries_the_fields_stats_needs(self):
        client = FakeNpm({"a": PackageVersions("a", 1, [])})
        record = audit_package(client, "a")
        for field in ("q_label", "has_signature", "sig_algorithm", "ecosystem"):
            assert field in record
        assert record["ecosystem"] == "npm"

    def test_the_unit_of_analysis_matches_pypi(self):
        """Per-project, any version ever attested."""
        assert PackageVersions("p", 100, ["0.0.1"]).has_attestation
        assert not PackageVersions("p", 100, []).has_attestation
