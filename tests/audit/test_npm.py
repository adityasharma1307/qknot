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

from qknot.audit.model import QLabel, SigAlgorithm
from qknot.audit.npm_client import (
    BULK_LIMIT,
    NpmClient,
    NpmError,
    PackageVersions,
    is_scoped,
    predicate_types,
    provenance_certificate,
)
from qknot.audit.npm_scanner import audit_package, unavailable_package

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


class TestRateLimitFailuresAreNotSilentZeroes:
    """The 429 storm that cost 86% of the first ranking run.

    api.npmjs.org rate-limits far more aggressively than the registry. The
    original client swallowed the resulting `NpmError` and returned None, which
    made a throttled request indistinguishable from a package with no download
    data -- and because the candidate pool is sorted, the losses tracked the
    alphabet rather than anything about the packages.
    """

    class _Throttled:
        status_code = 429

        def json(self) -> dict[str, Any]:
            return {}

    class _Session:
        def __init__(self, response: Any) -> None:
            self._response = response
            self.calls = 0

        def get(self, *_args: Any, **_kwargs: Any) -> Any:
            self.calls += 1
            return self._response

    def test_single_downloads_raises_on_429_rather_than_returning_none(self):
        client = NpmClient(session=self._Session(self._Throttled()))
        with pytest.raises(NpmError, match="429"):
            client.single_downloads("@babel/core")

    def test_bulk_downloads_raises_on_429_rather_than_reporting_no_counts(self):
        client = NpmClient(session=self._Session(self._Throttled()))
        with pytest.raises(NpmError, match="429"):
            client.bulk_downloads(["express", "lodash"])

    def test_the_docstring_records_why_swallowing_was_wrong(self):
        """So the next person does not re-add the except clause."""
        text = NpmClient.single_downloads.__doc__ or ""
        assert "absent-versus-unchecked" in text


class TestPermanentVersusTransientFailure:
    """A 404 is npm answering. A 429 is npm declining. Retrying only helps one.

    The second ranking run retried 404s six times each with exponential
    backoff. On a rate-limited endpoint that is not merely wasted work: every
    pointless retry spends budget a genuinely transient 429 needed, so
    conflating the two actively worsens the throttling it is trying to survive.
    """

    class _Response:
        def __init__(self, status: int, headers: dict[str, str] | None = None) -> None:
            self.status_code = status
            self.headers = headers or {}

        def json(self) -> dict[str, Any]:
            return {}

    class _Session:
        def __init__(self, response: Any) -> None:
            self._response = response

        def get(self, *_args: Any, **_kwargs: Any) -> Any:
            return self._response

    def test_a_404_is_marked_permanent(self):
        client = NpmClient(session=self._Session(self._Response(404)))
        with pytest.raises(NpmError) as caught:
            client.single_downloads("@scope/never-published")
        assert caught.value.is_permanent

    def test_a_429_is_not_permanent(self):
        client = NpmClient(session=self._Session(self._Response(429)))
        with pytest.raises(NpmError) as caught:
            client.single_downloads("@babel/core")
        assert not caught.value.is_permanent

    def test_a_server_stated_retry_after_is_preferred_to_a_guess(self):
        """npm knows how long it wants us to wait better than our curve does."""
        client = NpmClient(session=self._Session(
            self._Response(429, {"Retry-After": "30"})))
        with pytest.raises(NpmError) as caught:
            client.single_downloads("@babel/core")
        assert caught.value.retry_after == 30.0

    def test_a_missing_or_garbled_retry_after_is_none_not_zero(self):
        """Zero would mean 'retry immediately', the opposite of the instruction."""
        client = NpmClient(session=self._Session(
            self._Response(429, {"Retry-After": "soon"})))
        with pytest.raises(NpmError) as caught:
            client.single_downloads("@babel/core")
        assert caught.value.retry_after is None


class TestProvenanceVersionsAreMatchedByFamily:
    """6 signed HEAD packages were filed as unclassifiable over a version string.

    react-fast-compare, @typescript-eslint/experimental-utils and others carry
    slsa.dev/provenance/v0.2, but the matcher pinned the exact v1 string and so
    skipped a real provenance attestation carrying a Fulcio certificate.
    """

    def _provenance(self, version: str) -> dict[str, Any]:
        return {"attestations": [
            {"predicateType": "https://github.com/npm/attestation/tree/main/"
                              "specs/publish/v0.1",
             "bundle": {"verificationMaterial": {"publicKey": {"hint": "x"}}}},
            {"predicateType": f"https://slsa.dev/provenance/{version}",
             "bundle": {"verificationMaterial": {
                 "certificate": {"rawBytes": _certificate_b64()}}}}]}

    @pytest.mark.parametrize("version", ["v0.2", "v1"])
    def test_a_certificate_is_found_under_either_provenance_version(self, version):
        assert provenance_certificate(self._provenance(version)) is not None

    def test_a_v0_2_package_classifies_end_to_end(self):
        """The head packages that were erroring: signed, and now classified."""
        client = FakeNpm(
            {"react-fast-compare": PackageVersions("react-fast-compare", 5,
                                                   ["3.2.2"])},
            {"react-fast-compare@3.2.2": self._provenance("v0.2")})
        record = audit_package(client, "react-fast-compare")
        assert record["sig_algorithm"] == SigAlgorithm.ECDSA_P256.value
        assert record["q_label"] == QLabel.VULNERABLE.value
        assert record["q_label"] != QLabel.ERROR.value

    def test_publish_only_is_still_unclassifiable(self):
        """The fix must not turn a publish-only package into a false positive."""
        client = FakeNpm(
            {"p": PackageVersions("p", 1, ["1.0.0"])},
            {"p@1.0.0": {"attestations": [
                {"predicateType": "https://github.com/npm/attestation/tree/"
                                  "main/specs/publish/v0.1",
                 "bundle": {"verificationMaterial": {"publicKey": {"hint": "x"}}}}]}})
        record = audit_package(client, "p")
        assert record["sig_algorithm"] == SigAlgorithm.UNKNOWN.value
        assert record["has_signature"] is True
