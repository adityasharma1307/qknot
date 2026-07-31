"""The study's central claim is a negative. This is what makes it sayable.

"No post-quantum signatures were found in any ecosystem" is only worth stating
if the detector could have produced a positive. Before this, it could not:
`cryptography` rejects a certificate whose SubjectPublicKeyInfo carries an
algorithm OID it does not implement, at LOAD time, so `public_key()` was never
reached and the "this may be a post-quantum key" branch below it was
unreachable for the case it was written for. `SigAlgorithm.ML_DSA_87` existed in
the model and no code path could return it.

The first real post-quantum attestation in any registry would have been filed
as "certificate does not parse" and counted with corrupt data.
"""
from __future__ import annotations

import base64
import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from qresp.audit.model import QLabel, SigAlgorithm, classify_algorithm
from qresp.audit.pqc_oid import encode_oid, postquantum_oid_in
from qresp.audit.pypi_client import (
    PostQuantumCertificate,
    ProjectFiles,
    PyPiError,
    key_algorithm_of_certificate,
)
from qresp.audit.pypi_scanner import audit_project

EC_OID = bytes.fromhex("06072a8648ce3d0201")     # id-ecPublicKey


def _certificate_with_oid(dotted: str) -> str:
    """A DER certificate whose SPKI algorithm OID is `dotted`.

    Spliced rather than generated, because no Python library can currently
    issue an ML-DSA certificate -- which is itself why this gap existed. What
    matters is reproducing what `cryptography` DOES with such bytes, and it
    refuses them identically whether the OID arrived by splice or by a real CA.
    """
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pq-probe")])
    now = datetime.datetime.now(datetime.timezone.utc)
    der = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
           .public_key(key.public_key()).serial_number(1)
           .not_valid_before(now - datetime.timedelta(days=1))
           .not_valid_after(now + datetime.timedelta(days=1))
           .sign(key, hashes.SHA256())).public_bytes(Encoding.DER)
    return base64.b64encode(der.replace(EC_OID, encode_oid(dotted), 1)).decode()


class TestTheGapItself:
    def test_cryptography_rejects_this_certificate_at_parse_time(self):
        """Narrower than it first appears, and the narrowing matters.

        The spliced certificate carries EC key material under an ML-DSA OID, so
        it is malformed whatever the library supports. This therefore shows
        that the OID-fallback path is REACHED, not that cryptography lacks
        ML-DSA support -- an earlier version of this docstring claimed the
        latter, which was an overclaim.

        The real question, "could this environment have parsed a genuine ML-DSA
        certificate?", is not answerable by a fixture: it depends on the
        installed wheel's OpenSSL. `capability.pqc_parsing_capability()` probes
        it, and every scan manifest records the answer.
        """
        raw = base64.b64decode(_certificate_with_oid("2.16.840.1.101.3.4.3.19"))
        with pytest.raises(Exception):        # noqa: B017 -- any parse failure
            x509.load_der_x509_certificate(raw)

    def test_the_environment_reports_its_own_pq_parsing_capability(self):
        """A negative result needs the detector's competence on the record."""
        from qresp.audit.capability import pqc_parsing_capability

        capability = pqc_parsing_capability()
        assert set(capability) >= {"mlDsaCertificatesParseable",
                                   "slhDsaCertificatesParseable",
                                   "oidFallbackActive"}
        assert capability["oidFallbackActive"] is True

    def test_capability_is_probed_not_inferred_from_a_version(self):
        """Measured: cryptography 48.0.0 on OpenSSL 4.0.0 -- well past the
        3.5.0 the release notes name -- still exposes no ml_dsa module, because
        the bundled-wheel build decides it. A version comparison would have
        reported support that is not there."""
        from qresp.audit.capability import scan_environment

        environment = scan_environment()
        assert "openssl" in environment
        assert isinstance(environment["pqcParsing"]["mlDsaCertificatesParseable"], bool)

    def test_the_model_has_pq_labels_that_were_unreachable(self):
        """They existed all along; nothing could return them."""
        assert classify_algorithm(SigAlgorithm.ML_DSA_87) is QLabel.SAFE


class TestDetection:
    @pytest.mark.parametrize("dotted,expected", [
        ("2.16.840.1.101.3.4.3.17", SigAlgorithm.ML_DSA_44),
        ("2.16.840.1.101.3.4.3.18", SigAlgorithm.ML_DSA_65),
        ("2.16.840.1.101.3.4.3.19", SigAlgorithm.ML_DSA_87),
        ("2.16.840.1.101.3.4.3.20", SigAlgorithm.SLH_DSA),
        ("2.16.840.1.101.3.4.3.31", SigAlgorithm.SLH_DSA),
    ])
    def test_each_fips_204_205_oid_is_recognised(self, dotted, expected):
        with pytest.raises(PostQuantumCertificate) as caught:
            key_algorithm_of_certificate(_certificate_with_oid(dotted))
        assert caught.value.algorithm is expected
        assert caught.value.oid == dotted
        assert "FINDING" in str(caught.value)

    def test_the_oid_encoder_matches_the_registry(self):
        """Spot-check against the CSOR value, so a typo in the table shows up."""
        assert encode_oid("2.16.840.1.101.3.4.3.19").hex() == "0609608648016503040313"

    def test_ordinary_corruption_is_still_just_corruption(self):
        """Otherwise every truncated file becomes a false finding."""
        assert postquantum_oid_in(b"not a certificate at all") is None
        with pytest.raises(PyPiError) as caught:
            key_algorithm_of_certificate(base64.b64encode(b"garbage").decode())
        assert not isinstance(caught.value, PostQuantumCertificate)

    def test_a_classical_certificate_is_unaffected(self):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "ok")])
        now = datetime.datetime.now(datetime.timezone.utc)
        der = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(key.public_key()).serial_number(1)
               .not_valid_before(now - datetime.timedelta(days=1))
               .not_valid_after(now + datetime.timedelta(days=1))
               .sign(key, hashes.SHA256())).public_bytes(Encoding.DER)
        algorithm, _ = key_algorithm_of_certificate(base64.b64encode(der).decode())
        assert algorithm is SigAlgorithm.ECDSA_P256


class TestItReachesTheRecord:
    """A finding that never leaves the parser is still a lost finding."""

    class _Client:
        def __init__(self, certificate: str) -> None:
            self._certificate = certificate
            self.url = "https://pypi.org/integrity/pq/1/pq.whl/provenance"

        def list_projects(self):
            return ["pq"]

        def project_files(self, name):
            return ProjectFiles(name, 1, [self.url])

        def fetch_provenance(self, url):
            return {"attestation_bundles": [{
                "publisher": {"kind": "GitHub", "repository": "acme/pq"},
                "attestations": [{
                    "verification_material": {"certificate": self._certificate},
                    "envelope": {"statement": "...", "signature": "..."}}]}]}

    def test_a_pq_project_is_classified_not_errored(self):
        client = self._Client(_certificate_with_oid("2.16.840.1.101.3.4.3.19"))
        record = audit_project(client, "pq")
        assert record["sig_algorithm"] == SigAlgorithm.ML_DSA_87.value
        assert record["q_label"] == QLabel.SAFE.value
        assert record["q_label"] != QLabel.ERROR.value
        assert "POST-QUANTUM FINDING" in record["notes"]

    def test_it_is_not_counted_as_unsigned_either(self):
        client = self._Client(_certificate_with_oid("2.16.840.1.101.3.4.3.19"))
        assert audit_project(client, "pq")["has_signature"] is True
