"""End-to-end registration verification: all eight steps, offline.

A full stack is minted -- a CA, a Fulcio-style leaf over the classical key, a
transparency log with a signed tree head -- a real dual-signed bundle is built,
and the whole chain is verified. This is the artefact to hand an expert: the
trust logic runs end to end, and the two network seams (getting a cert, writing
to a log) are the only pieces mocked, because they produce these same bytes.
"""
from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from cryptography.x509.oid import NameOID

from qresp.signing.backends import get_backend
from qresp.signing.registration import (
    HybridRegistration,
    KeyRef,
    Revocation,
    SignedRevocation,
    _key_fingerprint,
)
from qresp.signing.registration_chain import (
    RegistrationBundle,
    authorize_for_artifact,
    verify_registration_chain,
)
from qresp.signing.rekor import LogEntry, leaf_hash
from qresp.signing.temporal import BindingBasis

ISSUER_OID_V1 = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.1")
IDENTITY = "alice@example.com"
ISSUER = "https://accounts.google.com"
CLASSICAL_ALG = "ecdsa-p256"


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


class Harness:
    """Mints the whole trust stack and builds a verifiable registration bundle.

    log_time is when the registration was 'logged' -- the instant the Fulcio
    cert is validated against and the temporal rescue turns on.
    """

    def __init__(self, log_time=None, recovery_alg=None):
        self.log_time = log_time or (_now() - datetime.timedelta(days=1))

        # CA + Fulcio leaf over an ECDSA classical key, valid AROUND log_time.
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root")])
        self.root = self._ca("Root", self.root_key, root_name, self_signed=True)

        self.classical_priv = ec.generate_private_key(ec.SECP256R1())
        self.classical_pub = self.classical_priv.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
        self.classical_sk = None  # ECDSA backend keygen differs; sign via cert key
        leaf = (x509.CertificateBuilder()
                .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]))
                .issuer_name(root_name)
                .public_key(self.classical_priv.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(self.log_time - datetime.timedelta(minutes=5))
                .not_valid_after(self.log_time + datetime.timedelta(minutes=10))
                .add_extension(x509.SubjectAlternativeName(
                    [x509.RFC822Name(IDENTITY)]), critical=False)
                .add_extension(x509.UnrecognizedExtension(
                    ISSUER_OID_V1, ISSUER.encode("utf-8")), critical=False)
                .sign(self.root_key, hashes.SHA256()))
        self.leaf_der = leaf.public_bytes(Encoding.DER)

        # PQC key + optional recovery key.
        self.pqc = get_backend("ml-dsa-87")
        self.pqc_pub, self.pqc_sk = self.pqc.keygen()
        self.recovery_alg = recovery_alg
        self.recovery_ref = None
        self.recovery_sk = None
        if recovery_alg:
            rb = get_backend(recovery_alg)
            rpub, self.recovery_sk = rb.keygen()
            self.recovery_ref = KeyRef(recovery_alg, rpub)

        # Log key for the signed tree head.
        self.log_key = ec.generate_private_key(ec.SECP256R1())
        self.log_pub = self.log_key.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    def _ca(self, name, key, subject, self_signed):
        return (x509.CertificateBuilder()
                .subject_name(subject).issuer_name(subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(self.log_time - datetime.timedelta(days=365))
                .not_valid_after(self.log_time + datetime.timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                .sign(key, hashes.SHA256()))

    def registration(self, not_after=None):
        return HybridRegistration(
            IDENTITY, ISSUER, KeyRef(CLASSICAL_ALG, self.classical_pub),
            KeyRef("ml-dsa-87", self.pqc_pub),
            self.log_time.isoformat(), not_after=not_after,
            recovery_key=self.recovery_ref)

    def bundle(self, not_after=None):
        reg = self.registration(not_after)
        payload = reg.to_payload()
        from qresp.signing.dsse import pae, rekord_preimage
        signed_bytes = pae("application/vnd.qresp.hybrid-key-registration+json", payload)
        # classical signature made with the cert's EC key directly
        classical_sig = self.classical_priv.sign(signed_bytes, ec.ECDSA(hashes.SHA256()))
        pqc_sig = self.pqc.sign(self.pqc_sk, signed_bytes)
        from qresp.signing.registration import HybridSignedRegistration
        env = HybridSignedRegistration(
            payload=payload, classical_signature=classical_sig,
            classical_certificate_der=self.leaf_der, pqc_signature=pqc_sig)

        # a one-entry transparency tree over a hashedrekord body
        from qresp.signing.rekor import hashedrekord_body
        preimage = rekord_preimage(
            "application/vnd.qresp.hybrid-key-registration+json", payload)
        entry_bytes = hashedrekord_body(preimage)
        root = leaf_hash(entry_bytes)
        sth = LogEntry.signed_tree_head(root, 1)
        entry = LogEntry(
            entry_body=entry_bytes, log_index=0, tree_size=1,
            inclusion_proof=[], root_hash=root,
            integrated_time=int(self.log_time.timestamp()),
            tree_head_signature=self.log_key.sign(sth, ec.ECDSA(hashes.SHA256())))
        return RegistrationBundle(envelope=env, intermediate_certificates=[],
                                  log_entry=entry), reg


class TestTheHappyPath:
    def test_a_valid_registration_verifies_directly(self):
        h = Harness()
        bundle, _ = h.bundle()
        binding = verify_registration_chain(
            bundle, fulcio_roots=[h.root.public_bytes(Encoding.DER)],
            log_public_key=h.log_pub, now=_now())
        assert binding.identity == IDENTITY
        assert binding.pqc_algorithm == "ml-dsa-87"
        assert binding.basis is BindingBasis.DIRECT
        assert binding.pqc_public_key == h.pqc_pub


class TestTheTemporalRescue:
    def test_after_p256_is_disallowed_the_binding_is_rescued(self):
        """The whole point: registered before the deadline, verified long after,
        trusted because the log timestamp proves it predates the disallow date."""
        logged = datetime.datetime(2028, 1, 1, tzinfo=datetime.timezone.utc)
        h = Harness(log_time=logged)
        bundle, _ = h.bundle()
        far_future = datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc)
        binding = verify_registration_chain(
            bundle, fulcio_roots=[h.root.public_bytes(Encoding.DER)],
            log_public_key=h.log_pub, now=far_future)
        assert binding.basis is BindingBasis.RESCUED

    def test_a_registration_logged_after_the_deadline_is_rejected(self):
        """No rescue: logged after p256 was disallowed, so nothing proves the
        binding predates the break."""
        logged = datetime.datetime(2036, 1, 1, tzinfo=datetime.timezone.utc)
        h = Harness(log_time=logged)
        bundle, _ = h.bundle()
        with pytest.raises(Exception, match="past its disallow date"):
            verify_registration_chain(
                bundle, fulcio_roots=[h.root.public_bytes(Encoding.DER)],
                log_public_key=h.log_pub,
                now=datetime.datetime(2037, 1, 1, tzinfo=datetime.timezone.utc))


class TestItRejectsTampering:
    def test_a_registration_against_the_wrong_root_is_rejected(self):
        h = Harness()
        bundle, _ = h.bundle()
        other_root = ec.generate_private_key(ec.SECP256R1())
        other = (x509.CertificateBuilder()
                 .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "X")]))
                 .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "X")]))
                 .public_key(other_root.public_key()).serial_number(1)
                 .not_valid_before(_now() - datetime.timedelta(days=1))
                 .not_valid_after(_now() + datetime.timedelta(days=1))
                 .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                 .sign(other_root, hashes.SHA256()))
        with pytest.raises(Exception, match="certificate chain"):
            verify_registration_chain(
                bundle, fulcio_roots=[other.public_bytes(Encoding.DER)],
                log_public_key=h.log_pub, now=_now())

    def test_an_identity_mismatch_between_cert_and_payload_is_rejected(self):
        """The cert says alice; forge a payload claiming bob over the same keys."""
        h = Harness()
        bundle, reg = h.bundle()
        forged = HybridRegistration(
            "bob@evil.com", ISSUER, KeyRef(CLASSICAL_ALG, h.classical_pub),
            KeyRef("ml-dsa-87", h.pqc_pub), h.log_time.isoformat())
        # re-sign the forged payload so proof-of-possession passes; the cert
        # cross-check (step 4) is what must catch it.
        from qresp.signing.dsse import pae
        sb = pae("application/vnd.qresp.hybrid-key-registration+json", forged.to_payload())
        from qresp.signing.registration import HybridSignedRegistration
        env = HybridSignedRegistration(
            payload=forged.to_payload(),
            classical_signature=h.classical_priv.sign(sb, ec.ECDSA(hashes.SHA256())),
            classical_certificate_der=h.leaf_der,
            pqc_signature=h.pqc.sign(h.pqc_sk, sb))
        from qresp.signing.dsse import rekord_preimage
        preimage = rekord_preimage(
            "application/vnd.qresp.hybrid-key-registration+json", forged.to_payload())
        from qresp.signing.rekor import hashedrekord_body
        eb = hashedrekord_body(preimage)
        root = leaf_hash(eb)
        entry = LogEntry(
            entry_body=eb, log_index=0, tree_size=1,
            inclusion_proof=[], root_hash=root,
            integrated_time=int(h.log_time.timestamp()),
            tree_head_signature=h.log_key.sign(
                LogEntry.signed_tree_head(root, 1), ec.ECDSA(hashes.SHA256())))
        bad = RegistrationBundle(env, [], entry)
        with pytest.raises(Exception, match="attests identity"):
            verify_registration_chain(
                bad, fulcio_roots=[h.root.public_bytes(Encoding.DER)],
                log_public_key=h.log_pub, now=_now())


class TestArtifactAuthorisation:
    def test_notafter_rejects_a_later_artefact(self):
        h = Harness()
        bundle, _ = h.bundle(not_after="2027-01-01T00:00:00Z")
        binding = verify_registration_chain(
            bundle, fulcio_roots=[h.root.public_bytes(Encoding.DER)],
            log_public_key=h.log_pub, now=_now())
        from qresp.signing.registration import NotYetRegistered
        with pytest.raises(NotYetRegistered):
            authorize_for_artifact(
                binding, datetime.datetime(2028, 6, 1, tzinfo=datetime.timezone.utc))

    def test_a_covered_artefact_returns_the_pqc_key(self):
        h = Harness()
        bundle, _ = h.bundle(not_after="2030-01-01T00:00:00Z")
        binding = verify_registration_chain(
            bundle, fulcio_roots=[h.root.public_bytes(Encoding.DER)],
            log_public_key=h.log_pub, now=_now())
        key = authorize_for_artifact(
            binding, datetime.datetime(2027, 1, 1, tzinfo=datetime.timezone.utc))
        assert key == h.pqc_pub

    def test_a_recovery_revocation_kills_a_later_artefact(self):
        h = Harness(recovery_alg="ml-dsa-87")
        bundle, reg = h.bundle()
        binding = verify_registration_chain(
            bundle, fulcio_roots=[h.root.public_bytes(Encoding.DER)],
            log_public_key=h.log_pub, now=_now())
        # recovery-signed revocation dated before the artefact
        rev = Revocation(IDENTITY, _key_fingerprint(h.pqc_pub), "compromised",
                         "2027-01-01T00:00:00Z")
        from qresp.signing.dsse import pae
        sb = pae("application/vnd.qresp.key-revocation+json", rev.to_payload())
        signed = SignedRevocation(rev.to_payload(),
                                  get_backend("ml-dsa-87").sign(h.recovery_sk, sb))
        with pytest.raises(Exception, match="was revoked"):
            authorize_for_artifact(
                binding, datetime.datetime(2028, 1, 1, tzinfo=datetime.timezone.utc),
                revocations=[(signed, h.log_time)])
