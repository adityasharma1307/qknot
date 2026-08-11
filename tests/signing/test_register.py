"""`qknot register` orchestration, offline, against fake network clients.

The two network seams -- Fulcio and Rekor -- are faked with clients that mint the
SAME trust stack the rest of the suite uses: a real minted CA + Fulcio-style
leaf, and a one-leaf transparency tree with a REAL-format checkpoint and SET
(via _rekor_doubles). So the orchestration logic runs end to end here; only the
sockets are stubbed, and the bundle register emits is verified by the same
`verify_registration_chain` a third party would run.

The real-network version -- an actual Fulcio cert and Rekor entry -- is the
residual-3 fixture, captured on a machine with network + OIDC and locked by
test_registration_fixture.py (skips until present).
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
    load_der_public_key,
)
from cryptography.x509.oid import NameOID

from qknot.signing.backends import get_backend
from qknot.signing.register import FulcioCertificate, register
from qknot.signing.registration import RegistrationError
from qknot.signing.registration_chain import verify_registration_chain
from qknot.signing.rekor import hashedrekord_body, leaf_hash
from qknot.signing.temporal import BindingBasis

from ._rekor_doubles import log_id_for, signed_checkpoint, signed_entry_timestamp

ISSUER_OID_V1 = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.1")
IDENTITY = "alice@example.com"
ISSUER = "https://accounts.google.com"


def _now():
    return datetime.datetime.now(datetime.timezone.utc)


class FakeFulcio:
    """Mints a CA and issues a Fulcio-style leaf over the classical key it is
    handed -- exactly the bytes a real Fulcio returns, minus the network."""

    def __init__(self, moment, identity=IDENTITY, issuer=ISSUER):
        self.moment = moment
        self.identity = identity
        self.issuer = issuer
        self.root_key = ec.generate_private_key(ec.SECP256R1())
        self.root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root")])
        self.root = (x509.CertificateBuilder()
                     .subject_name(self.root_name).issuer_name(self.root_name)
                     .public_key(self.root_key.public_key())
                     .serial_number(x509.random_serial_number())
                     .not_valid_before(moment - datetime.timedelta(days=365))
                     .not_valid_after(moment + datetime.timedelta(days=365))
                     .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                                    critical=True)
                     .sign(self.root_key, hashes.SHA256()))

    @property
    def root_der(self):
        return self.root.public_bytes(Encoding.DER)

    def certify(self, classical_public_key_spki_der, classical_secret_pkcs8_der):
        classical_pub = load_der_public_key(classical_public_key_spki_der)
        leaf = (x509.CertificateBuilder()
                .subject_name(x509.Name(
                    [x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]))
                .issuer_name(self.root_name)
                .public_key(classical_pub)
                .serial_number(x509.random_serial_number())
                .not_valid_before(self.moment - datetime.timedelta(minutes=5))
                .not_valid_after(self.moment + datetime.timedelta(minutes=10))
                .add_extension(x509.SubjectAlternativeName(
                    [x509.RFC822Name(self.identity)]), critical=False)
                .add_extension(x509.UnrecognizedExtension(
                    ISSUER_OID_V1, self.issuer.encode("utf-8")), critical=False)
                .sign(self.root_key, hashes.SHA256()))
        return FulcioCertificate(leaf_der=leaf.public_bytes(Encoding.DER),
                                 intermediate_ders=[])


class FakeRekor:
    """A one-leaf transparency tree that answers with a real-format checkpoint
    and SET signed by `log_key`. `sign_with` lets a test point the checkpoint at
    a DIFFERENT key to prove the round-trip gate catches an unverifiable bundle."""

    def __init__(self, moment, log_key=None, sign_with=None):
        self.moment = moment
        self.log_key = log_key or ec.generate_private_key(ec.SECP256R1())
        self.sign_with = sign_with or self.log_key

    @property
    def log_pub(self):
        return self.log_key.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    def submit_hashedrekord(self, *, preimage, classical_signature, certificate_der):
        body = hashedrekord_body(preimage)
        root = leaf_hash(body)                     # one-leaf tree
        integrated = int(self.moment.timestamp())
        log_id = log_id_for(self.sign_with.public_key())
        import base64
        return {
            "logIndex": 42,                         # GLOBAL index
            "logId": {"keyId": base64.b64encode(log_id).decode("ascii")},
            "integratedTime": integrated,
            "inclusionPromise": {
                "signedEntryTimestamp": base64.b64encode(
                    signed_entry_timestamp(body, integrated, log_id, 42,
                                           self.sign_with)).decode("ascii")},
            "inclusionProof": {
                "logIndex": 0,                      # shard-local index
                "rootHash": base64.b64encode(root).decode("ascii"),
                "treeSize": 1,
                "hashes": [],
                "checkpoint": {"envelope": signed_checkpoint(1, root, self.sign_with)},
            },
            "canonicalizedBody": base64.b64encode(body).decode("ascii"),
        }


def _pqc():
    backend = get_backend("ml-dsa-87")
    pub, sk = backend.keygen()
    return pub, sk


class TestRegisterEmitsAVerifiableBundle:
    def test_the_emitted_bundle_verifies_to_a_direct_binding(self):
        moment = _now() - datetime.timedelta(minutes=1)
        fulcio, rekor = FakeFulcio(moment), FakeRekor(moment)
        pqc_pub, pqc_sk = _pqc()
        bundle = register(
            pqc_algorithm="ml-dsa-87", pqc_public_key=pqc_pub, pqc_secret=pqc_sk,
            fulcio=fulcio, rekor=rekor,
            fulcio_roots=[fulcio.root_der], log_public_key=rekor.log_pub,
            created=moment, now=_now())
        # re-verify externally, with no special cases -- the third-party call.
        binding = verify_registration_chain(
            bundle, fulcio_roots=[fulcio.root_der],
            log_public_key=rekor.log_pub, now=_now())
        assert binding.identity == IDENTITY
        assert binding.issuer == ISSUER
        assert binding.pqc_algorithm == "ml-dsa-87"
        assert binding.pqc_public_key == pqc_pub
        assert binding.basis is BindingBasis.DIRECT

    def test_identity_and_issuer_are_taken_from_the_cert_not_free_typed(self):
        moment = _now() - datetime.timedelta(minutes=1)
        # the Fulcio cert attests bob; the caller passes NO identity at all.
        fulcio = FakeFulcio(moment, identity="bob@corp.example",
                            issuer="https://login.corp.example")
        rekor = FakeRekor(moment)
        pqc_pub, pqc_sk = _pqc()
        bundle = register(
            pqc_algorithm="ml-dsa-87", pqc_public_key=pqc_pub, pqc_secret=pqc_sk,
            fulcio=fulcio, rekor=rekor,
            fulcio_roots=[fulcio.root_der], log_public_key=rekor.log_pub,
            created=moment, now=_now())
        from qknot.signing.registration import HybridRegistration
        reg = HybridRegistration.from_payload(bundle.envelope.payload)
        assert reg.identity == "bob@corp.example"
        assert reg.issuer == "https://login.corp.example"


class TestRegisterTemporalRescue:
    def test_a_registration_logged_before_the_deadline_rescues_later(self):
        """Registered and logged in 2028 (before p256 is disallowed 2031-12-31),
        verified in 2040: the log timestamp proves it predates the break."""
        moment = datetime.datetime(2028, 1, 1, tzinfo=datetime.timezone.utc)
        future = datetime.datetime(2040, 1, 1, tzinfo=datetime.timezone.utc)
        fulcio, rekor = FakeFulcio(moment), FakeRekor(moment)
        pqc_pub, pqc_sk = _pqc()
        bundle = register(
            pqc_algorithm="ml-dsa-87", pqc_public_key=pqc_pub, pqc_secret=pqc_sk,
            fulcio=fulcio, rekor=rekor,
            fulcio_roots=[fulcio.root_der], log_public_key=rekor.log_pub,
            created=moment, now=future)
        binding = verify_registration_chain(
            bundle, fulcio_roots=[fulcio.root_der],
            log_public_key=rekor.log_pub, now=future)
        assert binding.basis is BindingBasis.RESCUED


class TestRegisterRoundTripGate:
    def test_register_refuses_a_bundle_that_does_not_verify(self):
        """The mandatory step-8 check bites: if the log's checkpoint is signed by
        a key other than the one the verifier trusts, register must fail rather
        than hand back a bundle that only 'logged'."""
        moment = _now() - datetime.timedelta(minutes=1)
        fulcio = FakeFulcio(moment)
        wrong_key = ec.generate_private_key(ec.SECP256R1())
        rekor = FakeRekor(moment, sign_with=wrong_key)   # checkpoint+SET off-key
        pqc_pub, pqc_sk = _pqc()
        with pytest.raises(RegistrationError, match="does not verify"):
            register(
                pqc_algorithm="ml-dsa-87", pqc_public_key=pqc_pub,
                pqc_secret=pqc_sk, fulcio=fulcio, rekor=rekor,
                fulcio_roots=[fulcio.root_der], log_public_key=rekor.log_pub,
                created=moment, now=_now())
