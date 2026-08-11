"""Fulcio-style chain verification (spec steps 3-4), against a minted CA.

The whole trust chain is validated offline: a root CA signs an intermediate,
the intermediate signs a Fulcio-style leaf carrying a SAN identity and an OIDC
issuer extension. This is exactly what runs in production; only the certificate
ACQUISITION is a network flow, and it produces the same bytes tested here.
"""
from __future__ import annotations

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.oid import NameOID

from qknot.signing.fulcio import ChainError, verify_chain

ISSUER_OID_V1 = x509.ObjectIdentifier("1.3.6.1.4.1.57264.1.1")
NOW = datetime.datetime.now(datetime.timezone.utc)


def _ca(name, issuer_key=None, issuer_name=None):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    signer_key = issuer_key or key
    signer_name = issuer_name or subject
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(signer_name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - datetime.timedelta(days=1))
            .not_valid_after(NOW + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(signer_key, hashes.SHA256()))
    return key, subject, cert


def _leaf(issuer_key, issuer_name, identity="alice@example.com",
          issuer="https://accounts.google.com"):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]))
            .issuer_name(issuer_name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - datetime.timedelta(minutes=5))
            .not_valid_after(NOW + datetime.timedelta(minutes=10))
            .add_extension(x509.SubjectAlternativeName(
                [x509.RFC822Name(identity)]), critical=False)
            .add_extension(x509.UnrecognizedExtension(
                ISSUER_OID_V1, issuer.encode("utf-8")), critical=False)
            .sign(issuer_key, hashes.SHA256()))
    return key, cert


@pytest.fixture
def chain():
    root_key, root_name, root = _ca("Test Fulcio Root")
    int_key, int_name, inter = _ca("Test Intermediate", root_key, root_name)
    leaf_key, leaf = _leaf(int_key, int_name)
    return {
        "leaf": leaf.public_bytes(Encoding.DER),
        "intermediates": [inter.public_bytes(Encoding.DER)],
        "roots": [root.public_bytes(Encoding.DER)],
        "leaf_key": leaf_key,
    }


class TestAValidChain:
    def test_it_validates_and_returns_the_identity(self, chain):
        fid = verify_chain(chain["leaf"], chain["intermediates"], chain["roots"])
        assert fid.identity == "alice@example.com"
        assert fid.issuer == "https://accounts.google.com"


class TestItRejects:
    def test_an_empty_trust_store_is_a_config_error(self, chain):
        with pytest.raises(ChainError, match="configuration error"):
            verify_chain(chain["leaf"], chain["intermediates"], [])

    def test_a_chain_to_an_untrusted_root(self, chain):
        other_root_key, other_name, other_root = _ca("Someone Else's Root")
        with pytest.raises(ChainError, match="not among the trusted roots"):
            verify_chain(chain["leaf"], chain["intermediates"],
                         [other_root.public_bytes(Encoding.DER)])

    def test_a_leaf_signed_by_a_key_not_in_the_chain(self, chain):
        """A leaf minted by a rogue intermediate the real root never signed."""
        rogue_key, rogue_name, _ = _ca("Rogue Intermediate")
        rogue_leaf_key, rogue_leaf = _leaf(rogue_key, rogue_name)
        with pytest.raises(ChainError, match="not signed by|not among"):
            verify_chain(rogue_leaf.public_bytes(Encoding.DER),
                         chain["intermediates"], chain["roots"])

    def test_an_expired_leaf(self):
        root_key, root_name, root = _ca("Root")
        int_key, int_name, inter = _ca("Int", root_key, root_name)
        key = ec.generate_private_key(ec.SECP256R1())
        past = NOW - datetime.timedelta(days=30)
        expired = (x509.CertificateBuilder()
                   .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]))
                   .issuer_name(int_name).public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(past - datetime.timedelta(days=1))
                   .not_valid_after(past)
                   .add_extension(x509.SubjectAlternativeName(
                       [x509.RFC822Name("a@b.com")]), critical=False)
                   .add_extension(x509.UnrecognizedExtension(
                       ISSUER_OID_V1, b"https://issuer"), critical=False)
                   .sign(int_key, hashes.SHA256()))
        with pytest.raises(ChainError, match="outside"):
            verify_chain(expired.public_bytes(Encoding.DER),
                         [inter.public_bytes(Encoding.DER)],
                         [root.public_bytes(Encoding.DER)])

    def test_a_leaf_with_no_issuer_extension(self):
        root_key, root_name, root = _ca("Root")
        int_key, int_name, inter = _ca("Int", root_key, root_name)
        key = ec.generate_private_key(ec.SECP256R1())
        no_issuer = (x509.CertificateBuilder()
                     .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")]))
                     .issuer_name(int_name).public_key(key.public_key())
                     .serial_number(x509.random_serial_number())
                     .not_valid_before(NOW - datetime.timedelta(minutes=1))
                     .not_valid_after(NOW + datetime.timedelta(minutes=10))
                     .add_extension(x509.SubjectAlternativeName(
                         [x509.RFC822Name("a@b.com")]), critical=False)
                     .sign(int_key, hashes.SHA256()))
        with pytest.raises(ChainError, match="no OIDC issuer"):
            verify_chain(no_issuer.public_bytes(Encoding.DER),
                         [inter.public_bytes(Encoding.DER)],
                         [root.public_bytes(Encoding.DER)])


class TestPathDiscovery:
    """verify_chain builds the path from an UNORDERED pool (residual 1): callers
    no longer pre-sort intermediates, and a TUF-style CA pool works as-is."""

    def _two_level(self):
        root_key, root_name, root = _ca("Disco Root")
        ia_key, ia_name, ia = _ca("Disco IA", root_key, root_name)   # signed by root
        ib_key, ib_name, ib = _ca("Disco IB", ia_key, ia_name)       # signed by IA
        _leaf_key, leaf = _leaf(ib_key, ib_name)                     # signed by IB
        return root, [ia, ib], leaf

    def test_intermediates_in_any_order_validate(self):
        root, inters, leaf = self._two_level()
        ders = [c.public_bytes(Encoding.DER) for c in inters]
        for order in ([0, 1], [1, 0]):
            fid = verify_chain(leaf.public_bytes(Encoding.DER),
                               [ders[i] for i in order],
                               [root.public_bytes(Encoding.DER)])
            assert fid.identity == "alice@example.com"

    def test_an_unordered_ca_pool_as_roots_validates(self):
        """The trusted_root.json shape: root AND intermediates in one unordered
        trusted pool, no separate intermediates argument."""
        root, inters, leaf = self._two_level()
        pool = [c.public_bytes(Encoding.DER)
                for c in [inters[1], root, inters[0]]]        # shuffled
        fid = verify_chain(leaf.public_bytes(Encoding.DER), [], pool)
        assert fid.issuer == "https://accounts.google.com"

    def test_an_unrelated_extra_ca_in_the_pool_is_ignored(self):
        root, inters, leaf = self._two_level()
        _k, _n, junk = _ca("Unrelated CA")
        fid = verify_chain(
            leaf.public_bytes(Encoding.DER),
            [inters[0].public_bytes(Encoding.DER),
             inters[1].public_bytes(Encoding.DER),
             junk.public_bytes(Encoding.DER)],
            [root.public_bytes(Encoding.DER)])
        assert fid.identity == "alice@example.com"

    def test_a_lookalike_root_in_the_bundle_cannot_shadow_the_real_root(self):
        """An untrusted cert carrying the real root's subject name but a
        different key must not displace the trusted root: trusted bytes win."""
        root, inters, leaf = self._two_level()
        fake_key = ec.generate_private_key(ec.SECP256R1())
        rn = root.subject
        fake = (x509.CertificateBuilder().subject_name(rn).issuer_name(rn)
                .public_key(fake_key.public_key())
                .serial_number(x509.random_serial_number())
                .not_valid_before(NOW - datetime.timedelta(days=1))
                .not_valid_after(NOW + datetime.timedelta(days=365))
                .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                               critical=True)
                .sign(fake_key, hashes.SHA256()))
        fid = verify_chain(
            leaf.public_bytes(Encoding.DER),
            [inters[0].public_bytes(Encoding.DER),
             inters[1].public_bytes(Encoding.DER),
             fake.public_bytes(Encoding.DER)],          # shadow attempt
            [root.public_bytes(Encoding.DER)])
        assert fid.identity == "alice@example.com"

    def test_a_cross_signed_loop_is_refused(self):
        ka = ec.generate_private_key(ec.SECP256R1())
        kb = ec.generate_private_key(ec.SECP256R1())
        na = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Loop A")])
        nb = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Loop B")])

        def _ca_named(subject, subject_key, issuer, issuer_key):
            return (x509.CertificateBuilder()
                    .subject_name(subject).issuer_name(issuer)
                    .public_key(subject_key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(NOW - datetime.timedelta(days=1))
                    .not_valid_after(NOW + datetime.timedelta(days=365))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                                   critical=True)
                    .sign(issuer_key, hashes.SHA256()))

        a = _ca_named(na, ka, nb, kb)          # A signed by B
        b = _ca_named(nb, kb, na, ka)          # B signed by A -> a loop
        _lk, leaf = _leaf(ka, na)              # leaf issued by A
        _rk, _rn, root = _ca("Loop Trusted Root")
        with pytest.raises(ChainError, match="loops|not among"):
            verify_chain(leaf.public_bytes(Encoding.DER),
                         [a.public_bytes(Encoding.DER), b.public_bytes(Encoding.DER)],
                         [root.public_bytes(Encoding.DER)])
