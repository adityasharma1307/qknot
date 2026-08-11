"""Verification against REAL timestamp responses from public authorities.

This closes the gap `test_transparency.py` declares it cannot cover. That file
tests the policy layer against stubs and says so; this one runs the actual
cryptography over tokens obtained from live public TSAs and committed under
`tsa_fixtures/`, alongside a `manifest.json` recording what was timestamped and
when.

Re-capture them with:

    python scripts/verify/capture_tsa_fixtures.py

which is needed whenever MESSAGE changes -- a TSA signs the exact bytes it was
given, so a token cannot be carried across a change to the message it covers.
(That is why the rename to QKnot required re-issuing these: editing the
constant would not have renamed what the authorities already signed.)

They are offline artefacts: nothing here reaches the network, and these tests
run under the suite-wide block in conftest.py like everything else. A timestamp
is signed data, so it keeps proving what it proved on the day it was issued.

WHY THE ROOT IS PINNED BY FINGERPRINT
=====================================
SwissSign's response happens to embed its own root. Verifying against a root
pulled out of the response being verified would be circular -- the token would
be certifying itself -- and would test nothing, since any forged chain carries
a matching forged root. So the root is located in the response and then
CHECKED against a SHA-256 recorded here. If SwissSign rotates its root the
fingerprint stops matching and this test fails loudly, which is the correct
outcome: a trust anchor changing is exactly the event a verifier should not
absorb silently.
"""
from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime
from pathlib import Path

import pytest

pytest.importorskip("rfc3161_client", reason="needs `qknot[transparency]`")

import rfc3161_client  # noqa: E402
from cryptography import x509  # noqa: E402
from cryptography.hazmat.primitives.serialization import Encoding  # noqa: E402

from qknot.signing.temporal import Bound, TimeEvidence  # noqa: E402
from qknot.signing.transparency import (  # noqa: E402
    TimestampError,
    TimestampToken,
    establish_time,
    verify_timestamp,
)

FIXTURES = Path(__file__).parent / "tsa_fixtures"

# The exact bytes the fixtures were timestamped over.
MESSAGE = b"qknot-fixture-v1"

# Written by scripts/verify/capture_tsa_fixtures.py alongside the tokens. The
# filenames and issue times used to be hard-coded here, which meant re-capturing
# required hand-editing five assertions and quietly assumed both authorities
# stamped within the same second -- true once, by luck, and not a property
# either TSA offers. Reading them back from the capture keeps the assertion
# meaningful (verification must recover the time the capture recorded, from a
# token that has not been altered since) without the fragility.
_MANIFEST_PATH = FIXTURES / "manifest.json"

pytestmark = pytest.mark.skipif(
    not _MANIFEST_PATH.exists(),
    reason="no captured TSA fixtures (run "
           "scripts/verify/capture_tsa_fixtures.py)")

_MANIFEST = (json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
             if _MANIFEST_PATH.exists()
             else {"message": MESSAGE.decode(), "tokens": {}})

assert _MANIFEST["message"] == MESSAGE.decode(), (
    f"manifest.json records message {_MANIFEST['message']!r} but this test "
    f"verifies against {MESSAGE.decode()!r}. A TSA signs the bytes it was "
    f"given; re-capture with scripts/verify/capture_tsa_fixtures.py."
)


def _issued(name: str) -> datetime:
    return datetime.fromisoformat(_MANIFEST["tokens"][name]["gen_time"])

# SwissSign Signature Services Root 2020 - 2, DER SHA-256.
SWISSSIGN_ROOT_SHA256 = (
    "b87f292a4d9feace2d669159eb26f56d85ec77c19e01098cd754e8abb310cde5"
)


def _token(name: str, url: str) -> TimestampToken:
    raw = (FIXTURES / name).read_text(encoding="utf-8").strip()
    return TimestampToken(der=base64.b64decode(raw), url=url)


def _certificates(token: TimestampToken) -> list[x509.Certificate]:
    response = rfc3161_client.decode_timestamp_response(token.der)
    return [x509.load_der_x509_certificate(der)
            for der in response.signed_data.certificates]


def _fingerprint(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()


@pytest.fixture
def swisssign() -> TimestampToken:
    return _token(_MANIFEST["tokens"]["swisssign"]["file"],
                  _MANIFEST["tokens"]["swisssign"]["url"])


@pytest.fixture
def sslcom() -> TimestampToken:
    return _token(_MANIFEST["tokens"]["sslcom"]["file"],
                  _MANIFEST["tokens"]["sslcom"]["url"])


def _swisssign_anchor(token: TimestampToken) -> dict[str, object]:
    """Build the trust anchor, refusing to proceed on an unrecognised root."""
    certs = _certificates(token)
    root = next(c for c in certs if c.subject == c.issuer)
    assert _fingerprint(root) == SWISSSIGN_ROOT_SHA256, (
        "the self-signed certificate in this response is not the root this "
        "test pins. Either the fixture was regenerated after a root rotation, "
        "or the chain is not what it claims to be. Do not update the "
        "fingerprint without establishing which."
    )
    leaf = next(c for c in certs if "TSA UNIT" in c.subject.rfc4514_string())
    return {
        "tsa_certificate": leaf,
        "roots": [root],
        "intermediates": [c for c in certs if c is not leaf and c is not root],
    }


class TestARealTokenVerifies:
    """The positive case, with real cryptography over a real token."""

    def test_a_genuine_timestamp_verifies_and_yields_its_time(self, swisssign):
        established = verify_timestamp(swisssign, MESSAGE, **_swisssign_anchor(swisssign))
        assert established == _issued("swisssign")

    def test_the_same_token_over_different_bytes_is_rejected(self, swisssign):
        """The property everything rests on, now against a REAL signature.

        The stubbed version of this test in test_transparency.py could only
        check that the policy layer propagates a failure. This one checks that
        the cryptography actually detects the substitution.
        """
        with pytest.raises(TimestampError, match="does not verify"):
            verify_timestamp(swisssign, b"different-bytes",
                             **_swisssign_anchor(swisssign))

    @pytest.mark.parametrize("label,mutate", [
        ("truncated", lambda d: d[:-1]),
        ("byte flipped in the signed TSTInfo", lambda d: bytes(
            bytearray(d)[:100] + bytes([bytearray(d)[100] ^ 0x01]) + bytearray(d)[101:])),
        ("header corrupted", lambda d: b"\x31" + d[1:]),
    ])
    def test_a_tampered_response_does_not_verify(self, swisssign, label, mutate):
        """Corrupt the token in three distinct ways; each must be rejected.

        These targets are chosen deliberately rather than at a convenient
        offset. An earlier version flipped the byte at len//2, which lands
        inside the certificate blob -- and since `rfc3161-client` does not
        path-validate (see `test_the_root_is_not_path_validated`), corrupting a
        certificate is not reliably fatal. That test passed in isolation and
        failed under the full suite, and rather than tune the offset until it
        went green the target was moved to regions whose integrity the library
        genuinely checks: the DER framing, and the signed TSTInfo itself.

        A test whose outcome depends on which unverified bytes happened to be
        hit is not testing tamper-detection; it is sampling it.
        """
        tampered = TimestampToken(der=mutate(swisssign.der), url=swisssign.url)
        with pytest.raises(TimestampError):
            verify_timestamp(tampered, MESSAGE, **_swisssign_anchor(swisssign))

    def test_verification_needs_no_network(self, swisssign):
        """Explicit: conftest.py blocks sockets, so passing IS the assertion.

        Offline verification is a claim this project makes about itself, and a
        claim about absence is worth testing directly rather than inferring
        from the fact that nothing obviously connects.
        """
        assert verify_timestamp(swisssign, MESSAGE, **_swisssign_anchor(swisssign))


class TestTheAnchorMustComeFromTheVerifier:
    def test_ssl_com_does_not_ship_its_root_at_all(self, sslcom):
        """Empirical support for the design, from a second authority.

        SSL.com's response carries only the leaf and its issuing CA -- no
        self-signed root. So its timestamps CANNOT be verified from the
        response alone; an anchor has to come from somewhere the attacker does
        not control. SwissSign happens to include a root, which makes it
        tempting to just use that, and this is the counterexample showing why
        the API takes anchors as arguments rather than reading them from the
        token.
        """
        assert not any(c.subject == c.issuer for c in _certificates(sslcom)), (
            "SSL.com now embeds a self-signed root; re-check the assumption "
            "that anchors must be supplied externally"
        )

    def test_the_leaf_certificate_is_enforced(self, swisssign, sslcom):
        """`tsa_certificate` is the real security boundary.

        Supply a different authority's leaf and verification fails: the library
        requires the certificate embedded in the response to equal the one the
        verifier passed in. This is the property the design actually rests on.
        """
        anchor = _swisssign_anchor(swisssign)
        with pytest.raises(TimestampError, match="does not verify"):
            verify_timestamp(swisssign, MESSAGE,
                             tsa_certificate=_certificates(sslcom)[0],
                             roots=anchor["roots"],
                             intermediates=anchor["intermediates"])

    def test_the_root_is_not_path_validated(self, swisssign, sslcom):
        """Documents a limitation found by testing, not one designed in.

        This test asserts the *surprising* behaviour on purpose. A SwissSign
        token verifies while an SSL.com CA is passed as its root, so
        `rfc3161-client` accepts `roots`/`intermediates` without building a
        chain to them. The docstring of `verify_timestamp` previously implied
        otherwise; this is what the library measurably does.

        Pinning it has two purposes. It stops anyone reading the API and
        assuming a chain was checked -- the mistake already made here once. And
        if the library later gains path validation, this test fails, which is
        the right way to find out that the security properties changed.

        The property that remains, and is sufficient for time evidence, is
        certificate pinning: see `test_the_leaf_certificate_is_enforced`.
        """
        anchor = _swisssign_anchor(swisssign)
        established = verify_timestamp(
            swisssign, MESSAGE,
            tsa_certificate=anchor["tsa_certificate"],
            roots=[_certificates(sslcom)[-1]],       # deliberately wrong root
            intermediates=[],
        )
        assert established == _issued("swisssign"), (
            "if this now raises, rfc3161-client has gained path validation. "
            "That is good news: update verify_timestamp's docstring, which "
            "currently records that roots are NOT validated."
        )


class TestTheEvidenceProduced:
    def test_a_verified_real_timestamp_becomes_an_upper_bound(self, swisssign):
        """End to end: real token -> verified time -> UPPER bound evidence.

        This is the path that makes temporal.py's rescue branch reachable, and
        until these fixtures existed no test could walk it with real data.
        """
        established = verify_timestamp(swisssign, MESSAGE, **_swisssign_anchor(swisssign))
        evidence = TimeEvidence.from_timestamp_authority(established.isoformat())

        assert evidence.bound is Bound.UPPER
        assert evidence.trusted
        assert evidence.proves_not_after == _issued("swisssign")

    def test_it_can_rescue_a_signature_made_before_a_deadline(self, swisssign):
        """The whole point, demonstrated rather than asserted.

        A classical algorithm disallowed after 2031-12-31 does not invalidate a
        signature shown to have existed in July 2026. Before this evidence
        existed the rescue branch could not be entered from any real artefact.
        """
        from qknot.signing.algorithms import REGISTRY

        established = verify_timestamp(swisssign, MESSAGE, **_swisssign_anchor(swisssign))
        deadline = REGISTRY["ed25519"].disallowed_after_date

        assert deadline is not None
        assert established < deadline, (
            "fixture must predate the deprecation deadline for this to "
            "demonstrate a rescue"
        )
        assert TimeEvidence.from_timestamp_authority(
            established.isoformat()).proves_not_after < deadline


class TestEndToEndPolicy:
    def test_establish_time_accepts_one_real_token_at_threshold_one(self, swisssign):
        """`establish_time` over real cryptography, not a stub.

        Threshold 1 because only SwissSign's root is pinned here. A genuine
        two-source test needs SSL.com's root vendored as well -- see
        `test_ssl_com_does_not_ship_its_root_at_all`, which is why it is not
        simply lifted from the response.
        """
        established = establish_time(
            [swisssign], MESSAGE,
            anchors={swisssign.url: _swisssign_anchor(swisssign)},
            threshold=1,
        )
        assert established == _issued("swisssign")

    def test_the_default_threshold_still_refuses_a_single_source(self, swisssign):
        """Even a genuine, verified token is not enough on its own."""
        with pytest.raises(TimestampError, match="need 2"):
            establish_time([swisssign], MESSAGE,
                           anchors={swisssign.url: _swisssign_anchor(swisssign)})


class TestTheFixturesThemselves:
    @pytest.mark.parametrize("authority", ["swisssign", "sslcom"])
    def test_each_fixture_parses_under_strict_der(self, authority):
        """Both authorities emit canonical DER -- which is why they were chosen.

        Three of the eight probed on 2026-07-30, including DigiCert and Apple,
        did not, and are unusable with a strict parser. See DEFAULT_TSA_URLS.
        """
        entry = _MANIFEST["tokens"][authority]
        assert _token(entry["file"], entry["url"]).gen_time == _issued(authority)
