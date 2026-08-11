"""What the signatures actually cover.

HISTORY, KEPT BECAUSE IT IS THE POINT OF THE FILE
=================================================
This file was written to *document a gap*. The signatures used to cover
`binding.binding_bytes` alone -- suite, digest, digest algorithm, context -- so
the entropy attestation, backend descriptors and signer notes travelled inside
the DSSE envelope, looked signed to any reader, and were covered by nothing. An
attacker could re-serialise a bundle, set `sideChannelResistant: true`, delete
the note recording a PRNG fallback, and verification still passed.

The tests below used to assert that forgery *succeeded*. They now assert it is
rejected, because signing moved to the DSSE pre-authentication encoding over the
whole statement (see dsse.py). Each attack is kept rather than deleted: a test
that once demonstrated a weakness is the best regression test for the fix, and
if someone later reverts to signing the binding alone these fail immediately.

The remaining honest caveat -- that signed metadata is tamper-evident but still
self-asserted -- is pinned at the bottom.
"""
from __future__ import annotations

import base64
import json

import pytest

pytest.importorskip("cryptography", reason="needs `cryptography`")
pytest.importorskip("dilithium_py", reason="needs `dilithium-py`")

from qknot.signing.backends import Exposure  # noqa: E402
from qknot.signing.bundle import build_bundle, parse_bundle  # noqa: E402
from qknot.signing.dsse import DSSE_PAYLOAD_TYPE, pae  # noqa: E402
from qknot.signing.sign import (  # noqa: E402
    VerificationFailed,
    VerifyMode,
    keygen,
    sign,
    verify,
)

SUITE = ["ed25519", "ml-dsa-44"]


@pytest.fixture(scope="module")
def artefact(tmp_path_factory):
    root = tmp_path_factory.mktemp("m")
    (root / "w.bin").write_bytes(b"w" * 256)
    return root


@pytest.fixture(scope="module")
def signed(artefact):
    keys = keygen(suite=SUITE, seed=b"\x5a" * 32)
    return sign(artefact, keys, exposure=Exposure.OFFLINE, subject_name="m")


def _edit_payload(bundle: dict, mutate) -> dict:
    """Apply `mutate` to the statement and re-encode the envelope payload."""
    statement = json.loads(base64.b64decode(bundle["dsseEnvelope"]["payload"]))
    mutate(statement)
    bundle["dsseEnvelope"]["payload"] = base64.b64encode(
        json.dumps(statement, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    return bundle


class TestMetadataForgeryIsNowDetected:
    """Each of these passed verification before the PAE change."""

    def test_flipping_the_side_channel_claim_is_rejected(self, artefact, signed):
        bundle = _edit_payload(
            build_bundle(signed),
            lambda s: s["subject"][0]["backends"]["ml-dsa-44"].__setitem__(
                "sideChannelResistant", True),
        )
        with pytest.raises(VerificationFailed, match="signature is invalid"):
            verify(artefact, parse_bundle(bundle), mode=VerifyMode.STRICT)

    def test_deleting_a_prng_fallback_note_is_rejected(self, artefact, signed):
        """The note a reader most wants to trust, and the easiest to remove."""
        bundle = _edit_payload(
            build_bundle(signed), lambda s: s["subject"][0].__setitem__("notes", []))
        with pytest.raises(VerificationFailed, match="signature is invalid"):
            verify(artefact, parse_bundle(bundle), mode=VerifyMode.STRICT)

    def test_inventing_a_quantum_entropy_source_is_rejected(self, artefact, signed):
        bundle = _edit_payload(
            build_bundle(signed),
            lambda s: s["subject"][0].__setitem__("entropyAttestation", {
                "kdf": "HKDF-SHA3-256",
                "contributions": [{"backend": "anu", "role": "secret",
                                   "is_quantum": True}],
            }),
        )
        with pytest.raises(VerificationFailed, match="signature is invalid"):
            verify(artefact, parse_bundle(bundle), mode=VerifyMode.STRICT)

    def test_swapping_the_subject_name_is_rejected(self, artefact, signed):
        """Relabelling a signature as covering a different artefact."""
        bundle = _edit_payload(
            build_bundle(signed),
            lambda s: s["subject"][0].__setitem__("name", "openai/gpt-5"))
        with pytest.raises(VerificationFailed, match="signature is invalid"):
            verify(artefact, parse_bundle(bundle), mode=VerifyMode.STRICT)

    def test_even_classical_mode_rejects_metadata_forgery(self, artefact, signed):
        """Coverage is a property of the signature, not of the mode. Unlike the
        binding check -- which only STRICT performs -- this holds everywhere."""
        bundle = _edit_payload(
            build_bundle(signed),
            lambda s: s["subject"][0].__setitem__("notes", ["signed on an HSM"]))
        with pytest.raises(VerificationFailed, match="signature is invalid"):
            verify(artefact, parse_bundle(bundle), mode=VerifyMode.CLASSICAL)


class TestThePayloadIsCarriedVerbatim:
    def test_a_roundtrip_still_verifies(self, artefact, signed):
        parsed = parse_bundle(build_bundle(signed))
        assert verify(artefact, parsed, mode=VerifyMode.STRICT)["verified"]

    def test_the_bundle_payload_is_exactly_what_was_signed(self, signed):
        bundle = build_bundle(signed)
        assert base64.b64decode(bundle["dsseEnvelope"]["payload"]) == signed.payload

    def test_reserialising_identically_is_still_accepted(self, artefact, signed):
        """Our canonical form round-trips, so an honest re-encode is not
        punished. This is what makes verbatim carriage a safety net rather than
        a brittleness."""
        bundle = _edit_payload(build_bundle(signed), lambda s: None)
        assert verify(artefact, parse_bundle(bundle),
                      mode=VerifyMode.STRICT)["verified"]

    def test_signatures_cover_the_pae_not_the_raw_payload(self, signed):
        """Signing the payload directly would let a signature over one
        payloadType be replayed as one over another."""
        from qknot.signing.backends import get_backend

        backend = get_backend("ed25519")
        assert backend.verify(signed.public_keys["ed25519"],
                              pae(DSSE_PAYLOAD_TYPE, signed.payload),
                              signed.signatures["ed25519"])
        assert not backend.verify(signed.public_keys["ed25519"], signed.payload,
                                  signed.signatures["ed25519"])

    def test_a_payloadless_artefact_fails_clearly(self, artefact, signed):
        """Rather than as a mysterious invalid signature."""
        from dataclasses import replace

        with pytest.raises(ValueError, match="must be re-signed"):
            verify(artefact, replace(signed, payload=b""))


class TestTheRemainingCaveatIsStated:
    """Tamper-evident is not the same as witnessed, and the report says so."""

    def test_signed_claims_are_reported(self, artefact, signed):
        report = verify(artefact, signed, mode=VerifyMode.STRICT)
        claims = report["signed_claims"]
        assert claims["backends"]["ml-dsa-44"]["sideChannelResistant"] is False
        assert any("non-constant-time" in n for n in claims["signer_notes"])

    def test_the_report_does_not_claim_they_were_witnessed(self, artefact, signed):
        report = verify(artefact, signed, mode=VerifyMode.STRICT)
        note = report["signed_claims"]["_note"]
        assert "asserted by the signer" in note
        assert "not independently witnessed" in note

    def test_the_old_unverified_section_is_gone(self, artefact, signed):
        """It described a gap that no longer exists; leaving it would understate
        what verification now establishes."""
        report = verify(artefact, signed, mode=VerifyMode.STRICT)
        assert "unverified_claims" not in report
