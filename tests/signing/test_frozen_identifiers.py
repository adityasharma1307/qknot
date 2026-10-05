"""v0.1.1 wire identifiers. Changing one is a new format, not a cleanup."""
from __future__ import annotations

from qknot.signing.backends import KEY_FINGERPRINT_SALT
from qknot.signing.registration import (
    HYBRID_REGISTRATION_PAYLOAD_TYPE,
    REGISTRATION_PAYLOAD_TYPE,
    REVOCATION_PAYLOAD_TYPE,
)
from qknot.signing.sign import KEYGEN_SALT


def test_media_types_and_hkdf_salts_are_the_v0_1_1_strings():
    assert REGISTRATION_PAYLOAD_TYPE == "application/vnd.qknot.key-registration+json"
    assert HYBRID_REGISTRATION_PAYLOAD_TYPE == (
        "application/vnd.qknot.hybrid-key-registration+json"
    )
    assert REVOCATION_PAYLOAD_TYPE == "application/vnd.qknot.key-revocation+json"
    assert KEYGEN_SALT == b"qknot-keygen-v1"
    assert KEY_FINGERPRINT_SALT == b"qknot-key-fingerprint-v1"
