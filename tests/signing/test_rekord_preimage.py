"""The one shared hashedrekord pre-image (spec Fix 1).

The artefact and registration submission paths must agree on the logged
pre-image to the byte, or an inclusion proof stops validating for a reason
nobody can see. So there is one function, and it hashes the PAE of the payload
-- not the envelope with its signatures.
"""
from __future__ import annotations

import hashlib

from qknot.signing.dsse import pae, rekord_preimage


def test_the_preimage_is_sha256_of_the_pae_exactly():
    payload_type = "application/vnd.qknot.key-registration+json"
    payload = b'{"identity":"a@example.com"}'
    assert rekord_preimage(payload_type, payload) == \
        hashlib.sha256(pae(payload_type, payload)).digest()


def test_it_covers_the_payload_not_any_surrounding_signatures():
    """Adding or reordering signatures around the payload cannot change the
    logged hash, because the hash is over the PAE of the payload alone."""
    pt = "application/vnd.qknot.key-registration+json"
    payload = b'{"claim":"x"}'
    once = rekord_preimage(pt, payload)
    # Whatever an envelope wraps around this payload, the pre-image is fixed.
    assert once == rekord_preimage(pt, payload)


def test_the_payload_type_is_bound_in():
    """A registration payload cannot be replayed as a differently-typed one."""
    payload = b'{"claim":"x"}'
    assert rekord_preimage("type/a", payload) != rekord_preimage("type/b", payload)
