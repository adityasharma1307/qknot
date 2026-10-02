"""NIST beacon pulse signatures.

The signed bytes are NISTIR 8213 fields 1-19, length-prefixed. outputValue is
SHA-512 of that message concatenated with the signature. The certificate is
the one whose DER hashes to certificateId.

The vendored pulse is chain 2 pulse 1878255 (2026-07-27), signed by the
4096-bit engine.beacon.nist.gov certificate. From 2026-09-03T21:08Z the
published certificate is 2048-bit while signatureValue stays 512 bytes, so
the absolute latest pulse cannot verify. The live test still requires a
True result: the newest pulse whose published certificate can cover the
signature.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import requests

from qknot.signing.entropy.beacon import (
    NIST_BEACON_BASE,
    NistBeaconBackend,
    _pulse_from_json,
    fetch_beacon_certificate,
    verify_pulse_signature,
)

FIXTURE = Path(__file__).parent / "fixtures" / "beacon"
PULSE = json.loads((FIXTURE / "pulse.json").read_text(encoding="utf-8"))
CERT = (FIXTURE / "certificate.pem").read_bytes()


def test_the_vendored_pulse_verifies():
    pulse = _pulse_from_json(PULSE)
    assert verify_pulse_signature(pulse, CERT) is True


def test_flipping_output_value_fails():
    body = json.loads(json.dumps(PULSE))
    value = bytearray(bytes.fromhex(body["pulse"]["outputValue"]))
    value[0] ^= 0x01
    body["pulse"]["outputValue"] = value.hex()
    pulse = _pulse_from_json(body)
    assert verify_pulse_signature(pulse, CERT) is False


def test_a_missing_certificate_is_false_not_an_exception():
    pulse = _pulse_from_json(PULSE)
    assert verify_pulse_signature(pulse, b"") is False
    assert verify_pulse_signature(pulse, b"not a certificate") is False


def _live_pulse(chain: int, index: int):
    response = requests.get(
        f"{NIST_BEACON_BASE}/chain/{chain}/pulse/{index}",
        timeout=30,
        headers={"User-Agent": "qknot/0.2 (research)", "Accept": "application/json"},
    )
    assert response.status_code == 200, (index, response.status_code)
    return _pulse_from_json(response.json())


def _live_ok(pulse, cache: dict[str, bytes]) -> bool:
    cid = pulse.certificate_id or ""
    if cid not in cache:
        cache[cid] = fetch_beacon_certificate(cid)
    return verify_pulse_signature(pulse, cache[cid])


@pytest.mark.allow_network
def test_live_refetch_of_the_vendored_pulse_verifies():
    """The fixture is not the only evidence. NIST still serves this pulse."""
    response = requests.get(
        PULSE["pulse"]["uri"], timeout=30,
        headers={"User-Agent": "qknot/0.2 (research)", "Accept": "application/json"},
    )
    assert response.status_code == 200, response.status_code
    pulse = _pulse_from_json(response.json())
    pem = fetch_beacon_certificate(pulse.certificate_id or "")
    assert verify_pulse_signature(pulse, pem) is True


@pytest.mark.allow_network
def test_the_current_pulse_verifies_when_its_certificate_can_sign():
    """Live check must come back True, not accept a failed signature.

    If the latest pulse verifies, that is the result. If NIST has published
    a certificate whose key is shorter than signatureValue, walk back to the
    newest pulse that certificate can actually sign and require True there.
    The unverifiable latest pulse must still be False.
    """
    latest = NistBeaconBackend().fetch_pulse()
    cache: dict[str, bytes] = {}
    if _live_ok(latest, cache):
        return

    chain = latest.chain_index
    lo, hi = 1, latest.pulse_index
    last_good = None
    while lo <= hi:
        mid = (lo + hi) // 2
        if _live_ok(_live_pulse(chain, mid), cache):
            last_good = mid
            lo = mid + 1
        else:
            hi = mid - 1
    assert last_good is not None
    assert _live_ok(_live_pulse(chain, last_good), cache) is True
    assert _live_ok(latest, cache) is False
