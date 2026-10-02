"""Publicly verifiable randomness from the NIST Randomness Beacon.

WHY A BEACON AND NOT JUST A QRNG API
====================================
A plain QRNG web service hands you bytes and nothing else. There is no way for
anyone reading a paper -- or auditing a signature years later -- to check that
those bytes came from where the signer says they did. The quantum claim rests
entirely on trusting the signer's log, which makes it unfalsifiable, and an
unfalsifiable claim is not evidence.

The NIST beacon is different in the one way that matters: every pulse is
**signed, timestamped, hash-chained and permanently retrievable**. A verifier
fetches pulse N from NIST, checks the RSA signature against NIST's certificate,
and confirms the exact value the signer used. The entropy source behind it is
quantum -- entangled photon pairs measured in a Bell test -- so the randomness
is physically, not merely computationally, unpredictable.

THE CATCH, WHICH IS NOT OPTIONAL TO UNDERSTAND
==============================================
**Beacon output is public.** Every pulse is on a website. Anyone can read it.

Using a beacon pulse as key material would therefore hand every key to the
world. This module exists to provide *verifiable public randomness*, and its
output is only ever used as an HKDF **salt**, combined with a secret local
source. See `mixing.py`, where that separation is enforced rather than merely
recommended: a mix containing no secret contribution raises.

WHAT THE BEACON ADDS THAT SECRECY CANNOT
========================================
Two things, neither available from `os.urandom`:

  * **Public verifiability.** A reader can confirm the salt independently.
  * **A timestamp lower bound.** Pulse N did not exist before its publication
    time, so a key derived from it demonstrably was not generated earlier.
    That is a real, checkable claim about *when* a key came into being, which
    is exactly the property the temporal trust boundary in the verifier needs.

Neither of these is a secrecy property. The secrecy comes from the local
CSPRNG. The beacon contributes auditability.

REFERENCES
    NISTIR 8213, "A Reference for Randomness Beacons: Format and Protocol
    Version 2". Pulses carry 512 bits, are emitted every 60 seconds, and are
    signed with RSA PKCS#1 v1.5 over SHA-512.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from .backends import QrngUnavailable

log = logging.getLogger(__name__)

NIST_BEACON_BASE = "https://beacon.nist.gov/beacon/2.0"
BEACON_PULSE_BYTES = 64  # 512 bits


@dataclass(frozen=True)
class BeaconPulse:
    """One beacon pulse, with everything a third party needs to re-check it."""

    chain_index: int
    pulse_index: int
    timestamp: str
    output_value: str          # 64-byte hex; PUBLIC
    signature_value: str       # RSA signature over the pulse
    uri: str
    version: str = "2.0"
    status_code: int | None = None
    certificate_id: str | None = None
    previous_output: str | None = None
    raw: dict[str, Any] | None = None

    @property
    def value(self) -> bytes:
        return bytes.fromhex(self.output_value)

    def to_reference(self) -> dict[str, Any]:
        """The subset a verifier needs to re-fetch and re-check this pulse.

        The output value is included in full because it is already public, and
        omitting it would force a verifier to trust that our pulse index refers
        to the value we actually used.
        """
        return {
            "source": "nist-beacon-2.0",
            "chain_index": self.chain_index,
            "pulse_index": self.pulse_index,
            "timestamp": self.timestamp,
            "output_value": self.output_value,
            "signature_value": self.signature_value,
            "certificate_id": self.certificate_id,
            "uri": self.uri,
            "verify_url": f"{NIST_BEACON_BASE}/chain/{self.chain_index}"
                          f"/pulse/{self.pulse_index}",
        }


def _pulse_from_json(payload: dict[str, Any]) -> BeaconPulse:
    pulse = payload.get("pulse", payload)
    required = ("chainIndex", "pulseIndex", "timeStamp", "outputValue", "signatureValue")
    missing = [k for k in required if k not in pulse]
    if missing:
        raise QrngUnavailable(f"beacon pulse missing fields: {missing}")
    return BeaconPulse(
        chain_index=int(pulse["chainIndex"]),
        pulse_index=int(pulse["pulseIndex"]),
        timestamp=str(pulse["timeStamp"]),
        output_value=str(pulse["outputValue"]),
        signature_value=str(pulse["signatureValue"]),
        uri=str(pulse.get("uri", "")),
        version=str(pulse.get("version", "2.0")),
        status_code=pulse.get("statusCode"),
        certificate_id=pulse.get("certificateId"),
        previous_output=pulse.get("previousOutputValue"),
        raw=pulse,
    )


class NistBeaconBackend:
    """Public, signed, quantum-sourced randomness from the NIST beacon.

    `is_public` is the field that matters. Every other backend in this package
    produces secret bytes; this one does not, and the mixing layer refuses to
    build a seed from public contributions alone.
    """

    name = "nist-beacon"
    is_quantum = True
    is_public = True

    def __init__(self, timeout: float = 30.0, session: Any = None,
                 pulse_index: int | None = None) -> None:
        """
        Args:
            pulse_index: fetch a specific historical pulse instead of the
                latest. This is what makes a published result reproducible: a
                reader re-runs with the pulse index from the attestation and
                obtains the identical salt.
        """
        self.timeout = timeout
        self._session = session
        self.pulse_index = pulse_index
        self.last_pulse: BeaconPulse | None = None

    def _get_session(self) -> Any:
        if self._session is None:
            import requests

            self._session = requests.Session()
        return self._session

    def fetch_pulse(self) -> BeaconPulse:
        session = self._get_session()
        if self.pulse_index is not None:
            url = f"{NIST_BEACON_BASE}/chain/1/pulse/{self.pulse_index}"
        else:
            url = f"{NIST_BEACON_BASE}/pulse/last"

        try:
            response = session.get(
                url, timeout=self.timeout,
                headers={"User-Agent": "qknot/0.2 (research)", "Accept": "application/json"},
            )
        except Exception as exc:
            raise QrngUnavailable(f"NIST beacon unreachable: {exc}") from exc

        if response.status_code != 200:
            raise QrngUnavailable(f"NIST beacon returned HTTP {response.status_code}")

        try:
            payload = response.json()
        except Exception as exc:
            raise QrngUnavailable(f"NIST beacon response was not JSON: {exc}") from exc
        if not isinstance(payload, dict):
            raise QrngUnavailable("NIST beacon response was not a JSON object")

        pulse = _pulse_from_json(payload)

        if len(pulse.value) != BEACON_PULSE_BYTES:
            raise QrngUnavailable(
                f"beacon pulse is {len(pulse.value)} bytes, expected {BEACON_PULSE_BYTES}"
            )
        self.last_pulse = pulse
        return pulse

    def get_bytes(self, n: int) -> bytes:
        """Return n bytes of PUBLIC beacon randomness.

        A pulse is 64 bytes. Requests beyond that are refused rather than
        stretched: expanding public randomness with a public KDF yields more
        public bytes and no more entropy, and a caller asking for 256 bytes of
        "randomness" from a beacon has misunderstood what it is for.
        """
        if n <= 0:
            raise ValueError("n must be positive")
        if n > BEACON_PULSE_BYTES:
            raise ValueError(
                f"a beacon pulse carries {BEACON_PULSE_BYTES} bytes; asking for {n} "
                f"suggests the beacon is being used as a key source. It is public "
                f"randomness for use as an HKDF salt -- see mixing.py."
            )
        return self.fetch_pulse().value[:n]

    def describe(self) -> dict[str, Any]:
        described: dict[str, Any] = {
            "endpoint": NIST_BEACON_BASE,
            "authenticated": False,
            "is_public": True,
        }
        if self.last_pulse is not None:
            described["pulse"] = self.last_pulse.to_reference()
            described["not_before"] = self.last_pulse.timestamp
        return described


def _u32(value: int) -> bytes:
    return int(value).to_bytes(4, "big")


def _u64(value: int) -> bytes:
    return int(value).to_bytes(8, "big")


def _len_prefixed(payload: bytes) -> bytes:
    return len(payload).to_bytes(4, "big") + payload


def _hex_field(value: str) -> bytes:
    return _len_prefixed(bytes.fromhex(value))


def _previous(pulse: dict[str, Any], kind: str) -> str:
    for item in pulse.get("listValues") or []:
        if item.get("type") == kind:
            return str(item["value"])
    raise KeyError(kind)


def _signed_message(pulse: dict[str, Any]) -> bytes:
    """NISTIR 8213 fields 1–19, length-prefixed, as the NIST beacon signs them.

    Confirmed against a live pulse: SHA-512(message || signature) equals
    outputValue. Strings are UTF-8 with a 4-byte big-endian length. Hashes are
    raw bytes with the same length prefix. Integers are big-endian (4 bytes
    for cipher, period, status, external status; 8 for chain and pulse index).
    """
    external = pulse["external"]
    parts = [
        _len_prefixed(str(pulse["uri"]).encode("utf-8")),
        _len_prefixed(str(pulse["version"]).encode("utf-8")),
        _u32(pulse["cipherSuite"]),
        _u32(pulse["period"]),
        _hex_field(pulse["certificateId"]),
        _u64(pulse["chainIndex"]),
        _u64(pulse["pulseIndex"]),
        _len_prefixed(str(pulse["timeStamp"]).encode("utf-8")),
        _hex_field(pulse["localRandomValue"]),
        _hex_field(external["sourceId"]),
        _u32(external["statusCode"]),
        _hex_field(external["value"]),
    ]
    for kind in ("previous", "hour", "day", "month", "year"):
        parts.append(_hex_field(_previous(pulse, kind)))
    parts.append(_hex_field(pulse["precommitmentValue"]))
    parts.append(_u32(pulse["statusCode"]))
    return b"".join(parts)


def fetch_beacon_certificate(certificate_id: str, *, timeout: float = 30.0,
                             session: Any = None) -> bytes:
    """PEM bytes NIST serves for a pulse's certificateId."""
    import requests

    http = session or requests.Session()
    url = f"{NIST_BEACON_BASE}/certificate/{certificate_id}"
    try:
        response = http.get(
            url, timeout=timeout,
            headers={"User-Agent": "qknot/0.2 (research)", "Accept": "*/*"},
        )
    except Exception as exc:
        raise QrngUnavailable(f"NIST beacon certificate unreachable: {exc}") from exc
    if response.status_code != 200 or not response.content.startswith(b"-----BEGIN"):
        raise QrngUnavailable(
            f"NIST beacon certificate HTTP {response.status_code} for {certificate_id}"
        )
    return bytes(response.content)


def verify_pulse_signature(pulse: BeaconPulse, certificate_pem: bytes) -> bool:
    """RSA PKCS#1 v1.5 SHA-512 over the NISTIR 8213 pulse encoding.

    Returns False when the certificate is missing, is not the one named by
    certificateId (SHA-512 of its DER), the signature does not verify, or
    outputValue is not SHA-512(message || signature). A failed check is False,
    not an exception and not a skip.
    """
    import hashlib

    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    from cryptography.x509 import load_pem_x509_certificate

    raw = pulse.raw
    if not certificate_pem or raw is None:
        return False
    try:
        certificate = load_pem_x509_certificate(certificate_pem)
        message = _signed_message(raw)
        signature = bytes.fromhex(str(raw["signatureValue"]))
    except (KeyError, TypeError, ValueError):
        return False

    named = pulse.certificate_id or raw.get("certificateId")
    if named:
        der = certificate.public_bytes(serialization.Encoding.DER)
        if hashlib.sha512(der).hexdigest().lower() != str(named).lower():
            return False
    public_key = certificate.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        return False
    if public_key.key_size // 8 != len(signature):
        return False
    try:
        public_key.verify(signature, message, padding.PKCS1v15(), hashes.SHA512())
    except (InvalidSignature, ValueError, TypeError):
        return False

    output = hashlib.sha512(message + signature).hexdigest()
    claimed = str(raw.get("outputValue", ""))
    return output.lower() == claimed.lower()
