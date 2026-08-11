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


def verify_pulse_signature(pulse: BeaconPulse, certificate_pem: bytes) -> bool:
    """Check a pulse's RSA signature against NIST's certificate.

    NOT IMPLEMENTED. Documented contract so a verifier and a future
    implementation agree on what is being checked:

      * The signed message is the concatenation of the pulse fields in the
        order given by NISTIR 8213 section 3, each length-prefixed.
      * The signature is RSA PKCS#1 v1.5 over SHA-512.
      * The certificate must chain to NIST's published beacon CA, and
        `certificate_id` in the pulse is the SHA-512 of its DER encoding, so a
        verifier can confirm they fetched the right certificate.

    Until this is implemented, the attestation records everything needed for a
    third party to perform the check themselves, and does not claim the
    signature has been verified. That distinction is the whole point of the
    module: never assert more than has actually been established.
    """
    raise NotImplementedError(
        "Pulse signature verification is a documented contract, not an "
        "implementation. The attestation records the pulse index, value and "
        "signature so a verifier can check it independently at "
        f"{NIST_BEACON_BASE}/chain/<chain>/pulse/<index>."
    )
