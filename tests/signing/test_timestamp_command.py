"""Attaching an RFC 3161 upper bound to a bundle.

The signed DSSE payload is left alone. The token sits beside it. A missing
`qknot[transparency]` extra is a hard error, not a skip.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from qknot.cli import app
from qknot.signing.transparency import (
    TimestampToken,
    attach_timestamp,
    bundle_signature_message,
    request_timestamp,
    verify_timestamp,
)

runner = CliRunner()


def _bundle() -> dict:
    return {
        "dsseEnvelope": {
            "payload": base64.b64encode(b"{}").decode(),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [
                {"keyid": "ml-dsa-87", "sig": base64.b64encode(b"pq").decode()},
                {"keyid": "ed25519", "sig": base64.b64encode(b"ed").decode()},
            ],
        }
    }


def test_the_timestamp_covers_signatures_in_keyid_order():
    message = bundle_signature_message(_bundle())
    assert message == b"ed" + b"pq"


def test_attach_timestamp_does_not_rewrite_the_signed_payload(monkeypatch):
    bundle = _bundle()

    def fake(message, url, **kwargs):
        assert message == b"ed" + b"pq"
        return TimestampToken(der=b"\x30\x03\x02\x01\x00", url=url)

    monkeypatch.setattr("qknot.signing.transparency.request_timestamp", fake)
    stamped = attach_timestamp(bundle, "http://tsa.example")
    assert stamped["dsseEnvelope"] == bundle["dsseEnvelope"]
    assert stamped["timeEvidence"]["tokens"][0]["kind"] == "rfc3161"
    assert stamped["timeEvidence"]["message_sha256"]


def test_timestamp_without_the_extra_names_the_install(monkeypatch, tmp_path: Path):
    monkeypatch.setitem(sys.modules, "rfc3161_client", None)
    bundle = tmp_path / "b.json"
    bundle.write_text(json.dumps(_bundle()), encoding="utf-8")
    result = runner.invoke(app, [
        "timestamp", "--bundle", str(bundle), "--out", str(tmp_path / "out.json"),
    ])
    assert result.exit_code == 2, result.output
    assert "qknot[transparency]" in result.output
    assert "Traceback" not in result.output


@pytest.mark.allow_network
def test_a_live_tsa_grants_a_timestamp_that_verifies():
    """The adapter still matches a production TSA. Replay lives in
    test_transparency_real.py over the qknot-fixture-v1 tokens."""
    import hashlib

    import rfc3161_client
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    message = b"qknot-live-s4"
    token = request_timestamp(message, "http://tsa.swisssign.net", timeout=30)
    response = rfc3161_client.decode_timestamp_response(token.der)
    certs = [x509.load_der_x509_certificate(der)
             for der in response.signed_data.certificates]
    root = next(cert for cert in certs if cert.subject == cert.issuer)
    leaf = next(cert for cert in certs
                if "TSA UNIT" in cert.subject.rfc4514_string())
    fingerprint = hashlib.sha256(root.public_bytes(Encoding.DER)).hexdigest()
    assert fingerprint == (
        "b87f292a4d9feace2d669159eb26f56d85ec77c19e01098cd754e8abb310cde5"
    )
    stamped = verify_timestamp(
        token, message,
        tsa_certificate=leaf,
        roots=[root],
        intermediates=[cert for cert in certs if cert is not leaf and cert is not root],
    )
    assert stamped.tzinfo is not None
