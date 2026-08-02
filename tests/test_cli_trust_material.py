"""`qresp trust-material`: fetches a real Fulcio/Rekor trust store from
Sigstore's production TUF root, so `register`/`verify --registration` are not
stuck trusting fixtures or a server's own say-so.

The fetch itself (`sigstore._internal.tuf.TrustUpdater`) needs a live network
round-trip to tuf-repo-cdn.sigstore.dev and is exercised for real by whoever
runs the command; these tests are offline and prove the two things this
process controls: the failure modes are legible, and the parsing/writing of a
trusted_root.json -- once fetched -- is correct.
"""
from __future__ import annotations

import base64
import datetime
import json
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)
from cryptography.x509.oid import NameOID
from typer.testing import CliRunner

from qresp.cli import app

pytest.importorskip("sigstore", reason="needs `sigstore` (the register extra)")

runner = CliRunner()
NOW = datetime.datetime.now(datetime.timezone.utc)


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _self_signed_ca_der() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Fulcio Root")])
    cert = (x509.CertificateBuilder()
            .subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - datetime.timedelta(days=1))
            .not_valid_after(NOW + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(Encoding.DER)


def _rekor_key_der() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def _trusted_root_json(ca_ders: list[bytes], rekor_key_ders: list[bytes]) -> dict:
    """The shape `TrustUpdater.get_trusted_root_path()` would hand back --
    matches `_from_trusted_root_json` in scripts/verify/check_sigstore_fixture.py
    and `_load_cert_pool` in cli.py, which already parse this shape elsewhere."""
    return {
        "certificateAuthorities": [
            {"certChain": {"certificates": [{"rawBytes": _b64(der)} for der in ca_ders]}}
        ],
        "tlogs": [
            {"publicKey": {"rawBytes": _b64(der)}} for der in rekor_key_ders
        ],
    }


class _FakeTrustUpdater:
    """Stands in for sigstore._internal.tuf.TrustUpdater: no network, just
    hands back a path to a trusted_root.json already on disk."""

    def __init__(self, path):
        self._path = path

    def __call__(self, url):
        return self

    def get_trusted_root_path(self):
        return self._path


def test_missing_sigstore_is_reported_not_a_traceback(monkeypatch):
    """`sigstore` is an optional dependency (the `register` extra). Without
    it, the command must fail with actionable guidance, not an ImportError
    traceback."""
    monkeypatch.setitem(sys.modules, "sigstore._internal.tuf", None)
    result = runner.invoke(app, ["trust-material", "--out", "/tmp/unused-trust"])
    assert result.exit_code == 2
    assert "pip install sigstore" in result.output
    assert "qresp[register]" in result.output


def test_a_fetch_failure_is_reported_not_a_traceback(monkeypatch, tmp_path):
    import sigstore._internal.tuf as tuf_mod

    class _ExplodingUpdater:
        def __init__(self, url):
            pass

        def get_trusted_root_path(self):
            raise tuf_mod.TUFError("network unreachable in this sandbox")

    monkeypatch.setattr(tuf_mod, "TrustUpdater", _ExplodingUpdater)
    result = runner.invoke(app, ["trust-material", "--out", str(tmp_path / "trust")])
    assert result.exit_code == 1
    assert "could not fetch/verify the TUF trust root" in result.output
    assert "--fulcio-roots instead" in result.output


def test_a_real_trusted_root_shape_is_parsed_and_written(monkeypatch, tmp_path):
    """The part under QResP's control: given a trusted_root.json, extract
    every CA cert and the (first) Rekor key, and write them in the formats
    --fulcio-roots/--log-key already accept."""
    import sigstore._internal.tuf as tuf_mod

    ca_a, ca_b = _self_signed_ca_der(), _self_signed_ca_der()
    rekor_key = _rekor_key_der()
    root_path = tmp_path / "trusted_root.json"
    root_path.write_text(
        json.dumps(_trusted_root_json([ca_a, ca_b], [rekor_key])), encoding="utf-8")

    monkeypatch.setattr(tuf_mod, "TrustUpdater", _FakeTrustUpdater(root_path))

    out_dir = tmp_path / "trust"
    result = runner.invoke(app, ["trust-material", "--out", str(out_dir)])
    assert result.exit_code == 0, result.output
    assert "wrote 2 Fulcio CA certificate(s)" in result.output

    roots_pem = (out_dir / "fulcio_roots.pem").read_bytes()
    parsed = x509.load_pem_x509_certificates(roots_pem)
    assert {c.public_bytes(Encoding.DER) for c in parsed} == {ca_a, ca_b}

    assert (out_dir / "rekor.pub").read_bytes() == rekor_key


def test_multiple_rekor_keys_writes_the_first_and_warns(monkeypatch, tmp_path):
    import sigstore._internal.tuf as tuf_mod

    ca = _self_signed_ca_der()
    current_key, retired_key = _rekor_key_der(), _rekor_key_der()
    root_path = tmp_path / "trusted_root.json"
    root_path.write_text(
        json.dumps(_trusted_root_json([ca], [current_key, retired_key])),
        encoding="utf-8")
    monkeypatch.setattr(tuf_mod, "TrustUpdater", _FakeTrustUpdater(root_path))

    out_dir = tmp_path / "trust"
    result = runner.invoke(app, ["trust-material", "--out", str(out_dir)])
    assert result.exit_code == 0, result.output
    assert "2 Rekor keys" in result.output
    assert (out_dir / "rekor.pub").read_bytes() == current_key


def test_a_trust_root_missing_ca_certs_is_reported_not_a_crash(monkeypatch, tmp_path):
    import sigstore._internal.tuf as tuf_mod

    root_path = tmp_path / "trusted_root.json"
    root_path.write_text(
        json.dumps(_trusted_root_json([], [_rekor_key_der()])), encoding="utf-8")
    monkeypatch.setattr(tuf_mod, "TrustUpdater", _FakeTrustUpdater(root_path))

    result = runner.invoke(app, ["trust-material", "--out", str(tmp_path / "trust")])
    assert result.exit_code == 1
    flat = " ".join(result.output.split())
    assert "no CA" in flat or "missing" in flat.lower()
    assert "shape may have changed" in flat
