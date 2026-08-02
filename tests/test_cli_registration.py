"""The verify-registration CLI: a real bundle written to disk, verified end to
end through the command. The offline half of the registration product."""
from __future__ import annotations

import datetime
import json

from cryptography.hazmat.primitives.serialization import Encoding
from typer.testing import CliRunner

from qresp.cli import app

# reuse the end-to-end harness that mints the whole trust stack
from tests.signing.test_registration_chain import Harness

runner = CliRunner()


def _write_bundle(tmp_path, harness, not_after=None):
    bundle, _ = harness.bundle(not_after=not_after)
    bundle_path = tmp_path / "registration.json"
    bundle_path.write_text(json.dumps(bundle.to_dict()), encoding="utf-8")
    roots_path = tmp_path / "roots.der"
    roots_path.write_bytes(harness.root.public_bytes(Encoding.DER))
    key_path = tmp_path / "log.der"
    key_path.write_bytes(harness.log_pub)
    return bundle_path, roots_path, key_path


def test_a_valid_registration_verifies_and_names_its_basis(tmp_path):
    h = Harness()
    b, roots, key = _write_bundle(tmp_path, h)
    result = runner.invoke(app, ["verify-registration", "--bundle", str(b),
                                 "--fulcio-roots", str(roots), "--log-key", str(key)])
    assert result.exit_code == 0, result.output
    assert "REGISTRATION TRUSTED" in result.output
    assert "basis           : direct" in result.output
    assert "alice@example.com" in result.output


def test_it_reports_the_rescued_basis_in_the_future(tmp_path):
    logged = datetime.datetime(2028, 1, 1, tzinfo=datetime.timezone.utc)
    h = Harness(log_time=logged)
    b, roots, key = _write_bundle(tmp_path, h)
    result = runner.invoke(app, ["verify-registration", "--bundle", str(b),
                                 "--fulcio-roots", str(roots), "--log-key", str(key),
                                 "--at", "2040-01-01T00:00:00Z"])
    assert result.exit_code == 0, result.output
    assert "rescued-by-timestamp" in result.output


def test_an_untrusted_root_is_reported_not_a_crash(tmp_path):
    h = Harness()
    b, _, key = _write_bundle(tmp_path, h)
    # point at a DIFFERENT harness's root
    other = Harness()
    other_root = tmp_path / "other.der"
    other_root.write_bytes(other.root.public_bytes(Encoding.DER))
    result = runner.invoke(app, ["verify-registration", "--bundle", str(b),
                                 "--fulcio-roots", str(other_root), "--log-key", str(key)])
    assert result.exit_code == 1
    assert "NOT TRUSTED" in result.output


def test_notafter_coverage_is_reported(tmp_path):
    h = Harness()
    b, roots, key = _write_bundle(tmp_path, h, not_after="2027-01-01T00:00:00Z")
    covered = runner.invoke(app, ["verify-registration", "--bundle", str(b),
                                  "--fulcio-roots", str(roots), "--log-key", str(key),
                                  "--artifact-signed-at", "2026-06-01T00:00:00Z"])
    assert covered.exit_code == 0
    assert "covers the artefact" in covered.output

    not_covered = runner.invoke(app, ["verify-registration", "--bundle", str(b),
                                      "--fulcio-roots", str(roots), "--log-key", str(key),
                                      "--artifact-signed-at", "2028-06-01T00:00:00Z"])
    assert not_covered.exit_code == 1
    assert "does NOT cover" in not_covered.output


# ---------------------------------------------------------------------------
# `qresp register`: the producing half. The two network seams are replaced with
# the offline fakes from tests/signing/test_register.py, so the COMMAND -- its
# argument handling, key writing, step-8 gate and exit codes -- is exercised
# without touching Fulcio or Rekor. The live path is covered by the captured
# residual-3 fixture.
# ---------------------------------------------------------------------------

def _patch_network(monkeypatch, fulcio, rekor):
    """Point the CLI's client constructors at offline fakes."""
    import qresp.signing.sigstore_clients as clients

    monkeypatch.setattr(clients, "acquire_identity_token",
                        lambda **_: "test-token")
    monkeypatch.setattr(clients, "FulcioRestClient", lambda *_a, **_k: fulcio)
    monkeypatch.setattr(clients, "RekorRestClient", lambda *_a, **_k: rekor)
    monkeypatch.setattr(clients, "rekor_public_key_der",
                        lambda *_a, **_k: rekor.log_pub)


def _fakes(moment=None, **kwargs):
    from tests.signing.test_register import FakeFulcio, FakeRekor

    moment = moment or (datetime.datetime.now(datetime.timezone.utc)
                        - datetime.timedelta(minutes=1))
    fulcio = FakeFulcio(moment)
    rekor = FakeRekor(moment, **kwargs)
    # the CLI asks the Fulcio client for the identity it is registering
    fulcio.subject = "alice@example.com"
    fulcio.claims = {"iss": "https://accounts.google.com"}
    return fulcio, rekor


def test_register_writes_a_verifiable_bundle_and_keys(tmp_path, monkeypatch):
    """The product loop: register writes a bundle, and the OTHER command --
    the one a third party runs -- verifies it against an explicitly supplied
    trust store, chaining the leaf to a real CA root."""
    fulcio, rekor = _fakes()
    _patch_network(monkeypatch, fulcio, rekor)
    roots = tmp_path / "ca.der"
    roots.write_bytes(fulcio.root_der)          # a real trust store, not Fulcio's word
    out = tmp_path / "reg"
    result = runner.invoke(app, ["register", "--out", str(out),
                                 "--fulcio-roots", str(roots)])
    assert result.exit_code == 0, result.output
    assert "REGISTERED" in result.output
    assert "basis           : direct" in result.output

    bundle_path = out / "bundle.json"
    assert bundle_path.exists()
    verified = runner.invoke(app, ["verify-registration",
                                   "--bundle", str(bundle_path),
                                   "--fulcio-roots", str(roots),
                                   "--log-key", str(out / "rekor_key.der")])
    assert verified.exit_code == 0, verified.output
    assert "REGISTRATION TRUSTED" in verified.output
    assert "alice@example.com" in verified.output

    # a generated PQC key pair is written, and the secret is flagged as such
    assert (out / "ml-dsa-87.pub").exists()
    assert (out / "ml-dsa-87.key").exists()
    assert "SECRET KEY" in result.output


def test_register_exits_non_zero_when_the_bundle_does_not_verify(
        tmp_path, monkeypatch):
    """The step-8 gate at the command level: a log that signs its checkpoint
    with a key the verifier does not trust must FAIL the command, not produce a
    bundle. 'It logged' is not success."""
    from cryptography.hazmat.primitives.asymmetric import ec

    fulcio, rekor = _fakes(sign_with=ec.generate_private_key(ec.SECP256R1()))
    _patch_network(monkeypatch, fulcio, rekor)
    out = tmp_path / "reg"
    result = runner.invoke(app, ["register", "--out", str(out)])
    assert result.exit_code == 1, result.output
    assert "NOT VERIFIABLE" in result.output
    assert not (out / "bundle.json").exists()


def test_register_refuses_a_half_supplied_pqc_key_pair(tmp_path, monkeypatch):
    fulcio, rekor = _fakes()
    _patch_network(monkeypatch, fulcio, rekor)
    pub = tmp_path / "k.pub"
    pub.write_bytes(b"not-a-real-key")
    result = runner.invoke(app, ["register", "--out", str(tmp_path / "reg"),
                                 "--pqc-public-key", str(pub)])
    assert result.exit_code == 2
    assert "must be given together" in result.output
