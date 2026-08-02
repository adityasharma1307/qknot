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
