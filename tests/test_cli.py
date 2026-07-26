"""The command line, which had no tests at all.

111 statements at 0% coverage, including the two commands that expose the
project's reusable half. A CLI is the surface most users touch and the one
where a broken flag is least likely to be noticed by a passing unit test.

Network-touching paths (`scan`, `scan-ids`, and entropy's ANU/beacon calls) are
exercised with `--seed`/`system`-only sources or not at all; these tests must
run offline and deterministically.
"""
from __future__ import annotations

import json

import pytest

pytest.importorskip("typer", reason="needs `typer`")
pytest.importorskip("cryptography", reason="needs `cryptography`")
pytest.importorskip("dilithium_py", reason="needs `dilithium-py`")

from typer.testing import CliRunner  # noqa: E402

from qresp.cli import app  # noqa: E402

runner = CliRunner()
SEED = "2a" * 32


@pytest.fixture
def artefact(tmp_path):
    root = tmp_path / "model"
    root.mkdir()
    (root / "config.json").write_bytes(b'{"arch":"test"}')
    (root / "model.safetensors").write_bytes(b"weights" * 64)
    return root


@pytest.fixture
def signed(tmp_path, artefact):
    bundle = tmp_path / "sig.json"
    result = runner.invoke(app, [
        "sign", str(artefact), "--out", str(bundle),
        "--name", "demo", "--context", "model-release", "--seed", SEED,
    ])
    assert result.exit_code == 0, result.output
    return bundle


class TestHelpIsReachable:
    def test_top_level_help(self):
        assert runner.invoke(app, ["--help"]).exit_code == 0

    @pytest.mark.parametrize("command",
                             ["scan", "scan-ids", "entropy", "summarise", "sign", "verify"])
    def test_every_command_has_help(self, command):
        result = runner.invoke(app, [command, "--help"])
        assert result.exit_code == 0, f"{command} --help failed"


class TestSign:
    def test_signing_writes_a_bundle(self, artefact, signed):
        bundle = json.loads(signed.read_text(encoding="utf-8"))
        assert len(bundle["dsseEnvelope"]["signatures"]) == 2

    def test_it_reports_both_algorithms(self, artefact, tmp_path):
        result = runner.invoke(app, ["sign", str(artefact), "--out",
                                     str(tmp_path / "b.json"), "--seed", SEED])
        assert "ed25519" in result.output and "ml-dsa-44" in result.output

    def test_it_says_secret_keys_were_not_written(self, artefact, tmp_path):
        """The single most important thing the command can tell a user."""
        result = runner.invoke(app, ["sign", str(artefact), "--out",
                                     str(tmp_path / "b.json"), "--seed", SEED])
        assert "Secret keys were NOT written" in result.output

    def test_public_keys_can_be_exported(self, artefact, tmp_path):
        keys = tmp_path / "keys.json"
        runner.invoke(app, ["sign", str(artefact), "--out", str(tmp_path / "b.json"),
                            "--keys-out", str(keys), "--seed", SEED])
        exported = json.loads(keys.read_text(encoding="utf-8"))
        assert set(exported) == {"ed25519", "ml-dsa-44"}
        assert "publicKey" in exported["ed25519"]

    def test_exported_keys_contain_no_secret_material(self, artefact, tmp_path):
        keys = tmp_path / "keys.json"
        runner.invoke(app, ["sign", str(artefact), "--out", str(tmp_path / "b.json"),
                            "--keys-out", str(keys), "--seed", SEED])
        text = keys.read_text(encoding="utf-8").lower()
        assert "secret" not in text and "private" not in text

    def test_a_seed_alone_does_not_reproduce_the_bundle(self, artefact, tmp_path):
        """ML-DSA signing is hedged by default (FIPS 204): 32 fresh random
        bytes go into every signature, so the same key over the same artefact
        yields different bytes. Worth asserting, because "seeded" reads as
        "reproducible" and here it is not."""
        outs = []
        for name in ("a.json", "b.json"):
            path = tmp_path / name
            runner.invoke(app, ["sign", str(artefact), "--out", str(path),
                                "--name", "demo", "--seed", SEED])
            outs.append(path.read_text(encoding="utf-8"))
        assert outs[0] != outs[1]

    def test_deterministic_mode_reproduces_the_bundle_byte_for_byte(
        self, artefact, tmp_path
    ):
        outs = []
        for name in ("a.json", "b.json"):
            path = tmp_path / name
            result = runner.invoke(app, ["sign", str(artefact), "--out", str(path),
                                         "--name", "demo", "--seed", SEED,
                                         "--deterministic"])
            assert result.exit_code == 0, result.output
            outs.append(path.read_text(encoding="utf-8"))
        assert outs[0] == outs[1]

    def test_deterministic_mode_records_what_it_gave_up(self, artefact, tmp_path):
        result = runner.invoke(app, ["sign", str(artefact), "--out",
                                     str(tmp_path / "b.json"), "--seed", SEED,
                                     "--deterministic"])
        assert "fault-injection" in result.output

    def test_online_exposure_is_refused(self, artefact, tmp_path):
        """The exposure gate must reach the CLI, not just the library."""
        result = runner.invoke(app, ["sign", str(artefact), "--out",
                                     str(tmp_path / "b.json"), "--seed", SEED,
                                     "--exposure", "online"])
        assert result.exit_code == 1
        assert "not constant-time" in result.output

    def test_a_bad_exposure_is_rejected(self, artefact, tmp_path):
        result = runner.invoke(app, ["sign", str(artefact), "--out",
                                     str(tmp_path / "b.json"), "--exposure", "sideways"])
        assert result.exit_code == 2

    def test_a_bad_seed_is_rejected(self, artefact, tmp_path):
        result = runner.invoke(app, ["sign", str(artefact), "--out",
                                     str(tmp_path / "b.json"), "--seed", "xyz"])
        assert result.exit_code == 2

    def test_excluded_paths_are_reported(self, artefact, tmp_path):
        (artefact / "__pycache__").mkdir()
        (artefact / "__pycache__" / "a.pyc").write_bytes(b"x")
        result = runner.invoke(app, ["sign", str(artefact), "--out",
                                     str(tmp_path / "b.json"), "--seed", SEED])
        assert "excluded" in result.output


class TestVerify:
    def test_a_clean_artefact_verifies(self, artefact, signed):
        result = runner.invoke(app, ["verify", str(artefact), "--bundle", str(signed),
                                     "--context", "model-release"])
        assert result.exit_code == 0
        assert "VERIFIED" in result.output

    def test_tampering_fails_with_a_nonzero_exit(self, artefact, signed):
        (artefact / "model.safetensors").write_bytes(b"BACKDOORED")
        result = runner.invoke(app, ["verify", str(artefact), "--bundle", str(signed),
                                     "--context", "model-release"])
        assert result.exit_code == 1
        assert "VERIFICATION FAILED" in result.output

    def test_an_unsigned_addition_fails(self, artefact, signed):
        """The exclusion fix, reached through the CLI."""
        (artefact / "__pycache__").mkdir()
        (artefact / "__pycache__" / "evil.pyc").write_bytes(b"payload")
        result = runner.invoke(app, ["verify", str(artefact), "--bundle", str(signed),
                                     "--context", "model-release"])
        assert result.exit_code == 1

    def test_the_wrong_context_fails(self, artefact, signed):
        result = runner.invoke(app, ["verify", str(artefact), "--bundle", str(signed),
                                     "--context", "different"])
        assert result.exit_code == 1

    def test_it_reports_what_was_checked(self, artefact, signed):
        result = runner.invoke(app, ["verify", str(artefact), "--bundle", str(signed),
                                     "--context", "model-release"])
        assert "algorithms checked" in result.output
        assert "binding enforced" in result.output

    def test_classical_mode_warns_about_the_binding(self, artefact, signed):
        result = runner.invoke(app, ["verify", str(artefact), "--bundle", str(signed),
                                     "--context", "model-release", "--mode", "classical"])
        assert result.exit_code == 0
        assert "does not enforce the algorithm binding" in result.output

    def test_a_bad_mode_is_rejected(self, artefact, signed):
        result = runner.invoke(app, ["verify", str(artefact), "--bundle", str(signed),
                                     "--mode", "vibes"])
        assert result.exit_code == 2

    def test_a_missing_bundle_is_reported_not_traced(self, artefact, tmp_path):
        result = runner.invoke(app, ["verify", str(artefact), "--bundle",
                                     str(tmp_path / "nope.json")])
        assert result.exit_code == 2
        assert "could not read the bundle" in result.output

    def test_a_corrupt_bundle_is_reported_not_traced(self, artefact, tmp_path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        result = runner.invoke(app, ["verify", str(artefact), "--bundle", str(bad)])
        assert result.exit_code == 2


class TestEntropy:
    def test_mixing_is_the_default_and_works_offline(self, tmp_path):
        out = tmp_path / "att.json"
        result = runner.invoke(app, ["entropy", "--bytes", "32", "--no-beacon",
                                     "--out", str(out)])
        assert result.exit_code == 0
        attestation = json.loads(out.read_text(encoding="utf-8"))
        assert attestation["kdf"] == "HKDF-SHA3-256"
        assert any(c["role"] == "secret" for c in attestation["contributions"])

    def test_the_attestation_is_readable_by_the_temporal_layer(self, tmp_path):
        """The concrete reason mixing is now the default."""
        from qresp.signing.temporal import evidence_from_attestation

        out = tmp_path / "att.json"
        runner.invoke(app, ["entropy", "--no-beacon", "--out", str(out)])
        attestation = json.loads(out.read_text(encoding="utf-8"))
        assert "not_before" in attestation
        # No beacon offline, so no evidence -- but the shape is understood
        # rather than unparseable.
        assert evidence_from_attestation(attestation) is None

    def test_raw_entropy_is_withheld_unless_asked(self, tmp_path):
        result = runner.invoke(app, ["entropy", "--no-beacon"])
        assert "raw:" not in result.output

    def test_the_legacy_backend_flag_warns(self):
        result = runner.invoke(app, ["entropy", "--backend", "system"])
        assert result.exit_code == 0
        assert "legacy attestation" in result.output

    def test_an_unknown_backend_exits_cleanly(self):
        result = runner.invoke(app, ["entropy", "--backend", "nonsense"])
        assert result.exit_code == 2

    def test_an_unimplemented_backend_falls_back_and_says_so(self):
        """FALLBACK is the default policy, so an unavailable quantum source is
        not an error -- but the attestation must not claim quantum origin."""
        result = runner.invoke(app, ["entropy", "--backend", "ibm"])
        assert result.exit_code == 0
        assert "not a quantum source" in result.output

    def test_abort_policy_turns_an_unavailable_backend_into_a_failure(self):
        result = runner.invoke(app, ["entropy", "--backend", "ibm",
                                     "--on-qrng-failure", "abort"])
        assert result.exit_code == 1

    def test_an_invalid_failure_policy_is_rejected(self):
        result = runner.invoke(app, ["entropy", "--backend", "system",
                                     "--on-qrng-failure", "panic"])
        assert result.exit_code == 2


class TestSummarise:
    def test_it_summarises_a_dataset(self, tmp_path):
        dataset = tmp_path / "d.jsonl"
        rows = [
            {"model_id": "a/b", "publisher": "a", "downloads": 1,
             "last_modified": None, "file_count": 1, "has_signature": False,
             "candidate_files": [], "sig_algorithm": "none", "sig_format": "none",
             "key_size_bits": None, "q_label": "unsigned",
             "audit_ts": "2026-07-26T00:00:00Z", "notes": None},
            {"model_id": "c/d", "publisher": "c", "downloads": 2,
             "last_modified": None, "file_count": 1, "has_signature": True,
             "candidate_files": ["x.sig"], "sig_algorithm": "ecdsa_p256",
             "sig_format": "sigstore", "key_size_bits": 256, "q_label": "vulnerable",
             "audit_ts": "2026-07-26T00:00:00Z", "notes": None},
        ]
        dataset.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
        result = runner.invoke(app, ["summarise", "--in", str(dataset)])
        assert result.exit_code == 0
        assert "unsigned" in result.output.lower()
