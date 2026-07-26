"""Tests for qresp.detect — signature-file detection from filename lists."""
from __future__ import annotations

import pytest

from qresp.audit.detect import detect_signature_files, has_any_signature
from qresp.audit.model import SigFormat


class TestSigstoreDetection:
    def test_model_sig_is_sigstore(self):
        result = detect_signature_files(["README.md", "model.sig"])
        assert result == [("model.sig", SigFormat.SIGSTORE)]

    def test_sigstore_suffix_is_sigstore(self):
        result = detect_signature_files(["weights.bin.sigstore"])
        assert result == [("weights.bin.sigstore", SigFormat.SIGSTORE)]

    def test_sigstore_json_suffix_is_sigstore(self):
        result = detect_signature_files(["weights.bin.sigstore.json"])
        assert result == [("weights.bin.sigstore.json", SigFormat.SIGSTORE)]

    def test_nested_model_sig(self):
        result = detect_signature_files(["signatures/model.sig"])
        assert result == [("signatures/model.sig", SigFormat.SIGSTORE)]

    def test_case_insensitive(self):
        result = detect_signature_files(["WEIGHTS.SIGSTORE"])
        assert result == [("WEIGHTS.SIGSTORE", SigFormat.SIGSTORE)]


class TestInTotoDetection:
    def test_intoto_json(self):
        result = detect_signature_files(["model.intoto.json"])
        assert result == [("model.intoto.json", SigFormat.IN_TOTO)]

    def test_in_toto_with_hyphen(self):
        result = detect_signature_files(["attestation.in-toto.json"])
        assert result == [("attestation.in-toto.json", SigFormat.IN_TOTO)]

    def test_jsonl_variant(self):
        result = detect_signature_files(["model.intoto.jsonl"])
        assert result == [("model.intoto.jsonl", SigFormat.IN_TOTO)]


class TestGpgDetection:
    def test_asc_is_gpg(self):
        result = detect_signature_files(["weights.pt.asc"])
        assert result == [("weights.pt.asc", SigFormat.GPG)]

    def test_pgp_suffix(self):
        result = detect_signature_files(["model.pgp"])
        assert result == [("model.pgp", SigFormat.GPG)]

    def test_gpg_suffix(self):
        result = detect_signature_files(["model.gpg"])
        assert result == [("model.gpg", SigFormat.GPG)]


class TestNonSignatureFiles:
    @pytest.mark.parametrize(
        "filename",
        [
            "README.md",
            "config.json",
            "tokenizer.json",
            "model-00001-of-00004.safetensors",
            "pytorch_model.bin",
            "model.safetensors.index.json",
        ],
    )
    def test_normal_files_are_not_signatures(self, filename: str):
        result = detect_signature_files([filename])
        assert result == []


class TestMixedListing:
    def test_unsigned_model_listing(self):
        files = [
            "README.md", "config.json", "tokenizer.json",
            "model.safetensors", "tokenizer_config.json",
        ]
        assert has_any_signature(files) is False
        assert detect_signature_files(files) == []

    def test_signed_model_listing(self):
        files = ["README.md", "config.json", "model.safetensors", "model.sig"]
        assert has_any_signature(files) is True
        result = detect_signature_files(files)
        assert result == [("model.sig", SigFormat.SIGSTORE)]

    def test_multiple_signatures_preserves_order(self):
        files = ["model.sig", "model.intoto.json", "weights.asc"]
        result = detect_signature_files(files)
        formats = [fmt for _, fmt in result]
        assert formats == [SigFormat.SIGSTORE, SigFormat.IN_TOTO, SigFormat.GPG]

    def test_rule_priority_sigstore_beats_generic_sig(self):
        # `model.sig` should match the more specific SIGSTORE rule, not generic CUSTOM
        result = detect_signature_files(["model.sig"])
        assert result == [("model.sig", SigFormat.SIGSTORE)]

    def test_unknown_sig_falls_back_to_custom(self):
        # A `.sig` file that is NOT named "model.sig" falls through to CUSTOM
        result = detect_signature_files(["weird-thing.sig"])
        assert result == [("weird-thing.sig", SigFormat.CUSTOM)]
