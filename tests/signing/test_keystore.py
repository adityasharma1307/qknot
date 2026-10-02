"""Secret keys stay owner-only. A world-readable file is not loaded."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from qknot.signing.sign import FileKeyStore


def test_a_world_readable_key_file_is_rejected(tmp_path: Path):
    target = tmp_path / "ml-dsa-87.key"
    target.write_bytes(b"secret")
    if os.name != "nt":
        target.chmod(0o644)
    store = FileKeyStore(tmp_path)
    with pytest.raises(PermissionError, match="world-readable"):
        store.get("ml-dsa-87")


def test_put_writes_owner_only_and_get_returns_the_bytes(tmp_path: Path):
    store = FileKeyStore(tmp_path)
    store.put("ed25519", b"\x01\x02")
    assert store.get("ed25519") == b"\x01\x02"
    if os.name != "nt":
        assert (tmp_path / "ed25519.key").stat().st_mode & 0o077 == 0


def test_a_key_name_cannot_escape_the_directory(tmp_path: Path):
    store = FileKeyStore(tmp_path)
    with pytest.raises(ValueError):
        store.put("../outside", b"x")
