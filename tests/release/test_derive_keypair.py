"""derive_keypair.py: the bridge between `sign --seed` and `register
--pqc-public-key/--pqc-secret-key`. The property under test is exact -- the
key this script writes must be BYTE-IDENTICAL to the key `keygen()` (and
therefore `qresp sign --seed`) derives internally, or the whole point of the
bridge (sign and register referring to the same key) silently fails.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "release" / "derive_keypair.py"
sys.path.insert(0, str(REPO_ROOT / "src"))

from qresp.signing.sign import keygen  # noqa: E402

SEED = "11" * 32  # 32 bytes, hex -- fixed so the test is deterministic


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        capture_output=True, text=True, cwd=REPO_ROOT,
    )


def test_the_derived_key_matches_keygen_exactly(tmp_path):
    out_dir = tmp_path / "keys"
    result = _run(["--seed", SEED, "--algorithm", "ml-dsa-87", "--out", str(out_dir)])
    assert result.returncode == 0, result.stderr

    expected = keygen(suite=["ml-dsa-87"], seed=bytes.fromhex(SEED)).keys["ml-dsa-87"]
    assert (out_dir / "ml-dsa-87.pub").read_bytes() == expected.public_key
    assert (out_dir / "ml-dsa-87.key").read_bytes() == expected.secret_key
    assert expected.fingerprint in result.stdout


def test_the_key_does_not_depend_on_what_else_is_in_the_suite(tmp_path):
    """The whole bridge only works if deriving ml-dsa-87 alone gives the same
    key as deriving it alongside ed25519 -- which is what `sign`'s default
    suite actually does. If this ever stopped being true, a key derived here
    would silently NOT be the one `sign --seed` used."""
    solo = tmp_path / "solo"
    _run(["--seed", SEED, "--algorithm", "ml-dsa-87", "--out", str(solo)])

    hybrid = keygen(suite=["ed25519", "ml-dsa-87"], seed=bytes.fromhex(SEED))
    assert (solo / "ml-dsa-87.pub").read_bytes() == hybrid.keys["ml-dsa-87"].public_key
    assert (solo / "ml-dsa-87.key").read_bytes() == hybrid.keys["ml-dsa-87"].secret_key


def test_a_short_seed_is_refused_not_silently_weakened(tmp_path):
    result = _run(["--seed", "ab" * 8, "--out", str(tmp_path / "keys")])
    assert result.returncode != 0
    assert "at least 32 bytes" in (result.stdout + result.stderr)
    assert not (tmp_path / "keys").exists()


def test_non_hex_seed_is_refused(tmp_path):
    result = _run(["--seed", "not-hex-at-all", "--out", str(tmp_path / "keys")])
    assert result.returncode != 0
    assert "hex" in (result.stdout + result.stderr).lower()


def test_secret_key_file_is_restricted(tmp_path):
    out_dir = tmp_path / "keys"
    _run(["--seed", SEED, "--out", str(out_dir)])
    sk = out_dir / "ml-dsa-87.key"
    assert sk.exists()
    # chmod(0o600) is wrapped in contextlib.suppress(OSError) for filesystems
    # that reject it (some mounted/network filesystems); on a normal local
    # tmp_path it must actually apply.
    assert (sk.stat().st_mode & 0o777) == 0o600
