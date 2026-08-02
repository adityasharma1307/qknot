"""Build the release source tarball that gets signed.

Deliberately not `python -m build`: that shells out to setuptools via a
tempdir copy that recurses through the whole working tree (including
`.venv`, `.git`, caches) before setuptools' own excludes ever apply, which is
slow and, on at least one real filesystem this project has been developed on,
recurses into a symlink loop and crashes. This script lists exactly what
belongs in the release directly -- `pyproject.toml`, `README.md`, `LICENSE`,
and `src/` -- so there is nothing to exclude in the first place.

    python scripts/release/build_sdist.py --version 0.1.0

Produces `release/qresp-<version>.tar.gz`, deterministically enough to
inspect (sorted file order) but not byte-reproducible across machines
(gzip/tar embed mtimes) -- that is a nice-to-have, not a security property.
The signature is what a verifier actually relies on.
"""
from __future__ import annotations

import argparse
import tarfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

INCLUDE_FILES = ["pyproject.toml", "README.md", "LICENSE"]
INCLUDE_DIRS = ["src"]
SKIP_SEGMENTS = {"__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".venv"}


def _should_skip(path: Path) -> bool:
    return any(seg in SKIP_SEGMENTS for seg in path.parts) or path.suffix == ".pyc"


def build(version: str, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    tarpath = out_dir / f"qresp-{version}.tar.gz"
    prefix = f"qresp-{version}"

    with tarfile.open(tarpath, "w:gz") as tf:
        for name in INCLUDE_FILES:
            fp = REPO_ROOT / name
            if fp.exists():
                tf.add(fp, arcname=f"{prefix}/{name}")
        for name in INCLUDE_DIRS:
            for filepath in sorted((REPO_ROOT / name).rglob("*")):
                if filepath.is_file() and not _should_skip(filepath):
                    arc = f"{prefix}/{filepath.relative_to(REPO_ROOT).as_posix()}"
                    tf.add(filepath, arcname=arc)
    return tarpath


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--version", default="0.1.0")
    parser.add_argument("--out", type=Path, default=REPO_ROOT / "release")
    args = parser.parse_args()

    tarpath = build(args.version, args.out)
    with tarfile.open(tarpath, "r:gz") as tf:
        names = tf.getnames()
    print(f"built: {tarpath} ({tarpath.stat().st_size} bytes, {len(names)} files)")
    print(f"\nsign it with:")
    print(f"  qresp sign {tarpath} --out {args.out}/qresp-{args.version}.bundle.json "
          f"--keys-out {args.out}/qresp-{args.version}.keys.json "
          f"--name qresp-{args.version} --context qresp-release")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
