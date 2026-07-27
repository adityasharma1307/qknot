"""Content digests for arbitrary artefacts.

SHA-3, NOT SHA-2
================
Grover's algorithm gives a quadratic speed-up on preimage search, halving a
hash's effective preimage security: SHA-256's 256-bit preimage resistance
becomes roughly 128 bits against a quantum adversary. That is not broken, but
it is thinner than it looks for an artefact whose signature is meant to outlive
the transition, and it sits oddly beside an ML-DSA signature chosen for exactly
that horizon.

SHA3-256 has the same nominal output size but a 1600-bit internal state, so its
collision and preimage margins degrade more gracefully under the same
reduction. Choosing SHA-2 alongside a post-quantum signature would make the
hash the weakest link in a chain built to avoid exactly that.

The OMS registry mandates `sha256` and permits `blake2b`/`blake3`; SHA-3 is
absent. We therefore emit *both*: `sha256` for conformance with existing
verifiers, `sha3-256` alongside it. See `bundle.py` for where each lands, and
docs/OMS-COMPATIBILITY.md for the schema constraints that forced that choice.

MULTI-FILE ARTEFACTS
====================
A model is rarely one file. `manifest_digest` builds a canonical manifest of
per-file digests and hashes that, so a repository of a thousand shards reduces
to one value that a signature can cover. Three properties matter:

  * **Order independence.** Entries are sorted by path before hashing, so the
    same tree yields the same digest regardless of filesystem enumeration
    order.
  * **Structure binding.** Each entry is length-prefixed, so a file named
    "a/b" with digest X cannot be confused with a file named "a" containing
    "/b" plus X. Concatenating unprefixed fields is a classic source of
    collision attacks in manifest formats.
  * **Exclusions are part of the digest.** See below. This one was missing and
    was exploitable.

WHY EXCLUDED FILES ARE STILL HASHED INTO THE DIGEST
===================================================
Some paths should not have their *contents* hashed: `.git` is enormous and
irrelevant to a model, `__pycache__` is build output, and a symlink's target may
sit outside the artefact entirely.

An earlier version simply skipped them, which created a hole big enough to walk
through. Because a skipped file left no trace in the manifest, **adding one did
not change the digest**, so a signature over a clean tree kept verifying after
an attacker dropped files into it:

    clean tree              6b3cd61b...
    + __pycache__ payload   6b3cd61b...   unchanged
    + symlink out of tree   6b3cd61b...   unchanged
    + .git/hooks payload    6b3cd61b...   unchanged

`__pycache__` is the dangerous one: CPython loads a `.pyc` whose embedded header
matches its source, so that is an unsigned code-execution path sitting behind a
signature that verifies clean.

The fix is not to hash the contents -- the reasons for skipping them are still
good -- but to make the *skipping itself* visible. Every excluded path is
recorded with its reason (and, for a symlink, its target) and hashed into the
manifest digest. Adding a file under `__pycache__` now changes the exclusion
list, which changes the digest, which invalidates every signature. The contents
are still never read.

Exclusions are hashed under their own domain tag so an excluded path can never
be confused with an included one carrying a coincidentally equal digest.

Nothing here is specific to machine learning. It hashes bytes and trees of
bytes.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

# Digest algorithms this module can emit. `sha256` is kept because the OMS
# algorithm registry requires it; `sha3-256` is what we actually rely on.
ALGORITHMS = {
    "sha3-256": hashlib.sha3_256,
    "sha3-512": hashlib.sha3_512,
    "sha256": hashlib.sha256,
}
DEFAULT_ALGORITHM = "sha3-256"
OMS_REQUIRED_ALGORITHM = "sha256"

# Domain separation. A manifest digest must never collide with a file digest of
# the same bytes, and neither must be reusable as a signature binding.
#
# v3. The tag moves whenever the construction changes, so two incompatible
# schemes can never share an identifier:
#   v2  exclusions became part of the digest
#   v3  symlinks to regular files are followed and their target recorded
MANIFEST_DOMAIN = b"qresp-manifest-v3"

# Separate tags for the two sections, so an excluded path can never be
# reinterpreted as an included one.
_INCLUDED_TAG = b"included"
_EXCLUDED_TAG = b"excluded"

_CHUNK = 1 << 20


def _hasher(algorithm: str) -> hashlib._Hash:
    try:
        return ALGORITHMS[algorithm]()
    except KeyError:
        raise ValueError(
            f"unknown digest algorithm {algorithm!r}; choose from {sorted(ALGORITHMS)}"
        ) from None


def digest_bytes(data: bytes, algorithm: str = DEFAULT_ALGORITHM) -> str:
    h = _hasher(algorithm)
    h.update(data)
    return h.hexdigest()


def digest_file(path: Path, algorithm: str = DEFAULT_ALGORITHM) -> str:
    """Stream a file through the hash. Never loads it into memory.

    Model weights run to tens of gigabytes; reading one into RAM to hash it
    would make the tool unusable on the artefacts it exists to protect.
    """
    h = _hasher(algorithm)
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(_CHUNK), b""):
            h.update(chunk)
    return h.hexdigest()


@dataclass(frozen=True)
class FileEntry:
    """One file in a manifest. `path` is POSIX-relative to the artefact root.

    `link_target` is set when the path is a symlink whose content was hashed.
    Recording it matters: two symlinks pointing at identical content are not the
    same artefact, and repointing one at a different file that happens to hash
    the same would otherwise be invisible.
    """

    path: str
    size: int
    digests: dict[str, str]
    link_target: str | None = None

    def digest(self, algorithm: str = DEFAULT_ALGORITHM) -> str:
        return self.digests[algorithm]


@dataclass(frozen=True)
class ExcludedEntry:
    """A path deliberately not hashed, recorded so that adding one is detected.

    `reason` says why (`ignored:<pattern>` or `symlink`), and `target` carries a
    symlink's destination -- repointing a symlink is a change to the artefact
    even though no regular file moved.
    """

    path: str
    reason: str
    target: str | None = None

    def to_dict(self) -> dict[str, str]:
        out = {"path": self.path, "reason": self.reason}
        if self.target is not None:
            out["target"] = self.target
        return out


@dataclass(frozen=True)
class Manifest:
    """A canonical listing of an artefact's files and their digests."""

    entries: list[FileEntry]
    algorithm: str
    root_digest: str
    excluded: list[ExcludedEntry] = field(default_factory=list)

    @property
    def total_bytes(self) -> int:
        return sum(e.size for e in self.entries)

    def __len__(self) -> int:
        return len(self.entries)

    def exclusion_summary(self) -> dict[str, int]:
        """Counts by reason, for recording in a bundle without listing everything."""
        summary: dict[str, int] = {}
        for item in self.excluded:
            summary[item.reason] = summary.get(item.reason, 0) + 1
        return summary


def _field_bytes(data: bytes) -> bytes:
    return len(data).to_bytes(8, "big") + data


def manifest_digest(
    entries: list[FileEntry],
    algorithm: str = DEFAULT_ALGORITHM,
    excluded: list[ExcludedEntry] | tuple[ExcludedEntry, ...] = (),
) -> str:
    """Hash a canonical serialisation of the manifest.

    Two sections, each under its own domain tag and preceded by its count:

        included: len(path) || path || len(digest) || digest
                  || len(link_target) || link_target
        excluded: len(path) || path || len(reason) || reason || len(target) || target

    All lengths are 8-byte big-endian, and both sections are sorted by path.

    The length prefixes are not decoration. Without them, an entry
    ("a/b", "cafe") and an entry ("a", "/bcafe") serialise identically, so an
    attacker could restructure a tree without changing its digest. This is the
    standard failure mode of naive manifest hashing.

    The counts are there for the same reason at the section level: without them
    a trailing included entry could be re-read as a leading excluded one.
    """
    h = _hasher(algorithm)
    h.update(MANIFEST_DOMAIN)
    h.update(_field_bytes(algorithm.encode()))

    h.update(_INCLUDED_TAG)
    included = sorted(entries, key=lambda e: e.path)
    h.update(len(included).to_bytes(8, "big"))
    for entry in included:
        h.update(_field_bytes(entry.path.encode("utf-8")))
        h.update(_field_bytes(bytes.fromhex(entry.digest(algorithm))))
        h.update(_field_bytes((entry.link_target or "").encode("utf-8")))

    h.update(_EXCLUDED_TAG)
    skipped = sorted(excluded, key=lambda e: e.path)
    h.update(len(skipped).to_bytes(8, "big"))
    for item in skipped:
        h.update(_field_bytes(item.path.encode("utf-8")))
        h.update(_field_bytes(item.reason.encode("utf-8")))
        h.update(_field_bytes((item.target or "").encode("utf-8")))

    return h.hexdigest()


def build_manifest(
    root: Path,
    algorithm: str = DEFAULT_ALGORITHM,
    also: tuple[str, ...] = (OMS_REQUIRED_ALGORITHM,),
    ignore: tuple[str, ...] = (".git", "__pycache__"),
    follow_symlinks: bool = True,
) -> Manifest:
    """Walk `root` and digest every file under it.

    Every path under `root` ends up in exactly one of two lists: hashed into
    `entries`, or recorded in `excluded`. Nothing is dropped. Both lists are
    bound into the root digest, so adding a file to an ignored directory or
    repointing a symlink changes the digest even though neither is read.

    Args:
        also: additional algorithms to compute per file. Defaults to sha256 so
            the resulting manifest can populate OMS resource descriptors, whose
            `algorithm` field does not permit SHA-3.
        ignore: directory or file names whose *contents* are not hashed. Their
            paths are still recorded.
        follow_symlinks: **on by default**, and the default matters. A
            `huggingface_hub` snapshot directory is composed *entirely* of
            symlinks into a shared blob cache:

                snapshots/<rev>/config.json -> ../../blobs/<sha>

            With symlinks excluded, such a tree has zero hashable files and
            signing it raised "no files found" -- so the single most common
            artefact this tool exists to sign could not be signed at all.

            Following a symlink hashes the content it resolves to and records
            the link target in the entry. Both are bound into the digest, so
            repointing a link is detected even if the new target hashes
            identically, and adding one is detected because it adds an entry.
            Set this to False for a strictly self-contained tree, where links
            are recorded as exclusions and never read.

    Raises:
        ValueError: if `root` is not a directory, or contains no files. An
            empty manifest would produce a digest over nothing, which would
            then be signed and would attest to nothing.
    """
    root = Path(root)
    if not root.is_dir():
        raise ValueError(f"{root} is not a directory")

    wanted = (algorithm, *(a for a in also if a != algorithm))
    entries: list[FileEntry] = []
    excluded: list[ExcludedEntry] = []

    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()

        ignored_by = next((part for part in path.parts if part in ignore), None)
        if ignored_by is not None:
            # Record files, not the directories themselves: a directory adds no
            # information beyond the paths beneath it, and recording both would
            # make the list depend on whether empty directories exist.
            if path.is_file() or path.is_symlink():
                excluded.append(ExcludedEntry(rel, f"ignored:{ignored_by}"))
            continue

        link_target: str | None = None
        if path.is_symlink():
            try:
                link_target = str(os.readlink(path))
            except OSError as exc:                     # pragma: no cover
                link_target = f"<unreadable: {exc}>"

            if not follow_symlinks:
                excluded.append(ExcludedEntry(rel, "symlink", target=link_target))
                continue
            if not path.is_file():
                # Dangling, or pointing at a directory. Not read either way:
                # a broken link has no content, and following a directory link
                # risks a cycle. Recorded so its presence is still covered.
                reason = "symlink-broken" if not path.exists() else "symlink-directory"
                excluded.append(ExcludedEntry(rel, reason, target=link_target))
                continue

        if not path.is_file():
            continue

        entries.append(FileEntry(
            path=rel,
            size=path.stat().st_size,
            digests={a: digest_file(path, a) for a in wanted},
            link_target=link_target,
        ))

    if not entries:
        raise ValueError(
            f"no files found under {root}. Signing an empty manifest would "
            f"produce a signature that attests to nothing."
        )

    return Manifest(
        entries=entries,
        algorithm=algorithm,
        root_digest=manifest_digest(entries, algorithm, excluded),
        excluded=excluded,
    )


def digest_artefact(
    target: Path, algorithm: str = DEFAULT_ALGORITHM
) -> tuple[str, Manifest | None]:
    """Digest a file or a directory tree uniformly.

    Returns (digest, manifest). The manifest is None for a single file.
    Callers should not care which they were given; that is the point.
    """
    target = Path(target)
    if target.is_file():
        return digest_file(target, algorithm), None
    manifest = build_manifest(target, algorithm)
    return manifest.root_digest, manifest
