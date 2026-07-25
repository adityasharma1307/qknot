"""Signature file detection.

Given the list of files in a HuggingFace repo, identify which ones
look like cryptographic signature artifacts. Detection is intentionally
filename-based: we want to avoid downloading model weights (which can
be gigabytes per file).
"""
from __future__ import annotations

import re

from .model import SigFormat

# ---------------------------------------------------------------------------
# Detection rules
# ---------------------------------------------------------------------------
# Suffix patterns are matched case-insensitively against the full filename.
# Each rule maps a regex pattern to a SigFormat label. Order matters: more
# specific patterns come first so that, for example, "model.sigstore" is
# classified as SIGSTORE rather than the generic CUSTOM .sig matcher.

_SUFFIX_RULES: list[tuple[re.Pattern[str], SigFormat]] = [
    # Sigstore bundle conventions (most common for ML model signing).
    # `.sigstore` and `.sigstore.json` suffixes anywhere in the path:
    (re.compile(r"\.sigstore(\.json)?$", re.IGNORECASE), SigFormat.SIGSTORE),
    # OMS convention: a file literally named `model.sig` (at any directory depth):
    (re.compile(r"(?:^|/)model\.sig$", re.IGNORECASE), SigFormat.SIGSTORE),
    (re.compile(r"(?:^|/)signature\.json$", re.IGNORECASE), SigFormat.SIGSTORE),

    # in-toto attestations
    (re.compile(r"\.intoto\.jsonl?$", re.IGNORECASE), SigFormat.IN_TOTO),
    (re.compile(r"\.in-toto\.jsonl?$", re.IGNORECASE), SigFormat.IN_TOTO),
    (re.compile(r"(?:^|/)attestation\.json$", re.IGNORECASE), SigFormat.IN_TOTO),

    # GPG / OpenPGP. `.asc` is the ASCII-armoured form.
    (re.compile(r"\.asc$", re.IGNORECASE), SigFormat.GPG),
    (re.compile(r"\.gpg$", re.IGNORECASE), SigFormat.GPG),
    (re.compile(r"\.pgp$", re.IGNORECASE), SigFormat.GPG),

    # Generic `.sig` last resort. After the more specific rules above,
    # anything that still ends in `.sig` is treated as custom/unknown.
    (re.compile(r"\.sig$", re.IGNORECASE), SigFormat.CUSTOM),
]


def detect_signature_files(filenames: list[str]) -> list[tuple[str, SigFormat]]:
    """Return a list of (filename, detected format) for every candidate signature file.

    The function is purely filename-based and does not require network access.

    Args:
        filenames: list of file paths relative to the repo root, as returned
                   by the HuggingFace API in `siblings[].rfilename`.

    Returns:
        List of (filename, SigFormat) tuples for every file that matched a
        signature pattern. The list preserves the input order and may be empty.
    """
    matches: list[tuple[str, SigFormat]] = []
    for name in filenames:
        for pattern, fmt in _SUFFIX_RULES:
            if pattern.search(name):
                matches.append((name, fmt))
                break  # first match wins; rules are ordered specific -> generic
    return matches


def has_any_signature(filenames: list[str]) -> bool:
    """Convenience predicate: True iff any candidate signature file is present."""
    return bool(detect_signature_files(filenames))
