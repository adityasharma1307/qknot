#!/usr/bin/env python3
"""Classify how much of each signed repo its signatures actually cover.

THE PROBLEM
===========
`has_signature` is true if a repo carries at least one recognised signature
file. That says nothing about how much of the repo is protected. A repo with
one signed artefact among fifty unsigned ones would be counted as signed, and
the headline figure would overstate the protection in the registry.

WHY A FILE-COUNT RATIO DOES NOT ANSWER IT
=========================================
The obvious check -- signature files divided by total files -- is worthless
here, because the dominant signing schemes sign a *manifest*:

  * OpenSSF Model Signing writes a single `model.sig` whose payload enumerates
    a digest for every artefact in the repo.
  * `SHA256SUMS.sig` signs a checksum file that lists every artefact.

Both give a ratio near 1/N while covering everything. Conversely a repo could
have many `.sig` files that each cover one artefact and still leave most of the
repo unprotected. The ratio cannot distinguish full manifest coverage from
sparse per-artefact coverage, so this script classifies by scheme instead.

CATEGORIES
==========
    manifest       a signature over a listing that covers the repo
                   transitively (model.sig, SHA256SUMS.sig, tensors.map.sig)
    per_artefact   signatures named after specific artefacts (`<file>.sig`)
    both           a manifest signature plus per-artefact signatures
    unclear        neither shape recognised

THE LIMIT, STATED PLAINLY
=========================
Manifest coverage is *assumed*, not verified. Confirming it would mean parsing
the DSSE payload and checking that the enumerated digests account for every
artefact in the repo. The scanner deliberately never downloads weights and does
not open signature payloads, so that check is out of scope. Any repo classified
`manifest` here is trusted to have a complete manifest; a signer who signed a
manifest listing only half the files would be indistinguishable.

That limitation belongs in the paper. It is the difference between "this repo
carries a signature" -- which is what the audit measures -- and "this repo's
artefacts are all protected", which it does not.

    python scripts/check_signature_coverage.py
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Filenames that denote a signature over a listing rather than one artefact.
MANIFEST_SIGNATURE_NAMES = re.compile(
    r"(?:^|/)(?:"
    r"model\.sig"          # OpenSSF Model Signing
    r"|SHA256SUMS\.sig"    # checksum manifest
    r"|SHA512SUMS\.sig"
    r"|tensors\.map\.sig"  # GGUF split-tensor map
    r"|manifest\.sig"
    r"|.*\.sigstore(?:\.json)?"  # Sigstore bundle over a manifest
    r")$",
    re.IGNORECASE,
)

# `<some-artefact>.<ext>.sig` -- a signature naming one specific file.
PER_ARTEFACT_SIGNATURE = re.compile(r"\.(?:safetensors|bin|gguf|pt|pth|onnx|zip|h5)\.sig$",
                                    re.IGNORECASE)


# Formats that are manifest-based by construction, whatever the file is called.
# A Sigstore bundle's DSSE payload is an in-toto statement listing a digest per
# artefact; in-toto attestations likewise. Classifying these by filename alone
# would miss, for example, CohereLabs' `signatures/<repo-name>.sig`, which is a
# Sigstore bundle despite matching no conventional manifest name.
MANIFEST_FORMATS = frozenset({"sigstore", "oms", "in_toto"})


def classify(candidate_files: list[str], sig_format: str | None = None) -> str:
    has_manifest = (
        any(MANIFEST_SIGNATURE_NAMES.search(f) for f in candidate_files)
        or (sig_format in MANIFEST_FORMATS)
    )
    has_per_artefact = any(PER_ARTEFACT_SIGNATURE.search(f) for f in candidate_files)
    if has_manifest and has_per_artefact:
        return "both"
    if has_manifest:
        return "manifest"
    if has_per_artefact:
        return "per_artefact"
    return "unclear"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("datasets", nargs="*", type=Path, default=[
        REPO_ROOT / "data" / "head_10k_2026-07-25.jsonl",
        REPO_ROOT / "data" / "longtail_10k_2026-07-25.jsonl",
    ])
    args = parser.parse_args(argv)

    concerning = 0
    for path in args.datasets:
        if not path.exists():
            print(f"skip (missing): {path}")
            continue
        rows = [json.loads(ln) for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
        signed = [r for r in rows if r["has_signature"]]

        print(f"\n{path.name}  --  {len(signed)} signed repos")
        print("-" * 72)
        kinds = Counter(classify(r["candidate_files"], r.get("sig_format")) for r in signed)
        for kind, n in kinds.most_common():
            print(f"  {kind:<14} {n:>4}")

        # The shape that would actually undermine the headline number.
        risky = [r for r in signed
                 if classify(r["candidate_files"], r.get("sig_format")) == "per_artefact"]
        if risky:
            concerning += len(risky)
            print(f"\n  {len(risky)} repo(s) signed per-artefact with NO manifest signature.")
            print("  These are the ones where `signed` may overstate coverage:")
            for r in risky:
                print(f"    {len(r['candidate_files']):>3} sigs / {r['file_count']:>4} files  "
                      f"{r['model_id']}")

        mixed = [r for r in signed
                 if classify(r["candidate_files"], r.get("sig_format")) == "both"]
        if mixed:
            print(f"\n  {len(mixed)} repo(s) carry a manifest signature AND per-artefact")
            print("  signatures. Coverage depends on whether the manifest is complete,")
            print("  which cannot be determined without opening the payload:")
            for r in mixed:
                print(f"    {len(r['candidate_files']):>3} sigs / {r['file_count']:>4} files  "
                      f"{r['model_id'][:56]}")

        unclear = [r for r in signed
                   if classify(r["candidate_files"], r.get("sig_format")) == "unclear"]
        for r in unclear:
            print(f"\n  unclear scheme: {r['model_id']}  {r['candidate_files'][:2]}")

    print("\n" + "=" * 72)
    if concerning:
        print(f"{concerning} repo(s) rely on per-artefact signatures alone. Review before")
        print("quoting the signed rate as a coverage figure.")
    else:
        print("No repo relies on per-artefact signatures alone. Every signed repo")
        print("carries a manifest-style signature, so `signed` does not overstate")
        print("coverage -- subject to the manifests being complete, which this tool")
        print("does not verify. See the module docstring.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
