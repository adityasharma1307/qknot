#!/usr/bin/env python3
"""Classify signatures in gated repos from file metadata, without downloading.

THE PROBLEM
===========
Three CohereLabs repos in the head stratum carry `signatures/<name>.sig` but
return HTTP 401 when the file is fetched: the repo is gated behind accepted
terms. The audit records them as `error`, which is honest but leaves signed
repos uncategorised and makes any vulnerable-versus-safe contrast incomplete.

Requesting access would fix it, but at a cost to reproducibility: the dataset
would then depend on access grants made to one person's account, which nobody
re-running the audit can replicate.

THE OBSERVATION
===============
`model_info` succeeds on these repos -- that is how the audit learned the
signature filenames in the first place. Only the file *content* is withheld.
With `files_metadata=True` the API also returns each file's size, and for a
signature file the size is precisely the signal `parse_raw_signature` uses:
schemes emit fixed-length output, so 512 bytes is RSA-4096, 2420 is ML-DSA-44,
and so on.

So the algorithm can often be pinned without reading the file at all, using
public metadata that any reader can fetch. That keeps the result reproducible.

THE LIMIT
=========
This is inference from length, weaker than parsing, and it fails where a
signature is wrapped in a container whose size includes headers -- an OpenPGP
packet around RSA-4096 is 566 bytes, not 512, and will not match. Such cases
stay unclassified rather than being guessed at. Every classification produced
here is noted as size-derived so it is never mistaken for a parse.

    python scripts/classify_gated.py --ids data/rescan_unclassified.txt
    python scripts/classify_gated.py --ids ids.txt --out data/gated_2026-07-25.jsonl
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))

from qresp.audit.detect import detect_signature_files  # noqa: E402
from qresp.audit.model import classify_algorithm  # noqa: E402
from qresp.audit.parse import _RAW_SIGNATURE_SIZES  # noqa: E402

# An OpenPGP packet wrapping a raw signature adds framing, so the file is
# larger than the signature it carries. These are the observed totals; they are
# listed separately from _RAW_SIGNATURE_SIZES because the inference is
# different in kind -- it identifies a container, not a bare signature.
_CONTAINER_SIZES: dict[int, str] = {
    566: "openpgp_v4_rsa_sha512",  # observed on Thireus/*-SPECIAL_SPLIT
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--ids", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--token", default=None, help="Defaults to $HF_TOKEN.")
    args = parser.parse_args(argv)

    import os

    from huggingface_hub import HfApi

    api = HfApi(token=args.token or os.environ.get("HF_TOKEN"))

    ids = [ln.strip() for ln in args.ids.read_text(encoding="utf-8").splitlines() if ln.strip()]
    print(f"{len(ids)} repo(s) to inspect\n")

    records = []
    for model_id in ids:
        try:
            info = api.model_info(model_id, files_metadata=True)
        except Exception as exc:
            print(f"  [SKIP] {model_id}\n         metadata unavailable: {str(exc)[:70]}")
            continue

        siblings = info.siblings or []
        candidates = detect_signature_files([s.rfilename for s in siblings])
        if not candidates:
            print(f"  [SKIP] {model_id} -- no signature files")
            continue

        sizes = {s.rfilename: s.size for s in siblings}
        for name, _fmt in candidates:
            size = sizes.get(name)
            if size is None:
                print(f"  [    ] {model_id}\n         {name}: size withheld by the API")
                continue

            algo = _RAW_SIGNATURE_SIZES.get(size)
            if algo is not None:
                label = classify_algorithm(algo)
                print(f"  [ OK ] {model_id}\n         {name}: {size} bytes "
                      f"-> {algo.value} ({label.value})")
                records.append({
                    "model_id": model_id,
                    "file": name,
                    "size": size,
                    "sig_algorithm": algo.value,
                    "q_label": label.value,
                    "notes": f"inferred_from_file_size_without_download: {size} bytes",
                    "audit_ts": datetime.now(timezone.utc).isoformat(),
                })
            elif size in _CONTAINER_SIZES:
                print(f"  [ ?? ] {model_id}\n         {name}: {size} bytes "
                      f"-> matches container {_CONTAINER_SIZES[size]}, "
                      f"content needed to confirm")
            else:
                print(f"  [ ?? ] {model_id}\n         {name}: {size} bytes "
                      f"-> no known scheme of this length")

    print(f"\n{len(records)} signature(s) classified from metadata alone")
    if args.out and records:
        args.out.write_text(
            "\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8"
        )
        print(f"written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
