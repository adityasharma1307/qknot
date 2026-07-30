"""Enumerate the npm namespace into a sampling frame, one name per line.

    python scripts/audit/fetch_npm_frame.py --out data/npm_frame_2026-07-30.txt

WHY NOT replicate.npmjs.com/_all_docs
=====================================
That was the plan. It returns **HTTP 400** -- npm has restricted the public
CouchDB replication endpoint, so paging the namespace out of it is no longer
available regardless of `limit`.

The replacement is better on the axis this project cares about. The npm package
`all-the-package-names` publishes the full list as `names.json`, and a **pinned
version is a dated artefact**: fix the version and the exact frame is
reproducible by anyone, indefinitely. `_all_docs` could never offer that -- the
namespace advances between requests, so two people paging it get two different
frames and neither can reconstruct the other's.

Same reasoning that replaced BigQuery with a published PyPI ranking, and the
same provenance tier: a third party's published snapshot, cited by version.

MEASURED 2026-07-30, version 2.0.2517
=====================================
    4,290,079 names, 26 MB compressed, ONE request
    1,603,659 scoped (37.4%)

That scoped fraction is why the head ranking is two-stage. npm's bulk downloads
endpoint rejects scoped names, so a bulk-only ranking would have silently
excluded **over a third of the namespace**, including a disproportionate share
of the most popular packages (`@babel/*`, `@types/*`). The bias would have been
towards unscoped packages, not towards popular ones.
"""
from __future__ import annotations

import argparse
import io
import json
import sys
import tarfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

PACKAGE = "all-the-package-names"
REGISTRY = "https://registry.npmjs.org"
UA = {"User-Agent": "qresp-audit (+https://github.com/qresp)"}


def _get(url: str, timeout: float = 300.0) -> bytes:
    request = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data: bytes = response.read()
    return data


def resolve_version(version: str | None) -> tuple[str, str]:
    """Return (version, tarball_url). Pin explicitly for reproducibility."""
    metadata = json.loads(_get(f"{REGISTRY}/{PACKAGE}"))
    if version is None:
        version = str(metadata["dist-tags"]["latest"])
        print(f"  version: {version} (latest -- pin it with --version to make "
              f"this frame reproducible)")
    else:
        print(f"  version: {version} (pinned)")
    if version not in metadata["versions"]:
        raise SystemExit(f"{PACKAGE}@{version} does not exist")
    return version, str(metadata["versions"][version]["dist"]["tarball"])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--version", default=None,
                        help=f"Pin a {PACKAGE} version. Default: latest.")
    args = parser.parse_args(argv)

    print(f"enumerating npm via {PACKAGE}")
    started = time.time()
    version, tarball = resolve_version(args.version)

    print(f"  fetching {tarball}")
    raw = _get(tarball)
    print(f"  {len(raw)/1e6:.1f} MB in {time.time()-started:.0f}s")

    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
        member = next((m for m in archive.getmembers()
                       if m.name.endswith("names.json")), None)
        if member is None:
            raise SystemExit("names.json not found in the tarball")
        handle = archive.extractfile(member)
        if handle is None:
            raise SystemExit("names.json could not be read")
        names = json.load(handle)

    scoped = sum(1 for n in names if n.startswith("@"))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text("\n".join(names) + "\n", encoding="utf-8")

    manifest = args.out.with_suffix(".manifest.json")
    manifest.write_text(json.dumps({
        "generated": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "source": f"npm:{PACKAGE}@{version}",
        "tarball": tarball,
        "total": len(names),
        "scoped": scoped,
        "note": "Pinned version makes this frame exactly reproducible; "
                "replicate.npmjs.com/_all_docs returns HTTP 400 and could not "
                "offer that property regardless.",
    }, indent=2), encoding="utf-8")

    print(f"\n  {len(names):,} names ({scoped:,} scoped, "
          f"{100*scoped/len(names):.1f}%)")
    print(f"  -> {args.out}")
    print(f"  -> {manifest}")
    print("\n  Scoped packages cannot use npm's bulk downloads endpoint, which "
          "is why\n  the head ranking is two-stage: over a third of the "
          "namespace would\n  otherwise be excluded from it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
