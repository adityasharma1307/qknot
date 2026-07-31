"""What the environment running a scan could and could not have detected.

WHY A SCAN MUST RECORD THIS ABOUT ITSELF
========================================
The study reports that no post-quantum signatures were found. Whether that
sentence is about the ecosystems or about the scanner depends entirely on
whether the scanner's X.509 stack could parse a post-quantum certificate --
and that is a property of the environment, not of this repository.

`cryptography` added ML-DSA certificate loading in 2026, gated on OpenSSL 3.5.0
or later. Its own release notes add that because it ships wheels with a bundled
OpenSSL, most users will not have the APIs even after upgrading. Measured here:
cryptography 48.0.0 linked against **OpenSSL 4.0.0** still exposes no
`asymmetric.ml_dsa` module. The OpenSSL version is necessary and not
sufficient; how the wheel was built decides it.

So "could this run have seen an ML-DSA certificate?" has a different answer on
different machines, on the same day, with the same requirements file. A scan
that does not record its own answer cannot support a negative result later --
the reader is asked to trust that the detector worked, which is exactly what
this project refuses to do anywhere else.

This module answers it, and `scan_environment()` goes into every manifest.
"""
from __future__ import annotations

import platform
import sys
from typing import Any

__all__ = ["pqc_parsing_capability", "scan_environment"]


def _openssl_version() -> str | None:
    try:
        from cryptography.hazmat.backends.openssl.backend import backend
    except Exception:
        return None
    try:
        text: str = backend.openssl_version_text()
        return text
    except Exception:
        return None


def pqc_parsing_capability() -> dict[str, Any]:
    """Which post-quantum schemes this environment's X.509 stack understands.

    Probes for the modules rather than reading a version number, because the
    version does not determine the answer: the same `cryptography` release
    exposes these or does not, depending on the OpenSSL it was built against.
    A probe is a measurement; a version comparison would be an inference from
    convention, which is the failure mode this project has now found three
    times.
    """
    schemes: dict[str, bool] = {}
    for name in ("ml_dsa", "slh_dsa", "ml_kem"):
        try:
            __import__(f"cryptography.hazmat.primitives.asymmetric.{name}")
            schemes[name] = True
        except Exception:
            schemes[name] = False

    return {
        "mlDsaCertificatesParseable": schemes["ml_dsa"],
        "slhDsaCertificatesParseable": schemes["slh_dsa"],
        "mlKemAvailable": schemes["ml_kem"],
        # The fallback is what actually caught a post-quantum certificate in
        # this repository, and it works regardless of the above.
        "oidFallbackActive": True,
        "note": (
            "A False here means this environment's cryptography build cannot "
            "parse such certificates through the structured path. qresp still "
            "detects them by algorithm OID (audit/pqc_oid.py) and records them "
            "as findings rather than parse errors -- but a scan run in an "
            "environment where these are False could not have CLASSIFIED one "
            "through the normal path, and any negative result must be read "
            "with that in mind."
        ),
    }


def scan_environment() -> dict[str, Any]:
    """The provenance of a scan run. Embedded in every manifest."""
    try:
        import cryptography

        version = cryptography.__version__
    except Exception:
        version = None

    return {
        "python": sys.version.split()[0],
        "platform": platform.platform(),
        "cryptography": version,
        "openssl": _openssl_version(),
        "pqcParsing": pqc_parsing_capability(),
    }
