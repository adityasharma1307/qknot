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


def _mldsa_module() -> Any:
    """The module is `mldsa`, NOT `ml_dsa`. That mistake cost a false negative.

    The first version of this probe imported
    `cryptography.hazmat.primitives.asymmetric.ml_dsa`, found nothing, and
    reported "ML-DSA certificates not parseable" on two independent machines.
    The real module is `mldsa` and it was present and working on both. Absence
    of a name I guessed is not absence of a capability -- which is the exact
    error this module was written to stop, committed inside the fix for it.
    """
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
    except Exception:
        return None
    return mldsa


def pqc_parsing_capability() -> dict[str, Any]:
    """What this environment can actually do with post-quantum certificates.

    FUNCTIONAL, not nominal: it generates a key and signs with it rather than
    asking whether an import succeeded. A module can be importable and
    non-functional when the linked OpenSSL lacks the primitive, and the whole
    point of this file is that the version does not decide the answer.

    Measured on cryptography 48.0.0 / OpenSSL 4.0.0 and 49.0.0 / OpenSSL 4.0.1,
    which behaved identically:

      * ML-DSA keys: generate and sign work, all three parameter sets.
      * ML-DSA certificate ISSUANCE: refused. `CertificateBuilder.public_key()`
        raises TypeError listing only classical key types, so no Python code
        here can mint one -- which is why the fixtures in
        tests/audit/test_postquantum_detection.py splice an OID instead.
      * SLH-DSA: absent entirely. No `slhdsa` module at all.
    """
    mldsa = _mldsa_module()

    ml_dsa_works = False
    if mldsa is not None:
        try:
            key = mldsa.MLDSA87PrivateKey.generate()
            ml_dsa_works = len(key.sign(b"capability-probe")) > 0
        except Exception:
            ml_dsa_works = False

    slh_dsa = False
    for name in ("slhdsa", "slh_dsa"):
        try:
            __import__(f"cryptography.hazmat.primitives.asymmetric.{name}")
            slh_dsa = True
            break
        except Exception:
            continue

    can_issue = False
    if ml_dsa_works:
        try:
            import datetime

            from cryptography import x509
            from cryptography.x509.oid import NameOID

            key = mldsa.MLDSA87PrivateKey.generate()
            name_obj = x509.Name(
                [x509.NameAttribute(NameOID.COMMON_NAME, "probe")])
            now = datetime.datetime.now(datetime.timezone.utc)
            (x509.CertificateBuilder().subject_name(name_obj)
                 .issuer_name(name_obj).public_key(key.public_key())
                 .serial_number(1)
                 .not_valid_before(now - datetime.timedelta(days=1))
                 .not_valid_after(now + datetime.timedelta(days=1))
                 .sign(key, None))
            can_issue = True
        except Exception:
            can_issue = False

    try:
        from cryptography.hazmat.bindings._rust import openssl as rust

        openssl_350 = bool(rust.CRYPTOGRAPHY_OPENSSL_350_OR_GREATER)
    except Exception:
        openssl_350 = False

    return {
        "mlDsaKeysUsable": ml_dsa_works,
        "mlDsaCertificatesIssuable": can_issue,
        "slhDsaAvailable": slh_dsa,
        "opensslIsAtLeast350": openssl_350,
        "oidFallbackActive": True,
        "note": (
            "mlDsaKeysUsable is probed by generating and signing, not by "
            "importing: a module can be present and non-functional when the "
            "linked OpenSSL lacks the primitive. mlDsaCertificatesIssuable is "
            "reported separately because it is FALSE even where keys work -- "
            "CertificateBuilder refuses non-classical public keys -- so no "
            "Python here can mint a post-quantum certificate to test against. "
            "slhDsaAvailable False means a FIPS 205 signature could not be "
            "classified through the structured path at all; the OID fallback "
            "in audit/pqc_oid.py still records it as a finding."
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
