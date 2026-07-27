"""RETIRED. Use scripts/verify/run_fips204_acvp.py instead.

This script validated the wrong algorithm.

It ran `PQCsignKAT_Dilithium{2,3,5}.rsp` against
`dilithium_py.dilithium.Dilithium{2,3,5}` -- both halves the **round-3
Dilithium** submission. The backend this project signs with is
`dilithium_py.ml_dsa.ML_DSA_44`, which is **ML-DSA (FIPS 204)**.

Different algorithms, not a renaming:

    Dilithium2 secret key  2528 bytes
    ML-DSA-44  secret key  2560 bytes
    a Dilithium2 signature does not verify under ML-DSA-44

So it passed, and told us nothing about the code that actually signs. The
replacement uses NIST's ACVP FIPS 204 vectors -- vendored, so they run offline
-- and covers keyGen, sigGen and sigVer, byte-exact including the hedged path.

Kept as a stub rather than deleted so that anyone following an old reference,
a commit message, or a draft of the paper lands here and reads why, instead of
finding a missing file and assuming the check was dropped.

    python scripts/verify/run_fips204_acvp.py
    pytest tests/signing/test_fips204_acvp.py -q

See tests/signing/fips204_vectors/PROVENANCE.md for the full account.
"""
from __future__ import annotations

import sys

MESSAGE = __doc__


def main() -> int:
    print(MESSAGE)
    return 2


if __name__ == "__main__":
    sys.exit(main())
