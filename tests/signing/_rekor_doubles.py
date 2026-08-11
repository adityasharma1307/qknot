"""Test-only builders for Rekor log material, in Rekor's REAL formats.

This is the ONLY place a signed checkpoint or SET is fabricated, and it is under
`tests/` for a reason: production `verify_log_entry` has no home-grown format to
accept. The unit tests sign the SAME formats production verifies -- a Go-sumdb
signed note for the checkpoint, and the canonical-JSON SET -- using a test key.
So "the double" is not a fake format on a side path; it is real Rekor bytes with
a test key, which is what makes the offline tests meaningful.

The formats here were pinned against real Sigstore bundle bytes (see
tests/signing/test_sigstore_fixture.py, which verifies the very same code paths
against production checkpoints and SETs).
"""
from __future__ import annotations

import base64
import hashlib
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from qknot.signing.rekor import LogEntry

# The origin (first body line) may contain spaces, exactly as Rekor's
# "rekor.sigstore.dev - <tree-id>" does; the signature line's key name is the
# space-free hostname, again exactly as Rekor's "— rekor.sigstore.dev <b64>".
_KEY_NAME = "qknot.test"
_ORIGIN = f"{_KEY_NAME} - 0000000000000000"


def log_id_for(public_key: ec.EllipticCurvePublicKey) -> bytes:
    """The Rekor logID: SHA-256 of the key's DER SubjectPublicKeyInfo."""
    der = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).digest()


def signed_checkpoint(
    tree_size: int, root_hash: bytes, key: ec.EllipticCurvePrivateKey,
    *, origin: str = _ORIGIN,
) -> str:
    """A real-format Rekor checkpoint (Go-sumdb signed note) over (size, root).

    Body is origin / tree_size / base64(root); the note is signed over the body
    plus its trailing newline; the signature line carries a 4-byte key hint then
    the raw signature, base64-encoded. `verify_checkpoint` parses exactly this.
    """
    body = f"{origin}\n{tree_size}\n{base64.b64encode(root_hash).decode('ascii')}\n"
    signature = key.sign(body.encode("utf-8"), ec.ECDSA(hashes.SHA256()))
    blob = base64.b64encode(b"\x00\x00\x00\x00" + signature).decode("ascii")
    key_name = origin.split(" ", 1)[0]
    return f"{body}\n— {key_name} {blob}"


def signed_entry_timestamp(
    entry_body: bytes, integrated_time: int, log_id: bytes, log_index: int,
    key: ec.EllipticCurvePrivateKey,
) -> bytes:
    """A real-format Rekor SET over {body, integratedTime, logID, logIndex}."""
    payload = json.dumps({
        "body": base64.b64encode(entry_body).decode("ascii"),
        "integratedTime": integrated_time,
        "logID": log_id.hex(),
        "logIndex": log_index,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return key.sign(payload, ec.ECDSA(hashes.SHA256()))


def make_log_entry(
    *,
    entry_body: bytes,
    log_index: int,
    tree_size: int,
    root_hash: bytes,
    inclusion_proof: list[bytes],
    integrated_time: int,
    key: ec.EllipticCurvePrivateKey,
    proof_index: int | None = None,
) -> LogEntry:
    """A LogEntry whose checkpoint and SET are real-format, signed by `key`.

    `root_hash` is the caller's reconstructed Merkle root: the checkpoint the
    double signs names exactly it, so an honest entry verifies and a tampered
    body/proof/root fails the reconstruction-vs-checkpoint check in
    `verify_log_entry`. `proof_index` defaults to `log_index` -- equal in a
    single-shard test tree; on real sharded Rekor they differ.
    """
    log_id = log_id_for(key.public_key())
    return LogEntry(
        entry_body=entry_body,
        log_index=log_index,
        proof_index=log_index if proof_index is None else proof_index,
        inclusion_proof=inclusion_proof,
        checkpoint=signed_checkpoint(tree_size, root_hash, key),
        log_id=log_id,
        integrated_time=integrated_time,
        set_signature=signed_entry_timestamp(
            entry_body, integrated_time, log_id, log_index, key),
    )
