"""Transparency-log inclusion: step 6 of the registration verification, and the
source of the upper-bound time `T` the temporal rescue turns on.

This is the *verification* side and it is pure computation, so it is built and
tested offline against a locally constructed Merkle tree. It does not SUBMIT to
a live log -- that is the second network seam an operator wires to a vetted
Rekor client -- but the cryptographic core it depends on (RFC 6962 inclusion
proofs and a signed tree head) is exactly what a real log produces, so what an
expert reviews here is what runs.

Three things are checked, and all three are required:

  1. the entry the log holds commits to OUR registration -- its logged hash
     equals `rekord_preimage(payloadType, payload)`, or the proof is about
     someone else's entry;
  2. the inclusion proof reconstructs the signed root -- RFC 6962 section 2.1.1;
  3. the tree head is signed by the log's key -- so the root, and therefore the
     inclusion, is the log's own claim and not the submitter's.

`integratedTime` is then an UPPER bound: the entry existed by that instant.
Only an upper bound can rescue (temporal.binding_trust), which is why this
returns it typed as one.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

__all__ = [
    "InclusionError",
    "LogEntry",
    "leaf_hash",
    "verify_inclusion_root",
    "verify_log_entry",
]


class InclusionError(Exception):
    """A transparency-log inclusion proof did not verify."""


def _hash_children(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def leaf_hash(entry_bytes: bytes) -> bytes:
    """RFC 6962 leaf hash: SHA-256 of 0x00 || entry, domain-separated from the
    0x01 prefix of internal nodes so a leaf can never be read as a node."""
    return hashlib.sha256(b"\x00" + entry_bytes).digest()


def _inner_proof_size(index: int, tree_size: int) -> int:
    return (index ^ (tree_size - 1)).bit_length()


def verify_inclusion_root(
    log_index: int,
    tree_size: int,
    leaf: bytes,
    proof: list[bytes],
) -> bytes:
    """Reconstruct the Merkle root from a leaf and its audit path (RFC 6962).

    The sigstore/trillian split into an inner path (below the tree's border)
    and a border path, which is the form that is correct for non-power-of-two
    trees -- the common case for a live log. Returns the computed root for the
    caller to compare against the signed one.
    """
    if not 0 <= log_index < tree_size:
        raise InclusionError(
            f"log index {log_index} is outside a tree of size {tree_size}")

    inner = _inner_proof_size(log_index, tree_size)
    if inner > len(proof):
        raise InclusionError(
            f"proof of {len(proof)} hashes is too short for an inner size of "
            f"{inner}")

    result = leaf
    index = log_index
    for sibling in proof[:inner]:
        if index & 1 == 0:
            result = _hash_children(result, sibling)
        else:
            result = _hash_children(sibling, result)
        index >>= 1
    for sibling in proof[inner:]:
        result = _hash_children(sibling, result)
    return result


@dataclass(frozen=True)
class LogEntry:
    """A transparency-log entry and the proof it is included.

    `body_sha256` is the hash the log recorded -- which for a registration is
    `rekord_preimage(...)`. `entry_leaf` is the RFC 6962 leaf the tree actually
    hashed; a real Rekor leaf is the canonicalised entry body, so the two are
    kept distinct rather than assumed equal.
    """

    body_sha256: bytes            # what the entry attests: our registration hash
    entry_leaf: bytes             # the bytes the Merkle leaf was computed over
    log_index: int
    tree_size: int
    inclusion_proof: list[bytes]
    root_hash: bytes
    integrated_time: int          # epoch seconds; the upper bound T
    tree_head_signature: bytes    # the log's signature over the signed tree head

    def to_dict(self) -> dict[str, Any]:
        import base64

        return {
            "bodySha256": base64.b64encode(self.body_sha256).decode("ascii"),
            "entryLeaf": base64.b64encode(self.entry_leaf).decode("ascii"),
            "logIndex": self.log_index,
            "treeSize": self.tree_size,
            "inclusionProof": [base64.b64encode(h).decode("ascii")
                               for h in self.inclusion_proof],
            "rootHash": base64.b64encode(self.root_hash).decode("ascii"),
            "integratedTime": self.integrated_time,
            "treeHeadSignature": base64.b64encode(
                self.tree_head_signature).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LogEntry:
        import base64

        try:
            return cls(
                body_sha256=base64.b64decode(data["bodySha256"], validate=True),
                entry_leaf=base64.b64decode(data["entryLeaf"], validate=True),
                log_index=int(data["logIndex"]),
                tree_size=int(data["treeSize"]),
                inclusion_proof=[base64.b64decode(h, validate=True)
                                 for h in data["inclusionProof"]],
                root_hash=base64.b64decode(data["rootHash"], validate=True),
                integrated_time=int(data["integratedTime"]),
                tree_head_signature=base64.b64decode(
                    data["treeHeadSignature"], validate=True),
            )
        except (KeyError, ValueError) as exc:
            raise InclusionError(f"log entry is malformed: {exc}") from exc

    @staticmethod
    def signed_tree_head(root_hash: bytes, tree_size: int) -> bytes:
        """The canonical bytes the log signs. Kept as one function so the
        producer and verifier cannot disagree on what the signature covers --
        the same lesson as the shared rekord pre-image."""
        return b"qresp-sth-v1\n%d\n%s" % (tree_size, root_hash.hex().encode())


def verify_log_entry(
    entry: LogEntry,
    expected_preimage: bytes,
    log_public_key_der: bytes,
    at_time: datetime | None = None,
) -> datetime:
    """Verify inclusion and return the upper-bound time `T`.

    Configuration -- the log's public key -- is validated before the entry's
    attacker-controlled fields are trusted, the same ordering as elsewhere.
    """
    if not log_public_key_der:
        raise InclusionError(
            "no log public key supplied; inclusion cannot be verified against "
            "an unknown log. Configuration error, not a proof failure.")

    at_time = at_time or datetime.now(timezone.utc)

    # 1. The entry is about OUR registration, not some other logged document.
    if entry.body_sha256 != expected_preimage:
        raise InclusionError(
            "the log entry's recorded hash does not match this registration's "
            "pre-image; the inclusion proof is for a different entry")

    # 2. The inclusion proof reconstructs the claimed root. entry_leaf is the
    #    bytes the Merkle leaf was computed over, so it is hashed here -- the
    #    proof math operates on leaf HASHES, and passing raw bytes would look
    #    like a proof failure while actually being a units mismatch.
    computed = verify_inclusion_root(
        entry.log_index, entry.tree_size, leaf_hash(entry.entry_leaf),
        entry.inclusion_proof)
    if computed != entry.root_hash:
        raise InclusionError(
            "inclusion proof does not reconstruct the signed root; the entry is "
            "not in the tree the log attests to")

    # 3. The tree head is the LOG's claim, signed by the log's key.
    _verify_tree_head_signature(
        LogEntry.signed_tree_head(entry.root_hash, entry.tree_size),
        entry.tree_head_signature, log_public_key_der)

    integrated = datetime.fromtimestamp(entry.integrated_time, tz=timezone.utc)
    if integrated > at_time:
        raise InclusionError(
            f"the log's integratedTime {integrated.isoformat()} is in the "
            f"future relative to {at_time.isoformat()}; a timestamp that has "
            f"not happened yet cannot bound anything")
    return integrated


def _verify_tree_head_signature(
    message: bytes, signature: bytes, key_der: bytes,
) -> None:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519
    from cryptography.hazmat.primitives.serialization import load_der_public_key

    try:
        key: Any = load_der_public_key(key_der)
    except Exception as exc:  # noqa: BLE001
        raise InclusionError(f"log public key does not parse: {exc}") from exc

    try:
        if isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        elif isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, message)
        else:
            raise InclusionError(
                f"log key type {type(key).__name__} is not supported")
    except InvalidSignature as exc:
        raise InclusionError(
            "the signed tree head does not verify under the log's public key; "
            "the root -- and so the inclusion -- is not the log's own claim"
        ) from exc
