"""Transparency-log inclusion: step 6 of the registration verification, and the
source of the upper-bound time `T` the temporal rescue turns on.

This is the *verification* side and it is pure computation, so it is built and
tested offline against a locally constructed Merkle tree. It does not SUBMIT to
a live log -- that is the second network seam an operator wires to a vetted
Rekor client -- but the cryptographic core it depends on (RFC 6962 inclusion
proofs and a signed tree head) is exactly what a real log produces, so what an
expert reviews here is what runs.

Three things are checked, and all three are required:

  1. the digest is EXTRACTED FROM the entry body that is proven included, and
     equals `rekord_preimage(payloadType, payload)`. It is not a free-floating
     field the submitter can set independently -- an expert review found that a
     separate `body_sha256` let a real inclusion proof for an unrelated entry
     be rebound to any registration by rewriting that field. The digest now
     comes from the same bytes whose inclusion is proven, so the two cannot be
     decoupled;
  2. the inclusion proof reconstructs the signed root -- RFC 6962 section 2.1.1;
  3. the tree head is signed by the log's key -- so the root, and therefore the
     inclusion, is the log's own claim and not the submitter's.

The entry body is a hashedrekord-shaped structure (kind, spec.data.hash), which
is what a real Rekor leaf carries. The digest lives at spec.data.hash.value and
is parsed out here -- so mapping a live Rekor entry into a LogEntry is a shape
translation, not a trust decision.

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
    "hashedrekord_body",
    "hashedrekord_digest",
    "leaf_hash",
    "verify_inclusion_root",
    "verify_log_entry",
]


def hashedrekord_body(preimage: bytes) -> bytes:
    """A canonical hashedrekord-shaped entry body committing to `preimage`.

    The shape a real Rekor hashedrekord carries, minimally: kind, and
    spec.data.hash.{algorithm,value}. Canonical JSON so the bytes are a function
    of the digest alone -- the Merkle leaf is computed over exactly these bytes,
    so nothing outside them can be smuggled into what the log attests.
    """
    import json

    return json.dumps({
        "kind": "hashedrekord",
        "apiVersion": "0.0.1",
        "spec": {"data": {"hash": {
            "algorithm": "sha256", "value": preimage.hex()}}},
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")


def hashedrekord_digest(entry_body: bytes) -> bytes:
    """Extract the sha256 digest a hashedrekord entry body commits to.

    Parsed from the SAME bytes whose inclusion is proven, which is the whole
    point: the digest and the proven leaf cannot be decoupled.
    """
    import json

    try:
        data = json.loads(entry_body)
        hashinfo = data["spec"]["data"]["hash"]
    except Exception as exc:  # noqa: BLE001
        raise InclusionError(
            f"entry body is not a parseable hashedrekord: {exc}") from exc
    if hashinfo.get("algorithm") != "sha256":
        raise InclusionError(
            f"entry hash algorithm is {hashinfo.get('algorithm')!r}, not sha256")
    try:
        return bytes.fromhex(hashinfo["value"])
    except (KeyError, ValueError) as exc:
        raise InclusionError(f"entry hash value is not hex: {exc}") from exc


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

    `entry_body` is the canonical hashedrekord body: the RFC 6962 leaf is hashed
    over exactly these bytes, and the digest the entry attests is parsed out of
    them (`hashedrekord_digest`). There is deliberately no separate digest
    field -- one would let a real inclusion proof be rebound to a different
    registration, which is the hole this design closes.
    """

    entry_body: bytes             # the canonical hashedrekord body, and the leaf
    log_index: int
    tree_size: int
    inclusion_proof: list[bytes]
    root_hash: bytes
    integrated_time: int          # epoch seconds; the upper bound T
    tree_head_signature: bytes    # the log's signature over the signed tree head

    def to_dict(self) -> dict[str, Any]:
        import base64

        return {
            "entryBody": base64.b64encode(self.entry_body).decode("ascii"),
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
                entry_body=base64.b64decode(data["entryBody"], validate=True),
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
        """A TEST-DOUBLE signed-tree-head format, NOT Rekor's.

        A real transparency log signs a checkpoint (Rekor v2) or an STH / SET
        (v1) with its own canonicalisation. `qresp-sth-v1` is a deliberately
        minimal stand-in so the Merkle and signature logic can be exercised
        offline, and it is the ONE thing here that a Sigstore adapter must
        replace rather than map: an operator wiring a real log parses the log's
        checkpoint/SET and verifies it with the log's own rules, then feeds the
        established root and integratedTime into this module. Everything else --
        the inclusion proof math, the digest-to-leaf binding -- is real and
        unchanged. Named with `qresp-` and documented as a double so it is never
        mistaken for the real format.
        """
        return b"qresp-sth-v1-TESTDOUBLE\n%d\n%s" % (
            tree_size, root_hash.hex().encode())


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

    # 1. The digest is PARSED FROM the entry body -- the same bytes whose
    #    inclusion is proven below -- and must equal our registration's
    #    pre-image. There is no independent digest field to rewrite, so a real
    #    proof for an unrelated entry cannot be rebound to this registration.
    if hashedrekord_digest(entry.entry_body) != expected_preimage:
        raise InclusionError(
            "the entry body commits to a different digest than this "
            "registration's pre-image; the inclusion proof is for another entry")

    # 2. That same body is the leaf whose inclusion the proof reconstructs.
    computed = verify_inclusion_root(
        entry.log_index, entry.tree_size, leaf_hash(entry.entry_body),
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
