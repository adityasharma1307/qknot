"""Transparency-log inclusion: step 6 of the registration verification, and the
source of the upper-bound time `T` the temporal rescue turns on.

This is the *verification* side. It does not SUBMIT to a live log -- that is the
network seam an operator wires to a vetted Rekor client -- but every byte it
consumes is the byte a real Rekor entry carries, and every signature it checks is
a signature Rekor actually produces. What an expert reviews here is what runs.

WHAT IS AUTHENTICATED, AND BY WHAT
==================================
A registration's trustworthy time is load-bearing: the whole temporal rescue
turns on `T`. So nothing here is trusted as a bare field; each claim is tied to a
signature by the log's own key:

  1. THE PRE-IMAGE. The digest is EXTRACTED FROM the entry body that is proven
     included (`hashedrekord_digest`), and must equal the registration's
     pre-image. It is not a free field the submitter can set -- an expert review
     found that a separate `body_sha256` let a real inclusion proof for an
     unrelated entry be rebound to any registration. The digest now comes from
     the same bytes whose inclusion is proven, so the two cannot be decoupled.

  2. THE ROOT. The Merkle root is NOT accepted as a field either. It is parsed
     out of the log's signed CHECKPOINT (Rekor's STH), whose signature is
     verified under the log key, and the inclusion proof must reconstruct THAT
     root -- the checkpoint's, not a submitted one. A signature over a note that
     names a different root, or an inclusion proof to a root the log never
     signed, both fail.

  3. THE TIME. `integratedTime` is NOT accepted as a field either. It is
     authenticated by the log's signed entry timestamp (the SET, Rekor's
     `inclusionPromise`), whose signature over `{body, integratedTime, logID,
     logIndex}` is verified under the log key. Since the rescue turns on `T`, a
     `T` the log never signed would be the softest hole in the design; this
     closes it.

  4. THE LOG. The SET's `logID` must be `SHA-256(log public key)`, binding the
     entry to the specific log whose key the verifier trusts -- an entry signed
     by a different log cannot be presented under this one's key.

`integratedTime` is then an UPPER bound: the entry existed by that instant. Only
an upper bound can rescue (temporal.binding_trust), which is why this returns it
typed as one.

The checkpoint and SET are Rekor's real formats (Go-sumdb signed note; the
canonical-JSON SET). There is deliberately no home-grown stand-in format in this
module: a verifier that only understood a QResP-invented note would either
reject real Rekor material or, worse, accept a fabricated note wrapped around a
real root. Tests exercise these SAME real formats with a test key (see
tests/signing/_rekor_doubles.py), so the format the unit tests sign is the format
production verifies.
"""
from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

__all__ = [
    "InclusionError",
    "LogEntry",
    "hashedrekord_body",
    "hashedrekord_digest",
    "leaf_hash",
    "verify_checkpoint",
    "verify_inclusion_root",
    "verify_log_entry",
    "verify_set",
]


class InclusionError(Exception):
    """A transparency-log inclusion proof did not verify."""


# ---------------------------------------------------------------------------
# The hashedrekord body: the leaf, and the digest it commits to.
# ---------------------------------------------------------------------------

def hashedrekord_body(preimage: bytes) -> bytes:
    """A canonical hashedrekord-shaped entry body committing to `preimage`.

    The shape a real Rekor hashedrekord carries, minimally: kind, and
    spec.data.hash.{algorithm,value}. Canonical JSON so the bytes are a function
    of the digest alone -- the Merkle leaf is computed over exactly these bytes,
    so nothing outside them can be smuggled into what the log attests.
    """
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


# ---------------------------------------------------------------------------
# RFC 6962 inclusion math.
# ---------------------------------------------------------------------------

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
    caller to compare against the log's signed one.
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


# ---------------------------------------------------------------------------
# The log's signatures: checkpoint (root) and SET (time).
# ---------------------------------------------------------------------------

def _verify_log_signature(message: bytes, signature: bytes, key_der: bytes) -> None:
    """Verify one of the log's own signatures under its public key.

    Rekor signs with ECDSA-P256/SHA-256; Ed25519 is accepted for logs that use
    it. Any failure is an InclusionError so callers treat it as a rejection.
    """
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
            "a log signature does not verify under the log's public key; the "
            "claim it covers is not the log's own") from exc


def verify_checkpoint(
    checkpoint: str, log_public_key_der: bytes,
) -> tuple[int, bytes]:
    """Verify a Rekor checkpoint (signed tree head) and return (tree_size, root).

    A checkpoint is a Go-sumdb signed note: a text body followed by a blank line
    and one or more signature lines. The body's first three lines are the origin,
    the tree size, and the base64 root hash; the note is signed over the body
    plus its trailing newline. The signature line is `<sep> <key-name> <base64>`,
    and the base64 decodes to a 4-byte key hint followed by the raw signature.

    Returns the tree size and root the LOG signed. The caller must require the
    inclusion proof to reconstruct THIS root -- the checkpoint is the only
    trustworthy source of it, never a submitted field.
    """
    text, sep, sigblock = checkpoint.partition("\n\n")
    if not sep:
        raise InclusionError(
            "checkpoint has no blank line separating body from signature; it is "
            "not a signed note")
    signed = (text + "\n").encode("utf-8")

    lines = text.split("\n")
    if len(lines) < 3:
        raise InclusionError(
            "checkpoint body has fewer than three lines (origin, size, root)")
    try:
        tree_size = int(lines[1])
    except ValueError as exc:
        raise InclusionError(
            f"checkpoint tree size {lines[1]!r} is not an integer") from exc
    if tree_size <= 0:
        raise InclusionError(f"checkpoint tree size {tree_size} is not positive")
    try:
        root_hash = base64.b64decode(lines[2], validate=True)
    except Exception as exc:  # noqa: BLE001
        raise InclusionError(
            f"checkpoint root hash {lines[2]!r} is not base64") from exc
    if len(root_hash) != 32:
        raise InclusionError(
            f"checkpoint root hash is {len(root_hash)} bytes, not a SHA-256 root")

    sigline = next(
        (ln for ln in sigblock.splitlines()
         if ln.startswith("— ") or ln.startswith("- ")), None)
    if sigline is None:
        raise InclusionError("checkpoint has no signature line")
    parts = sigline.split(" ", 2)
    if len(parts) < 3:
        raise InclusionError("checkpoint signature line is malformed")
    try:
        raw = base64.b64decode(parts[2], validate=True)
    except Exception as exc:  # noqa: BLE001
        raise InclusionError("checkpoint signature is not base64") from exc
    if len(raw) <= 4:
        raise InclusionError(
            "checkpoint signature is too short to carry a key hint and signature")
    signature = raw[4:]                       # strip the 4-byte key hint

    _verify_log_signature(signed, signature, log_public_key_der)
    return tree_size, root_hash


def verify_set(
    entry_body: bytes,
    integrated_time: int,
    log_id: bytes,
    log_index: int,
    set_signature: bytes,
    log_public_key_der: bytes,
) -> None:
    """Verify a Rekor signed entry timestamp (SET), authenticating the time.

    The SET is an ECDSA signature over the RFC 8785 / canonical JSON of
    {body, integratedTime, logID, logIndex}, where `body` is the base64 of the
    canonicalized entry body and `logID` is the hex of the log key's SHA-256.
    Verifying it is what makes `integratedTime` the log's signed claim rather
    than a number the submitter chose -- and the rescue turns on that number.
    """
    payload = json.dumps({
        "body": base64.b64encode(entry_body).decode("ascii"),
        "integratedTime": integrated_time,
        "logID": log_id.hex(),
        "logIndex": log_index,
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    _verify_log_signature(payload, set_signature, log_public_key_der)


# ---------------------------------------------------------------------------
# The entry, and the composed verification.
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class LogEntry:
    """A transparency-log entry and everything needed to authenticate it offline.

    Every field that carries a trust claim is checked against a log signature in
    `verify_log_entry`, so none of them is trusted as presented:

      * `entry_body` -- the canonical hashedrekord body; the RFC 6962 leaf is
        hashed over exactly these bytes, and the attested digest is parsed out of
        them. There is deliberately no separate digest field.
      * `checkpoint` -- the log's signed note; the ONLY source of the root and
        tree size (both parsed out and authenticated, never taken as fields).
      * `set_signature` + `log_id` -- the log's signed entry timestamp, which
        authenticates `integrated_time`.

    `inclusion_proof`, `log_index` and `proof_index` carry no trust on their own:
    a wrong proof or index simply fails to reconstruct the checkpoint's signed
    root, or fails the SET signature.

    There are TWO indices because a sharded log (Rekor is one) has two: the
    GLOBAL `log_index` that the SET signs and that names the entry across the
    whole log, and the shard-local `proof_index` -- the entry's position within
    the checkpoint's Merkle tree -- that the RFC 6962 proof is computed against.
    They are equal only in a single-shard log; conflating them makes the SET
    fail on real Rekor material (`proof_index < tree_size <= log_index`).
    """

    entry_body: bytes             # the canonical hashedrekord body, and the leaf
    log_index: int                # GLOBAL log index; the SET signs this
    proof_index: int              # position in the checkpoint's tree; Merkle proof
    inclusion_proof: list[bytes]
    checkpoint: str               # the log's signed note (STH): root + tree size
    log_id: bytes                 # SHA-256 of the log key; binds the SET's logID
    integrated_time: int          # claimed T; authenticated by the SET below
    set_signature: bytes          # the log's signed entry timestamp

    def to_dict(self) -> dict[str, Any]:
        return {
            "entryBody": base64.b64encode(self.entry_body).decode("ascii"),
            "logIndex": self.log_index,
            "proofIndex": self.proof_index,
            "inclusionProof": [base64.b64encode(h).decode("ascii")
                               for h in self.inclusion_proof],
            "checkpoint": self.checkpoint,
            "logId": base64.b64encode(self.log_id).decode("ascii"),
            "integratedTime": self.integrated_time,
            "setSignature": base64.b64encode(self.set_signature).decode("ascii"),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> LogEntry:
        try:
            return cls(
                entry_body=base64.b64decode(data["entryBody"], validate=True),
                log_index=int(data["logIndex"]),
                proof_index=int(data["proofIndex"]),
                inclusion_proof=[base64.b64decode(h, validate=True)
                                 for h in data["inclusionProof"]],
                checkpoint=str(data["checkpoint"]),
                log_id=base64.b64decode(data["logId"], validate=True),
                integrated_time=int(data["integratedTime"]),
                set_signature=base64.b64decode(
                    data["setSignature"], validate=True),
            )
        except (KeyError, ValueError) as exc:
            raise InclusionError(f"log entry is malformed: {exc}") from exc


def verify_log_entry(
    entry: LogEntry,
    expected_preimage: bytes,
    log_public_key_der: bytes,
    at_time: datetime | None = None,
) -> datetime:
    """Verify inclusion end-to-end and return the authenticated upper bound `T`.

    Configuration -- the log's public key -- is validated before the entry's
    attacker-controlled fields are trusted, the same ordering as elsewhere. Then
    every trust claim is tied to a log signature: the digest to the proven leaf,
    the root to the signed checkpoint, the time to the signed SET, and the SET to
    this specific log.
    """
    if not log_public_key_der:
        raise InclusionError(
            "no log public key supplied; inclusion cannot be verified against "
            "an unknown log. Configuration error, not a proof failure.")

    at_time = at_time or datetime.now(timezone.utc)

    # 1. The digest is PARSED FROM the entry body -- the same bytes whose
    #    inclusion is proven below -- and must equal our registration's
    #    pre-image. No independent digest field exists to rewrite, so a real
    #    proof for an unrelated entry cannot be rebound to this registration.
    if hashedrekord_digest(entry.entry_body) != expected_preimage:
        raise InclusionError(
            "the entry body commits to a different digest than this "
            "registration's pre-image; the inclusion proof is for another entry")

    # 2. The root and tree size come from the LOG's signed checkpoint, not from
    #    submitted fields. The signature is verified here.
    tree_size, signed_root = verify_checkpoint(entry.checkpoint, log_public_key_der)

    # 3. The inclusion proof must reconstruct THAT signed root -- the log's own
    #    claim -- at the checkpoint's tree size. Reconstructing some other root
    #    the log never signed is not inclusion.
    computed = verify_inclusion_root(
        entry.proof_index, tree_size, leaf_hash(entry.entry_body),
        entry.inclusion_proof)
    if computed != signed_root:
        raise InclusionError(
            "inclusion proof does not reconstruct the checkpoint's signed root; "
            "the entry is not in the tree the log attests to")

    # 4. The SET binds this entry to THIS log and authenticates integratedTime.
    #    logID must be SHA-256 of the trusted log key, so an entry timestamped by
    #    a different log cannot be presented under this key.
    expected_log_id = hashlib.sha256(log_public_key_der).digest()
    if entry.log_id != expected_log_id:
        raise InclusionError(
            "the entry's logID is not SHA-256 of the trusted log key; this entry "
            "belongs to a different log than the one this verifier trusts")
    verify_set(entry.entry_body, entry.integrated_time, entry.log_id,
               entry.log_index, entry.set_signature, log_public_key_der)

    # 5. Only now is integratedTime trustworthy: it is the log's signed claim.
    integrated = datetime.fromtimestamp(entry.integrated_time, tz=timezone.utc)
    if integrated > at_time:
        raise InclusionError(
            f"the log's integratedTime {integrated.isoformat()} is in the "
            f"future relative to {at_time.isoformat()}; a timestamp that has "
            f"not happened yet cannot bound anything")
    return integrated
