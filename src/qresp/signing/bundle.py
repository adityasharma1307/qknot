"""Serialise a hybrid signature as an OMS-compatible Sigstore bundle.

WHERE EVERYTHING GOES, AND WHY THERE WAS NO CHOICE
==================================================
The placements below are not preferences. They are the only positions the OMS
v1.0 schemas permit, established by validating candidates against the published
schemas rather than by reading the prose. See
`tests/signing/test_oms_compatibility.py`, which re-checks each one.

    dsseEnvelope.signatures[]          MULTIPLE ALLOWED -> both signatures
    subject[].digest["sha3-256"]       digest_set is open -> SHA-3 digest
    subject[].algorithmBinding         subject is open -> THE BINDING
    predicate.resources[] extra keys   open -> per-file SHA-3 digests

    signature.algorithm                REFUSED (additionalProperties: false)
    predicate top-level fields         REFUSED
    statement top-level fields         REFUSED
    serialization.hash_type = sha3     REFUSED (enum)

THE CONSEQUENCE WORTH REPORTING
===============================
`signatures` is an array with no maximum, so a hybrid bundle is structurally
valid OMS today. But `signature` is closed to new fields and the spec states
that `keyid` "is not used for verification", so **a conformant OMS bundle can
carry an ML-DSA signature that no verifier can identify**. OMS can carry a
hybrid signature and cannot describe one. That gap is the substance of the
spec proposal in docs/OMS-COMPATIBILITY.md.

WHY THE BINDING GOES IN THE SUBJECT
===================================
It must sit inside the DSSE payload, because the payload is what the signatures
cover. A binding outside it could be edited freely, and the whole
non-separability argument would collapse. `predicate` and the statement root
are both closed, so `subject[]` -- which permits additional properties -- is
the only position that is both schema-valid and signed.

That reasoning is now literally true rather than aspirational: signatures are
computed over the DSSE PAE of this payload (see dsse.py), so everything the
statement carries -- binding, entropy attestation, backend descriptors, notes --
is covered. The payload is therefore emitted verbatim from `signed.payload` and
never rebuilt, since re-serialising it risks a byte difference that would
invalidate a genuine signature.

BACKWARD COMPATIBILITY
======================
An unmodified OMS verifier reads this bundle, validates it, finds the Ed25519
signature it understands, and ignores the rest. It gets exactly the protection
it would have had anyway. A QResP-aware verifier additionally checks the ML-DSA
signature and enforces the binding. Nothing is forked.
"""
from __future__ import annotations

import base64
import json
from typing import Any

from .sign import SignedArtefact

OMS_PREDICATE_TYPE = "https://model_signing/signature/v1.0"
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
SIGSTORE_BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"

# OMS requires sha256 in resource descriptors and permits nothing else, so the
# manifest carries both and this is the one the descriptors declare.
OMS_DIGEST_ALGORITHM = "sha256"


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def build_statement(
    signed: SignedArtefact,
    subject_name: str,
    include_entropy_attestation: bool = True,
) -> dict[str, Any]:
    """The in-toto Statement that both signatures cover."""
    digest_set: dict[str, str] = {}
    if signed.manifest is not None:
        # OMS requires a sha256 entry. The manifest computed both.
        # `excluded` must be passed here too: omitting it would produce a
        # sha256 digest over a different construction from the sha3-256 one,
        # so the two entries in the digest set would not describe the same tree.
        from .digest import manifest_digest

        digest_set[OMS_DIGEST_ALGORITHM] = manifest_digest(
            signed.manifest.entries, OMS_DIGEST_ALGORITHM,
            signed.manifest.excluded)
    digest_set[signed.digest_algorithm] = signed.digest

    subject: dict[str, Any] = {
        "name": subject_name,
        "digest": digest_set,
        # The extension point that makes non-separability possible inside OMS.
        "algorithmBinding": signed.binding.to_dict(),
        "signerPublicKeys": {
            algorithm: key.hex() for algorithm, key in sorted(signed.public_keys.items())
        },
        "backends": signed.backend_info,
    }

    if include_entropy_attestation and signed.entropy_attestation is not None:
        attestation = signed.entropy_attestation
        subject["entropyAttestation"] = (
            attestation.to_dict() if hasattr(attestation, "to_dict") else attestation
        )

    if signed.notes:
        subject["notes"] = signed.notes

    if signed.manifest is not None and signed.manifest.excluded:
        # A summary, not the full list: the paths are already bound into the
        # root digest, so a verifier re-walking the tree detects any change.
        # Carrying every path of a large .git checkout would bloat the bundle
        # for no additional guarantee. The count is here so a reader can see at
        # a glance that the artefact contained unhashed paths at all.
        subject["exclusions"] = {
            "count": len(signed.manifest.excluded),
            "byReason": signed.manifest.exclusion_summary(),
            "note": (
                "paths present in the artefact whose contents were not hashed. "
                "Their names, reasons and symlink targets ARE bound into the "
                "digest, so adding or repointing one invalidates the signature."
            ),
        }

    resources = []
    if signed.manifest is not None:
        for entry in signed.manifest.entries:
            descriptor: dict[str, Any] = {
                "name": entry.path,
                "digest": entry.digests[OMS_DIGEST_ALGORITHM],
                "algorithm": OMS_DIGEST_ALGORITHM,
            }
            # resource_descriptor permits extra properties, so the SHA-3 digest
            # rides alongside rather than replacing the required one.
            if signed.digest_algorithm in entry.digests:
                descriptor["digestSha3_256"] = entry.digests[signed.digest_algorithm]
            resources.append(descriptor)
    else:
        resources.append({
            "name": subject_name,
            "digest": digest_set.get(OMS_DIGEST_ALGORITHM, signed.digest),
            "algorithm": OMS_DIGEST_ALGORITHM,
            "digestSha3_256": signed.digest,
        })

    return {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": [subject],
        "predicateType": OMS_PREDICATE_TYPE,
        "predicate": {
            "resources": resources,
            "serialization": {
                "method": "files",
                # Constrained to an enum that excludes SHA-3. The SHA-3 digests
                # travel as extra descriptor fields; this declares the one OMS
                # can express. Gap 2 in the spec proposal.
                "hash_type": OMS_DIGEST_ALGORITHM,
                "allow_symlinks": False,
            },
        },
    }


def build_bundle(
    signed: SignedArtefact,
    subject_name: str | None = None,
    include_entropy_attestation: bool = True,
) -> dict[str, Any]:
    """Assemble the full Sigstore-shaped bundle.

    The payload is emitted **verbatim** from `signed.payload` rather than
    rebuilt. Rebuilding would re-run `json.dumps` and any difference at all --
    key order, separators, unicode escaping, a field added since signing -- would
    produce a bundle whose signatures do not verify, with nothing in the error
    to suggest that serialisation was the cause.

    Signatures are emitted in the binding's canonical (sorted) order so the
    bundle is byte-reproducible from the same inputs.

    Args:
        subject_name: optional assertion about what was signed. The name is
            inside the signed payload and fixed at signing time, so this is
            checked rather than applied; pass `subject_name=` to `sign()` to
            set it.
    """
    if not signed.payload:
        raise ValueError(
            "this SignedArtefact carries no payload. It was produced before "
            "DSSE PAE signing and must be re-signed."
        )
    if subject_name is not None and subject_name != signed.subject_name:
        raise ValueError(
            f"subject_name={subject_name!r} does not match the signed payload, "
            f"which names {signed.subject_name!r}. The subject is inside the "
            f"signed material and cannot be changed after signing; pass "
            f"subject_name to sign() instead."
        )
    payload = signed.payload

    signatures = []
    for algorithm in signed.binding.algorithms:
        signature = signed.signatures.get(algorithm)
        if signature is None:
            continue
        # `keyid` is the only place an algorithm hint can go, and the spec says
        # it is not used for verification. Populating it is better than nothing
        # and is not a substitute for the `algorithm` field OMS lacks.
        signatures.append({"sig": _b64(signature), "keyid": algorithm})

    return {
        "mediaType": SIGSTORE_BUNDLE_MEDIA_TYPE,
        "dsseEnvelope": {
            "payload": _b64(payload),
            "payloadType": DSSE_PAYLOAD_TYPE,
            "signatures": signatures,
        },
    }


def parse_bundle(bundle: dict[str, Any]) -> SignedArtefact:
    """Reconstruct a SignedArtefact from a bundle, for verification.

    Deliberately reads the algorithm list from the **binding**, not from the
    signatures present. Trusting the signatures would defeat the whole
    mechanism: an attacker who strips one would simply be believed.
    """
    from .combiner import HybridBinding

    envelope = bundle.get("dsseEnvelope")
    if not isinstance(envelope, dict):
        raise ValueError("bundle has no dsseEnvelope")

    try:
        payload = base64.b64decode(envelope["payload"])
        statement = json.loads(payload)
    except Exception as exc:
        raise ValueError(f"could not decode the DSSE payload: {exc}") from exc
    if not isinstance(statement, dict) or not statement.get("subject"):
        raise ValueError("payload is not an in-toto statement with a subject")

    subject = statement["subject"][0]
    raw_binding = subject.get("algorithmBinding")
    if not raw_binding:
        raise ValueError(
            "bundle carries no algorithmBinding. It may be a plain OMS bundle, "
            "which cannot be verified for non-separability."
        )

    binding = HybridBinding(
        suite=raw_binding["suite"],
        algorithms=list(raw_binding["algorithms"]),
        digest=subject["digest"].get(raw_binding["digestAlgorithm"], ""),
        digest_algorithm=raw_binding["digestAlgorithm"],
        binding=raw_binding["binding"],
        binding_algorithm=raw_binding.get("bindingAlgorithm", "sha3-256"),
        context=raw_binding.get("context", ""),
    )

    signatures: dict[str, bytes] = {}
    for entry in envelope.get("signatures", []):
        keyid = entry.get("keyid")
        if keyid:
            signatures[keyid] = base64.b64decode(entry["sig"])

    public_keys = {
        algorithm: bytes.fromhex(value)
        for algorithm, value in (subject.get("signerPublicKeys") or {}).items()
    }

    return SignedArtefact(
        binding=binding,
        signatures=signatures,
        public_keys=public_keys,
        digest=binding.digest,
        digest_algorithm=binding.digest_algorithm,
        timestamp="",
        # The raw bytes as they arrived. Verification recomputes the PAE from
        # these, so re-encoding here -- however faithfully -- would risk
        # invalidating a genuine signature over a formatting difference.
        payload=payload,
        subject_name=subject.get("name", "artefact"),
        manifest=None,
        entropy_attestation=subject.get("entropyAttestation"),
        backend_info=subject.get("backends", {}),
        notes=subject.get("notes", []),
    )


def bundle_to_json(bundle: dict[str, Any], indent: int = 2) -> str:
    return json.dumps(bundle, indent=indent, sort_keys=True)
