"""Revocation search, and the difference between "none" and "did not look".

The property under test is mostly not "does it find revocations" but "does it
ever claim an all-clear it did not earn". An attacker who can make the search
fail -- block the network, rate-limit the verifier, serve entries whose contents
cannot be retrieved -- must not thereby obtain a clean verdict, because that is
enormously cheaper than attacking any of the cryptography.
"""
from __future__ import annotations

import base64
import datetime

import pytest

pytest.importorskip("cryptography", reason="needs `cryptography`")

from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.serialization import (  # noqa: E402
    Encoding,
    PublicFormat,
)

from qresp.signing.dsse import rekord_preimage  # noqa: E402
from qresp.signing.registration import (  # noqa: E402
    REVOCATION_PAYLOAD_TYPE,
    Revocation,
    _key_fingerprint,
)
from qresp.signing.rekor import hashedrekord_body, leaf_hash  # noqa: E402
from qresp.signing.revocation_search import (  # noqa: E402
    RevocationSearchOutcome,
    find_revocations,
    not_searched,
)

from ._rekor_doubles import log_id_for, signed_checkpoint, signed_entry_timestamp  # noqa: E402

IDENTITY = "alice@example.com"


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


class FakeSearchClient:
    """Serves whatever entries a test wants -- including none, or broken ones."""

    def __init__(self, entries=None, explode=False):
        self.entries = entries or []
        self.explode = explode

    def search_by_identity(self, identity):
        if self.explode:
            raise ConnectionError("the log is unreachable")
        return self.entries


def _log_key():
    key = ec.generate_private_key(ec.SECP256R1())
    return key, key.public_key().public_bytes(
        Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def _logged_revocation(revocation: Revocation, log_key, *, with_statement=True,
                       signature=b"sig-not-checked-here", moment=None):
    """A log entry that really does carry this revocation's digest."""
    payload = revocation.to_payload()
    preimage = rekord_preimage(REVOCATION_PAYLOAD_TYPE, payload)
    body = hashedrekord_body(preimage)
    root = leaf_hash(body)
    when = moment or (datetime.datetime.now(datetime.timezone.utc)
                      - datetime.timedelta(days=1))
    integrated = int(when.timestamp())
    log_id = log_id_for(log_key.public_key())
    entry = {
        "logIndex": 7,
        "logId": {"keyId": _b64(log_id)},
        "integratedTime": integrated,
        "inclusionPromise": {"signedEntryTimestamp": _b64(
            signed_entry_timestamp(body, integrated, log_id, 7, log_key))},
        "inclusionProof": {
            "logIndex": 0, "treeSize": 1, "hashes": [],
            "rootHash": _b64(root),
            "checkpoint": {"envelope": signed_checkpoint(1, root, log_key)},
        },
        "canonicalizedBody": _b64(body),
    }
    if with_statement:
        entry["qrespRevocation"] = {"payload": _b64(payload),
                                    "signature": _b64(signature)}
    return entry


def _revocation(fingerprint, identity=IDENTITY):
    return Revocation(identity=identity, pqc_key_fingerprint=fingerprint,
                      reason="key compromised", revoked_at="2026-06-01T00:00:00Z")


FINGERPRINT = _key_fingerprint(b"the-registered-pqc-key")


class TestItNeverClaimsAnUnearnedAllClear:
    """The heart of it."""

    def test_a_transport_failure_is_failed_not_none_found(self):
        _key, pub = _log_key()
        result = find_revocations(IDENTITY, FINGERPRINT,
                                  client=FakeSearchClient(explode=True),
                                  log_public_key=pub)
        assert result.outcome is RevocationSearchOutcome.FAILED
        assert not result.is_conclusive
        assert "NOT evidence" in result.detail

    def test_entries_whose_statements_are_unavailable_are_failed(self):
        """The log stores digests. An entry we cannot read is UNKNOWN, and
        reporting it as an all-clear would be the whole hole."""
        key, pub = _log_key()
        entry = _logged_revocation(_revocation(FINGERPRINT), key,
                                   with_statement=False)
        result = find_revocations(IDENTITY, FINGERPRINT,
                                  client=FakeSearchClient([entry]),
                                  log_public_key=pub)
        assert result.outcome is RevocationSearchOutcome.FAILED
        assert not result.is_conclusive
        assert "UNKNOWN, not 'no'" in result.detail

    def test_not_searched_is_not_conclusive(self):
        assert not not_searched().is_conclusive

    def test_an_empty_log_is_conclusive(self):
        """Having genuinely looked and found nothing is a real answer."""
        _key, pub = _log_key()
        result = find_revocations(IDENTITY, FINGERPRINT,
                                  client=FakeSearchClient([]),
                                  log_public_key=pub)
        assert result.outcome is RevocationSearchOutcome.NONE_FOUND
        assert result.is_conclusive


class TestItFindsRealRevocations:
    def test_a_logged_revocation_for_this_key_is_found_with_its_log_time(self):
        key, pub = _log_key()
        entry = _logged_revocation(_revocation(FINGERPRINT), key)
        result = find_revocations(IDENTITY, FINGERPRINT,
                                  client=FakeSearchClient([entry]),
                                  log_public_key=pub)
        assert result.outcome is RevocationSearchOutcome.FOUND
        assert len(result.revocations) == 1
        _statement, logged_at = result.revocations[0]
        assert isinstance(logged_at, datetime.datetime)
        assert logged_at.tzinfo is not None


class TestItIgnoresWhatIsNotAboutThisKey:
    """Ignoring is correct here -- a log search returns unrelated entries -- but
    only for candidates it could actually READ and rule out."""

    def test_a_revocation_of_a_different_key_is_not_applied(self):
        key, pub = _log_key()
        other = _key_fingerprint(b"someone-elses-key")
        entry = _logged_revocation(_revocation(other), key)
        result = find_revocations(IDENTITY, FINGERPRINT,
                                  client=FakeSearchClient([entry]),
                                  log_public_key=pub)
        assert result.outcome is RevocationSearchOutcome.NONE_FOUND
        assert result.revocations == []

    def test_a_revocation_naming_a_different_identity_is_not_applied(self):
        key, pub = _log_key()
        entry = _logged_revocation(
            _revocation(FINGERPRINT, identity="mallory@evil.example"), key)
        result = find_revocations(IDENTITY, FINGERPRINT,
                                  client=FakeSearchClient([entry]),
                                  log_public_key=pub)
        assert result.outcome is RevocationSearchOutcome.NONE_FOUND

    def test_a_statement_the_log_does_not_carry_is_inconclusive_not_clear(self):
        """A forged 'revocation' served alongside a real log entry. It names
        this key, so it is not harmless noise -- and because the log stores only
        a digest, we cannot tell whether the real entry revokes this key. The
        honest answer is UNKNOWN. Reporting 'none found' here would let an
        attacker suppress a real revocation by serving a mismatched statement."""
        key, pub = _log_key()
        entry = _logged_revocation(_revocation(FINGERPRINT), key)
        forged = _revocation(FINGERPRINT)
        forged = Revocation(identity=forged.identity,
                            pqc_key_fingerprint=forged.pqc_key_fingerprint,
                            reason="TOTALLY different reason",
                            revoked_at="2020-01-01T00:00:00Z")
        entry["qrespRevocation"] = {"payload": _b64(forged.to_payload()),
                                    "signature": _b64(b"x")}
        result = find_revocations(IDENTITY, FINGERPRINT,
                                  client=FakeSearchClient([entry]),
                                  log_public_key=pub)
        assert result.revocations == []
        assert result.outcome is RevocationSearchOutcome.FAILED
        assert not result.is_conclusive

    def test_a_damaged_revocation_does_not_become_an_all_clear(self):
        """The suppression attack: take a REAL revocation of this key and break
        its log authentication (here, present it under the wrong log key). It
        must not be silently skipped into a clean verdict."""
        key, _pub = _log_key()
        _other_key, other_pub = _log_key()
        entry = _logged_revocation(_revocation(FINGERPRINT), key)
        result = find_revocations(IDENTITY, FINGERPRINT,
                                  client=FakeSearchClient([entry]),
                                  log_public_key=other_pub)
        assert result.revocations == []
        assert result.outcome is RevocationSearchOutcome.FAILED
        assert not result.is_conclusive
