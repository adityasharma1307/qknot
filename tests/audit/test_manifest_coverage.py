"""A manifest that omits a fetched file is not covered, and not unsigned."""
from __future__ import annotations

import base64
import json

from qknot.audit.detect import manifest_status
from qknot.audit.model import QLabel


def _oms(names: list[str]) -> bytes:
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "model", "digest": {"sha256": "ab"}}],
        "predicate": {
            "resources": [
                {"name": name, "digest": "aa" * 32, "algorithm": "sha256"}
                for name in names
            ],
        },
    }
    envelope = {
        "payload": base64.b64encode(json.dumps(statement).encode()).decode(),
        "payloadType": "application/vnd.in-toto+json",
    }
    return json.dumps(envelope).encode()


def test_every_listed_name_present_is_complete():
    payload = _oms(["weights.safetensors", "config.json"])
    assert manifest_status(
        payload, ["weights.safetensors", "config.json", "model.sig"],
    ) == "manifest-complete"


def test_a_missing_listed_file_is_incomplete_not_unsigned():
    payload = _oms(["weights.safetensors", "config.json"])
    status = manifest_status(payload, ["weights.safetensors", "model.sig"])
    assert status == "manifest-incomplete"
    assert status != QLabel.UNSIGNED.value
    assert status != QLabel.ERROR.value


def test_an_unreadable_payload_is_not_unsigned():
    status = manifest_status(b"not json", ["model.sig"])
    assert status == "manifest-unreadable"
    assert status != QLabel.UNSIGNED.value
