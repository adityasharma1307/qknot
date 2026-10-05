"""A live OIDC registration needs a pre-minted token. Absence is a failure."""
from __future__ import annotations

import os

import pytest


def test_the_identity_token_is_provisioned():
    token = os.environ.get("QKNOT_IDENTITY_TOKEN", "").strip()
    if not token:
        pytest.fail(
            "token not provisioned: set the IDENTITY_TOKEN repository secret, "
            "exposed to tests as QKNOT_IDENTITY_TOKEN"
        )
    assert token.count(".") >= 2, "token not provisioned: value is not a JWT"
