#!/usr/bin/env python3
"""
OpenWhisk helper metadata tests for crypto-profile-aware confidential actions.
"""

import base64
import json
import os
import sys

import pytest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from openwhisk_extensions.controller.confidential_actions import (  # noqa: E402
    ConfidentialInvokeRequest,
)
from openwhisk_extensions.invoker.confidential_invoker import (  # noqa: E402
    ConfidentialActionsInvoker,
)


def test_controller_activation_message_carries_key_and_profile_metadata():
    request = ConfidentialInvokeRequest(
        fid="fid",
        c_req=b"encrypted-request",
        c_key=b"encrypted-request-key",
        pk_u=b"user-public-key",
        nonce=b"nonce",
        c_k_func=b"encrypted-function-key",
        crypto_profile="compat",
    )

    activation = request.to_activation_message()

    assert activation["C_k_func"] == base64.b64encode(b"encrypted-function-key").decode("utf-8")
    assert activation["crypto_profile"] == "eccibe"
    assert activation["key_ciphertext_format"] == "key-ciphertext-v1-ecc-p256"


def test_invoker_receive_activation_decodes_key_and_profile_metadata():
    message = {
        "activationId": "act-123",
        "action": {"path": "guest", "name": "confidentialAction"},
        "content": {
            "FID": "fid",
            "C_req": base64.b64encode(b"encrypted-request").decode("utf-8"),
            "C_k_func": base64.b64encode(b"encrypted-function-key").decode("utf-8"),
            "C_key": base64.b64encode(b"encrypted-request-key").decode("utf-8"),
            "pkU": base64.b64encode(b"user-public-key").decode("utf-8"),
            "crypto_profile": "eccibe",
            "key_ciphertext_format": "key-ciphertext-v1-ecc-p256",
        },
        "nonce": base64.b64encode(b"nonce").decode("utf-8"),
    }

    activation = ConfidentialActionsInvoker().receive_activation(json.dumps(message).encode("utf-8"))

    assert activation["C_k_func"] == b"encrypted-function-key"
    assert activation["C_key"] == b"encrypted-request-key"
    assert activation["crypto_profile"] == "eccibe"
    assert activation["key_ciphertext_format"] == "key-ciphertext-v1-ecc-p256"


def test_openwhisk_helpers_allow_registered_bfibe_metadata():
    request = ConfidentialInvokeRequest(
        fid="fid",
        c_req=b"encrypted-request",
        c_key=b"bfibe-request-envelope",
        pk_u=b"user-public-key",
        nonce=b"nonce",
        c_k_func=b"bfibe-function-envelope",
        crypto_profile="bfibe",
        key_ciphertext_format="bfibe-mcl-bls12381-envelope-v1",
    )

    activation = request.to_activation_message()

    assert activation["crypto_profile"] == "bfibe-mcl-bls12381"
    assert activation["key_ciphertext_format"] == "bfibe-mcl-bls12381-envelope-v1"


def test_openwhisk_helpers_reject_mismatched_profile_format():
    with pytest.raises(ValueError, match="key_ciphertext_format"):
        ConfidentialInvokeRequest(
            fid="fid",
            c_req=b"encrypted-request",
            c_key=b"encrypted-request-key",
            pk_u=b"user-public-key",
            nonce=b"nonce",
            crypto_profile="eccibe",
            key_ciphertext_format="bfibe-mcl-bls12381-envelope-v1",
        )
