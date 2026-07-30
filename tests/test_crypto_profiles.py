#!/usr/bin/env python3
"""
Crypto profile selection tests.

These tests protect the migration boundary between the existing ECCIBE-compatible
implementation and the future SGX/MCL Boneh-Franklin IBE implementation.
"""

import os
import sys

import pytest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from client_sdk.sdk import ClientSDK  # noqa: E402
from crypto_lib.bfibe_envelope import BFIBE_KEY_CIPHERTEXT_FORMAT, BFIBE_PROFILE_ID  # noqa: E402
from crypto_lib.profiles import get_crypto_profile, list_crypto_profiles  # noqa: E402


def test_default_client_profile_is_eccibe(monkeypatch):
    monkeypatch.delenv("ASYNCS_CRYPTO_PROFILE", raising=False)

    sdk = ClientSDK()
    info = sdk.get_scheme_info()

    assert sdk.crypto_profile_id == "eccibe"
    assert sdk.ibe_scheme_name == "eccibe"
    assert info["crypto_profile"] == "eccibe"
    assert info["key_ciphertext_format"] == "key-ciphertext-v1-ecc-p256"
    assert info["sgx_integrated"] is True


def test_environment_can_select_eccibe_alias(monkeypatch):
    monkeypatch.setenv("ASYNCS_CRYPTO_PROFILE", "compat")

    sdk = ClientSDK()

    assert sdk.crypto_profile_id == "eccibe"
    assert sdk.ibe_scheme_name == "eccibe"


def test_bfibe_target_profile_is_registered_but_not_accidentally_enabled():
    profile = get_crypto_profile("bfibe")

    assert profile.profile_id == BFIBE_PROFILE_ID
    assert profile.python_scheme is None
    assert profile.is_true_ibe is True
    assert profile.sgx_integrated is False
    assert profile.key_ciphertext_format == BFIBE_KEY_CIPHERTEXT_FORMAT

    with pytest.raises(NotImplementedError, match="MCL/BLS12-381"):
        ClientSDK(crypto_profile="bfibe")


def test_existing_py_ecc_boneh_franklin_is_explicitly_demo_only():
    profile = get_crypto_profile("boneh-franklin")

    assert profile.profile_id == "bfibe-py-ecc-bn128-demo"
    assert profile.python_scheme == "boneh-franklin"
    assert profile.is_true_ibe is True
    assert profile.sgx_integrated is False
    assert profile.key_ciphertext_format == "py-ecc-bn128-pickle-demo"

    sdk = ClientSDK(crypto_profile="boneh-franklin")
    info = sdk.get_scheme_info()
    assert sdk.crypto_profile_id == "bfibe-py-ecc-bn128-demo"
    assert info["crypto_profile"] == "bfibe-py-ecc-bn128-demo"
    assert info["sgx_integrated"] is False


def test_profile_inventory_distinguishes_paper_target_from_demo():
    profile_ids = {profile.profile_id for profile in list_crypto_profiles()}

    assert "eccibe" in profile_ids
    assert "bfibe-mcl-bls12381" in profile_ids
    assert "bfibe-py-ecc-bn128-demo" in profile_ids
