#!/usr/bin/env python3
"""
Tests for BF-IBE KMS-to-worker key-release formats.

The true BF-IBE path has two distinct byte formats:
1. A plaintext private-key set that only exists before/after AEAD protection
   inside trusted code.
2. An outer KMS-to-worker release envelope whose ciphertext carries that
   private-key set over the untrusted host/socket boundary.
"""

import os
import sys

import pytest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from crypto_lib.bfibe_key_release import (  # noqa: E402
    BFIBE_KEY_RELEASE_MAGIC,
    BFIBE_KEY_RELEASE_VERSION,
    BFIBE_PRIVATE_KEY_SET_MAGIC,
    BFIBE_PRIVATE_KEY_SET_VERSION,
    BfIbeKeyRelease,
    BfIbePrivateKeyRecord,
    BfIbePrivateKeySet,
    decode_bfibe_key_release,
    decode_bfibe_private_key_set,
    encode_bfibe_key_release,
    encode_bfibe_private_key_set,
    key_release_associated_data,
)


def _sample_private_key_set() -> BfIbePrivateKeySet:
    return BfIbePrivateKeySet(
        records=(
            BfIbePrivateKeyRecord(
                purpose="request-key",
                identity="fid:0123456789abcdef",
                private_key=b"REQ-SK-BYTES",
            ),
            BfIbePrivateKeyRecord(
                purpose="function-key",
                identity="l:0011223344556677",
                private_key=b"FUNC-SK-BYTES",
            ),
        ),
    )


def test_bfibe_private_key_set_roundtrip_is_deterministic():
    key_set = _sample_private_key_set()

    encoded = encode_bfibe_private_key_set(key_set)
    encoded_again = encode_bfibe_private_key_set(key_set)
    decoded = decode_bfibe_private_key_set(encoded)

    assert encoded == encoded_again
    assert encoded.startswith(BFIBE_PRIVATE_KEY_SET_MAGIC)
    assert encoded[len(BFIBE_PRIVATE_KEY_SET_MAGIC)] == BFIBE_PRIVATE_KEY_SET_VERSION
    assert decoded == key_set
    assert b"REQ-SK-BYTES" in encoded
    assert b"FUNC-SK-BYTES" in encoded


def test_bfibe_key_release_roundtrip_keeps_private_keys_inside_ciphertext():
    key_set = _sample_private_key_set()
    plaintext = encode_bfibe_private_key_set(key_set)
    release = BfIbeKeyRelease(
        fid="fid:0123456789abcdef",
        worker_identity="worker:mrenclave:00112233",
        wrap_public_key=b"K" * 64,
        nonce=b"n" * 12,
        ciphertext=b"encrypted-private-key-set",
    )

    encoded = encode_bfibe_key_release(release)
    encoded_again = encode_bfibe_key_release(release)
    decoded = decode_bfibe_key_release(encoded)

    assert encoded == encoded_again
    assert encoded.startswith(BFIBE_KEY_RELEASE_MAGIC)
    assert encoded[len(BFIBE_KEY_RELEASE_MAGIC)] == BFIBE_KEY_RELEASE_VERSION
    assert decoded == release
    assert b"REQ-SK-BYTES" not in encoded
    assert b"FUNC-SK-BYTES" not in encoded
    assert plaintext != encoded


def test_bfibe_key_release_carries_wrap_public_key_in_clear_and_binds_it_in_aad():
    release = BfIbeKeyRelease(
        fid="fid:0123456789abcdef",
        worker_identity="worker:mrenclave:00112233",
        wrap_public_key=b"KMS-WRAP-PUBLIC-KEY-BYTES",
        nonce=b"n" * 12,
        ciphertext=b"encrypted-private-key-set",
    )
    different_wrap_key = BfIbeKeyRelease(
        fid=release.fid,
        worker_identity=release.worker_identity,
        wrap_public_key=b"DIFFERENT-KMS-WRAP-PUBLIC-KEY",
        nonce=release.nonce,
        ciphertext=release.ciphertext,
    )

    encoded = encode_bfibe_key_release(release)
    decoded = decode_bfibe_key_release(encoded)

    assert decoded.wrap_public_key == release.wrap_public_key
    assert release.wrap_public_key in encoded
    assert key_release_associated_data(release) != key_release_associated_data(different_wrap_key)


def test_bfibe_key_release_rejects_bad_magic_version_and_length():
    release = BfIbeKeyRelease(
        fid="fid",
        worker_identity="worker",
        wrap_public_key=b"K" * 64,
        nonce=b"n" * 12,
        ciphertext=b"ct",
    )
    encoded = bytearray(encode_bfibe_key_release(release))

    bad_magic = bytearray(encoded)
    bad_magic[: len(BFIBE_KEY_RELEASE_MAGIC)] = b"NOTREL!!"
    with pytest.raises(ValueError, match="magic"):
        decode_bfibe_key_release(bytes(bad_magic))

    bad_version = bytearray(encoded)
    bad_version[len(BFIBE_KEY_RELEASE_MAGIC)] = BFIBE_KEY_RELEASE_VERSION + 1
    with pytest.raises(ValueError, match="version"):
        decode_bfibe_key_release(bytes(bad_version))

    with pytest.raises(ValueError, match="length"):
        decode_bfibe_key_release(bytes(encoded) + b"extra")


def test_bfibe_private_key_set_rejects_empty_records_bad_purpose_and_empty_key():
    with pytest.raises(ValueError, match="records"):
        BfIbePrivateKeySet(records=())

    with pytest.raises(ValueError, match="purpose"):
        BfIbePrivateKeyRecord(
            purpose="debug-key",
            identity="fid",
            private_key=b"sk",
        )

    with pytest.raises(ValueError, match="private_key"):
        BfIbePrivateKeyRecord(
            purpose="request-key",
            identity="fid",
            private_key=b"",
        )


def test_bfibe_key_release_aad_binds_profile_fid_and_worker_metadata():
    base = BfIbeKeyRelease(
        fid="fid-a",
        worker_identity="worker-a",
        wrap_public_key=b"K" * 64,
        nonce=b"n" * 12,
        ciphertext=b"ct-a",
    )
    different_worker = BfIbeKeyRelease(
        fid="fid-a",
        worker_identity="worker-b",
        wrap_public_key=b"K" * 64,
        nonce=b"n" * 12,
        ciphertext=b"ct-a",
    )
    different_ciphertext = BfIbeKeyRelease(
        fid="fid-a",
        worker_identity="worker-a",
        wrap_public_key=b"K" * 64,
        nonce=b"n" * 12,
        ciphertext=b"ct-b",
    )

    aad = key_release_associated_data(base)

    assert aad.startswith(b"ASYNCS/BFIBE/KEYRELEASE/AAD/v1")
    assert aad != key_release_associated_data(different_worker)
    assert aad == key_release_associated_data(different_ciphertext)


def test_bfibe_key_release_rejects_empty_wrap_key_bad_nonce_and_empty_ciphertext():
    with pytest.raises(ValueError, match="wrap_public_key"):
        BfIbeKeyRelease(
            fid="fid",
            worker_identity="worker",
            wrap_public_key=b"",
            nonce=b"n" * 12,
            ciphertext=b"ct",
        )

    with pytest.raises(ValueError, match="nonce"):
        BfIbeKeyRelease(
            fid="fid",
            worker_identity="worker",
            wrap_public_key=b"K" * 64,
            nonce=b"short",
            ciphertext=b"ct",
        )

    with pytest.raises(ValueError, match="ciphertext"):
        BfIbeKeyRelease(
            fid="fid",
            worker_identity="worker",
            wrap_public_key=b"K" * 64,
            nonce=b"n" * 12,
            ciphertext=b"",
        )


def test_bfibe_key_release_formats_have_stable_cross_language_vectors():
    key_set = BfIbePrivateKeySet(
        records=(
            BfIbePrivateKeyRecord(
                purpose="request-key",
                identity="fid:001122",
                private_key=bytes.fromhex("aa" * 16),
            ),
            BfIbePrivateKeyRecord(
                purpose="function-key",
                identity="l:667788",
                private_key=bytes.fromhex("bb" * 24),
            ),
        ),
    )
    release = BfIbeKeyRelease(
        fid="fid:001122",
        worker_identity="mrenclave:334455",
        wrap_public_key=bytes.fromhex("11" * 64),
        nonce=bytes.fromhex("33" * 12),
        ciphertext=bytes.fromhex("cc" * 32),
    )

    assert encode_bfibe_private_key_set(key_set).hex() == (
        "41534246534b533101000000120000000262666962652d6d636c2d626c733132"
        "3338310000000b0000000a00000010726571756573742d6b65796669643a3030"
        "31313232aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000c000000080000001866"
        "756e6374696f6e2d6b65796c3a363637373838bbbbbbbbbbbbbbbbbbbbbbbbbb"
        "bbbbbbbbbbbbbbbbbbbbbb"
    )
    assert encode_bfibe_key_release(release).hex() == (
        "4153424652454c3101000000120000000a00000010000000400000000c0000002062666962652d6d636c2d626c7331323338316669643a3030313132326d72656e636c6176653a33333434353511111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111333333333333333333333333cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    )
    assert key_release_associated_data(release).hex() == (
        "4153594e43532f42464942452f4b455952454c454153452f4141442f76310000001262666962652d6d636c2d626c7331323338310000000a6669643a303031313232000000106d72656e636c6176653a3333343435350000004011111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    )
