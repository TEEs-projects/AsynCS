#!/usr/bin/env python3
"""
Tests for the versioned BF-IBE key-ciphertext envelope.

The envelope is intentionally crypto-free: it fixes the cross-language wire
format before the SGX/MCL encrypt/decrypt backend is wired into KMS and worker.
"""

import os
import sys

import pytest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from crypto_lib.bfibe_envelope import (  # noqa: E402
    BFIBE_ENVELOPE_MAGIC,
    BFIBE_ENVELOPE_VERSION,
    BfIbeEnvelope,
    decode_bfibe_envelope,
    encode_bfibe_envelope,
    envelope_associated_data,
)


def test_bfibe_envelope_roundtrip_is_deterministic():
    envelope = BfIbeEnvelope(
        purpose="request-key",
        identity="fid:0123456789abcdef",
        aad_context=b"REQ" + bytes.fromhex("00" * 32),
        c1=b"G2-COMPRESSED-BYTES",
        nonce=b"123456789012",
        ciphertext=b"encrypted-key-and-tag",
    )

    encoded = encode_bfibe_envelope(envelope)
    encoded_again = encode_bfibe_envelope(envelope)
    decoded = decode_bfibe_envelope(encoded)

    assert encoded == encoded_again
    assert encoded.startswith(BFIBE_ENVELOPE_MAGIC)
    assert encoded[len(BFIBE_ENVELOPE_MAGIC)] == BFIBE_ENVELOPE_VERSION
    assert decoded == envelope


def test_bfibe_envelope_rejects_wrong_magic_and_version():
    envelope = BfIbeEnvelope(
        purpose="function-key",
        identity="l:abcd",
        aad_context=b"PKG",
        c1=b"c1",
        nonce=b"n" * 12,
        ciphertext=b"ct",
    )
    encoded = bytearray(encode_bfibe_envelope(envelope))

    bad_magic = bytearray(encoded)
    bad_magic[: len(BFIBE_ENVELOPE_MAGIC)] = b"NOTBFIBE"
    with pytest.raises(ValueError, match="magic"):
        decode_bfibe_envelope(bytes(bad_magic))

    bad_version = bytearray(encoded)
    bad_version[len(BFIBE_ENVELOPE_MAGIC)] = BFIBE_ENVELOPE_VERSION + 1
    with pytest.raises(ValueError, match="version"):
        decode_bfibe_envelope(bytes(bad_version))


def test_bfibe_envelope_rejects_unknown_purpose_and_profile():
    with pytest.raises(ValueError, match="purpose"):
        BfIbeEnvelope(
            purpose="debug-key",
            identity="fid",
            aad_context=b"",
            c1=b"c1",
            nonce=b"n" * 12,
            ciphertext=b"ct",
        )

    with pytest.raises(ValueError, match="profile"):
        BfIbeEnvelope(
            profile_id="eccibe",
            purpose="request-key",
            identity="fid",
            aad_context=b"",
            c1=b"c1",
            nonce=b"n" * 12,
            ciphertext=b"ct",
        )


def test_bfibe_envelope_aad_changes_with_identity_and_context():
    base = BfIbeEnvelope(
        purpose="request-key",
        identity="fid-a",
        aad_context=b"context-a",
        c1=b"c1",
        nonce=b"n" * 12,
        ciphertext=b"ct",
    )
    different_identity = BfIbeEnvelope(
        purpose="request-key",
        identity="fid-b",
        aad_context=b"context-a",
        c1=b"c1",
        nonce=b"n" * 12,
        ciphertext=b"ct",
    )
    different_context = BfIbeEnvelope(
        purpose="request-key",
        identity="fid-a",
        aad_context=b"context-b",
        c1=b"c1",
        nonce=b"n" * 12,
        ciphertext=b"ct",
    )

    aad = envelope_associated_data(base)

    assert aad.startswith(b"ASYNCS/BFIBE/AAD/v1")
    assert aad != envelope_associated_data(different_identity)
    assert aad != envelope_associated_data(different_context)


def test_bfibe_envelope_has_stable_cross_language_test_vector():
    envelope = BfIbeEnvelope(
        purpose="function-key",
        identity="l:0011223344556677",
        aad_context=b"PKG" + bytes.fromhex("11" * 32),
        c1=bytes.fromhex("22" * 48),
        nonce=bytes.fromhex("33" * 12),
        ciphertext=bytes.fromhex("44" * 32),
    )

    assert encode_bfibe_envelope(envelope).hex() == (
        "415342464942453101000000120000000c000000120000002300000030000000"
        "0c0000002062666962652d6d636c2d626c73313233383166756e6374696f6e2d"
        "6b65796c3a30303131323233333434353536363737504b471111111111111111"
        "1111111111111111111111111111111111111111111111112222222222222222"
        "2222222222222222222222222222222222222222222222222222222222222222"
        "2222222222222222333333333333333333333333444444444444444444444444"
        "4444444444444444444444444444444444444444"
    )
    assert envelope_associated_data(envelope).hex() == (
        "4153594e43532f42464942452f4141442f76310000001262666962652d6d636c"
        "2d626c7331323338310000000c66756e6374696f6e2d6b6579000000126c3a30"
        "30313132323333343435353636373700000023504b4711111111111111111111"
        "11111111111111111111111111111111111111111111"
    )
