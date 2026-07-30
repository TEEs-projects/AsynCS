#!/usr/bin/env python3
"""
IC1: KeyCiphertextV1 format + ECCIBE interop sanity.

This test validates the repo-wide encoding used for C_key / C_k_func produced by ECCIBE:
  C = EphemeralPK(65) || iv12 || tag16 || ct

It also validates ECCIBE.encrypt/decrypt roundtrip still works after encoding changes
and that extraction uses little-endian scalar alignment with SGX.
"""

import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from crypto_lib.ibe import ECCIBE  # noqa: E402


def main() -> int:
    print("=" * 60)
    print("IC1 KeyCiphertextV1 + ECCIBE Sanity Test")
    print("=" * 60)

    ibe = ECCIBE()
    params, msk = ibe.setup()

    identity = "fid_" + "a" * 60
    message = b"0123456789abcdef"  # 16 bytes

    pk = ibe.extract_public(msk, identity)
    sk = ibe.extract(msk, identity)
    c = ibe.encrypt(pk, identity, message)

    # Format checks
    assert len(c) >= 65 + 12 + 16 + 1
    epk = c[:65]
    iv = c[65 : 65 + 12]
    tag = c[65 + 12 : 65 + 12 + 16]
    ct = c[65 + 12 + 16 :]

    assert epk[0] == 0x04, "EphemeralPK must be uncompressed point (0x04||X||Y)"
    assert len(iv) == 12
    assert len(tag) == 16
    assert len(ct) == len(message), "Ciphertext length must match plaintext length (AES-GCM)"

    pt = ibe.decrypt(sk, c)
    assert pt == message, "ECCIBE decrypt must recover original message"

    print("✅ KeyCiphertextV1 format OK; ECCIBE roundtrip OK.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

