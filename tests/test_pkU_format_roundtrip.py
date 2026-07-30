#!/usr/bin/env python3
"""
Unit test: pkU encoding must be strict and round-trip stable.

Wire format (required):
  0x04 || X(32 bytes big-endian) || Y(32 bytes big-endian)
"""

import os
import sys

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_lib.kem import P256HKDFKEM


def sgx_le_from_wire_be(pkU65: bytes):
    assert len(pkU65) == 65
    assert pkU65[0] == 0x04
    x_be = pkU65[1:33]
    y_be = pkU65[33:65]
    x_le = x_be[::-1]
    y_le = y_be[::-1]
    return x_le, y_le


def wire_be_from_sgx_le(x_le: bytes, y_le: bytes):
    assert len(x_le) == 32 and len(y_le) == 32
    return b"\x04" + x_le[::-1] + y_le[::-1]


def test_pkU_format_roundtrip():
    kem = P256HKDFKEM()
    pkU, skU = kem.keygen()

    assert isinstance(pkU, (bytes, bytearray))
    assert len(pkU) == 65
    assert pkU[0] == 0x04
    assert len(skU) == 32

    # cryptography decode/encode roundtrip (canonical uncompressed point)
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), pkU)
    pkU2 = pub.public_bytes(
        encoding=Encoding.X962,
        format=PublicFormat.UncompressedPoint,
    )
    assert pkU2 == pkU

    # SGX boundary conversion roundtrip (wire BE <-> SGX LE)
    x_le, y_le = sgx_le_from_wire_be(pkU)
    pkU3 = wire_be_from_sgx_le(x_le, y_le)
    assert pkU3 == pkU


def main() -> int:
    print("=" * 60)
    print("Test: pkU format roundtrip (P-256 uncompressed)")
    print("=" * 60)
    try:
        test_pkU_format_roundtrip()
        print("✅ PASS")
        return 0
    except Exception as e:
        print("❌ FAIL:", e)
        return 1


if __name__ == "__main__":
    sys.exit(main())
