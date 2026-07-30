#!/usr/bin/env python3
"""
Implementation Gap(G2): RID canonicalization

Canonical encoding:
- FID is a 32-byte digest serialized as 64-hex string (preferred)
- RID = H(FID_bytes || C_req_bytes)

This test ensures SDK/controller/invoker agree on the canonical encoding, while
preserving legacy behavior for non-hex FID values used by some unit tests.
"""

import os
import sys
import hashlib

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from client_sdk.sdk import ClientSDK  # noqa: E402
from openwhisk_extensions.invoker.confidential_invoker import ConfidentialActionsInvoker  # noqa: E402
from openwhisk_extensions.controller.confidential_actions import ClientReceiptHandler  # noqa: E402


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def test_hex_fid_canonicalization() -> None:
    print("\n[Test] Canonical RID with hex FID (32-byte digest)")
    sdk = ClientSDK()

    fid = sdk.compute_fid("tenant", "action", "v1", b"wasm-bytes")
    assert len(fid) == 64, "FID should be 64 hex chars"

    c_req = b"\x01\x02C_REQ_BYTES\x03\x04"

    fid_bytes = bytes.fromhex(fid)
    expected = _sha256(fid_bytes + c_req).hex()

    rid_sdk = sdk._compute_rid(fid, c_req)
    rid_invoker = ConfidentialActionsInvoker.compute_rid(fid, c_req)
    rid_controller = ClientReceiptHandler.compute_rid(fid, c_req)

    assert rid_sdk == expected, "SDK RID must be canonical H(FID_bytes || C_req)"
    assert rid_invoker == expected, "Invoker RID must match canonical encoding"
    assert rid_controller == expected, "Controller/client receipt RID must match canonical encoding"
    print("  ✓ SDK/controller/invoker agree on canonical RID")


def test_legacy_non_hex_fid_behavior() -> None:
    print("\n[Test] Legacy RID behavior for non-hex FID (compatibility)")
    fid = "test_fid_protocolB"
    c_req = b"C_REQ_BYTES"

    expected_legacy = _sha256(fid.encode("utf-8") + c_req).hex()
    rid_invoker = ConfidentialActionsInvoker.compute_rid(fid, c_req)
    rid_controller = ClientReceiptHandler.compute_rid(fid, c_req)

    assert rid_invoker == expected_legacy, "Invoker must preserve legacy RID for non-hex FID"
    assert rid_controller == expected_legacy, "Controller must preserve legacy RID for non-hex FID"
    print("  ✓ Legacy behavior preserved for non-hex FID")


def static_audit_worker_enclave() -> None:
    print("\n[Static Audit] Worker enclave RID uses canonical hex FID when available")
    enclave_cpp = os.path.join(ROOT, "sgx_worker", "Enclave", "Enclave.cpp")
    with open(enclave_cpp, "r", encoding="utf-8") as f:
        content = f.read()

    required = [
        "Canonical encoding:",
        "fid_len == 64",
        "bytes32",
        "hex_nibble",
    ]
    for needle in required:
        assert needle in content, f"Missing expected canonicalization logic in enclave: {needle}"
    print("  ✓ Enclave source contains hex-FID canonicalization branch")


def main() -> int:
    print("=" * 60)
    print("RID Canonicalization Tests (G2)")
    print("=" * 60)

    test_hex_fid_canonicalization()
    test_legacy_non_hex_fid_behavior()
    static_audit_worker_enclave()

    print("\n✅ G2 RID canonicalization verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

