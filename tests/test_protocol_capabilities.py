#!/usr/bin/env python3
"""
Protocol(A) capability semantics audit

Verifies the code-level security property:
- dkf/dklabelfunc are treated as DecKey-only capabilities
- AEAD encrypt/decrypt uses only derived session keys (k_req/k_func/k_U)

This is a static audit of the SGX Worker enclave source.
"""

import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENCLAVE_CPP = os.path.join(ROOT, "sgx_worker", "Enclave", "Enclave.cpp")


def main() -> int:
    print("=" * 60)
    print("Protocol(A) Capability Semantics Audit")
    print("=" * 60)

    with open(ENCLAVE_CPP, "r", encoding="utf-8") as f:
        content = f.read()

    # 1) Ensure we have an explicit DecKey primitive.
    assert "static bool DecKey(" in content, "Missing DecKey(cap, ciphertext) primitive"
    print("  ✓ DecKey(cap, ciphertext) primitive present")

    # 2) Ensure capabilities are fed into DecKey (and not directly into AEAD).
    assert "DecKey(g_worker_key" in content, "dkf (g_worker_key) should be used via DecKey(...)"
    assert "DecKey(g_dklabel_func" in content, "dklabelfunc (g_dklabel_func) should be used via DecKey(...)"
    print("  ✓ Capabilities are used via DecKey(...)")

    # 3) Ensure AEAD is not invoked with dkf/dklabelfunc as the key argument.
    forbidden = [
        "(const sgx_aes_gcm_128bit_key_t*)g_worker_key",
        "(const sgx_aes_gcm_128bit_key_t*)g_dklabel_func",
    ]
    for needle in forbidden:
        assert needle not in content, f"Forbidden AEAD key usage found: {needle}"
    print("  ✓ No AEAD call uses dkf/dklabelfunc directly")

    # 4) Ensure session-key variables are used as AEAD keys in the encrypted execution path.
    required = [
        "(const sgx_aes_gcm_128bit_key_t*)k_func_128",
        "(const sgx_aes_gcm_128bit_key_t*)k_req_128",
        "(const sgx_aes_gcm_128bit_key_t*)k_U_128",
    ]
    for needle in required:
        assert needle in content, f"Expected session-key AEAD usage missing: {needle}"
    print("  ✓ AEAD uses derived session keys (k_func/k_req/k_U)")

    print("\n✅ Protocol(A) capability semantics verified (static audit).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

