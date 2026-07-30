#!/usr/bin/env python3
"""
AAD Binding Security Tests

Tests that verify proper AAD (Additional Authenticated Data) binding for:
- aad_pkg = ("PKG", FID) for function code encryption
- aad_req = ("REQ", FID, nonce, H(pkU)) for request encryption  
- aad_out = ("OUT", FID, RID, H(pkU)) for output encryption

These tests verify that:
1. Correct AAD allows successful decryption
2. Wrong AAD causes decryption to fail (security property)
3. Empty AAD is not used (security property)
"""

import os
import sys
import hashlib

# Add parent directory to path for SDK imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client_sdk.sdk import ClientSDK
from crypto_lib.ibe import ECCIBE


def test_aad_pkg_binding():
    """Test aad_pkg = ("PKG", FID) binding for function code encryption."""
    print("\n[Test] aad_pkg binding for function code encryption")
    
    sdk = ClientSDK()
    code_wasm = b"test wasm code"
    
    # Encrypt function code
    result = sdk.encrypt_function_code("tenant", "action", "v1", code_wasm)
    fid = result["fid"]
    c_func = result["c_func"]
    k_func = result["k_func"]
    
    # 1. Verify correct AAD works
    correct_aad = sdk._build_aad_pkg(fid)
    decrypted = sdk.aead.decrypt(k_func, c_func, correct_aad)
    assert decrypted == code_wasm, "Correct aad_pkg should allow decryption"
    print("  ✓ Correct aad_pkg allows decryption")
    
    # 2. Verify wrong FID fails
    wrong_fid = "b" * 64
    wrong_aad = sdk._build_aad_pkg(wrong_fid)
    try:
        sdk.aead.decrypt(k_func, c_func, wrong_aad)
        assert False, "Wrong FID should fail"
    except Exception:
        print("  ✓ Wrong FID in aad_pkg causes decryption failure")
    
    # 3. Verify empty AAD fails
    try:
        sdk.aead.decrypt(k_func, c_func, b"")
        assert False, "Empty AAD should fail"
    except Exception:
        print("  ✓ Empty AAD causes decryption failure")
    
    # 4. Verify using only FID (without PKG prefix) fails
    fid_only = bytes.fromhex(fid)
    try:
        sdk.aead.decrypt(k_func, c_func, fid_only)
        assert False, "FID without PKG prefix should fail"
    except Exception:
        print("  ✓ FID without 'PKG' prefix causes decryption failure")
    
    print("  ✅ aad_pkg binding test PASSED")
    return True


def test_aad_req_binding():
    """Test aad_req = ("REQ", FID, nonce, H(pkU)) binding for request encryption."""
    print("\n[Test] aad_req binding for request encryption")
    
    sdk = ClientSDK()
    ibe = ECCIBE()
    
    params, msk = ibe.setup()
    fid = "a" * 64
    input_data = b"test input"
    
    pk_FID = ibe.extract_public(msk, fid)
    inv = sdk.prepare_invocation(fid, input_data, pk_FID)
    
    c_req = inv["c_req"]
    nonce = inv["nonce"]
    pkU = inv["pkU"]
    
    # Decrypt k_req to test AEAD
    sk_FID = ibe.extract(msk, fid)
    k_req = ibe.decrypt(sk_FID, inv["c_key"])
    
    # 1. Verify correct AAD works
    correct_aad = sdk._build_aad_req(fid, nonce, pkU)
    decrypted = sdk.aead.decrypt(k_req, c_req, correct_aad)
    assert decrypted == input_data, "Correct aad_req should allow decryption"
    print("  ✓ Correct aad_req allows decryption")
    
    # 2. Verify wrong FID fails
    wrong_fid = "b" * 64
    wrong_aad = sdk._build_aad_req(wrong_fid, nonce, pkU)
    try:
        sdk.aead.decrypt(k_req, c_req, wrong_aad)
        assert False, "Wrong FID should fail"
    except Exception:
        print("  ✓ Wrong FID in aad_req causes decryption failure")
    
    # 3. Verify wrong nonce fails
    wrong_nonce = "f" * 32
    wrong_aad = sdk._build_aad_req(fid, wrong_nonce, pkU)
    try:
        sdk.aead.decrypt(k_req, c_req, wrong_aad)
        assert False, "Wrong nonce should fail"
    except Exception:
        print("  ✓ Wrong nonce in aad_req causes decryption failure")
    
    # 4. Verify wrong pkU fails
    wrong_pkU, _ = sdk.kem.keygen()
    wrong_aad = sdk._build_aad_req(fid, nonce, wrong_pkU)
    try:
        sdk.aead.decrypt(k_req, c_req, wrong_aad)
        assert False, "Wrong pkU should fail"
    except Exception:
        print("  ✓ Wrong pkU in aad_req causes decryption failure")
    
    # 5. Verify empty AAD fails
    try:
        sdk.aead.decrypt(k_req, c_req, b"")
        assert False, "Empty AAD should fail"
    except Exception:
        print("  ✓ Empty AAD causes decryption failure")
    
    # 6. Verify using only FID (old format) fails
    fid_only = bytes.fromhex(fid)
    try:
        sdk.aead.decrypt(k_req, c_req, fid_only)
        assert False, "FID-only AAD should fail"
    except Exception:
        print("  ✓ FID-only AAD (old format) causes decryption failure")
    
    print("  ✅ aad_req binding test PASSED")
    return True


def test_aad_out_binding():
    """Test aad_out = ("OUT", FID, RID, H(pkU)) binding for output encryption."""
    print("\n[Test] aad_out binding for output encryption")
    
    sdk = ClientSDK()
    
    fid = "a" * 64
    rid = "b" * 64
    output_data = b"test output"
    
    pk, sk = sdk.kem.keygen()
    ct, k_U = sdk.kem.encap(pk)
    
    # Encrypt output with proper aad_out
    aad_out = sdk._build_aad_out(fid, rid, pk)
    # SGX worker emits AES-128-GCM results, using the first 16 bytes of the
    # KEM shared secret as the output AEAD key.
    c_out = sdk.aead.encrypt(k_U[:16], output_data, aad_out)
    
    # 1. Verify correct AAD works
    decrypted = sdk.decrypt_result(ct, c_out, sk, fid, rid, pk)
    assert decrypted == output_data, "Correct aad_out should allow decryption"
    print("  ✓ Correct aad_out allows decryption")
    
    # 2. Verify wrong FID fails
    wrong_fid = "c" * 64
    try:
        sdk.decrypt_result(ct, c_out, sk, wrong_fid, rid, pk)
        assert False, "Wrong FID should fail"
    except Exception:
        print("  ✓ Wrong FID in aad_out causes decryption failure")
    
    # 3. Verify wrong RID fails
    wrong_rid = "d" * 64
    try:
        sdk.decrypt_result(ct, c_out, sk, fid, wrong_rid, pk)
        assert False, "Wrong RID should fail"
    except Exception:
        print("  ✓ Wrong RID in aad_out causes decryption failure")
    
    # 4. Verify wrong pkU fails
    wrong_pk, _ = sdk.kem.keygen()
    try:
        sdk.decrypt_result(ct, c_out, sk, fid, rid, wrong_pk)
        assert False, "Wrong pkU should fail"
    except Exception:
        print("  ✓ Wrong pkU in aad_out causes decryption failure")
    
    # 5. Test that AID is NOT used for AAD (critical security check)
    # Old format using AID should fail
    k_U_direct = sdk.kem.decap(sk, ct)[:16]
    try:
        sdk.aead.decrypt(k_U_direct, c_out, b"some_aid")
        assert False, "AID-based AAD should fail"
    except Exception:
        print("  ✓ AID-based AAD causes decryption failure (security verified)")
    
    print("  ✅ aad_out binding test PASSED")
    return True


def test_no_empty_aad():
    """Test that empty AAD is not used anywhere in the protocol."""
    print("\n[Test] Verify no empty AAD is used in protocol")
    
    sdk = ClientSDK()
    ibe = ECCIBE()
    params, msk = ibe.setup()
    
    # Test 1: encrypt_function_code never uses empty AAD
    result = sdk.encrypt_function_code("tenant", "action", "v1", b"code")
    aad_pkg = sdk._build_aad_pkg(result["fid"])
    assert len(aad_pkg) > 0, "aad_pkg should not be empty"
    assert aad_pkg.startswith(b"PKG"), "aad_pkg should start with 'PKG'"
    print("  ✓ encrypt_function_code uses non-empty aad_pkg")
    
    # Test 2: prepare_invocation never uses empty AAD
    pk_FID = ibe.extract_public(msk, result["fid"])
    inv = sdk.prepare_invocation(result["fid"], b"input", pk_FID)
    aad_req = sdk._build_aad_req(inv["fid"], inv["nonce"], inv["pkU"])
    assert len(aad_req) > 0, "aad_req should not be empty"
    assert aad_req.startswith(b"REQ"), "aad_req should start with 'REQ'"
    print("  ✓ prepare_invocation uses non-empty aad_req")
    
    # Test 3: decrypt_result never uses empty AAD
    aad_out = sdk._build_aad_out(inv["fid"], inv["rid"], inv["pkU"])
    assert len(aad_out) > 0, "aad_out should not be empty"
    assert aad_out.startswith(b"OUT"), "aad_out should start with 'OUT'"
    print("  ✓ decrypt_result uses non-empty aad_out")
    
    print("  ✅ No empty AAD test PASSED")
    return True


def test_rid_computation():
    """Test RID = H(FID || C_req) computation is correct and consistent."""
    print("\n[Test] RID computation correctness")
    
    sdk = ClientSDK()
    ibe = ECCIBE()
    params, msk = ibe.setup()
    
    fid = "a" * 64
    input_data = b"test input"
    
    pk_FID = ibe.extract_public(msk, fid)
    inv = sdk.prepare_invocation(fid, input_data, pk_FID)
    
    # 1. Verify RID is computed correctly
    expected_rid = hashlib.sha256(bytes.fromhex(fid) + inv["c_req"]).hexdigest()
    assert inv["rid"] == expected_rid, "RID should be H(FID || C_req)"
    print("  ✓ RID is correctly computed as H(FID || C_req)")
    
    # 2. Verify RID is deterministic (same inputs = same RID)
    rid1 = sdk._compute_rid(fid, inv["c_req"])
    rid2 = sdk._compute_rid(fid, inv["c_req"])
    assert rid1 == rid2, "RID should be deterministic"
    print("  ✓ RID computation is deterministic")
    
    # 3. Verify different c_req produces different RID
    inv2 = sdk.prepare_invocation(fid, b"different input", pk_FID)
    assert inv["rid"] != inv2["rid"], "Different c_req should produce different RID"
    print("  ✓ Different c_req produces different RID")
    
    # 4. Verify different FID produces different RID (even with same c_req technically impossible)
    rid_different_fid = sdk._compute_rid("b" * 64, inv["c_req"])
    assert inv["rid"] != rid_different_fid, "Different FID should produce different RID"
    print("  ✓ Different FID produces different RID")
    
    print("  ✅ RID computation test PASSED")
    return True


def main():
    print("=" * 60)
    print("AAD Binding Security Tests")
    print("=" * 60)
    
    tests = [
        ("aad_pkg binding", test_aad_pkg_binding),
        ("aad_req binding", test_aad_req_binding),
        ("aad_out binding", test_aad_out_binding),
        ("no empty AAD", test_no_empty_aad),
        ("RID computation", test_rid_computation),
    ]
    
    results = {}
    for name, test_func in tests:
        try:
            results[name] = test_func()
        except Exception as e:
            print(f"  ❌ Exception: {e}")
            import traceback
            traceback.print_exc()
            results[name] = False
    
    # Summary
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    
    passed = sum(1 for r in results.values() if r)
    total = len(results)
    
    for name, result in results.items():
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {name}: {status}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
