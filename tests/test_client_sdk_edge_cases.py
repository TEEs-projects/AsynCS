#!/usr/bin/env python3
"""
Client SDK Edge Case Tests

Tests that the Client SDK properly handles edge cases:
- Empty/null inputs
- Invalid FID formats
- Malformed keys
- Large inputs
- Special characters
- Unicode handling
- Concurrent operations
- Memory constraints
"""

import os
import sys
import threading
import time

# Add parent directory to path for SDK imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from client_sdk.sdk import ClientSDK
from crypto_lib.ibe import ECCIBE


def test_0_empty_tenant_id():
    """Test 0: SDK handles empty tenant_id"""
    print("\n[Test 0] SDK handles empty tenant_id")
    
    sdk = ClientSDK()
    code_wasm = b"(module)"
    
    # Empty tenant_id should still work (produces valid hash)
    try:
        fid = sdk.compute_fid("", "action", "v1", code_wasm)
        if len(fid) == 64:  # SHA-256 hex output
            print(f"  ✓ Empty tenant_id produces valid FID")
            print(f"  ✅ Test 0 PASSED")
            return True
    except Exception as e:
        print(f"  ❌ Unexpected error: {e}")
    
    print(f"  ❌ Test 0 FAILED")
    return False


def test_1_empty_action_name():
    """Test 1: SDK handles empty action_name"""
    print("\n[Test 1] SDK handles empty action_name")
    
    sdk = ClientSDK()
    code_wasm = b"(module)"
    
    try:
        fid = sdk.compute_fid("tenant", "", "v1", code_wasm)
        if len(fid) == 64:
            print(f"  ✓ Empty action_name produces valid FID")
            print(f"  ✅ Test 1 PASSED")
            return True
    except Exception as e:
        print(f"  ❌ Unexpected error: {e}")
    
    print(f"  ❌ Test 1 FAILED")
    return False


def test_2_empty_version():
    """Test 2: SDK handles empty version"""
    print("\n[Test 2] SDK handles empty version")
    
    sdk = ClientSDK()
    code_wasm = b"(module)"
    
    try:
        fid = sdk.compute_fid("tenant", "action", "", code_wasm)
        if len(fid) == 64:
            print(f"  ✓ Empty version produces valid FID")
            print(f"  ✅ Test 2 PASSED")
            return True
    except Exception as e:
        print(f"  ❌ Unexpected error: {e}")
    
    print(f"  ❌ Test 2 FAILED")
    return False


def test_3_empty_code():
    """Test 3: SDK handles empty code_wasm"""
    print("\n[Test 3] SDK handles empty code_wasm")
    
    sdk = ClientSDK()
    
    try:
        result = sdk.encrypt_function_code("tenant", "action", "v1", b"")
        if result["fid"] and result["c_func"] and result["l"]:
            print(f"  ✓ Empty code produces valid encryption result")
            print(f"  ✅ Test 3 PASSED")
            return True
    except Exception as e:
        print(f"  ❌ Unexpected error: {e}")
    
    print(f"  ❌ Test 3 FAILED")
    return False


def test_4_unicode_tenant_id():
    """Test 4: SDK handles unicode in tenant_id"""
    print("\n[Test 4] SDK handles unicode in tenant_id")
    
    sdk = ClientSDK()
    code_wasm = b"(module)"
    
    unicode_tenants = [
        "用户",
        "ユーザー",
        "المستخدم",
        "🚀tenant",
        "tëńânt",
    ]
    
    passed = 0
    for tenant in unicode_tenants:
        try:
            fid = sdk.compute_fid(tenant, "action", "v1", code_wasm)
            if len(fid) == 64:
                passed += 1
                print(f"  ✓ '{tenant}' produces valid FID")
        except Exception as e:
            print(f"  ❌ '{tenant}' failed: {e}")
    
    if passed == len(unicode_tenants):
        print(f"  ✅ Test 4 PASSED")
        return True
    else:
        print(f"  ❌ Test 4 FAILED ({passed}/{len(unicode_tenants)})")
        return False


def test_5_special_characters():
    """Test 5: SDK handles special characters"""
    print("\n[Test 5] SDK handles special characters")
    
    sdk = ClientSDK()
    code_wasm = b"(module)"
    
    special_inputs = [
        ("tenant/with/slashes", "action", "v1"),
        ("tenant", "action.with.dots", "v1"),
        ("tenant", "action", "v1-beta+build.123"),
        ("tenant@domain", "action:subaction", "v1"),
        ("tenant\ttab", "action\nnewline", "v1"),
    ]
    
    passed = 0
    for tenant, action, version in special_inputs:
        try:
            fid = sdk.compute_fid(tenant, action, version, code_wasm)
            if len(fid) == 64:
                passed += 1
                print(f"  ✓ Special chars handled: {tenant[:10]}...")
        except Exception as e:
            print(f"  ❌ Failed for: {tenant}: {e}")
    
    if passed == len(special_inputs):
        print(f"  ✅ Test 5 PASSED")
        return True
    else:
        print(f"  ❌ Test 5 FAILED ({passed}/{len(special_inputs)})")
        return False


def test_6_large_code_wasm():
    """Test 6: SDK handles large code_wasm"""
    print("\n[Test 6] SDK handles large code_wasm")
    
    sdk = ClientSDK()
    
    # Test with 1MB of code
    large_code = os.urandom(1024 * 1024)
    
    try:
        start = time.time()
        result = sdk.encrypt_function_code("tenant", "action", "v1", large_code)
        elapsed = time.time() - start
        
        if result["fid"] and len(result["c_func"]) > len(large_code):
            print(f"  ✓ 1MB code encrypted in {elapsed:.2f}s")
            print(f"  ✅ Test 6 PASSED")
            return True
    except Exception as e:
        print(f"  ❌ Large code failed: {e}")
    
    print(f"  ❌ Test 6 FAILED")
    return False


def test_7_fid_uniqueness():
    """Test 7: Different inputs produce different FIDs"""
    print("\n[Test 7] Different inputs produce different FIDs")
    
    sdk = ClientSDK()
    code_wasm = b"(module)"
    code_wasm2 = b"different"
    
    fids = []
    inputs = [
        ("tenant1", "action", "v1", code_wasm),
        ("tenant2", "action", "v1", code_wasm),
        ("tenant", "action1", "v1", code_wasm),
        ("tenant", "action2", "v1", code_wasm),
        ("tenant", "action", "v1", code_wasm),  # duplicate entry
        ("tenant", "action", "v2", code_wasm),
        ("tenant", "action", "v1", code_wasm2),
    ]
    
    for tenant, action, version, code in inputs:
        fid = sdk.compute_fid(tenant, action, version, code)
        fids.append(fid)
    
    # Check that duplicate inputs produce same FID
    if fids[2] != fids[4]:  # ("tenant", "action1") vs ("tenant", "action")
        # Entry 4 is duplicate of ("tenant", "action", "v1", code_wasm)
        # Find which entries should match
        pass
    
    # Verify unique entries produce unique FIDs
    unique_inputs = [
        ("tenant1", "action", "v1", code_wasm),
        ("tenant2", "action", "v1", code_wasm),
        ("tenant", "action1", "v1", code_wasm),
        ("tenant", "action2", "v1", code_wasm),
        ("tenant", "action", "v2", code_wasm),
        ("tenant", "action", "v1", code_wasm2),
    ]
    
    unique_fids = set()
    for tenant, action, version, code in unique_inputs:
        fid = sdk.compute_fid(tenant, action, version, code)
        unique_fids.add(fid)
    
    if len(unique_fids) == len(unique_inputs):
        print(f"  ✓ Different inputs produce different FIDs ({len(unique_fids)} unique)")
        print(f"  ✅ Test 7 PASSED")
        return True
    else:
        print(f"  ❌ Expected {len(unique_inputs)} unique FIDs, got {len(unique_fids)}")
        print(f"  ❌ Test 7 FAILED")
        return False


def test_8_encryption_roundtrip():
    """Test 8: Full encryption/decryption roundtrip"""
    print("\n[Test 8] Full encryption/decryption roundtrip")
    
    sdk = ClientSDK()
    ibe = ECCIBE()
    
    # Setup
    params, msk = ibe.setup()
    code_wasm = b"Hello, World WASM!"
    
    # Encrypt function
    result = sdk.encrypt_function_code("tenant", "action", "v1", code_wasm)
    
    # Get IBE public key for L and encrypt k_func
    pk_L = ibe.extract_public(msk, result["l"])
    c_k_func = sdk.encrypt_function_key(result["k_func"], pk_L, result["l"])
    
    # Simulate worker decryption
    sk_L = ibe.extract(msk, result["l"])
    k_func_dec = ibe.decrypt(sk_L, c_k_func)
    
    # Verify k_func matches
    if k_func_dec == result["k_func"]:
        # Now decrypt the code using proper aad_pkg binding
        aad_pkg = sdk._build_aad_pkg(result["fid"])
        code_dec = sdk.aead.decrypt(k_func_dec, result["c_func"], aad_pkg)
        
        if code_dec == code_wasm:
            print(f"  ✓ Full roundtrip successful")
            print(f"  ✅ Test 8 PASSED")
            return True
    
    print(f"  ❌ Test 8 FAILED")
    return False


def test_9_invocation_prep():
    """Test 9: Invocation preparation produces valid output"""
    print("\n[Test 9] Invocation preparation produces valid output")
    
    sdk = ClientSDK()
    ibe = ECCIBE()
    
    params, msk = ibe.setup()
    fid = "a" * 64  # Valid hex FID
    input_data = b"test input"
    
    pk_FID = ibe.extract_public(msk, fid)
    
    result = sdk.prepare_invocation(fid, input_data, pk_FID)
    
    checks = [
        ("fid", result.get("fid") == fid),
        ("c_req", len(result.get("c_req", b"")) > len(input_data)),
        ("c_key", len(result.get("c_key", b"")) > 0),
        ("pkU", len(result.get("pkU", b"")) > 0),
        ("skU", len(result.get("skU", b"")) > 0),
        ("nonce", len(result.get("nonce", "")) == 32),  # 16 bytes hex
    ]
    
    passed = 0
    for name, check in checks:
        if check:
            passed += 1
            print(f"  ✓ {name} is valid")
        else:
            print(f"  ❌ {name} is invalid")
    
    if passed == len(checks):
        print(f"  ✅ Test 9 PASSED")
        return True
    else:
        print(f"  ❌ Test 9 FAILED")
        return False


def test_10_decrypt_result_invalid_ct():
    """Test 10: decrypt_result handles invalid ciphertext"""
    print("\n[Test 10] decrypt_result handles invalid ciphertext")
    
    sdk = ClientSDK()
    
    # Generate valid KEM keys
    pk, sk = sdk.kem.keygen()
    ct, _ = sdk.kem.encap(pk)
    
    # Use valid FID and RID for testing
    fid = "a" * 64
    rid = "b" * 64
    
    errors_caught = 0
    expected = 3
    
    # Invalid c_out
    try:
        sdk.decrypt_result(ct, b"invalid", sk, fid, rid, pk)
    except Exception:
        errors_caught += 1
        print(f"  ✓ Rejected invalid c_out")
    
    # Invalid skU
    try:
        sdk.decrypt_result(ct, os.urandom(50), b"invalid_sk", fid, rid, pk)
    except Exception:
        errors_caught += 1
        print(f"  ✓ Rejected invalid skU")
    
    # Invalid ct
    try:
        sdk.decrypt_result(b"invalid_ct", os.urandom(50), sk, fid, rid, pk)
    except Exception:
        errors_caught += 1
        print(f"  ✓ Rejected invalid ct")
    
    if errors_caught >= expected:
        print(f"  ✅ Test 10 PASSED")
        return True
    else:
        print(f"  ❌ Test 10 FAILED ({errors_caught}/{expected})")
        return False


def test_11_deterministic_fid():
    """Test 11: FID computation is deterministic"""
    print("\n[Test 11] FID computation is deterministic")
    
    sdk = ClientSDK()
    code_wasm = b"(module)"
    
    fid1 = sdk.compute_fid("tenant", "action", "v1", code_wasm)
    fid2 = sdk.compute_fid("tenant", "action", "v1", code_wasm)
    fid3 = sdk.compute_fid("tenant", "action", "v1", code_wasm)
    
    if fid1 == fid2 == fid3:
        print(f"  ✓ FID is deterministic")
        print(f"  ✅ Test 11 PASSED")
        return True
    else:
        print(f"  ❌ FID not deterministic")
        print(f"  ❌ Test 11 FAILED")
        return False


def test_12_encryption_non_deterministic():
    """Test 12: Encryption is non-deterministic (different IVs)"""
    print("\n[Test 12] Encryption is non-deterministic")
    
    sdk = ClientSDK()
    code_wasm = b"(module)"
    
    result1 = sdk.encrypt_function_code("tenant", "action", "v1", code_wasm)
    result2 = sdk.encrypt_function_code("tenant", "action", "v1", code_wasm)
    
    # FID should be same
    if result1["fid"] != result2["fid"]:
        print(f"  ❌ FIDs should be identical")
        print(f"  ❌ Test 12 FAILED")
        return False
    
    # k_func should be different (random)
    if result1["k_func"] == result2["k_func"]:
        print(f"  ❌ k_func should be random each time")
        print(f"  ❌ Test 12 FAILED")
        return False
    
    # c_func should be different (different k_func and IV)
    if result1["c_func"] == result2["c_func"]:
        print(f"  ❌ c_func should be different")
        print(f"  ❌ Test 12 FAILED")
        return False
    
    print(f"  ✓ FID deterministic, encryption non-deterministic")
    print(f"  ✅ Test 12 PASSED")
    return True


def test_13_label_computation():
    """Test 13: Label (L) is correctly computed from ciphertext"""
    print("\n[Test 13] Label (L) is correctly computed from ciphertext")
    
    sdk = ClientSDK()
    import hashlib
    
    code_wasm = b"(module)"
    result = sdk.encrypt_function_code("tenant", "action", "v1", code_wasm)
    
    # Verify L = H(C_func)
    expected_l = hashlib.sha256(result["c_func"]).hexdigest()
    
    if result["l"] == expected_l:
        print(f"  ✓ L correctly computed from C_func")
        print(f"  ✅ Test 13 PASSED")
        return True
    else:
        print(f"  ❌ L computation incorrect")
        print(f"  ❌ Test 13 FAILED")
        return False


def test_14_func_measurement():
    """Test 14: func_measurement is correctly computed"""
    print("\n[Test 14] func_measurement is correctly computed")
    
    sdk = ClientSDK()
    import hashlib
    
    code_wasm = b"(module with content)"
    result = sdk.encrypt_function_code("tenant", "action", "v1", code_wasm)
    
    # Verify func_measurement = H(code_wasm)
    expected_measurement = hashlib.sha256(code_wasm).hexdigest()
    
    if result["func_measurement"] == expected_measurement:
        print(f"  ✓ func_measurement correctly computed")
        print(f"  ✅ Test 14 PASSED")
        return True
    else:
        print(f"  ❌ func_measurement computation incorrect")
        print(f"  ❌ Test 14 FAILED")
        return False


def test_15_concurrent_operations():
    """Test 15: SDK handles concurrent operations"""
    print("\n[Test 15] SDK handles concurrent operations")
    
    sdk = ClientSDK()
    results = []
    errors = []
    
    def worker(idx):
        try:
            code = f"module_{idx}".encode()
            result = sdk.encrypt_function_code(f"tenant_{idx}", f"action_{idx}", "v1", code)
            results.append(result)
        except Exception as e:
            errors.append(e)
    
    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    
    if len(results) == 10 and len(errors) == 0:
        print(f"  ✓ 10 concurrent operations succeeded")
        print(f"  ✅ Test 15 PASSED")
        return True
    else:
        print(f"  ❌ {len(errors)} errors in concurrent operations")
        print(f"  ❌ Test 15 FAILED")
        return False


def test_16_invocation_roundtrip():
    """Test 16: Full invocation roundtrip with proper AAD binding"""
    print("\n[Test 16] Full invocation roundtrip")
    
    sdk = ClientSDK()
    ibe = ECCIBE()
    
    # Setup IBE
    params, msk = ibe.setup()
    
    # Client prepares invocation
    fid = "a" * 64
    input_data = b"test input data"
    
    pk_FID = ibe.extract_public(msk, fid)
    inv = sdk.prepare_invocation(fid, input_data, pk_FID)
    
    # Worker side: decrypt c_key to get k_req
    sk_FID = ibe.extract(msk, fid)
    k_req = ibe.decrypt(sk_FID, inv["c_key"])
    
    # Worker decrypts input using proper aad_req binding
    aad_req = sdk._build_aad_req(fid, inv["nonce"], inv["pkU"])
    input_dec = sdk.aead.decrypt(k_req, inv["c_req"], aad_req)
    
    if input_dec == input_data:
        print(f"  ✓ Input correctly decrypted by worker")
        
        # Worker encrypts result using KEM with proper aad_out binding
        result_data = b"output from function"
        ct, k_U = sdk.kem.encap(inv["pkU"])
        
        # Use proper aad_out = ("OUT", FID, RID, H(pkU))
        aad_out = sdk._build_aad_out(inv["fid"], inv["rid"], inv["pkU"])
        # SGX worker emits AES-128-GCM results, using the first 16 bytes of
        # the KEM shared secret as the output AEAD key.
        c_out = sdk.aead.encrypt(k_U[:16], result_data, aad_out)
        
        # Client decrypts result using new API
        result_dec = sdk.decrypt_result(ct, c_out, inv["skU"], inv["fid"], inv["rid"], inv["pkU"])
        
        if result_dec == result_data:
            print(f"  ✓ Result correctly decrypted by client")
            print(f"  ✅ Test 16 PASSED")
            return True
    
    print(f"  ❌ Test 16 FAILED")
    return False


def test_17_long_strings():
    """Test 17: SDK handles very long strings"""
    print("\n[Test 17] SDK handles very long strings")
    
    sdk = ClientSDK()
    code_wasm = b"(module)"
    
    # Very long tenant/action/version
    long_tenant = "t" * 10000
    long_action = "a" * 10000
    long_version = "v" * 10000
    
    try:
        fid = sdk.compute_fid(long_tenant, long_action, long_version, code_wasm)
        if len(fid) == 64:
            print(f"  ✓ Long strings handled correctly")
            print(f"  ✅ Test 17 PASSED")
            return True
    except Exception as e:
        print(f"  ❌ Failed with long strings: {e}")
    
    print(f"  ❌ Test 17 FAILED")
    return False


def test_18_binary_code():
    """Test 18: SDK handles binary code with all byte values"""
    print("\n[Test 18] SDK handles binary code with all byte values")
    
    sdk = ClientSDK()
    
    # Code containing all possible byte values
    code_wasm = bytes(range(256)) * 10
    
    try:
        result = sdk.encrypt_function_code("tenant", "action", "v1", code_wasm)
        
        # Verify we can decrypt it back using proper aad_pkg binding
        aad_pkg = sdk._build_aad_pkg(result["fid"])
        code_dec = sdk.aead.decrypt(result["k_func"], result["c_func"], aad_pkg)
        
        if code_dec == code_wasm:
            print(f"  ✓ Binary code with all byte values handled")
            print(f"  ✅ Test 18 PASSED")
            return True
    except Exception as e:
        print(f"  ❌ Failed with binary code: {e}")
    
    print(f"  ❌ Test 18 FAILED")
    return False


def test_19_input_types():
    """Test 19: SDK validates input types"""
    print("\n[Test 19] SDK validates input types")
    
    sdk = ClientSDK()
    
    errors_caught = 0
    expected = 3
    
    # Wrong type for code_wasm (string instead of bytes)
    try:
        sdk.encrypt_function_code("tenant", "action", "v1", "string not bytes")
        print(f"  ❌ Should reject string for code_wasm")
    except (TypeError, AttributeError):
        errors_caught += 1
        print(f"  ✓ Rejected string for code_wasm")
    except Exception as e:
        # Some type error occurred
        errors_caught += 1
        print(f"  ✓ Rejected string for code_wasm (error: {type(e).__name__})")
    
    # Wrong type for input_data (string instead of bytes)
    ibe = ECCIBE()
    params, msk = ibe.setup()
    pk = ibe.extract_public(msk, "test")
    try:
        sdk.prepare_invocation("a" * 64, "string not bytes", pk)
        print(f"  ❌ Should reject string for input_data")
    except (TypeError, AttributeError):
        errors_caught += 1
        print(f"  ✓ Rejected string for input_data")
    except Exception as e:
        errors_caught += 1
        print(f"  ✓ Rejected string for input_data (error: {type(e).__name__})")
    
    # Test that bytes work correctly
    try:
        result = sdk.encrypt_function_code("tenant", "action", "v1", b"valid bytes")
        if result["fid"]:
            errors_caught += 1
            print(f"  ✓ Accepted valid bytes for code_wasm")
    except Exception as e:
        print(f"  ❌ Should accept valid bytes: {e}")
    
    if errors_caught >= expected:
        print(f"  ✅ Test 19 PASSED")
        return True
    else:
        print(f"  ❌ Test 19 FAILED ({errors_caught}/{expected})")
        return False


def test_20_aad_out_binding():
    """Test 20: Proper aad_out binding in result decryption (replaces AID handling)"""
    print("\n[Test 20] aad_out binding in result decryption")
    
    sdk = ClientSDK()
    
    # Test various FID/RID combinations to verify proper binding
    test_cases = [
        ("a" * 64, "b" * 64, "simple case"),
        ("0" * 64, "f" * 64, "zeros and fs"),
        ("deadbeef" * 8, "cafebabe" * 8, "hex patterns"),
        ("1234567890abcdef" * 4, "fedcba0987654321" * 4, "numeric patterns"),
        ("a1b2c3d4e5f6" * 6 + "0" * 8, "9876543210fedcba" * 4, "mixed patterns"),
    ]
    
    passed = 0
    for fid, rid, label in test_cases:
        try:
            pk, sk = sdk.kem.keygen()
            ct, k_U = sdk.kem.encap(pk)
            result_data = b"function output"
            
            # Encrypt with proper aad_out binding
            aad_out = sdk._build_aad_out(fid, rid, pk)
            # Match SGX worker output encryption: AES-128-GCM with k_U[:16].
            c_out = sdk.aead.encrypt(k_U[:16], result_data, aad_out)
            
            # Decrypt using new API
            dec = sdk.decrypt_result(ct, c_out, sk, fid, rid, pk)
            if dec == result_data:
                passed += 1
                print(f"  ✓ {label} handled correctly")
        except Exception as e:
            print(f"  ❌ {label} failed: {e}")
    
    if passed == len(test_cases):
        print(f"  ✅ Test 20 PASSED")
        return True
    else:
        print(f"  ❌ Test 20 FAILED ({passed}/{len(test_cases)})")
        return False


def test_21_rid_e2e_protocol():
    """Test 21: RID = H(FID || C_req) is correctly computed and used end-to-end"""
    print("\n[Test 21] RID = H(FID || C_req) End-to-End Protocol")
    
    import hashlib
    sdk = ClientSDK()
    ibe = ECCIBE()
    
    params, msk = ibe.setup()
    
    # Client side: prepare invocation
    fid = "deadbeefcafebabe" * 4  # 64 hex chars = 32 bytes FID
    input_data = b"test request input"
    pk_FID = ibe.extract_public(msk, fid)
    
    inv = sdk.prepare_invocation(fid, input_data, pk_FID)
    
    # Verify 1: RID is returned by prepare_invocation
    assert "rid" in inv, "RID should be in invocation result"
    assert len(inv["rid"]) == 64, f"RID should be 64 hex chars, got {len(inv['rid'])}"
    print(f"  ✓ Client computed RID: {inv['rid'][:16]}...")
    
    # Verify 2: Worker can independently compute the same RID from (FID, C_req)
    # This simulates the worker side recomputing RID
    fid_bytes = bytes.fromhex(fid)
    c_req = inv["c_req"]
    worker_rid_bytes = hashlib.sha256(fid_bytes + c_req).digest()
    worker_rid = worker_rid_bytes.hex()
    
    assert inv["rid"] == worker_rid, f"RID mismatch: client={inv['rid']}, worker={worker_rid}"
    print(f"  ✓ Worker independently computed same RID: {worker_rid[:16]}...")
    
    # Verify 3: RID is deterministic (same inputs = same RID)
    # Same invocation would produce same C_req if we don't randomize nonce/k_req
    # But C_req includes random nonce, so different invocations produce different RIDs
    # The key point is: given the SAME (FID, C_req), RID is always the same
    rid_check1 = sdk._compute_rid(fid, c_req)
    rid_check2 = sdk._compute_rid(fid, c_req)
    assert rid_check1 == rid_check2 == inv["rid"], "RID must be deterministic"
    print(f"  ✓ RID is deterministic for same (FID, C_req)")
    
    # Verify 4: Different C_req produces different RID (for same FID)
    inv2 = sdk.prepare_invocation(fid, b"different input", pk_FID)
    assert inv["rid"] != inv2["rid"], "Different C_req should produce different RID"
    print(f"  ✓ Different C_req produces different RID")
    
    # Verify 5: aad_out uses RID (not AID)
    # Build aad_out and verify RID is embedded
    aad_out = sdk._build_aad_out(fid, inv["rid"], inv["pkU"])
    rid_bytes = bytes.fromhex(inv["rid"])
    assert rid_bytes in aad_out, "RID should be embedded in aad_out"
    print(f"  ✓ aad_out correctly embeds RID")
    
    print(f"  ✅ Test 21 PASSED")
    return True


def main():
    print("=" * 60)
    print("Client SDK Edge Case Tests")
    print("=" * 60)
    
    tests = [
        (0, test_0_empty_tenant_id),
        (1, test_1_empty_action_name),
        (2, test_2_empty_version),
        (3, test_3_empty_code),
        (4, test_4_unicode_tenant_id),
        (5, test_5_special_characters),
        (6, test_6_large_code_wasm),
        (7, test_7_fid_uniqueness),
        (8, test_8_encryption_roundtrip),
        (9, test_9_invocation_prep),
        (10, test_10_decrypt_result_invalid_ct),
        (11, test_11_deterministic_fid),
        (12, test_12_encryption_non_deterministic),
        (13, test_13_label_computation),
        (14, test_14_func_measurement),
        (15, test_15_concurrent_operations),
        (16, test_16_invocation_roundtrip),
        (17, test_17_long_strings),
        (18, test_18_binary_code),
        (19, test_19_input_types),
        (20, test_20_aad_out_binding),
        (21, test_21_rid_e2e_protocol),
    ]
    
    results = {}
    for idx, test_func in tests:
        try:
            results[idx] = test_func()
        except Exception as e:
            print(f"  ❌ Exception in Test {idx}: {e}")
            import traceback
            traceback.print_exc()
            results[idx] = False
    
    # Summary
    print("\n" + "=" * 60)
    print("Summary")
    print("=" * 60)
    
    passed = sum(1 for r in results.values() if r)
    total = len(results)
    
    for idx in sorted(results.keys()):
        status = "✅ PASS" if results[idx] else "❌ FAIL"
        print(f"  Test {idx}: {status}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
