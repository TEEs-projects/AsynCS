#!/usr/bin/env python3
"""
Crypto API Error Handling Tests

Tests that the crypto library properly handles error cases:
- Invalid key sizes
- Invalid ciphertext
- Tampering detection
- Wrong key usage
- Invalid parameters
"""

import os
import sys

# Add parent directory to path for SDK imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from crypto_lib.aead import AESGCMImpl, ChaCha20Poly1305Impl
from crypto_lib.kem import P256HKDFKEM, X25519HKDFKEM
from crypto_lib.hash import SHA256Impl, SHA384Impl


def test_0_aead_invalid_key_size():
    """Test 0: AEAD rejects invalid key sizes"""
    print("\n[Test 0] AEAD rejects invalid key sizes")
    
    aead = AESGCMImpl()
    
    # Test with wrong key sizes
    test_cases = [
        (b"short", "too short key"),
        (b"a" * 15, "15 bytes"),
        (b"a" * 17, "17 bytes"),
        (b"a" * 64, "64 bytes"),
    ]
    
    errors_caught = 0
    for key, desc in test_cases:
        try:
            aead.encrypt(key, b"test", b"")
            print(f"  ❌ Should have rejected {desc}")
        except Exception as e:
            errors_caught += 1
            print(f"  ✓ Rejected {desc}")
    
    if errors_caught == len(test_cases):
        print(f"  ✅ Test 0 PASSED")
        return True
    else:
        print(f"  ❌ Test 0 FAILED")
        return False


def test_1_aead_tampered_ciphertext():
    """Test 1: AEAD detects tampered ciphertext"""
    print("\n[Test 1] AEAD detects tampered ciphertext")
    
    aead = AESGCMImpl()
    key = bytes([0xBB] * 16)
    plaintext = b"Secret data"
    
    ct = bytearray(aead.encrypt(key, plaintext, b""))
    
    # Tamper with different parts
    tamper_positions = [0, 12, 20, len(ct)-1]
    
    errors_caught = 0
    for pos in tamper_positions:
        ct_copy = bytearray(ct)
        ct_copy[pos] ^= 0xFF
        try:
            aead.decrypt(key, bytes(ct_copy), b"")
            print(f"  ❌ Should have detected tampering at position {pos}")
        except Exception:
            errors_caught += 1
            print(f"  ✓ Detected tampering at position {pos}")
    
    if errors_caught == len(tamper_positions):
        print(f"  ✅ Test 1 PASSED")
        return True
    else:
        print(f"  ❌ Test 1 FAILED")
        return False


def test_2_aead_wrong_key_decryption():
    """Test 2: AEAD rejects decryption with wrong key"""
    print("\n[Test 2] AEAD rejects decryption with wrong key")
    
    aead = AESGCMImpl()
    key1 = bytes([0xAA] * 16)
    key2 = bytes([0xBB] * 16)
    plaintext = b"Secret data"
    
    ct = aead.encrypt(key1, plaintext, b"")
    
    try:
        aead.decrypt(key2, ct, b"")
        print(f"  ❌ Should have rejected wrong key")
        return False
    except Exception:
        print(f"  ✓ Rejected wrong key")
        print(f"  ✅ Test 2 PASSED")
        return True


def test_3_aead_truncated_ciphertext():
    """Test 3: AEAD rejects truncated ciphertext"""
    print("\n[Test 3] AEAD rejects truncated ciphertext")
    
    aead = AESGCMImpl()
    key = bytes([0xBB] * 16)
    plaintext = b"Secret data"
    
    ct = aead.encrypt(key, plaintext, b"")
    
    # Try various truncated lengths
    truncate_lengths = [0, 10, 20, 27, len(ct)-1]
    
    errors_caught = 0
    for length in truncate_lengths:
        try:
            aead.decrypt(key, ct[:length], b"")
            print(f"  ❌ Should have rejected ciphertext truncated to {length} bytes")
        except Exception:
            errors_caught += 1
            print(f"  ✓ Rejected ciphertext truncated to {length} bytes")
    
    if errors_caught == len(truncate_lengths):
        print(f"  ✅ Test 3 PASSED")
        return True
    else:
        print(f"  ❌ Test 3 FAILED")
        return False


def test_4_aead_wrong_aad():
    """Test 4: AEAD rejects wrong AAD"""
    print("\n[Test 4] AEAD rejects wrong AAD")
    
    aead = AESGCMImpl()
    key = bytes([0xBB] * 16)
    plaintext = b"Secret data"
    
    ct = aead.encrypt(key, plaintext, b"correct_aad")
    
    wrong_aads = [b"", b"wrong_aad", b"different", b"x" * 100]
    
    errors_caught = 0
    for wrong_aad in wrong_aads:
        try:
            aead.decrypt(key, ct, wrong_aad)
            print(f"  ❌ Should have rejected AAD: {wrong_aad[:20]}")
        except Exception:
            errors_caught += 1
            print(f"  ✓ Rejected wrong AAD")
    
    if errors_caught == len(wrong_aads):
        print(f"  ✅ Test 4 PASSED")
        return True
    else:
        print(f"  ❌ Test 4 FAILED")
        return False


def test_5_chacha_error_handling():
    """Test 5: ChaCha20-Poly1305 error handling"""
    print("\n[Test 5] ChaCha20-Poly1305 error handling")
    
    chacha = ChaCha20Poly1305Impl()
    
    # Wrong key size
    try:
        chacha.encrypt(b"short_key", b"test", b"")
        print(f"  ❌ Should have rejected short key")
        return False
    except Exception:
        print(f"  ✓ Rejected invalid key size")
    
    # Tampered ciphertext
    key = bytes([0xCC] * 32)
    ct = bytearray(chacha.encrypt(key, b"test", b""))
    ct[15] ^= 0xFF
    
    try:
        chacha.decrypt(key, bytes(ct), b"")
        print(f"  ❌ Should have detected tampering")
        return False
    except Exception:
        print(f"  ✓ Detected tampering")
    
    print(f"  ✅ Test 5 PASSED")
    return True


def test_6_kem_invalid_inputs():
    """Test 6: KEM handles invalid inputs"""
    print("\n[Test 6] KEM handles invalid inputs")
    
    # P-256 KEM
    kem = P256HKDFKEM()
    pk, sk = kem.keygen()
    ct, key = kem.encap(pk)
    
    # Try to decap with wrong ciphertext
    errors_caught = 0
    
    # Truncated ciphertext
    try:
        kem.decap(sk, ct[:32])
        print(f"  ❌ Should have rejected truncated ciphertext")
    except Exception:
        errors_caught += 1
        print(f"  ✓ Rejected truncated ciphertext")
    
    # Corrupted ciphertext
    ct_bad = bytearray(ct)
    ct_bad[10] ^= 0xFF
    try:
        bad_key = kem.decap(sk, bytes(ct_bad))
        # Even if it doesn't throw, keys should differ
        if bad_key != key:
            errors_caught += 1
            print(f"  ✓ Corrupted ciphertext produces different key")
        else:
            print(f"  ❌ Corrupted ciphertext should produce different key")
    except Exception:
        errors_caught += 1
        print(f"  ✓ Rejected corrupted ciphertext")
    
    if errors_caught >= 2:
        print(f"  ✅ Test 6 PASSED")
        return True
    else:
        print(f"  ❌ Test 6 FAILED")
        return False


def test_7_x25519_kem_error_handling():
    """Test 7: X25519 KEM error handling"""
    print("\n[Test 7] X25519 KEM error handling")
    
    kem = X25519HKDFKEM()
    pk, sk = kem.keygen()
    ct, key = kem.encap(pk)
    
    # Verify decap works normally
    dec_key = kem.decap(sk, ct)
    if dec_key != key:
        print(f"  ❌ Normal decap failed")
        return False
    
    print(f"  ✓ Normal decap works")
    
    # Wrong sk should produce different key
    pk2, sk2 = kem.keygen()
    wrong_key = kem.decap(sk2, ct)
    
    if wrong_key != key:
        print(f"  ✓ Wrong SK produces different key")
        print(f"  ✅ Test 7 PASSED")
        return True
    else:
        print(f"  ❌ Wrong SK should produce different key")
        return False


def test_8_hash_empty_input():
    """Test 8: Hash handles empty input"""
    print("\n[Test 8] Hash handles empty input")
    
    sha256 = SHA256Impl()
    sha384 = SHA384Impl()
    
    # Empty input should produce valid hash
    h256 = sha256.digest(b"")
    h384 = sha384.digest(b"")
    
    # SHA-256 of empty is known
    expected_sha256_empty = bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    
    if h256 == expected_sha256_empty:
        print(f"  ✓ SHA-256 empty input correct")
    else:
        print(f"  ❌ SHA-256 empty input incorrect")
        return False
    
    if len(h384) == 48:
        print(f"  ✓ SHA-384 empty input produces 48 bytes")
    else:
        print(f"  ❌ SHA-384 empty input wrong length")
        return False
    
    print(f"  ✅ Test 8 PASSED")
    return True


def test_9_hash_large_input():
    """Test 9: Hash handles large input"""
    print("\n[Test 9] Hash handles large input")
    
    sha256 = SHA256Impl()
    
    # Large input (1MB)
    large_data = b"x" * (1024 * 1024)
    
    h = sha256.digest(large_data)
    
    if len(h) == 32:
        print(f"  ✓ SHA-256 handled 1MB input")
        print(f"  ✅ Test 9 PASSED")
        return True
    else:
        print(f"  ❌ SHA-256 failed on large input")
        return False


def test_10_aead_very_short_ciphertext():
    """Test 10: AEAD rejects very short ciphertext"""
    print("\n[Test 10] AEAD rejects very short ciphertext")
    
    aead = AESGCMImpl()
    key = bytes([0xBB] * 16)
    
    # Try decrypting very short data
    short_data = [b"", b"a", b"ab", b"abc", b"x" * 10, b"x" * 27]
    
    errors_caught = 0
    for data in short_data:
        try:
            aead.decrypt(key, data, b"")
            print(f"  ❌ Should have rejected {len(data)} byte ciphertext")
        except Exception:
            errors_caught += 1
            print(f"  ✓ Rejected {len(data)} byte ciphertext")
    
    if errors_caught == len(short_data):
        print(f"  ✅ Test 10 PASSED")
        return True
    else:
        print(f"  ❌ Test 10 FAILED")
        return False


def test_11_consistency_after_errors():
    """Test 11: API remains usable after errors"""
    print("\n[Test 11] API remains usable after errors")
    
    aead = AESGCMImpl()
    key = bytes([0xBB] * 16)
    
    # Cause some errors
    try:
        aead.encrypt(b"bad_key", b"test", b"")
    except:
        pass
    
    try:
        aead.decrypt(key, b"bad_ct", b"")
    except:
        pass
    
    # API should still work after errors
    plaintext = b"Test after errors"
    ct = aead.encrypt(key, plaintext, b"")
    dec = aead.decrypt(key, ct, b"")
    
    if dec == plaintext:
        print(f"  ✓ API works after errors")
        print(f"  ✅ Test 11 PASSED")
        return True
    else:
        print(f"  ❌ API broken after errors")
        return False


def test_12_ibe_invalid_parameters():
    """Test 12: IBE handles invalid parameters"""
    print("\n[Test 12] IBE handles invalid parameters")
    
    from crypto_lib.ibe import ECCIBE
    
    ibe = ECCIBE()
    params, msk = ibe.setup()
    
    errors_caught = 0
    expected_errors = 4
    
    # Test 1: Invalid public key for encryption
    try:
        ibe.encrypt(b"not a valid public key", "test_id", b"message")
        print(f"  ❌ Should have rejected invalid public key")
    except Exception:
        errors_caught += 1
        print(f"  ✓ Rejected invalid public key")
    
    # Test 2: Invalid ciphertext for decryption
    sk = ibe.extract(msk, "test_id")
    try:
        ibe.decrypt(sk, b"invalid_ciphertext_too_short")
        print(f"  ❌ Should have rejected invalid ciphertext")
    except Exception:
        errors_caught += 1
        print(f"  ✓ Rejected invalid ciphertext")
    
    # Test 3: Invalid private key for decryption
    pk = ibe.extract_public(msk, "test_id")
    ct = ibe.encrypt(pk, "test_id", b"secret message")
    try:
        ibe.decrypt(b"not_a_valid_private_key", ct)
        print(f"  ❌ Should have rejected invalid private key")
    except Exception:
        errors_caught += 1
        print(f"  ✓ Rejected invalid private key")
    
    # Test 4: Wrong private key (different identity)
    sk_other = ibe.extract(msk, "other_id")
    try:
        result = ibe.decrypt(sk_other, ct)
        # The decryption may succeed but return garbage, or fail
        # We verify the result is not the original message
        if result == b"secret message":
            print(f"  ❌ Should not decrypt with wrong identity key")
        else:
            errors_caught += 1
            print(f"  ✓ Wrong key produced wrong result (expected)")
    except Exception:
        errors_caught += 1
        print(f"  ✓ Wrong key rejected or failed decryption")
    
    if errors_caught >= expected_errors:
        print(f"  ✅ Test 12 PASSED")
        return True
    else:
        print(f"  ❌ Test 12 FAILED ({errors_caught}/{expected_errors})")
        return False


def test_13_chacha_tamper_detection():
    """Test 13: ChaCha20-Poly1305 tamper detection"""
    print("\n[Test 13] ChaCha20-Poly1305 tamper detection")
    
    chacha = ChaCha20Poly1305Impl()
    key = bytes([0xCC] * 32)
    plaintext = b"Sensitive data to protect"
    aad = b"authenticated but not encrypted"
    
    ct = bytearray(chacha.encrypt(key, plaintext, aad))
    
    errors_caught = 0
    expected_errors = 4
    
    # Tamper with nonce (first 12 bytes)
    ct_copy = bytearray(ct)
    ct_copy[5] ^= 0xFF
    try:
        chacha.decrypt(key, bytes(ct_copy), aad)
        print(f"  ❌ Should have detected nonce tampering")
    except Exception:
        errors_caught += 1
        print(f"  ✓ Detected nonce tampering")
    
    # Tamper with tag (after nonce, 16 bytes)
    ct_copy = bytearray(ct)
    ct_copy[15] ^= 0xFF
    try:
        chacha.decrypt(key, bytes(ct_copy), aad)
        print(f"  ❌ Should have detected tag tampering")
    except Exception:
        errors_caught += 1
        print(f"  ✓ Detected tag tampering")
    
    # Tamper with ciphertext (after nonce+tag)
    ct_copy = bytearray(ct)
    ct_copy[30] ^= 0xFF
    try:
        chacha.decrypt(key, bytes(ct_copy), aad)
        print(f"  ❌ Should have detected ciphertext tampering")
    except Exception:
        errors_caught += 1
        print(f"  ✓ Detected ciphertext tampering")
    
    # Wrong AAD
    try:
        chacha.decrypt(key, ct, b"wrong aad")
        print(f"  ❌ Should have detected wrong AAD")
    except Exception:
        errors_caught += 1
        print(f"  ✓ Detected wrong AAD")
    
    if errors_caught >= expected_errors:
        print(f"  ✅ Test 13 PASSED")
        return True
    else:
        print(f"  ❌ Test 13 FAILED ({errors_caught}/{expected_errors})")
        return False


def test_14_kem_roundtrip_integrity():
    """Test 14: KEM key encapsulation/decapsulation integrity"""
    print("\n[Test 14] KEM key encapsulation/decapsulation integrity")
    
    tests_passed = 0
    expected_tests = 4
    
    # Test P256 KEM
    p256_kem = P256HKDFKEM()
    pk_p256, sk_p256 = p256_kem.keygen()
    ct_p256, key1_p256 = p256_kem.encap(pk_p256)
    key2_p256 = p256_kem.decap(sk_p256, ct_p256)
    
    if key1_p256 == key2_p256:
        tests_passed += 1
        print(f"  ✓ P256 KEM roundtrip succeeded")
    else:
        print(f"  ❌ P256 KEM roundtrip failed")
    
    # Test X25519 KEM
    x25519_kem = X25519HKDFKEM()
    pk_x25519, sk_x25519 = x25519_kem.keygen()
    ct_x25519, key1_x25519 = x25519_kem.encap(pk_x25519)
    key2_x25519 = x25519_kem.decap(sk_x25519, ct_x25519)
    
    if key1_x25519 == key2_x25519:
        tests_passed += 1
        print(f"  ✓ X25519 KEM roundtrip succeeded")
    else:
        print(f"  ❌ X25519 KEM roundtrip failed")
    
    # Test tampered ciphertext produces different key (X25519)
    ct_tampered = bytearray(ct_x25519)
    ct_tampered[10] ^= 0xFF
    try:
        key3 = x25519_kem.decap(sk_x25519, bytes(ct_tampered))
        if key3 != key1_x25519:
            tests_passed += 1
            print(f"  ✓ Tampered ciphertext produced different key")
        else:
            print(f"  ❌ Tampered ciphertext should produce different key")
    except Exception:
        tests_passed += 1
        print(f"  ✓ Tampered ciphertext rejected")
    
    # Test multiple P256 encaps produce different keys
    ct_a, key_a = p256_kem.encap(pk_p256)
    ct_b, key_b = p256_kem.encap(pk_p256)
    if ct_a != ct_b and key_a != key_b:
        tests_passed += 1
        print(f"  ✓ Multiple P256 encaps produce different results")
    else:
        print(f"  ❌ Multiple encaps should produce different results")
    
    if tests_passed >= expected_tests:
        print(f"  ✅ Test 14 PASSED")
        return True
    else:
        print(f"  ❌ Test 14 FAILED ({tests_passed}/{expected_tests})")
        return False


def main():
    print("=" * 60)
    print("Crypto API Error Handling Tests")
    print("=" * 60)
    
    tests = [
        (0, test_0_aead_invalid_key_size),
        (1, test_1_aead_tampered_ciphertext),
        (2, test_2_aead_wrong_key_decryption),
        (3, test_3_aead_truncated_ciphertext),
        (4, test_4_aead_wrong_aad),
        (5, test_5_chacha_error_handling),
        (6, test_6_kem_invalid_inputs),
        (7, test_7_x25519_kem_error_handling),
        (8, test_8_hash_empty_input),
        (9, test_9_hash_large_input),
        (10, test_10_aead_very_short_ciphertext),
        (11, test_11_consistency_after_errors),
        (12, test_12_ibe_invalid_parameters),
        (13, test_13_chacha_tamper_detection),
        (14, test_14_kem_roundtrip_integrity),
    ]
    
    results = {}
    for idx, test_func in tests:
        try:
            results[idx] = test_func()
        except Exception as e:
            print(f"  ❌ Exception in Test {idx}: {e}")
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
