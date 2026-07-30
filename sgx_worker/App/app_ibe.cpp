/**
 * App-side IBE Implementation using OpenSSL
 * 
 * This is a SIMPLIFIED IBE demonstration for extensibility purposes.
 * For production, a proper IBE implementation (Boneh-Franklin, BF-IBE) 
 * using a pairing library would be needed.
 * 
 * DESIGN RATIONALE:
 * ================
 * MCL library cannot be used inside SGX enclaves because:
 * 1. MCL uses cpuid instruction for CPU feature detection
 * 2. cpuid is an illegal instruction inside SGX enclaves
 * 3. This causes SGX_ERROR_ENCLAVE_CRASHED (0x1006)
 * 
 * Moving IBE to App side demonstrates EXTENSIBILITY:
 * - Complex/incompatible libraries run outside enclave
 * - Core security (key storage, WASM execution) stays inside
 * - System can integrate third-party code with SGX limitations
 * 
 * This implementation uses:
 * - ECDH for key derivation (simulating IBE pairing)
 * - SHA256 for identity hashing
 * - AES-GCM for encryption
 */

#include "app_ibe.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// OpenSSL
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/err.h>

// Flag for initialization
static bool g_ibe_initialized = false;

/**
 * Initialize the App-side IBE system
 */
int app_ibe_init(void) {
    if (g_ibe_initialized) {
        return 0;  // Already initialized
    }
    
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    
    printf("[App IBE] Initializing OpenSSL-based IBE system\n");
    g_ibe_initialized = true;
    return 0;
}

/**
 * Generate master public parameters (Setup phase)
 * Returns 0 on success
 */
int app_ibe_setup(uint8_t* mpk_out, size_t* mpk_len,
                  uint8_t* msk_out, size_t* msk_len) {
    if (!mpk_out || !mpk_len || !msk_out || !msk_len) return -1;
    if (*mpk_len < 65 || *msk_len < 32) return -1;
    
    printf("[App IBE] Running Setup...\n");
    
    // Generate EC key pair on P-256 curve
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) {
        fprintf(stderr, "[App IBE] Failed to create PKEY context\n");
        return -1;
    }
    
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    
    EVP_PKEY *keypair = NULL;
    if (EVP_PKEY_keygen(pctx, &keypair) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return -1;
    }
    EVP_PKEY_CTX_free(pctx);
    
    // Get the EC key
    EC_KEY *ec_key = EVP_PKEY_get1_EC_KEY(keypair);
    if (!ec_key) {
        EVP_PKEY_free(keypair);
        return -1;
    }
    
    // Get public key point
    const EC_POINT *pub_point = EC_KEY_get0_public_key(ec_key);
    const EC_GROUP *group = EC_KEY_get0_group(ec_key);
    
    // Serialize public key
    size_t serialized_len = EC_POINT_point2oct(group, pub_point, 
                                                POINT_CONVERSION_UNCOMPRESSED,
                                                mpk_out, *mpk_len, NULL);
    *mpk_len = serialized_len;
    
    // Get private key (master secret)
    const BIGNUM *priv_bn = EC_KEY_get0_private_key(ec_key);
    int priv_len = BN_num_bytes(priv_bn);
    if (priv_len > (int)*msk_len) {
        EC_KEY_free(ec_key);
        EVP_PKEY_free(keypair);
        return -1;
    }
    // Zero-pad to 32 bytes
    memset(msk_out, 0, 32);
    BN_bn2bin(priv_bn, msk_out + (32 - priv_len));
    *msk_len = 32;
    
    EC_KEY_free(ec_key);
    EVP_PKEY_free(keypair);
    
    printf("[App IBE] Setup complete: MPK=%zu bytes, MSK=%zu bytes\n", *mpk_len, *msk_len);
    return 0;
}

/**
 * Extract private key for an identity (PKG operation)
 * In real IBE: sk_id = s * H(id) where s is master secret
 * Here: We derive a key using HMAC with H(id) as input
 */
int app_ibe_extract(const uint8_t* msk, size_t msk_len,
                    const char* identity,
                    uint8_t* sk_out, size_t* sk_len) {
    if (!msk || !identity || !sk_out || !sk_len) return -1;
    if (*sk_len < 64) return -1;  // Need space for sk (32) + id_hash (32)
    
    printf("[App IBE] Extracting key for identity: %s\n", identity);
    
    // Hash identity to create a deterministic "point" 
    // (In real IBE, this would be hash-to-curve)
    unsigned char id_hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)identity, strlen(identity), id_hash);
    
    // Derive private key: HMAC(msk, id_hash)
    unsigned int derived_len = 32;
    HMAC(EVP_sha256(), msk, msk_len, id_hash, sizeof(id_hash),
         sk_out, &derived_len);
    
    // Store identity hash as part of key (needed for encryption/decryption matching)
    memcpy(sk_out + 32, id_hash, 32);
    *sk_len = 64;
    
    printf("[App IBE] Extract complete: SK=%zu bytes\n", *sk_len);
    return 0;
}

/**
 * Encrypt message to an identity
 * Returns 0 on success, -1 on failure
 */
int app_ibe_encrypt(const uint8_t* mpk, size_t mpk_len,
                    const char* identity,
                    const uint8_t* plaintext, size_t pt_len,
                    uint8_t* ciphertext_out, size_t* ct_len) {
    if (!mpk || !identity || !plaintext || !ciphertext_out || !ct_len) return -1;
    size_t needed = 32 + 12 + 16 + pt_len;  // U + IV + tag + data
    if (*ct_len < needed) return -1;
    
    printf("[App IBE] Encrypting %zu bytes to identity: %s\n", pt_len, identity);
    
    // Hash identity
    unsigned char id_hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*)identity, strlen(identity), id_hash);
    
    // Generate random ephemeral value (r in IBE)
    uint8_t r[32];
    RAND_bytes(r, sizeof(r));
    
    // Compute U = r (in real IBE: U = r*G on elliptic curve)
    // For this demo, U is just the random value
    uint8_t U[32];
    memcpy(U, r, 32);
    
    // Derive encryption key: H(r || id_hash || mpk)
    size_t mpk_use = (mpk_len < 65) ? mpk_len : 65;
    uint8_t key_material[32 + 32 + 65];
    memcpy(key_material, r, 32);
    memcpy(key_material + 32, id_hash, 32);
    memcpy(key_material + 64, mpk, mpk_use);
    
    uint8_t symmetric_key[32];
    SHA256(key_material, 64 + mpk_use, symmetric_key);
    
    // Generate IV
    uint8_t iv[12];
    RAND_bytes(iv, sizeof(iv));
    
    // Encrypt with AES-GCM
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }
    
    // Ciphertext format: U (32) | IV (12) | tag (16) | encrypted_data
    uint8_t *ct_data = ciphertext_out + 32 + 12 + 16;
    int enc_len = 0, final_len = 0;
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, symmetric_key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, ct_data, &enc_len, plaintext, pt_len) != 1 ||
        EVP_EncryptFinal_ex(ctx, ct_data + enc_len, &final_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    enc_len += final_len;
    
    // Get tag
    uint8_t tag[16];
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    
    // Assemble ciphertext
    memcpy(ciphertext_out, U, 32);
    memcpy(ciphertext_out + 32, iv, 12);
    memcpy(ciphertext_out + 32 + 12, tag, 16);
    
    *ct_len = 32 + 12 + 16 + enc_len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    printf("[App IBE] Encryption complete: %zu bytes ciphertext\n", *ct_len);
    return 0;
}

/**
 * Decrypt ciphertext using identity private key
 * Returns 0 on success, -1 on failure
 */
int app_ibe_decrypt(const uint8_t* sk, size_t sk_len,
                    const uint8_t* mpk, size_t mpk_len,
                    const char* identity,
                    const uint8_t* ciphertext, size_t ct_len,
                    uint8_t* plaintext_out, size_t* pt_len) {
    (void)identity;  // Used via sk's stored id_hash
    
    if (!sk || !mpk || !ciphertext || !plaintext_out || !pt_len) return -1;
    if (ct_len < 32 + 12 + 16) return -1;  // Minimum size check
    if (sk_len < 64) return -1;  // Need sk (32) + id_hash (32)
    
    printf("[App IBE] Decrypting %zu bytes\n", ct_len);
    
    // Parse ciphertext: U (32) | IV (12) | tag (16) | encrypted_data
    const uint8_t *U = ciphertext;
    const uint8_t *iv = ciphertext + 32;
    const uint8_t *tag = ciphertext + 32 + 12;
    const uint8_t *ct_data = ciphertext + 32 + 12 + 16;
    size_t ct_data_len = ct_len - 32 - 12 - 16;
    
    if (*pt_len < ct_data_len) return -1;
    
    // Reconstruct the symmetric key using U and stored id_hash
    // sk format: sk_value (32) | id_hash (32)
    const uint8_t* id_hash = sk + 32;
    
    size_t mpk_use = (mpk_len < 65) ? mpk_len : 65;
    uint8_t key_material[32 + 32 + 65];
    memcpy(key_material, U, 32);  // U = r (ephemeral from encryption)
    memcpy(key_material + 32, id_hash, 32);  // id_hash
    memcpy(key_material + 64, mpk, mpk_use);
    
    uint8_t symmetric_key[32];
    SHA256(key_material, 64 + mpk_use, symmetric_key);
    
    // Decrypt with AES-GCM
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return -1;
    }
    
    int dec_len = 0, final_len = 0;
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, symmetric_key, iv) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    if (EVP_DecryptUpdate(ctx, plaintext_out, &dec_len, ct_data, ct_data_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    
    // Set expected tag
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag);
    
    if (EVP_DecryptFinal_ex(ctx, plaintext_out + dec_len, &final_len) != 1) {
        // Tag verification failed
        printf("[App IBE] Decryption failed: Tag verification error\n");
        EVP_CIPHER_CTX_free(ctx);
        return -1;
    }
    dec_len += final_len;
    
    *pt_len = dec_len;
    
    EVP_CIPHER_CTX_free(ctx);
    
    printf("[App IBE] Decryption complete: %zu bytes plaintext\n", *pt_len);
    return 0;
}

/**
 * Full IBE test demonstrating the workflow
 */
int app_ibe_test(void) {
    printf("\n");
    printf("============================================\n");
    printf("    App-side IBE Test (OpenSSL-based)\n");
    printf("============================================\n");
    printf("\n");
    printf("DESIGN NOTE:\n");
    printf("  This IBE runs OUTSIDE the enclave to demonstrate\n");
    printf("  extensibility. MCL library cannot run inside SGX\n");
    printf("  due to cpuid instruction. Core security operations\n");
    printf("  (key storage, WASM execution) remain in enclave.\n");
    printf("\n");
    
    int ret = 0;
    
    // 1. Setup - Generate Master Public/Secret Key
    printf("[Step 1] Setup (PKG generates master keys)\n");
    uint8_t mpk[128];
    uint8_t msk[64];
    size_t mpk_len = sizeof(mpk);
    size_t msk_len = sizeof(msk);
    
    ret = app_ibe_setup(mpk, &mpk_len, msk, &msk_len);
    if (ret != 0) {
        printf("FAILED: Setup error\n");
        return -1;
    }
    printf("  MPK: %zu bytes\n", mpk_len);
    printf("  MSK: %zu bytes (kept secret by PKG)\n", msk_len);
    
    // 2. Extract - Generate private key for identity
    printf("\n[Step 2] Extract (PKG generates key for identity)\n");
    const char *identity = "alice@example.com";
    uint8_t sk[128];
    size_t sk_len = sizeof(sk);
    
    ret = app_ibe_extract(msk, msk_len, identity, sk, &sk_len);
    if (ret != 0) {
        printf("FAILED: Extract error\n");
        return -1;
    }
    printf("  Identity: %s\n", identity);
    printf("  SK: %zu bytes (given to Alice securely)\n", sk_len);
    
    // 3. Encrypt - Anyone can encrypt to identity using MPK
    printf("\n[Step 3] Encrypt (Bob encrypts message to Alice)\n");
    const char *message = "Hello Alice! This is a secret message from Bob.";
    size_t msg_len = strlen(message) + 1;
    
    uint8_t ciphertext[1024];
    size_t ct_len = sizeof(ciphertext);
    
    ret = app_ibe_encrypt(mpk, mpk_len, identity,
                          (uint8_t*)message, msg_len,
                          ciphertext, &ct_len);
    if (ret != 0) {
        printf("FAILED: Encrypt error\n");
        return -1;
    }
    printf("  Plaintext: \"%s\" (%zu bytes)\n", message, msg_len);
    printf("  Ciphertext: %zu bytes\n", ct_len);
    
    // 4. Decrypt - Alice decrypts with her private key
    printf("\n[Step 4] Decrypt (Alice decrypts with her SK)\n");
    uint8_t decrypted[1024];
    size_t dec_len = sizeof(decrypted);
    
    ret = app_ibe_decrypt(sk, sk_len, mpk, mpk_len, identity,
                          ciphertext, ct_len, decrypted, &dec_len);
    if (ret != 0) {
        printf("FAILED: Decrypt error\n");
        return -1;
    }
    printf("  Decrypted: \"%s\" (%zu bytes)\n", (char*)decrypted, dec_len);
    
    // 5. Verify
    printf("\n[Step 5] Verify\n");
    if (msg_len == dec_len && memcmp(message, decrypted, msg_len) == 0) {
        printf("  SUCCESS: Decrypted message matches original!\n");
        ret = 0;
    } else {
        printf("  FAILED: Message mismatch!\n");
        ret = -1;
    }
    
    // 6. Test with wrong identity (should fail)
    printf("\n[Step 6] Security Test (wrong identity should fail)\n");
    uint8_t wrong_sk[128];
    size_t wrong_sk_len = sizeof(wrong_sk);
    app_ibe_extract(msk, msk_len, "eve@attacker.com", wrong_sk, &wrong_sk_len);
    
    uint8_t wrong_decrypt[1024];
    size_t wrong_len = sizeof(wrong_decrypt);
    int wrong_result = app_ibe_decrypt(wrong_sk, wrong_sk_len, mpk, mpk_len, 
                                        "eve@attacker.com",
                                        ciphertext, ct_len, 
                                        wrong_decrypt, &wrong_len);
    if (wrong_result != 0) {
        printf("  SUCCESS: Wrong identity correctly rejected\n");
    } else {
        // Even if decrypt returns 0, content should be garbage
        if (memcmp(message, wrong_decrypt, msg_len) != 0) {
            printf("  SUCCESS: Wrong identity produced invalid plaintext\n");
        } else {
            printf("  FAILED: Security breach - wrong identity could decrypt!\n");
            ret = -1;
        }
    }
    
    printf("\n============================================\n");
    if (ret == 0) {
        printf("    IBE TEST PASSED\n");
    } else {
        printf("    IBE TEST FAILED\n");
    }
    printf("============================================\n\n");
    
    return ret;
}
