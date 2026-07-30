/**
 * App-side IBE (Identity-Based Encryption) Implementation
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
 * This implementation uses OpenSSL for a simplified IBE demonstration.
 * For production, use a pairing-based IBE library compiled without cpuid.
 */

#ifndef APP_IBE_H
#define APP_IBE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the IBE system (App-side)
 * @return 0 on success, non-zero on failure
 */
int app_ibe_init(void);

/**
 * Setup master keys for IBE (PKG operation)
 * @param mpk_out Buffer for master public key (at least 128 bytes)
 * @param mpk_len In: buffer size, Out: actual size
 * @param msk_out Buffer for master secret key (at least 64 bytes)
 * @param msk_len In: buffer size, Out: actual size
 * @return 0 on success
 */
int app_ibe_setup(uint8_t* mpk_out, size_t* mpk_len,
                  uint8_t* msk_out, size_t* msk_len);

/**
 * Extract user private key for an identity (PKG operation)
 * @param msk Master secret key
 * @param msk_len Master secret key length
 * @param identity User identity string (e.g., "function_id@tenant")
 * @param sk_out Buffer for user secret key (at least 64 bytes)
 * @param sk_len In: buffer size, Out: actual size
 * @return 0 on success
 */
int app_ibe_extract(const uint8_t* msk, size_t msk_len,
                    const char* identity,
                    uint8_t* sk_out, size_t* sk_len);

/**
 * Encrypt data for an identity
 * @param mpk Master public key
 * @param mpk_len Master public key length
 * @param identity Recipient identity
 * @param plaintext Data to encrypt
 * @param pt_len Plaintext length
 * @param ciphertext_out Buffer for ciphertext (at least pt_len + 128 bytes)
 * @param ct_len In: buffer size, Out: actual size
 * @return 0 on success
 */
int app_ibe_encrypt(const uint8_t* mpk, size_t mpk_len,
                    const char* identity,
                    const uint8_t* plaintext, size_t pt_len,
                    uint8_t* ciphertext_out, size_t* ct_len);

/**
 * Decrypt data with user secret key
 * @param sk User secret key
 * @param sk_len User secret key length
 * @param mpk Master public key
 * @param mpk_len Master public key length
 * @param identity Identity used for encryption
 * @param ciphertext Encrypted data
 * @param ct_len Ciphertext length
 * @param plaintext_out Buffer for plaintext
 * @param pt_len In: buffer size, Out: actual size
 * @return 0 on success
 */
int app_ibe_decrypt(const uint8_t* sk, size_t sk_len,
                    const uint8_t* mpk, size_t mpk_len,
                    const char* identity,
                    const uint8_t* ciphertext, size_t ct_len,
                    uint8_t* plaintext_out, size_t* pt_len);

/**
 * Run full IBE test demonstrating the workflow
 * @return 0 on success (test passed), non-zero on failure
 */
int app_ibe_test(void);

#ifdef __cplusplus
}
#endif

#endif /* APP_IBE_H */
