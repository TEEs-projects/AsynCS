/**
 * MCL-based Boneh-Franklin IBE wrapper for SGX Enclave
 * 
 * This implements Identity-Based Encryption using the mcl library
 * with BLS12-381 pairing curve.
 * 
 * Current Type-3 pairing roles:
 * - MPK = msk * G1
 * - sk_id = msk * H(id) in G2
 * - ciphertext carries U = r * G1
 *
 * Build trusted MCL with: scripts/build_trusted_mcl.sh
 */

#ifndef MCL_IBE_H
#define MCL_IBE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the IBE system. Must be called once before any other function.
 * @return 0 on success, non-zero on error
 */
int mcl_ibe_init(void);

/**
 * IBE Setup: Generate master public key and master secret key
 * @param mpk_out Output buffer for master public key (serialized G1 point)
 * @param mpk_len Size of mpk_out buffer, updated to actual size
 * @param msk_out Output buffer for master secret key (serialized Fr)
 * @param msk_len Size of msk_out buffer, updated to actual size
 * @return 0 on success, non-zero on error
 */
int mcl_ibe_setup(uint8_t* mpk_out, size_t* mpk_len,
                  uint8_t* msk_out, size_t* msk_len);

/**
 * IBE Extract: Derive private key for an identity
 * @param msk Master secret key (from setup)
 * @param msk_len Length of msk
 * @param identity Identity string (e.g., FID)
 * @param identity_len Length of identity
 * @param sk_id_out Output buffer for identity private key (serialized G2 point)
 * @param sk_id_len Size of sk_id_out buffer, updated to actual size
 * @return 0 on success, non-zero on error
 */
int mcl_ibe_extract(const uint8_t* msk, size_t msk_len,
                    const char* identity, size_t identity_len,
                    uint8_t* sk_id_out, size_t* sk_id_len);

/**
 * IBE Encrypt: Encrypt message for an identity
 * @param mpk Master public key (from setup)
 * @param mpk_len Length of mpk
 * @param identity Identity string (e.g., FID)
 * @param identity_len Length of identity
 * @param message Plaintext message
 * @param message_len Length of message
 * @param ciphertext_out Output buffer for ciphertext
 * @param ciphertext_len Size of ciphertext_out buffer, updated to actual size
 * @return 0 on success, non-zero on error
 * 
 * Ciphertext format: U-size || U (G1 point) || IV || tag || encrypted_message
 */
int mcl_ibe_encrypt(const uint8_t* mpk, size_t mpk_len,
                    const char* identity, size_t identity_len,
                    const uint8_t* message, size_t message_len,
                    uint8_t* ciphertext_out, size_t* ciphertext_len);

/**
 * IBE Decrypt: Decrypt ciphertext using identity private key
 * @param sk_id Identity private key (from extract)
 * @param sk_id_len Length of sk_id
 * @param ciphertext Ciphertext (from encrypt)
 * @param ciphertext_len Length of ciphertext
 * @param message_out Output buffer for plaintext
 * @param message_len Size of message_out buffer, updated to actual size
 * @return 0 on success, non-zero on error
 */
int mcl_ibe_decrypt(const uint8_t* sk_id, size_t sk_id_len,
                    const uint8_t* ciphertext, size_t ciphertext_len,
                    uint8_t* message_out, size_t* message_len);

#ifdef __cplusplus
}
#endif

#endif // MCL_IBE_H
