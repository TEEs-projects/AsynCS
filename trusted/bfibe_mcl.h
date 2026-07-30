/*
 * Shared trusted Boneh-Franklin IBE wrapper.
 *
 * This module is enclave-agnostic: worker and KMS enclaves both link this
 * source and provide bfibe_mcl_log() locally.
 */

#ifndef ASYNCS_TRUSTED_BFIBE_MCL_H
#define ASYNCS_TRUSTED_BFIBE_MCL_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int bfibe_mcl_init(void);

int bfibe_mcl_derive_master_secret(const uint8_t* seed, size_t seed_len,
                                   uint8_t* msk_out, size_t* msk_len);

int bfibe_mcl_setup(uint8_t* mpk_out, size_t* mpk_len,
                    uint8_t* msk_out, size_t* msk_len);

int bfibe_mcl_public_from_msk(const uint8_t* msk, size_t msk_len,
                              uint8_t* mpk_out, size_t* mpk_len);

int bfibe_mcl_extract(const uint8_t* msk, size_t msk_len,
                      const char* identity, size_t identity_len,
                      uint8_t* sk_id_out, size_t* sk_id_len);

int bfibe_mcl_encrypt(const uint8_t* mpk, size_t mpk_len,
                      const char* identity, size_t identity_len,
                      const uint8_t* message, size_t message_len,
                      uint8_t* ciphertext_out, size_t* ciphertext_len);

int bfibe_mcl_decrypt(const uint8_t* sk_id, size_t sk_id_len,
                      const uint8_t* ciphertext, size_t ciphertext_len,
                      uint8_t* message_out, size_t* message_len);

int bfibe_mcl_decrypt_key_envelope(const uint8_t* sk_id, size_t sk_id_len,
                                   const uint8_t* c1, size_t c1_len,
                                   const uint8_t* nonce, size_t nonce_len,
                                   const uint8_t* ciphertext, size_t ciphertext_len,
                                   const uint8_t* aad, size_t aad_len,
                                   uint8_t session_key_out32[32]);

#ifdef __cplusplus
}
#endif

#endif
