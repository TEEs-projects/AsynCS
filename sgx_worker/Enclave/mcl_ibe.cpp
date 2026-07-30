#include "mcl_ibe.h"
#include "bfibe_mcl.h"

int mcl_ibe_init(void) {
    return bfibe_mcl_init();
}

int mcl_ibe_setup(uint8_t* mpk_out, size_t* mpk_len,
                  uint8_t* msk_out, size_t* msk_len) {
    return bfibe_mcl_setup(mpk_out, mpk_len, msk_out, msk_len);
}

int mcl_ibe_extract(const uint8_t* msk, size_t msk_len,
                    const char* identity, size_t identity_len,
                    uint8_t* sk_id_out, size_t* sk_id_len) {
    return bfibe_mcl_extract(msk, msk_len, identity, identity_len, sk_id_out, sk_id_len);
}

int mcl_ibe_encrypt(const uint8_t* mpk, size_t mpk_len,
                    const char* identity, size_t identity_len,
                    const uint8_t* message, size_t message_len,
                    uint8_t* ciphertext_out, size_t* ciphertext_len) {
    return bfibe_mcl_encrypt(
        mpk,
        mpk_len,
        identity,
        identity_len,
        message,
        message_len,
        ciphertext_out,
        ciphertext_len
    );
}

int mcl_ibe_decrypt(const uint8_t* sk_id, size_t sk_id_len,
                    const uint8_t* ciphertext, size_t ciphertext_len,
                    uint8_t* message_out, size_t* message_len) {
    return bfibe_mcl_decrypt(sk_id, sk_id_len, ciphertext, ciphertext_len, message_out, message_len);
}
