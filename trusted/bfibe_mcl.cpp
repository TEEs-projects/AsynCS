/*
 * Shared trusted Boneh-Franklin IBE implementation.
 *
 * Type-3 BLS12-381 roles:
 * - MPK = msk * G1
 * - sk_id = msk * H(identity) in G2
 * - ciphertext carries U = r * G1
 */

#include "bfibe_mcl.h"

#define MCL_FP_BIT 384
#define MCL_FR_BIT 256

#include "mcl/bn.h"

#include "sgx_tcrypto.h"
#include "sgx_trts.h"
#include <string.h>

extern "C" void bfibe_mcl_log(const char* message);

static bool g_mcl_initialized = false;

static void log_message(const char* message) {
    bfibe_mcl_log(message);
}

static int get_bfibe_g1_generator(mclBnG1* g1) {
    static const char kGeneratorDomain[] = "ASYNCS/BFIBE/G1/GENERATOR/v1";

    if (!g1) {
        return -1;
    }
    if (mclBnG1_hashAndMapTo(g1, kGeneratorDomain, sizeof(kGeneratorDomain) - 1) != 0) {
        log_message("BF-IBE MCL: Failed to hash fixed G1 generator\n");
        return -1;
    }
    if (mclBnG1_isZero(g1)) {
        log_message("BF-IBE MCL: Fixed G1 generator mapped to zero\n");
        return -1;
    }
    return 0;
}

int bfibe_mcl_init(void) {
    if (g_mcl_initialized) {
        return 0;
    }

    int ret = mclBn_init(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
    if (ret != 0) {
        log_message("BF-IBE MCL: Failed to initialize mcl\n");
        return ret;
    }

    g_mcl_initialized = true;
    log_message("BF-IBE MCL: Initialized with BLS12-381\n");
    return 0;
}

int bfibe_mcl_derive_master_secret(const uint8_t* seed, size_t seed_len,
                                   uint8_t* msk_out, size_t* msk_len) {
    if (!seed || seed_len == 0 || !msk_out || !msk_len) {
        return -1;
    }
    if (bfibe_mcl_init() != 0) {
        return -1;
    }

    sgx_sha256_hash_t hash;
    sgx_status_t status = sgx_sha256_msg(seed, seed_len, &hash);
    if (status != SGX_SUCCESS) {
        log_message("BF-IBE MCL: Failed to hash master-secret seed\n");
        return -1;
    }

    mclBnFr msk;
    mclBnFr_setLittleEndianMod(&msk, hash, sizeof(hash));

    size_t msk_size = mclBnFr_serialize(msk_out, *msk_len, &msk);
    memset(hash, 0, sizeof(hash));
    if (msk_size == 0) {
        log_message("BF-IBE MCL: Failed to serialize derived msk\n");
        return -1;
    }
    *msk_len = msk_size;
    return 0;
}

int bfibe_mcl_setup(uint8_t* mpk_out, size_t* mpk_len,
                    uint8_t* msk_out, size_t* msk_len) {
    if (!mpk_out || !mpk_len || !msk_out || !msk_len) {
        return -1;
    }
    if (bfibe_mcl_init() != 0) {
        return -1;
    }

    mclBnFr msk;
    uint8_t random_bytes[32];
    sgx_status_t status = sgx_read_rand(random_bytes, sizeof(random_bytes));
    if (status != SGX_SUCCESS) {
        log_message("BF-IBE MCL: Failed to generate msk randomness\n");
        return -1;
    }
    mclBnFr_setLittleEndianMod(&msk, random_bytes, sizeof(random_bytes));

    mclBnG1 mpk;
    mclBnG1 g1;
    if (get_bfibe_g1_generator(&g1) != 0) {
        memset(random_bytes, 0, sizeof(random_bytes));
        return -1;
    }
    mclBnG1_mul(&mpk, &g1, &msk);
    if (mclBnG1_isZero(&mpk)) {
        memset(random_bytes, 0, sizeof(random_bytes));
        log_message("BF-IBE MCL: Derived mpk is zero\n");
        return -1;
    }

    size_t msk_size = mclBnFr_serialize(msk_out, *msk_len, &msk);
    if (msk_size == 0) {
        log_message("BF-IBE MCL: Failed to serialize msk\n");
        return -1;
    }
    *msk_len = msk_size;

    size_t mpk_size = mclBnG1_serialize(mpk_out, *mpk_len, &mpk);
    if (mpk_size == 0) {
        log_message("BF-IBE MCL: Failed to serialize mpk\n");
        return -1;
    }
    *mpk_len = mpk_size;

    log_message("BF-IBE MCL: Setup complete\n");
    return 0;
}

int bfibe_mcl_public_from_msk(const uint8_t* msk, size_t msk_len,
                              uint8_t* mpk_out, size_t* mpk_len) {
    if (!msk || !mpk_out || !mpk_len) {
        return -1;
    }
    if (bfibe_mcl_init() != 0) {
        return -1;
    }

    mclBnFr msk_fr;
    if (mclBnFr_deserialize(&msk_fr, msk, msk_len) == 0) {
        log_message("BF-IBE MCL: Failed to deserialize msk for mpk\n");
        return -1;
    }

    mclBnG1 g1;
    if (get_bfibe_g1_generator(&g1) != 0) {
        return -1;
    }

    mclBnG1 mpk;
    mclBnG1_mul(&mpk, &g1, &msk_fr);
    if (mclBnG1_isZero(&mpk)) {
        log_message("BF-IBE MCL: Derived mpk is zero\n");
        return -1;
    }

    size_t mpk_size = mclBnG1_serialize(mpk_out, *mpk_len, &mpk);
    if (mpk_size == 0) {
        log_message("BF-IBE MCL: Failed to serialize mpk\n");
        return -1;
    }
    *mpk_len = mpk_size;
    return 0;
}

int bfibe_mcl_extract(const uint8_t* msk, size_t msk_len,
                      const char* identity, size_t identity_len,
                      uint8_t* sk_id_out, size_t* sk_id_len) {
    if (!msk || !identity || !sk_id_out || !sk_id_len) {
        return -1;
    }
    if (bfibe_mcl_init() != 0) {
        return -1;
    }

    mclBnFr msk_fr;
    if (mclBnFr_deserialize(&msk_fr, msk, msk_len) == 0) {
        log_message("BF-IBE MCL: Failed to deserialize msk\n");
        return -1;
    }

    mclBnG2 q_id;
    mclBnG2_hashAndMapTo(&q_id, identity, identity_len);

    mclBnG2 sk_id;
    mclBnG2_mul(&sk_id, &q_id, &msk_fr);

    size_t sk_size = mclBnG2_serialize(sk_id_out, *sk_id_len, &sk_id);
    if (sk_size == 0) {
        log_message("BF-IBE MCL: Failed to serialize sk_id\n");
        return -1;
    }
    *sk_id_len = sk_size;

    log_message("BF-IBE MCL: Extract complete\n");
    return 0;
}

int bfibe_mcl_encrypt(const uint8_t* mpk, size_t mpk_len,
                      const char* identity, size_t identity_len,
                      const uint8_t* message, size_t message_len,
                      uint8_t* ciphertext_out, size_t* ciphertext_len) {
    if (!mpk || !identity || !message || !ciphertext_out || !ciphertext_len) {
        return -1;
    }
    if (bfibe_mcl_init() != 0) {
        return -1;
    }

    mclBnG1 mpk_g1;
    if (mclBnG1_deserialize(&mpk_g1, mpk, mpk_len) == 0) {
        log_message("BF-IBE MCL: Failed to deserialize mpk\n");
        return -1;
    }

    mclBnG2 q_id;
    mclBnG2_hashAndMapTo(&q_id, identity, identity_len);

    mclBnFr r;
    uint8_t random_bytes[32];
    sgx_status_t status = sgx_read_rand(random_bytes, sizeof(random_bytes));
    if (status != SGX_SUCCESS) {
        log_message("BF-IBE MCL: Failed to generate encryption randomness\n");
        return -1;
    }
    mclBnFr_setLittleEndianMod(&r, random_bytes, sizeof(random_bytes));

    mclBnG1 U;
    mclBnG1 g1;
    if (get_bfibe_g1_generator(&g1) != 0) {
        memset(random_bytes, 0, sizeof(random_bytes));
        return -1;
    }
    mclBnG1_mul(&U, &g1, &r);
    if (mclBnG1_isZero(&U)) {
        memset(random_bytes, 0, sizeof(random_bytes));
        log_message("BF-IBE MCL: Derived ephemeral U is zero\n");
        return -1;
    }

    mclBnGT temp;
    mclBn_pairing(&temp, &mpk_g1, &q_id);

    mclBnGT shared;
    mclBnGT_pow(&shared, &temp, &r);

    uint8_t shared_bytes[576];
    size_t shared_size = mclBnGT_serialize(shared_bytes, sizeof(shared_bytes), &shared);
    if (shared_size == 0) {
        log_message("BF-IBE MCL: Failed to serialize shared GT value\n");
        return -1;
    }

    sgx_sha256_hash_t aes_key_full;
    status = sgx_sha256_msg(shared_bytes, shared_size, &aes_key_full);
    if (status != SGX_SUCCESS) {
        log_message("BF-IBE MCL: Failed to hash shared GT value\n");
        return -1;
    }

    uint8_t u_bytes[96];
    size_t u_size = mclBnG1_serialize(u_bytes, sizeof(u_bytes), &U);
    if (u_size == 0 || u_size > 0xffff) {
        log_message("BF-IBE MCL: Failed to serialize U\n");
        return -1;
    }

    size_t required = 2 + u_size + 12 + 16 + message_len;
    if (*ciphertext_len < required) {
        *ciphertext_len = required;
        return -1;
    }

    uint8_t iv[12];
    status = sgx_read_rand(iv, sizeof(iv));
    if (status != SGX_SUCCESS) {
        log_message("BF-IBE MCL: Failed to generate IV\n");
        return -1;
    }

    uint8_t* out = ciphertext_out;
    *out++ = (uint8_t)(u_size >> 8);
    *out++ = (uint8_t)(u_size & 0xff);
    memcpy(out, u_bytes, u_size);
    out += u_size;
    memcpy(out, iv, sizeof(iv));
    out += sizeof(iv);

    uint8_t* tag = out;
    out += 16;

    uint8_t aes_key[16];
    memcpy(aes_key, aes_key_full, sizeof(aes_key));
    status = sgx_rijndael128GCM_encrypt(
        (const sgx_aes_gcm_128bit_key_t*)aes_key,
        message,
        message_len,
        out,
        iv,
        sizeof(iv),
        NULL,
        0,
        (sgx_aes_gcm_128bit_tag_t*)tag
    );

    memset(aes_key, 0, sizeof(aes_key));
    memset(aes_key_full, 0, sizeof(aes_key_full));
    if (status != SGX_SUCCESS) {
        log_message("BF-IBE MCL: AES encryption failed\n");
        return -1;
    }

    *ciphertext_len = required;
    log_message("BF-IBE MCL: Encrypt complete\n");
    return 0;
}

int bfibe_mcl_decrypt(const uint8_t* sk_id, size_t sk_id_len,
                      const uint8_t* ciphertext, size_t ciphertext_len,
                      uint8_t* message_out, size_t* message_len) {
    if (!sk_id || !ciphertext || !message_out || !message_len) {
        return -1;
    }
    if (bfibe_mcl_init() != 0) {
        return -1;
    }
    if (ciphertext_len < 2 + 12 + 16) {
        return -1;
    }

    mclBnG2 sk_id_g2;
    if (mclBnG2_deserialize(&sk_id_g2, sk_id, sk_id_len) == 0) {
        log_message("BF-IBE MCL: Failed to deserialize sk_id\n");
        return -1;
    }

    const uint8_t* in = ciphertext;
    size_t u_size = ((size_t)in[0] << 8) | in[1];
    in += 2;
    if (u_size == 0 || ciphertext_len < 2 + u_size + 12 + 16) {
        return -1;
    }

    mclBnG1 U;
    if (mclBnG1_deserialize(&U, in, u_size) == 0) {
        log_message("BF-IBE MCL: Failed to deserialize U\n");
        return -1;
    }
    in += u_size;

    const uint8_t* iv = in;
    in += 12;
    const uint8_t* tag = in;
    in += 16;
    const size_t encrypted_len = ciphertext_len - 2 - u_size - 12 - 16;
    if (*message_len < encrypted_len) {
        *message_len = encrypted_len;
        return -1;
    }

    mclBnGT shared;
    mclBn_pairing(&shared, &U, &sk_id_g2);

    uint8_t shared_bytes[576];
    size_t shared_size = mclBnGT_serialize(shared_bytes, sizeof(shared_bytes), &shared);
    if (shared_size == 0) {
        log_message("BF-IBE MCL: Failed to serialize shared GT value\n");
        return -1;
    }

    sgx_sha256_hash_t aes_key_full;
    sgx_status_t status = sgx_sha256_msg(shared_bytes, shared_size, &aes_key_full);
    if (status != SGX_SUCCESS) {
        log_message("BF-IBE MCL: Failed to hash shared GT value\n");
        return -1;
    }

    uint8_t aes_key[16];
    memcpy(aes_key, aes_key_full, sizeof(aes_key));
    status = sgx_rijndael128GCM_decrypt(
        (const sgx_aes_gcm_128bit_key_t*)aes_key,
        in,
        encrypted_len,
        message_out,
        iv,
        12,
        NULL,
        0,
        (const sgx_aes_gcm_128bit_tag_t*)tag
    );

    memset(aes_key, 0, sizeof(aes_key));
    memset(aes_key_full, 0, sizeof(aes_key_full));
    if (status != SGX_SUCCESS) {
        log_message("BF-IBE MCL: AES decryption failed\n");
        return -1;
    }

    *message_len = encrypted_len;
    log_message("BF-IBE MCL: Decrypt complete\n");
    return 0;
}

int bfibe_mcl_decrypt_key_envelope(const uint8_t* sk_id, size_t sk_id_len,
                                   const uint8_t* c1, size_t c1_len,
                                   const uint8_t* nonce, size_t nonce_len,
                                   const uint8_t* ciphertext, size_t ciphertext_len,
                                   const uint8_t* aad, size_t aad_len,
                                   uint8_t session_key_out32[32]) {
    if (!sk_id || !c1 || !nonce || !ciphertext || !session_key_out32) {
        return -1;
    }
    if (nonce_len != 12 || ciphertext_len <= 16) {
        return -1;
    }
    if (!aad && aad_len != 0) {
        return -1;
    }
    if (bfibe_mcl_init() != 0) {
        return -1;
    }

    const size_t encrypted_len = ciphertext_len - 16;
    const uint8_t* tag = ciphertext + encrypted_len;
    if (!(encrypted_len == 16 || encrypted_len == 32)) {
        return -1;
    }

    mclBnG2 sk_id_g2;
    if (mclBnG2_deserialize(&sk_id_g2, sk_id, sk_id_len) == 0) {
        log_message("BF-IBE MCL: Failed to deserialize sk_id\n");
        return -1;
    }

    mclBnG1 U;
    if (mclBnG1_deserialize(&U, c1, c1_len) == 0) {
        log_message("BF-IBE MCL: Failed to deserialize envelope C1\n");
        return -1;
    }

    mclBnGT shared;
    mclBn_pairing(&shared, &U, &sk_id_g2);

    uint8_t shared_bytes[576];
    size_t shared_size = mclBnGT_serialize(shared_bytes, sizeof(shared_bytes), &shared);
    if (shared_size == 0) {
        log_message("BF-IBE MCL: Failed to serialize shared GT value\n");
        return -1;
    }

    sgx_sha256_hash_t aes_key_full;
    sgx_status_t status = sgx_sha256_msg(shared_bytes, shared_size, &aes_key_full);
    memset(shared_bytes, 0, sizeof(shared_bytes));
    if (status != SGX_SUCCESS) {
        log_message("BF-IBE MCL: Failed to hash shared GT value\n");
        return -1;
    }

    uint8_t aes_key[16];
    memcpy(aes_key, aes_key_full, sizeof(aes_key));
    uint8_t plaintext[32] = {0};
    status = sgx_rijndael128GCM_decrypt(
        (const sgx_aes_gcm_128bit_key_t*)aes_key,
        ciphertext,
        encrypted_len,
        plaintext,
        nonce,
        nonce_len,
        aad,
        aad_len,
        (const sgx_aes_gcm_128bit_tag_t*)tag
    );

    memset(aes_key, 0, sizeof(aes_key));
    memset(aes_key_full, 0, sizeof(aes_key_full));
    if (status != SGX_SUCCESS) {
        memset(plaintext, 0, sizeof(plaintext));
        log_message("BF-IBE MCL: key envelope AES decryption failed\n");
        return -1;
    }

    memset(session_key_out32, 0, 32);
    memcpy(session_key_out32, plaintext, encrypted_len);
    memset(plaintext, 0, sizeof(plaintext));
    return 0;
}
