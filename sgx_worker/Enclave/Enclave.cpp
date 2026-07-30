#include "Enclave_t.h"
#include "wasm_export.h"
#include "bh_platform.h"
#include "sgx_tcrypto.h"
#include "mcl_ibe.h"
#include "bfibe_mcl.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "sgx_utils.h"

static void function_cache_clear();
extern "C" int enclave_print(const char *message);
extern "C" {
    extern uint8_t* global_output_buffer;
    extern uint32_t global_output_capacity;
    extern uint32_t global_output_pos;
    extern bool capture_output;
    extern bool capture_output_overflow;
}

static const uint32_t C1_ASYNCS_TRACE_VERSION = 1;
static const uint32_t C1_TRACE_RID_VALID = 1u << 0;
static const uint32_t C1_TRACE_PAYLOAD_VALID = 1u << 1;
static const uint32_t C1_TRACE_FUNCTION_CACHE_HIT = 1u << 2;
static const uint32_t C1_TRACE_CFUNC_DECRYPT_EXECUTED = 1u << 3;
static const uint32_t C1_TRACE_WORKLOAD_CYCLES_VALID = 1u << 4;
static const uint32_t C1_TRACE_OUTPUT_KEM_CYCLES_VALID = 1u << 5;
static const uint32_t C1_TRACE_OUTPUT_AES_GCM_CYCLES_VALID = 1u << 6;
static const uint32_t C1_TRACE_FUNCTION_CACHE_VALID = 1u << 7;
static const uint32_t C1_TRACE_SUCCESS = 1u << 8;
static const uint32_t C3_TRACE_INPUT_KEY_CYCLES_VALID = 1u << 9;
static const uint32_t C3_TRACE_INPUT_AES_GCM_CYCLES_VALID = 1u << 10;
static const uint32_t C2_TRACE_FUNCTION_KEY_CYCLES_VALID = 1u << 11;
static const uint32_t C2_TRACE_CFUNC_AES_GCM_CYCLES_VALID = 1u << 12;
static const uint32_t C2_TRACE_WASM_LOAD_CYCLES_VALID = 1u << 13;
static const uint32_t C2_TRACE_WASM_INSTANTIATE_CYCLES_VALID = 1u << 14;
static const uint32_t ASYNCS_MAX_OUTPUT_CAPACITY_BYTES = 1024u * 1024u;

static uint64_t g_workload_tsc_begin = 0;
static uint64_t g_workload_tsc_end = 0;
static bool g_workload_tsc_begin_valid = false;
static bool g_workload_tsc_end_valid = false;

static void output_capture_release() {
    if (global_output_buffer != NULL) {
        volatile uint8_t* byte = global_output_buffer;
        for (uint32_t index = 0; index < global_output_capacity + 1; ++index) {
            byte[index] = 0;
        }
        free(global_output_buffer);
    }
    global_output_buffer = NULL;
    global_output_capacity = 0;
    global_output_pos = 0;
}

static bool output_capture_prepare(uint32_t capacity) {
    output_capture_release();
    if (capacity == 0 || capacity > ASYNCS_MAX_OUTPUT_CAPACITY_BYTES) {
        return false;
    }
    global_output_buffer = (uint8_t*)malloc((size_t)capacity + 1);
    if (global_output_buffer == NULL) {
        return false;
    }
    global_output_capacity = capacity;
    memset(global_output_buffer, 0, (size_t)capacity + 1);
    return true;
}

static inline uint64_t c1_tsc_begin_read() {
    uint32_t lo = 0;
    uint32_t hi = 0;
    __asm__ __volatile__("lfence\n\trdtsc\n\t" : "=a"(lo), "=d"(hi) :: "memory");
    return ((uint64_t)hi << 32) | lo;
}

static inline uint64_t c1_tsc_end_read() {
    uint32_t lo = 0;
    uint32_t hi = 0;
    uint32_t aux = 0;
    __asm__ __volatile__("rdtscp\n\tlfence\n\t" : "=a"(lo), "=d"(hi), "=c"(aux) :: "memory");
    return ((uint64_t)hi << 32) | lo;
}

static uint64_t c1_workload_tsc_begin(wasm_exec_env_t) {
    g_workload_tsc_begin = c1_tsc_begin_read();
    g_workload_tsc_begin_valid = true;
    return g_workload_tsc_begin;
}

static uint64_t c1_workload_tsc_end(wasm_exec_env_t) {
    g_workload_tsc_end = c1_tsc_end_read();
    g_workload_tsc_end_valid = true;
    return g_workload_tsc_end;
}

static int32_t c1_workload_set_output(wasm_exec_env_t, const uint8_t* data, uint32_t len) {
    if (!capture_output || global_output_buffer == NULL || data == NULL || len == 0 ||
        len > global_output_capacity) {
        capture_output_overflow = true;
        return -1;
    }
    memcpy(global_output_buffer, data, len);
    global_output_buffer[len] = 0;
    global_output_pos = len;
    return 0;
}

static NativeSymbol c1_native_symbols[] = {
    { "c1_workload_tsc_begin", (void*)c1_workload_tsc_begin, "()I", NULL },
    { "c1_workload_tsc_end", (void*)c1_workload_tsc_end, "()I", NULL },
    { "c1_workload_set_output", (void*)c1_workload_set_output, "(*~)i", NULL },
};

// Base64 encoding table
static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Base64 encode binary data. Returns malloc'd null-terminated string.
// Caller must free the returned pointer.
static char* base64_encode(const uint8_t* data, uint32_t len) {
    if (data == NULL || len == 0) return NULL;
    
    uint32_t out_len = ((len + 2) / 3) * 4;
    char* out = (char*)malloc(out_len + 1);
    if (!out) return NULL;
    
    uint32_t i = 0, j = 0;
    while (i < len) {
        uint32_t a = i < len ? data[i++] : 0;
        uint32_t b = i < len ? data[i++] : 0;
        uint32_t c = i < len ? data[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        
        out[j++] = base64_table[(triple >> 18) & 0x3F];
        out[j++] = base64_table[(triple >> 12) & 0x3F];
        out[j++] = base64_table[(triple >> 6) & 0x3F];
        out[j++] = base64_table[triple & 0x3F];
    }
    
    // Add padding
    uint32_t mod = len % 3;
    if (mod == 1) {
        out[out_len - 2] = '=';
        out[out_len - 1] = '=';
    } else if (mod == 2) {
        out[out_len - 1] = '=';
    }
    out[out_len] = '\0';
    return out;
}

static bool sha256_hex(const uint8_t* data, uint32_t len, char out_hex[65]) {
    static const char hex[] = "0123456789abcdef";
    static const char empty_sha256[] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    sgx_sha256_hash_t hash;
    if (len == 0) {
        memcpy(out_hex, empty_sha256, sizeof(empty_sha256));
        return true;
    }
    if (data == NULL) {
        return false;
    }
    if (sgx_sha256_msg(data, len, &hash) != SGX_SUCCESS) {
        return false;
    }
    for (uint32_t i = 0; i < sizeof(hash); ++i) {
        out_hex[i * 2] = hex[(hash[i] >> 4) & 0x0f];
        out_hex[i * 2 + 1] = hex[hash[i] & 0x0f];
    }
    out_hex[64] = '\0';
    return true;
}

static void trace_e3_payload_consumed(const uint8_t* data, uint32_t len) {
    char payload_sha256[65] = {0};
    if (sha256_hex(data, len, payload_sha256)) {
        char payload_trace[160];
        snprintf(payload_trace, sizeof(payload_trace),
                 "ACSC_TRACE_E3_PAYLOAD:payload_bytes_consumed=%u payload_sha256=%s\n",
                 len,
                 payload_sha256);
        enclave_print(payload_trace);
    } else {
        enclave_print("ACSC_TRACE_E3_PAYLOAD:payload_bytes_consumed= payload_sha256=\n");
    }
}

static bool capture_e3_payload_evidence(
    const uint8_t* data,
    uint32_t len,
    c1_asyncs_invoke_trace_t* invoke_trace
) {
    sgx_sha256_hash_t payload_sha256;
    if (invoke_trace == NULL || (len > 0 && data == NULL)) {
        return false;
    }
    if (sgx_sha256_msg(data, len, &payload_sha256) != SGX_SUCCESS) {
        return false;
    }
    invoke_trace->payload_bytes_consumed = len;
    memcpy(invoke_trace->payload_sha256, payload_sha256, sizeof(payload_sha256));
    invoke_trace->flags |= C1_TRACE_PAYLOAD_VALID;
    return true;
}

extern "C" {
    typedef int (*os_print_function_t)(const char *message);
    extern void os_set_print_function(os_print_function_t pf);

    // Forward declaration
    int enclave_print(const char *message);

    void bfibe_mcl_log(const char* message) {
        enclave_print(message);
    }

    // Global Key Pair
    sgx_ec256_private_t g_private_key;
    sgx_ec256_public_t g_public_key;
    bool g_worker_keypair_ready = false;

    void ecall_create_report(const sgx_target_info_t* target_info, sgx_report_t* report, uint8_t public_key[64]) {
        sgx_status_t ret;
        sgx_ecc_state_handle_t ecc_handle;

        // 1. Open ECC context
        ret = sgx_ecc256_open_context(&ecc_handle);
        if (ret != SGX_SUCCESS) {
            enclave_print("Error opening ECC context\n");
            return;
        }

        // 2. Generate Key Pair
        ret = sgx_ecc256_create_key_pair(&g_private_key, &g_public_key, ecc_handle);
        if (ret != SGX_SUCCESS) {
            enclave_print("Error creating key pair\n");
            sgx_ecc256_close_context(ecc_handle);
            return;
        }
        sgx_ecc256_close_context(ecc_handle);

        // 3. Prepare Report Data (Hash of Public Key)
        sgx_report_data_t report_data = {0};
        sgx_sha256_hash_t hash;
        ret = sgx_sha256_msg((uint8_t*)&g_public_key, sizeof(sgx_ec256_public_t), &hash);
        if (ret != SGX_SUCCESS) {
            enclave_print("Error hashing public key\n");
            return;
        }
        memcpy(report_data.d, hash, sizeof(hash));

        // 4. Create Report
        sgx_create_report(target_info, &report_data, report);

        // 5. Return Public Key
        memcpy(public_key, &g_public_key, 64);
        g_worker_keypair_ready = true;
    }

    // Global Worker Key (Decrypted)
    // Protocol(A): Treat this as dkf (a DecKey-only capability), NOT an AEAD key.
    // The worker must derive per-request/per-function AEAD keys via DecKey.
    uint8_t g_worker_key[32];
    char g_worker_fid[128] = {0};
    bool g_key_loaded = false;

    uint8_t g_bfibe_request_sk[256] = {0};
    uint32_t g_bfibe_request_sk_len = 0;
    uint8_t g_bfibe_function_sk[256] = {0};
    uint32_t g_bfibe_function_sk_len = 0;
    char g_bfibe_fid[128] = {0};
    bool g_bfibe_key_loaded = false;

    void ecall_decrypt_key(uint8_t* encrypted_key, uint8_t* decrypted_key, const char* fid) {
        enclave_print("Enclave: Decrypting received key...\n");
        
        // Unpack: KMS PubKey (64) + IV (12) + Tag (16) + Ciphertext (32)
        uint8_t* p = encrypted_key;
        sgx_ec256_public_t kms_pub;
        memcpy(&kms_pub, p, 64); p += 64;
        
        uint8_t iv[12];
        memcpy(iv, p, 12); p += 12;
        
        uint8_t tag[16];
        memcpy(tag, p, 16); p += 16;
        
        uint8_t ciphertext[32];
        memcpy(ciphertext, p, 32);
        
        // Compute Shared Secret
        sgx_status_t ret;
        sgx_ecc_state_handle_t ecc_handle;
        ret = sgx_ecc256_open_context(&ecc_handle);
        if (ret != SGX_SUCCESS) { enclave_print("Error opening ECC context\n"); return; }
        
        sgx_ec256_dh_shared_t shared_secret;
        ret = sgx_ecc256_compute_shared_dhkey(&g_private_key, &kms_pub, &shared_secret, ecc_handle);
        sgx_ecc256_close_context(ecc_handle);
        
        if (ret != SGX_SUCCESS) { enclave_print("Error computing shared secret\n"); return; }
        
        // Derive AES Key (First 16 bytes of shared secret)
        uint8_t aes_key[16];
        memcpy(aes_key, shared_secret.s, 16);
        
        // Decrypt
        uint8_t plaintext[32];
        ret = sgx_rijndael128GCM_decrypt(
            (const sgx_aes_gcm_128bit_key_t*)aes_key,
            ciphertext, 32,
            plaintext,
            iv, 12,
            NULL, 0,
            (const sgx_aes_gcm_128bit_tag_t*)tag
        );
        
        if (ret != SGX_SUCCESS) {
            enclave_print("Error decrypting key from KMS\n");
            return;
        }
        
        memcpy(g_worker_key, plaintext, 32);
        if (decrypted_key != NULL) {
            memcpy(decrypted_key, g_worker_key, 32);
        }
        
        if (!g_key_loaded || strncmp(g_worker_fid, fid, 128) != 0) {
            function_cache_clear();
        }

        // Store FID
        strncpy(g_worker_fid, fid, 128);
        g_key_loaded = true;
        
        enclave_print("Enclave: Key stored securely for FID: ");
        enclave_print(fid);
        enclave_print("\n");
    }

    // Flag to track if dklabel was received from KMS (paper-compliant path)
    bool g_dklabel_from_kms = false;
    uint8_t g_worker_dklabel[32] = {0};  // dklabel received from KMS

    // Paper-compliant key loading: receive both dkf and dklabel from KMS
    // This ensures KMS has enforced BindLabelToFID(label, FID) before releasing dklabel
    void ecall_decrypt_keys_batch(uint8_t* encrypted_dkf, uint8_t* encrypted_dklabel, const char* fid) {
        enclave_print("Enclave: Decrypting keys from KMS (batch: dkf + dklabel)...\n");
        
        // Decrypt dkf (same logic as ecall_decrypt_key)
        {
            uint8_t* p = encrypted_dkf;
            sgx_ec256_public_t kms_pub;
            memcpy(&kms_pub, p, 64); p += 64;
            
            uint8_t iv[12];
            memcpy(iv, p, 12); p += 12;
            
            uint8_t tag[16];
            memcpy(tag, p, 16); p += 16;
            
            uint8_t ciphertext[32];
            memcpy(ciphertext, p, 32);
            
            sgx_status_t ret;
            sgx_ecc_state_handle_t ecc_handle;
            ret = sgx_ecc256_open_context(&ecc_handle);
            if (ret != SGX_SUCCESS) { enclave_print("Error opening ECC context for dkf\n"); return; }
            
            sgx_ec256_dh_shared_t shared_secret;
            ret = sgx_ecc256_compute_shared_dhkey(&g_private_key, &kms_pub, &shared_secret, ecc_handle);
            sgx_ecc256_close_context(ecc_handle);
            
            if (ret != SGX_SUCCESS) { enclave_print("Error computing shared secret for dkf\n"); return; }
            
            uint8_t aes_key[16];
            memcpy(aes_key, shared_secret.s, 16);
            
            uint8_t plaintext[32];
            ret = sgx_rijndael128GCM_decrypt(
                (const sgx_aes_gcm_128bit_key_t*)aes_key,
                ciphertext, 32,
                plaintext,
                iv, 12,
                NULL, 0,
                (const sgx_aes_gcm_128bit_tag_t*)tag
            );
            
            if (ret != SGX_SUCCESS) {
                enclave_print("Error decrypting dkf from KMS\n");
                return;
            }
            
            memcpy(g_worker_key, plaintext, 32);
        }
        
        // Decrypt dklabel
        {
            uint8_t* p = encrypted_dklabel;
            sgx_ec256_public_t kms_pub;
            memcpy(&kms_pub, p, 64); p += 64;
            
            uint8_t iv[12];
            memcpy(iv, p, 12); p += 12;
            
            uint8_t tag[16];
            memcpy(tag, p, 16); p += 16;
            
            uint8_t ciphertext[32];
            memcpy(ciphertext, p, 32);
            
            sgx_status_t ret;
            sgx_ecc_state_handle_t ecc_handle;
            ret = sgx_ecc256_open_context(&ecc_handle);
            if (ret != SGX_SUCCESS) { enclave_print("Error opening ECC context for dklabel\n"); return; }
            
            sgx_ec256_dh_shared_t shared_secret;
            ret = sgx_ecc256_compute_shared_dhkey(&g_private_key, &kms_pub, &shared_secret, ecc_handle);
            sgx_ecc256_close_context(ecc_handle);
            
            if (ret != SGX_SUCCESS) { enclave_print("Error computing shared secret for dklabel\n"); return; }
            
            uint8_t aes_key[16];
            memcpy(aes_key, shared_secret.s, 16);
            
            uint8_t plaintext[32];
            ret = sgx_rijndael128GCM_decrypt(
                (const sgx_aes_gcm_128bit_key_t*)aes_key,
                ciphertext, 32,
                plaintext,
                iv, 12,
                NULL, 0,
                (const sgx_aes_gcm_128bit_tag_t*)tag
            );
            
            if (ret != SGX_SUCCESS) {
                enclave_print("Error decrypting dklabel from KMS\n");
                return;
            }
            
            memcpy(g_worker_dklabel, plaintext, 32);
            g_dklabel_from_kms = true;
        }
        
        if (!g_key_loaded || strncmp(g_worker_fid, fid, 128) != 0) {
            function_cache_clear();
        }

        // Store FID and mark keys as loaded
        strncpy(g_worker_fid, fid, 128);
        g_key_loaded = true;
        
        enclave_print("Enclave: Both dkf and dklabel loaded from KMS for FID: ");
        enclave_print(fid);
        enclave_print("\n");
        enclave_print("  Note: dklabel obtained via KMS (BindLabelToFID enforced)\n");
    }

    int ecall_has_key(const char* fid) {
        if (g_key_loaded && strncmp(g_worker_fid, fid, 128) == 0) {
            return 1;
        }
        if (g_bfibe_key_loaded && strncmp(g_bfibe_fid, fid, 128) == 0) {
            return 1;
        }
        return 0;
    }

    static const char BFIBE_KEY_RELEASE_MAGIC[] = "ASBFREL1";
    static const char BFIBE_PRIVATE_KEY_SET_MAGIC[] = "ASBFSKS1";
    static const char BFIBE_PROFILE_ID[] = "bfibe-mcl-bls12381";
    static const char BFIBE_AAD_MAGIC[] = "ASYNCS/BFIBE/KEYRELEASE/AAD/v1";
    static const uint32_t BFIBE_KEY_RELEASE_MAGIC_LEN = 8;
    static const uint8_t BFIBE_KEY_RELEASE_VERSION = 1;
    static const uint8_t BFIBE_PRIVATE_KEY_SET_VERSION = 1;

    struct BfibeReleaseView {
        const uint8_t* profile;
        uint32_t profile_len;
        const uint8_t* fid;
        uint32_t fid_len;
        const uint8_t* worker_identity;
        uint32_t worker_identity_len;
        const uint8_t* wrap_public_key;
        uint32_t wrap_public_key_len;
        const uint8_t* nonce;
        uint32_t nonce_len;
        const uint8_t* ciphertext;
        uint32_t ciphertext_len;
    };

    static void bfibe_zero(void* ptr, uint32_t len) {
        if (!ptr) return;
        volatile uint8_t* p = (volatile uint8_t*)ptr;
        while (len--) {
            *p++ = 0;
        }
    }

    static bool bytes_equal_literal(const uint8_t* data, uint32_t data_len, const char* literal) {
        uint32_t literal_len = (uint32_t)strlen(literal);
        return data_len == literal_len && memcmp(data, literal, literal_len) == 0;
    }

    static bool bytes_starts_with_literal(const uint8_t* data, uint32_t data_len, const char* literal) {
        uint32_t literal_len = (uint32_t)strlen(literal);
        return data_len >= literal_len && memcmp(data, literal, literal_len) == 0;
    }

    static bool read_u32_be(const uint8_t* data, uint32_t data_size, uint32_t* offset, uint32_t* out) {
        if (!data || !offset || !out || *offset > data_size || data_size - *offset < 4) {
            return false;
        }
        const uint8_t* p = data + *offset;
        *out = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
        *offset += 4;
        return true;
    }

    static bool take_bytes(const uint8_t* data, uint32_t data_size, uint32_t* offset, uint32_t len, const uint8_t** out) {
        if (!data || !offset || !out || *offset > data_size || len > data_size - *offset) {
            return false;
        }
        *out = data + *offset;
        *offset += len;
        return true;
    }

    static bool append_bytes_local(uint8_t* out, uint32_t capacity, uint32_t* offset, const void* data, uint32_t len) {
        if (!out || !offset || (!data && len != 0) || *offset > capacity || len > capacity - *offset) {
            return false;
        }
        if (len > 0) {
            memcpy(out + *offset, data, len);
        }
        *offset += len;
        return true;
    }

    static bool append_u32_be_local(uint8_t* out, uint32_t capacity, uint32_t* offset, uint32_t value) {
        uint8_t encoded[4];
        encoded[0] = (uint8_t)(value >> 24);
        encoded[1] = (uint8_t)(value >> 16);
        encoded[2] = (uint8_t)(value >> 8);
        encoded[3] = (uint8_t)value;
        return append_bytes_local(out, capacity, offset, encoded, sizeof(encoded));
    }

    static bool append_aad_part(uint8_t* out, uint32_t capacity, uint32_t* offset, const void* data, uint32_t len) {
        return append_u32_be_local(out, capacity, offset, len) &&
               append_bytes_local(out, capacity, offset, data, len);
    }

    static bool is_bfibe_key_release_payload(const uint8_t* release, uint32_t release_size) {
        if (!release || release_size < BFIBE_KEY_RELEASE_MAGIC_LEN + 1) return false;
        return memcmp(release, BFIBE_KEY_RELEASE_MAGIC, BFIBE_KEY_RELEASE_MAGIC_LEN) == 0 &&
               release[BFIBE_KEY_RELEASE_MAGIC_LEN] == BFIBE_KEY_RELEASE_VERSION;
    }

    static bool parse_bfibe_key_release(const uint8_t* release, uint32_t release_size, BfibeReleaseView* view) {
        if (!view || !is_bfibe_key_release_payload(release, release_size)) {
            return false;
        }
        uint32_t offset = BFIBE_KEY_RELEASE_MAGIC_LEN + 1;
        uint32_t profile_len = 0;
        uint32_t fid_len = 0;
        uint32_t worker_identity_len = 0;
        uint32_t wrap_public_key_len = 0;
        uint32_t nonce_len = 0;
        uint32_t ciphertext_len = 0;
        if (!read_u32_be(release, release_size, &offset, &profile_len) ||
            !read_u32_be(release, release_size, &offset, &fid_len) ||
            !read_u32_be(release, release_size, &offset, &worker_identity_len) ||
            !read_u32_be(release, release_size, &offset, &wrap_public_key_len) ||
            !read_u32_be(release, release_size, &offset, &nonce_len) ||
            !read_u32_be(release, release_size, &offset, &ciphertext_len)) {
            return false;
        }

        view->profile_len = profile_len;
        view->fid_len = fid_len;
        view->worker_identity_len = worker_identity_len;
        view->wrap_public_key_len = wrap_public_key_len;
        view->nonce_len = nonce_len;
        view->ciphertext_len = ciphertext_len;
        if (!take_bytes(release, release_size, &offset, profile_len, &view->profile) ||
            !take_bytes(release, release_size, &offset, fid_len, &view->fid) ||
            !take_bytes(release, release_size, &offset, worker_identity_len, &view->worker_identity) ||
            !take_bytes(release, release_size, &offset, wrap_public_key_len, &view->wrap_public_key) ||
            !take_bytes(release, release_size, &offset, nonce_len, &view->nonce) ||
            !take_bytes(release, release_size, &offset, ciphertext_len, &view->ciphertext)) {
            return false;
        }
        return offset == release_size &&
               bytes_equal_literal(view->profile, view->profile_len, BFIBE_PROFILE_ID) &&
               view->wrap_public_key_len == 64 &&
               view->nonce_len == 12 &&
               view->ciphertext_len > 16;
    }

    static bool build_bfibe_key_release_aad(const BfibeReleaseView* view, uint8_t* aad, uint32_t aad_capacity, uint32_t* aad_size) {
        if (!view || !aad || !aad_size) return false;
        uint32_t offset = 0;
        uint32_t aad_magic_len = (uint32_t)strlen(BFIBE_AAD_MAGIC);
        if (!append_bytes_local(aad, aad_capacity, &offset, BFIBE_AAD_MAGIC, aad_magic_len) ||
            !append_aad_part(aad, aad_capacity, &offset, view->profile, view->profile_len) ||
            !append_aad_part(aad, aad_capacity, &offset, view->fid, view->fid_len) ||
            !append_aad_part(aad, aad_capacity, &offset, view->worker_identity, view->worker_identity_len) ||
            !append_aad_part(aad, aad_capacity, &offset, view->wrap_public_key, view->wrap_public_key_len)) {
            return false;
        }
        *aad_size = offset;
        return true;
    }

    static bool import_bfibe_private_key_record(
        const uint8_t* purpose,
        uint32_t purpose_len,
        const uint8_t* identity,
        uint32_t identity_len,
        const uint8_t* private_key,
        uint32_t private_key_len,
        const char* fid,
        bool* found_request_key,
        bool* found_function_key
    ) {
        if (!purpose || !identity || !private_key || !fid || !found_request_key || !found_function_key) {
            return false;
        }
        if (bytes_equal_literal(purpose, purpose_len, "request-key")) {
            char expected_identity[160];
            int written = snprintf(expected_identity, sizeof(expected_identity), "fid:%s", fid);
            if (written <= 0 || (uint32_t)written >= sizeof(expected_identity)) return false;
            if (identity_len != (uint32_t)written || memcmp(identity, expected_identity, identity_len) != 0) return false;
            if (private_key_len == 0 || private_key_len > sizeof(g_bfibe_request_sk)) return false;
            memcpy(g_bfibe_request_sk, private_key, private_key_len);
            g_bfibe_request_sk_len = private_key_len;
            *found_request_key = true;
            return true;
        }
        if (bytes_equal_literal(purpose, purpose_len, "function-key")) {
            if (private_key_len == 0 || private_key_len > sizeof(g_bfibe_function_sk)) return false;
            if (!bytes_starts_with_literal(identity, identity_len, "label:")) {
                return false;
            }
            memcpy(g_bfibe_function_sk, private_key, private_key_len);
            g_bfibe_function_sk_len = private_key_len;
            *found_function_key = true;
            return true;
        }
        return false;
    }

    static bool parse_bfibe_private_key_set(const uint8_t* plaintext, uint32_t plaintext_size, const char* fid) {
        if (!plaintext || !fid || plaintext_size < 17) {
            return false;
        }
        uint32_t offset = 0;
        const uint8_t* magic = NULL;
        if (!take_bytes(plaintext, plaintext_size, &offset, 8, &magic) ||
            memcmp(magic, BFIBE_PRIVATE_KEY_SET_MAGIC, 8) != 0 ||
            plaintext[offset++] != BFIBE_PRIVATE_KEY_SET_VERSION) {
            return false;
        }

        uint32_t profile_len = 0;
        uint32_t record_count = 0;
        const uint8_t* profile = NULL;
        if (!read_u32_be(plaintext, plaintext_size, &offset, &profile_len) ||
            !read_u32_be(plaintext, plaintext_size, &offset, &record_count) ||
            !take_bytes(plaintext, plaintext_size, &offset, profile_len, &profile) ||
            !bytes_equal_literal(profile, profile_len, BFIBE_PROFILE_ID) ||
            record_count == 0) {
            return false;
        }

        bfibe_zero(g_bfibe_request_sk, sizeof(g_bfibe_request_sk));
        bfibe_zero(g_bfibe_function_sk, sizeof(g_bfibe_function_sk));
        g_bfibe_request_sk_len = 0;
        g_bfibe_function_sk_len = 0;
        bool found_request_key = false;
        bool found_function_key = false;
        for (uint32_t i = 0; i < record_count; i++) {
            uint32_t purpose_len = 0;
            uint32_t identity_len = 0;
            uint32_t private_key_len = 0;
            const uint8_t* purpose = NULL;
            const uint8_t* identity = NULL;
            const uint8_t* private_key = NULL;
            if (!read_u32_be(plaintext, plaintext_size, &offset, &purpose_len) ||
                !read_u32_be(plaintext, plaintext_size, &offset, &identity_len) ||
                !read_u32_be(plaintext, plaintext_size, &offset, &private_key_len) ||
                !take_bytes(plaintext, plaintext_size, &offset, purpose_len, &purpose) ||
                !take_bytes(plaintext, plaintext_size, &offset, identity_len, &identity) ||
                !take_bytes(plaintext, plaintext_size, &offset, private_key_len, &private_key) ||
                !import_bfibe_private_key_record(
                    purpose,
                    purpose_len,
                    identity,
                    identity_len,
                    private_key,
                    private_key_len,
                    fid,
                    &found_request_key,
                    &found_function_key
                )) {
                bfibe_zero(g_bfibe_request_sk, sizeof(g_bfibe_request_sk));
                bfibe_zero(g_bfibe_function_sk, sizeof(g_bfibe_function_sk));
                g_bfibe_request_sk_len = 0;
                g_bfibe_function_sk_len = 0;
                return false;
            }
        }
        return offset == plaintext_size && found_request_key && found_function_key;
    }

    int ecall_load_bfibe_key_release(uint8_t* release, uint32_t release_size, const char* fid) {
        if (!fid || !g_worker_keypair_ready) {
            enclave_print("Error: BF-IBE key-release requires worker keypair.\n");
            return -1;
        }

        BfibeReleaseView view;
        if (!parse_bfibe_key_release(release, release_size, &view)) {
            enclave_print("Error: Invalid BF-IBE key-release envelope.\n");
            return -1;
        }
        if (view.fid_len != strlen(fid) || memcmp(view.fid, fid, view.fid_len) != 0) {
            enclave_print("Error: BF-IBE key-release FID mismatch.\n");
            return -1;
        }

        uint8_t aad[256];
        uint32_t aad_size = 0;
        if (!build_bfibe_key_release_aad(&view, aad, sizeof(aad), &aad_size)) {
            enclave_print("Error: BF-IBE key-release AAD build failed.\n");
            return -1;
        }

        sgx_status_t ret;
        sgx_ecc_state_handle_t ecc_handle;
        ret = sgx_ecc256_open_context(&ecc_handle);
        if (ret != SGX_SUCCESS) {
            enclave_print("Error: BF-IBE key-release ECC context failed.\n");
            return -1;
        }
        sgx_ec256_public_t kms_pub;
        memcpy(&kms_pub, view.wrap_public_key, 64);
        sgx_ec256_dh_shared_t shared_secret;
        ret = sgx_ecc256_compute_shared_dhkey(&g_private_key, &kms_pub, &shared_secret, ecc_handle);
        sgx_ecc256_close_context(ecc_handle);
        if (ret != SGX_SUCCESS) {
            enclave_print("Error: BF-IBE key-release shared secret failed.\n");
            return -1;
        }

        uint32_t encrypted_len = view.ciphertext_len - 16;
        const uint8_t* tag = view.ciphertext + encrypted_len;
        uint8_t* plaintext = (uint8_t*)malloc(encrypted_len);
        if (!plaintext) {
            return -1;
        }
        uint8_t aes_key[16];
        memcpy(aes_key, shared_secret.s, sizeof(aes_key));
        ret = sgx_rijndael128GCM_decrypt(
            (const sgx_aes_gcm_128bit_key_t*)aes_key,
            view.ciphertext,
            encrypted_len,
            plaintext,
            view.nonce,
            view.nonce_len,
            aad,
            aad_size,
            (const sgx_aes_gcm_128bit_tag_t*)tag
        );
        bfibe_zero(aes_key, sizeof(aes_key));
        bfibe_zero(&shared_secret, sizeof(shared_secret));
        if (ret != SGX_SUCCESS) {
            bfibe_zero(plaintext, encrypted_len);
            free(plaintext);
            enclave_print("Error: BF-IBE key-release decrypt failed.\n");
            return -1;
        }

        bool imported = parse_bfibe_private_key_set(plaintext, encrypted_len, fid);
        bfibe_zero(plaintext, encrypted_len);
        free(plaintext);
        if (!imported) {
            enclave_print("Error: BF-IBE private-key set import failed.\n");
            return -1;
        }

        if (!g_bfibe_key_loaded || strncmp(g_bfibe_fid, fid, 128) != 0) {
            function_cache_clear();
        }
        strncpy(g_bfibe_fid, fid, 127);
        g_bfibe_fid[127] = '\0';
        g_bfibe_key_loaded = true;
        enclave_print("BF-IBE key-release imported successfully.\n");
        return 0;
    }

    // Per-invocation bounded capture buffer. The untrusted caller selects the
    // capacity, and the enclave enforces ASYNCS_MAX_OUTPUT_CAPACITY_BYTES.
    uint8_t* global_output_buffer = NULL;
    uint32_t global_output_capacity = 0;
    uint32_t global_output_pos = 0;
    bool capture_output = false;
    bool capture_output_overflow = false;

    int enclave_print(const char *message) {
        if (capture_output) {
            size_t len = strlen(message);
            if (global_output_buffer != NULL &&
                global_output_pos + len <= global_output_capacity) {
                memcpy(global_output_buffer + global_output_pos, message, len);
                global_output_pos += len;
            } else {
                capture_output_overflow = true;
            }
            return 0;
        }
        ocall_print(message);
        return 0;
    }
}

// Forward declarations for globals defined later in this file.
extern uint8_t g_dklabel_func[32];
extern bool g_dklabel_func_valid;
int ecall_zeroize_label_key();
void secure_zeroize(void* ptr, size_t len);

// ============================================================================
// Protocol(A): DecKey-only capabilities + session keys
// ============================================================================
// Paper semantics:
//   dkf is used only in DecKey(dkf, C_key) -> k_req
//   dklabelfunc is used only in DecKey(dklabelfunc, C_k_func) -> k_func
//   AEAD uses only k_req/k_func/k_U (never dkf/dklabelfunc directly)
//
// This demo code does not yet plumb explicit (C_key, C_k_func) buffers through
// the legacy encrypted invocation ABI. To preserve the "never use dkf as AEAD
// key" security property, we model DecKey as a deterministic key-derivation
// step over (capability || ciphertext-bytes).

static bool sha256_concat(const uint8_t* a, uint32_t a_len,
                          const uint8_t* b, uint32_t b_len,
                          uint8_t out32[32]) {
    uint32_t total = a_len + b_len;
    uint8_t* buf = (uint8_t*)malloc(total);
    if (!buf) return false;
    memcpy(buf, a, a_len);
    memcpy(buf + a_len, b, b_len);
    sgx_sha256_hash_t hash;
    sgx_status_t ret = sgx_sha256_msg(buf, total, &hash);
    free(buf);
    if (ret != SGX_SUCCESS) return false;
    memcpy(out32, hash, 32);
    return true;
}

// Protocol(B): RID := H(FID || C_req), computed locally in enclave.
// - FID comes from enclave state (g_worker_fid) established when key is loaded.
// - C_req is the encrypted request bytes as received from the untrusted control plane.
//   In this enclave ABI, C_req is provided as (iv, tag, ciphertext) split across params;
//   we reconstruct the on-the-wire C_req bytes as nonce||tag||ciphertext.
static bool compute_rid_from_fid_and_c_req(const char* fid,
                                           const uint8_t* c_req,
                                           uint32_t c_req_len,
                                           uint8_t rid32[32]) {
    if (!fid || !c_req) return false;
    sgx_sha256_hash_t hash;

    // Canonical encoding:
    // - If FID is a 64-hex SHA-256 digest, treat it as 32 raw bytes.
    // - Otherwise, fall back to hashing the UTF-8 string bytes (legacy/tests).
    auto hex_nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };

    uint8_t fid_bytes32[32];
    size_t fid_len = strnlen(fid, 128);
    bool fid_is_hex32 = (fid_len == 64);
    if (fid_is_hex32) {
        for (size_t i = 0; i < 32; i++) {
            int hi = hex_nibble(fid[i * 2]);
            int lo = hex_nibble(fid[i * 2 + 1]);
            if (hi < 0 || lo < 0) {
                fid_is_hex32 = false;
                break;
            }
            fid_bytes32[i] = (uint8_t)((hi << 4) | lo);
        }
    }

    const uint8_t* fid_prefix = fid_is_hex32 ? fid_bytes32 : (const uint8_t*)fid;
    uint32_t fid_prefix_len = fid_is_hex32 ? 32u : (uint32_t)fid_len;

    uint32_t total = fid_prefix_len + c_req_len;
    uint8_t* buf = (uint8_t*)malloc(total);
    if (!buf) return false;
    memcpy(buf, fid_prefix, fid_prefix_len);
    memcpy(buf + fid_prefix_len, c_req, c_req_len);

    sgx_status_t ret = sgx_sha256_msg(buf, total, &hash);
    free(buf);
    if (ret != SGX_SUCCESS) return false;
    memcpy(rid32, hash, 32);
    return true;
}

static void print_hex_prefixed(const char* prefix, const uint8_t* data, uint32_t len) {
    enclave_print(prefix);
    char byte_hex[3];
    byte_hex[2] = '\0';
    for (uint32_t i = 0; i < len; i++) {
        snprintf(byte_hex, sizeof(byte_hex), "%02x", data[i]);
        enclave_print(byte_hex);
    }
    enclave_print("\n");
}

// Derive a stable label = H(C_func) from the encrypted wasm package bytes.
static bool compute_label_from_cfunc(const uint8_t* c_func, uint32_t c_func_len, uint8_t label32[32]) {
    sgx_sha256_hash_t hash;
    sgx_status_t ret = sgx_sha256_msg(c_func, c_func_len, &hash);
    if (ret != SGX_SUCCESS) return false;
    memcpy(label32, hash, 32);
    return true;
}

struct CachedFunctionCode {
    bool valid;
    char fid[129];
    uint8_t cfunc_hash[32];
    uint8_t* wasm;
    uint32_t wasm_size;
};

static CachedFunctionCode g_cached_function_code = {false, {0}, {0}, NULL, 0};

static void function_cache_clear() {
    if (g_cached_function_code.wasm) {
        secure_zeroize(g_cached_function_code.wasm, g_cached_function_code.wasm_size);
        free(g_cached_function_code.wasm);
    }
    memset(g_cached_function_code.fid, 0, sizeof(g_cached_function_code.fid));
    secure_zeroize(g_cached_function_code.cfunc_hash, sizeof(g_cached_function_code.cfunc_hash));
    g_cached_function_code.wasm = NULL;
    g_cached_function_code.wasm_size = 0;
    g_cached_function_code.valid = false;
}

static bool function_cache_lookup(const char* fid,
                                  const uint8_t cfunc_hash[32],
                                  uint8_t** wasm_out,
                                  uint32_t* wasm_size_out) {
    if (!fid || !cfunc_hash || !wasm_out || !wasm_size_out) return false;
    if (!g_cached_function_code.valid || !g_cached_function_code.wasm) return false;
    if (strncmp(g_cached_function_code.fid, fid, 128) != 0) return false;
    if (memcmp(g_cached_function_code.cfunc_hash, cfunc_hash, 32) != 0) return false;
    *wasm_out = g_cached_function_code.wasm;
    *wasm_size_out = g_cached_function_code.wasm_size;
    return true;
}

static bool function_cache_store(const char* fid,
                                 const uint8_t cfunc_hash[32],
                                 const uint8_t* wasm,
                                 uint32_t wasm_size) {
    if (!fid || !cfunc_hash || !wasm || wasm_size == 0) return false;

    uint8_t* wasm_copy = (uint8_t*)malloc(wasm_size);
    if (!wasm_copy) return false;
    memcpy(wasm_copy, wasm, wasm_size);

    function_cache_clear();
    strncpy(g_cached_function_code.fid, fid, 128);
    g_cached_function_code.fid[128] = '\0';
    memcpy(g_cached_function_code.cfunc_hash, cfunc_hash, 32);
    g_cached_function_code.wasm = wasm_copy;
    g_cached_function_code.wasm_size = wasm_size;
    g_cached_function_code.valid = true;
    return true;
}

// Legacy: derive a label-scoped capability locally.
// Preferred (paper): KMS derives and releases dklabel = H(MSK || label) with BindLabelToFID enforcement.
// This local derivation is kept for backwards-compatibility with existing repo wiring and will be removed
// once dklabel is plumbed end-to-end (closure gap follow-up).
static bool derive_dklabelfunc(const uint8_t dkf[32], const uint8_t label32[32], uint8_t dklabelfunc32[32]) {
    const uint8_t domain[] = {'D','K','L','A','B','E','L'};
    uint8_t tmp[32];
    if (!sha256_concat(dkf, 32, label32, 32, tmp)) return false;
    return sha256_concat(tmp, 32, domain, (uint32_t)sizeof(domain), dklabelfunc32);
}

// DecKey(cap, C_key/C_k_func) -> session_key
//
// G3 alignment:
// - dkf/dklabelfunc are treated as DecKey-only capabilities.
// - DecKey consumes explicit key ciphertexts (C_key/C_k_func), not arbitrary payload ciphertext bytes.
//
// IC1 alignment (interop):
// - Capabilities are 32-byte scalars (dkf, dklabel) released by KMS.
// - Key ciphertexts are ECIES-style blobs produced by the SDK's ECCIBE implementation.
//
// KeyCiphertextV1 encoding model for (C_key / C_k_func) in this repo:
//   C = EphemeralPK(65) || iv12 || tag16 || ct
// Where EphemeralPK is uncompressed P-256 point (0x04||X||Y), and ct is 16 or 32 bytes.
static const char BFIBE_ENVELOPE_MAGIC[] = "ASBFIBE1";
static const char BFIBE_KEY_ENVELOPE_AAD_MAGIC[] = "ASYNCS/BFIBE/AAD/v1";
static const uint32_t BFIBE_ENVELOPE_MAGIC_LEN = 8;
static const uint8_t BFIBE_ENVELOPE_VERSION = 1;

struct BfibeKeyEnvelopeView {
    const uint8_t* profile;
    uint32_t profile_len;
    const uint8_t* purpose;
    uint32_t purpose_len;
    const uint8_t* identity;
    uint32_t identity_len;
    const uint8_t* aad_context;
    uint32_t aad_context_len;
    const uint8_t* c1;
    uint32_t c1_len;
    const uint8_t* nonce;
    uint32_t nonce_len;
    const uint8_t* ciphertext;
    uint32_t ciphertext_len;
};

static bool is_bfibe_envelope(const uint8_t* c, uint32_t c_len) {
    if (!c || c_len < BFIBE_ENVELOPE_MAGIC_LEN + 1) return false;
    return memcmp(c, BFIBE_ENVELOPE_MAGIC, BFIBE_ENVELOPE_MAGIC_LEN) == 0 &&
           c[BFIBE_ENVELOPE_MAGIC_LEN] == BFIBE_ENVELOPE_VERSION;
}

static bool parse_bfibe_envelope(const uint8_t* c, uint32_t c_len, BfibeKeyEnvelopeView* view) {
    if (!view || !is_bfibe_envelope(c, c_len)) {
        return false;
    }

    uint32_t offset = BFIBE_ENVELOPE_MAGIC_LEN + 1;
    uint32_t profile_len = 0;
    uint32_t purpose_len = 0;
    uint32_t identity_len = 0;
    uint32_t aad_context_len = 0;
    uint32_t c1_len = 0;
    uint32_t nonce_len = 0;
    uint32_t ciphertext_len = 0;
    if (!read_u32_be(c, c_len, &offset, &profile_len) ||
        !read_u32_be(c, c_len, &offset, &purpose_len) ||
        !read_u32_be(c, c_len, &offset, &identity_len) ||
        !read_u32_be(c, c_len, &offset, &aad_context_len) ||
        !read_u32_be(c, c_len, &offset, &c1_len) ||
        !read_u32_be(c, c_len, &offset, &nonce_len) ||
        !read_u32_be(c, c_len, &offset, &ciphertext_len)) {
        return false;
    }

    view->profile_len = profile_len;
    view->purpose_len = purpose_len;
    view->identity_len = identity_len;
    view->aad_context_len = aad_context_len;
    view->c1_len = c1_len;
    view->nonce_len = nonce_len;
    view->ciphertext_len = ciphertext_len;
    if (!take_bytes(c, c_len, &offset, profile_len, &view->profile) ||
        !take_bytes(c, c_len, &offset, purpose_len, &view->purpose) ||
        !take_bytes(c, c_len, &offset, identity_len, &view->identity) ||
        !take_bytes(c, c_len, &offset, aad_context_len, &view->aad_context) ||
        !take_bytes(c, c_len, &offset, c1_len, &view->c1) ||
        !take_bytes(c, c_len, &offset, nonce_len, &view->nonce) ||
        !take_bytes(c, c_len, &offset, ciphertext_len, &view->ciphertext)) {
        return false;
    }

    bool valid_purpose =
        bytes_equal_literal(view->purpose, view->purpose_len, "request-key") ||
        bytes_equal_literal(view->purpose, view->purpose_len, "function-key");
    return offset == c_len &&
           bytes_equal_literal(view->profile, view->profile_len, BFIBE_PROFILE_ID) &&
           valid_purpose &&
           view->identity_len > 0 &&
           view->c1_len > 0 &&
           view->nonce_len == 12 &&
           view->ciphertext_len > 16;
}

static bool build_bfibe_envelope_aad(const BfibeKeyEnvelopeView* view, uint8_t* aad, uint32_t aad_capacity, uint32_t* aad_size) {
    if (!view || !aad || !aad_size) return false;
    uint32_t offset = 0;
    uint32_t aad_magic_len = (uint32_t)strlen(BFIBE_KEY_ENVELOPE_AAD_MAGIC);
    if (!append_bytes_local(aad, aad_capacity, &offset, BFIBE_KEY_ENVELOPE_AAD_MAGIC, aad_magic_len) ||
        !append_aad_part(aad, aad_capacity, &offset, view->profile, view->profile_len) ||
        !append_aad_part(aad, aad_capacity, &offset, view->purpose, view->purpose_len) ||
        !append_aad_part(aad, aad_capacity, &offset, view->identity, view->identity_len) ||
        !append_aad_part(aad, aad_capacity, &offset, view->aad_context, view->aad_context_len)) {
        return false;
    }
    *aad_size = offset;
    return true;
}

static bool DecKey(const uint8_t cap32[32],
                   const uint8_t* c,
                   uint32_t c_len,
                   const uint8_t* domain,
                   uint32_t domain_len,
                   uint8_t key_out32[32]) {
    if (!c || !key_out32 || !domain) return false;
    if (is_bfibe_envelope(c, c_len)) {
        if (!g_bfibe_key_loaded) {
            enclave_print("Error: BF-IBE key envelope requires imported BF private keys.\n");
            return false;
        }

        BfibeKeyEnvelopeView view;
        if (!parse_bfibe_envelope(c, c_len, &view)) {
            enclave_print("Error: Invalid BF-IBE key envelope.\n");
            return false;
        }
        if (view.aad_context_len != domain_len ||
            memcmp(view.aad_context, domain, domain_len) != 0) {
            enclave_print("Error: BF-IBE key envelope AAD context mismatch.\n");
            return false;
        }

        const uint8_t* sk_id = NULL;
        uint32_t sk_id_len = 0;
        if (bytes_equal_literal(view.purpose, view.purpose_len, "request-key")) {
            char expected_identity[160];
            int written = snprintf(expected_identity, sizeof(expected_identity), "fid:%s", g_bfibe_fid);
            if (written <= 0 || (uint32_t)written >= sizeof(expected_identity)) return false;
            if (view.identity_len != (uint32_t)written ||
                memcmp(view.identity, expected_identity, view.identity_len) != 0) {
                enclave_print("Error: BF-IBE request-key identity mismatch.\n");
                return false;
            }
            sk_id = g_bfibe_request_sk;
            sk_id_len = g_bfibe_request_sk_len;
        } else if (bytes_equal_literal(view.purpose, view.purpose_len, "function-key")) {
            if (!bytes_starts_with_literal(view.identity, view.identity_len, "label:")) {
                enclave_print("Error: BF-IBE function-key identity mismatch.\n");
                return false;
            }
            sk_id = g_bfibe_function_sk;
            sk_id_len = g_bfibe_function_sk_len;
        } else {
            return false;
        }

        if (!sk_id || sk_id_len == 0) {
            enclave_print("Error: BF-IBE private key cache is empty.\n");
            return false;
        }

        uint8_t aad[512];
        uint32_t aad_size = 0;
        if (!build_bfibe_envelope_aad(&view, aad, sizeof(aad), &aad_size)) {
            enclave_print("Error: BF-IBE key envelope AAD build failed.\n");
            return false;
        }

        uint8_t bfibe_key_out[32] = {0};
        int decrypt_ret = bfibe_mcl_decrypt_key_envelope(
            sk_id,
            sk_id_len,
            view.c1,
            view.c1_len,
            view.nonce,
            view.nonce_len,
            view.ciphertext,
            view.ciphertext_len,
            aad,
            aad_size,
            bfibe_key_out
        );
        bfibe_zero(aad, sizeof(aad));
        if (decrypt_ret != 0) {
            secure_zeroize(bfibe_key_out, sizeof(bfibe_key_out));
            enclave_print("Error: BF-IBE key envelope decrypt failed.\n");
            return false;
        }

        memcpy(key_out32, bfibe_key_out, 32);
        secure_zeroize(bfibe_key_out, sizeof(bfibe_key_out));
        return true;
    }
    if (!cap32) return false;
    if (c_len < 65 + 12 + 16 + 16) return false;

    const uint8_t* epk65 = c;
    const uint8_t* iv12 = c + 65;
    const uint8_t* tag16 = c + 65 + 12;
    const uint8_t* ct = c + 65 + 12 + 16;
    uint32_t ct_len = c_len - (65 + 12 + 16);
    if (!(ct_len == 16 || ct_len == 32)) return false;

    // Compute shared secret: SS = ECDH(cap32, EphemeralPK)
    if (epk65[0] != 0x04) return false;

    auto reverse32 = [](const uint8_t* in, uint8_t* out) {
        for (int i = 0; i < 32; i++) out[i] = in[31 - i];
    };

    sgx_ecc_state_handle_t ecc_handle;
    sgx_status_t ret = sgx_ecc256_open_context(&ecc_handle);
    if (ret != SGX_SUCCESS) return false;

    sgx_ec256_private_t priv;
    // SGX expects little-endian scalar; crypto_lib ECCIBE derives scalar as SHA256(msk||id) bytes.
    memcpy(priv.r, cap32, 32);

    sgx_ec256_public_t pub;
    // SGX expects coordinates in little-endian arrays.
    reverse32(epk65 + 1, pub.gx);
    reverse32(epk65 + 33, pub.gy);

    sgx_ec256_dh_shared_t shared_secret;
    ret = sgx_ecc256_compute_shared_dhkey(&priv, &pub, &shared_secret, ecc_handle);
    sgx_ecc256_close_context(ecc_handle);
    secure_zeroize(&priv, sizeof(priv));
    if (ret != SGX_SUCCESS) return false;

    // Derive AES-128 key from shared secret.
    // Must match crypto_lib ECCIBE: SHA256(SS || "ECC-IBE-ENC")[:16]
    const uint8_t info[] = {'E','C','C','-','I','B','E','-','E','N','C'};
    uint8_t ss_info32[32];
    if (!sha256_concat(shared_secret.s, 32, info, (uint32_t)sizeof(info), ss_info32)) {
        secure_zeroize(&shared_secret, sizeof(shared_secret));
        return false;
    }
    secure_zeroize(&shared_secret, sizeof(shared_secret));

    uint8_t k_dec_128[16];
    memcpy(k_dec_128, ss_info32, 16);
    secure_zeroize(ss_info32, sizeof(ss_info32));

    uint8_t out_buf[32] = {0};
    ret = sgx_rijndael128GCM_decrypt(
        (const sgx_aes_gcm_128bit_key_t*)k_dec_128,
        ct,
        ct_len,
        out_buf,
        iv12,
        12,
        NULL,
        0,
        (const sgx_aes_gcm_128bit_tag_t*)tag16
    );
    secure_zeroize(k_dec_128, sizeof(k_dec_128));
    if (ret != SGX_SUCCESS) {
        secure_zeroize(out_buf, sizeof(out_buf));
        return false;
    }

    memset(key_out32, 0, 32);
    memcpy(key_out32, out_buf, ct_len);
    secure_zeroize(out_buf, sizeof(out_buf));
    return true;
}

static bool request_uses_bfibe_key_ciphertexts(const uint8_t* c_k_func,
                                               uint32_t c_k_func_size,
                                               const uint8_t* c_key,
                                               uint32_t c_key_size) {
    return is_bfibe_envelope(c_key, c_key_size) ||
           is_bfibe_envelope(c_k_func, c_k_func_size);
}

// ============================================================================
// Protocol(A): Strict AAD construction helpers
// ============================================================================
// Canonical encoding:
// - If FID is a 64-hex SHA-256 digest, treat it as 32 raw bytes.
// - Otherwise, fall back to UTF-8 string bytes (legacy/tests).
static bool fid_to_bytes_or_str(const char* fid,
                                const uint8_t** out_ptr,
                                uint32_t* out_len,
                                uint8_t out_bytes32[32]) {
    if (!fid || !out_ptr || !out_len) return false;

    auto hex_nibble = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    };

    size_t fid_len = strnlen(fid, 128);
    bool fid_is_hex32 = (fid_len == 64);
    if (fid_is_hex32) {
        for (size_t i = 0; i < 32; i++) {
            int hi = hex_nibble(fid[i * 2]);
            int lo = hex_nibble(fid[i * 2 + 1]);
            if (hi < 0 || lo < 0) {
                fid_is_hex32 = false;
                break;
            }
            out_bytes32[i] = (uint8_t)((hi << 4) | lo);
        }
    }

    if (fid_is_hex32) {
        *out_ptr = out_bytes32;
        *out_len = 32;
    } else {
        *out_ptr = (const uint8_t*)fid;
        *out_len = (uint32_t)fid_len;
    }
    return true;
}

static bool sha256_bytes(const uint8_t* data, uint32_t len, uint8_t out32[32]) {
    sgx_sha256_hash_t hash;
    sgx_status_t ret = sgx_sha256_msg(data, len, &hash);
    if (ret != SGX_SUCCESS) return false;
    memcpy(out32, hash, 32);
    return true;
}

static bool build_aad_pkg(const char* fid, uint8_t** aad, uint32_t* aad_len) {
    const uint8_t prefix[] = {'P','K','G'};
    const uint8_t* fid_ptr = NULL;
    uint32_t fid_len = 0;
    uint8_t fid_bytes32[32];
    if (!fid_to_bytes_or_str(fid, &fid_ptr, &fid_len, fid_bytes32)) return false;

    *aad_len = (uint32_t)sizeof(prefix) + fid_len;
    *aad = (uint8_t*)malloc(*aad_len);
    if (!*aad) return false;
    memcpy(*aad, prefix, sizeof(prefix));
    memcpy(*aad + sizeof(prefix), fid_ptr, fid_len);
    return true;
}

static bool build_aad_req(const char* fid, const uint8_t nonce16[16], const uint8_t pkU65[65],
                          uint8_t** aad, uint32_t* aad_len) {
    const uint8_t prefix[] = {'R','E','Q'};
    const uint8_t* fid_ptr = NULL;
    uint32_t fid_len = 0;
    uint8_t fid_bytes32[32];
    if (!fid_to_bytes_or_str(fid, &fid_ptr, &fid_len, fid_bytes32)) return false;

    uint8_t h_pkU[32];
    if (!sha256_bytes(pkU65, 65, h_pkU)) return false;

    *aad_len = (uint32_t)sizeof(prefix) + fid_len + 16 + 32;
    *aad = (uint8_t*)malloc(*aad_len);
    if (!*aad) return false;

    uint32_t off = 0;
    memcpy(*aad + off, prefix, sizeof(prefix)); off += (uint32_t)sizeof(prefix);
    memcpy(*aad + off, fid_ptr, fid_len); off += fid_len;
    memcpy(*aad + off, nonce16, 16); off += 16;
    memcpy(*aad + off, h_pkU, 32);
    return true;
}

static bool build_aad_out(const char* fid, const uint8_t rid32[32], const uint8_t pkU65[65],
                          uint8_t** aad, uint32_t* aad_len) {
    const uint8_t prefix[] = {'O','U','T'};
    const uint8_t* fid_ptr = NULL;
    uint32_t fid_len = 0;
    uint8_t fid_bytes32[32];
    if (!fid_to_bytes_or_str(fid, &fid_ptr, &fid_len, fid_bytes32)) return false;

    uint8_t h_pkU[32];
    if (!sha256_bytes(pkU65, 65, h_pkU)) return false;

    *aad_len = (uint32_t)sizeof(prefix) + fid_len + 32 + 32;
    *aad = (uint8_t*)malloc(*aad_len);
    if (!*aad) return false;

    uint32_t off = 0;
    memcpy(*aad + off, prefix, sizeof(prefix)); off += (uint32_t)sizeof(prefix);
    memcpy(*aad + off, fid_ptr, fid_len); off += fid_len;
    memcpy(*aad + off, rid32, 32); off += 32;
    memcpy(*aad + off, h_pkU, 32);
    return true;
}

void ecall_init() {
    enclave_print("Inside ecall_init...\n");
    os_set_print_function(enclave_print);

    RuntimeInitArgs init_args;
    memset(&init_args, 0, sizeof(RuntimeInitArgs));

    init_args.mem_alloc_type = Alloc_With_System_Allocator;
    init_args.native_module_name = "env";
    init_args.native_symbols = c1_native_symbols;
    init_args.n_native_symbols = sizeof(c1_native_symbols) / sizeof(NativeSymbol);
    // init_args.mem_alloc_option.pool.heap_buf = NULL; // Use default
    // init_args.mem_alloc_option.pool.heap_size = 0; // Use default

    if (!wasm_runtime_full_init(&init_args)) {
        enclave_print("Init runtime failed.\n");
        return;
    }
    enclave_print("WAMR initialized inside Enclave.\n");
}

bool run_wasm_helper(
    uint8_t* wasm_buffer,
    uint32_t wasm_size,
    char* input_str,
    c1_asyncs_invoke_trace_t* invoke_trace
) {
    char error_buf[128];
    wasm_module_t module = NULL;
    wasm_module_inst_t module_inst = NULL;
    wasm_exec_env_t exec_env = NULL;
    uint8_t* wasm_copy = NULL;
    char *argv[] = { (char*)"wasm_app", input_str };
    int argc = (input_str != NULL) ? 2 : 1;

    if (!wasm_buffer || wasm_size == 0) {
        enclave_print("Load module failed.\n");
        enclave_print("empty wasm buffer");
        return false;
    }

    wasm_copy = (uint8_t*)malloc(wasm_size);
    if (!wasm_copy) {
        enclave_print("Load module failed.\n");
        enclave_print("malloc failed for wasm copy");
        return false;
    }
    memcpy(wasm_copy, wasm_buffer, wasm_size);

    if (invoke_trace != NULL) {
        invoke_trace->wasm_load_begin_cycles = c1_tsc_begin_read();
    }
    module = wasm_runtime_load(wasm_copy, wasm_size, error_buf, sizeof(error_buf));
    if (!module) {
        enclave_print("Load module failed.\n");
        enclave_print(error_buf);
        free(wasm_copy);
        return false;
    }
    if (invoke_trace != NULL) {
        invoke_trace->wasm_load_end_cycles = c1_tsc_end_read();
        invoke_trace->wasm_load_cycles =
            invoke_trace->wasm_load_end_cycles - invoke_trace->wasm_load_begin_cycles;
        invoke_trace->flags |= C2_TRACE_WASM_LOAD_CYCLES_VALID;
    }

    wasm_runtime_set_wasi_args(module, NULL, 0, NULL, 0, NULL, 0, argv, argc);

    if (invoke_trace != NULL) {
        invoke_trace->wasm_instantiate_begin_cycles = c1_tsc_begin_read();
    }
    module_inst = wasm_runtime_instantiate(module, 16384, 16384, error_buf, sizeof(error_buf));
    if (!module_inst) {
        enclave_print("Instantiate module failed. Error: ");
        enclave_print(error_buf);
        enclave_print("\n");
        wasm_runtime_unload(module);
        free(wasm_copy);
        return false;
    }
    if (invoke_trace != NULL) {
        invoke_trace->wasm_instantiate_end_cycles = c1_tsc_end_read();
        invoke_trace->wasm_instantiate_cycles =
            invoke_trace->wasm_instantiate_end_cycles -
            invoke_trace->wasm_instantiate_begin_cycles;
        invoke_trace->flags |= C2_TRACE_WASM_INSTANTIATE_CYCLES_VALID;
    }

    exec_env = wasm_runtime_create_exec_env(module_inst, 8192);
    if (!exec_env) {
        enclave_print("Create exec env failed.\n");
        wasm_runtime_deinstantiate(module_inst);
        wasm_runtime_unload(module);
        free(wasm_copy);
        return false;
    }

    capture_output = true;
    capture_output_overflow = false;
    global_output_pos = 0;
    if (global_output_buffer == NULL || global_output_capacity == 0) {
        capture_output = false;
        enclave_print("WASM output capture buffer is not prepared.\n");
        wasm_runtime_destroy_exec_env(exec_env);
        wasm_runtime_deinstantiate(module_inst);
        wasm_runtime_unload(module);
        free(wasm_copy);
        return false;
    }
    memset(global_output_buffer, 0, (size_t)global_output_capacity + 1);
    g_workload_tsc_begin = 0;
    g_workload_tsc_end = 0;
    g_workload_tsc_begin_valid = false;
    g_workload_tsc_end_valid = false;
    bool execute_ok = wasm_application_execute_main(module_inst, argc, argv);
    capture_output = false;

    if (!execute_ok) {
        enclave_print("Execute main failed.\n");
    }

    wasm_runtime_destroy_exec_env(exec_env);
    wasm_runtime_deinstantiate(module_inst);
    wasm_runtime_unload(module);
    free(wasm_copy);
    if (capture_output_overflow) {
        enclave_print("WASM output exceeded enclave capture buffer.\n");
        return false;
    }
    return execute_ok;
}

void ecall_run_wasm(uint8_t* wasm_buffer, uint32_t wasm_size) {
    if (!output_capture_prepare(4096)) {
        enclave_print("Failed to prepare default WASM output buffer.\n");
        return;
    }
    run_wasm_helper(wasm_buffer, wasm_size, NULL, NULL);
    output_capture_release();
}

void ecall_run_encrypted_wasm(
    uint8_t* encrypted_wasm,
    uint32_t wasm_size,
    uint8_t* encrypted_input,
    uint32_t input_size,
    uint8_t* c_k_func,
    uint32_t c_k_func_size,
    uint8_t* c_key,
    uint32_t c_key_size,
    uint8_t* nonce,
    uint8_t* pkU,
    uint8_t* encrypted_result,
    uint32_t max_out_size,
    uint32_t* result_size,
    uint8_t* result_tag,
    uint8_t* result_iv,
    uint8_t* wasm_iv,
    uint8_t* wasm_mac,
    uint8_t* input_iv,
    uint8_t* input_mac
) {
    sgx_status_t ret;
    bool wasm_decrypted = false;
    bool input_decrypted = false;
    bool function_cache_hit = false;
    bool cfunc_decrypt_executed = false;
    uint8_t label32[32] = {0};
    uint8_t dklabelfunc32[32] = {0};
    uint8_t k_func32[32] = {0};
    uint8_t k_req32[32] = {0};
    uint8_t k_func_128[16] = {0};
    uint8_t k_req_128[16] = {0};
    uint8_t* function_wasm = NULL;
    uint32_t function_wasm_size = 0;
    uint8_t* decrypted_wasm = NULL;
    uint8_t* decrypted_input = NULL;
    uint8_t* aad_pkg = NULL;
    uint32_t aad_pkg_len = 0;
    uint8_t* aad_req = NULL;
    uint32_t aad_req_len = 0;
    uint8_t* aad_out = NULL;
    uint32_t aad_out_len = 0;
    char* input_b64 = NULL;
    int wasm_ok = 0;

    const bool use_bfibe_keys = request_uses_bfibe_key_ciphertexts(
        c_k_func,
        c_k_func_size,
        c_key,
        c_key_size
    );
    if (!use_bfibe_keys && !g_key_loaded) {
        enclave_print("Error: Key not loaded in Enclave.\n");
        return;
    }
    if (use_bfibe_keys && !g_bfibe_key_loaded) {
        enclave_print("Error: BF-IBE key not loaded in Enclave.\n");
        return;
    }
    const char* invocation_fid = use_bfibe_keys ? g_bfibe_fid : g_worker_fid;

    // Protocol(B): Compute RID locally from (FID, C_req) and emit it for the untrusted invoker.
    // This is used as the retrieval key and must not depend on any control-plane-provided RID.
    uint8_t* c_req_full = (uint8_t*)malloc(12 + 16 + input_size);
    if (!c_req_full) {
        enclave_print("Error: malloc failed for C_req reconstruction.\n");
        return;
    }
    memcpy(c_req_full, input_iv, 12);
    memcpy(c_req_full + 12, input_mac, 16);
    memcpy(c_req_full + 28, encrypted_input, input_size);
    uint8_t rid32[32];
    if (compute_rid_from_fid_and_c_req(invocation_fid, c_req_full, 28 + input_size, rid32)) {
        print_hex_prefixed("RID_HEX:", rid32, 32);
    } else {
        enclave_print("Error: RID computation failed.\n");
    }
    free(c_req_full);

    // Protocol(A): Build strict AAD values.
    if (!build_aad_pkg(invocation_fid, &aad_pkg, &aad_pkg_len) ||
        !build_aad_req(invocation_fid, nonce, pkU, &aad_req, &aad_req_len) ||
        !build_aad_out(invocation_fid, rid32, pkU, &aad_out, &aad_out_len)) {
        enclave_print("Error: Failed to build AAD values.\n");
        goto cleanup;
    }

    // Protocol(A): Derive per-function/per-request AEAD keys via DecKey.
    // - dkf (g_worker_key) is NOT used directly in AEAD.
    // - dklabelfunc (g_dklabel_func) is NOT used directly in AEAD.
    //
    // Paper-compliant path:
    //   dklabel is obtained from KMS (via ecall_decrypt_keys_batch), which enforced
    //   BindLabelToFID(label, FID) before release.
    //
    // Legacy path (fallback):
    //   dklabelfunc is derived locally from dkf. This bypasses KMS's BindLabelToFID
    //   enforcement and should be deprecated for production use.
    //
    if (!compute_label_from_cfunc(encrypted_wasm, wasm_size, label32)) {
        enclave_print("Error: Failed to compute C_func label.\n");
        goto cleanup;
    }
    function_cache_hit = function_cache_lookup(invocation_fid, label32, &function_wasm, &function_wasm_size);

    if (!c_key || c_key_size == 0 || (!function_cache_hit && (!c_k_func || c_k_func_size == 0))) {
        enclave_print("Error: Missing C_key or cold-path C_k_func buffer (G3).\n");
        goto cleanup;
    }

    if (!function_cache_hit) {
        if (use_bfibe_keys) {
            // BF-IBE DecKey consumes the C_k_func envelope and imported
            // label identity key directly, so there is no legacy dklabel scalar.
            memset(dklabelfunc32, 0, sizeof(dklabelfunc32));
        } else if (g_dklabel_from_kms) {
            // Paper-compliant: use dklabel obtained from KMS
            enclave_print("Using dklabel from KMS (BindLabelToFID enforced).\n");
            memcpy(dklabelfunc32, g_worker_dklabel, 32);
        } else {
            // Legacy fallback: derive locally (KMS BindLabelToFID not enforced on this path)
            enclave_print("WARNING: Using legacy local dklabel derivation (BindLabelToFID not enforced).\n");
            if (!derive_dklabelfunc(g_worker_key, label32, dklabelfunc32)) {
                enclave_print("Error: Failed to derive dklabelfunc.\n");
                goto cleanup;
            }
        }

        // Cache dklabelfunc to enable post-load zeroization feature.
        memcpy(g_dklabel_func, dklabelfunc32, 32);
        g_dklabel_func_valid = true;
    }

    // Protocol(A): DecKey(dklabelfunc, C_k_func) -> k_func on cold load;
    // DecKey(dkf, C_key) -> k_req on every request.
    {
        const uint8_t dom_ckfunc[] = {'C','_','K','_','F','U','N','C'};
        const uint8_t dom_ckey[] = {'C','_','K','E','Y'};
        if (use_bfibe_keys) {
            if (!DecKey(NULL, c_key, c_key_size, aad_req, aad_req_len, k_req32)) {
                enclave_print("Error: DecKey(C_key) failed.\n");
                goto cleanup;
            }
            if (!function_cache_hit &&
                !DecKey(NULL, c_k_func, c_k_func_size, aad_pkg, aad_pkg_len, k_func32)) {
                enclave_print("Error: DecKey(C_k_func) failed.\n");
                goto cleanup;
            }
        } else if (!DecKey(g_worker_key, c_key, c_key_size, dom_ckey,
                           (uint32_t)sizeof(dom_ckey), k_req32)) {
            enclave_print("Error: DecKey(C_key) failed.\n");
            goto cleanup;
        } else if (!function_cache_hit &&
                   !DecKey(g_dklabel_func, c_k_func, c_k_func_size, dom_ckfunc,
                           (uint32_t)sizeof(dom_ckfunc), k_func32)) {
            enclave_print("Error: DecKey(C_k_func) failed.\n");
            goto cleanup;
        }
    }

    // Protocol(C): Zeroize dklabelfunc immediately after DecKey(dklabelfunc, C_k_func).
    if (!function_cache_hit) {
        ecall_zeroize_label_key();
        secure_zeroize(dklabelfunc32, sizeof(dklabelfunc32));
        memcpy(k_func_128, k_func32, 16);
    }

    memcpy(k_req_128, k_req32, 16);

    if (!function_cache_hit) {
        // Decrypt WASM on cold function-code load.
        decrypted_wasm = (uint8_t*)malloc(wasm_size);
        if (decrypted_wasm == NULL) {
            enclave_print("Malloc failed for decrypted wasm.\n");
            goto cleanup;
        }

        enclave_print("Debugging Decryption:\n");
        char debug_buf[128];
        if (!use_bfibe_keys) {
            snprintf(debug_buf, 128, "Key: %02x%02x%02x%02x...\n", g_worker_key[0], g_worker_key[1], g_worker_key[2], g_worker_key[3]);
            enclave_print(debug_buf);
        }
        snprintf(debug_buf, 128, "IV: %02x%02x%02x%02x...\n", wasm_iv[0], wasm_iv[1], wasm_iv[2], wasm_iv[3]);
        enclave_print(debug_buf);
        snprintf(debug_buf, 128, "Tag: %02x%02x%02x%02x...\n", wasm_mac[0], wasm_mac[1], wasm_mac[2], wasm_mac[3]);
        enclave_print(debug_buf);
        snprintf(debug_buf, 128, "CT: %02x%02x%02x%02x...\n", encrypted_wasm[0], encrypted_wasm[1], encrypted_wasm[2], encrypted_wasm[3]);
        enclave_print(debug_buf);

        uint8_t local_iv[12];
        uint8_t local_mac[16];
        memcpy(local_iv, wasm_iv, 12);
        memcpy(local_mac, wasm_mac, 16);

        // Use only first 16 bytes of k_func for AES-128-GCM.
        // sgx_rijndael128GCM_decrypt only supports 128-bit keys.
    
        cfunc_decrypt_executed = true;
        ret = sgx_rijndael128GCM_decrypt(
            (const sgx_aes_gcm_128bit_key_t*)k_func_128,
            encrypted_wasm,
            wasm_size,
            decrypted_wasm,
            local_iv,
            12,
            aad_pkg,
            aad_pkg_len,
            (const sgx_aes_gcm_128bit_tag_t*)local_mac
        );

        if (ret != SGX_SUCCESS) {
            char buf[64];
            snprintf(buf, 64, "WASM Decryption failed. Error: 0x%x\n", ret);
            enclave_print(buf);
            goto cleanup;
        }
        wasm_decrypted = true;
        enclave_print("Decryption succeeded. Running WASM...\n");

        // Protocol(C): Discard k_func after decrypting C_func (function code).
        secure_zeroize(k_func_128, sizeof(k_func_128));
        secure_zeroize(k_func32, sizeof(k_func32));

        if (function_cache_store(invocation_fid, label32, decrypted_wasm, wasm_size)) {
            function_wasm = g_cached_function_code.wasm;
            function_wasm_size = g_cached_function_code.wasm_size;
            secure_zeroize(decrypted_wasm, wasm_size);
            free(decrypted_wasm);
            decrypted_wasm = NULL;
            wasm_decrypted = false;
        } else {
            function_wasm = decrypted_wasm;
            function_wasm_size = wasm_size;
        }
    }

    // Decrypt Input
    if (input_size > 0) {
        decrypted_input = (uint8_t*)malloc(input_size + 1);
        if (decrypted_input == NULL) {
            enclave_print("Malloc failed for decrypted input.\n");
            goto cleanup;
        }
        
        ret = sgx_rijndael128GCM_decrypt(
            (const sgx_aes_gcm_128bit_key_t*)k_req_128,
            encrypted_input,
            input_size,
            decrypted_input,
            input_iv,
            12,
            aad_req,
            aad_req_len,
            (const sgx_aes_gcm_128bit_tag_t*)input_mac
        );
        if (ret != SGX_SUCCESS) {
            enclave_print("Input Decryption failed.\n");
            goto cleanup;
        }
        decrypted_input[input_size] = '\0';
        enclave_print("Input Decryption succeeded.\n");
    }
    input_decrypted = true;

    trace_e3_payload_consumed(decrypted_input, input_size);

    char function_cache_trace[192];
    snprintf(function_cache_trace, sizeof(function_cache_trace),
             "ACSC_TRACE_FUNCTION_CACHE:function_cache_hit=%d cfunc_decrypt_executed=%d function_cache_bytes=%u\n",
             function_cache_hit ? 1 : 0,
             cfunc_decrypt_executed ? 1 : 0,
             function_wasm_size);
    enclave_print(function_cache_trace);

    // Base64 encode input to avoid null-byte truncation in C string argv
    if (decrypted_input != NULL && input_size > 0) {
        input_b64 = base64_encode(decrypted_input, input_size);
    }
    if (!output_capture_prepare(max_out_size)) {
        enclave_print("Invalid or unavailable output capacity.\n");
        goto cleanup;
    }
    wasm_ok = run_wasm_helper(function_wasm, function_wasm_size, input_b64, NULL) ? 1 : 0;
    if (input_b64) {
        secure_zeroize(input_b64, strlen(input_b64));
        free(input_b64);
        input_b64 = NULL;
    }

    if (!wasm_ok) {
        goto cleanup;
    }

    // Encrypt result
    if (global_output_pos > max_out_size) {
        enclave_print("Output buffer too small.\n");
        goto cleanup;
    }

    // Generate random IV
    sgx_read_rand(result_iv, 12);

    ret = sgx_rijndael128GCM_encrypt(
        (const sgx_aes_gcm_128bit_key_t*)k_req_128,
        (const uint8_t*)global_output_buffer,
        global_output_pos,
        encrypted_result,
        result_iv,
        12,
        aad_out,
        aad_out_len,
        (sgx_aes_gcm_128bit_tag_t*)result_tag
    );

    if (ret != SGX_SUCCESS) {
        enclave_print("Result encryption failed.\n");
        goto cleanup;
    }

    *result_size = global_output_pos;
    enclave_print("Result encrypted successfully.\n");
cleanup:
    // Best-effort cleanup and key zeroization on all paths.
    ecall_zeroize_label_key();

    if (aad_pkg) free(aad_pkg);
    if (aad_req) free(aad_req);
    if (aad_out) free(aad_out);

    if (decrypted_input) {
        if (input_decrypted) secure_zeroize(decrypted_input, input_size + 1);
        free(decrypted_input);
    }

    if (decrypted_wasm) {
        if (wasm_decrypted) secure_zeroize(decrypted_wasm, wasm_size);
        free(decrypted_wasm);
    }

    // This legacy ABI uses k_req for both input decryption and output encryption; clear at end.
    secure_zeroize(k_func_128, sizeof(k_func_128));
    secure_zeroize(k_func32, sizeof(k_func32));
    secure_zeroize(k_req_128, sizeof(k_req_128));
    secure_zeroize(k_req32, sizeof(k_req32));
    secure_zeroize(dklabelfunc32, sizeof(dklabelfunc32));
    secure_zeroize(label32, sizeof(label32));
    output_capture_release();
}

// KEM Encapsulation using ECDH
// Input: pkU (65 bytes: 04 || X || Y)
// Output: ct (65 bytes: ephemeral public key), key (32 bytes: derived key)
int ecall_kem_encap(uint8_t* pkU, uint8_t* ct_out, uint8_t* key_out) {
    sgx_status_t ret;
    sgx_ecc_state_handle_t ecc_handle;
    
    // Parse pkU (format: 04 || X(32 BE) || Y(32 BE))
    if (pkU[0] != 0x04) {
        enclave_print("KEM: Invalid pkU format (expected 0x04 prefix)\n");
        return -1;
    }
    
    sgx_ec256_public_t client_pk;
    // SGX ECC types use little-endian coordinate bytes; convert from big-endian wire format.
    for (int i = 0; i < 32; i++) {
        client_pk.gx[i] = pkU[1 + (31 - i)];
        client_pk.gy[i] = pkU[33 + (31 - i)];
    }
    
    // Generate ephemeral key pair
    ret = sgx_ecc256_open_context(&ecc_handle);
    if (ret != SGX_SUCCESS) {
        enclave_print("KEM: Failed to open ECC context\n");
        return -1;
    }
    
    sgx_ec256_private_t eph_sk;
    sgx_ec256_public_t eph_pk;
    ret = sgx_ecc256_create_key_pair(&eph_sk, &eph_pk, ecc_handle);
    if (ret != SGX_SUCCESS) {
        sgx_ecc256_close_context(ecc_handle);
        enclave_print("KEM: Failed to generate ephemeral key\n");
        return -1;
    }
    
    // Compute shared secret via ECDH
    sgx_ec256_dh_shared_t shared_secret;
    ret = sgx_ecc256_compute_shared_dhkey(&eph_sk, &client_pk, &shared_secret, ecc_handle);
    sgx_ecc256_close_context(ecc_handle);
    
    if (ret != SGX_SUCCESS) {
        enclave_print("KEM: Failed to compute shared secret\n");
        return -1;
    }
    
    // Output ct = ephemeral public key (04 || X(32 BE) || Y(32 BE))
    ct_out[0] = 0x04;
    for (int i = 0; i < 32; i++) {
        ct_out[1 + i] = eph_pk.gx[31 - i];
        ct_out[33 + i] = eph_pk.gy[31 - i];
    }
    
    // Derive key from shared secret using SHA256.
    // Keep the SGX-native byte order (little-endian) to match client-side KEM derivation.
    sgx_sha256_hash_t hash;
    ret = sgx_sha256_msg(shared_secret.s, 32, &hash);
    if (ret != SGX_SUCCESS) {
        enclave_print("KEM: Failed to derive key\n");
        return -1;
    }
    memcpy(key_out, hash, 32);
    
    return 0;
}

// Run encrypted WASM with KEM for result encryption
void ecall_run_encrypted_wasm_kem(
    uint8_t* encrypted_wasm,
    uint32_t wasm_size,
    uint8_t* encrypted_input,
    uint32_t input_size,
    uint8_t* c_k_func,
    uint32_t c_k_func_size,
    uint8_t* c_key,
    uint32_t c_key_size,
    uint8_t* nonce,
    uint8_t* pkU,
    uint8_t* encrypted_result,
    uint32_t max_out_size,
    uint32_t* result_size,
    uint8_t* result_tag,
    uint8_t* result_iv,
    uint8_t* kem_ct,
    c1_asyncs_invoke_trace_t* invoke_trace,
    uint8_t* wasm_iv,
    uint8_t* wasm_mac,
    uint8_t* input_iv,
    uint8_t* input_mac
) {
    sgx_status_t ret;
    bool wasm_decrypted = false;
    bool input_decrypted = false;
    bool kem_derived = false;
    bool function_cache_hit = false;
    bool cfunc_decrypt_executed = false;
    uint8_t label32[32] = {0};
    uint8_t dklabelfunc32[32] = {0};
    uint8_t k_func32[32] = {0};
    uint8_t k_req32[32] = {0};
    uint8_t k_func_128[16] = {0};
    uint8_t k_req_128[16] = {0};
    uint8_t k_U[32] = {0};
    uint8_t k_U_128[16] = {0};
    uint8_t* function_wasm = NULL;
    uint32_t function_wasm_size = 0;
    uint8_t* decrypted_wasm = NULL;
    uint8_t* decrypted_input = NULL;
    uint8_t* aad_pkg = NULL;
    uint32_t aad_pkg_len = 0;
    uint8_t* aad_req = NULL;
    uint32_t aad_req_len = 0;
    uint8_t* aad_out = NULL;
    uint32_t aad_out_len = 0;
    int kem_ret = -1;
    char* input_b64 = NULL;
    int wasm_ok = 0;
    uint64_t phase_begin_cycles = 0;
    uint64_t phase_end_cycles = 0;

    if (invoke_trace == NULL) {
        enclave_print("Error: Missing bounded invocation trace output.\n");
        return;
    }
    memset(invoke_trace, 0, sizeof(*invoke_trace));
    invoke_trace->version = C1_ASYNCS_TRACE_VERSION;
    const bool use_bfibe_keys = request_uses_bfibe_key_ciphertexts(
        c_k_func,
        c_k_func_size,
        c_key,
        c_key_size
    );
    if (!use_bfibe_keys && !g_key_loaded) {
        enclave_print("Error: Key not loaded in Enclave.\n");
        return;
    }
    if (use_bfibe_keys && !g_bfibe_key_loaded) {
        enclave_print("Error: BF-IBE key not loaded in Enclave.\n");
        return;
    }
    const char* invocation_fid = use_bfibe_keys ? g_bfibe_fid : g_worker_fid;

    // Protocol(B): Compute RID locally from (FID, C_req) and return it in the
    // same ECALL. The untrusted App emits the existing RID marker afterwards.
    uint8_t* c_req_full = (uint8_t*)malloc(12 + 16 + input_size);
    if (!c_req_full) {
        enclave_print("Error: malloc failed for C_req reconstruction.\n");
        return;
    }
    memcpy(c_req_full, input_iv, 12);
    memcpy(c_req_full + 12, input_mac, 16);
    memcpy(c_req_full + 28, encrypted_input, input_size);
    uint8_t rid32[32];
    if (compute_rid_from_fid_and_c_req(invocation_fid, c_req_full, 28 + input_size, rid32)) {
        memcpy(invoke_trace->rid, rid32, sizeof(rid32));
        invoke_trace->flags |= C1_TRACE_RID_VALID;
    } else {
        enclave_print("Error: RID computation failed.\n");
        free(c_req_full);
        goto cleanup;
    }
    free(c_req_full);

    if (!build_aad_pkg(invocation_fid, &aad_pkg, &aad_pkg_len) ||
        !build_aad_req(invocation_fid, nonce, pkU, &aad_req, &aad_req_len) ||
        !build_aad_out(invocation_fid, rid32, pkU, &aad_out, &aad_out_len)) {
        enclave_print("Error: Failed to build AAD values.\n");
        goto cleanup;
    }

    if (!compute_label_from_cfunc(encrypted_wasm, wasm_size, label32)) {
        enclave_print("Error: Failed to compute C_func label.\n");
        goto cleanup;
    }
    function_cache_hit = function_cache_lookup(invocation_fid, label32, &function_wasm, &function_wasm_size);

    if (!c_key || c_key_size == 0 || (!function_cache_hit && (!c_k_func || c_k_func_size == 0))) {
        enclave_print("Error: Missing C_key or cold-path C_k_func buffer (G3).\n");
        goto cleanup;
    }

    // Protocol(A): Derive per-function/per-request AEAD keys via DecKey.
    // Paper-compliant path: use dklabel from KMS if available.
    if (!function_cache_hit) {
        if (use_bfibe_keys) {
            // BF-IBE DecKey consumes the C_k_func envelope and imported
            // label identity key directly, so there is no legacy dklabel scalar.
            memset(dklabelfunc32, 0, sizeof(dklabelfunc32));
        } else if (g_dklabel_from_kms) {
            enclave_print("Using dklabel from KMS (BindLabelToFID enforced).\n");
            memcpy(dklabelfunc32, g_worker_dklabel, 32);
        } else {
            enclave_print("WARNING: Using legacy local dklabel derivation (BindLabelToFID not enforced).\n");
            if (!derive_dklabelfunc(g_worker_key, label32, dklabelfunc32)) {
                enclave_print("Error: Failed to derive dklabelfunc.\n");
                goto cleanup;
            }
        }

        memcpy(g_dklabel_func, dklabelfunc32, 32);
        g_dklabel_func_valid = true;
    }

    // Record the per-request key decapsulation separately from the conditional
    // cold function-key path. C3 uses these same-ECALL TSC boundaries directly.
    {
        const uint8_t dom_ckfunc[] = {'C','_','K','_','F','U','N','C'};
        const uint8_t dom_ckey[] = {'C','_','K','E','Y'};
        invoke_trace->input_key_decap_begin_cycles = c1_tsc_begin_read();
        if (use_bfibe_keys) {
            if (!DecKey(NULL, c_key, c_key_size, aad_req, aad_req_len, k_req32)) {
                enclave_print("Error: DecKey(C_key) failed.\n");
                goto cleanup;
            }
        } else if (!DecKey(g_worker_key, c_key, c_key_size, dom_ckey,
                           (uint32_t)sizeof(dom_ckey), k_req32)) {
            enclave_print("Error: DecKey(C_key) failed.\n");
            goto cleanup;
        }
        invoke_trace->input_key_decap_end_cycles = c1_tsc_end_read();
        invoke_trace->input_key_decap_cycles =
            invoke_trace->input_key_decap_end_cycles -
            invoke_trace->input_key_decap_begin_cycles;
        invoke_trace->flags |= C3_TRACE_INPUT_KEY_CYCLES_VALID;

        if (!function_cache_hit) {
            invoke_trace->function_key_decap_begin_cycles = c1_tsc_begin_read();
            if (use_bfibe_keys) {
                if (!DecKey(NULL, c_k_func, c_k_func_size, aad_pkg, aad_pkg_len, k_func32)) {
                    enclave_print("Error: DecKey(C_k_func) failed.\n");
                    goto cleanup;
                }
            } else if (!DecKey(g_dklabel_func, c_k_func, c_k_func_size, dom_ckfunc,
                               (uint32_t)sizeof(dom_ckfunc), k_func32)) {
                enclave_print("Error: DecKey(C_k_func) failed.\n");
                goto cleanup;
            }
            invoke_trace->function_key_decap_end_cycles = c1_tsc_end_read();
            invoke_trace->function_key_decap_cycles =
                invoke_trace->function_key_decap_end_cycles -
                invoke_trace->function_key_decap_begin_cycles;
            invoke_trace->flags |= C2_TRACE_FUNCTION_KEY_CYCLES_VALID;
        }
    }

    // Protocol(C): Zeroize dklabelfunc immediately after deriving k_func.
    if (!function_cache_hit) {
        ecall_zeroize_label_key();
        secure_zeroize(dklabelfunc32, sizeof(dklabelfunc32));
        memcpy(k_func_128, k_func32, 16);
    }

    memcpy(k_req_128, k_req32, 16);

    if (!function_cache_hit) {
        // Decrypt WASM on cold function-code load.
        decrypted_wasm = (uint8_t*)malloc(wasm_size);
        if (decrypted_wasm == NULL) {
            enclave_print("Malloc failed for decrypted wasm.\n");
            goto cleanup;
        }

        cfunc_decrypt_executed = true;
        invoke_trace->cfunc_aes_gcm_begin_cycles = c1_tsc_begin_read();
        ret = sgx_rijndael128GCM_decrypt(
            (const sgx_aes_gcm_128bit_key_t*)k_func_128,
            encrypted_wasm,
            wasm_size,
            decrypted_wasm,
            wasm_iv,
            12,
            aad_pkg,
            aad_pkg_len,
            (const sgx_aes_gcm_128bit_tag_t*)wasm_mac
        );
        invoke_trace->cfunc_aes_gcm_end_cycles = c1_tsc_end_read();

        if (ret != SGX_SUCCESS) {
            char buf[64];
            snprintf(buf, 64, "WASM Decryption failed. Error: 0x%x\n", ret);
            enclave_print(buf);
            goto cleanup;
        }
        invoke_trace->cfunc_aes_gcm_cycles =
            invoke_trace->cfunc_aes_gcm_end_cycles -
            invoke_trace->cfunc_aes_gcm_begin_cycles;
        invoke_trace->flags |= C2_TRACE_CFUNC_AES_GCM_CYCLES_VALID;
        wasm_decrypted = true;
        // Protocol(C): Discard k_func after decrypting C_func (function code).
        secure_zeroize(k_func_128, sizeof(k_func_128));
        secure_zeroize(k_func32, sizeof(k_func32));

        if (function_cache_store(invocation_fid, label32, decrypted_wasm, wasm_size)) {
            function_wasm = g_cached_function_code.wasm;
            function_wasm_size = g_cached_function_code.wasm_size;
            secure_zeroize(decrypted_wasm, wasm_size);
            free(decrypted_wasm);
            decrypted_wasm = NULL;
            wasm_decrypted = false;
        } else {
            function_wasm = decrypted_wasm;
            function_wasm_size = wasm_size;
        }
    }

    // Decrypt the application input and preserve direct same-ECALL boundaries.
    if (input_size > 0) {
        decrypted_input = (uint8_t*)malloc(input_size + 1);
        if (decrypted_input == NULL) {
            enclave_print("Malloc failed for decrypted input.\n");
            goto cleanup;
        }

        invoke_trace->input_aes_gcm_begin_cycles = c1_tsc_begin_read();
        ret = sgx_rijndael128GCM_decrypt(
            (const sgx_aes_gcm_128bit_key_t*)k_req_128,
            encrypted_input,
            input_size,
            decrypted_input,
            input_iv,
            12,
            aad_req,
            aad_req_len,
            (const sgx_aes_gcm_128bit_tag_t*)input_mac
        );
        invoke_trace->input_aes_gcm_end_cycles = c1_tsc_end_read();

        if (ret != SGX_SUCCESS) {
            enclave_print("Input Decryption failed.\n");
            goto cleanup;
        }
        decrypted_input[input_size] = '\0';
        invoke_trace->input_aes_gcm_cycles =
            invoke_trace->input_aes_gcm_end_cycles -
            invoke_trace->input_aes_gcm_begin_cycles;
        invoke_trace->flags |= C3_TRACE_INPUT_AES_GCM_CYCLES_VALID;
    }
    input_decrypted = true;
    if (!capture_e3_payload_evidence(decrypted_input, input_size, invoke_trace)) {
        enclave_print("Error: Failed to capture payload evidence.\n");
        goto cleanup;
    }

    // Protocol(C): Discard k_req immediately after decrypting C_req.
    secure_zeroize(k_req_128, sizeof(k_req_128));
    secure_zeroize(k_req32, sizeof(k_req32));

    invoke_trace->function_cache_bytes = function_wasm_size;
    invoke_trace->flags |= C1_TRACE_FUNCTION_CACHE_VALID;
    if (function_cache_hit) {
        invoke_trace->flags |= C1_TRACE_FUNCTION_CACHE_HIT;
    }
    if (cfunc_decrypt_executed) {
        invoke_trace->flags |= C1_TRACE_CFUNC_DECRYPT_EXECUTED;
    }

    // Base64 encode input to avoid null-byte truncation in C string argv
    if (decrypted_input != NULL && input_size > 0) {
        input_b64 = base64_encode(decrypted_input, input_size);
    }
    if (!output_capture_prepare(max_out_size)) {
        enclave_print("Invalid or unavailable output capacity.\n");
        goto cleanup;
    }
    wasm_ok = run_wasm_helper(function_wasm, function_wasm_size, input_b64, invoke_trace) ? 1 : 0;
    if (input_b64) {
        secure_zeroize(input_b64, strlen(input_b64));
        free(input_b64);
        input_b64 = NULL;
    }

    if (!wasm_ok) {
        goto cleanup;
    }
    if (!g_workload_tsc_begin_valid || !g_workload_tsc_end_valid ||
        g_workload_tsc_end < g_workload_tsc_begin) {
        enclave_print("Error: Workload did not provide valid enclave TSC boundaries.\n");
        goto cleanup;
    }
    invoke_trace->workload_begin_cycles = g_workload_tsc_begin;
    invoke_trace->workload_end_cycles = g_workload_tsc_end;
    invoke_trace->workload_core_cycles = g_workload_tsc_end - g_workload_tsc_begin;
    invoke_trace->flags |= C1_TRACE_WORKLOAD_CYCLES_VALID;

    // Perform KEM encapsulation to get k_U
    phase_begin_cycles = c1_tsc_begin_read();
    kem_ret = ecall_kem_encap(pkU, kem_ct, k_U);
    phase_end_cycles = c1_tsc_end_read();
    if (kem_ret != 0) {
        enclave_print("KEM encapsulation failed.\n");
        goto cleanup;
    }
    invoke_trace->output_kem_begin_cycles = phase_begin_cycles;
    invoke_trace->output_kem_end_cycles = phase_end_cycles;
    invoke_trace->output_kem_cycles = phase_end_cycles - phase_begin_cycles;
    invoke_trace->flags |= C1_TRACE_OUTPUT_KEM_CYCLES_VALID;
    kem_derived = true;

    // Encrypt result with k_U (using first 16 bytes for AES-128-GCM)
    memcpy(k_U_128, k_U, 16);
    if (global_output_pos > max_out_size) {
        enclave_print("Output buffer too small.\n");
        goto cleanup;
    }

    // Generate random IV
    sgx_read_rand(result_iv, 12);

    phase_begin_cycles = c1_tsc_begin_read();
    ret = sgx_rijndael128GCM_encrypt(
        (const sgx_aes_gcm_128bit_key_t*)k_U_128,  // Use KEM-derived key (AES-128-GCM)
        (const uint8_t*)global_output_buffer,
        global_output_pos,
        encrypted_result,
        result_iv,
        12,
        aad_out,
        aad_out_len,
        (sgx_aes_gcm_128bit_tag_t*)result_tag
    );
    phase_end_cycles = c1_tsc_end_read();

    if (ret != SGX_SUCCESS) {
        enclave_print("Result encryption with KEM key failed.\n");
        goto cleanup;
    }
    invoke_trace->output_aes_gcm_begin_cycles = phase_begin_cycles;
    invoke_trace->output_aes_gcm_end_cycles = phase_end_cycles;
    invoke_trace->output_aes_gcm_cycles = phase_end_cycles - phase_begin_cycles;
    invoke_trace->flags |= C1_TRACE_OUTPUT_AES_GCM_CYCLES_VALID;

    *result_size = global_output_pos;
    invoke_trace->flags |= C1_TRACE_SUCCESS;

cleanup:
    // Best-effort cleanup and key zeroization on all paths.
    ecall_zeroize_label_key();

    if (aad_pkg) free(aad_pkg);
    if (aad_req) free(aad_req);
    if (aad_out) free(aad_out);

    if (decrypted_input) {
        if (input_decrypted) secure_zeroize(decrypted_input, input_size + 1);
        free(decrypted_input);
    }

    if (decrypted_wasm) {
        if (wasm_decrypted) secure_zeroize(decrypted_wasm, wasm_size);
        free(decrypted_wasm);
    }

    if (kem_derived) {
        // Protocol(C): Discard k_U after encrypting C_out.
        secure_zeroize(k_U_128, sizeof(k_U_128));
        secure_zeroize(k_U, sizeof(k_U));
    }

    secure_zeroize(k_func_128, sizeof(k_func_128));
    secure_zeroize(k_func32, sizeof(k_func32));
    secure_zeroize(k_req_128, sizeof(k_req_128));
    secure_zeroize(k_req32, sizeof(k_req32));
    secure_zeroize(dklabelfunc32, sizeof(dklabelfunc32));
    secure_zeroize(label32, sizeof(label32));
    output_capture_release();
}

// ============================================================================
// SECURE MEMORY ZEROIZATION
// ============================================================================
// Use volatile pointer to prevent compiler optimization of the memset.
// This ensures the memory is actually cleared even if the compiler thinks
// the buffer is no longer used.

// Secure zeroization function - immune to compiler optimization
void secure_zeroize(void* ptr, size_t len) {
    volatile unsigned char* p = (volatile unsigned char*)ptr;
    while (len--) {
        *p++ = 0;
    }
}

// ============================================================================
// LABEL-DERIVED KEY (dklabel_func) MANAGEMENT
// ============================================================================
// dklabel_func is the label-derived key used during function load phase.
// Per security best practice, it should be zeroized after use to minimize
// exposure window. If function needs to be reloaded (e.g., after scale-to-zero),
// the key will be re-requested from KMS.

// Storage for label-derived key (dklabel_func)
// This key is used to decrypt C_k_func -> k_func during function load
uint8_t g_dklabel_func[32] = {0};
bool g_dklabel_func_valid = false;

// Per-invocation context that should be cleaned after each invocation
struct InvocationContext {
    uint8_t request_key[32];      // Per-request derived key (if any)
    uint8_t intermediate_data[64]; // Any intermediate sensitive data
    bool has_data;
} g_invocation_ctx = {{0}, {0}, false};

// ============================================================================

// Clean up per-invocation sensitive state
// Called after each invocation completes
void ecall_clean_ctx() {
    enclave_print("Cleaning per-invocation context...\n");
    
    // Zeroize per-invocation request key
    secure_zeroize(g_invocation_ctx.request_key, sizeof(g_invocation_ctx.request_key));
    
    // Zeroize intermediate buffers
    secure_zeroize(g_invocation_ctx.intermediate_data, sizeof(g_invocation_ctx.intermediate_data));
    
    // The per-invocation output buffer is normally released by the run ECALL.
    // Release it here as a best-effort cleanup if an earlier path retained it.
    output_capture_release();
    
    g_invocation_ctx.has_data = false;
    
    enclave_print("Context cleaned successfully.\n");
}

// Zeroize dklabel_func (label-derived key) after function load
// Security best practice: Minimizes exposure window
int ecall_zeroize_label_key() {
    if (!g_dklabel_func_valid) {
        return 0;  // Not an error - key may not have been loaded
    }

    // Use secure zeroization to prevent compiler optimization
    secure_zeroize(g_dklabel_func, sizeof(g_dklabel_func));
    g_dklabel_func_valid = false;

    return 0;
}

int ecall_mcl_ibe_test() {
    enclave_print("=== Trusted MCL BF-IBE Enclave Test ===\n");

    uint8_t mpk[256] = {0};
    size_t mpk_len = sizeof(mpk);
    uint8_t msk[64] = {0};
    size_t msk_len = sizeof(msk);
    uint8_t sk_id[256] = {0};
    size_t sk_id_len = sizeof(sk_id);
    uint8_t ciphertext[512] = {0};
    size_t ciphertext_len = sizeof(ciphertext);
    uint8_t plaintext_out[64] = {0};
    size_t plaintext_out_len = sizeof(plaintext_out);

    const char identity[] = "bfibe-smoke-identity";
    const uint8_t plaintext[] = {
        0x41, 0x53, 0x59, 0x4e, 0x43, 0x53, 0x2d, 0x42,
        0x46, 0x49, 0x42, 0x45, 0x2d, 0x4f, 0x4b
    };

    if (mcl_ibe_setup(mpk, &mpk_len, msk, &msk_len) != 0) {
        enclave_print("MCL IBE: setup failed\n");
        return -1;
    }
    if (mcl_ibe_extract(msk, msk_len, identity, strlen(identity), sk_id, &sk_id_len) != 0) {
        enclave_print("MCL IBE: extract failed\n");
        return -1;
    }
    if (mcl_ibe_encrypt(
            mpk,
            mpk_len,
            identity,
            strlen(identity),
            plaintext,
            sizeof(plaintext),
            ciphertext,
            &ciphertext_len) != 0) {
        enclave_print("MCL IBE: encrypt failed\n");
        return -1;
    }
    if (mcl_ibe_decrypt(
            sk_id,
            sk_id_len,
            ciphertext,
            ciphertext_len,
            plaintext_out,
            &plaintext_out_len) != 0) {
        enclave_print("MCL IBE: decrypt failed\n");
        return -1;
    }
    if (plaintext_out_len != sizeof(plaintext) ||
        memcmp(plaintext_out, plaintext, sizeof(plaintext)) != 0) {
        enclave_print("MCL IBE: roundtrip plaintext mismatch\n");
        return -1;
    }

    enclave_print("MCL IBE: Enclave roundtrip OK\n");
    return 0;
}
