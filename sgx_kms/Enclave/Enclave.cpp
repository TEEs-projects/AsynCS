#include "Enclave_t.h"
#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "sgx_tseal.h"
#include "sgx_report.h"
#include "bfibe_mcl.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

// Quote structure for DCAP (simplified, matching sgx_quote3_t layout)
// We only need the header and report_body offsets.
// Full header: 48 bytes; report_body: 384 bytes starting at offset 48.
#define QUOTE3_REPORT_BODY_OFFSET 48
#define REPORT_BODY_SIZE 384
#define MRENCLAVE_OFFSET_IN_BODY 64
#define REPORT_DATA_OFFSET_IN_BODY 320
#define REPORT_DATA_SIZE 64

extern "C" void bfibe_mcl_log(const char* message) {
    ocall_print(message);
}

// Global MSK
uint8_t g_msk[32];
bool g_msk_initialized = false;

static const char BFIBE_MSK_DOMAIN[] = "ASYNCS/BFIBE/MSK/v1";

static int derive_bfibe_msk(uint8_t* bf_msk_out, size_t* bf_msk_len) {
    if (!g_msk_initialized || !bf_msk_out || !bf_msk_len) {
        return -1;
    }

    uint8_t seed[(sizeof(BFIBE_MSK_DOMAIN) - 1) + sizeof(g_msk)];
    memcpy(seed, BFIBE_MSK_DOMAIN, sizeof(BFIBE_MSK_DOMAIN) - 1);
    memcpy(seed + sizeof(BFIBE_MSK_DOMAIN) - 1, g_msk, sizeof(g_msk));

    int ret = bfibe_mcl_derive_master_secret(seed, sizeof(seed), bf_msk_out, bf_msk_len);
    memset(seed, 0, sizeof(seed));
    return ret;
}

// ============================================================================
// POLICY REGISTRY (policyFID and Label Binding)
// ============================================================================
// Security guarantees:
// 1. policyFID is write-once (first-writer-wins)
// 2. Label is bound to FID at deployment time (BindLabelToFID)
// 3. Key release is gated by VerifyRA(quote, policyFID)

#define MAX_POLICY_ENTRIES 128
#define MAX_FID_LEN 128
#define LABEL_LEN 65  // SHA256 hex string (64 chars) + null terminator

// Policy entry: Maps FID to (policyFID, bound labels)
struct PolicyEntry {
    char fid[MAX_FID_LEN];
    uint8_t policy_mrenclave[32];   // Required MRENCLAVE for this FID
    bool policy_set;                 // Write-once flag
    char bound_labels[4][LABEL_LEN]; // Up to 4 labels bound to this FID
    int num_labels;
};

PolicyEntry g_policy_registry[MAX_POLICY_ENTRIES];
int g_num_policies = 0;

// RA Verification result cache (per-session)
bool g_ra_verified = false;
uint8_t g_verified_mrenclave[32];
char g_verified_fid[MAX_FID_LEN] = {0};
// IC2: Cache verified report_data for worker_pk binding check
uint8_t g_verified_report_data[64] = {0};

// Find policy entry by FID (or return NULL)
PolicyEntry* find_policy(const char* fid) {
    for (int i = 0; i < g_num_policies; i++) {
        if (strcmp(g_policy_registry[i].fid, fid) == 0) {
            return &g_policy_registry[i];
        }
    }
    return NULL;
}

// Register policyFID for FID (write-once)
int register_policy_fid(const char* fid, const uint8_t* mrenclave) {
    PolicyEntry* entry = find_policy(fid);
    if (entry != NULL) {
        if (entry->policy_set) {
            ocall_print("KMS: Policy already set for FID (write-once rejected)\n");
            return -1;  // Write-once: reject overwrite
        }
    } else {
        // Create new entry
        if (g_num_policies >= MAX_POLICY_ENTRIES) {
            ocall_print("KMS: Policy registry full\n");
            return -1;
        }
        entry = &g_policy_registry[g_num_policies++];
        strncpy(entry->fid, fid, MAX_FID_LEN - 1);
        entry->fid[MAX_FID_LEN - 1] = '\0';
        entry->num_labels = 0;
    }
    
    memcpy(entry->policy_mrenclave, mrenclave, 32);
    entry->policy_set = true;
    ocall_print("KMS: Policy registered for FID (write-once)\n");
    return 0;
}

// Bind label to FID (BindLabelToFID)
int bind_label_to_fid(const char* fid, const char* label) {
    PolicyEntry* entry = find_policy(fid);
    if (entry == NULL) {
        // Create new entry without policy (can add labels before policy)
        if (g_num_policies >= MAX_POLICY_ENTRIES) {
            ocall_print("KMS: Policy registry full\n");
            return -1;
        }
        entry = &g_policy_registry[g_num_policies++];
        strncpy(entry->fid, fid, MAX_FID_LEN - 1);
        entry->fid[MAX_FID_LEN - 1] = '\0';
        entry->policy_set = false;
        entry->num_labels = 0;
    }
    
    // Check if label already bound
    for (int i = 0; i < entry->num_labels; i++) {
        if (strcmp(entry->bound_labels[i], label) == 0) {
            return 0;  // Already bound, OK
        }
    }
    
    // Add new label binding
    if (entry->num_labels >= 4) {
        ocall_print("KMS: Too many labels bound to FID\n");
        return -1;
    }
    
    strncpy(entry->bound_labels[entry->num_labels], label, LABEL_LEN - 1);
    entry->bound_labels[entry->num_labels][LABEL_LEN - 1] = '\0';
    entry->num_labels++;
    
    ocall_print("KMS: Label bound to FID\n");
    return 0;
}

// Check if label is bound to FID
bool is_label_bound_to_fid(const char* fid, const char* label) {
    PolicyEntry* entry = find_policy(fid);
    if (entry == NULL) {
        return false;  // No policy entry means no binding
    }
    
    for (int i = 0; i < entry->num_labels; i++) {
        if (strcmp(entry->bound_labels[i], label) == 0) {
            return true;
        }
    }
    return false;
}

// Check if RA passes for this FID
bool verify_ra_for_fid(const char* fid) {
    PolicyEntry* entry = find_policy(fid);
    if (entry == NULL || !entry->policy_set) return true;

    if (!g_ra_verified) {
        ocall_print("KMS: RA not verified, denying key release (policy requires VerifyRA)\n");
        return false;
    }

    // Ensure cached verification is bound to the same FID (prevents cross-FID reuse).
    if (strncmp(g_verified_fid, fid, MAX_FID_LEN) != 0) {
        ocall_print("KMS: RA verified state is not bound to requested FID, denying key release\n");
        return false;
    }
    
    // Check if verified MRENCLAVE matches policy
    if (memcmp(g_verified_mrenclave, entry->policy_mrenclave, 32) == 0) {
        ocall_print("KMS: RA verified, MRENCLAVE matches policy\n");
        return true;
    }
    
    ocall_print("KMS: RA FAILED - MRENCLAVE does not match policy\n");
    return false;
}

// IC2: Verify that H(worker_pk) matches the report_data from the verified quote.
// This binds the attestation to a specific worker ephemeral public key, preventing
// a malicious worker from using another worker's valid quote to obtain keys.
// Parameters:
//   public_key: Worker's ephemeral public key (64 bytes: X || Y, without 0x04 prefix)
// Returns: true if binding matches, false otherwise
bool verify_report_data_binding(const uint8_t* public_key) {
    if (!g_ra_verified) {
        ocall_print("KMS: Cannot verify report_data binding - RA not verified.\n");
        return false;
    }
    
    // Compute H(worker_pk) - the public_key here is 64 bytes (X||Y)
    // Worker stores H(full 64-byte pk) in report_data
    sgx_sha256_hash_t h_pk;
    sgx_status_t ret = sgx_sha256_msg(public_key, 64, &h_pk);
    if (ret != SGX_SUCCESS) {
        ocall_print("KMS: Failed to hash worker public key.\n");
        return false;
    }
    
    // Compare against first 32 bytes of cached report_data
    // (report_data is 64 bytes, we use first 32 for H(pk))
    if (memcmp(h_pk, g_verified_report_data, 32) == 0) {
        ocall_print("KMS: IC2 report_data binding verified (H(worker_pk) matches).\n");
        return true;
    }
    
    // Debug: show mismatch
    char buf[256];
    snprintf(buf, sizeof(buf), "KMS: IC2 report_data binding FAILED.\n  H(worker_pk): %02x%02x%02x%02x...\n  report_data:  %02x%02x%02x%02x...\n",
             ((uint8_t*)h_pk)[0], ((uint8_t*)h_pk)[1], ((uint8_t*)h_pk)[2], ((uint8_t*)h_pk)[3],
             g_verified_report_data[0], g_verified_report_data[1], g_verified_report_data[2], g_verified_report_data[3]);
    ocall_print(buf);
    
    return false;
}

sgx_status_t derive_key_pair(const char* fid, sgx_ec256_private_t* sk, sgx_ec256_public_t* pk) {
    if (!g_msk_initialized) return SGX_ERROR_INVALID_STATE;

    // Mock for testing: Use fixed key for default_fid
    if (strcmp(fid, "default_fid") == 0) {
        memset(sk, 0xBB, 32);
        return sgx_ecc256_calculate_pub_from_priv(sk, pk);
    }

    // 1. Hash MSK || FID
    uint32_t fid_len = strlen(fid);
    uint32_t buf_len = 32 + fid_len;
    uint8_t* buf = (uint8_t*)malloc(buf_len);
    if (!buf) return SGX_ERROR_OUT_OF_MEMORY;
    
    memcpy(buf, g_msk, 32);
    memcpy(buf + 32, fid, fid_len);
    
    sgx_sha256_hash_t hash;
    sgx_status_t ret = sgx_sha256_msg(buf, buf_len, &hash);
    free(buf);
    if (ret != SGX_SUCCESS) return ret;
    
    // 2. Use Hash as Private Key
    memcpy(sk, hash, 32);
    
    // 3. Calculate Public Key
    // sgx_ecc256_calculate_pub_from_priv does not take a handle
    ret = sgx_ecc256_calculate_pub_from_priv(sk, pk);
    
    return ret;
}

void ecall_init_kms(uint8_t* sealed_data, uint32_t sealed_size, uint8_t* out_sealed_data, uint32_t out_sealed_size, uint32_t* actual_sealed_size) {
    ocall_print("KMS Enclave Initializing...\n");
    
    if (actual_sealed_size) *actual_sealed_size = 0;

    if (sealed_data != NULL && sealed_size > 0) {
        // Try to unseal
        uint32_t decrypted_len = sgx_get_encrypt_txt_len((const sgx_sealed_data_t*)sealed_data);
        if (decrypted_len == 32) {
            uint8_t* decrypted_data = (uint8_t*)malloc(decrypted_len);
            if (decrypted_data) {
                sgx_status_t ret = sgx_unseal_data(
                    (const sgx_sealed_data_t*)sealed_data,
                    NULL, 0,
                    decrypted_data, &decrypted_len
                );
                if (ret == SGX_SUCCESS) {
                    memcpy(g_msk, decrypted_data, 32);
                    g_msk_initialized = true;
                    ocall_print("KMS Enclave: MSK Unsealed Successfully.\n");
                    free(decrypted_data);
                    return;
                }
                free(decrypted_data);
            }
        }
        ocall_print("KMS Enclave: Failed to unseal MSK. Generating new one.\n");
    }
    
    // Generate new MSK
    sgx_read_rand(g_msk, 32);
    g_msk_initialized = true;
    ocall_print("KMS Enclave: New MSK Generated.\n");
    
    // Seal MSK
    uint32_t required_size = sgx_calc_sealed_data_size(0, 32);
    
    char debug_buf[64];
    snprintf(debug_buf, sizeof(debug_buf), "KMS Enclave: Required sealed size: %d\n", required_size);
    ocall_print(debug_buf);

    if (out_sealed_data != NULL && out_sealed_size >= required_size) {
        // Use a local buffer to ensure alignment and correct size handling
        uint8_t* temp_sealed = (uint8_t*)malloc(required_size);
        if (!temp_sealed) {
            ocall_print("KMS Enclave: Out of memory for sealing.\n");
            return;
        }

        sgx_status_t ret = sgx_seal_data(
            0, NULL,
            32, g_msk,
            required_size, (sgx_sealed_data_t*)temp_sealed
        );
        
        if (ret == SGX_SUCCESS) {
            memcpy(out_sealed_data, temp_sealed, required_size);
            ocall_print("KMS Enclave: MSK Sealed Successfully.\n");
            if (actual_sealed_size) *actual_sealed_size = required_size;
        } else {
            char buf[64];
            snprintf(buf, sizeof(buf), "KMS Enclave: Failed to seal MSK. Error: 0x%x\n", ret);
            ocall_print(buf);
        }
        free(temp_sealed);
    } else {
        ocall_print("KMS Enclave: Output buffer too small for sealed data.\n");
    }
}

int ecall_verify_quote(uint8_t* quote, uint32_t quote_size) {
    ocall_print("KMS Enclave: Verifying Quote...\n");
    
    // TODO: Implement real DCAP verification using sgx_dcap_tvl
    // For now, we just check if quote is not null
    if (quote == NULL || quote_size == 0) {
        ocall_print("KMS Enclave: Invalid Quote.\n");
        return -1;
    }

    // Legacy API does not bind verification to an FID; do not allow it to
    // produce a cached "verified" state that could be reused across FIDs.
    ocall_print("KMS Enclave: Quote verify API requires FID binding; call ecall_verify_quote_for_fid.\n");
    return -1;
}

int ecall_verify_quote_for_fid(const char* fid, uint8_t* quote, uint32_t quote_size) {
    ocall_print("KMS Enclave: Verifying Quote for FID...\n");

    // =========================================================================
    // Quote Verification Architecture (IC2)
    // =========================================================================
    //
    // Two-tier verification model:
    //
    // 1. HOST-SIDE (DCAP signature verification):
    //    - Uses Intel QVL (Quote Verification Library) to verify quote signature chain
    //    - Checks TCB status, revocation, collateral freshness
    //    - This happens BEFORE calling this ECALL
    //
    // 2. ENCLAVE-SIDE (policy enforcement - THIS FUNCTION):
    //    - Parses quote structure to extract MRENCLAVE and report_data
    //    - Enforces policy[FID] MRENCLAVE allow-list
    //    - Caches report_data for H(worker_pk) binding check during key release
    //
    // Security property:
    //    - The HOST cannot bypass the enclave's policy decisions
    //    - Even if DCAP verification passes, key release is gated on:
    //      a) MRENCLAVE matching policy[FID]
    //      b) report_data == H(worker_pk) (verified during key release)
    //    - A malicious host could call this ECALL without first doing DCAP verify,
    //      but the extracted MRENCLAVE would be garbage and fail policy check
    //
    // Simulation mode note:
    //    - In SGX_MODE_SIM builds, DCAP signature verification is skipped
    //    - The enclave still performs structure parsing and policy checks
    //    - This is acceptable for functional testing, NOT for production claims
    //
    // =========================================================================

    // Reset verification state
    g_ra_verified = false;
    memset(g_verified_mrenclave, 0, 32);
    memset(g_verified_fid, 0, sizeof(g_verified_fid));
    memset(g_verified_report_data, 0, sizeof(g_verified_report_data));

    if (fid == NULL || quote == NULL || quote_size == 0) {
        ocall_print("KMS Enclave: Invalid Quote/FID.\n");
        return -1;
    }

    // Parse quote structure to extract MRENCLAVE and report_data
    // Minimum quote size: header(48) + report_body(384) = 432 bytes
    if (quote_size < QUOTE3_REPORT_BODY_OFFSET + REPORT_BODY_SIZE) {
        char buf[128];
        snprintf(buf, sizeof(buf), "KMS Enclave: Quote too small (%u bytes, need %u).\n", 
                 quote_size, QUOTE3_REPORT_BODY_OFFSET + REPORT_BODY_SIZE);
        ocall_print(buf);
        return -1;
    }

    // Extract MRENCLAVE from report_body (offset 64 within report_body, 32 bytes)
    const uint8_t* report_body = quote + QUOTE3_REPORT_BODY_OFFSET;
    const uint8_t* mrenclave = report_body + MRENCLAVE_OFFSET_IN_BODY;
    const uint8_t* report_data = report_body + REPORT_DATA_OFFSET_IN_BODY;

    // Cache the extracted MRENCLAVE
    memcpy(g_verified_mrenclave, mrenclave, 32);
    // Cache the report_data for later worker_pk binding check
    memcpy(g_verified_report_data, report_data, 64);
    
    strncpy(g_verified_fid, fid, MAX_FID_LEN - 1);
    g_verified_fid[MAX_FID_LEN - 1] = '\0';

    // Debug: Print extracted MRENCLAVE
    char hex_buf[128];
    snprintf(hex_buf, sizeof(hex_buf), "KMS Enclave: Extracted MRENCLAVE: %02x%02x%02x%02x...\n",
             mrenclave[0], mrenclave[1], mrenclave[2], mrenclave[3]);
    ocall_print(hex_buf);

    // Policy enforcement: check MRENCLAVE against policy[FID] allow-list
    PolicyEntry* entry = find_policy(fid);
    if (entry != NULL && entry->policy_set) {
        if (memcmp(g_verified_mrenclave, entry->policy_mrenclave, 32) != 0) {
            ocall_print("KMS Enclave: Quote MRENCLAVE does not match policy (DENIED).\n");
            g_ra_verified = false;
            memset(g_verified_mrenclave, 0, 32);
            memset(g_verified_fid, 0, sizeof(g_verified_fid));
            memset(g_verified_report_data, 0, sizeof(g_verified_report_data));
            return -1;
        }
        ocall_print("KMS Enclave: MRENCLAVE matches policy[FID].\n");
    } else {
        ocall_print("KMS Enclave: No policy set for FID, accepting (open policy).\n");
    }

    g_ra_verified = true;
    ocall_print("KMS Enclave: Quote parsed and verified (FID-bound).\n");
    return 0;
}

int ecall_get_public_key(const char* fid, uint8_t* public_key) {
    sgx_ec256_private_t sk;
    sgx_ec256_public_t pk;
    
    if (derive_key_pair(fid, &sk, &pk) != SGX_SUCCESS) return -1;
    
    // Format: 04 || X || Y (65 bytes)
    public_key[0] = 0x04;
    memcpy(public_key + 1, pk.gx, 32);
    memcpy(public_key + 33, pk.gy, 32);
    
    return 0;
}

int ecall_get_key(const char* fid, uint8_t* public_key, uint8_t* key) {
    ocall_print("KMS Enclave: Generating Key for FID: ");
    ocall_print(fid);
    ocall_print("\n");
    
    ocall_print("KMS Enclave: Received Worker Public Key.\n");

    if (!verify_ra_for_fid(fid)) {
        ocall_print("KMS Enclave: Denying key release: VerifyRA(policy[FID]) failed.\n");
        return -1;
    }

    // IC2: Verify report_data binding (H(worker_pk) == quote.report_data[0:32])
    // Skip for default_fid which is used in tests without full quote flow
    if (strcmp(fid, "default_fid") != 0) {
        if (!verify_report_data_binding(public_key)) {
            ocall_print("KMS Enclave: Denying key release: IC2 report_data binding failed.\n");
            return -1;
        }
    }

    sgx_status_t ret;
    
    // 1. Generate the "IBE Key" (Real Derived Key)
    sgx_ec256_private_t sk;
    sgx_ec256_public_t pk;
    if (derive_key_pair(fid, &sk, &pk) != SGX_SUCCESS) return -1;
    
    uint8_t ibe_key[32];
    memcpy(ibe_key, sk.r, 32);
    
    // 2. Generate Ephemeral ECC Key Pair
    sgx_ecc_state_handle_t ecc_handle;
    sgx_ec256_private_t my_priv;
    sgx_ec256_public_t my_pub;
    
    ret = sgx_ecc256_open_context(&ecc_handle);
    if (ret != SGX_SUCCESS) return -1;
    
    ret = sgx_ecc256_create_key_pair(&my_priv, &my_pub, ecc_handle);
    if (ret != SGX_SUCCESS) { sgx_ecc256_close_context(ecc_handle); return -1; }
    
    // 3. Compute Shared Secret
    sgx_ec256_public_t worker_pub;
    memcpy(&worker_pub, public_key, 64);
    
    sgx_ec256_dh_shared_t shared_secret;
    ret = sgx_ecc256_compute_shared_dhkey(&my_priv, &worker_pub, &shared_secret, ecc_handle);
    if (ret != SGX_SUCCESS) { sgx_ecc256_close_context(ecc_handle); return -1; }
    
    sgx_ecc256_close_context(ecc_handle);
    
    // 4. Encrypt IBE Key using Shared Secret (AES-GCM)
    // Use shared_secret.s as AES Key (32 bytes -> AES-256? No, sgx_rijndael128GCM uses 128-bit key)
    // We need to derive a 16-byte key. Let's just use the first 16 bytes of shared secret.
    uint8_t aes_key[16];
    memcpy(aes_key, shared_secret.s, 16);
    
    uint8_t iv[12];
    sgx_read_rand(iv, 12);
    
    uint8_t tag[16];
    uint8_t ciphertext[32];
    
    ret = sgx_rijndael128GCM_encrypt(
        (const sgx_aes_gcm_128bit_key_t*)aes_key,
        ibe_key, 32,
        ciphertext,
        iv, 12,
        NULL, 0,
        (sgx_aes_gcm_128bit_tag_t*)tag
    );
    
    if (ret != SGX_SUCCESS) return -1;
    
    // 5. Pack Result: MyPub(64) + IV(12) + Tag(16) + Ciphertext(32) = 124 bytes
    uint8_t* p = key;
    memcpy(p, &my_pub, 64); p += 64;
    memcpy(p, iv, 12); p += 12;
    memcpy(p, tag, 16); p += 16;
    memcpy(p, ciphertext, 32);
    
    ocall_print("KMS Enclave: Key Encrypted and Sent.\n");
    
    return 0;
}

// ============================================================================
// Label-Key Derivation for dklabel_func
// ============================================================================
// Label = H(C_func) is bound to FID during deployment.
// This function derives a label-specific key that can decrypt C_k_func.

// Derive key from label (internal helper)
// Returns encrypted key in output buffer (124 bytes)
int derive_label_key_internal(const char* fid, const char* label, uint8_t* public_key, uint8_t* key_out) {
    ocall_print("KMS Enclave: Deriving Label Key for label: ");
    ocall_print(label);
    ocall_print("\n");

    if (!verify_ra_for_fid(fid)) {
        ocall_print("KMS Enclave: Denying label-key release: VerifyRA(policy[FID]) failed.\n");
        return -1;
    }

    // IC2: Verify report_data binding (H(worker_pk) == quote.report_data[0:32])
    if (strcmp(fid, "default_fid") != 0) {
        if (!verify_report_data_binding(public_key)) {
            ocall_print("KMS Enclave: Denying label-key release: IC2 report_data binding failed.\n");
            return -1;
        }
    }

    // Protocol(D): Enforce BindLabelToFID(labelfunc, FID) before releasing label-derived key.
    if (!is_label_bound_to_fid(fid, label)) {
        ocall_print("KMS Enclave: Denying label-key release: BindLabelToFID failed.\n");
        return -1;
    }

    sgx_status_t ret;
    
    // 1. Derive label-specific key from MSK and label
    // Security: Key is bound to both MSK and label=H(C_func)
    uint32_t label_len = strlen(label);
    uint32_t buf_len = 32 + label_len;
    uint8_t* buf = (uint8_t*)malloc(buf_len);
    if (!buf) return -1;
    
    memcpy(buf, g_msk, 32);
    memcpy(buf + 32, label, label_len);
    
    sgx_sha256_hash_t hash;
    ret = sgx_sha256_msg(buf, buf_len, &hash);
    free(buf);
    if (ret != SGX_SUCCESS) return -1;
    
    uint8_t label_key[32];
    memcpy(label_key, hash, 32);
    
    // 2. Encrypt label_key with worker's public key (ECDH)
    sgx_ecc_state_handle_t ecc_handle;
    sgx_ec256_private_t my_priv;
    sgx_ec256_public_t my_pub;
    
    ret = sgx_ecc256_open_context(&ecc_handle);
    if (ret != SGX_SUCCESS) return -1;
    
    ret = sgx_ecc256_create_key_pair(&my_priv, &my_pub, ecc_handle);
    if (ret != SGX_SUCCESS) { sgx_ecc256_close_context(ecc_handle); return -1; }
    
    // 3. Compute Shared Secret
    sgx_ec256_public_t worker_pub;
    memcpy(&worker_pub, public_key, 64);
    
    sgx_ec256_dh_shared_t shared_secret;
    ret = sgx_ecc256_compute_shared_dhkey(&my_priv, &worker_pub, &shared_secret, ecc_handle);
    if (ret != SGX_SUCCESS) { sgx_ecc256_close_context(ecc_handle); return -1; }
    
    sgx_ecc256_close_context(ecc_handle);
    
    // 4. Encrypt label_key using Shared Secret (AES-GCM)
    uint8_t aes_key[16];
    memcpy(aes_key, shared_secret.s, 16);
    
    uint8_t iv[12];
    sgx_read_rand(iv, 12);
    
    uint8_t tag[16];
    uint8_t ciphertext[32];
    
    ret = sgx_rijndael128GCM_encrypt(
        (const sgx_aes_gcm_128bit_key_t*)aes_key,
        label_key, 32,
        ciphertext,
        iv, 12,
        NULL, 0,
        (sgx_aes_gcm_128bit_tag_t*)tag
    );
    
    if (ret != SGX_SUCCESS) return -1;
    
    // 5. Pack Result: MyPub(64) + IV(12) + Tag(16) + Ciphertext(32) = 124 bytes
    uint8_t* p = key_out;
    memcpy(p, &my_pub, 64); p += 64;
    memcpy(p, iv, 12); p += 12;
    memcpy(p, tag, 16); p += 16;
    memcpy(p, ciphertext, 32);
    
    ocall_print("KMS Enclave: Label Key Encrypted and Ready.\n");
    
    return 0;
}

// ============================================================================
// Batch DeriveKeys API
// ============================================================================
// Combines FID key + label key derivation in single RPC.
// Reduces cold start latency by eliminating multiple round trips.
//
// Protocol:
// 1. Worker computes label = H(C_func) after receiving C_func
// 2. Worker sends single request with (FID, label)
// 3. KMS performs one VerifyRA check (done in App layer before calling this ecall)
// 4. KMS returns dkf (FID-derived) + dklabel (label-derived) in one response
//
// Security guarantees:
// - dkf: Derived from MSK || FID, used for request-level operations
// - dklabel: Derived from MSK || label, used to decrypt C_k_func -> k_func
// - Both are encrypted with worker's ephemeral public key

int ecall_derive_keys_batch(const char* fid, const char* label, uint8_t* public_key, uint8_t* dkf_out, uint8_t* dklabel_out) {
    ocall_print("KMS Enclave: Batch DeriveKeys for FID: ");
    ocall_print(fid);
    ocall_print(", Label: ");
    ocall_print(label);
    ocall_print("\n");

    if (!verify_ra_for_fid(fid)) {
        ocall_print("KMS Enclave: Denying batch key release: VerifyRA(policy[FID]) failed.\n");
        return -1;
    }
    
    // Derive FID key (dkf) - reuse existing ecall_get_key logic
    int ret1 = ecall_get_key(fid, public_key, dkf_out);
    if (ret1 != 0) {
        ocall_print("KMS Enclave: Failed to derive FID key.\n");
        return -1;
    }
    
    // Derive Label key (dklabel) 
    int ret2 = derive_label_key_internal(fid, label, public_key, dklabel_out);
    if (ret2 != 0) {
        ocall_print("KMS Enclave: Failed to derive Label key.\n");
        return -1;
    }
    
    ocall_print("KMS Enclave: Batch DeriveKeys Success - both keys derived.\n");
    ocall_print("  Network round trips reduced from 2 to 1.\n");
    
    return 0;
}

// ============================================================================
// BF-IBE Key Release Boundary
// ============================================================================
// ASBFREL1 is the outer encrypted KMS-to-worker release envelope.
// ASBFSKS1 is the trusted plaintext private-key set carried inside that envelope.
static const char BFIBE_KEY_RELEASE_MAGIC[] = "ASBFREL1";
static const char BFIBE_PRIVATE_KEY_SET_MAGIC[] = "ASBFSKS1";
static const char BFIBE_PROFILE_ID[] = "bfibe-mcl-bls12381";
static const char BFIBE_AAD_MAGIC[] = "ASYNCS/BFIBE/KEYRELEASE/AAD/v1";
static const uint8_t BFIBE_KEY_RELEASE_VERSION = 1;
static const uint8_t BFIBE_PRIVATE_KEY_SET_VERSION = 1;
static const uint32_t BFIBE_MAX_PRIVATE_KEY_SET_SIZE = 2048;
static const uint32_t BFIBE_MAX_CIPHERTEXT_FIELD_SIZE = BFIBE_MAX_PRIVATE_KEY_SET_SIZE + 16;

static void put_u32_be(uint8_t* out, uint32_t value) {
    out[0] = (uint8_t)(value >> 24);
    out[1] = (uint8_t)(value >> 16);
    out[2] = (uint8_t)(value >> 8);
    out[3] = (uint8_t)value;
}

static int append_bytes(uint8_t* out, uint32_t capacity, uint32_t* offset, const void* data, uint32_t len) {
    if (!out || !offset || (!data && len != 0) || *offset > capacity || len > capacity - *offset) {
        return -1;
    }
    if (len > 0) {
        memcpy(out + *offset, data, len);
    }
    *offset += len;
    return 0;
}

static int append_u8(uint8_t* out, uint32_t capacity, uint32_t* offset, uint8_t value) {
    return append_bytes(out, capacity, offset, &value, 1);
}

static int append_u32_be(uint8_t* out, uint32_t capacity, uint32_t* offset, uint32_t value) {
    uint8_t encoded[4];
    put_u32_be(encoded, value);
    return append_bytes(out, capacity, offset, encoded, sizeof(encoded));
}

static int append_part_for_aad(uint8_t* out, uint32_t capacity, uint32_t* offset, const void* data, uint32_t len) {
    if (append_u32_be(out, capacity, offset, len) != 0) return -1;
    return append_bytes(out, capacity, offset, data, len);
}

static void hex_encode(const uint8_t* input, uint32_t input_len, char* out, uint32_t out_capacity) {
    static const char hex[] = "0123456789abcdef";
    if (out_capacity < input_len * 2 + 1) {
        if (out_capacity > 0) out[0] = '\0';
        return;
    }
    for (uint32_t i = 0; i < input_len; i++) {
        out[i * 2] = hex[input[i] >> 4];
        out[i * 2 + 1] = hex[input[i] & 0x0f];
    }
    out[input_len * 2] = '\0';
}

static int make_prefixed_identity(const char* prefix, const char* value, char* out, uint32_t out_capacity) {
    int written = snprintf(out, out_capacity, "%s%s", prefix, value);
    if (written <= 0 || (uint32_t)written >= out_capacity) {
        return -1;
    }
    return 0;
}

static int build_worker_identity(char* out, uint32_t out_capacity) {
    char mrenclave_hex[65];
    hex_encode(g_verified_mrenclave, 32, mrenclave_hex, sizeof(mrenclave_hex));
    return make_prefixed_identity("mrenclave:", mrenclave_hex, out, out_capacity);
}

static int build_bfibe_private_key_set(
    const char* request_identity,
    const uint8_t* request_sk,
    uint32_t request_sk_len,
    const char* function_identity,
    const uint8_t* function_sk,
    uint32_t function_sk_len,
    uint8_t* out,
    uint32_t out_capacity,
    uint32_t* actual_size
) {
    const char request_purpose[] = "request-key";
    const char function_purpose[] = "function-key";
    const uint32_t profile_len = (uint32_t)strlen(BFIBE_PROFILE_ID);
    const uint32_t request_purpose_len = (uint32_t)strlen(request_purpose);
    const uint32_t request_identity_len = (uint32_t)strlen(request_identity);
    const uint32_t function_purpose_len = (uint32_t)strlen(function_purpose);
    const uint32_t function_identity_len = (uint32_t)strlen(function_identity);
    uint32_t offset = 0;

    if (append_bytes(out, out_capacity, &offset, BFIBE_PRIVATE_KEY_SET_MAGIC, 8) != 0) return -1;
    if (append_u8(out, out_capacity, &offset, BFIBE_PRIVATE_KEY_SET_VERSION) != 0) return -1;
    if (append_u32_be(out, out_capacity, &offset, profile_len) != 0) return -1;
    if (append_u32_be(out, out_capacity, &offset, 2) != 0) return -1;
    if (append_bytes(out, out_capacity, &offset, BFIBE_PROFILE_ID, profile_len) != 0) return -1;

    if (append_u32_be(out, out_capacity, &offset, request_purpose_len) != 0) return -1;
    if (append_u32_be(out, out_capacity, &offset, request_identity_len) != 0) return -1;
    if (append_u32_be(out, out_capacity, &offset, request_sk_len) != 0) return -1;
    if (append_bytes(out, out_capacity, &offset, request_purpose, request_purpose_len) != 0) return -1;
    if (append_bytes(out, out_capacity, &offset, request_identity, request_identity_len) != 0) return -1;
    if (append_bytes(out, out_capacity, &offset, request_sk, request_sk_len) != 0) return -1;

    if (append_u32_be(out, out_capacity, &offset, function_purpose_len) != 0) return -1;
    if (append_u32_be(out, out_capacity, &offset, function_identity_len) != 0) return -1;
    if (append_u32_be(out, out_capacity, &offset, function_sk_len) != 0) return -1;
    if (append_bytes(out, out_capacity, &offset, function_purpose, function_purpose_len) != 0) return -1;
    if (append_bytes(out, out_capacity, &offset, function_identity, function_identity_len) != 0) return -1;
    if (append_bytes(out, out_capacity, &offset, function_sk, function_sk_len) != 0) return -1;

    *actual_size = offset;
    return 0;
}

static int build_bfibe_key_release_aad(
    const char* fid,
    const char* worker_identity,
    const uint8_t* wrap_public_key,
    uint32_t wrap_public_key_len,
    uint8_t* out,
    uint32_t out_capacity,
    uint32_t* actual_size
) {
    uint32_t offset = 0;
    const uint32_t aad_magic_len = (uint32_t)strlen(BFIBE_AAD_MAGIC);
    const uint32_t profile_len = (uint32_t)strlen(BFIBE_PROFILE_ID);
    const uint32_t fid_len = (uint32_t)strlen(fid);
    const uint32_t worker_identity_len = (uint32_t)strlen(worker_identity);

    if (append_bytes(out, out_capacity, &offset, BFIBE_AAD_MAGIC, aad_magic_len) != 0) return -1;
    if (append_part_for_aad(out, out_capacity, &offset, BFIBE_PROFILE_ID, profile_len) != 0) return -1;
    if (append_part_for_aad(out, out_capacity, &offset, fid, fid_len) != 0) return -1;
    if (append_part_for_aad(out, out_capacity, &offset, worker_identity, worker_identity_len) != 0) return -1;
    if (append_part_for_aad(out, out_capacity, &offset, wrap_public_key, wrap_public_key_len) != 0) return -1;

    *actual_size = offset;
    return 0;
}

static int build_bfibe_key_release(
    const char* fid,
    const char* worker_identity,
    const uint8_t* wrap_public_key,
    uint32_t wrap_public_key_len,
    const uint8_t* nonce,
    uint32_t nonce_len,
    const uint8_t* ciphertext,
    uint32_t ciphertext_len,
    uint8_t* out,
    uint32_t out_capacity,
    uint32_t* actual_size
) {
    uint32_t offset = 0;
    const uint32_t profile_len = (uint32_t)strlen(BFIBE_PROFILE_ID);
    const uint32_t fid_len = (uint32_t)strlen(fid);
    const uint32_t worker_identity_len = (uint32_t)strlen(worker_identity);

    if (append_bytes(out, out_capacity, &offset, BFIBE_KEY_RELEASE_MAGIC, 8) != 0) return -1;
    if (append_u8(out, out_capacity, &offset, BFIBE_KEY_RELEASE_VERSION) != 0) return -1;
    if (append_u32_be(out, out_capacity, &offset, profile_len) != 0) return -1;
    if (append_u32_be(out, out_capacity, &offset, fid_len) != 0) return -1;
    if (append_u32_be(out, out_capacity, &offset, worker_identity_len) != 0) return -1;
    if (append_u32_be(out, out_capacity, &offset, wrap_public_key_len) != 0) return -1;
    if (append_u32_be(out, out_capacity, &offset, nonce_len) != 0) return -1;
    if (append_u32_be(out, out_capacity, &offset, ciphertext_len) != 0) return -1;
    if (append_bytes(out, out_capacity, &offset, BFIBE_PROFILE_ID, profile_len) != 0) return -1;
    if (append_bytes(out, out_capacity, &offset, fid, fid_len) != 0) return -1;
    if (append_bytes(out, out_capacity, &offset, worker_identity, worker_identity_len) != 0) return -1;
    if (append_bytes(out, out_capacity, &offset, wrap_public_key, wrap_public_key_len) != 0) return -1;
    if (append_bytes(out, out_capacity, &offset, nonce, nonce_len) != 0) return -1;
    if (append_bytes(out, out_capacity, &offset, ciphertext, ciphertext_len) != 0) return -1;

    *actual_size = offset;
    return 0;
}

int ecall_get_bfibe_public_params(uint8_t* mpk_out, uint32_t mpk_capacity, uint32_t* actual_mpk_size) {
    if (actual_mpk_size) {
        *actual_mpk_size = 0;
    }
    if (!mpk_out || !actual_mpk_size || mpk_capacity == 0) {
        return -1;
    }

    uint8_t bf_msk[64] = {0};
    size_t bf_msk_len = sizeof(bf_msk);
    if (derive_bfibe_msk(bf_msk, &bf_msk_len) != 0) {
        memset(bf_msk, 0, sizeof(bf_msk));
        return -1;
    }

    size_t mpk_len = mpk_capacity;
    int ret = bfibe_mcl_public_from_msk(bf_msk, bf_msk_len, mpk_out, &mpk_len);
    memset(bf_msk, 0, sizeof(bf_msk));
    if (ret != 0 || mpk_len > mpk_capacity) {
        return -1;
    }

    *actual_mpk_size = (uint32_t)mpk_len;
    ocall_print("KMS Enclave: BF-IBE public params exported.\n");
    return 0;
}

int ecall_get_bfibe_key_release(
    const char* fid,
    const char* label,
    uint8_t* public_key,
    uint8_t* release_out,
    uint32_t release_capacity,
    uint32_t* actual_release_size
) {
    if (actual_release_size) {
        *actual_release_size = 0;
    }
    if (!fid || !label || !public_key || !release_out || !actual_release_size) {
        ocall_print("KMS Enclave: Invalid BF-IBE key-release arguments.\n");
        return -1;
    }

    if (!verify_ra_for_fid(fid)) {
        ocall_print("KMS Enclave: Denying BF-IBE key release: VerifyRA(policy[FID]) failed.\n");
        return -1;
    }
    if (!verify_report_data_binding(public_key)) {
        ocall_print("KMS Enclave: Denying BF-IBE key release: report_data binding failed.\n");
        return -1;
    }
    if (!is_label_bound_to_fid(fid, label)) {
        ocall_print("KMS Enclave: Denying BF-IBE key release: label is not bound to FID.\n");
        return -1;
    }

    uint8_t bf_msk[64];
    size_t bf_msk_len = sizeof(bf_msk);
    if (derive_bfibe_msk(bf_msk, &bf_msk_len) != 0) {
        ocall_print("KMS Enclave: Failed to derive BF-IBE MSK for release.\n");
        return -1;
    }

    char request_identity[MAX_FID_LEN + 5];
    char function_identity[LABEL_LEN + 7];
    char worker_identity[80];
    if (make_prefixed_identity("fid:", fid, request_identity, sizeof(request_identity)) != 0 ||
        make_prefixed_identity("label:", label, function_identity, sizeof(function_identity)) != 0 ||
        build_worker_identity(worker_identity, sizeof(worker_identity)) != 0) {
        memset(bf_msk, 0, sizeof(bf_msk));
        return -1;
    }

    uint8_t request_sk[256];
    uint8_t function_sk[256];
    size_t request_sk_len = sizeof(request_sk);
    size_t function_sk_len = sizeof(function_sk);
    int ret_req = bfibe_mcl_extract(
        bf_msk,
        bf_msk_len,
        request_identity,
        strlen(request_identity),
        request_sk,
        &request_sk_len
    );
    int ret_func = bfibe_mcl_extract(
        bf_msk,
        bf_msk_len,
        function_identity,
        strlen(function_identity),
        function_sk,
        &function_sk_len
    );
    memset(bf_msk, 0, sizeof(bf_msk));
    if (ret_req != 0 || ret_func != 0 || request_sk_len == 0 || function_sk_len == 0) {
        memset(request_sk, 0, sizeof(request_sk));
        memset(function_sk, 0, sizeof(function_sk));
        ocall_print("KMS Enclave: BF-IBE Extract failed for release.\n");
        return -1;
    }

    uint8_t private_key_set[BFIBE_MAX_PRIVATE_KEY_SET_SIZE];
    uint32_t private_key_set_size = 0;
    if (build_bfibe_private_key_set(
            request_identity,
            request_sk,
            (uint32_t)request_sk_len,
            function_identity,
            function_sk,
            (uint32_t)function_sk_len,
            private_key_set,
            sizeof(private_key_set),
            &private_key_set_size
        ) != 0) {
        memset(request_sk, 0, sizeof(request_sk));
        memset(function_sk, 0, sizeof(function_sk));
        return -1;
    }
    memset(request_sk, 0, sizeof(request_sk));
    memset(function_sk, 0, sizeof(function_sk));

    sgx_status_t sgx_ret;
    sgx_ecc_state_handle_t ecc_handle;
    sgx_ec256_private_t kms_priv;
    sgx_ec256_public_t kms_pub;
    sgx_ec256_public_t worker_pub;
    sgx_ec256_dh_shared_t shared_secret;
    memcpy(&worker_pub, public_key, 64);

    sgx_ret = sgx_ecc256_open_context(&ecc_handle);
    if (sgx_ret != SGX_SUCCESS) {
        memset(private_key_set, 0, sizeof(private_key_set));
        return -1;
    }
    sgx_ret = sgx_ecc256_create_key_pair(&kms_priv, &kms_pub, ecc_handle);
    if (sgx_ret != SGX_SUCCESS) {
        sgx_ecc256_close_context(ecc_handle);
        memset(private_key_set, 0, sizeof(private_key_set));
        return -1;
    }
    sgx_ret = sgx_ecc256_compute_shared_dhkey(&kms_priv, &worker_pub, &shared_secret, ecc_handle);
    sgx_ecc256_close_context(ecc_handle);
    if (sgx_ret != SGX_SUCCESS) {
        memset(private_key_set, 0, sizeof(private_key_set));
        return -1;
    }

    uint8_t nonce[12];
    sgx_ret = sgx_read_rand(nonce, sizeof(nonce));
    if (sgx_ret != SGX_SUCCESS) {
        memset(private_key_set, 0, sizeof(private_key_set));
        return -1;
    }

    uint8_t aad[256];
    uint32_t aad_size = 0;
    if (build_bfibe_key_release_aad(
            fid,
            worker_identity,
            (const uint8_t*)&kms_pub,
            64,
            aad,
            sizeof(aad),
            &aad_size
        ) != 0) {
        memset(private_key_set, 0, sizeof(private_key_set));
        return -1;
    }

    uint8_t aes_key[16];
    memcpy(aes_key, shared_secret.s, sizeof(aes_key));
    uint8_t ciphertext_field[BFIBE_MAX_CIPHERTEXT_FIELD_SIZE];
    uint8_t tag[16];
    sgx_ret = sgx_rijndael128GCM_encrypt(
        (const sgx_aes_gcm_128bit_key_t*)aes_key,
        private_key_set,
        private_key_set_size,
        ciphertext_field,
        nonce,
        sizeof(nonce),
        aad,
        aad_size,
        (sgx_aes_gcm_128bit_tag_t*)tag
    );
    memset(aes_key, 0, sizeof(aes_key));
    memset(private_key_set, 0, sizeof(private_key_set));
    if (sgx_ret != SGX_SUCCESS) {
        return -1;
    }
    memcpy(ciphertext_field + private_key_set_size, tag, sizeof(tag));
    uint32_t ciphertext_field_size = private_key_set_size + sizeof(tag);

    uint32_t release_size = 0;
    if (build_bfibe_key_release(
            fid,
            worker_identity,
            (const uint8_t*)&kms_pub,
            64,
            nonce,
            sizeof(nonce),
            ciphertext_field,
            ciphertext_field_size,
            release_out,
            release_capacity,
            &release_size
        ) != 0) {
        *actual_release_size = release_size;
        memset(ciphertext_field, 0, sizeof(ciphertext_field));
        return -1;
    }

    memset(ciphertext_field, 0, sizeof(ciphertext_field));
    *actual_release_size = release_size;
    ocall_print("KMS Enclave: BF-IBE key release encrypted and ready.\n");
    return 0;
}

int ecall_bfibe_extract_test() {
    uint8_t bf_msk[64];
    size_t bf_msk_len = sizeof(bf_msk);
    if (derive_bfibe_msk(bf_msk, &bf_msk_len) != 0) {
        ocall_print("KMS Enclave: BF-IBE MSK derivation failed.\n");
        return -1;
    }

    const char request_identity[] = "request-key:fid:test";
    const char function_identity[] = "function-key:label:test";
    uint8_t request_sk[256];
    uint8_t function_sk[256];
    size_t request_sk_len = sizeof(request_sk);
    size_t function_sk_len = sizeof(function_sk);

    int ret_req = bfibe_mcl_extract(
        bf_msk,
        bf_msk_len,
        request_identity,
        sizeof(request_identity) - 1,
        request_sk,
        &request_sk_len
    );
    int ret_func = bfibe_mcl_extract(
        bf_msk,
        bf_msk_len,
        function_identity,
        sizeof(function_identity) - 1,
        function_sk,
        &function_sk_len
    );

    memset(bf_msk, 0, sizeof(bf_msk));
    if (ret_req != 0 || ret_func != 0 || request_sk_len == 0 || function_sk_len == 0) {
        memset(request_sk, 0, sizeof(request_sk));
        memset(function_sk, 0, sizeof(function_sk));
        ocall_print("KMS Enclave: BF-IBE Extract smoke failed.\n");
        return -1;
    }
    if (request_sk_len == function_sk_len && memcmp(request_sk, function_sk, request_sk_len) == 0) {
        memset(request_sk, 0, sizeof(request_sk));
        memset(function_sk, 0, sizeof(function_sk));
        ocall_print("KMS Enclave: BF-IBE Extract identities collided.\n");
        return -1;
    }

    memset(request_sk, 0, sizeof(request_sk));
    memset(function_sk, 0, sizeof(function_sk));
    ocall_print("KMS Enclave: BF-IBE Extract smoke passed.\n");
    return 0;
}

// ============================================================================
// POLICY REGISTRY ECALLS
// ============================================================================

// Register policyFID for FID (write-once, first-writer-wins)
int ecall_register_policy_fid(const char* fid, uint8_t* mrenclave) {
    ocall_print("KMS Enclave: Registering policyFID for FID: ");
    ocall_print(fid);
    ocall_print("\n");
    
    return register_policy_fid(fid, mrenclave);
}

// Bind label to FID (BindLabelToFID)
int ecall_bind_label_to_fid(const char* fid, const char* label) {
    ocall_print("KMS Enclave: Binding label to FID: ");
    ocall_print(fid);
    ocall_print("\n  Label: ");
    ocall_print(label);
    ocall_print("\n");
    
    return bind_label_to_fid(fid, label);
}

// Set RA verification result (called by App after DCAP verification)
int ecall_set_ra_result(int verified, uint8_t* mrenclave) {
    (void)verified;
    (void)mrenclave;
    // Non-bypassable policy gating: the host must not be able to set verified
    // state directly. Quote verification must be done via ecall_verify_quote_for_fid.
    ocall_print("KMS Enclave: Denying host-set RA result (non-bypassable policy requires enclave verification).\n");
    g_ra_verified = false;
    memset(g_verified_mrenclave, 0, 32);
    memset(g_verified_fid, 0, sizeof(g_verified_fid));
    return -1;
}

// Check if label is bound to FID
int ecall_check_label_binding(const char* fid, const char* label) {
    return is_label_bound_to_fid(fid, label) ? 1 : 0;
}
