#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <string>
#include <utility>
#include <vector>
#include "sgx_urts.h"
#include "Enclave_u.h"

// DCAP Quote Verification headers
#include "sgx_dcap_quoteverify.h"
#include "sgx_quote_3.h"

#define MAX_PATH FILENAME_MAX
#define PORT 3000
#define KMS_MAX_CRYPTO_PROFILE_LEN 64
#define KMS_MAX_QUOTE_SIZE (64 * 1024)
#define KMS_MAX_FID_LEN 4096
#define KMS_MAX_LABEL_LEN 128
#define BFIBE_MAX_RELEASE_LEN 4096

sgx_enclave_id_t global_eid = 0;

// Policy: Allowed MRENCLAVE values (32 bytes each, hex string)
// This would normally be configured externally
#define MAX_ALLOWED_ENCLAVES 10
uint8_t g_allowed_mrenclaves[MAX_ALLOWED_ENCLAVES][32];
int g_num_allowed_enclaves = 0;
bool g_policy_enabled = false;  // If false, accept any valid quote

static uint64_t mono_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static int env_int_default(const char* name, int default_value, int min_value, int max_value) {
    const char* v = getenv(name);
    if (!v || !v[0]) return default_value;
    char* end = NULL;
    long parsed = strtol(v, &end, 10);
    if (end == v || *end != '\0' || parsed < min_value || parsed > max_value) {
        return default_value;
    }
    return (int)parsed;
}

static int kms_listen_backlog() {
    return env_int_default("KMS_LISTEN_BACKLOG", 128, 1, 4096);
}

struct KmsTimingTrailer {
    uint64_t verify_dur_ns;
    uint64_t key_release_dur_ns;
    uint64_t total_dur_ns;
};
static_assert(sizeof(KmsTimingTrailer) == sizeof(uint64_t) * 3, "KMS timing trailer must be three uint64_t fields");

static bool send_all(int fd, const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, data + sent, len - sent, 0);
        if (n <= 0) return false;
        sent += (size_t)n;
    }
    return true;
}

static bool read_exact(int fd, void* data, size_t len) {
    uint8_t* p = (uint8_t*)data;
    size_t read_bytes = 0;
    while (read_bytes < len) {
        ssize_t n = read(fd, p + read_bytes, len - read_bytes);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return false;
        read_bytes += (size_t)n;
    }
    return true;
}

static bool read_u32(int fd, uint32_t* out) {
    return read_exact(fd, out, sizeof(*out));
}

static void send_keys_with_timing(int client_socket, const uint8_t* combined_keys, const KmsTimingTrailer& timing) {
    uint8_t response[248 + sizeof(KmsTimingTrailer)];
    memcpy(response, combined_keys, 248);
    memcpy(response + 248, &timing, sizeof(timing));
    send_all(client_socket, response, sizeof(response));
}

static bool send_bfibe_release_with_timing(
    int client_socket,
    const char* fid,
    const char* label,
    uint8_t public_key[64],
    uint64_t kms_verify_dur_ns,
    uint64_t kms_total_begin_ns,
    uint64_t* key_release_dur_ns
) {
    uint8_t bfibe_release[BFIBE_MAX_RELEASE_LEN];
    uint32_t actual_release_size = 0;
    int release_ret = -1;
    uint64_t key_release_begin_ns = mono_ns();
    sgx_status_t ret = ecall_get_bfibe_key_release(
        global_eid,
        &release_ret,
        fid,
        label,
        public_key,
        bfibe_release,
        sizeof(bfibe_release),
        &actual_release_size
    );
    if (key_release_dur_ns) {
        *key_release_dur_ns = mono_ns() - key_release_begin_ns;
    }
    if (ret == SGX_SUCCESS && release_ret == 0 && actual_release_size > 0) {
        uint64_t kms_key_release_dur_ns = key_release_dur_ns ? *key_release_dur_ns : 0;
        uint64_t kms_total_dur_ns = mono_ns() - kms_total_begin_ns;
        KmsTimingTrailer timing = {
            kms_verify_dur_ns,
            kms_key_release_dur_ns,
            kms_total_dur_ns,
        };
        uint8_t response[BFIBE_MAX_RELEASE_LEN + sizeof(KmsTimingTrailer)];
        memcpy(response, bfibe_release, actual_release_size);
        memcpy(response + actual_release_size, &timing, sizeof(timing));
        send_all(client_socket, response, actual_release_size + sizeof(timing));
        printf("BF-IBE key release sent to worker successfully (%u bytes).\n", actual_release_size);
        return true;
    }

    const char* error_msg = "BFIBE_KEY_RELEASE_ERROR";
    send(client_socket, error_msg, strlen(error_msg), 0);
    printf("Error generating BF-IBE key release. ret=0x%x, release_ret=%d, size=%u\n",
           ret, release_ret, actual_release_size);
    return false;
}

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {SGX_ERROR_UNEXPECTED, "Unexpected error occurred.", NULL},
    {SGX_ERROR_INVALID_PARAMETER, "Invalid parameter.", NULL},
    {SGX_ERROR_OUT_OF_MEMORY, "Out of memory.", NULL},
    {SGX_ERROR_ENCLAVE_LOST, "Power transition occurred.", "Please refer to the sample \"PowerTransition\" for details."},
    {SGX_ERROR_INVALID_ENCLAVE, "Invalid enclave image.", NULL},
    {SGX_ERROR_INVALID_ENCLAVE_ID, "Invalid enclave identification.", NULL},
    {SGX_ERROR_INVALID_SIGNATURE, "Invalid enclave signature.", NULL},
    {SGX_ERROR_OUT_OF_EPC, "Out of EPC memory.", NULL},
    {SGX_ERROR_NO_DEVICE, "Invalid SGX device.", "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."},
    {SGX_ERROR_MEMORY_MAP_CONFLICT, "Memory map conflicted.", NULL},
    {SGX_ERROR_INVALID_METADATA, "Invalid enclave metadata.", NULL},
    {SGX_ERROR_DEVICE_BUSY, "SGX device was busy.", NULL},
    {SGX_ERROR_INVALID_VERSION, "Enclave version was invalid.", NULL},
    {SGX_ERROR_MODE_INCOMPATIBLE, "Target enclave mode is incompatible with the mode of the current process.", NULL},
    {SGX_ERROR_ENCLAVE_FILE_ACCESS, "Can't open enclave file.", NULL},
    {SGX_ERROR_NDEBUG_ENCLAVE, "The enclave is signed as product enclave, and can not be created as debuggable enclave.", NULL},
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret) {
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }
    
    if (idx == ttl)
        printf("Error: Unexpected error occurred.\n");
}

/* Initialize the enclave */
int initialize_enclave(void) {
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;
    
    ret = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* OCall functions */
void ocall_print(const char *str) {
    printf("%s", str);
}

/* Print hex bytes */
void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len && i < 32; i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) printf("...");
    printf("\n");
}

/* Add allowed MRENCLAVE to policy */
void add_allowed_mrenclave(const uint8_t* mrenclave) {
    if (g_num_allowed_enclaves < MAX_ALLOWED_ENCLAVES) {
        memcpy(g_allowed_mrenclaves[g_num_allowed_enclaves], mrenclave, 32);
        g_num_allowed_enclaves++;
        printf("Added allowed MRENCLAVE #%d\n", g_num_allowed_enclaves);
    }
}

/* Check if MRENCLAVE is in allowed list */
bool check_mrenclave_policy(const uint8_t* mrenclave) {
    if (!g_policy_enabled) {
        printf("Policy check: DISABLED (accepting any valid quote)\n");
        return true;
    }
    
    for (int i = 0; i < g_num_allowed_enclaves; i++) {
        if (memcmp(g_allowed_mrenclaves[i], mrenclave, 32) == 0) {
            printf("Policy check: MRENCLAVE ALLOWED (match #%d)\n", i+1);
            return true;
        }
    }
    
    printf("Policy check: MRENCLAVE NOT IN ALLOWED LIST\n");
    print_hex("Received MRENCLAVE", mrenclave, 32);
    return false;
}

/* Real DCAP Quote Verification */
int verify_quote_dcap(uint8_t* quote, uint32_t quote_size, uint8_t* mrenclave_out) {
    quote3_error_t dcap_ret = SGX_QL_SUCCESS;
    uint32_t collateral_expiration_status = 1;
    sgx_ql_qv_result_t quote_verification_result = SGX_QL_QV_RESULT_UNSPECIFIED;
    time_t current_time = time(NULL);
    uint32_t supplemental_data_size = 0;
    uint8_t* p_supplemental_data = NULL;
    
    printf("\n=== DCAP Quote Verification ===\n");
    printf("Quote size: %u bytes\n", quote_size);
    
    // Minimum quote size check
    if (quote_size < sizeof(sgx_quote3_t)) {
        printf("Error: Quote too small (min %zu bytes)\n", sizeof(sgx_quote3_t));
        return -1;
    }
    
    // Parse quote header
    sgx_quote3_t* p_quote = (sgx_quote3_t*)quote;
    printf("Quote version: %d\n", p_quote->header.version);
    printf("Attestation key type: %d\n", p_quote->header.att_key_type);
    
    // Extract MRENCLAVE from quote
    if (mrenclave_out) {
        memcpy(mrenclave_out, p_quote->report_body.mr_enclave.m, 32);
    }
    print_hex("MRENCLAVE", p_quote->report_body.mr_enclave.m, 32);
    print_hex("MRSIGNER", p_quote->report_body.mr_signer.m, 32);
    
    // Get supplemental data size
    dcap_ret = sgx_qv_get_quote_supplemental_data_size(&supplemental_data_size);
    if (dcap_ret != SGX_QL_SUCCESS) {
        printf("Warning: Failed to get supplemental data size: 0x%04x\n", dcap_ret);
        supplemental_data_size = 0;
    } else {
        printf("Supplemental data size: %u bytes\n", supplemental_data_size);
        if (supplemental_data_size > 0) {
            p_supplemental_data = (uint8_t*)malloc(supplemental_data_size);
        }
    }
    
    // Verify quote using QVL (Quote Verification Library)
    // We pass NULL for p_qve_report_info to use library-based verification
    // (as opposed to QvE-based verification which requires another enclave)
    dcap_ret = sgx_qv_verify_quote(
        quote,
        quote_size,
        NULL,  // No external collateral - will be fetched from PCCS
        current_time,
        &collateral_expiration_status,
        &quote_verification_result,
        NULL,  // No QvE report - using library verification
        supplemental_data_size,
        p_supplemental_data
    );
    
    if (p_supplemental_data) {
        free(p_supplemental_data);
    }
    
    if (dcap_ret != SGX_QL_SUCCESS) {
        printf("Quote verification API call failed: 0x%04x\n", dcap_ret);
        
        // Provide more specific error messages
        switch (dcap_ret) {
            case 0xe002: printf("  -> SGX_QL_ERROR_INVALID_PARAMETER\n"); break;
            case 0xe003: printf("  -> SGX_QL_QUOTE_FORMAT_UNSUPPORTED\n"); break;
            case 0xe00d: printf("  -> SGX_QL_NETWORK_ERROR (PCCS not reachable)\n"); break;
            case 0xe019: printf("  -> SGX_QL_NO_PLATFORM_CERT_DATA\n"); break;
            case 0xe067: printf("  -> SGX_QL_NO_QUOTE_COLLATERAL_DATA\n"); break;
            default: printf("  -> Check SGX error documentation\n"); break;
        }
        return -1;
    }
    
    // Check collateral expiration
    if (collateral_expiration_status != 0) {
        printf("Warning: Collateral expired (status: %u)\n", collateral_expiration_status);
    }
    
    // Interpret verification result
    printf("Quote verification result: ");
    switch (quote_verification_result) {
        case SGX_QL_QV_RESULT_OK:
            printf("OK - Quote verified successfully!\n");
            return 0;  // Success
            
        case SGX_QL_QV_RESULT_CONFIG_NEEDED:
            printf("CONFIG_NEEDED - Platform needs configuration\n");
            return 0;  // Still acceptable
            
        case SGX_QL_QV_RESULT_OUT_OF_DATE:
            printf("OUT_OF_DATE - TCB level is out of date\n");
            return 0;  // Still acceptable for our use case
            
        case SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED:
            printf("OUT_OF_DATE_CONFIG_NEEDED\n");
            return 0;  // Still acceptable
            
        case SGX_QL_QV_RESULT_SW_HARDENING_NEEDED:
            printf("SW_HARDENING_NEEDED\n");
            return 0;  // Still acceptable
            
        case SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED:
            printf("CONFIG_AND_SW_HARDENING_NEEDED\n");
            return 0;  // Still acceptable
            
        case SGX_QL_QV_RESULT_INVALID_SIGNATURE:
            printf("INVALID_SIGNATURE - Quote signature is invalid!\n");
            return -1;  // Fail
            
        case SGX_QL_QV_RESULT_REVOKED:
            printf("REVOKED - Quote has been revoked!\n");
            return -1;  // Fail
            
        default:
            printf("UNKNOWN (0x%04x)\n", quote_verification_result);
            return -1;  // Fail on unknown result
    }
}

void handle_client(int client_socket) {
    uint32_t quote_size = 0;
    if (!read_u32(client_socket, &quote_size)) return;
    if (quote_size == 0 || quote_size > KMS_MAX_QUOTE_SIZE) {
        const char* error_msg = "INVALID_QUOTE_SIZE";
        send_all(client_socket, (const uint8_t*)error_msg, strlen(error_msg));
        return;
    }
    
    uint8_t* quote = (uint8_t*)malloc(quote_size);
    if (!quote) return;
    if (!read_exact(client_socket, quote, quote_size)) { free(quote); return; }
    
    uint32_t fid_len = 0;
    if (!read_u32(client_socket, &fid_len)) { free(quote); return; }
    if (fid_len == 0 || fid_len > KMS_MAX_FID_LEN) {
        const char* error_msg = "INVALID_FID_LEN";
        send_all(client_socket, (const uint8_t*)error_msg, strlen(error_msg));
        free(quote);
        return;
    }
    
    char* fid = (char*)malloc(fid_len + 1);
    if (!fid) { free(quote); return; }
    if (!read_exact(client_socket, fid, fid_len)) { free(quote); free(fid); return; }
    fid[fid_len] = '\0';

    uint32_t label_len = 0;
    if (!read_u32(client_socket, &label_len)) { free(quote); free(fid); return; }
    if (label_len == 0 || label_len > KMS_MAX_LABEL_LEN) {
        const char* error_msg = "INVALID_LABEL_LEN";
        send_all(client_socket, (const uint8_t*)error_msg, strlen(error_msg));
        free(quote);
        free(fid);
        return;
    }
    
    char* label = (char*)malloc(label_len + 1);
    if (!label) { free(quote); free(fid); return; }
    if (!read_exact(client_socket, label, label_len)) { free(quote); free(fid); free(label); return; }
    label[label_len] = '\0';

    uint8_t public_key[64];
    if (!read_exact(client_socket, public_key, 64)) { free(quote); free(fid); free(label); return; }

    uint32_t crypto_profile_len = 0;
    if (!read_u32(client_socket, &crypto_profile_len)) { free(quote); free(fid); free(label); return; }
    if (crypto_profile_len == 0 || crypto_profile_len > KMS_MAX_CRYPTO_PROFILE_LEN) {
        const char* error_msg = "INVALID_CRYPTO_PROFILE";
        send_all(client_socket, (const uint8_t*)error_msg, strlen(error_msg));
        free(quote);
        free(fid);
        free(label);
        return;
    }
    char crypto_profile[KMS_MAX_CRYPTO_PROFILE_LEN + 1];
    if (!read_exact(client_socket, crypto_profile, crypto_profile_len)) { free(quote); free(fid); free(label); return; }
    crypto_profile[crypto_profile_len] = '\0';
    
    printf("\n========================================\n");
    printf("Received Key Request:\n");
    printf("  Quote Size: %d bytes\n", quote_size);
    printf("  FID: %s\n", fid);
    printf("  Label: %s\n", label);
    printf("  Crypto Profile: %s\n", crypto_profile);
    printf("========================================\n");

    uint64_t kms_total_begin_ns = mono_ns();
    uint64_t kms_verify_dur_ns = 0;
    uint64_t kms_key_release_dur_ns = 0;

#ifdef SGX_MODE_SIM
    // Simulation mode does not provide meaningful DCAP quotes or MRENCLAVE values.
    // For end-to-end functional testing, skip DCAP verification and policy checks.
    printf("[SIM MODE] Skipping DCAP quote verification and MRENCLAVE policy enforcement.\n");

    // Even in SIM mode, route through enclave quote verification API to ensure
    // the non-bypassable gating path is exercised (DCAP contents are not meaningful).
    int qret = -1;
    uint64_t verify_begin_ns = mono_ns();
    (void)ecall_verify_quote_for_fid(global_eid, &qret, fid, quote, quote_size);
    kms_verify_dur_ns = mono_ns() - verify_begin_ns;

    printf("Retrieving Keys for FID: %s (label: %s, profile: %s)\n", fid, label, crypto_profile);

    if (strcmp(crypto_profile, "bfibe-mcl-bls12381") == 0) {
        send_bfibe_release_with_timing(
            client_socket,
            fid,
            label,
            public_key,
            kms_verify_dur_ns,
            kms_total_begin_ns,
            &kms_key_release_dur_ns
        );
    } else {
        if (strcmp(crypto_profile, "eccibe") != 0) {
            const char* error_msg = "UNSUPPORTED_CRYPTO_PROFILE";
            send(client_socket, error_msg, strlen(error_msg), 0);
            printf("Unsupported crypto profile: %s\n", crypto_profile);
        } else {
            // Paper-compliant path: derive both dkf and dklabel with BindLabelToFID enforcement
            uint8_t dkf_out[124];
            uint8_t dklabel_out[124];
            int batch_ret = -1;
            uint64_t key_release_begin_ns = mono_ns();
            sgx_status_t ret = ecall_derive_keys_batch(global_eid, &batch_ret, fid, label, public_key, dkf_out, dklabel_out);
            kms_key_release_dur_ns = mono_ns() - key_release_begin_ns;

            if (ret == SGX_SUCCESS && batch_ret == 0) {
                // Send both keys: dkf (124 bytes) + dklabel (124 bytes) = 248 bytes total
                uint8_t combined_keys[248];
                memcpy(combined_keys, dkf_out, 124);
                memcpy(combined_keys + 124, dklabel_out, 124);
                uint64_t kms_total_dur_ns = mono_ns() - kms_total_begin_ns;
                KmsTimingTrailer timing = {
                    kms_verify_dur_ns,
                    kms_key_release_dur_ns,
                    kms_total_dur_ns,
                };
                send_keys_with_timing(client_socket, combined_keys, timing);
                printf("Both keys (dkf + dklabel) sent to worker successfully.\n");
                printf("  Note: BindLabelToFID enforced by KMS enclave.\n");
            } else {
                const char* error_msg = "KEY_GEN_ERROR";
                send(client_socket, error_msg, strlen(error_msg), 0);
                printf("Error generating keys (batch). ret=0x%x, batch_ret=%d\n", ret, batch_ret);
            }
        }
    }
#else
    // Real DCAP verification
    uint8_t mrenclave[32];
    uint64_t verify_begin_ns = mono_ns();
    int verify_ret = verify_quote_dcap(quote, quote_size, mrenclave);
    
    if (verify_ret != 0) {
        kms_verify_dur_ns = mono_ns() - verify_begin_ns;
        printf("DCAP Quote Verification FAILED\n");
        const char* error_msg = "DCAP_VERIFY_FAILED";
        send(client_socket, error_msg, strlen(error_msg), 0);
    } else {
        printf("DCAP Quote Verification PASSED\n");
        
        // Check MRENCLAVE policy
        if (!check_mrenclave_policy(mrenclave)) {
            kms_verify_dur_ns = mono_ns() - verify_begin_ns;
            printf("MRENCLAVE Policy Check FAILED\n");
            const char* error_msg = "POLICY_DENIED";
            send(client_socket, error_msg, strlen(error_msg), 0);
        } else {
            printf("MRENCLAVE Policy Check PASSED\n");
            printf("Retrieving Keys for FID: %s (label: %s, profile: %s)\n", fid, label, crypto_profile);

            // Non-bypassable enclave-side gating (FID-bound).
            int qret = -1;
            sgx_status_t qstatus = ecall_verify_quote_for_fid(global_eid, &qret, fid, quote, quote_size);
            kms_verify_dur_ns = mono_ns() - verify_begin_ns;
            if (qstatus != SGX_SUCCESS || qret != 0) {
                printf("Enclave VerifyRA(policy[FID]) FAILED\n");
                const char* error_msg = "ENCLAVE_VERIFY_FAILED";
                send(client_socket, error_msg, strlen(error_msg), 0);
                free(quote);
                free(fid);
                free(label);
                close(client_socket);
                return;
            }

            if (strcmp(crypto_profile, "bfibe-mcl-bls12381") == 0) {
                send_bfibe_release_with_timing(
                    client_socket,
                    fid,
                    label,
                    public_key,
                    kms_verify_dur_ns,
                    kms_total_begin_ns,
                    &kms_key_release_dur_ns
                );
            } else {
                if (strcmp(crypto_profile, "eccibe") != 0) {
                    const char* error_msg = "UNSUPPORTED_CRYPTO_PROFILE";
                    send(client_socket, error_msg, strlen(error_msg), 0);
                    printf("Unsupported crypto profile: %s\n", crypto_profile);
                } else {
                    // Paper-compliant path: derive both dkf and dklabel with BindLabelToFID enforcement
                    uint8_t dkf_out[124];
                    uint8_t dklabel_out[124];
                    int batch_ret = -1;
                    uint64_t key_release_begin_ns = mono_ns();
                    sgx_status_t ret = ecall_derive_keys_batch(global_eid, &batch_ret, fid, label, public_key, dkf_out, dklabel_out);
                    kms_key_release_dur_ns = mono_ns() - key_release_begin_ns;

                    if (ret == SGX_SUCCESS && batch_ret == 0) {
                        // Send both keys: dkf (124 bytes) + dklabel (124 bytes) = 248 bytes total
                        uint8_t combined_keys[248];
                        memcpy(combined_keys, dkf_out, 124);
                        memcpy(combined_keys + 124, dklabel_out, 124);
                        uint64_t kms_total_dur_ns = mono_ns() - kms_total_begin_ns;
                        KmsTimingTrailer timing = {
                            kms_verify_dur_ns,
                            kms_key_release_dur_ns,
                            kms_total_dur_ns,
                        };
                        send_keys_with_timing(client_socket, combined_keys, timing);
                        printf("Both keys (dkf + dklabel) sent to worker successfully.\n");
                        printf("  Note: BindLabelToFID enforced by KMS enclave.\n");
                    } else {
                        const char* error_msg = "KEY_GEN_ERROR";
                        send(client_socket, error_msg, strlen(error_msg), 0);
                        printf("Error generating keys (batch). ret=0x%x, batch_ret=%d\n", ret, batch_ret);
                    }
                }
            }
        }
    }
#endif

    free(quote);
    free(fid);
    free(label);
    close(client_socket);
}

void load_policy_from_file(const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) {
        printf("No policy file found (%s), policy enforcement disabled.\n", filename);
        g_policy_enabled = false;
        return;
    }
    
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        // Remove newline
        line[strcspn(line, "\n")] = 0;
        
        // Skip empty lines and comments
        if (line[0] == '\0' || line[0] == '#') continue;
        
        // Parse hex MRENCLAVE (64 hex chars = 32 bytes)
        if (strlen(line) >= 64) {
            uint8_t mrenclave[32];
            for (int i = 0; i < 32; i++) {
                unsigned int byte;
                sscanf(line + i*2, "%2x", &byte);
                mrenclave[i] = (uint8_t)byte;
            }
            add_allowed_mrenclave(mrenclave);
        }
    }
    
    fclose(f);
    
    if (g_num_allowed_enclaves > 0) {
        g_policy_enabled = true;
        printf("Policy enabled with %d allowed MRENCLAVE values.\n", g_num_allowed_enclaves);
    } else {
        printf("No MRENCLAVE entries found in policy file, policy disabled.\n");
        g_policy_enabled = false;
    }
}

int main(int argc, char *argv[]) {
    setbuf(stdout, NULL);
    
    printf("=== SGX KMS with DCAP Quote Verification ===\n");

    std::vector<std::pair<std::string, std::string>> bind_requests;
    bool print_pubkey = false;
    bool bfibe_test = false;
    bool bfibe_public_params = false;
    std::string print_id;
    std::string print_out;
    std::string bfibe_public_out;
    std::string mrenclave_policy_file = "kms_policy.txt";
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--policy-file") == 0) {
            if (i + 1 >= argc) {
                printf("Usage: %s --policy-file <MRENCLAVE_ALLOWLIST_FILE>\n", argv[0]);
                return 1;
            }
            mrenclave_policy_file = argv[i + 1];
            i += 1;
            continue;
        }
        if (strcmp(argv[i], "--bind-label") == 0) {
            if (i + 4 >= argc || strcmp(argv[i + 1], "--fid") != 0 || strcmp(argv[i + 3], "--label") != 0) {
                printf("Usage: %s --bind-label --fid <FID> --label <LABEL> [--bind-label --fid <FID> --label <LABEL> ...]\n", argv[0]);
                return 1;
            }
            bind_requests.emplace_back(argv[i + 2], argv[i + 4]);
            i += 4;
            continue;
        }
        if (strcmp(argv[i], "--print-pubkey") == 0) {
            if (i + 4 >= argc || strcmp(argv[i + 1], "--id") != 0 || strcmp(argv[i + 3], "--out") != 0) {
                printf("Usage: %s --print-pubkey --id <ID> --out <FILE>\n", argv[0]);
                return 1;
            }
            print_pubkey = true;
            print_id = argv[i + 2];
            print_out = argv[i + 4];
            i += 4;
            continue;
        }
        if (strcmp(argv[i], "--bfibe-test") == 0) {
            bfibe_test = true;
            continue;
        }
        if (strcmp(argv[i], "--bfibe-public-params") == 0) {
            if (i + 2 >= argc || strcmp(argv[i + 1], "--out") != 0) {
                printf("Usage: %s --bfibe-public-params --out <FILE>\n", argv[0]);
                return 1;
            }
            bfibe_public_params = true;
            bfibe_public_out = argv[i + 2];
            i += 2;
            continue;
        }
    }

    int one_shot_count = (print_pubkey ? 1 : 0) + (bfibe_test ? 1 : 0) + (bfibe_public_params ? 1 : 0);
    if ((one_shot_count > 0 && !bind_requests.empty()) || one_shot_count > 1) {
        printf("Error: one-shot commands cannot be combined in the same run.\n");
        return 1;
    }
    
    /* Initialize the enclave */
    if(initialize_enclave() < 0) {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1; 
    }
    
    // Load MRENCLAVE policy from file. Missing or empty allow-list means:
    // keep DCAP quote verification enabled, but accept any verified enclave.
    load_policy_from_file(mrenclave_policy_file.c_str());
    
    // Load Sealed Data
    uint8_t* sealed_data = NULL;
    uint32_t sealed_size = 0;
    FILE* f = fopen("kms_data.sealed", "rb");
    if (f) {
        fseek(f, 0, SEEK_END);
        sealed_size = ftell(f);
        fseek(f, 0, SEEK_SET);
        sealed_data = (uint8_t*)malloc(sealed_size);
        fread(sealed_data, 1, sealed_size, f);
        fclose(f);
        printf("Loaded sealed data: %d bytes\n", sealed_size);
    }

    // Prepare buffer for new sealed data
    uint32_t out_sealed_size = 2048; 
    uint8_t* out_sealed_data = (uint8_t*)malloc(out_sealed_size);
    uint32_t actual_sealed_size = 0;

    sgx_status_t ret = ecall_init_kms(global_eid, sealed_data, sealed_size, out_sealed_data, out_sealed_size, &actual_sealed_size);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }

    for (const auto& request : bind_requests) {
        int bind_ret = -1;
        ret = ecall_bind_label_to_fid(global_eid, &bind_ret, request.first.c_str(), request.second.c_str());
        if (ret != SGX_SUCCESS || bind_ret != 0) {
            printf("BindLabelToFID failed: FID=%s label=%s (ret=0x%x, bind_ret=%d)\n",
                   request.first.c_str(), request.second.c_str(), ret, bind_ret);
            return 1;
        }
        printf("BindLabelToFID success: FID=%s label=%s\n", request.first.c_str(), request.second.c_str());
    }

    // Save Sealed Data if generated
    if (actual_sealed_size > 0) {
        f = fopen("kms_data.sealed", "wb");
        if (f) {
            fwrite(out_sealed_data, 1, actual_sealed_size, f);
            fclose(f);
            printf("Saved sealed data: %d bytes\n", actual_sealed_size);
        }
    }

    if (bfibe_test) {
        int test_ret = -1;
        ret = ecall_bfibe_extract_test(global_eid, &test_ret);
        if (ret != SGX_SUCCESS || test_ret != 0) {
            printf("KMS BF-IBE Extract test: FAILED (ret=0x%x, test_ret=%d)\n", ret, test_ret);
            return 1;
        }
        printf("KMS BF-IBE Extract test: PASSED\n");
        if (sealed_data) free(sealed_data);
        if (out_sealed_data) free(out_sealed_data);
        sgx_destroy_enclave(global_eid);
        return 0;
    }

    if (bfibe_public_params) {
        uint8_t bfibe_mpk[256] = {0};
        uint32_t actual_mpk_size = 0;
        int params_ret = -1;
        ret = ecall_get_bfibe_public_params(
            global_eid,
            &params_ret,
            bfibe_mpk,
            sizeof(bfibe_mpk),
            &actual_mpk_size
        );
        if (ret != SGX_SUCCESS || params_ret != 0 || actual_mpk_size == 0) {
            printf("BF-IBE public params export failed (ret=0x%x, params_ret=%d, size=%u)\n",
                   ret, params_ret, actual_mpk_size);
            return 1;
        }
        FILE* out = fopen(bfibe_public_out.c_str(), "wb");
        if (!out) {
            printf("Failed to open output file: %s\n", bfibe_public_out.c_str());
            return 1;
        }
        fwrite(bfibe_mpk, 1, actual_mpk_size, out);
        fclose(out);
        printf("BF-IBE public params written: file=%s size=%u\n",
               bfibe_public_out.c_str(), actual_mpk_size);
        if (sealed_data) free(sealed_data);
        if (out_sealed_data) free(out_sealed_data);
        sgx_destroy_enclave(global_eid);
        return 0;
    }

    if (print_pubkey) {
        uint8_t public_key[65];
        int pk_ret = -1;
        ret = ecall_get_public_key(global_eid, &pk_ret, print_id.c_str(), public_key);
        if (ret != SGX_SUCCESS || pk_ret != 0) {
            printf("Print public key failed: id=%s (ret=0x%x, pk_ret=%d)\n",
                   print_id.c_str(), ret, pk_ret);
            return 1;
        }
        FILE* out = fopen(print_out.c_str(), "wb");
        if (!out) {
            printf("Failed to open output file: %s\n", print_out.c_str());
            return 1;
        }
        fwrite(public_key, 1, sizeof(public_key), out);
        fclose(out);
        printf("Public key written: id=%s file=%s\n", print_id.c_str(), print_out.c_str());
        return 0;
    }

    if (sealed_data) free(sealed_data);
    if (out_sealed_data) free(out_sealed_data);

    // Start Server
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address))<0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    int backlog = kms_listen_backlog();
    if (listen(server_fd, backlog) < 0) {
        perror("listen");
        exit(EXIT_FAILURE);
    }

    printf("\nKMS Server listening on port %d backlog %d\n", PORT, backlog);
    printf("DCAP Quote Verification: ENABLED\n");
    printf("MRENCLAVE Policy: %s\n\n", g_policy_enabled ? "ENABLED" : "DISABLED");

    while(1) {
        if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen))<0) {
            perror("accept");
            exit(EXIT_FAILURE);
        }
        handle_client(new_socket);
    }

    sgx_destroy_enclave(global_eid);
    return 0;
}
