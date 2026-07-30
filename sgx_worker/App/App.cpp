#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "sgx_urts.h"
#include "Enclave_u.h"
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#ifndef SGX_MODE_SIM
#include "sgx_dcap_ql_wrapper.h"
#endif
#include "sgx_report.h"
#include "sgx_error.h"

#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <cpuid.h>
#include <x86intrin.h>
#include <string>
#include <vector>
#include <sstream>
#include <iostream>

// App-side IBE for extensibility demonstration
// (MCL library uses cpuid instruction which is illegal inside SGX enclaves)
#include "app_ibe.h"

#define ENCLAVE_FILENAME "enclave.signed.so"
#define WORKER_QUOTE3_REPORT_BODY_OFFSET 48
#define WORKER_REPORT_BODY_SIZE 384
#define WORKER_REPORT_DATA_OFFSET_IN_BODY 320

sgx_enclave_id_t global_eid = 0;

static const uint32_t C1_TRACE_RID_VALID = 1u << 0;
static const uint32_t C1_TRACE_PAYLOAD_VALID = 1u << 1;
static const uint32_t C1_TRACE_FUNCTION_CACHE_HIT = 1u << 2;
static const uint32_t C1_TRACE_CFUNC_DECRYPT_EXECUTED = 1u << 3;
static const uint32_t C1_TRACE_WORKLOAD_CYCLES_VALID = 1u << 4;
static const uint32_t C1_TRACE_OUTPUT_KEM_CYCLES_VALID = 1u << 5;
static const uint32_t C1_TRACE_OUTPUT_AES_GCM_CYCLES_VALID = 1u << 6;
static const uint32_t C1_TRACE_FUNCTION_CACHE_VALID = 1u << 7;
static const uint32_t C1_TRACE_SUCCESS = 1u << 8;
static const uint32_t ASYNCS_DEFAULT_OUTPUT_CAPACITY_BYTES = 4096;
static const uint32_t ASYNCS_MAX_OUTPUT_CAPACITY_BYTES = 1024u * 1024u;
static const uint32_t C1_TRACE_REQUIRED_FLAGS =
    C1_TRACE_RID_VALID |
    C1_TRACE_PAYLOAD_VALID |
    C1_TRACE_WORKLOAD_CYCLES_VALID |
    C1_TRACE_OUTPUT_KEM_CYCLES_VALID |
    C1_TRACE_OUTPUT_AES_GCM_CYCLES_VALID |
    C1_TRACE_FUNCTION_CACHE_VALID |
    C1_TRACE_SUCCESS;

static uint64_t g_c1_tsc_hz = 0;
static const char* g_c1_tsc_frequency_method = "unavailable";

static void initialize_c1_tsc_frequency() {
    unsigned int denominator = 0;
    unsigned int numerator = 0;
    unsigned int crystal_hz = 0;
    unsigned int unused = 0;
    if (__get_cpuid_max(0, NULL) >= 0x15 &&
        __get_cpuid_count(0x15, 0, &denominator, &numerator, &crystal_hz, &unused) &&
        denominator != 0 && numerator != 0 && crystal_hz != 0) {
        g_c1_tsc_hz = ((uint64_t)crystal_hz * numerator) / denominator;
        g_c1_tsc_frequency_method = "cpuid_0x15_crystal";
        return;
    }

    struct timespec start = {};
    struct timespec end = {};
    struct timespec delay = {0, 20000000};
    unsigned int aux = 0;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &start) != 0) {
        return;
    }
    uint64_t start_cycles = __rdtsc();
    nanosleep(&delay, NULL);
    uint64_t end_cycles = __rdtscp(&aux);
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &end) != 0) {
        return;
    }
    uint64_t elapsed_ns = (uint64_t)(end.tv_sec - start.tv_sec) * 1000000000ULL;
    if (end.tv_nsec >= start.tv_nsec) {
        elapsed_ns += (uint64_t)(end.tv_nsec - start.tv_nsec);
    } else {
        elapsed_ns -= 1000000000ULL;
        elapsed_ns += (uint64_t)(1000000000L + end.tv_nsec - start.tv_nsec);
    }
    if (elapsed_ns > 0 && end_cycles > start_cycles) {
        g_c1_tsc_hz = (uint64_t)(((__uint128_t)(end_cycles - start_cycles) * 1000000000ULL) / elapsed_ns);
        g_c1_tsc_frequency_method = "calibrated_monotonic_raw_20ms";
    }
}

static uint64_t c1_cycles_to_ns(uint64_t cycles, uint64_t tsc_hz) {
    if (tsc_hz == 0) {
        return 0;
    }
    return (uint64_t)(((__uint128_t)cycles * 1000000000ULL) / tsc_hz);
}

static void print_hex_value(const char* prefix, const uint8_t* value, size_t len) {
    printf("%s", prefix);
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", value[i]);
    }
    printf("\n");
}

static const char* kms_host() {
    const char* v = getenv("KMS_HOST");
    return (v && v[0]) ? v : "localhost";
}

static int kms_port() {
    const char* v = getenv("KMS_PORT");
    if (!v || !v[0]) return 3000;
    int p = atoi(v);
    return (p > 0 && p < 65536) ? p : 3000;
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

static int kms_connect_attempts() {
    return env_int_default("KMS_CONNECT_ATTEMPTS", 5, 1, 100);
}

static int kms_connect_retry_sleep_ms() {
    return env_int_default("KMS_CONNECT_RETRY_SLEEP_MS", 50, 0, 60000);
}

static const char* kms_crypto_profile() {
    const char* v = getenv("ASYNCS_CRYPTO_PROFILE");
    return (v && v[0]) ? v : "eccibe";
}

static bool allow_dummy_quote() {
    const char* v = getenv("ACSC_ALLOW_DUMMY_QUOTE");
    return v && strcmp(v, "1") == 0;
}

static void embed_report_in_sim_quote(uint8_t* quote, uint32_t quote_size, const sgx_report_t* report) {
    if (!quote || !report || quote_size < WORKER_QUOTE3_REPORT_BODY_OFFSET + WORKER_REPORT_BODY_SIZE) {
        return;
    }
    size_t report_body_len = sizeof(report->body);
    if (report_body_len > WORKER_REPORT_BODY_SIZE) {
        report_body_len = WORKER_REPORT_BODY_SIZE;
    }
    memcpy(quote + WORKER_QUOTE3_REPORT_BODY_OFFSET, &report->body, report_body_len);
    memcpy(
        quote + WORKER_QUOTE3_REPORT_BODY_OFFSET + WORKER_REPORT_DATA_OFFSET_IN_BODY,
        report->body.report_data.d,
        sizeof(report->body.report_data.d)
    );
}

static void embed_report_in_sim_quote(std::vector<uint8_t>& quote, const sgx_report_t* report) {
    if (quote.empty()) {
        return;
    }
    embed_report_in_sim_quote(quote.data(), (uint32_t)quote.size(), report);
}

static uint64_t now_ns_epoch() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t mono_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static std::string b64_encode(const uint8_t* data, size_t len) {
    std::string out;
    out.resize(((len + 2) / 3) * 4);
    int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(&out[0]), data, (int)len);
    if (n < 0) return std::string();
    out.resize((size_t)n);
    return out;
}

static bool b64_decode(const std::string& in, std::vector<uint8_t>& out) {
    if (in.empty()) return false;
    out.resize(((in.size() + 3) / 4) * 3);
    int n = EVP_DecodeBlock(reinterpret_cast<unsigned char*>(out.data()),
                            reinterpret_cast<const unsigned char*>(in.data()),
                            (int)in.size());
    if (n < 0) return false;
    int pad = 0;
    if (!in.empty() && in.back() == '=') pad++;
    if (in.size() > 1 && in[in.size() - 2] == '=') pad++;
    n -= pad;
    if (n < 0) return false;
    out.resize((size_t)n);
    return true;
}

static bool hex_decode(const std::string& hex, std::vector<uint8_t>& out) {
    if (hex.size() < 2 || (hex.size() % 2) != 0) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        unsigned int byte = 0;
        if (sscanf(hex.c_str() + i, "%2x", &byte) != 1) return false;
        out.push_back((uint8_t)byte);
    }
    return !out.empty();
}

static bool read_exact(int fd, void* buf, size_t len) {
    uint8_t* p = reinterpret_cast<uint8_t*>(buf);
    size_t left = len;
    while (left > 0) {
        ssize_t n = read(fd, p, left);
        if (n <= 0) return false;
        p += n;
        left -= (size_t)n;
    }
    return true;
}

static bool write_exact(int fd, const void* buf, size_t len) {
    const uint8_t* p = reinterpret_cast<const uint8_t*>(buf);
    size_t left = len;
    while (left > 0) {
        ssize_t n = send(fd, p, left, 0);
        if (n <= 0) return false;
        p += n;
        left -= (size_t)n;
    }
    return true;
}

static bool read_u32(int fd, uint32_t* out) {
    uint32_t val = 0;
    if (!read_exact(fd, &val, sizeof(val))) return false;
    *out = val;
    return true;
}

static bool write_u32(int fd, uint32_t val) {
    return write_exact(fd, &val, sizeof(val));
}

static bool is_valid_p256_point_le(const uint8_t* pt_le, size_t len) {
    if (!pt_le || len != 65 || pt_le[0] != 0x04) return false;
    bool all_zero = true;
    for (size_t i = 1; i < len; i++) {
        if (pt_le[i] != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) return false;

    // Convert SGX-style uncompressed point (04 || X_le || Y_le) to standard octets (big-endian).
    uint8_t pt_be[65];
    pt_be[0] = 0x04;
    for (int i = 0; i < 32; i++) pt_be[1 + i] = pt_le[1 + (31 - i)];
    for (int i = 0; i < 32; i++) pt_be[33 + i] = pt_le[33 + (31 - i)];

    bool ok = false;
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) return false;
    EC_POINT* point = EC_POINT_new(group);
    if (!point) {
        EC_GROUP_free(group);
        return false;
    }
    if (EC_POINT_oct2point(group, point, pt_be, sizeof(pt_be), NULL) != 1) goto out;
    if (EC_POINT_is_on_curve(group, point, NULL) != 1) goto out;
    ok = true;
out:
    EC_POINT_free(point);
    EC_GROUP_free(group);
    return ok;
}

static bool is_valid_p256_point_be(const uint8_t* pt_be, size_t len) {
    if (!pt_be || len != 65 || pt_be[0] != 0x04) return false;
    bool all_zero = true;
    for (size_t i = 1; i < len; i++) {
        if (pt_be[i] != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero) return false;

    bool ok = false;
    EC_GROUP* group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) return false;
    EC_POINT* point = EC_POINT_new(group);
    if (!point) {
        EC_GROUP_free(group);
        return false;
    }
    if (EC_POINT_oct2point(group, point, pt_be, len, NULL) != 1) goto out;
    if (EC_POINT_is_on_curve(group, point, NULL) != 1) goto out;
    ok = true;
out:
    EC_POINT_free(point);
    EC_GROUP_free(group);
    return ok;
}

void ocall_print(const char *str) {
    fprintf(stderr, "%s", str);
}

static uint64_t g_worker_wait_kms_dur_ns = 0;
static uint64_t g_kms_verify_dur_ns = 0;
static uint64_t g_kms_key_release_dur_ns = 0;
static uint64_t g_kms_total_dur_ns = 0;
static uint64_t g_quote_gen_dur_ns = 0;
static uint64_t g_kms_send_mono_ns = 0;
static uint64_t g_kms_recv_mono_ns = 0;

static const int KMS_KEYS_LEN = 248;
static const int BFIBE_MAX_RELEASE_LEN = 4096;
static const char BFIBE_KEY_RELEASE_MAGIC[] = "ASBFREL1";
static const int BFIBE_KEY_RELEASE_MAGIC_LEN = 8;
static const uint8_t BFIBE_KEY_RELEASE_VERSION = 1;

struct KmsTimingTrailer {
    uint64_t verify_dur_ns;
    uint64_t key_release_dur_ns;
    uint64_t total_dur_ns;
};
static_assert(sizeof(KmsTimingTrailer) == sizeof(uint64_t) * 3, "KMS timing trailer must be three uint64_t fields");
static const int KMS_TIMING_TRAILER_LEN = (int)sizeof(KmsTimingTrailer);
static const int KMS_RESPONSE_MAX_LEN = BFIBE_MAX_RELEASE_LEN + KMS_TIMING_TRAILER_LEN;

static int read_kms_response(int sock, uint8_t* buffer, size_t capacity) {
    size_t total = 0;
    while (total < capacity) {
        ssize_t n = read(sock, buffer + total, capacity - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (n == 0) break;
        total += (size_t)n;
    }
    return (int)total;
}

static bool is_bfibe_key_release_response(const uint8_t* buffer, int len) {
    if (!buffer || len < BFIBE_KEY_RELEASE_MAGIC_LEN + 1) return false;
    return memcmp(buffer, BFIBE_KEY_RELEASE_MAGIC, BFIBE_KEY_RELEASE_MAGIC_LEN) == 0 &&
           buffer[BFIBE_KEY_RELEASE_MAGIC_LEN] == BFIBE_KEY_RELEASE_VERSION;
}

static bool read_u32_be_host(const uint8_t* buffer, int len, int* offset, uint32_t* out) {
    if (!buffer || !offset || !out || *offset < 0 || *offset > len - 4) return false;
    *out = ((uint32_t)buffer[*offset] << 24) |
           ((uint32_t)buffer[*offset + 1] << 16) |
           ((uint32_t)buffer[*offset + 2] << 8) |
           (uint32_t)buffer[*offset + 3];
    *offset += 4;
    return true;
}

static int bfibe_key_release_payload_len(const uint8_t* buffer, int len) {
    if (!is_bfibe_key_release_response(buffer, len)) return -1;

    int offset = BFIBE_KEY_RELEASE_MAGIC_LEN + 1;
    uint32_t profile_len = 0;
    uint32_t fid_len = 0;
    uint32_t worker_identity_len = 0;
    uint32_t wrap_public_key_len = 0;
    uint32_t nonce_len = 0;
    uint32_t ciphertext_len = 0;
    if (!read_u32_be_host(buffer, len, &offset, &profile_len) ||
        !read_u32_be_host(buffer, len, &offset, &fid_len) ||
        !read_u32_be_host(buffer, len, &offset, &worker_identity_len) ||
        !read_u32_be_host(buffer, len, &offset, &wrap_public_key_len) ||
        !read_u32_be_host(buffer, len, &offset, &nonce_len) ||
        !read_u32_be_host(buffer, len, &offset, &ciphertext_len)) {
        return -1;
    }

    uint64_t release_len = (uint64_t)offset +
                           (uint64_t)profile_len +
                           (uint64_t)fid_len +
                           (uint64_t)worker_identity_len +
                           (uint64_t)wrap_public_key_len +
                           (uint64_t)nonce_len +
                           (uint64_t)ciphertext_len;
    if (release_len > (uint64_t)len || release_len > (uint64_t)BFIBE_MAX_RELEASE_LEN) {
        return -1;
    }
    return (int)release_len;
}

void connect_to_kms(const char* host, int port, uint8_t* quote, uint32_t quote_size, const char* fid, const char* label, uint8_t* public_key) {
    uint64_t wait_begin = mono_ns();
    g_worker_wait_kms_dur_ns = 0;
    g_kms_verify_dur_ns = 0;
    g_kms_key_release_dur_ns = 0;
    g_kms_total_dur_ns = 0;
    g_kms_send_mono_ns = wait_begin; // [# breakpoints]
    g_kms_recv_mono_ns = 0;
    int sock = -1;
    struct addrinfo hints;
    struct addrinfo* res = NULL;
    uint8_t buffer[KMS_RESPONSE_MAX_LEN] = {0};

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    int gai = getaddrinfo(host, port_str, &hints, &res);
    if (gai != 0 || res == NULL) {
        printf("KMS resolve failed: host=%s port=%d err=%s\n", host, port, gai_strerror(gai));
        g_worker_wait_kms_dur_ns = (mono_ns() - wait_begin);
        return;
    }

    int connect_attempts = kms_connect_attempts();
    int retry_sleep_ms = kms_connect_retry_sleep_ms();
    for (int attempt = 1; attempt <= connect_attempts && sock < 0; attempt++) {
        for (struct addrinfo* ai = res; ai != NULL; ai = ai->ai_next) {
            sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
            if (sock < 0) continue;
            if (connect(sock, ai->ai_addr, ai->ai_addrlen) == 0) {
                break;
            }
            close(sock);
            sock = -1;
        }
        if (sock < 0 && attempt < connect_attempts && retry_sleep_ms > 0) {
            long jitter_ms = (long)(mono_ns() % (uint64_t)(retry_sleep_ms + 1));
            long sleep_ms = retry_sleep_ms + jitter_ms;
            printf("KMS connect retry: host=%s port=%d attempt=%d/%d sleep_ms=%ld\n",
                   host, port, attempt, connect_attempts, sleep_ms);
            struct timespec sleep_time;
            sleep_time.tv_sec = sleep_ms / 1000;
            sleep_time.tv_nsec = (sleep_ms % 1000) * 1000000L;
            nanosleep(&sleep_time, NULL);
        }
    }
    freeaddrinfo(res);

    if (sock < 0) {
        printf("KMS connect failed: host=%s port=%d\n", host, port);
        g_worker_wait_kms_dur_ns = (mono_ns() - wait_begin);
        return;
    }

    uint32_t fid_len = strlen(fid);
    uint32_t label_len = strlen(label);
    const char* crypto_profile = kms_crypto_profile();
    uint32_t crypto_profile_len = strlen(crypto_profile);
    if (!write_u32(sock, quote_size) ||
        !write_exact(sock, quote, quote_size) ||
        !write_u32(sock, fid_len) ||
        !write_exact(sock, fid, fid_len) ||
        !write_u32(sock, label_len) ||
        !write_exact(sock, label, label_len) ||
        !write_exact(sock, public_key, 64) ||
        !write_u32(sock, crypto_profile_len) ||
        !write_exact(sock, crypto_profile, crypto_profile_len)) {
        printf("KMS request send failed: host=%s port=%d\n", host, port);
        close(sock);
        g_worker_wait_kms_dur_ns = (mono_ns() - wait_begin);
        return;
    }

    printf("Request sent to KMS (host=%s:%d, FID: %s, label: %s, profile: %s)\n",
           host, port, fid, label, crypto_profile);
    
    int valread = read_kms_response(sock, buffer, sizeof(buffer));
    if (valread > 0) {
        if (is_bfibe_key_release_response(buffer, valread)) {
            int bfibe_release_len = bfibe_key_release_payload_len(buffer, valread);
            if (bfibe_release_len <= 0) {
                printf("KMS Response Error: malformed BF-IBE key-release envelope (%d bytes)\n", valread);
            } else {
                printf("Received BF-IBE key-release envelope from KMS (%d response bytes, %d release bytes).\n",
                       valread, bfibe_release_len);
                int bf_ret = -1;
                sgx_status_t ret = ecall_load_bfibe_key_release(
                    global_eid,
                    &bf_ret,
                    buffer,
                    (uint32_t)bfibe_release_len,
                    fid
                );
                if (ret != SGX_SUCCESS) {
                    printf("Error calling ecall_load_bfibe_key_release: 0x%x\n", ret);
                } else {
                    printf("BF-IBE key-release boundary returned %d.\n", bf_ret);
                }
                if (valread >= bfibe_release_len + KMS_TIMING_TRAILER_LEN) {
                    KmsTimingTrailer timing = {0, 0, 0};
                    memcpy(&timing, buffer + bfibe_release_len, sizeof(timing));
                    g_kms_verify_dur_ns = timing.verify_dur_ns;
                    g_kms_key_release_dur_ns = timing.key_release_dur_ns;
                    g_kms_total_dur_ns = timing.total_dur_ns;
                }
            }
        }
        // Paper-compliant path: KMS sends both dkf (124 bytes) + dklabel (124 bytes) = 248 bytes
        else if (valread >= KMS_KEYS_LEN) {
            printf("Received Encrypted Keys from KMS (dkf + dklabel = %d bytes)\n", valread);
            
            // Split into dkf and dklabel
            uint8_t* encrypted_dkf = buffer;
            uint8_t* encrypted_dklabel = buffer + 124;
            
            // Pass both keys to Enclave for decryption
            ecall_decrypt_keys_batch(global_eid, encrypted_dkf, encrypted_dklabel, fid);
            printf("Both keys (dkf + dklabel) decrypted successfully.\n");
            printf("  Note: dklabel obtained from KMS (BindLabelToFID enforced at KMS side).\n");
            
            // Verify Cache
            int has_key = 0;
            ecall_has_key(global_eid, &has_key, fid);
            if (has_key) {
                printf("Cache Verification: Keys for FID %s are present in Enclave.\n", fid);
            } else {
                printf("Cache Verification: FAILED.\n");
            }
            if (valread >= KMS_KEYS_LEN + KMS_TIMING_TRAILER_LEN) {
                KmsTimingTrailer timing = {0, 0, 0};
                memcpy(&timing, buffer + KMS_KEYS_LEN, sizeof(timing));
                g_kms_verify_dur_ns = timing.verify_dur_ns;
                g_kms_key_release_dur_ns = timing.key_release_dur_ns;
                g_kms_total_dur_ns = timing.total_dur_ns;
            }
        } else if (valread == 124) {
            // Legacy fallback: single key (dkf only)
            printf("WARNING: Received single key from KMS (%d bytes) - legacy path.\n", valread);
            printf("  Note: Local dklabel derivation will be used (BindLabelToFID NOT enforced).\n");
            
            uint8_t decrypted_key[32];
            sgx_status_t ret = ecall_decrypt_key(global_eid, buffer, decrypted_key, fid);
            if (ret != SGX_SUCCESS) {
                printf("Error calling ecall_decrypt_key: 0x%x\n", ret);
            } else {
                printf("Key Decrypted Successfully (legacy single-key path).\n");
            }
        } else {
            printf("KMS Response Error: unexpected size %d\n", valread);
        }
    } else {
        printf("KMS Response Error\n");
    }
    g_kms_recv_mono_ns = mono_ns(); // [# breakpoints]
    close(sock);
    g_worker_wait_kms_dur_ns = (mono_ns() - wait_begin);
}
 

static bool generate_quote_bytes(const char* fid, const char* label, std::vector<uint8_t>& quote_out, uint8_t public_key[64]);

static bool generate_quote_bytes(const char* fid, const char* label, std::vector<uint8_t>& quote_out, uint8_t public_key[64]) {
#ifdef SGX_MODE_SIM
    uint32_t quote_size = 1024;
    quote_out.assign(quote_size, 0xEE);
    sgx_target_info_t dummy_target_info = {0};
    sgx_report_t dummy_report;
    ecall_create_report(global_eid, &dummy_target_info, &dummy_report, public_key);
    embed_report_in_sim_quote(quote_out, &dummy_report);
    (void)fid;
    (void)label;
    return true;
#else
    quote3_error_t qe3_ret = SGX_QL_SUCCESS;
    sgx_status_t status = SGX_SUCCESS;
    sgx_target_info_t qe_target_info;
    sgx_report_t report;
    uint32_t quote_size = 0;
    uint8_t* p_quote_buffer = NULL;

    qe3_ret = sgx_qe_get_target_info(&qe_target_info);
    if (SGX_QL_SUCCESS != qe3_ret) {
        if (qe3_ret == 0xe019 || qe3_ret == 0xe00d) { // SGX_QL_NO_PLATFORM_CERT_DATA or SGX_QL_NETWORK_ERROR
            if (!allow_dummy_quote()) {
                return false;
            }
            quote_size = 1024;
            quote_out.assign(quote_size, 0xDD);
            sgx_target_info_t dummy_target_info = {0};
            sgx_report_t dummy_report;
            ecall_create_report(global_eid, &dummy_target_info, &dummy_report, public_key);
            embed_report_in_sim_quote(quote_out, &dummy_report);
            (void)fid;
            (void)label;
            return true;
        }
        return false;
    }

    status = ecall_create_report(global_eid, &qe_target_info, &report, public_key);
    if (status != SGX_SUCCESS) {
        return false;
    }

    qe3_ret = sgx_qe_get_quote_size(&quote_size);
    if (SGX_QL_SUCCESS != qe3_ret) {
        return false;
    }

    p_quote_buffer = (uint8_t*)malloc(quote_size);
    if (!p_quote_buffer) return false;
    memset(p_quote_buffer, 0, quote_size);

    qe3_ret = sgx_qe_get_quote(&report, quote_size, p_quote_buffer);
    if (SGX_QL_SUCCESS != qe3_ret) {
        free(p_quote_buffer);
        return false;
    }

    quote_out.assign(p_quote_buffer, p_quote_buffer + quote_size);
    free(p_quote_buffer);
    (void)fid;
    (void)label;
    return true;
#endif
}

#ifdef SGX_MODE_SIM
void generate_quote(const char* fid, const char* label) {
    printf("Generating Quote (SIMULATION MODE)...\n");
    g_quote_gen_dur_ns = 0;
    uint64_t quote_begin = mono_ns();
    uint32_t quote_size = 1024;
    uint8_t* p_quote_buffer = (uint8_t*)malloc(quote_size);
    if (p_quote_buffer) {
        memset(p_quote_buffer, 0xEE, quote_size); // Fill with 0xEE for SIM

        // Generate Key Pair in Enclave
        sgx_target_info_t dummy_target_info = {0};
        sgx_report_t dummy_report;
        uint8_t public_key[64];
        ecall_create_report(global_eid, &dummy_target_info, &dummy_report, public_key);
        embed_report_in_sim_quote(p_quote_buffer, quote_size, &dummy_report);
        printf("Generated Public Key in Enclave.\n");
        g_quote_gen_dur_ns = mono_ns() - quote_begin;

        // Connect to KMS
        connect_to_kms(kms_host(), kms_port(), p_quote_buffer, quote_size, fid, label, public_key);

        free(p_quote_buffer);
    }
}
#else
void generate_quote(const char* fid, const char* label) {
    quote3_error_t qe3_ret = SGX_QL_SUCCESS;
    sgx_status_t status = SGX_SUCCESS;
    sgx_target_info_t qe_target_info;
    sgx_report_data_t report_data = {0};
    sgx_report_t report;
    uint32_t quote_size = 0;
    uint8_t* p_quote_buffer = NULL;

    printf("Generating Quote...\n");
    g_quote_gen_dur_ns = 0;
    uint64_t quote_begin = mono_ns();

    // 1. Init Quote (get target info)
    qe3_ret = sgx_qe_get_target_info(&qe_target_info);
    if (SGX_QL_SUCCESS != qe3_ret) {
        printf("Error in sgx_qe_get_target_info. 0x%04x\n", qe3_ret);

        if (qe3_ret == 0xe019 || qe3_ret == 0xe00d) { // SGX_QL_NO_PLATFORM_CERT_DATA or SGX_QL_NETWORK_ERROR
            if (!allow_dummy_quote()) {
                printf("ERROR: DCAP PCCS unavailable; dummy quote fallback disabled (task.md HW-only).\n");
                exit(2);
            }
            printf("WARNING: Generating DUMMY QUOTE (ACSC_ALLOW_DUMMY_QUOTE=1). NOT PAPER-COMPLIANT.\n");
            quote_size = 1024;
            p_quote_buffer = (uint8_t*)malloc(quote_size);
            if (p_quote_buffer) {
                memset(p_quote_buffer, 0xDD, quote_size);
                sgx_target_info_t dummy_target_info = {0};
                sgx_report_t dummy_report;
                uint8_t public_key[64];
                ecall_create_report(global_eid, &dummy_target_info, &dummy_report, public_key);
                embed_report_in_sim_quote(p_quote_buffer, quote_size, &dummy_report);
                connect_to_kms(kms_host(), kms_port(), p_quote_buffer, quote_size, fid, label, public_key);
                free(p_quote_buffer);
            }
            return;
        }
        exit(2);
    }
    printf("sgx_qe_get_target_info success\n");

    // 2. Get Report from Enclave
    uint8_t public_key[64];
    status = ecall_create_report(global_eid, &qe_target_info, &report, public_key);
    if (status != SGX_SUCCESS) {
        printf("Error in ecall_create_report. 0x%04x\n", status);
        return;
    }
    printf("ecall_create_report success. Public Key generated.\n");

    // 3. Get Quote Size
    qe3_ret = sgx_qe_get_quote_size(&quote_size);
    if (SGX_QL_SUCCESS != qe3_ret) {
        printf("Error in sgx_qe_get_quote_size. 0x%04x\n", qe3_ret);
        return;
    }
    printf("Quote size: %d\n", quote_size);

    // 4. Get Quote
    p_quote_buffer = (uint8_t*)malloc(quote_size);
    if (NULL == p_quote_buffer) {
        printf("Couldn't allocate quote buffer\n");
        return;
    }
    memset(p_quote_buffer, 0, quote_size);

    qe3_ret = sgx_qe_get_quote(&report, quote_size, p_quote_buffer);
    if (SGX_QL_SUCCESS != qe3_ret) {
        printf("Error in sgx_qe_get_quote. 0x%04x\n", qe3_ret);
        free(p_quote_buffer);
        return;
    }
    printf("sgx_qe_get_quote success\n");
    g_quote_gen_dur_ns = mono_ns() - quote_begin;

    // Print first few bytes of quote
    printf("Quote generated successfully. First 32 bytes:\n");
    for(int i=0; i<32 && i<quote_size; i++) {
        printf("%02x", p_quote_buffer[i]);
    }
    printf("\n");

    // Connect to KMS
    connect_to_kms(kms_host(), kms_port(), p_quote_buffer, quote_size, fid, label, public_key);

    free(p_quote_buffer);
}
#endif

char* read_file_to_buffer(const char* filename, uint32_t* size) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char* buffer = (char*)malloc(file_size);
    if (!buffer) {
        fclose(file);
        return NULL;
    }

    fread(buffer, 1, file_size, file);
    fclose(file);

    *size = (uint32_t)file_size;
    return buffer;
}

int encrypt_aes_gcm(const uint8_t *plaintext, int plaintext_len,
                    const uint8_t *key, const uint8_t *iv, int iv_len,
                    uint8_t *ciphertext, uint8_t *tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) return -1;

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) return -1;
    if(1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) return -1;

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) return -1;
    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return -1;
    ciphertext_len += len;

    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) return -1;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decrypt_aes_gcm(const uint8_t *ciphertext, int ciphertext_len,
                    const uint8_t *key, const uint8_t *iv, int iv_len,
                    const uint8_t *tag, uint8_t *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;
    int ret;

    if(!(ctx = EVP_CIPHER_CTX_new())) return -1;

    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) return -1;
    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) return -1;

    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) return -1;
    plaintext_len = len;

    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void*)tag)) return -1;

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    } else {
        return -1;
    }
}

struct InvokeArgs {
    std::string fid;
    std::string wasm_file;
    std::string input_file;
    std::string label;
    std::string c_k_func_file;
    std::string c_key_file;
    std::string pku_file;
    std::string nonce_file;
    uint32_t max_output_bytes;
};

static void split_tokens(const std::string& line, std::vector<std::string>& out) {
    out.clear();
    std::istringstream iss(line);
    std::string tok;
    while (iss >> tok) {
        out.push_back(tok);
    }
}

static bool parse_invoke_tokens(const std::vector<std::string>& tokens, InvokeArgs& out, std::string& err) {
    if (tokens.size() < 4) {
        err = "Usage: invoke <fid> <encrypted_wasm_file> <encrypted_input_file> [--label <label>] [--max-output-bytes <bytes>] --keys <C_k_func_file> <C_key_file> [pkU_file nonce_file]";
        return false;
    }
    out.fid = tokens[1];
    out.wasm_file = tokens[2];
    out.input_file = tokens[3];
    out.label = "default_label";
    out.c_k_func_file.clear();
    out.c_key_file.clear();
    out.pku_file.clear();
    out.nonce_file.clear();
    out.max_output_bytes = ASYNCS_DEFAULT_OUTPUT_CAPACITY_BYTES;

    size_t idx = 4;
    while (idx < tokens.size()) {
        if (tokens[idx] == "--label") {
            if (idx + 1 >= tokens.size()) {
                err = "Usage: invoke ... --label <label>";
                return false;
            }
            out.label = tokens[idx + 1];
            idx += 2;
            continue;
        }
        if (tokens[idx] == "--keys") {
            if (idx + 2 >= tokens.size()) {
                err = "Usage: invoke ... --keys <C_k_func_file> <C_key_file>";
                return false;
            }
            out.c_k_func_file = tokens[idx + 1];
            out.c_key_file = tokens[idx + 2];
            idx += 3;
            continue;
        }
        if (tokens[idx] == "--max-output-bytes") {
            if (idx + 1 >= tokens.size()) {
                err = "Usage: invoke ... --max-output-bytes <bytes>";
                return false;
            }
            errno = 0;
            char* end = NULL;
            unsigned long parsed = strtoul(tokens[idx + 1].c_str(), &end, 10);
            if (errno != 0 || end == tokens[idx + 1].c_str() || *end != '\0' ||
                parsed == 0 || parsed > ASYNCS_MAX_OUTPUT_CAPACITY_BYTES) {
                err = "Error: --max-output-bytes must be between 1 and 1048576.";
                return false;
            }
            out.max_output_bytes = (uint32_t)parsed;
            idx += 2;
            continue;
        }
        break;
    }

    if (out.c_k_func_file.empty() || out.c_key_file.empty()) {
        err = "Error: Missing --keys <C_k_func_file> <C_key_file> (required for G3).";
        return false;
    }

    size_t remaining = tokens.size() - idx;
    if (remaining == 0) {
        return true;
    }
    if (remaining == 2) {
        out.pku_file = tokens[idx];
        out.nonce_file = tokens[idx + 1];
        return true;
    }
    err = "Usage: invoke <fid> <encrypted_wasm_file> <encrypted_input_file> [--label <label>] [--max-output-bytes <bytes>] --keys <C_k_func_file> <C_key_file> [pkU_file nonce_file]";
    return false;
}

static int do_invoke(const InvokeArgs& args, bool allow_kms_cache) {
    uint64_t t_worker_invoke_begin_mono_ns = mono_ns();
    const char* fid = args.fid.c_str();
    const char* wasm_file = args.wasm_file.c_str();
    const char* input_file = args.input_file.c_str();
    const char* label = args.label.c_str();
    const char* c_k_func_file = args.c_k_func_file.c_str();
    const char* c_key_file = args.c_key_file.c_str();
    const char* pku_file = args.pku_file.empty() ? NULL : args.pku_file.c_str();
    const char* nonce_file = args.nonce_file.empty() ? NULL : args.nonce_file.c_str();
    const uint32_t max_output_bytes = args.max_output_bytes;

    bool need_kms = true;
    if (allow_kms_cache) {
        int has_key = 0;
        sgx_status_t has_ret = ecall_has_key(global_eid, &has_key, fid);
        if (has_ret == SGX_SUCCESS && has_key == 1) {
            need_kms = false;
        }
    }
    printf("ENCLAVE_KEY_CACHE_HIT:%d\n", need_kms ? 0 : 1);
    printf("KMS_CONTACTED:%d\n", need_kms ? 1 : 0);
    fflush(stdout);

    g_kms_send_mono_ns = 0;
    g_kms_recv_mono_ns = 0;
    g_worker_wait_kms_dur_ns = 0;
    g_kms_verify_dur_ns = 0;
    g_kms_key_release_dur_ns = 0;
    g_kms_total_dur_ns = 0;
    g_quote_gen_dur_ns = 0;

    uint64_t t_keypath_begin_mono_ns = mono_ns();
    uint64_t t_keypath_begin_ns = now_ns_epoch(); // [# breakpoints]
    if (need_kms) {
        generate_quote(fid, label);
    }
    uint64_t t_keypath_end_ns = now_ns_epoch(); // [# breakpoints]
    uint64_t t_keypath_end_mono_ns = mono_ns();
    uint64_t worker_keypath_dur_ns = t_keypath_end_mono_ns - t_keypath_begin_mono_ns;
    printf("T_KEYPATH_BEGIN_NS:%llu\n", (unsigned long long)t_keypath_begin_ns); // [# breakpoints]
    printf("T_KEYPATH_END_NS:%llu\n", (unsigned long long)t_keypath_end_ns); // [# breakpoints]
    printf("WORKER_KEYPATH_DUR_NS:%llu\n", (unsigned long long)worker_keypath_dur_ns);
    printf("WORKER_WAIT_KMS_DUR_NS:%llu\n", (unsigned long long)g_worker_wait_kms_dur_ns); // [# breakpoints]
    printf("KMS_VERIFY_DUR_NS:%llu\n", (unsigned long long)g_kms_verify_dur_ns); // [# breakpoints]
    printf("KMS_KEY_RELEASE_DUR_NS:%llu\n", (unsigned long long)g_kms_key_release_dur_ns); // [# breakpoints]
    printf("KMS_TOTAL_DUR_NS:%llu\n", (unsigned long long)g_kms_total_dur_ns); // [# breakpoints]
    printf("QUOTE_GEN_DUR_NS:%llu\n", (unsigned long long)g_quote_gen_dur_ns); // [# breakpoints]
    printf("T_KMS_SEND_MONO_NS:%llu\n", (unsigned long long)g_kms_send_mono_ns); // [# breakpoints]
    printf("T_KMS_RECV_MONO_NS:%llu\n", (unsigned long long)g_kms_recv_mono_ns); // [# breakpoints]
    fflush(stdout);

    int rc = -1;
    char* wasm_buffer = NULL;
    char* input_buffer = NULL;
    char* c_k_func_buf = NULL;
    char* c_key_buf = NULL;
    char* pku_buf = NULL;
    char* nonce_buf = NULL;
    uint8_t* wasm_iv = NULL;
    uint8_t* wasm_tag = NULL;
    uint8_t* wasm_ciphertext = NULL;
    uint32_t wasm_ciphertext_len = 0;
    uint8_t* input_iv = NULL;
    uint8_t* input_tag = NULL;
    uint8_t* input_ciphertext = NULL;
    uint32_t input_ciphertext_len = 0;
    uint32_t wasm_size = 0;
    uint32_t input_size = 0;
    uint32_t c_k_func_size = 0;
    uint32_t c_key_size = 0;
    std::vector<uint8_t> encrypted_result(max_output_bytes);
    uint32_t result_size = 0;
    uint8_t result_tag[16];
    uint8_t result_iv[12];
    uint8_t kem_ct[65];
    c1_asyncs_invoke_trace_t invoke_trace = {};
    bool used_kem = false;
    uint64_t t_exec_begin_ns = 0;
    uint64_t t_exec_end_ns = 0;
    uint64_t t_exec_begin_mono_ns = 0;
    uint64_t t_exec_end_mono_ns = 0;
    uint64_t worker_exec_dur_ns = 0;
    uint64_t worker_invoke_dur_ns = 0;
    int saved_stdin = -1;
    int stdin_pipe[2] = {-1, -1};
    bool stdin_swapped = false;

    wasm_buffer = read_file_to_buffer(wasm_file, &wasm_size);
    if (!wasm_buffer) {
        printf("Failed to read WASM file: %s\n", wasm_file);
        goto cleanup;
    }
    if (wasm_size < 28) {
        printf("Invalid Encrypted WASM file size.\n");
        goto cleanup;
    }
    wasm_iv = (uint8_t*)wasm_buffer;
    wasm_tag = (uint8_t*)wasm_buffer + 12;
    wasm_ciphertext = (uint8_t*)wasm_buffer + 28;
    wasm_ciphertext_len = wasm_size - 28;

    input_buffer = read_file_to_buffer(input_file, &input_size);
    if (!input_buffer) {
        printf("Failed to read Input file: %s\n", input_file);
        goto cleanup;
    }
    if (input_size < 28) {
        printf("Invalid Encrypted Input file size.\n");
        goto cleanup;
    }
    input_iv = (uint8_t*)input_buffer;
    input_tag = (uint8_t*)input_buffer + 12;
    input_ciphertext = (uint8_t*)input_buffer + 28;
    input_ciphertext_len = input_size - 28;

    c_k_func_buf = read_file_to_buffer(c_k_func_file, &c_k_func_size);
    if (!c_k_func_buf || c_k_func_size < 65 + 12 + 16 + 16) {
        printf("Invalid C_k_func file: %s (expected epk65||iv12||tag16||ct)\n", c_k_func_file);
        goto cleanup;
    }

    c_key_buf = read_file_to_buffer(c_key_file, &c_key_size);
    if (!c_key_buf || c_key_size < 65 + 12 + 16 + 16) {
        printf("Invalid C_key file: %s (expected epk65||iv12||tag16||ct)\n", c_key_file);
        goto cleanup;
    }

    if (pipe(stdin_pipe) == 0) {
        close(stdin_pipe[1]);  // empty stdin => EOF to WASM
        saved_stdin = dup(STDIN_FILENO);
        if (saved_stdin >= 0) {
            dup2(stdin_pipe[0], STDIN_FILENO);
            stdin_swapped = true;
        }
        close(stdin_pipe[0]);
    }

    t_exec_begin_mono_ns = mono_ns();
    t_exec_begin_ns = now_ns_epoch(); // [# breakpoints]
    if (pku_file != NULL || nonce_file != NULL) {
        if (pku_file == NULL || nonce_file == NULL) {
            printf("If providing pkU/nonce, both pkU_file and nonce_file must be provided.\n");
            goto cleanup;
        }

        uint32_t pku_size = 0;
        pku_buf = read_file_to_buffer(pku_file, &pku_size);
        if (!pku_buf || pku_size != 65) {
            printf("Invalid pkU file: %s (expected 65 bytes uncompressed P-256 key)\n", pku_file);
            goto cleanup;
        }

        uint32_t nonce_size = 0;
        nonce_buf = read_file_to_buffer(nonce_file, &nonce_size);
        if (!nonce_buf || nonce_size != 16) {
            printf("Invalid nonce file: %s (expected 16 bytes)\n", nonce_file);
            goto cleanup;
        }

        used_kem = true;
        memset(kem_ct, 0, sizeof(kem_ct));
        sgx_status_t ecall_st = ecall_run_encrypted_wasm_kem(
            global_eid,
            (uint8_t*)wasm_ciphertext, wasm_ciphertext_len,
            (uint8_t*)input_ciphertext, input_ciphertext_len,
            (uint8_t*)c_k_func_buf, c_k_func_size,
            (uint8_t*)c_key_buf, c_key_size,
            (uint8_t*)nonce_buf,
            (uint8_t*)pku_buf,
            encrypted_result.data(), max_output_bytes, &result_size,
            result_tag, result_iv,
            kem_ct,
            &invoke_trace,
            wasm_iv, wasm_tag,
            input_iv, input_tag
        );
        if (ecall_st != SGX_SUCCESS) {
            fprintf(stderr, "ecall_run_encrypted_wasm_kem failed: 0x%x\n", ecall_st);
            fflush(stderr);
            goto cleanup;
        }
        if (!is_valid_p256_point_be(kem_ct, sizeof(kem_ct))) {
            fprintf(stderr, "Invalid kem_ct produced by enclave (rejecting).\n");
            fflush(stderr);
            goto cleanup;
        }
        if (invoke_trace.version != 1 ||
            (invoke_trace.flags & C1_TRACE_REQUIRED_FLAGS) != C1_TRACE_REQUIRED_FLAGS) {
            fprintf(stderr,
                    "Incomplete bounded invocation trace: version=%u flags=0x%x required=0x%x\n",
                    invoke_trace.version,
                    invoke_trace.flags,
                    C1_TRACE_REQUIRED_FLAGS);
            fflush(stderr);
            goto cleanup;
        }
    } else {
        uint8_t zero_nonce[16] = {0};
        uint8_t zero_pku[65] = {0};
        sgx_status_t ecall_st = ecall_run_encrypted_wasm(
            global_eid,
            (uint8_t*)wasm_ciphertext, wasm_ciphertext_len,
            (uint8_t*)input_ciphertext, input_ciphertext_len,
            (uint8_t*)c_k_func_buf, c_k_func_size,
            (uint8_t*)c_key_buf, c_key_size,
            zero_nonce,
            zero_pku,
            encrypted_result.data(), max_output_bytes, &result_size,
            result_tag, result_iv,
            wasm_iv, wasm_tag,
            input_iv, input_tag
        );
        if (ecall_st != SGX_SUCCESS) {
            fprintf(stderr, "ecall_run_encrypted_wasm failed: 0x%x\n", ecall_st);
            fflush(stderr);
            goto cleanup;
        }
    }
    if (stdin_swapped && saved_stdin >= 0) {
        dup2(saved_stdin, STDIN_FILENO);
        close(saved_stdin);
        stdin_swapped = false;
    }
    t_exec_end_ns = now_ns_epoch(); // [# breakpoints]
    t_exec_end_mono_ns = mono_ns();
    worker_exec_dur_ns = t_exec_end_mono_ns - t_exec_begin_mono_ns;
    worker_invoke_dur_ns = mono_ns() - t_worker_invoke_begin_mono_ns;
    if (used_kem) {
        uint64_t tsc_hz = g_c1_tsc_hz;
        uint64_t input_key_decap_duration_ns = c1_cycles_to_ns(invoke_trace.input_key_decap_cycles, tsc_hz);
        uint64_t input_aes_gcm_duration_ns = c1_cycles_to_ns(invoke_trace.input_aes_gcm_cycles, tsc_hz);
        uint64_t workload_core_duration_ns = c1_cycles_to_ns(invoke_trace.workload_core_cycles, tsc_hz);
        uint64_t output_kem_duration_ns = c1_cycles_to_ns(invoke_trace.output_kem_cycles, tsc_hz);
        uint64_t output_aes_gcm_duration_ns = c1_cycles_to_ns(invoke_trace.output_aes_gcm_cycles, tsc_hz);
        uint64_t function_key_decap_duration_ns =
            c1_cycles_to_ns(invoke_trace.function_key_decap_cycles, tsc_hz);
        uint64_t cfunc_aes_gcm_duration_ns =
            c1_cycles_to_ns(invoke_trace.cfunc_aes_gcm_cycles, tsc_hz);
        uint64_t wasm_load_duration_ns = c1_cycles_to_ns(invoke_trace.wasm_load_cycles, tsc_hz);
        uint64_t wasm_instantiate_duration_ns =
            c1_cycles_to_ns(invoke_trace.wasm_instantiate_cycles, tsc_hz);
        print_hex_value("RID_HEX:", invoke_trace.rid, sizeof(invoke_trace.rid));
        printf("ACSC_TRACE_E3_PAYLOAD:payload_bytes_consumed=%u payload_sha256=",
               invoke_trace.payload_bytes_consumed);
        for (size_t i = 0; i < sizeof(invoke_trace.payload_sha256); ++i) {
            printf("%02x", invoke_trace.payload_sha256[i]);
        }
        printf("\n");
        printf("ACSC_TRACE_FUNCTION_CACHE:function_cache_hit=%d cfunc_decrypt_executed=%d function_cache_bytes=%u\n",
               (invoke_trace.flags & C1_TRACE_FUNCTION_CACHE_HIT) ? 1 : 0,
               (invoke_trace.flags & C1_TRACE_CFUNC_DECRYPT_EXECUTED) ? 1 : 0,
               invoke_trace.function_cache_bytes);
        printf("ACSC_TRACE_INTERNAL_TIMING:"
               "workload_timing_schema=enclave-rdtsc-v1 "
               "input_key_decap_begin_cycles=%llu "
               "input_key_decap_end_cycles=%llu "
               "input_aes_gcm_begin_cycles=%llu "
               "input_aes_gcm_end_cycles=%llu "
               "workload_begin_cycles=%llu "
               "workload_end_cycles=%llu "
               "output_kem_begin_cycles=%llu "
               "output_kem_end_cycles=%llu "
               "output_aes_gcm_begin_cycles=%llu "
               "output_aes_gcm_end_cycles=%llu "
               "function_key_decap_begin_cycles=%llu "
               "function_key_decap_end_cycles=%llu "
               "cfunc_aes_gcm_begin_cycles=%llu "
               "cfunc_aes_gcm_end_cycles=%llu "
               "wasm_load_begin_cycles=%llu "
               "wasm_load_end_cycles=%llu "
               "wasm_instantiate_begin_cycles=%llu "
               "wasm_instantiate_end_cycles=%llu "
               "input_key_decap_cycles=%llu "
               "input_aes_gcm_cycles=%llu "
               "workload_core_cycles=%llu "
               "output_kem_cycles=%llu "
               "output_aes_gcm_cycles=%llu "
               "function_key_decap_cycles=%llu "
               "cfunc_aes_gcm_cycles=%llu "
               "wasm_load_cycles=%llu "
               "wasm_instantiate_cycles=%llu "
               "tsc_hz=%llu "
               "tsc_frequency_method=%s "
               "input_key_decap_duration_ns=%llu "
               "input_aes_gcm_duration_ns=%llu "
               "workload_core_duration_ns=%llu "
               "output_kem_duration_ns=%llu "
               "output_aes_gcm_duration_ns=%llu "
               "function_key_decap_duration_ns=%llu "
               "cfunc_aes_gcm_duration_ns=%llu "
               "wasm_load_duration_ns=%llu "
               "wasm_instantiate_duration_ns=%llu\n",
               (unsigned long long)invoke_trace.input_key_decap_begin_cycles,
               (unsigned long long)invoke_trace.input_key_decap_end_cycles,
               (unsigned long long)invoke_trace.input_aes_gcm_begin_cycles,
               (unsigned long long)invoke_trace.input_aes_gcm_end_cycles,
               (unsigned long long)invoke_trace.workload_begin_cycles,
               (unsigned long long)invoke_trace.workload_end_cycles,
               (unsigned long long)invoke_trace.output_kem_begin_cycles,
               (unsigned long long)invoke_trace.output_kem_end_cycles,
               (unsigned long long)invoke_trace.output_aes_gcm_begin_cycles,
               (unsigned long long)invoke_trace.output_aes_gcm_end_cycles,
               (unsigned long long)invoke_trace.function_key_decap_begin_cycles,
               (unsigned long long)invoke_trace.function_key_decap_end_cycles,
               (unsigned long long)invoke_trace.cfunc_aes_gcm_begin_cycles,
               (unsigned long long)invoke_trace.cfunc_aes_gcm_end_cycles,
               (unsigned long long)invoke_trace.wasm_load_begin_cycles,
               (unsigned long long)invoke_trace.wasm_load_end_cycles,
               (unsigned long long)invoke_trace.wasm_instantiate_begin_cycles,
               (unsigned long long)invoke_trace.wasm_instantiate_end_cycles,
               (unsigned long long)invoke_trace.input_key_decap_cycles,
               (unsigned long long)invoke_trace.input_aes_gcm_cycles,
               (unsigned long long)invoke_trace.workload_core_cycles,
               (unsigned long long)invoke_trace.output_kem_cycles,
               (unsigned long long)invoke_trace.output_aes_gcm_cycles,
               (unsigned long long)invoke_trace.function_key_decap_cycles,
               (unsigned long long)invoke_trace.cfunc_aes_gcm_cycles,
               (unsigned long long)invoke_trace.wasm_load_cycles,
               (unsigned long long)invoke_trace.wasm_instantiate_cycles,
               (unsigned long long)tsc_hz,
               g_c1_tsc_frequency_method,
               (unsigned long long)input_key_decap_duration_ns,
               (unsigned long long)input_aes_gcm_duration_ns,
               (unsigned long long)workload_core_duration_ns,
               (unsigned long long)output_kem_duration_ns,
               (unsigned long long)output_aes_gcm_duration_ns,
               (unsigned long long)function_key_decap_duration_ns,
               (unsigned long long)cfunc_aes_gcm_duration_ns,
               (unsigned long long)wasm_load_duration_ns,
               (unsigned long long)wasm_instantiate_duration_ns);
        fflush(stdout);
    }
    printf("T_EXEC_BEGIN_NS:%llu\n", (unsigned long long)t_exec_begin_ns); // [# breakpoints]
    printf("T_EXEC_END_NS:%llu\n", (unsigned long long)t_exec_end_ns); // [# breakpoints]
    printf("T_EXEC_BEGIN_MONO_NS:%llu\n", (unsigned long long)t_exec_begin_mono_ns); // [# breakpoints]
    printf("T_EXEC_END_MONO_NS:%llu\n", (unsigned long long)t_exec_end_mono_ns); // [# breakpoints]
    printf("WORKER_EXEC_DUR_NS:%llu\n", (unsigned long long)worker_exec_dur_ns);
    printf("WORKER_INVOKE_DUR_NS:%llu\n", (unsigned long long)worker_invoke_dur_ns);
    printf("ACSC_TRACE_WORKER_INVOKE:"
           "key_cache_hit=%d "
           "kms_contacted=%d "
           "keypath_dur_ns=%llu "
           "kms_wait_dur_ns=%llu "
           "kms_verify_dur_ns=%llu "
           "kms_key_release_dur_ns=%llu "
           "kms_total_dur_ns=%llu "
           "quote_gen_dur_ns=%llu "
           "exec_ecall_dur_ns=%llu "
           "invoke_total_dur_ns=%llu "
           "wasm_bytes=%u "
           "input_bytes=%u "
           "result_bytes=%u "
           "output_capacity_bytes=%u "
           "rc=%d\n",
           need_kms ? 0 : 1,
           need_kms ? 1 : 0,
           (unsigned long long)worker_keypath_dur_ns,
           (unsigned long long)g_worker_wait_kms_dur_ns,
           (unsigned long long)g_kms_verify_dur_ns,
           (unsigned long long)g_kms_key_release_dur_ns,
           (unsigned long long)g_kms_total_dur_ns,
           (unsigned long long)g_quote_gen_dur_ns,
           (unsigned long long)worker_exec_dur_ns,
           (unsigned long long)worker_invoke_dur_ns,
           (unsigned int)wasm_ciphertext_len,
           (unsigned int)input_ciphertext_len,
           (unsigned int)result_size,
           (unsigned int)max_output_bytes,
           0);
    fflush(stdout);

    fprintf(stderr, "Encrypted Result Size: %d\n", result_size);
    if (used_kem) {
        printf("CT_HEX:");
        for (int i = 0; i < 65; i++) printf("%02x", kem_ct[i]);
        printf("\n");
    }
    printf("RESULT_HEX:");
    for (int i = 0; i < 12; i++) printf("%02x", result_iv[i]);
    for (int i = 0; i < 16; i++) printf("%02x", result_tag[i]);
    for (uint32_t i = 0; i < result_size; i++) printf("%02x", encrypted_result[i]);
    printf("\n");
    fflush(stdout);
    fprintf(stderr, "Loop finished.\n");
    fflush(stderr);

    rc = 0;

cleanup:
    if (stdin_swapped && saved_stdin >= 0) {
        dup2(saved_stdin, STDIN_FILENO);
        close(saved_stdin);
    }
    if (nonce_buf) free(nonce_buf);
    if (pku_buf) free(pku_buf);
    if (c_key_buf) free(c_key_buf);
    if (c_k_func_buf) free(c_k_func_buf);
    if (input_buffer) free(input_buffer);
    if (wasm_buffer) free(wasm_buffer);
    return rc;
}

static int do_run_wasm(const std::string& wasm_file, const std::string& input_file) {
    uint32_t wasm_size = 0;
    char* wasm_buffer = read_file_to_buffer(wasm_file.c_str(), &wasm_size);
    if (!wasm_buffer) {
        printf("ERROR: failed_to_read_wasm:%s\n", wasm_file.c_str());
        return -1;
    }

    char* input_buffer = NULL;
    uint32_t input_size = 0;
    if (!input_file.empty()) {
        input_buffer = read_file_to_buffer(input_file.c_str(), &input_size);
        if (!input_buffer) {
            printf("ERROR: failed_to_read_input:%s\n", input_file.c_str());
            free(wasm_buffer);
            return -1;
        }
    }

    int saved_stdin = -1;
    int pipefd[2] = {-1, -1};
    if (input_buffer) {
        if (pipe(pipefd) != 0) {
            printf("ERROR: stdin_pipe_failed\n");
            free(input_buffer);
            free(wasm_buffer);
            return -1;
        }
        if (input_size > 0) {
            ssize_t wrote = write(pipefd[1], input_buffer, input_size);
            (void)wrote;
        }
        close(pipefd[1]);
        saved_stdin = dup(STDIN_FILENO);
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[0]);
    }

    uint64_t t_exec_begin_ns = now_ns_epoch(); // [# breakpoints]
    ecall_run_wasm(global_eid, (uint8_t*)wasm_buffer, wasm_size);
    uint64_t t_exec_end_ns = now_ns_epoch(); // [# breakpoints]
    printf("T_EXEC_BEGIN_NS:%llu\n", (unsigned long long)t_exec_begin_ns); // [# breakpoints]
    printf("T_EXEC_END_NS:%llu\n", (unsigned long long)t_exec_end_ns); // [# breakpoints]
    fflush(stdout);

    if (saved_stdin >= 0) {
        dup2(saved_stdin, STDIN_FILENO);
        close(saved_stdin);
    }

    if (input_buffer) {
        free(input_buffer);
    }
    free(wasm_buffer);
    return 0;
}

static int run_server_loop() {
    printf("SERVER_READY\n");
    fflush(stdout);
    std::string line;
    while (std::getline(std::cin, line)) {
        if (line == "exit") break;
        if (line.empty()) continue;
        std::vector<std::string> tokens;
        split_tokens(line, tokens);
        if (tokens.empty()) continue;
        if (tokens[0] == "invoke") {
            InvokeArgs args;
            std::string err;
            printf("BEGIN_RESPONSE\n");
            if (!parse_invoke_tokens(tokens, args, err)) {
                printf("ERROR:%s\n", err.c_str());
                printf("RC:-1\n");
                printf("END_RESPONSE\n");
                fflush(stdout);
                continue;
            }
            int rc = do_invoke(args, true);
            printf("RC:%d\n", rc);
            printf("END_RESPONSE\n");
            fflush(stdout);
            continue;
        }
        if (tokens[0] == "run_wasm") {
            printf("BEGIN_RESPONSE\n");
            if (tokens.size() != 2 && tokens.size() != 3) {
                printf("ERROR:usage_run_wasm <wasm_path> [input_path]\n");
                printf("RC:-1\n");
                printf("END_RESPONSE\n");
                fflush(stdout);
                continue;
            }
            std::string input_path = (tokens.size() == 3) ? tokens[2] : "";
            int rc = do_run_wasm(tokens[1], input_path);
            printf("RC:%d\n", rc);
            printf("END_RESPONSE\n");
            fflush(stdout);
            continue;
        }
        
        printf("BEGIN_RESPONSE\n");
        printf("ERROR:unknown_command\n");
        printf("RC:-1\n");
        printf("END_RESPONSE\n");
        fflush(stdout);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    uint64_t enclave_create_begin_ns = mono_ns();
    printf("T_ENCLAVE_CREATE_BEGIN_MONO_NS:%llu\n", (unsigned long long)enclave_create_begin_ns);
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    uint64_t enclave_create_end_ns = mono_ns();
    uint64_t enclave_create_dur_ns = enclave_create_end_ns - enclave_create_begin_ns;
    printf("T_ENCLAVE_CREATE_END_MONO_NS:%llu\n", (unsigned long long)enclave_create_end_ns);
    printf("ENCLAVE_CREATE_DUR_NS:%llu\n", (unsigned long long)enclave_create_dur_ns);
    if (ret != SGX_SUCCESS) {
        printf("Failed to create enclave. Error code: %x\n", ret);
        return -1;
    }
    printf("Enclave created successfully.\n");
    fflush(stdout);

    uint64_t enclave_init_begin_ns = mono_ns();
    printf("T_ENCLAVE_INIT_BEGIN_MONO_NS:%llu\n", (unsigned long long)enclave_init_begin_ns);
    ecall_init(global_eid);
    uint64_t enclave_init_end_ns = mono_ns();
    uint64_t enclave_init_dur_ns = enclave_init_end_ns - enclave_init_begin_ns;
    printf("T_ENCLAVE_INIT_END_MONO_NS:%llu\n", (unsigned long long)enclave_init_end_ns);
    printf("ENCLAVE_INIT_DUR_NS:%llu\n", (unsigned long long)enclave_init_dur_ns);
    printf("ecall_init returned.\n");
    initialize_c1_tsc_frequency();
    printf("TSC_FREQUENCY_HZ:%llu\n", (unsigned long long)g_c1_tsc_hz);
    printf("TSC_FREQUENCY_METHOD:%s\n", g_c1_tsc_frequency_method);
    fflush(stdout);

    if (argc > 1 && strcmp(argv[1], "--server") == 0) {
        int rc = run_server_loop();
        sgx_destroy_enclave(global_eid);
        return rc;
    }

    if (argc > 1 && strcmp(argv[1], "--ibe-test") == 0) {
        printf("Running trusted MCL BF-IBE enclave test...\n");

        int ibe_result = -1;
        sgx_status_t ecall_ret = ecall_mcl_ibe_test(global_eid, &ibe_result);
        if (ecall_ret != SGX_SUCCESS) {
            printf("Trusted MCL BF-IBE enclave test ECALL failed: 0x%x\n", ecall_ret);
            sgx_destroy_enclave(global_eid);
            return -1;
        }

        if (ibe_result == 0) {
            printf("Trusted MCL BF-IBE enclave test: PASSED\n");
        } else {
            printf("Trusted MCL BF-IBE enclave test: FAILED (result=%d)\n", ibe_result);
        }
        sgx_destroy_enclave(global_eid);
        return ibe_result;
    } else if (argc > 1 && strcmp(argv[1], "--quote") == 0) {
        const char* fid = (argc > 2) ? argv[2] : "mock_fid_123";
        const char* label = (argc > 3) ? argv[3] : "mock_label_456";
        generate_quote(fid, label);
    } else if (argc > 1 && strcmp(argv[1], "--attest") == 0) {
        if (argc < 4) {
            printf("Usage: ./sgx_worker --attest <fid> <label>\n");
            sgx_destroy_enclave(global_eid);
            return -1;
        }
        const char* fid = argv[2];
        const char* label = argv[3];

        uint8_t public_key[64] = {0};
        std::vector<uint8_t> quote;
        bool ok = generate_quote_bytes(fid, label, quote, public_key);
        if (!ok) {
            printf("ERROR: attest_failed\n");
            sgx_destroy_enclave(global_eid);
            return -1;
        }

        std::string pk_b64 = b64_encode(public_key, 64);
        std::string quote_b64 = b64_encode(quote.data(), quote.size());
        printf("WORKER_PK_B64:%s\n", pk_b64.c_str()); // [# breakpoints]
        printf("QUOTE_B64:%s\n", quote_b64.c_str()); // [# breakpoints]
        fflush(stdout);
    }  else if (argc > 1 && strcmp(argv[1], "--encrypted") == 0) {
        // 1. Fetch Key from KMS (Worker Logic)
        generate_quote("mock_fid_123", "mock_label_456");

        // 2. Encrypt WASM (Client Logic - Simulating Client)
        const char* wasm_file = (argc > 2) ? argv[2] : "test.wasm";
        uint32_t wasm_size = 0;
        char* wasm_buffer = read_file_to_buffer(wasm_file, &wasm_size);
        if (!wasm_buffer) {
            printf("Failed to read WASM file: %s\n", wasm_file);
            sgx_destroy_enclave(global_eid);
            return -1;
        }

        uint8_t key[16];
        uint8_t iv[12];
        uint8_t tag[16];
        uint8_t* ciphertext = (uint8_t*)malloc(wasm_size);
        
        // Use the key that KMS provides (Mock: 0xAA...)
        memset(key, 0xAA, 16);
        memset(iv, 0xCD, 12);

        if (encrypt_aes_gcm((uint8_t*)wasm_buffer, wasm_size, key, iv, 12, ciphertext, tag) < 0) {
            printf("Encryption failed.\n");
            free(wasm_buffer);
            free(ciphertext);
            sgx_destroy_enclave(global_eid);
            return -1;
        }

        printf("Running Encrypted WASM file: %s (%d bytes)\n", wasm_file, wasm_size);
        
        std::vector<uint8_t> encrypted_result(ASYNCS_DEFAULT_OUTPUT_CAPACITY_BYTES);
        uint32_t result_size = 0;
        uint8_t result_tag[16];
        uint8_t result_iv[12];

        // 3. Run in Enclave (Worker Logic - uses cached key)
        uint8_t dummy_input[1] = {0};
        uint8_t dummy_iv[12] = {0};
        uint8_t dummy_mac[16] = {0};
        uint8_t dummy_nonce[16] = {0};
        uint8_t dummy_pku[65] = {0};
        uint8_t dummy_ckfunc[28 + 32] = {0};
        uint8_t dummy_ckey[28 + 32] = {0};
        ecall_run_encrypted_wasm(global_eid, ciphertext, wasm_size, dummy_input, 0,
                                 dummy_ckfunc, sizeof(dummy_ckfunc),
                                 dummy_ckey, sizeof(dummy_ckey),
                                 dummy_nonce, dummy_pku,
                                 encrypted_result.data(), encrypted_result.size(), &result_size,
                                 result_tag, result_iv, iv, tag, dummy_iv, dummy_mac);

        printf("Encrypted Result Size: %d\n", result_size);

        if (result_size > 0) {
            uint8_t* decrypted_result = (uint8_t*)malloc(result_size + 1);
            int dec_len = decrypt_aes_gcm(encrypted_result.data(), result_size, key, result_iv, 12, result_tag, decrypted_result);
            
            if (dec_len >= 0) {
                decrypted_result[dec_len] = '\0';
                printf("Decrypted Result: %s\n", decrypted_result);
            } else {
                printf("Result Decryption Failed!\n");
            }
            free(decrypted_result);
        }

        free(wasm_buffer);
        free(ciphertext);
    } else if (argc > 1 && strcmp(argv[1], "--invoke") == 0) {
        std::vector<std::string> tokens;
        for (int i = 1; i < argc; i++) {
            tokens.emplace_back(argv[i]);
        }
        InvokeArgs args;
        std::string err;
        if (!parse_invoke_tokens(tokens, args, err)) {
            printf("%s\n", err.c_str());
            sgx_destroy_enclave(global_eid);
            return -1;
        }
        int rc = do_invoke(args, false);
        sgx_destroy_enclave(global_eid);
        return rc;
    } else {
        const char* wasm_file = (argc > 1) ? argv[1] : "test.wasm";
        uint32_t wasm_size = 0;
        char* wasm_buffer = read_file_to_buffer(wasm_file, &wasm_size);
        if (!wasm_buffer) {
            printf("Failed to read WASM file: %s\n", wasm_file);
            sgx_destroy_enclave(global_eid);
            return -1;
        }

        printf("Running WASM file: %s (%d bytes)\n", wasm_file, wasm_size);
        uint64_t t_exec_begin_ns = now_ns_epoch(); // [# breakpoints]
        ecall_run_wasm(global_eid, (uint8_t*)wasm_buffer, wasm_size);
        uint64_t t_exec_end_ns = now_ns_epoch(); // [# breakpoints]
        printf("T_EXEC_BEGIN_NS:%llu\n", (unsigned long long)t_exec_begin_ns); // [# breakpoints]
        printf("T_EXEC_END_NS:%llu\n", (unsigned long long)t_exec_end_ns); // [# breakpoints]
        fflush(stdout);

        free(wasm_buffer);
    }

    sgx_destroy_enclave(global_eid);
    fprintf(stderr, "Exiting main...\n");
    fflush(stderr);
    return 0;
}
