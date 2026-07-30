#define MCL_FP_BIT 384
#define MCL_FR_BIT 256

#include "mcl/bn.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

const char kProfile[] = "bfibe-mcl-bls12381";
const char kEnvelopeMagic[] = "ASBFIBE1";
const uint8_t kEnvelopeVersion = 1;
const char kGeneratorDomain[] = "ASYNCS/BFIBE/G1/GENERATOR/v1";
const char kAadMagic[] = "ASYNCS/BFIBE/AAD/v1";

struct EnvelopeParts {
    std::string purpose;
    std::string identity;
    std::vector<uint8_t> aad_context;
    std::vector<uint8_t> c1;
    std::vector<uint8_t> nonce;
    std::vector<uint8_t> ciphertext;
};

void append_u32(std::vector<uint8_t>& out, uint32_t value) {
    out.push_back(static_cast<uint8_t>((value >> 24) & 0xff));
    out.push_back(static_cast<uint8_t>((value >> 16) & 0xff));
    out.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    out.push_back(static_cast<uint8_t>(value & 0xff));
}

uint32_t read_u32(const std::vector<uint8_t>& data, size_t* offset) {
    if (!offset || *offset + 4 > data.size()) {
        throw std::runtime_error("short u32");
    }
    uint32_t value =
        (static_cast<uint32_t>(data[*offset]) << 24) |
        (static_cast<uint32_t>(data[*offset + 1]) << 16) |
        (static_cast<uint32_t>(data[*offset + 2]) << 8) |
        static_cast<uint32_t>(data[*offset + 3]);
    *offset += 4;
    return value;
}

void append_part(std::vector<uint8_t>& out, const uint8_t* data, size_t size) {
    append_u32(out, static_cast<uint32_t>(size));
    out.insert(out.end(), data, data + size);
}

void append_part(std::vector<uint8_t>& out, const std::string& value) {
    append_part(out, reinterpret_cast<const uint8_t*>(value.data()), value.size());
}

std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw std::runtime_error("failed to open input file: " + path);
    }
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

void write_file(const std::string& path, const std::vector<uint8_t>& data) {
    std::ofstream out(path, std::ios::binary);
    if (!out) {
        throw std::runtime_error("failed to open output file: " + path);
    }
    out.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
}

uint8_t hex_value(char c) {
    if (c >= '0' && c <= '9') return static_cast<uint8_t>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<uint8_t>(10 + c - 'a');
    if (c >= 'A' && c <= 'F') return static_cast<uint8_t>(10 + c - 'A');
    throw std::runtime_error("invalid hex character");
}

std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        throw std::runtime_error("hex input must have even length");
    }
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        out.push_back(static_cast<uint8_t>((hex_value(hex[i]) << 4) | hex_value(hex[i + 1])));
    }
    return out;
}

std::vector<uint8_t> random_bytes(size_t size) {
    std::vector<uint8_t> out(size);
    if (RAND_bytes(out.data(), static_cast<int>(out.size())) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return out;
}

void init_mcl() {
    int ret = mclBn_init(MCL_BLS12_381, MCLBN_COMPILED_TIME_VAR);
    if (ret != 0) {
        throw std::runtime_error("mclBn_init failed");
    }
}

void get_generator(mclBnG1* g1) {
    if (!g1) {
        throw std::runtime_error("null generator pointer");
    }
    if (mclBnG1_hashAndMapTo(g1, kGeneratorDomain, sizeof(kGeneratorDomain) - 1) != 0) {
        throw std::runtime_error("mclBnG1_hashAndMapTo generator failed");
    }
    if (mclBnG1_isZero(g1)) {
        throw std::runtime_error("generator mapped to zero");
    }
}

std::vector<uint8_t> serialize_g1(const mclBnG1& point) {
    std::vector<uint8_t> out(96);
    size_t size = mclBnG1_serialize(out.data(), out.size(), &point);
    if (size == 0) {
        throw std::runtime_error("mclBnG1_serialize failed");
    }
    out.resize(size);
    return out;
}

std::vector<uint8_t> serialize_g2(const mclBnG2& point) {
    std::vector<uint8_t> out(192);
    size_t size = mclBnG2_serialize(out.data(), out.size(), &point);
    if (size == 0) {
        throw std::runtime_error("mclBnG2_serialize failed");
    }
    out.resize(size);
    return out;
}

std::vector<uint8_t> build_envelope_aad(const EnvelopeParts& parts) {
    std::vector<uint8_t> aad;
    aad.insert(aad.end(), kAadMagic, kAadMagic + sizeof(kAadMagic) - 1);
    append_part(aad, std::string(kProfile));
    append_part(aad, parts.purpose);
    append_part(aad, parts.identity);
    append_part(aad, parts.aad_context.data(), parts.aad_context.size());
    return aad;
}

std::vector<uint8_t> aes_gcm_encrypt(
    const uint8_t key[16],
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& aad
) {
    if (nonce.size() != 12) {
        throw std::runtime_error("nonce must be 12 bytes");
    }
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    std::vector<uint8_t> ciphertext(plaintext.size());
    std::vector<uint8_t> out;
    int len = 0;
    int ok =
        EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1 &&
        EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, nonce.data()) == 1;
    if (ok && !aad.empty()) {
        ok = EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) == 1;
    }
    if (ok && !plaintext.empty()) {
        ok = EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) == 1;
    }
    int final_len = 0;
    if (ok) {
        ok = EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &final_len) == 1;
    }
    uint8_t tag[16] = {0};
    if (ok) {
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) == 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        throw std::runtime_error("AES-GCM encrypt failed");
    }

    out = ciphertext;
    out.insert(out.end(), tag, tag + sizeof(tag));
    return out;
}

std::vector<uint8_t> aes_gcm_decrypt(
    const uint8_t key[16],
    const std::vector<uint8_t>& nonce,
    const std::vector<uint8_t>& ciphertext_and_tag,
    const std::vector<uint8_t>& aad
) {
    if (nonce.size() != 12 || ciphertext_and_tag.size() <= 16) {
        throw std::runtime_error("invalid AES-GCM input");
    }
    const size_t ciphertext_len = ciphertext_and_tag.size() - 16;
    const uint8_t* tag = ciphertext_and_tag.data() + ciphertext_len;
    std::vector<uint8_t> plaintext(ciphertext_len);
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    int len = 0;
    int ok =
        EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) == 1 &&
        EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, nonce.data()) == 1;
    if (ok && !aad.empty()) {
        ok = EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), static_cast<int>(aad.size())) == 1;
    }
    if (ok && ciphertext_len > 0) {
        ok = EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext_and_tag.data(), static_cast<int>(ciphertext_len)) == 1;
    }
    if (ok) {
        ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8_t*>(tag)) == 1;
    }
    int final_len = 0;
    if (ok) {
        ok = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &final_len) == 1;
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        throw std::runtime_error("AES-GCM decrypt failed");
    }
    return plaintext;
}

std::vector<uint8_t> encode_envelope(const EnvelopeParts& parts) {
    std::vector<uint8_t> out;
    out.insert(out.end(), kEnvelopeMagic, kEnvelopeMagic + 8);
    out.push_back(kEnvelopeVersion);
    append_u32(out, static_cast<uint32_t>(sizeof(kProfile) - 1));
    append_u32(out, static_cast<uint32_t>(parts.purpose.size()));
    append_u32(out, static_cast<uint32_t>(parts.identity.size()));
    append_u32(out, static_cast<uint32_t>(parts.aad_context.size()));
    append_u32(out, static_cast<uint32_t>(parts.c1.size()));
    append_u32(out, static_cast<uint32_t>(parts.nonce.size()));
    append_u32(out, static_cast<uint32_t>(parts.ciphertext.size()));
    out.insert(out.end(), kProfile, kProfile + sizeof(kProfile) - 1);
    out.insert(out.end(), parts.purpose.begin(), parts.purpose.end());
    out.insert(out.end(), parts.identity.begin(), parts.identity.end());
    out.insert(out.end(), parts.aad_context.begin(), parts.aad_context.end());
    out.insert(out.end(), parts.c1.begin(), parts.c1.end());
    out.insert(out.end(), parts.nonce.begin(), parts.nonce.end());
    out.insert(out.end(), parts.ciphertext.begin(), parts.ciphertext.end());
    return out;
}

std::vector<uint8_t> take_bytes(const std::vector<uint8_t>& data, size_t* offset, size_t len) {
    if (!offset || *offset + len > data.size()) {
        throw std::runtime_error("short envelope part");
    }
    std::vector<uint8_t> out(data.begin() + static_cast<long>(*offset), data.begin() + static_cast<long>(*offset + len));
    *offset += len;
    return out;
}

std::string take_string(const std::vector<uint8_t>& data, size_t* offset, size_t len) {
    auto bytes = take_bytes(data, offset, len);
    return std::string(bytes.begin(), bytes.end());
}

EnvelopeParts decode_envelope(const std::vector<uint8_t>& data) {
    if (data.size() < 8 + 1 + 7 * 4 || memcmp(data.data(), kEnvelopeMagic, 8) != 0) {
        throw std::runtime_error("invalid envelope magic");
    }
    size_t offset = 8;
    if (data[offset++] != kEnvelopeVersion) {
        throw std::runtime_error("invalid envelope version");
    }
    uint32_t profile_len = read_u32(data, &offset);
    uint32_t purpose_len = read_u32(data, &offset);
    uint32_t identity_len = read_u32(data, &offset);
    uint32_t aad_context_len = read_u32(data, &offset);
    uint32_t c1_len = read_u32(data, &offset);
    uint32_t nonce_len = read_u32(data, &offset);
    uint32_t ciphertext_len = read_u32(data, &offset);

    std::string profile = take_string(data, &offset, profile_len);
    if (profile != kProfile) {
        throw std::runtime_error("invalid envelope profile");
    }
    EnvelopeParts parts;
    parts.purpose = take_string(data, &offset, purpose_len);
    parts.identity = take_string(data, &offset, identity_len);
    parts.aad_context = take_bytes(data, &offset, aad_context_len);
    parts.c1 = take_bytes(data, &offset, c1_len);
    parts.nonce = take_bytes(data, &offset, nonce_len);
    parts.ciphertext = take_bytes(data, &offset, ciphertext_len);
    if (offset != data.size()) {
        throw std::runtime_error("trailing envelope bytes");
    }
    return parts;
}

std::vector<uint8_t> derive_public_from_msk(const std::vector<uint8_t>& msk_bytes) {
    if (msk_bytes.empty()) {
        throw std::runtime_error("msk must not be empty");
    }
    mclBnFr msk;
    mclBnFr_setLittleEndianMod(&msk, msk_bytes.data(), msk_bytes.size());
    mclBnG1 g1;
    get_generator(&g1);
    mclBnG1 mpk;
    mclBnG1_mul(&mpk, &g1, &msk);
    if (mclBnG1_isZero(&mpk)) {
        throw std::runtime_error("derived mpk is zero");
    }
    return serialize_g1(mpk);
}

std::vector<uint8_t> extract_private_key(const std::vector<uint8_t>& msk_bytes, const std::string& identity) {
    mclBnFr msk;
    mclBnFr_setLittleEndianMod(&msk, msk_bytes.data(), msk_bytes.size());
    mclBnG2 q_id;
    if (mclBnG2_hashAndMapTo(&q_id, identity.data(), identity.size()) != 0) {
        throw std::runtime_error("mclBnG2_hashAndMapTo failed");
    }
    mclBnG2 sk;
    mclBnG2_mul(&sk, &q_id, &msk);
    return serialize_g2(sk);
}

std::vector<uint8_t> encrypt_key_envelope(
    const std::vector<uint8_t>& mpk,
    const std::string& purpose,
    const std::string& identity,
    const std::vector<uint8_t>& aad_context,
    const std::vector<uint8_t>& key_plaintext,
    const std::vector<uint8_t>& r_bytes,
    const std::vector<uint8_t>& nonce
) {
    if (!(purpose == "request-key" || purpose == "function-key")) {
        throw std::runtime_error("purpose must be request-key or function-key");
    }
    if (!(key_plaintext.size() == 16 || key_plaintext.size() == 32)) {
        throw std::runtime_error("key plaintext must be 16 or 32 bytes");
    }

    mclBnG1 mpk_g1;
    if (mclBnG1_deserialize(&mpk_g1, mpk.data(), mpk.size()) == 0) {
        throw std::runtime_error("mclBnG1_deserialize mpk failed");
    }

    mclBnFr r;
    mclBnFr_setLittleEndianMod(&r, r_bytes.data(), r_bytes.size());
    if (mclBnFr_isZero(&r)) {
        throw std::runtime_error("r must not be zero");
    }

    mclBnG1 g1;
    get_generator(&g1);
    mclBnG1 U;
    mclBnG1_mul(&U, &g1, &r);
    if (mclBnG1_isZero(&U)) {
        throw std::runtime_error("derived U is zero");
    }

    mclBnG2 q_id;
    if (mclBnG2_hashAndMapTo(&q_id, identity.data(), identity.size()) != 0) {
        throw std::runtime_error("mclBnG2_hashAndMapTo failed");
    }

    mclBnGT temp;
    mclBn_pairing(&temp, &mpk_g1, &q_id);
    mclBnGT shared;
    mclBnGT_pow(&shared, &temp, &r);

    uint8_t shared_bytes[576] = {0};
    size_t shared_size = mclBnGT_serialize(shared_bytes, sizeof(shared_bytes), &shared);
    if (shared_size == 0) {
        throw std::runtime_error("mclBnGT_serialize failed");
    }
    uint8_t aes_key_full[SHA256_DIGEST_LENGTH] = {0};
    SHA256(shared_bytes, shared_size, aes_key_full);
    memset(shared_bytes, 0, sizeof(shared_bytes));

    EnvelopeParts parts;
    parts.purpose = purpose;
    parts.identity = identity;
    parts.aad_context = aad_context;
    parts.c1 = serialize_g1(U);
    parts.nonce = nonce;
    std::vector<uint8_t> aad = build_envelope_aad(parts);
    parts.ciphertext = aes_gcm_encrypt(aes_key_full, nonce, key_plaintext, aad);
    memset(aes_key_full, 0, sizeof(aes_key_full));
    return encode_envelope(parts);
}

std::vector<uint8_t> decrypt_key_envelope(const std::vector<uint8_t>& sk, const std::vector<uint8_t>& envelope) {
    EnvelopeParts parts = decode_envelope(envelope);
    mclBnG2 sk_g2;
    if (mclBnG2_deserialize(&sk_g2, sk.data(), sk.size()) == 0) {
        throw std::runtime_error("mclBnG2_deserialize sk failed");
    }
    mclBnG1 U;
    if (mclBnG1_deserialize(&U, parts.c1.data(), parts.c1.size()) == 0) {
        throw std::runtime_error("mclBnG1_deserialize U failed");
    }
    mclBnGT shared;
    mclBn_pairing(&shared, &U, &sk_g2);
    uint8_t shared_bytes[576] = {0};
    size_t shared_size = mclBnGT_serialize(shared_bytes, sizeof(shared_bytes), &shared);
    if (shared_size == 0) {
        throw std::runtime_error("mclBnGT_serialize failed");
    }
    uint8_t aes_key_full[SHA256_DIGEST_LENGTH] = {0};
    SHA256(shared_bytes, shared_size, aes_key_full);
    memset(shared_bytes, 0, sizeof(shared_bytes));
    std::vector<uint8_t> aad = build_envelope_aad(parts);
    std::vector<uint8_t> plaintext = aes_gcm_decrypt(aes_key_full, parts.nonce, parts.ciphertext, aad);
    memset(aes_key_full, 0, sizeof(aes_key_full));
    return plaintext;
}

void self_test() {
    init_mcl();
    std::vector<uint8_t> msk(32);
    for (size_t i = 0; i < msk.size(); ++i) msk[i] = static_cast<uint8_t>(i + 1);
    std::vector<uint8_t> key(16);
    for (size_t i = 0; i < key.size(); ++i) key[i] = static_cast<uint8_t>(0xa0 + i);
    std::vector<uint8_t> r(32);
    for (size_t i = 0; i < r.size(); ++i) r[i] = static_cast<uint8_t>(0x10 + i);
    std::vector<uint8_t> nonce(12);
    for (size_t i = 0; i < nonce.size(); ++i) nonce[i] = static_cast<uint8_t>(0x40 + i);
    std::string identity = "fid:0123456789abcdef";
    std::vector<uint8_t> aad_context = {'R', 'E', 'Q', 0x01, 0x02, 0x03};

    std::vector<uint8_t> mpk = derive_public_from_msk(msk);
    std::vector<uint8_t> sk = extract_private_key(msk, identity);
    std::vector<uint8_t> envelope = encrypt_key_envelope(
        mpk,
        "request-key",
        identity,
        aad_context,
        key,
        r,
        nonce
    );
    std::vector<uint8_t> decoded = decrypt_key_envelope(sk, envelope);
    if (decoded != key) {
        throw std::runtime_error("self-test decrypt mismatch");
    }
    std::cout << "bfibe_mcl_client_self_test=ok envelope_size=" << envelope.size() << "\n";
}

void usage(const char* argv0) {
    std::cerr
        << "Usage:\n"
        << "  " << argv0 << " --self-test\n"
        << "  " << argv0 << " --mpk FILE --purpose request-key|function-key --identity ID \\\n"
        << "      --aad-context-hex HEX --key-hex HEX --out FILE [--r-hex HEX] [--nonce-hex HEX]\n";
}

std::string require_arg(int argc, char** argv, int* i) {
    if (*i + 1 >= argc) {
        throw std::runtime_error(std::string("missing value for ") + argv[*i]);
    }
    *i += 1;
    return argv[*i];
}

}  // namespace

int main(int argc, char** argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--self-test") {
            self_test();
            return 0;
        }

        std::string mpk_path;
        std::string purpose;
        std::string identity;
        std::string aad_context_hex;
        std::string key_hex;
        std::string out_path;
        std::string r_hex;
        std::string nonce_hex;

        for (int i = 1; i < argc; ++i) {
            std::string arg = argv[i];
            if (arg == "--mpk") mpk_path = require_arg(argc, argv, &i);
            else if (arg == "--purpose") purpose = require_arg(argc, argv, &i);
            else if (arg == "--identity") identity = require_arg(argc, argv, &i);
            else if (arg == "--aad-context-hex") aad_context_hex = require_arg(argc, argv, &i);
            else if (arg == "--key-hex") key_hex = require_arg(argc, argv, &i);
            else if (arg == "--out") out_path = require_arg(argc, argv, &i);
            else if (arg == "--r-hex") r_hex = require_arg(argc, argv, &i);
            else if (arg == "--nonce-hex") nonce_hex = require_arg(argc, argv, &i);
            else {
                usage(argv[0]);
                return 2;
            }
        }

        if (mpk_path.empty() || purpose.empty() || identity.empty() ||
            key_hex.empty() || out_path.empty()) {
            usage(argv[0]);
            return 2;
        }

        init_mcl();
        std::vector<uint8_t> mpk = read_file(mpk_path);
        std::vector<uint8_t> aad_context = hex_to_bytes(aad_context_hex);
        std::vector<uint8_t> key = hex_to_bytes(key_hex);
        std::vector<uint8_t> r = r_hex.empty() ? random_bytes(32) : hex_to_bytes(r_hex);
        std::vector<uint8_t> nonce = nonce_hex.empty() ? random_bytes(12) : hex_to_bytes(nonce_hex);
        if (nonce.size() != 12) {
            throw std::runtime_error("nonce must be 12 bytes");
        }

        std::vector<uint8_t> envelope = encrypt_key_envelope(
            mpk,
            purpose,
            identity,
            aad_context,
            key,
            r,
            nonce
        );
        write_file(out_path, envelope);
        std::cout << "bfibe_mcl_client_encrypt=ok out=" << out_path
                  << " size=" << envelope.size() << "\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "bfibe_mcl_client_error=" << e.what() << "\n";
        return 1;
    }
}
