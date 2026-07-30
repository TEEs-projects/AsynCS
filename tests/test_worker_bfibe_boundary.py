#!/usr/bin/env python3
"""
Static audit for the worker-side BF-IBE transition boundary.

The worker must parse bfibe-mcl-bls12381 key-ciphertext envelopes before the
legacy ECC KeyCiphertextV1 parser, and must use imported BF identity private
keys rather than legacy ECCIBE capabilities.
"""

import os


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENCLAVE_CPP = os.path.join(ROOT, "sgx_worker", "Enclave", "Enclave.cpp")


def test_worker_deckey_decrypts_bfibe_envelope_before_legacy_ecies_parse():
    with open(ENCLAVE_CPP, "r", encoding="utf-8") as f:
        cpp = f.read()

    assert "BFIBE_ENVELOPE_MAGIC" in cpp
    assert "ASBFIBE1" in cpp
    assert "BFIBE_ENVELOPE_VERSION" in cpp
    assert "is_bfibe_envelope" in cpp

    deckey_start = cpp.index("static bool DecKey(")
    deckey_body = cpp[
        deckey_start:cpp.index("// Protocol(A): Strict AAD construction helpers", deckey_start)
    ]
    bfibe_check = cpp.index("is_bfibe_envelope(c, c_len)", deckey_start)
    legacy_epk_parse = cpp.index("const uint8_t* epk65 = c;", deckey_start)
    assert bfibe_check < legacy_epk_parse

    assert "BfibeKeyEnvelopeView" in cpp
    assert "parse_bfibe_envelope" in deckey_body
    assert "build_bfibe_envelope_aad" in deckey_body
    assert "view.aad_context_len != domain_len" in deckey_body
    assert "memcmp(view.aad_context, domain, domain_len)" in deckey_body
    assert "bfibe_mcl_decrypt_key_envelope" in deckey_body
    assert "g_bfibe_key_loaded" in deckey_body
    assert "g_bfibe_request_sk" in deckey_body
    assert "g_bfibe_function_sk" in deckey_body
    assert '"request-key"' in deckey_body
    assert '"function-key"' in deckey_body
    assert '"fid:%s"' in deckey_body
    assert '"label:"' in deckey_body
    assert "memcpy(key_out32" in deckey_body
    assert "BF-IBE envelope reached DecKey before bfibe-mcl worker support" not in deckey_body


def test_worker_encrypted_invocation_can_use_bfibe_loaded_key_state():
    with open(ENCLAVE_CPP, "r", encoding="utf-8") as f:
        cpp = f.read()

    assert "request_uses_bfibe_key_ciphertexts" in cpp
    assert "const bool use_bfibe_keys = request_uses_bfibe_key_ciphertexts" in cpp
    assert "const char* invocation_fid = use_bfibe_keys ? g_bfibe_fid : g_worker_fid" in cpp
    assert "if (use_bfibe_keys)" in cpp

    for function_name in ("void ecall_run_encrypted_wasm(", "void ecall_run_encrypted_wasm_kem("):
        body = cpp[cpp.index(function_name):cpp.index("cleanup:", cpp.index(function_name))]
        assert "if (!use_bfibe_keys && !g_key_loaded)" in body
        assert "if (use_bfibe_keys && !g_bfibe_key_loaded)" in body
        assert "build_aad_pkg(invocation_fid" in body
        assert "build_aad_req(invocation_fid" in body
        assert "compute_rid_from_fid_and_c_req(invocation_fid" in body
        assert "function_cache_lookup(invocation_fid" in body
        assert "function_cache_store(invocation_fid" in body
        assert "DecKey(NULL, c_key, c_key_size, aad_req, aad_req_len, k_req32)" in body
        assert "DecKey(NULL, c_k_func, c_k_func_size, aad_pkg, aad_pkg_len, k_func32)" in body


def test_worker_wasm_loader_does_not_mutate_cached_plaintext_wasm():
    with open(ENCLAVE_CPP, "r", encoding="utf-8") as f:
        cpp = f.read()

    helper = cpp[cpp.index("bool run_wasm_helper("):cpp.index("void ecall_run_wasm(", cpp.index("bool run_wasm_helper("))]

    assert "uint8_t* wasm_copy = NULL" in helper
    assert "wasm_copy = (uint8_t*)malloc(wasm_size)" in helper
    assert "memcpy(wasm_copy, wasm_buffer, wasm_size)" in helper
    assert "wasm_runtime_load(wasm_copy, wasm_size" in helper
    assert "free(wasm_copy)" in helper
