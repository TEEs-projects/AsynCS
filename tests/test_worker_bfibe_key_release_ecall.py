#!/usr/bin/env python3
"""
Static contract for the BF-IBE key-release ECALL boundary.

The true BF-IBE path requires variable-length serialized identity private keys
to cross from worker host into worker enclave. This test prevents regressions
back to fixed 124-byte capability blobs.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKER_EDL = ROOT / "sgx_worker" / "Enclave" / "Enclave.edl"
WORKER_CPP = ROOT / "sgx_worker" / "Enclave" / "Enclave.cpp"
WORKER_APP = ROOT / "sgx_worker" / "App" / "App.cpp"


def test_worker_edl_declares_variable_length_bfibe_key_release_ecall():
    edl = WORKER_EDL.read_text()

    assert "ecall_load_bfibe_key_release" in edl
    assert "[in, size=release_size] uint8_t* release" in edl
    assert "uint32_t release_size" in edl
    assert "[in, string] const char* fid" in edl
    assert "[in, count=124] uint8_t* release" not in edl


def test_worker_enclave_decrypts_and_imports_bfibe_private_key_release():
    cpp = WORKER_CPP.read_text()

    assert "int ecall_load_bfibe_key_release(" in cpp
    assert "ASBFREL1" in cpp
    release_body = cpp[cpp.index("int ecall_load_bfibe_key_release("):cpp.index("// Global buffer", cpp.index("int ecall_load_bfibe_key_release("))]
    assert "parse_bfibe_key_release" in release_body
    assert "build_bfibe_key_release_aad" in release_body
    assert "sgx_ecc256_compute_shared_dhkey" in release_body
    assert "sgx_rijndael128GCM_decrypt" in release_body
    assert "parse_bfibe_private_key_set" in release_body
    assert "g_bfibe_request_sk" in cpp
    assert "g_bfibe_function_sk" in cpp
    assert "BF-IBE key-release imported successfully" in cpp
    assert "BF-IBE key-release reached worker enclave before private-key import support" not in release_body
    assert "return -2;" not in release_body


def test_worker_has_key_checks_bfibe_cache_without_reusing_legacy_capability():
    cpp = WORKER_CPP.read_text()
    has_key_body = cpp[cpp.index("int ecall_has_key("):cpp.index("static const char BFIBE_KEY_RELEASE_MAGIC", cpp.index("int ecall_has_key("))]
    release_body = cpp[cpp.index("int ecall_load_bfibe_key_release("):cpp.index("// Global buffer", cpp.index("int ecall_load_bfibe_key_release("))]

    assert "g_bfibe_key_loaded" in has_key_body
    assert "g_bfibe_fid" in has_key_body
    assert "memcpy(g_worker_key" not in release_body
    assert "g_key_loaded = true" not in release_body


def test_worker_host_passes_bfibe_release_to_enclave_boundary_before_legacy_path():
    app = WORKER_APP.read_text()

    assert "ecall_load_bfibe_key_release(" in app
    assert "global_eid" in app
    assert "int bfibe_release_len = bfibe_key_release_payload_len(buffer, valread)" in app
    assert "(uint32_t)bfibe_release_len" in app
    assert "(uint32_t)valread" not in app
    assert "KMS_RESPONSE_MAX_LEN" in app

    guard_idx = app.index("is_bfibe_key_release_response(buffer, valread)")
    ecall_idx = app.index("ecall_load_bfibe_key_release(")
    legacy_idx = app.index("valread >= KMS_KEYS_LEN")
    assert guard_idx < ecall_idx < legacy_idx
