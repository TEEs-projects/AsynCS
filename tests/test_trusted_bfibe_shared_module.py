#!/usr/bin/env python3
import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def test_trusted_bfibe_module_is_shared_and_enclave_agnostic():
    header = _read("trusted/bfibe_mcl.h")
    source = _read("trusted/bfibe_mcl.cpp")

    assert "bfibe_mcl_setup" in header
    assert "bfibe_mcl_public_from_msk" in header
    assert "bfibe_mcl_extract" in header
    assert "bfibe_mcl_encrypt" in header
    assert "bfibe_mcl_decrypt" in header
    assert "bfibe_mcl_decrypt_key_envelope" in header
    assert "bfibe_mcl_log" in source
    assert "Enclave_t.h" not in source


def test_trusted_bfibe_module_derives_public_params_from_serialized_msk():
    header = _read("trusted/bfibe_mcl.h")
    source = _read("trusted/bfibe_mcl.cpp")

    assert "bfibe_mcl_public_from_msk" in header
    assert "const uint8_t* msk" in header
    assert "uint8_t* mpk_out" in header
    assert "size_t* mpk_len" in header

    helper_start = source.index("int bfibe_mcl_public_from_msk(")
    helper = source[helper_start:source.index("int bfibe_mcl_extract(", helper_start)]
    assert "mclBnFr_deserialize(&msk_fr, msk, msk_len)" in helper
    assert "get_bfibe_g1_generator(&g1)" in helper
    assert "mclBnG1_mul(&mpk, &g1, &msk_fr)" in helper
    assert "mclBnG1_isZero(&mpk)" in helper
    assert "mclBnG1_serialize(mpk_out, *mpk_len, &mpk)" in helper


def test_trusted_bfibe_module_uses_bls12_compatible_fixed_g1_generator():
    source = _read("trusted/bfibe_mcl.cpp")

    assert "ASYNCS/BFIBE/G1/GENERATOR/v1" in source
    assert "static int get_bfibe_g1_generator(" in source
    helper_start = source.index("static int get_bfibe_g1_generator(")
    helper = source[helper_start:source.index("int bfibe_mcl_init(", helper_start)]
    assert "mclBnG1_hashAndMapTo(g1" in helper
    assert "mclBnG1_isZero(g1)" in helper
    assert "mclBnG1_getBasePoint" not in source


def test_trusted_bfibe_module_decrypts_versioned_key_envelope_with_aad():
    header = _read("trusted/bfibe_mcl.h")
    source = _read("trusted/bfibe_mcl.cpp")

    assert "bfibe_mcl_decrypt_key_envelope" in header
    assert "const uint8_t* c1" in header
    assert "const uint8_t* nonce" in header
    assert "const uint8_t* aad" in header
    assert "uint8_t session_key_out32[32]" in header

    helper_start = source.index("int bfibe_mcl_decrypt_key_envelope(")
    helper = source[helper_start:]
    assert "mclBnG1_deserialize(&U, c1, c1_len)" in helper
    assert "mclBn_pairing(&shared, &U, &sk_id_g2)" in helper
    assert "encrypted_len = ciphertext_len - 16" in helper
    assert "tag = ciphertext + encrypted_len" in helper
    assert "sgx_rijndael128GCM_decrypt" in helper
    assert "aad," in helper
    assert "aad_len" in helper


def test_worker_and_kms_link_same_trusted_bfibe_module():
    worker_makefile = _read("sgx_worker/Makefile")
    kms_makefile = _read("sgx_kms/Makefile")

    for makefile in (worker_makefile, kms_makefile):
        assert "trusted/bfibe_mcl.cpp" in makefile
        assert "$(TRUSTED_MCL_PREFIX)/include" in makefile
        assert "-lmcl_trusted" in makefile


def test_each_enclave_provides_bfibe_log_hook():
    worker_enclave = _read("sgx_worker/Enclave/Enclave.cpp")
    kms_enclave = _read("sgx_kms/Enclave/Enclave.cpp")

    assert "void bfibe_mcl_log(const char* message)" in worker_enclave
    assert "void bfibe_mcl_log(const char* message)" in kms_enclave


def test_worker_legacy_mcl_wrapper_delegates_to_shared_module():
    wrapper = _read("sgx_worker/Enclave/mcl_ibe.cpp")

    assert '#include "bfibe_mcl.h"' in wrapper
    assert "return bfibe_mcl_setup(" in wrapper
    assert "return bfibe_mcl_extract(" in wrapper
    assert "return bfibe_mcl_encrypt(" in wrapper
    assert "return bfibe_mcl_decrypt(" in wrapper
