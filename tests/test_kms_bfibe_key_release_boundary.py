#!/usr/bin/env python3
"""
Static contract for KMS-side BF-IBE key-release boundary.

KMS must eventually produce an encrypted ASBFREL1 release envelope for an
attested worker. The worker identity must be derived from enclave-verified RA
state / report_data binding, not supplied as an untrusted host string.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
KMS_EDL = ROOT / "sgx_kms" / "Enclave" / "Enclave.edl"
KMS_CPP = ROOT / "sgx_kms" / "Enclave" / "Enclave.cpp"
KMS_APP = ROOT / "sgx_kms" / "App" / "App.cpp"


def test_kms_edl_declares_variable_length_bfibe_release_ecall_without_host_worker_identity():
    edl = KMS_EDL.read_text()

    assert "ecall_get_bfibe_key_release" in edl
    assert "[in, string] const char* fid" in edl
    assert "[in, string] const char* label" in edl
    assert "[in, count=64] uint8_t* public_key" in edl
    assert "[out, size=release_capacity] uint8_t* release_out" in edl
    assert "uint32_t release_capacity" in edl
    assert "[out] uint32_t* actual_release_size" in edl
    signature_start = edl.index("ecall_get_bfibe_key_release")
    signature_end = edl.index(");", signature_start)
    signature = edl[signature_start:signature_end]
    assert "worker_identity" not in signature


def test_kms_declares_bfibe_extract_smoke_ecall():
    edl = KMS_EDL.read_text()

    assert "ecall_bfibe_extract_test" in edl
    assert "public int ecall_bfibe_extract_test();" in edl


def test_kms_declares_bfibe_public_params_ecall():
    edl = KMS_EDL.read_text()

    assert "ecall_get_bfibe_public_params" in edl
    assert "[out, size=mpk_capacity] uint8_t* mpk_out" in edl
    assert "uint32_t mpk_capacity" in edl
    assert "[out] uint32_t* actual_mpk_size" in edl


def test_kms_enclave_bfibe_release_is_policy_gated_and_constructs_encrypted_envelope():
    cpp = KMS_CPP.read_text()

    assert "int ecall_get_bfibe_key_release(" in cpp
    assert "verify_ra_for_fid(fid)" in cpp
    assert "verify_report_data_binding(public_key)" in cpp
    assert "is_label_bound_to_fid(fid, label)" in cpp
    assert "ASBFREL1" in cpp
    assert "ASBFSKS1" in cpp
    release_body = cpp[cpp.index("int ecall_get_bfibe_key_release("):cpp.index("// ============================================================================", cpp.index("int ecall_get_bfibe_key_release("))]
    assert "g_verified_mrenclave" in cpp
    assert "build_worker_identity" in release_body
    assert "build_bfibe_private_key_set" in release_body
    assert "build_bfibe_key_release" in release_body
    assert "bfibe_mcl_extract(" in release_body
    assert "sgx_rijndael128GCM_encrypt" in release_body
    assert "BF-IBE Extract/private-key release not implemented yet" not in release_body
    assert "return -2;" not in release_body


def test_kms_enclave_derives_bfibe_msk_without_mutating_legacy_msk():
    cpp = KMS_CPP.read_text()

    assert '#include "bfibe_mcl.h"' in cpp
    assert "ASYNCS/BFIBE/MSK/v1" in cpp
    assert "derive_bfibe_msk" in cpp
    assert "bfibe_mcl_extract(" in cpp
    assert "g_msk" in cpp


def test_kms_enclave_exports_public_bfibe_mpk_from_derived_msk():
    cpp = KMS_CPP.read_text()

    assert "int ecall_get_bfibe_public_params(" in cpp
    body = cpp[
        cpp.index("int ecall_get_bfibe_public_params("):
        cpp.index("int ecall_get_bfibe_key_release(", cpp.index("int ecall_get_bfibe_public_params("))
    ]
    assert "derive_bfibe_msk" in body
    assert "bfibe_mcl_public_from_msk" in body
    assert "actual_mpk_size" in body
    assert "g_msk" not in body


def test_kms_app_exposes_bfibe_extract_smoke_command():
    app = KMS_APP.read_text()

    assert "--bfibe-test" in app
    assert "ecall_bfibe_extract_test" in app
    assert "KMS BF-IBE Extract test: PASSED" in app


def test_kms_app_exports_bfibe_public_params_file():
    app = KMS_APP.read_text()

    assert "--bfibe-public-params" in app
    assert "ecall_get_bfibe_public_params" in app
    assert "BF-IBE public params written" in app
    assert "fwrite(bfibe_mpk" in app
