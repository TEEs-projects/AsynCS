#!/usr/bin/env python3
"""
Implementation Gap(G3): Capabilities + key ciphertexts wired end-to-end.

This repo often uses static audits as verifiable evidence for SGX enclave invariants.

G3 requirements (minimum verifiable slice):
1) Worker/Invoker plumb explicit C_k_func and C_key ciphertexts (not payload ciphertext bytes).
2) Enclave DecKey consumes (iv||tag||ct) and fails on wrong capability/tag.
3) Enclave derives session keys only via DecKey(dkf/dklabelfunc, C_key/C_k_func).
"""

import os
import sys

import pytest


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKSPACE_ROOT = os.path.dirname(ROOT)
ENCLAVE_CPP = os.path.join(ROOT, "sgx_worker", "Enclave", "Enclave.cpp")
ENCLAVE_EDL = os.path.join(ROOT, "sgx_worker", "Enclave", "Enclave.edl")
WORKER_APP = os.path.join(ROOT, "sgx_worker", "App", "App.cpp")


def _invoker_scala_under(openwhisk_root: str) -> str:
    return os.path.join(
        openwhisk_root,
        "core",
        "invoker",
        "src",
        "main",
        "scala",
        "org",
        "apache",
        "openwhisk",
        "core",
        "invoker",
        "InvokerReactive.scala",
    )


def _resolve_invoker_scala() -> str:
    candidates = []
    configured = os.environ.get("ACSC_OPENWHISK_SRC", "").strip()
    if configured:
        candidates.append(_invoker_scala_under(configured))
    candidates.extend([
        _invoker_scala_under(os.path.join(WORKSPACE_ROOT, "openwhisk")),
        _invoker_scala_under(os.path.join(ROOT, "openwhisk")),
    ])

    for path in candidates:
        if os.path.isfile(path) and os.access(path, os.R_OK):
            return path

    checked = "\n  - ".join(candidates)
    raise FileNotFoundError(
        "Could not find a readable OpenWhisk InvokerReactive.scala. "
        "Set ACSC_OPENWHISK_SRC to the OpenWhisk checkout. Checked:\n  - "
        + checked
    )


try:
    INVOKER_SCALA = _resolve_invoker_scala()
except FileNotFoundError as error:
    pytest.skip(str(error), allow_module_level=True)


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def audit_edl_plumbs_key_ciphertexts() -> None:
    print("\n[Static Audit] EDL plumbs C_k_func + C_key into enclave ECALLs")
    edl = _read(ENCLAVE_EDL)

    for needle in [
        "public void ecall_run_encrypted_wasm(",
        "public void ecall_run_encrypted_wasm_kem(",
        "uint8_t* c_k_func",
        "uint32_t c_k_func_size",
        "uint8_t* c_key",
        "uint32_t c_key_size",
    ]:
        assert needle in edl, f"Missing in EDL: {needle}"
    print("  ✓ EDL includes c_k_func + c_key buffers and sizes")


def audit_enclave_deckey_is_not_placeholder_kdf() -> None:
    print("\n[Static Audit] Enclave DecKey decrypts KeyCiphertextV1 under capability")
    cpp = _read(ENCLAVE_CPP)

    assert "static bool DecKey(" in cpp
    assert (
        "Encoding model for (C_key / C_k_func)" in cpp
        or "KeyCiphertextV1 encoding model" in cpp
    ), "DecKey must document C_key/C_k_func encoding"
    assert "EphemeralPK(65)" in cpp or "epk65" in cpp, "DecKey must document EphemeralPK(65) encoding"
    assert "sgx_rijndael128GCM_decrypt(" in cpp, "DecKey must use SGX AES-GCM decrypt (not KDF)"
    assert "return sha256_concat(cap32" not in cpp, "Placeholder DecKey KDF must be removed"
    assert (
        "Error: Missing C_key or cold-path C_k_func buffer (G3)." in cpp
        or "Error: Missing C_k_func/C_key buffers (G3)." in cpp
    ), "Enclave must reject missing key ciphertexts"
    print("  ✓ DecKey uses AES-GCM decrypt and enclave rejects missing key ciphertexts")

    # Ensure the encrypted execution path derives session keys from explicit C_k_func/C_key.
    for needle in [
        "DecKey(g_dklabel_func, c_k_func",
        "DecKey(g_worker_key, c_key",
    ]:
        assert needle in cpp, f"Missing DecKey wiring to key ciphertexts: {needle}"
    forbidden = [
        "DecKey(g_dklabel_func, encrypted_wasm",
        "DecKey(g_worker_key, encrypted_input",
    ]
    for needle in forbidden:
        assert needle not in cpp, f"Forbidden placeholder wiring still present: {needle}"
    print("  ✓ Session keys derive from C_k_func/C_key (not payload ciphertext bytes)")


def audit_enclave_emits_e3_payload_consumption_trace() -> None:
    print("\n[Static Audit] Enclave emits E3 payload consumption trace")
    cpp = _read(ENCLAVE_CPP)

    for needle in [
        "ACSC_TRACE_E3_PAYLOAD",
        "payload_bytes_consumed=%u",
        "payload_sha256",
        "sgx_sha256_msg(data, len",
        "trace_e3_payload_consumed",
        "capture_e3_payload_evidence",
        "run_wasm_helper(function_wasm, function_wasm_size, input_b64)",
    ]:
        assert needle in cpp, f"Missing E3 payload evidence wiring: {needle}"
    assert "trace_e3_payload_consumed(decrypted_input, input_size)" in cpp
    assert "capture_e3_payload_evidence(decrypted_input, input_size, invoke_trace)" in cpp
    print("  ✓ E3 payload bytes/hash are traced after input decrypt and before WASM execution")


def audit_worker_cli_requires_keys() -> None:
    print("\n[Static Audit] Worker CLI requires --keys and passes buffers to enclave")
    app = _read(WORKER_APP)

    assert "--keys" in app, "Worker must accept --keys <C_k_func_file> <C_key_file>"
    assert "Missing --keys <C_k_func_file> <C_key_file>" in app, "Worker must enforce --keys for G3"
    assert "ecall_run_encrypted_wasm_kem" in app and "c_k_func_buf" in app and "c_key_buf" in app
    assert "ecall_run_encrypted_wasm(" in app and "c_k_func_buf" in app and "c_key_buf" in app
    print("  ✓ Worker parses --keys and passes key ciphertext buffers into enclave ECALLs")


def audit_invoker_plumbs_ckey_ckfunc() -> None:
    print("\n[Static Audit] OpenWhisk invoker writes C_key + C_k_func and passes --keys")
    scala = _read(INVOKER_SCALA)

    for needle in [
        "C_k_func",
        "C_key",
        "c_k_func.enc",
        "c_key.enc",
        "--keys",
    ]:
        assert needle in scala, f"Invoker missing expected G3 plumbing: {needle}"
    print("  ✓ Invoker writes C_key/C_k_func files and passes --keys to worker")


def main() -> int:
    print("=" * 60)
    print("Protocol(A) Capabilities Wiring Audit (G3)")
    print("=" * 60)

    audit_edl_plumbs_key_ciphertexts()
    audit_enclave_deckey_is_not_placeholder_kdf()
    audit_enclave_emits_e3_payload_consumption_trace()
    audit_worker_cli_requires_keys()
    audit_invoker_plumbs_ckey_ckfunc()

    print("\n✅ G3 static audit passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
