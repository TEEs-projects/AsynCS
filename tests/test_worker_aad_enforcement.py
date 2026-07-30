#!/usr/bin/env python3
"""
Implementation Gap(G1): Worker enclave enforces AEAD AAD bindings (PKG/REQ/OUT).

This repo commonly validates enclave properties via static audits. This test ensures:
1) Enclave builds aad_pkg/aad_req/aad_out and passes them into SGX AES-GCM API.
2) OpenWhisk invoker path passes nonce and pkU so enclave can compute aad_req/aad_out.
"""

import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENCLAVE_CPP = os.path.join(ROOT, "sgx_worker", "Enclave", "Enclave.cpp")
ENCLAVE_EDL = os.path.join(ROOT, "sgx_worker", "Enclave", "Enclave.edl")
WORKER_APP = os.path.join(ROOT, "sgx_worker", "App", "App.cpp")
INVOKER_SCALA = os.path.join(
    ROOT,
    "openwhisk",
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


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def audit_enclave_edl_signatures() -> None:
    print("\n[Static Audit] Enclave EDL exposes nonce/pkU for AAD binding")
    edl = _read(ENCLAVE_EDL)

    assert "ecall_run_encrypted_wasm(" in edl
    assert "ecall_run_encrypted_wasm_kem(" in edl
    assert "uint8_t* nonce" in edl, "EDL must pass nonce into encrypted wasm ECALLs"
    assert "uint8_t* pkU" in edl, "EDL must pass pkU into encrypted wasm ECALLs"
    print("  ✓ EDL includes nonce + pkU parameters")


def audit_enclave_aad_usage() -> None:
    print("\n[Static Audit] Enclave builds and uses aad_pkg/aad_req/aad_out")
    cpp = _read(ENCLAVE_CPP)

    required_helpers = [
        "Protocol(A): Strict AAD construction helpers",
        "build_aad_pkg",
        "build_aad_req",
        "build_aad_out",
    ]
    for needle in required_helpers:
        assert needle in cpp, f"Missing helper: {needle}"

    # Ensure AES-GCM calls are not using empty AAD in encrypted paths.
    forbidden_pairs = [
        # wasm decrypt (legacy)
        "(const sgx_aes_gcm_128bit_key_t*)k_func_128,\n        encrypted_wasm,\n        wasm_size,\n        decrypted_wasm",
        # input decrypt
        "(const sgx_aes_gcm_128bit_key_t*)k_req_128,\n            encrypted_input",
        # output encrypt (legacy)
        "(const sgx_aes_gcm_128bit_key_t*)k_req_128,\n        (const uint8_t*)global_output_buffer",
        # wasm decrypt (kem)
        "(const sgx_aes_gcm_128bit_key_t*)k_func_128,\n        encrypted_wasm,\n        wasm_size,\n        decrypted_wasm,\n        wasm_iv",
        # output encrypt (kem)
        "(const sgx_aes_gcm_128bit_key_t*)k_U_128",
    ]
    for start in forbidden_pairs:
        idx = cpp.find(start)
        assert idx != -1, "Expected SGX AES-GCM call site not found for audit"
        window = cpp[idx : idx + 350]
        assert "NULL" not in window or "aad_" in window, "AAD must not be NULL in encrypted paths"
        assert ",\n        0," not in window, "AAD length must not be 0 in encrypted paths"

    print("  ✓ Enclave passes non-empty AAD to AES-GCM for PKG/REQ/OUT")


def audit_worker_and_invoker_plumbing() -> None:
    print("\n[Static Audit] Worker CLI + Invoker pass nonce/pkU for AAD binding")
    app = _read(WORKER_APP)
    scala = _read(INVOKER_SCALA)

    assert "nonce_file" in app, "Worker App must accept nonce file argument"
    assert "pkU_file" in app or "pku_file" in app, "Worker App must accept pkU file argument"
    assert "If providing pkU/nonce, both pkU_file and nonce_file must be provided" in app
    print("  ✓ Worker CLI enforces pkU+nonce pairing")

    for needle in [
        'val nonceBase64 = content.fields.get("nonce")',
        "noncePath",
        "Files.write(noncePath",
        "pkUPath",
        "Files.write(pkUPath",
        "--invoke",
        "noncePath.toString",
    ]:
        assert needle in scala, f"Invoker missing expected nonce/pkU handling: {needle}"
    print("  ✓ Invoker writes pkU+nonce files and passes them to worker")


def main() -> int:
    print("=" * 60)
    print("Worker AAD Enforcement Audit (G1)")
    print("=" * 60)

    audit_enclave_edl_signatures()
    audit_enclave_aad_usage()
    audit_worker_and_invoker_plumbing()

    print("\n✅ G1 static audit passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

