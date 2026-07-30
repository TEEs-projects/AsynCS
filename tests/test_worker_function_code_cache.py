#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENCLAVE_CPP = ROOT / "sgx_worker" / "Enclave" / "Enclave.cpp"


def _source() -> str:
    return ENCLAVE_CPP.read_text(encoding="utf-8")


def _function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for idx in range(brace, len(source)):
        char = source[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[brace : idx + 1]
    raise AssertionError(f"unterminated function body for {signature}")


def test_enclave_declares_function_code_cache_with_zeroization() -> None:
    source = _source()

    assert "struct CachedFunctionCode" in source
    assert "g_cached_function_code" in source
    assert "static bool function_cache_lookup" in source
    assert "static bool function_cache_store" in source
    assert "static void function_cache_clear" in source
    assert "secure_zeroize(g_cached_function_code.wasm" in source
    assert "g_cached_function_code.valid = false" in source


def test_encrypted_wasm_paths_use_cache_before_cfunc_decrypt() -> None:
    source = _source()
    for signature in [
        "void ecall_run_encrypted_wasm(",
        "void ecall_run_encrypted_wasm_kem(",
    ]:
        body = _function_body(source, signature)
        cache_lookup_idx = body.find("function_cache_lookup(")
        decrypt_idx = body.find("sgx_rijndael128GCM_decrypt(")
        cache_store_idx = body.find("function_cache_store(")
        run_idx = body.find("run_wasm_helper(function_wasm, function_wasm_size, input_b64)")

        assert "bool function_cache_hit = false" in body
        assert "bool cfunc_decrypt_executed = false" in body
        assert cache_lookup_idx >= 0, f"{signature} must check function cache"
        assert decrypt_idx >= 0, f"{signature} must still decrypt on cache miss"
        assert cache_lookup_idx < decrypt_idx, f"{signature} must check cache before decrypting C_func"
        assert cache_store_idx > decrypt_idx, f"{signature} must store plaintext after decrypting C_func"
        assert run_idx > cache_store_idx, f"{signature} must execute from the cached/plaintext function buffer"
        assert "run_wasm_helper(decrypted_wasm, wasm_size" not in body


def test_encrypted_wasm_paths_emit_function_cache_trace() -> None:
    source = _source()
    legacy = _function_body(source, "void ecall_run_encrypted_wasm(")
    assert "ACSC_TRACE_FUNCTION_CACHE:" in legacy
    assert "function_cache_hit=%d" in legacy
    assert "cfunc_decrypt_executed=%d" in legacy
    assert "function_cache_bytes=%u" in legacy

    kem = _function_body(source, "void ecall_run_encrypted_wasm_kem(")
    assert "invoke_trace->function_cache_bytes" in kem
    assert "C1_TRACE_FUNCTION_CACHE_VALID" in kem
    assert "C1_TRACE_FUNCTION_CACHE_HIT" in kem
    assert "C1_TRACE_CFUNC_DECRYPT_EXECUTED" in kem
    assert "ACSC_TRACE_FUNCTION_CACHE:" not in kem


def test_key_reload_clears_function_cache_on_fid_change() -> None:
    source = _source()
    assert "static void function_cache_clear();" in source

    for signature in [
        "void ecall_decrypt_key(",
        "void ecall_decrypt_keys_batch(",
    ]:
        body = _function_body(source, signature)
        clear_idx = body.find("function_cache_clear()")
        fid_store_idx = body.find("strncpy(g_worker_fid, fid, 128)")

        assert "strncmp(g_worker_fid, fid, 128) != 0" in body
        assert clear_idx >= 0, f"{signature} must clear stale cached function code"
        assert fid_store_idx >= 0, f"{signature} must store the new FID"
        assert clear_idx < fid_store_idx, f"{signature} must clear before replacing FID"
