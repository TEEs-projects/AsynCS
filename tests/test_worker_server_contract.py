#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP_CPP = ROOT / "sgx_worker" / "App" / "App.cpp"
ENCLAVE_CPP = ROOT / "sgx_worker" / "Enclave" / "Enclave.cpp"


def _source() -> str:
    return APP_CPP.read_text(encoding="utf-8")


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


def test_worker_exposes_server_mode_contract() -> None:
    source = _source()
    assert "static int run_server_loop()" in source
    assert 'strcmp(argv[1], "--server") == 0' in source
    assert "SERVER_READY" in source
    assert "BEGIN_RESPONSE" in source
    assert "END_RESPONSE" in source
    assert "RC:%d" in source


def test_server_invoke_uses_key_cache_before_kms() -> None:
    source = _source()
    signature = "static int do_invoke(const InvokeArgs& args, bool allow_kms_cache)"
    assert signature in source
    body = _function_body(source, signature)
    assert "ecall_has_key" in body
    assert "need_kms = false" in body
    assert "if (need_kms)" in body
    assert body.index("ecall_has_key") < body.index("generate_quote")


def test_direct_invoke_keeps_cold_compatible_path() -> None:
    source = _source()
    assert 'strcmp(argv[1], "--invoke") == 0' in source
    assert "do_invoke(args, false)" in source


def test_server_invoke_emits_breakdown_duration_markers() -> None:
    source = _source()
    signature = "static int do_invoke(const InvokeArgs& args, bool allow_kms_cache)"
    body = _function_body(source, signature)

    assert "mono_ns()" in body
    assert "WORKER_KEYPATH_DUR_NS" in body
    assert "WORKER_EXEC_DUR_NS" in body
    assert "WORKER_INVOKE_DUR_NS" in body


def test_server_invoke_emits_structured_worker_trace_marker() -> None:
    source = _source()
    signature = "static int do_invoke(const InvokeArgs& args, bool allow_kms_cache)"
    body = _function_body(source, signature)

    assert "ACSC_TRACE_WORKER_INVOKE:" in body
    assert "key_cache_hit=%d" in body
    assert "kms_contacted=%d" in body
    assert "keypath_dur_ns=%llu" in body
    assert "kms_wait_dur_ns=%llu" in body
    assert "exec_ecall_dur_ns=%llu" in body
    assert "invoke_total_dur_ns=%llu" in body
    assert "wasm_bytes=%u" in body
    assert "input_bytes=%u" in body
    assert "result_bytes=%u" in body
    assert "rc=%d" in body


def test_app_validates_kem_ciphertext_in_wire_byte_order() -> None:
    app_source = _source()
    enclave_source = ENCLAVE_CPP.read_text(encoding="utf-8")
    kem_body = _function_body(enclave_source, "int ecall_kem_encap(")
    invoke_body = _function_body(app_source, "static int do_invoke(const InvokeArgs& args, bool allow_kms_cache)")

    assert "ct_out[0] = 0x04" in kem_body
    assert "ct_out[1 + i] = eph_pk.gx[31 - i]" in kem_body
    assert "ct_out[33 + i] = eph_pk.gy[31 - i]" in kem_body
    assert "static bool is_valid_p256_point_be" in app_source
    assert "is_valid_p256_point_be(kem_ct, sizeof(kem_ct))" in invoke_body
    assert "is_valid_p256_point_le(kem_ct, sizeof(kem_ct))" not in invoke_body
