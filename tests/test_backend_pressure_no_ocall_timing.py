#!/usr/bin/env python3
"""Static contract for the bounded AsynCS backend-pressure ECALL trace."""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENCLAVE = (ROOT / "sgx_worker/Enclave/Enclave.cpp").read_text(encoding="utf-8")
EDL = (ROOT / "sgx_worker/Enclave/Enclave.edl").read_text(encoding="utf-8")
APP = (ROOT / "sgx_worker/App/App.cpp").read_text(encoding="utf-8")
PROXY = (ROOT / "openwhisk_runtime/proxy.py").read_text(encoding="utf-8")
WORKLOAD = (ROOT / "workloads/backend_pressure_sleep50/src/main.rs").read_text(encoding="utf-8")
BFIBE = (ROOT / "trusted/bfibe_mcl.cpp").read_text(encoding="utf-8")


def function_body(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    return source[begin : source.index(end, begin)]


def test_captured_wasm_output_stays_inside_enclave_until_encrypted():
    printer = function_body(ENCLAVE, "int enclave_print(", "// Forward declarations",)
    capture_branch = printer[printer.index("if (capture_output)") : printer.index("ocall_print(message)")]
    assert "memcpy(global_output_buffer" in capture_branch
    assert "return 0;" in capture_branch

    helper = function_body(ENCLAVE, "bool run_wasm_helper(", "void ecall_run_wasm(")
    assert "capture_output = true" in helper
    assert "wasm_application_execute_main" in helper
    assert "capture_output = false" in helper
    assert "WASM Module Loaded and Instantiated Successfully" not in helper
    assert "WASM Execution Finished" not in helper


def test_kem_success_path_returns_bounded_trace_without_success_prints():
    body = function_body(
        ENCLAVE,
        "void ecall_run_encrypted_wasm_kem(",
        "// ============================================================================\n// SECURE MEMORY ZEROIZATION",
    )
    assert "c1_asyncs_invoke_trace_t* invoke_trace" in body
    assert "memcpy(invoke_trace->rid" in body
    assert "capture_e3_payload_evidence" in body
    assert "C1_TRACE_WORKLOAD_CYCLES_VALID" in body
    assert "C1_TRACE_OUTPUT_KEM_CYCLES_VALID" in body
    assert "C1_TRACE_OUTPUT_AES_GCM_CYCLES_VALID" in body
    assert "C3_TRACE_INPUT_KEY_CYCLES_VALID" in body
    assert "C3_TRACE_INPUT_AES_GCM_CYCLES_VALID" in body
    assert "C2_TRACE_FUNCTION_KEY_CYCLES_VALID" in body
    assert "C2_TRACE_CFUNC_AES_GCM_CYCLES_VALID" in body
    assert "C2_TRACE_WASM_LOAD_CYCLES_VALID" in ENCLAVE
    assert "C2_TRACE_WASM_INSTANTIATE_CYCLES_VALID" in ENCLAVE
    for boundary in (
        "input_key_decap_begin_cycles",
        "input_key_decap_end_cycles",
        "input_aes_gcm_begin_cycles",
        "input_aes_gcm_end_cycles",
        "workload_begin_cycles",
        "workload_end_cycles",
        "output_kem_begin_cycles",
        "output_kem_end_cycles",
        "output_aes_gcm_begin_cycles",
        "output_aes_gcm_end_cycles",
        "function_key_decap_begin_cycles",
        "function_key_decap_end_cycles",
        "cfunc_aes_gcm_begin_cycles",
        "cfunc_aes_gcm_end_cycles",
    ):
        assert boundary in body
    helper = function_body(ENCLAVE, "bool run_wasm_helper(", "void ecall_run_wasm(")
    for boundary in (
        "wasm_load_begin_cycles",
        "wasm_load_end_cycles",
        "wasm_instantiate_begin_cycles",
        "wasm_instantiate_end_cycles",
    ):
        assert boundary in helper
    assert 'print_hex_prefixed("RID_HEX:"' not in body
    for success_log in (
        "KEM: WASM Decryption succeeded",
        "KEM: Input Decryption succeeded",
        "KEM: Result encrypted with k_U successfully",
        "KEM: Encrypted Result Size",
    ):
        assert success_log not in body


def test_bfibe_request_envelope_decrypt_keeps_errors_but_has_no_success_log_ocall():
    helper = BFIBE[BFIBE.index("int bfibe_mcl_decrypt_key_envelope(") :]
    assert "BF-IBE MCL: Failed to deserialize sk_id" in helper
    assert "BF-IBE MCL: Failed to deserialize envelope C1" in helper
    assert "BF-IBE MCL: key envelope AES decryption failed" in helper
    assert "BF-IBE MCL: key envelope decrypt complete" not in helper


def test_trace_uses_same_ecall_and_app_emits_compatible_markers_afterward():
    assert "struct c1_asyncs_invoke_trace_t" in EDL
    assert "[out] struct c1_asyncs_invoke_trace_t* invoke_trace" in EDL
    assert "&invoke_trace" in APP
    assert 'print_hex_value("RID_HEX:"' in APP
    assert 'printf("ACSC_TRACE_E3_PAYLOAD:' in APP
    assert 'printf("ACSC_TRACE_FUNCTION_CACHE:' in APP
    assert 'printf("ACSC_TRACE_INTERNAL_TIMING:' in APP
    for field in (
        "function_key_decap_cycles",
        "cfunc_aes_gcm_cycles",
        "wasm_load_cycles",
        "wasm_instantiate_cycles",
    ):
        assert field in APP
        assert field in PROXY
    assert "cpuid_0x15_crystal" in APP
    assert "calibrated_monotonic_raw_20ms" in APP
    main_body = APP[APP.index("int main(") :]
    assert main_body.index("initialize_c1_tsc_frequency();") < main_body.index("run_server_loop();")
    assert "_worker_internal_timing_trace" in PROXY


def test_output_capacity_is_request_selected_but_enclave_bounded():
    assert "uint8_t encrypted_result[4096]" not in APP
    assert "char global_output_buffer[4096]" not in ENCLAVE
    assert "ASYNCS_DEFAULT_OUTPUT_CAPACITY_BYTES = 4096" in APP
    assert "ASYNCS_MAX_OUTPUT_CAPACITY_BYTES = 1024u * 1024u" in APP
    assert "ASYNCS_MAX_OUTPUT_CAPACITY_BYTES = 1024u * 1024u" in ENCLAVE
    assert "std::vector<uint8_t> encrypted_result(max_output_bytes)" in APP
    assert "output_capture_prepare(max_out_size)" in ENCLAVE
    assert 'value.get(\n            "output_capacity_bytes", DEFAULT_OUTPUT_CAPACITY_BYTES' in PROXY
    assert '"--max-output-bytes"' in PROXY


def test_workload_cycles_are_enclave_native_calls_not_wasi_clock_calls():
    assert 'init_args.native_module_name = "env"' in ENCLAVE
    assert '"c1_workload_tsc_begin"' in ENCLAVE
    assert '"c1_workload_tsc_end"' in ENCLAVE
    assert '"c1_workload_set_output"' in ENCLAVE
    assert '"(*~)i"' in ENCLAVE
    assert '"()I"' in ENCLAVE
    assert '"lfence\\n\\trdtsc' in ENCLAVE
    assert '"rdtscp\\n\\tlfence' in ENCLAVE
    assert "println!" not in WORKLOAD
    assert "c1_workload_set_output(output.as_ptr(), output.len())" in WORKLOAD
