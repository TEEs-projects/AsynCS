from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "sgx_worker" / "Enclave" / "Enclave.cpp"


def test_decrypted_input_is_configured_as_wasi_argv_before_instantiation():
    source = SOURCE.read_text(encoding="utf-8")
    helper = source[source.index("bool run_wasm_helper(") : source.index("void ecall_run_wasm(")]

    argv = 'char *argv[] = { (char*)"wasm_app", input_str };'
    set_args = "wasm_runtime_set_wasi_args(module, NULL, 0, NULL, 0, NULL, 0, argv, argc);"
    instantiate = "wasm_runtime_instantiate(module, 16384, 16384, error_buf, sizeof(error_buf))"
    execute = "wasm_application_execute_main(module_inst, argc, argv)"

    assert argv in helper
    assert set_args in helper
    assert helper.index(set_args) < helper.index(instantiate) < helper.index(execute)
