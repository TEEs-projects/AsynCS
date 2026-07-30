#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "run_worker_sim_smoke.sh"


def test_worker_sim_smoke_script_uses_sim_only_default_fid_tmpdir() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert "FID=default_fid" in source
    assert "acsc/_tmp/worker-sim-smoke-" in source
    assert 'make -B -C "$ACSC_ROOT/sgx_kms" SGX_MODE=SIM' in source
    assert 'MAKEFLAGS= make -B -C "$ACSC_ROOT/sgx_worker" SGX_MODE=SIM' in source
    assert "client_sdk.worker_smoke_artifacts" in source
    assert "--fid \"$FID\"" in source
    assert "list[str]" not in source


def test_worker_sim_smoke_script_manages_kms_lifecycle_and_double_invoke() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert "KMS_PID=" in source
    assert "RESTORE_KMS_GENERATED=" in source
    assert "trap cleanup EXIT" in source
    assert 'git -C "$ACSC_ROOT" restore -- "${KMS_GENERATED_TRACKED[@]}"' in source
    assert "./sgx_kms --bind-label --fid \"$FID\" --label \"$LABEL\"" in source
    assert "for idx in range(1, 3):" in source
    assert "ENCLAVE_KEY_CACHE_HIT:0" in source
    assert "KMS_CONTACTED:1" in source
    assert "ACSC_TRACE_FUNCTION_CACHE:function_cache_hit=0 cfunc_decrypt_executed=1" in source
    assert "ENCLAVE_KEY_CACHE_HIT:1" in source
    assert "KMS_CONTACTED:0" in source
    assert "ACSC_TRACE_FUNCTION_CACHE:function_cache_hit=1 cfunc_decrypt_executed=0" in source
    assert "ACSC_TRACE_INTERNAL_TIMING:workload_timing_schema=enclave-rdtsc-v1" in source
    assert "ACSC_WORKER_SMOKE_WASM" in source
    assert "ACSC_WORKER_SMOKE_EXPECT_JSON" in source
    assert "json.loads(plaintext.decode" in source
    assert "RC:0" in source


def test_worker_sim_smoke_script_can_select_crypto_profile() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert 'CRYPTO_PROFILE="${ACSC_WORKER_SMOKE_CRYPTO_PROFILE:-eccibe}"' in source
    assert '--crypto-profile "$CRYPTO_PROFILE"' in source
    assert 'EXPECTED_CRYPTO_PROFILE="$(python3 - "$RUN_DIR/metadata.json"' in source
    assert 'print(json.load(open(sys.argv[1], encoding="utf-8"))["crypto_profile"])' in source
    assert 'export ACSC_SMOKE_CRYPTO_PROFILE="$EXPECTED_CRYPTO_PROFILE"' in source
    assert 'os.environ["ASYNCS_CRYPTO_PROFILE"] = crypto_profile' in source
