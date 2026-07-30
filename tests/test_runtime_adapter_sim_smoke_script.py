#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "run_runtime_adapter_sim_smoke.sh"


def test_runtime_adapter_sim_smoke_uses_local_runtime_config() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert "acsc/_tmp/runtime-adapter-sim-smoke-" in source
    assert 'make -B -C "$ACSC_ROOT/sgx_kms" SGX_MODE=SIM' in source
    assert 'MAKEFLAGS= make -B -C "$ACSC_ROOT/sgx_worker" SGX_MODE=SIM' in source
    assert "ACSC_RUNTIME_APP_DIR" in source
    assert "ACSC_RUNTIME_WORKER_PATH" in source
    assert "ACSC_RUNTIME_WORKER_CWD" in source
    assert "ACSC_RUNTIME_PORT" in source
    assert "PROXY_PID=" in source
    assert "client_sdk.worker_smoke_artifacts" in source


def test_runtime_adapter_sim_smoke_can_select_crypto_profile() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert 'CRYPTO_PROFILE="${ACSC_RUNTIME_ADAPTER_SMOKE_CRYPTO_PROFILE:-eccibe}"' in source
    assert '--crypto-profile "$CRYPTO_PROFILE"' in source
    assert '"crypto_profile": metadata["crypto_profile"]' in source
    assert '"key_ciphertext_format": metadata["key_ciphertext_format"]' in source


def test_runtime_adapter_sim_smoke_exercises_init_run_reset() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert "urllib.request" in source
    assert "test_client" not in source
    assert 'post_json("/init"' in source
    assert 'post_json("/run"' in source
    assert 'post_json("/reset"' in source
    assert "for idx in range(1, 3):" in source
    assert "worker_started_this_invocation" in source
    assert "kms_contacted" in source
    assert "enclave_key_cache_hit" in source
    assert "function_cache_hit" in source
    assert "cfunc_decrypt_executed" in source
    assert "function_cache_bytes" in source
    assert "RUNTIME_SMOKE_OK" in source


def test_runtime_adapter_sim_smoke_requires_kms_timing_breakdown() -> None:
    source = SCRIPT.read_text(encoding="utf-8")

    assert "positive_when_contacted" in source
    assert '"kms_verify_dur_ns"' in source
    assert '"kms_key_release_dur_ns"' in source
    assert '"kms_total_dur_ns"' in source
    assert 'if trace.get("kms_contacted"):' in source
    assert 'require(value > 0, f"run {idx} expected positive {key}' in source
    assert 'require(value == 0, f"run {idx} expected zero {key}' in source
