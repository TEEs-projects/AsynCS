#!/usr/bin/env python3
import base64
import importlib.util
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
PROXY_PATH = ROOT / "openwhisk_runtime" / "proxy.py"


def load_proxy():
    spec = importlib.util.spec_from_file_location("acsc_c5_proxy_under_test", PROXY_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def base_payload() -> dict:
    return {
        "value": {
            "FID": "ab" * 32,
            "encrypted_input": b64(b"iv-tag-ciphertext"),
            "C_k_func": b64(b"function-key"),
            "C_key": b64(b"request-key"),
            "pkU": b64(b"\x04" + b"\x01" * 64),
            "nonce": b64(b"\x02" * 16),
        }
    }


def representative_response() -> dict:
    internal = {
        "input_key_decap_begin_cycles": 10,
        "input_key_decap_end_cycles": 20,
        "input_aes_gcm_begin_cycles": 21,
        "input_aes_gcm_end_cycles": 30,
        "workload_begin_cycles": 31,
        "workload_end_cycles": 80,
        "output_kem_begin_cycles": 81,
        "output_kem_end_cycles": 90,
        "output_aes_gcm_begin_cycles": 91,
        "output_aes_gcm_end_cycles": 100,
        "workload_core_duration_ns": 50_000_000,
        "tsc_hz": 2_500_000_000,
        "tsc_frequency_method": "cpuid_0x15_crystal",
    }
    trace = {
        **internal,
        "container_hostname": "c5-container",
        "worker_started_this_invocation": False,
        "kms_contacted": False,
        "enclave_key_cache_hit": True,
        "function_cache_hit": True,
        "payload_bytes_consumed": 47,
        "payload_sha256": "11" * 32,
        "internal_timing_summary": internal,
        "worker_invoke_summary": {"many": "duplicated fields"},
        "producer_timing_events": [
            {"event_code": "A200", "unix_ns": 1, "attrs": {"boundary": "adapter"}},
            {"event_code": "A400", "unix_ns": 2, "mono_ns": 3},
            {"event_code": "A410", "unix_ns": 4, "mono_ns": 5},
        ],
    }
    return {
        "C_out": b64(b"encrypted-c5-summary" * 40),
        "ct": b64(b"\x04" + b"\x03" * 64),
        "rid": "22" * 32,
        "trace": trace,
    }


def test_c5_measured_response_is_exactly_4096_and_keeps_crypto_evidence() -> None:
    proxy = load_proxy()
    original = representative_response()

    result = proxy._c5_fixed_measured_response(original)

    assert len(json.dumps(result, separators=(",", ":")).encode("utf-8")) == 4096
    assert result["C_out"] == original["C_out"]
    assert result["ct"] == original["ct"]
    assert result["rid"] == original["rid"]
    assert result["trace"]["schema_version"] == "c5-asyncs-compact-trace-v1"
    assert [event["event_code"] for event in result["trace"]["producer_timing_events"]] == [
        "A400",
        "A410",
    ]
    assert "internal_timing_summary" not in result["trace"]
    assert "worker_invoke_summary" not in result["trace"]
    assert result["trace"]["workload_core_duration_ns"] == 50_000_000


def test_c5_measured_response_fails_closed_when_ciphertext_cannot_fit() -> None:
    proxy = load_proxy()
    response = representative_response()
    response["C_out"] = "A" * 5000

    with pytest.raises(ValueError, match="exceeds 4096"):
        proxy._c5_fixed_measured_response(response)


def test_c5_result_size_requires_explicit_c5_schema() -> None:
    proxy = load_proxy()
    payload = base_payload()
    payload["value"]["c5_result_json_bytes"] = 4096

    response = proxy.app.test_client().post("/run", json=payload)

    assert response.status_code == 400
    assert response.get_json() == {
        "error": "C5 measured result requires c5-asyncs-request-v1"
    }
