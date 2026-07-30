#!/usr/bin/env python3
"""
Static guard for BF-IBE KMS-to-worker key-release payloads.

Until the worker enclave can load serialized BF identity private keys, the host
must not classify a variable-length BF key-release envelope as the legacy
248-byte dkf||dklabel response.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKER_APP = ROOT / "sgx_worker" / "App" / "App.cpp"


def test_worker_host_detects_bfibe_key_release_before_legacy_size_path():
    source = WORKER_APP.read_text()

    assert "BFIBE_KEY_RELEASE_MAGIC" in source
    assert "ASBFREL1" in source
    assert "is_bfibe_key_release_response(buffer, valread)" in source
    assert "ecall_load_bfibe_key_release(" in source
    assert "BF-IBE key-release boundary returned" in source

    guard_idx = source.index("is_bfibe_key_release_response(buffer, valread)")
    legacy_idx = source.index("valread >= KMS_KEYS_LEN")
    assert guard_idx < legacy_idx
