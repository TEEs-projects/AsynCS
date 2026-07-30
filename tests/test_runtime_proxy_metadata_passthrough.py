#!/usr/bin/env python3
"""
IC4: Runtime proxy must not hardcode default_fid and must plumb protocol metadata.

This is a static audit test (fast, deterministic) to ensure:
1) proxy expects FID, C_k_func, C_key, pkU, nonce in /run payload.
2) proxy invokes sgx_worker with `--keys <C_k_func> <C_key> <pkU> <nonce>`.
3) proxy parses RESULT_HEX and, if present, CT_HEX / RID_HEX.
"""

import os


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROXY = os.path.join(ROOT, "openwhisk_runtime", "proxy.py")


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def main() -> int:
    print("=" * 60)
    print("IC4 Runtime Proxy Metadata Passthrough Audit")
    print("=" * 60)

    proxy = _read(PROXY)

    # Must not hardcode default_fid in worker invocation.
    assert "\"default_fid\"" not in proxy, "proxy.py must not hardcode default_fid"

    # Must require protocol fields on /run.
    for needle in [
        "_require_field(value, \"FID\")",
        "_require_field(value, \"C_k_func\")",
        "_require_field(value, \"C_key\")",
        "_require_field(value, \"pkU\")",
        "_require_field(value, \"nonce\")",
        "_resolve_crypto_metadata(value)",
    ]:
        assert needle in proxy, f"Missing required field check: {needle}"

    for needle in [
        "crypto_profile",
        "key_ciphertext_format",
        "UnsupportedCryptoProfileError",
    ]:
        assert needle in proxy, f"Missing crypto metadata validation: {needle}"

    # Must pass --keys and the four files into sgx_worker.
    for needle in [
        "\"--keys\"",
        "CKFUNC_FILE",
        "CKEY_FILE",
        "PKU_FILE",
        "NONCE_FILE",
    ]:
        assert needle in proxy, f"Missing worker key plumbing: {needle}"

    # Must parse these worker markers.
    for needle in [
        "markers.get(\"RID_HEX\")",
        "markers.get(\"CT_HEX\")",
        "markers.get(\"RESULT_HEX\")",
        "markers.get(\"ACSC_TRACE_INTERNAL_TIMING\")",
        "workload_core_cycles",
        "output_kem_cycles",
        "output_aes_gcm_cycles",
        "tsc_frequency_method",
    ]:
        assert needle in proxy, f"Missing output prefix parsing: {needle}"

    print("✅ IC4 static audit passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
