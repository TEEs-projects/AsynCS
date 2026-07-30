#!/usr/bin/env python3
"""
Protocol(B): Worker enclave computes RID locally and never trusts control plane.

This repo validates protocol alignment via a mix of unit tests and static audits.
This test covers:
  1) Static audit of SGX Worker enclave source: RID := H(FID || C_req) is computed
     inside the enclave and returned through the same bounded ECALL trace.
  2) Control-plane defense-in-depth: if an activation message includes a bogus RID,
     the invoker parsing path does not treat it as authoritative.
"""

import base64
import json
import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENCLAVE_CPP = os.path.join(ROOT, "sgx_worker", "Enclave", "Enclave.cpp")
APP_CPP = os.path.join(ROOT, "sgx_worker", "App", "App.cpp")

sys.path.insert(0, ROOT)

from openwhisk_extensions.invoker.confidential_invoker import ConfidentialActionsInvoker  # noqa: E402


def static_audit_enclave_rid() -> None:
    print("\n[Static Audit] SGX Worker enclave computes RID locally")

    with open(ENCLAVE_CPP, "r", encoding="utf-8") as f:
        content = f.read()
    with open(APP_CPP, "r", encoding="utf-8") as f:
        app = f.read()

    required = [
        "compute_rid_from_fid_and_c_req",
        "memcpy(invoke_trace->rid, rid32",
        "C1_TRACE_RID_VALID",
        "memcpy(c_req_full, input_iv, 12);",
        "memcpy(c_req_full + 12, input_mac, 16);",
        "memcpy(c_req_full + 28, encrypted_input, input_size);",
        "compute_rid_from_fid_and_c_req(invocation_fid, c_req_full",
    ]
    for needle in required:
        assert needle in content, f"Missing expected RID logic in enclave: {needle}"
    assert 'print_hex_value("RID_HEX:", invoke_trace.rid' in app

    # Ensure the enclave ECALL signatures don't accept a control-plane RID parameter.
    forbidden = [
        "ecall_run_encrypted_wasm(",
        "ecall_run_encrypted_wasm_kem(",
    ]
    for fn in forbidden:
        start = content.find(fn)
        assert start != -1, f"Missing function definition: {fn}"
        sig = content[start : start + 500]
        assert "rid" not in sig.lower(), f"Unexpected RID parameter in enclave ECALL signature: {fn}"

    print("  ✓ Enclave computes RID := H(FID || C_req) and returns it without accepting RID input")


def invoker_ignores_control_plane_rid() -> None:
    print("\n[Unit Test] Invoker ignores control-plane RID field")

    invoker = ConfidentialActionsInvoker()

    fid = "test_fid_protocolB"
    c_req = b"\x01\x02\x03C_REQ_BYTES"
    bogus_rid = "deadbeef" * 8

    message = {
        "activationId": "act-xyz",
        "action": {"path": "guest", "name": "confidentialAction"},
        "content": {
            "FID": fid,
            "C_req": base64.b64encode(c_req).decode("utf-8"),
            "C_key": base64.b64encode(b"encrypted_key").decode("utf-8"),
            "pkU": base64.b64encode(b"user_public_key").decode("utf-8"),
            # Bogus RID injected by an untrusted control plane.
            "RID": bogus_rid,
        },
        "nonce": base64.b64encode(b"fresh_nonce").decode("utf-8"),
    }

    activation = invoker.receive_activation(json.dumps(message).encode("utf-8"))

    expected_rid = invoker.compute_rid(fid, c_req)
    assert expected_rid != bogus_rid, "Bogus RID should not match expected RID"

    # Defense-in-depth: receive_activation should not treat RID as a trusted field.
    assert "RID" not in activation, "Invoker should not expose control-plane RID as a parsed field"
    assert "rid" not in activation, "Invoker should not expose control-plane rid as a parsed field"

    # When storing, RID is derived from (FID, C_req) rather than any injected value.
    stored_success, stored_rid = invoker.store_result(fid, c_req, b"ct", b"c_out")
    assert stored_success, "First store should succeed"
    assert stored_rid == expected_rid, "Stored RID must be H(FID || C_req)"

    print("  ✓ Control-plane RID ignored; RID derived from (FID, C_req)")


def main() -> int:
    print("=" * 60)
    print("Protocol(B) RID Local Computation Tests")
    print("=" * 60)

    static_audit_enclave_rid()
    invoker_ignores_control_plane_rid()

    print("\n✅ Protocol(B) RID local computation verified.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
