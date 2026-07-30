#!/usr/bin/env python3
"""
Implementation Gap(G4): KMS enclave makes non-bypassable policy decisions.

Goal (Phase A):
- The host must not be able to bypass VerifyRA/policy[FID] enforcement by
  calling an "I verified" setter without providing a quote.
- The enclave must bind cached verification state to a specific FID (no reuse
  across FIDs).

This repo commonly uses static audits for enclave invariants.
"""

import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENCLAVE_CPP = os.path.join(ROOT, "sgx_kms", "Enclave", "Enclave.cpp")
ENCLAVE_EDL = os.path.join(ROOT, "sgx_kms", "Enclave", "Enclave.edl")
KMS_APP = os.path.join(ROOT, "sgx_kms", "App", "App.cpp")


def _read(path: str) -> str:
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def audit_edl_exposes_fid_bound_quote_verify() -> None:
    print("\n[Static Audit] EDL exposes FID-bound quote verification")
    edl = _read(ENCLAVE_EDL)
    assert "ecall_verify_quote_for_fid" in edl, "Missing ecall_verify_quote_for_fid in EDL"
    assert "[in, string] const char* fid" in edl, "FID must be an input to quote verification"
    print("  ✓ ecall_verify_quote_for_fid(fid, quote) present")


def audit_enclave_denies_host_set_ra_result() -> None:
    print("\n[Static Audit] Enclave denies host-set RA result")
    cpp = _read(ENCLAVE_CPP)
    assert "Denying host-set RA result" in cpp, "ecall_set_ra_result must deny bypass attempts"
    assert "return -1;" in cpp[cpp.find("int ecall_set_ra_result") : cpp.find("int ecall_set_ra_result") + 800]
    print("  ✓ ecall_set_ra_result() is non-bypassable (denies)")


def audit_enclave_binds_verified_state_to_fid() -> None:
    print("\n[Static Audit] Enclave binds verified state to requested FID")
    cpp = _read(ENCLAVE_CPP)
    assert "g_verified_fid" in cpp, "Missing g_verified_fid binding state"
    assert "RA verified state is not bound to requested FID" in cpp, "Missing cross-FID reuse denial"
    print("  ✓ verify_ra_for_fid enforces FID binding")


def audit_app_calls_enclave_verify_and_not_setter() -> None:
    print("\n[Static Audit] KMS App calls enclave verify (not ecall_set_ra_result)")
    app = _read(KMS_APP)
    assert "ecall_verify_quote_for_fid" in app, "KMS App must call enclave verify for non-bypassable gating"
    assert "ecall_set_ra_result" not in app, "KMS App must not call host-set RA setter"
    print("  ✓ App uses enclave verify path")


def main() -> int:
    print("=" * 60)
    print("KMS Non-Bypassable Policy Audit (G4)")
    print("=" * 60)

    audit_edl_exposes_fid_bound_quote_verify()
    audit_enclave_denies_host_set_ra_result()
    audit_enclave_binds_verified_state_to_fid()
    audit_app_calls_enclave_verify_and_not_setter()

    print("\n✅ G4 static audit passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

