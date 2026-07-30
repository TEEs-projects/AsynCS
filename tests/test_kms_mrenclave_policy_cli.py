#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_kms_supports_explicit_mrenclave_policy_file():
    app = (ROOT / "sgx_kms" / "App" / "App.cpp").read_text()

    assert "mrenclave_policy_file" in app
    assert 'std::string mrenclave_policy_file = "kms_policy.txt";' in app
    assert 'strcmp(argv[i], "--policy-file") == 0' in app
    assert 'Usage: %s --policy-file <MRENCLAVE_ALLOWLIST_FILE>' in app
    assert "load_policy_from_file(mrenclave_policy_file.c_str())" in app
