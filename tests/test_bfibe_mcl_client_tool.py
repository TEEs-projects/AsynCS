#!/usr/bin/env python3
import os
import stat
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
BUILD_SCRIPT = ROOT / "scripts" / "build_bfibe_mcl_client_tool.sh"
TOOL_SOURCE = ROOT / "crypto_lib" / "bfibe_mcl_client_tool.cpp"
HOST_MCL_ARCHIVE = ROOT / "_tmp" / "mcl-build" / "mcl" / "lib" / "libmcl.a"


def test_bfibe_mcl_client_tool_source_declares_mcl_compatible_envelope_path():
    source = TOOL_SOURCE.read_text(encoding="utf-8")

    assert "ASBFIBE1" in source
    assert "bfibe-mcl-bls12381" in source
    assert "ASYNCS/BFIBE/G1/GENERATOR/v1" in source
    assert "ASYNCS/BFIBE/AAD/v1" in source
    assert "mclBnG1_hashAndMapTo(g1" in source
    assert "mclBnG1_deserialize(&mpk_g1" in source
    assert "mclBnG2_hashAndMapTo(&q_id" in source
    assert "mclBn_pairing(&temp, &mpk_g1, &q_id)" in source
    assert "mclBnGT_serialize" in source
    assert "EVP_aes_128_gcm" in source


def test_bfibe_mcl_client_tool_build_script_is_executable():
    assert BUILD_SCRIPT.exists()
    assert os.stat(BUILD_SCRIPT).st_mode & stat.S_IXUSR
    content = BUILD_SCRIPT.read_text(encoding="utf-8")
    assert "bfibe_mcl_client_tool.cpp" in content
    assert "libmcl.a" in content
    assert "-lcrypto" in content


def test_bfibe_mcl_client_tool_builds_and_self_tests(tmp_path):
    if not HOST_MCL_ARCHIVE.exists():
        pytest.skip("host MCL archive is not built; run scripts/build_trusted_mcl.sh first")

    out = tmp_path / "bfibe_mcl_client_tool"
    subprocess.run(
        [str(BUILD_SCRIPT), "--out", str(out)],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )

    result = subprocess.run(
        [str(out), "--self-test"],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )

    assert "bfibe_mcl_client_self_test=ok" in result.stdout
