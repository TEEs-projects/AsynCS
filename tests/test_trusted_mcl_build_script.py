#!/usr/bin/env python3
"""
Static checks for the SGX-safe trusted MCL build script.

The real BF-IBE profile must be backed by a reproducible MCL/BLS12-381 build
that avoids host CPU dispatch and illegal enclave instructions.
"""

import os
import stat
import subprocess


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCRIPT = os.path.join(ROOT, "scripts", "build_trusted_mcl.sh")


def test_trusted_mcl_build_script_exists_and_is_executable():
    assert os.path.exists(SCRIPT), "Missing scripts/build_trusted_mcl.sh"
    mode = os.stat(SCRIPT).st_mode
    assert mode & stat.S_IXUSR, "scripts/build_trusted_mcl.sh must be executable"


def test_trusted_mcl_build_script_pins_verified_commit_and_flags():
    with open(SCRIPT, "r", encoding="utf-8") as f:
        content = f.read()

    required = [
        "0499298adcfad3bbcebf77f17700ebbe97166060",
        "MCL_USE_XBYAK=0",
        "MCL_BINT_ASM=0",
        "MCL_BINT_ASM_X64=0",
        "MCL_MSM=0",
        "MCL_USE_GMP=0",
        "MCL_USE_GMP_LIB=0",
        "MCL_DONT_USE_XBYAK",
        "MCL_DONT_USE_CSPRNG",
        "CYBOZU_DONT_USE_EXCEPTION",
        "CYBOZU_DONT_USE_STRING",
        "CYBOZU_HOST=0",
        "MCL_FP_BIT=384",
        "MCL_FR_BIT=256",
        "-DNDEBUG",
        "-fno-threadsafe-statics",
    ]
    for needle in required:
        assert needle in content, f"Missing SGX-safe MCL build setting: {needle}"


def test_trusted_mcl_build_script_checks_forbidden_instructions():
    with open(SCRIPT, "r", encoding="utf-8") as f:
        content = f.read()

    for needle in ("cpuid", "syscall", "xsave", "xrstor"):
        assert needle in content, f"Missing forbidden-instruction check for {needle}"

    assert "objdump" in content, "Build script must inspect trusted archive objects"
    assert "__assert_fail" in content, "Build script must reject host assert dependencies"


def test_trusted_mcl_check_only_accepts_repo_local_relative_archive_paths():
    check_dir = os.path.join(ROOT, "_tmp", "trusted-mcl-check-only-test")
    os.makedirs(check_dir, exist_ok=True)
    archive = os.path.join(check_dir, "empty.a")
    subprocess.run(["ar", "rcs", str(archive)], check=True)
    relative_archive = os.path.relpath(archive, ROOT)

    result = subprocess.run(
        [SCRIPT, "--check-only", relative_archive],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )

    assert "trusted-mcl-forbidden-instruction-check=ok" in result.stdout
