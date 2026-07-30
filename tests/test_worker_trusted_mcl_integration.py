#!/usr/bin/env python3
"""
Static contract for worker-side trusted MCL integration.

The BF-IBE path must execute pairing operations inside the worker enclave, not
fall back to the historical App-side demo.
"""

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKER_MAKEFILE = ROOT / "sgx_worker" / "Makefile"
WORKER_ENCLAVE_CPP = ROOT / "sgx_worker" / "Enclave" / "Enclave.cpp"
WORKER_MCL_HEADER = ROOT / "sgx_worker" / "Enclave" / "mcl_ibe.h"
WORKER_APP = ROOT / "sgx_worker" / "App" / "App.cpp"


def test_worker_makefile_links_trusted_mcl_into_enclave():
    makefile = WORKER_MAKEFILE.read_text()

    assert "TRUSTED_MCL_PREFIX" in makefile
    assert "Enclave/mcl_ibe.cpp" in makefile
    assert "-I$(TRUSTED_MCL_PREFIX)/include" in makefile
    assert "-L$(TRUSTED_MCL_PREFIX)/lib" in makefile
    assert "-lmcl_trusted" in makefile
    for needle in (
        "MCL_DONT_USE_XBYAK",
        "MCL_DONT_USE_CSPRNG",
        "CYBOZU_DONT_USE_EXCEPTION",
        "CYBOZU_DONT_USE_STRING",
        "MCL_BINT_ASM=0",
        "MCL_MSM=0",
        "NDEBUG",
        "fno-threadsafe-statics",
    ):
        assert needle in makefile


def test_worker_makefile_disables_parallel_edger8r_generation():
    makefile = WORKER_MAKEFILE.read_text()

    assert ".NOTPARALLEL:" in makefile
    assert "sgx_edger8r writes paired generated files" in makefile
    assert ".PHONY: all clean FORCE" in makefile
    assert "App/Enclave_u.c App/Enclave_u.h: FORCE" in makefile
    assert "Enclave/Enclave_t.c Enclave/Enclave_t.h: FORCE" in makefile


def test_worker_enclave_mcl_test_runs_inside_enclave_roundtrip():
    source = WORKER_ENCLAVE_CPP.read_text()

    assert '#include "mcl_ibe.h"' in source
    assert "NOTE: IBE implementation has been moved to App side" not in source
    assert "mcl_ibe_setup(" in source
    assert "mcl_ibe_extract(" in source
    assert "mcl_ibe_encrypt(" in source
    assert "mcl_ibe_decrypt(" in source
    assert "MCL IBE: Enclave roundtrip OK" in source


def test_worker_mcl_header_describes_current_g1_g2_roles():
    header = WORKER_MCL_HEADER.read_text()

    assert "MPK = msk * G1" in header
    assert "sk_id = msk * H(id) in G2" in header


def test_worker_ibe_test_cli_calls_enclave_mcl_smoke():
    app = WORKER_APP.read_text()

    ibe_branch = app[app.index('--ibe-test"') : app.index('} else if', app.index('--ibe-test"'))]
    assert "ecall_mcl_ibe_test(global_eid" in ibe_branch
    assert "app_ibe_test()" not in ibe_branch
    assert "App-side IBE" not in ibe_branch
