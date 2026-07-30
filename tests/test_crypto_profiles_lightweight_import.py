#!/usr/bin/env python3
"""Import-boundary tests for runtime/container profile selection."""

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_crypto_profiles_import_without_py_ecc() -> None:
    code = r"""
import importlib.abc
import sys

class BlockPyEcc(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "py_ecc" or fullname.startswith("py_ecc."):
            raise ModuleNotFoundError(fullname)
        return None

sys.meta_path.insert(0, BlockPyEcc())
from crypto_lib.profiles import get_crypto_profile

print(get_crypto_profile("bfibe").profile_id)
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT)
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(ROOT),
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "bfibe-mcl-bls12381"
