#!/usr/bin/env python3
"""
Implementation Gap(G5): OpenWhisk integration must carry real ct (no mock_ct)

This is a static audit over the Scala invoker integration code:
- Invoker must pass pkU to the worker (so worker can run KEM path)
- Invoker must parse CT_HEX from worker stdout
- Result JSON must include ct from the parsed value (not a mock constant)
"""

import os


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INVOKER_SCALA = os.path.join(
    ROOT,
    "openwhisk",
    "core",
    "invoker",
    "src",
    "main",
    "scala",
    "org",
    "apache",
    "openwhisk",
    "core",
    "invoker",
    "InvokerReactive.scala",
)


def main() -> int:
    print("=" * 60)
    print("OpenWhisk Real ct Audit (G5)")
    print("=" * 60)

    with open(INVOKER_SCALA, "r", encoding="utf-8") as f:
        content = f.read()

    assert "mock_ct" not in content, "Invoker must not return a hard-coded mock ct"
    print("  ✓ mock_ct removed")

    required = [
        'val pkUBase64 = content.fields.get("pkU")',
        "CT_HEX:",
        "ctHexPrefix",
        "pkUPath",
        "Files.write(pkUPath",
        'val cmd = Seq(workerPath, "--invoke", fid, wasmPath.toString, inputPath.toString, pkUPath.toString)',
    ]
    for needle in required:
        assert needle in content, f"Missing expected ct integration logic: {needle}"
    print("  ✓ pkU passed; CT_HEX parsed; ct derived from stdout")

    print("\n✅ G5 static audit passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

