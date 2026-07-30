#!/usr/bin/env python3
"""Build exact-size C2 sleep50 WASM artifacts with deterministic custom padding."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


TARGET_SIZES = (65536, 262144, 1048576, 4194304)
SECTION_NAME = b"asyncs.c2.padding.v1"
PADDING_DOMAIN = b"ASYNCS/C2/SLEEP50/PADDING/v1"


def uleb128(value: int) -> bytes:
    if value < 0:
        raise ValueError("ULEB128 value must be non-negative")
    encoded = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            byte |= 0x80
        encoded.append(byte)
        if not value:
            return bytes(encoded)


def deterministic_padding(target_size: int, length: int) -> bytes:
    output = bytearray()
    counter = 0
    target = target_size.to_bytes(8, "big")
    while len(output) < length:
        output.extend(hashlib.sha256(PADDING_DOMAIN + target + counter.to_bytes(8, "big")).digest())
        counter += 1
    return bytes(output[:length])


def custom_section(target_size: int, padding_length: int) -> bytes:
    payload = uleb128(len(SECTION_NAME)) + SECTION_NAME + deterministic_padding(target_size, padding_length)
    return b"\x00" + uleb128(len(payload)) + payload


def padded_module(base: bytes, target_size: int) -> bytes:
    if not base.startswith(b"\x00asm\x01\x00\x00\x00"):
        raise ValueError("base artifact is not a WebAssembly v1 module")
    if len(base) >= target_size:
        raise ValueError(f"base artifact ({len(base)}) must be smaller than target ({target_size})")

    padding_length = target_size - len(base) - len(SECTION_NAME) - 8
    for _ in range(16):
        section = custom_section(target_size, padding_length)
        delta = target_size - (len(base) + len(section))
        if delta == 0:
            return base + section
        padding_length += delta
        if padding_length < 0:
            break
    raise ValueError(f"could not construct exact-size custom section for {target_size}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    args = parser.parse_args()

    base = args.base.read_bytes()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    for target_size in TARGET_SIZES:
        output = padded_module(base, target_size)
        path = args.output_dir / f"asyncs-c2-sleep50-{target_size}.wasm"
        path.write_bytes(output)
        print(f"{target_size}\t{hashlib.sha256(output).hexdigest()}\t{path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
