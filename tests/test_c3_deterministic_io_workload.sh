#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
crate="$root/workloads/c3_deterministic_io"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

CARGO_TARGET_DIR="$tmp/native-target" cargo test \
  --manifest-path "$crate/Cargo.toml" \
  --offline \
  --locked

CARGO_TARGET_DIR="$tmp/wasm-target" cargo build \
  --manifest-path "$crate/Cargo.toml" \
  --offline \
  --locked \
  --release \
  --target wasm32-wasip1

built="$tmp/wasm-target/wasm32-wasip1/release/asyncs-c3-deterministic-io.wasm"
versioned="$crate/asyncs-c3-deterministic-io.wasm"
wasm-validate --enable-all "$built"
wasm-validate --enable-all "$versioned"
cmp "$built" "$versioned"
wasm-objdump -x "$built" >"$tmp/imports.txt"
grep -Fq '<env.c1_workload_tsc_begin> <- env.c1_workload_tsc_begin' "$tmp/imports.txt"
grep -Fq '<env.c1_workload_tsc_end> <- env.c1_workload_tsc_end' "$tmp/imports.txt"
grep -Fq '<env.c1_workload_set_output> <- env.c1_workload_set_output' "$tmp/imports.txt"
if grep -Eq 'poll_oneoff|clock_time_get|clock_nanosleep' "$tmp/imports.txt"; then
  echo "deterministic I/O workload must not add sleep/clock imports" >&2
  exit 1
fi

python3 - "$crate" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

crate = Path(sys.argv[1])
contract = json.loads((crate / "workload-contract.json").read_text(encoding="utf-8"))
assert contract["artifact_lifecycle"] == "versioned_experiment_input", contract
assert contract["build_command"] == "cargo build --offline --locked --release --target wasm32-wasip1", contract
assert contract["c3_development_probe_bytes"] == 1024, contract
assert contract["c3_development_medium_bytes"] == 65536, contract
assert contract["input_size_parameterized"] is True, contract
assert contract["output_bytes_equal_input_bytes"] is True, contract
assert contract["workload_id"] == "c3-deterministic-io-v1", contract
assert contract["workload_logic_hash"] == "rust-base64-decode-identity-sha256-base64-encode-v1", contract
checks = {
    "artifact_sha256": crate / contract["artifact_file"],
    "source_sha256": crate / "src/main.rs",
    "cargo_lock_sha256": crate / "Cargo.lock",
    "cargo_toml_sha256": crate / "Cargo.toml",
}
for field, path in checks.items():
    assert hashlib.sha256(path.read_bytes()).hexdigest() == contract[field], (field, contract)

for retained in (
    "workloads/backend_pressure_gzip/asyncs-backend-pressure-gzip.wasm",
    "workloads/backend_pressure_gzip64k/asyncs-backend-pressure-gzip64k.wasm",
    "workloads/backend_pressure_sleep50/asyncs-backend-pressure-sleep50.wasm",
    "workloads/backend_pressure_sleep77/asyncs-backend-pressure-sleep77.wasm",
):
    assert (crate.parents[1] / retained).is_file(), retained
PY

echo "PASS: fixed AsynCS C3 deterministic-I/O WASM rebuilds byte-for-byte for 1KiB/64KiB identity I/O"
