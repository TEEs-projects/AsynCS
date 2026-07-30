#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
crate="$root/workloads/backend_pressure_gzip"
runtime_smoke="$root/run_openwhisk_runtime_sim_smoke.sh"
contract="$crate/workload-contract.json"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

CARGO_TARGET_DIR="$tmp/target" cargo build \
  --manifest-path "$crate/Cargo.toml" \
  --offline \
  --locked \
  --release \
  --target wasm32-wasip1

built_wasm="$tmp/target/wasm32-wasip1/release/asyncs-backend-pressure-gzip.wasm"
versioned_wasm="$crate/asyncs-backend-pressure-gzip.wasm"
wasm-validate --enable-all "$built_wasm"
wasm-validate --enable-all "$versioned_wasm"
cmp "$built_wasm" "$versioned_wasm"
wasm-objdump -x "$built_wasm" >"$tmp/imports.txt"
grep -Fq '<env.c1_workload_tsc_begin> <- env.c1_workload_tsc_begin' "$tmp/imports.txt"
grep -Fq '<env.c1_workload_tsc_end> <- env.c1_workload_tsc_end' "$tmp/imports.txt"
grep -Fq '<env.c1_workload_set_output> <- env.c1_workload_set_output' "$tmp/imports.txt"
if grep -Fq 'clock_time_get' "$tmp/imports.txt"; then
  echo "backend-pressure workload must not import WASI clock_time_get" >&2
  exit 1
fi

python3 - <<'PY'
import hashlib

size = 524288
phrase = b"asyn-c1-backend-pressure-compress-workload-"
payload = bytearray(size)
for i in range(size):
    payload[i] = phrase[i % len(phrase)] if i < size // 2 else (i * 1103515245 + 12345) & 0xff
assert hashlib.sha256(payload).hexdigest() == "b9f2f3ff57c9532e291bb9f60ab41d68cfae9da9824620019767ba9327afb5e8"
PY

python3 - "$contract" "$built_wasm" "$versioned_wasm" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

contract_path, wasm_path, versioned_path = map(Path, sys.argv[1:])
contract = json.loads(contract_path.read_text(encoding="utf-8"))
assert contract["artifact_lifecycle"] == "versioned_experiment_input", contract
assert contract["schema_version"] == "c1-asyncs-backend-pressure-workload-v2", contract
assert contract["build_target"] == "wasm32-wasip1", contract
assert contract["build_command"] == "cargo build --offline --locked --release --target wasm32-wasip1", contract
assert contract["profile"] == "asyncs", contract
assert contract["request_payload_bytes"] == 1024, contract
assert contract["request_payload_in_internal_workload"] is False, contract
assert contract["workload_input_bytes"] == 524288, contract
assert contract["workload_input_mode"] == "mixed", contract
assert contract["workload_compress_level"] == 6, contract
assert contract["duration_evidence"] == [
    "workload_core_cycles",
    "output_kem_cycles",
    "output_aes_gcm_cycles",
    "worker_exec_dur_ns",
], contract
assert contract["timing_contract"] == {
    "derived_duration_policy": "only_when_tsc_hz_and_method_are_observed",
    "tsc_frequency_method": "cpuid_0x15_crystal_or_calibrated_monotonic_raw_20ms_or_unavailable",
    "workload_timing_schema": "enclave-rdtsc-v1",
}, contract
assert hashlib.sha256(wasm_path.read_bytes()).hexdigest() == contract["artifact_sha256"], contract
assert hashlib.sha256(versioned_path.read_bytes()).hexdigest() == contract["artifact_sha256"], contract
PY

grep -Fq 'workload_timing_schema\":\"enclave-rdtsc-v1' "$crate/src/main.rs"
grep -Fq 'workload_core_cycles' "$crate/src/main.rs"
grep -Fq 'c1_workload_set_output(output.as_ptr(), output.len())' "$crate/src/main.rs"
if grep -Fq 'println!' "$crate/src/main.rs"; then
  echo "backend-pressure workload output must use the trusted WAMR host interface" >&2
  exit 1
fi
if grep -Fq 'std::time::Instant' "$crate/src/main.rs"; then
  echo "backend-pressure workload must use the enclave TSC host interface" >&2
  exit 1
fi

grep -Fq 'CUSTOM_WASM="${ACSC_OPENWHISK_RUNTIME_WASM:-}"' "$runtime_smoke"
grep -Fq 'cp -f "$CUSTOM_WASM" "$RUN_DIR/minimal.wasm"' "$runtime_smoke"
grep -Fq '(func (export "_start"))' "$runtime_smoke"

echo "PASS: AsynCS backend-pressure workload source build and preparation contract"
