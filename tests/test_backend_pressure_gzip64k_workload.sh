#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
crate="$root/workloads/backend_pressure_gzip64k"
baseline="$root/workloads/backend_pressure_gzip"
contract="$crate/workload-contract.json"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

CARGO_TARGET_DIR="$tmp/target" cargo build \
  --manifest-path "$crate/Cargo.toml" \
  --offline \
  --locked \
  --release \
  --target wasm32-wasip1

built_wasm="$tmp/target/wasm32-wasip1/release/asyncs-backend-pressure-gzip64k.wasm"
versioned_wasm="$crate/asyncs-backend-pressure-gzip64k.wasm"
wasm-validate --enable-all "$built_wasm"
wasm-validate --enable-all "$versioned_wasm"
cmp "$built_wasm" "$versioned_wasm"
wasm-objdump -x "$built_wasm" >"$tmp/imports.txt"
grep -Fq '<env.c1_workload_tsc_begin> <- env.c1_workload_tsc_begin' "$tmp/imports.txt"
grep -Fq '<env.c1_workload_tsc_end> <- env.c1_workload_tsc_end' "$tmp/imports.txt"
grep -Fq '<env.c1_workload_set_output> <- env.c1_workload_set_output' "$tmp/imports.txt"
if grep -Fq 'clock_time_get' "$tmp/imports.txt"; then
  echo "backend-pressure gzip64k workload must not import WASI clock_time_get" >&2
  exit 1
fi

python3 - "$baseline" "$crate" "$contract" "$built_wasm" "$versioned_wasm" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

baseline, crate, contract_path, built_path, versioned_path = map(Path, sys.argv[1:])
size = 65_536
phrase = b"asyn-c1-backend-pressure-compress-workload-"
payload = bytes(
    phrase[index % len(phrase)]
    if index < size // 2
    else (index * 1_103_515_245 + 12_345) & 0xFF
    for index in range(size)
)
input_sha = hashlib.sha256(payload).hexdigest()
assert input_sha == "5ea5463bc5e1db3151bde51f6a8bd72abb70331f337d6a25ca6049ca7c439095"

baseline_source = (baseline / "src/main.rs").read_text(encoding="utf-8")
candidate_source = (crate / "src/main.rs").read_text(encoding="utf-8")
normalized = (
    candidate_source
    .replace("65_536", "524_288")
    .replace("asyncs-wasm-gzip-level6-mixed-64k", "asyncs-wasm-gzip-level6-mixed-512k")
    .replace(
        "rust-flate2-gzip-level6-mixed-65536-v1",
        "rust-flate2-gzip-level6-mixed-524288-v1",
    )
    .replace(input_sha, "b9f2f3ff57c9532e291bb9f60ab41d68cfae9da9824620019767ba9327afb5e8")
)
assert normalized == baseline_source, "64KiB source differs from the 512KiB algorithm beyond declared constants"

contract = json.loads(contract_path.read_text(encoding="utf-8"))
assert contract["artifact_lifecycle"] == "versioned_experiment_input", contract
assert contract["schema_version"] == "c1-asyncs-backend-pressure-workload-v2", contract
assert contract["build_command"] == "cargo build --offline --locked --release --target wasm32-wasip1", contract
assert contract["build_target"] == "wasm32-wasip1", contract
assert contract["compression_implementation"] == "flate2-1.1.9-rust_backend-miniz_oxide-0.8.9", contract
assert contract["request_payload_bytes"] == 1024, contract
assert contract["request_payload_in_internal_workload"] is False, contract
assert contract["workload_id"] == "asyncs-wasm-gzip-level6-mixed-64k", contract
assert contract["workload_logic_hash"] == "rust-flate2-gzip-level6-mixed-65536-v1", contract
assert contract["workload_kind"] == "wasm_gzip_sync", contract
assert contract["workload_input_bytes"] == 65_536, contract
assert contract["workload_input_mode"] == "mixed", contract
assert contract["workload_compress_level"] == 6, contract
assert contract["workload_input_sha256"] == input_sha, contract
assert contract["workload_output_bytes"] == 635, contract
assert contract["workload_output_sha256"] == "95ea9e48f2cbdedb3267a467fd2f20cad1e08dec511cf20074e161161804c075", contract
for path in (built_path, versioned_path):
    assert hashlib.sha256(path.read_bytes()).hexdigest() == contract["artifact_sha256"], path

baseline_contract = json.loads((baseline / "workload-contract.json").read_text(encoding="utf-8"))
baseline_artifact = baseline / baseline_contract["artifact"]
assert baseline_artifact.is_file(), baseline_artifact
assert hashlib.sha256(baseline_artifact.read_bytes()).hexdigest() == baseline_contract["artifact_sha256"]
PY

grep -Fq 'workload_timing_schema\":\"enclave-rdtsc-v1' "$crate/src/main.rs"
grep -Fq 'workload_core_cycles' "$crate/src/main.rs"
grep -Fq 'c1_workload_set_output(output.as_ptr(), output.len())' "$crate/src/main.rs"
if grep -Fq 'println!' "$crate/src/main.rs"; then
  echo "backend-pressure gzip64k output must use the trusted WAMR host interface" >&2
  exit 1
fi

echo "PASS: AsynCS backend-pressure gzip64k versioned workload contract"
