#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
crate="$root/workloads/backend_pressure_sleep77"
contract="$crate/workload-contract.json"
wamr_root="$(cd "$root/../wasm-micro-runtime" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

CARGO_TARGET_DIR="$tmp/target" cargo build \
  --manifest-path "$crate/Cargo.toml" \
  --offline \
  --locked \
  --release \
  --target wasm32-wasip1

built_wasm="$tmp/target/wasm32-wasip1/release/asyncs-backend-pressure-sleep77.wasm"
versioned_wasm="$crate/asyncs-backend-pressure-sleep77.wasm"
wasm-validate --enable-all "$built_wasm"
wasm-validate --enable-all "$versioned_wasm"
cmp "$built_wasm" "$versioned_wasm"
wasm-objdump -x "$built_wasm" >"$tmp/imports.txt"
grep -Fq '<env.c1_workload_tsc_begin> <- env.c1_workload_tsc_begin' "$tmp/imports.txt"
grep -Fq '<env.c1_workload_tsc_end> <- env.c1_workload_tsc_end' "$tmp/imports.txt"
grep -Fq '<env.c1_workload_set_output> <- env.c1_workload_set_output' "$tmp/imports.txt"
grep -Fq '<wasi_snapshot_preview1.poll_oneoff> <- wasi_snapshot_preview1.poll_oneoff' "$tmp/imports.txt"
if grep -Fq 'clock_time_get' "$tmp/imports.txt"; then
  echo "sleep77 workload should use poll_oneoff without an extra WASI clock query" >&2
  exit 1
fi

grep -Fq 'clock_nanosleep(' \
  "$wamr_root/core/iwasm/libraries/libc-wasi/sandboxed-system-primitives/src/posix.c"
grep -Fq 'ocall_clock_nanosleep(&ret' \
  "$wamr_root/core/shared/platform/linux-sgx/sgx_time.c"
grep -Fq 'return clock_nanosleep' \
  "$wamr_root/core/shared/platform/linux-sgx/untrusted/time.c"

python3 - "$contract" "$built_wasm" "$versioned_wasm" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

contract_path, wasm_path, versioned_path = map(Path, sys.argv[1:])
contract = json.loads(contract_path.read_text(encoding="utf-8"))
assert contract["artifact_lifecycle"] == "versioned_experiment_input", contract
assert contract["build_target"] == "wasm32-wasip1", contract
assert contract["build_command"] == "cargo build --offline --locked --release --target wasm32-wasip1", contract
assert contract["profile"] == "asyncs", contract
assert contract["request_payload_bytes"] == 1024, contract
assert contract["request_payload_in_internal_workload"] is False, contract
assert contract["workload_id"] == "asyncs-wasm-sleep-77ms", contract
assert contract["workload_logic_hash"] == "rust-std-thread-sleep-77ms-v1", contract
assert contract["workload_kind"] == "wasm_sleep", contract
assert contract["workload_sleep_ms"] == 77, contract
assert contract["sleep_releases_cpu"] is True, contract
assert contract["intentional_ocall"] == "wasi_poll_oneoff_to_sgx_clock_nanosleep", contract
assert contract["workload_input_bytes"] == 0, contract
assert contract["workload_input_mode"] == "none", contract
assert contract["workload_compress_level"] == 0, contract
assert hashlib.sha256(wasm_path.read_bytes()).hexdigest() == contract["artifact_sha256"], contract
assert hashlib.sha256(versioned_path.read_bytes()).hexdigest() == contract["artifact_sha256"], contract
PY

grep -Fq 'thread::sleep(Duration::from_millis(SLEEP_MS))' "$crate/src/main.rs"
grep -Fq 'workload_core_cycles' "$crate/src/main.rs"
grep -Fq 'c1_workload_set_output(output.as_ptr(), output.len())' "$crate/src/main.rs"
if grep -Fq 'println!' "$crate/src/main.rs"; then
  echo "sleep77 workload output must use the trusted WAMR host interface" >&2
  exit 1
fi

echo "PASS: AsynCS backend-pressure sleep77 workload releases CPU through the existing WASI/SGX sleep bridge"
