#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
top_root="${C5_REUSABLE_TOP_ROOT:-$(cd "$root/.." && pwd)}"
crate="$root/workloads/c5_representative_warm"
shared="$top_root/experiments/current-scripts/C5/shared"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

export C5_DYNAMIC_TEMPLATE_PATH="$shared/dynamic-html-template-v1.html"
export C5_DYNAMIC_DATA_PATH="$shared/dynamic-html-data-v1.json"
export C5_DYNAMIC_EXPECTED_PATH="$shared/expected-dynamic-html-v1.html"
export C5_COMPRESSION_INPUT_PATH="$shared/random-256k-v1.bin"

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

built="$tmp/wasm-target/wasm32-wasip1/release/asyncs-c5-representative-warm.wasm"
versioned="$crate/asyncs-c5-representative-warm.wasm"
wasm-validate --enable-all "$built"
wasm-validate --enable-all "$versioned"
cmp "$built" "$versioned"
wasm-objdump -x "$built" >"$tmp/imports.txt"
grep -Fq '<env.c1_workload_tsc_begin> <- env.c1_workload_tsc_begin' "$tmp/imports.txt"
grep -Fq '<env.c1_workload_tsc_end> <- env.c1_workload_tsc_end' "$tmp/imports.txt"
grep -Fq '<env.c1_workload_set_output> <- env.c1_workload_set_output' "$tmp/imports.txt"
grep -Fq '<wasi_snapshot_preview1.poll_oneoff> <- wasi_snapshot_preview1.poll_oneoff' "$tmp/imports.txt"
if grep -Eq 'clock_time_get|clock_nanosleep' "$tmp/imports.txt"; then
  echo "C5 workload must use the supported poll_oneoff bridge without another clock import" >&2
  exit 1
fi

python3 - "$crate" "$top_root" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

crate = Path(sys.argv[1])
top = Path(sys.argv[2])
contract = json.loads((crate / "workload-contract.json").read_text(encoding="utf-8"))
shared = json.loads(
    (top / contract["shared_contract"]["relative_path"]).read_text(encoding="utf-8")
)
assert contract["artifact_lifecycle"] == "versioned_experiment_input", contract
assert contract["build_target"] == "wasm32-wasip1", contract
assert contract["suite_id"] == shared["suite_id"] == "c5-representative-warm-v1"
assert contract["crypto_and_transport"]["measured_action_params_json_bytes"] == 1024
assert contract["crypto_and_transport"]["measured_result_json_bytes"] == 4096
assert set(contract["workloads"]) == set(shared["workloads"])
assert contract["shared_contract"]["sha256"] == hashlib.sha256(
    (top / contract["shared_contract"]["relative_path"]).read_bytes()
).hexdigest()
checks = {
    "artifact_sha256": crate / contract["artifact_file"],
    "source_sha256": crate / "src/main.rs",
    "cargo_lock_sha256": crate / "Cargo.lock",
    "cargo_toml_sha256": crate / "Cargo.toml",
}
for field, path in checks.items():
    assert hashlib.sha256(path.read_bytes()).hexdigest() == contract[field], (field, path)
assert (crate / contract["artifact_file"]).stat().st_size == contract["artifact_size_bytes"]
for workload_id, workload in contract["workloads"].items():
    shared_workload = shared["workloads"][workload_id]
    assert workload["workload_logic_hash"] == shared_workload["workload_logic_hash"]
    assert workload["application_input_bytes"] == shared_workload["application_input_bytes"]
    assert workload["application_input_sha256"] == shared_workload["application_input_sha256"]
    assert workload["output_verification"] == shared_workload["output_verification"]
assert contract["workloads"]["sleep50-path-control-v1"]["intentional_ocall"] == (
    "wasi_poll_oneoff_to_sgx_clock_nanosleep"
)
assert all(
    workload["intentional_ocall"] == "none"
    for name, workload in contract["workloads"].items()
    if name != "sleep50-path-control-v1"
)
PY

echo "PASS: AsynCS C5 workload rebuilds byte-for-byte and implements the frozen shared suite"
