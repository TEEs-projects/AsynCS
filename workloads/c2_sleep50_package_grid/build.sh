#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
grid="$root/workloads/c2_sleep50_package_grid"
base="$root/workloads/backend_pressure_sleep50/asyncs-backend-pressure-sleep50.wasm"
contract="$grid/package-grid-contract.json"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

python3 "$grid/build_artifacts.py" --base "$base" --output-dir "$tmp/generated" >"$tmp/generated.tsv"

for target in 65536 262144 1048576 4194304; do
  generated="$tmp/generated/asyncs-c2-sleep50-$target.wasm"
  versioned="$grid/asyncs-c2-sleep50-$target.wasm"
  [[ "$(stat -c%s "$generated")" == "$target" ]]
  wasm-validate --enable-all "$generated"
  wasm-validate --enable-all "$versioned"
  cmp "$generated" "$versioned"
done

wasm-objdump -x "$tmp/generated/asyncs-c2-sleep50-65536.wasm" >"$tmp/imports.txt"
grep -Fq '<env.c1_workload_tsc_begin> <- env.c1_workload_tsc_begin' "$tmp/imports.txt"
grep -Fq '<env.c1_workload_tsc_end> <- env.c1_workload_tsc_end' "$tmp/imports.txt"
grep -Fq '<env.c1_workload_set_output> <- env.c1_workload_set_output' "$tmp/imports.txt"
grep -Fq '<wasi_snapshot_preview1.poll_oneoff> <- wasi_snapshot_preview1.poll_oneoff' "$tmp/imports.txt"
if grep -Fq 'clock_time_get' "$tmp/imports.txt"; then
  echo "C2 sleep50 artifacts must retain the single poll_oneoff sleep path" >&2
  exit 1
fi

python3 - "$contract" "$base" "$grid" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

contract_path, base_path, grid = map(Path, sys.argv[1:])
contract = json.loads(contract_path.read_text(encoding="utf-8"))
base = base_path.read_bytes()
assert contract["schema_version"] == "c2-asyncs-sleep50-package-grid-v1"
assert contract["artifact_lifecycle"] == "versioned_experiment_input"
assert contract["workload_id"] == "asyncs-wasm-sleep-50ms"
assert contract["workload_logic_hash"] == "rust-std-thread-sleep-50ms-v1"
assert contract["workload_sleep_ms"] == 50
assert contract["padding_method"] == "deterministic_webassembly_custom_section_v1"
assert hashlib.sha256(base).hexdigest() == contract["base_artifact_sha256"]
for item in contract["artifacts"]:
    path = grid / item["artifact"]
    data = path.read_bytes()
    assert len(data) == item["raw_wasm_bytes"]
    assert hashlib.sha256(data).hexdigest() == item["artifact_sha256"]
PY

echo "PASS: C2 sleep50 package grid rebuilds byte-for-byte at four exact raw-WASM sizes"
