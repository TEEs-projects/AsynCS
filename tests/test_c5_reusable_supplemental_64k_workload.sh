#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
top_root="${C5_REUSABLE_TOP_ROOT:-$(cd "$root/.." && pwd)}"
crate="$root/workloads/c5_reusable_supplemental_64k"
c5="$top_root/experiments/current-scripts/C5"
shared_contract="$c5/supplemental-workload-contract-v1.json"
preset="$c5/shared/fixed-byte-identity-copy-64k-v1.bin"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

export C5_SUPPLEMENTAL_64K_PRESET_PATH="$preset"

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

built="$tmp/wasm-target/wasm32-wasip1/release/reusable-c5-supplemental-64k.wasm"
versioned="$crate/reusable-c5-supplemental-64k.wasm"
wasm-validate --enable-all "$built"
wasm-validate --enable-all "$versioned"
cmp "$built" "$versioned"
wasm-objdump -x "$built" >"$tmp/imports.txt"
grep -Fq '<env.c1_workload_tsc_begin> <- env.c1_workload_tsc_begin' "$tmp/imports.txt"
grep -Fq '<env.c1_workload_tsc_end> <- env.c1_workload_tsc_end' "$tmp/imports.txt"
grep -Fq '<env.c1_workload_set_output> <- env.c1_workload_set_output' "$tmp/imports.txt"

python3 - "$crate" "$top_root" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

crate = Path(sys.argv[1])
top = Path(sys.argv[2])
manifest = json.loads((crate / "workload-contract.json").read_text())
shared_path = top / manifest["shared_contract"]["relative_path"]
preset_path = top / manifest["preset"]["relative_path"]
shared = json.loads(shared_path.read_text())
workload_id = "fixed-byte-identity-copy-sha256-64k-v1"
workload = shared["workloads"][workload_id]

assert manifest["schema_version"] == "c5-reusable-supplemental-workload-contract-v1"
assert manifest["status"] == "local_static_only_no_live"
assert manifest["profile"] == "reusable-concurrency"
assert manifest["suite_id"] == shared["suite_id"] == "c5-supplemental-warm-v1"
assert manifest["workload_id"] == workload_id
assert manifest["shared_contract"]["sha256"] == hashlib.sha256(shared_path.read_bytes()).hexdigest()
assert manifest["preset"]["bytes"] == preset_path.stat().st_size == 65536
assert manifest["preset"]["sha256"] == hashlib.sha256(preset_path.read_bytes()).hexdigest()
assert manifest["preset"]["sha256"] == workload["application_input_sha256"]
assert manifest["direct_internal_timing"]["begin_host_call"] == "env.c1_workload_tsc_begin"
assert manifest["direct_internal_timing"]["end_host_call"] == "env.c1_workload_tsc_end"
assert manifest["direct_internal_timing"]["event_pair"] == "RF400..RF410"
assert manifest["direct_internal_timing"]["scope"] == workload["direct_duration_scope"]
assert manifest["transport_contract"] == shared["transport_contract"]

checks = {
    "artifact_sha256": crate / manifest["artifact_file"],
    "source_sha256": crate / "src/main.rs",
    "cargo_lock_sha256": crate / "Cargo.lock",
    "cargo_toml_sha256": crate / "Cargo.toml",
}
for field, path in checks.items():
    assert manifest[field] == hashlib.sha256(path.read_bytes()).hexdigest(), (field, path)
assert manifest["artifact_size_bytes"] == (crate / manifest["artifact_file"]).stat().st_size

source = (crate / "src/main.rs").read_text()
begin = source.rindex("c1_workload_tsc_begin()")
core = source.rindex("identity_copy_sha256().expect")
end = source.rindex("c1_workload_tsc_end()")
publish = source.rindex("c1_workload_set_output")
assert begin < core < end < publish
PY

old_contract="$root/workloads/c5_representative_warm/workload-contract.json"
old_artifact="$root/workloads/c5_representative_warm/asyncs-c5-representative-warm.wasm"
python3 - "$old_contract" "$old_artifact" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

contract_path, artifact_path = map(Path, sys.argv[1:])
contract = json.loads(contract_path.read_text())
assert hashlib.sha256(artifact_path.read_bytes()).hexdigest() == contract["artifact_sha256"]
assert contract["artifact_sha256"] == "836ea3df370f0373319456aa13fdad1b6297ff4747839c5c685be615390bae8d"
PY

echo "PASS: Reusable C5 supplemental guest preserves the existing C5 artifact and frozen 64 KiB semantics"
