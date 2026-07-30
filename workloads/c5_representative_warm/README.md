# AsynCS C5 representative warm workload

This versioned WASM implements the frozen shared C5 suite in one managed
AsynCS action artifact. The workload selector and phase arrive inside the real
hybrid-encrypted request. Fixed functional inputs come from the top-level C5
shared fixtures at build time and are embedded byte-for-byte in the artifact.

Rebuild and verify with:

```bash
bash tests/test_c5_representative_warm_workload.sh
```

The test uses Cargo's locked offline cache, validates the WAMR imports, proves
the dynamic HTML output is byte-identical, verifies compression input identity,
and checks that sleep50 uses the existing WASI `poll_oneoff` bridge.
