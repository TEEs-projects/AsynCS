# Build, run, and test

Install the SGX SDK and driver (or simulation mode), OpenSSL, Rust/Cargo, WAMR
build dependencies, and the platform toolchain for the selected profile. Set
`SGX_SDK` and `WAMR_ROOT`; keep machine-specific paths out of tracked files.
Use the existing scripts under `scripts/` and the SGX Makefiles in `sgx_kms`
and `sgx_worker`. Generate signing material locally; it is ignored by Git:

```bash
./scripts/generate_signing_key.sh path/to/Enclave_private.pem
```

The four directories under `workloads/` are the current measurement inputs.
Their contracts and the precompiled WASM artifacts used by accepted
measurements are retained; compare rebuilt artifact SHA256 values before use.

Obtain the pinned OpenWhisk and WAMR integrations from the independent
[openwhisk-asyncs](https://github.com/TEEs-projects/openwhisk-asyncs) and
[wamr-asyncs](https://github.com/TEEs-projects/wamr-asyncs) repositories, or
reconstruct them in clean public-upstream checkouts with
`third-party/apply-patches.sh`. Exact clone/checkout commands and commit IDs are
in [third-party/README.md](third-party/README.md) and `third-party/SOURCE-REFS.tsv`.
The component checkout and patch methods produce identical source trees. These
are currently private candidates; the AsynCS project license is not yet decided.
Data and reproduction instructions are in
[AsynCS-experiments](https://github.com/TEEs-projects/AsynCS-experiments).
Run the lightweight tests with:

```bash
python3 -m pytest tests/test_crypto_profiles.py tests/test_bfibe_envelope.py
```

Generated EDL C/H, signed enclaves, private keys, and other build outputs are
not release files. Full SGX/OpenWhisk builds and live deployment tests were
not run during packaging; the default pytest configuration excludes legacy
tests requiring external services or stale contracts.
