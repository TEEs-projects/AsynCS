# AsynCS C2 sleep50 package grid

These versioned experiment inputs keep the accepted sleep50 function unchanged
and vary only raw WASM size. Each artifact appends one valid deterministic custom
section to the accepted `backend_pressure_sleep50` artifact. WAMR ignores custom
sections, so request, result, imports, and executable code remain identical.

Run `./build.sh` to rebuild all four artifacts and compare them byte-for-byte.
The encrypted `C_func`, action ZIP, BF-IBE envelopes, and prepared requests are
generated before a live collection under the selected KMS authority; they are
not versioned binaries because their randomness and authority are run inputs.
