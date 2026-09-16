# AsynCS

## About the project

AsynCS is a research prototype for confidential asynchronous function deployment
and invocation. Its implementation extends Apache OpenWhisk with Intel SGX and
WebAssembly Micro Runtime (WAMR).

This repository is the main entry point for the project. It brings together the
AsynCS implementation, component repositories, build instructions, and experiment
data. The repositories below can all be reached from this page.

## Components and repositories

| Repository | Contents |
|---|---|
| [AsynCS](https://github.com/TEEs-projects/AsynCS) (this repository) | Client SDK, cryptographic library, SGX KMS and worker, runtime adapter, workloads, and lightweight tests |
| [openwhisk-asyncs](https://github.com/TEEs-projects/openwhisk-asyncs) | Modified Apache OpenWhisk for AsynCS |
| [wamr-asyncs](https://github.com/TEEs-projects/wamr-asyncs) | Modified WAMR for AsynCS |
| [AsynCS-experiments](https://github.com/TEEs-projects/AsynCS-experiments) | Experiment data, input contracts, and validation instructions |

The OpenWhisk and WAMR repositories retain their official upstream histories,
each followed by one integration commit. Their exact versions are recorded in
[`third-party/SOURCE-REFS.tsv`](third-party/SOURCE-REFS.tsv). Equivalent patches
are included under [`third-party/`](third-party/).

## Getting started

1. Clone this repository:

   ```bash
   git clone https://github.com/TEEs-projects/AsynCS.git
   cd AsynCS
   ```

2. Obtain the pinned OpenWhisk and WAMR integrations using the
   [component setup guide](third-party/README.md). It provides both direct
   component checkout instructions and reconstruction from official upstream
   versions using the included patches. Choose one method.

3. Follow [BUILD.md](BUILD.md) for prerequisites, local signing-key setup, and
   build and test guidance. Generated build outputs, signing private keys,
   generated EDL files, and deployment binaries are not included in this
   repository.

Source provenance is recorded in [SOURCE-MANIFEST.tsv](SOURCE-MANIFEST.tsv).
The included files can be checked with `sha256sum --check SHA256SUMS`.

## Experiment data and workloads

[AsynCS-experiments](https://github.com/TEEs-projects/AsynCS-experiments) contains
the C1-C5 experiment data, request-level and event-level tables, summaries,
validators, and documentation of the available measurements.

The corresponding workload sources, input contracts, and selected precompiled
WASM artifacts are under [`workloads/`](workloads/) in this repository. These
include the sleep50 workload, function-package size sweep, deterministic
input-size workload, and representative warm workloads. C5's shared inputs are
in the data repository under
[`C5/inputs/`](https://github.com/TEEs-projects/AsynCS-experiments/tree/main/C5/inputs).

## Release status and licenses

The AsynCS project license has not yet been selected.
Existing third-party licenses and notices are preserved
as described in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).
