# AsynCS

This repository is a source-focused anonymous snapshot of the AsynCS
implementation at the pinned source ref in `SOURCE-MANIFEST.tsv`. It contains
the client, cryptographic library, SGX KMS/worker source, runtime adapter, and
lightweight tests needed to inspect and build the implementation.

## Repository entry points

This is a private release candidate, not a public release. Access to all four
repositories currently requires authorization.

| Repository | Contents |
|---|---|
| [AsynCS](https://github.com/TEEs-projects/AsynCS) | Main entry point, AsynCS source, workloads, and [build instructions](BUILD.md) |
| [AsynCS-experiments](https://github.com/TEEs-projects/AsynCS-experiments) | C1-C5 data, evidence bounds, and reproduction instructions |
| [openwhisk-asyncs](https://github.com/TEEs-projects/openwhisk-asyncs) | OpenWhisk integration, pinned at `05cf828b78fd93774b6bc0d2f0a0d1236f5137b8` |
| [wamr-asyncs](https://github.com/TEEs-projects/wamr-asyncs) | WAMR integration, pinned at `0e8e3967b70a79f5f4942da9a18051ee48ecee64` |

## Included content

The selected current workloads are under `workloads/`: backend pressure
sleep50, the C2 sleep50 package grid, C3 deterministic IO, and the C5
representative warm suite. Their source contracts and the precompiled WASM
artifacts used by the accepted measurements are included. C1-C3 data exports
refer to these sibling workload contracts; C5's profile-independent inputs are
materialized in the experiments repository under `C5/inputs/`.

The OpenWhisk and WAMR integrations are provided in the two independent component
repositories above, with identical reproducible patches under `third-party/`.
Each component repository preserves its public upstream history followed by one
anonymous integration commit. See [component setup](third-party/README.md) and
[`third-party/SOURCE-REFS.tsv`](third-party/SOURCE-REFS.tsv) for both reconstruction
methods, repository URLs, bases, release commits, trees, and patch hashes. Private deployment
inventories are excluded from our changes. The selected
precompiled WASM workload artifacts are retained, while generated build
outputs, signing private keys, generated EDL, and deployment binaries are not.

Publication remains blocked until the project license is resolved.
