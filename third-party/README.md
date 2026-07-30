# Third-party history and reconstruction

The OpenWhisk and WAMR integrations have independent repositories. Each retains
its original public upstream history plus exactly one anonymous integration
commit. `SOURCE-REFS.tsv` records the upstream URL, base commit, component
repository, branch, release commit, complete tree, and patch SHA256. These are
private release candidates; they have not been published publicly. The AsynCS
project license remains undecided; upstream licenses and notices are retained.

| Component | Official upstream | Pinned upstream base | Component repository (`main`) |
|---|---|---|---|
| OpenWhisk | https://github.com/apache/openwhisk.git | `579635176cc0d7ae53d8ca14502e6b8b4e58a2eb` | https://github.com/TEEs-projects/openwhisk-asyncs |
| WAMR | https://github.com/wasm-micro-runtime/wasm-micro-runtime.git | `45e3e1ea984b26c076859c6e659cac6f42fffaed` | https://github.com/TEEs-projects/wamr-asyncs |

The WAMR project moved from the `bytecodealliance` GitHub organization; its
former URL redirects to the URL above. Both pinned commits were fetched directly
from the official repositories with complete ancestry during release preparation.

## Use the independent component repositories

From the AsynCS repository root, set absolute destinations outside this checkout.
Authenticate with GitHub for access to the private candidates, then clone and
check out the fixed integration commits (do not apply patches again):

```bash
export OPENWHISK_ROOT=/path/to/openwhisk
export WAMR_ROOT=/path/to/wasm-micro-runtime
git clone https://github.com/TEEs-projects/openwhisk-asyncs.git "$OPENWHISK_ROOT"
git -C "$OPENWHISK_ROOT" checkout --detach 05cf828b78fd93774b6bc0d2f0a0d1236f5137b8
git clone https://github.com/TEEs-projects/wamr-asyncs.git "$WAMR_ROOT"
git -C "$WAMR_ROOT" checkout --detach 0e8e3967b70a79f5f4942da9a18051ee48ecee64
```

## Reconstruct from public upstream and patches

From the AsynCS repository root, set absolute destinations outside this checkout:

```bash
export OPENWHISK_ROOT=/path/to/openwhisk
export WAMR_ROOT=/path/to/wasm-micro-runtime
git clone https://github.com/apache/openwhisk.git "$OPENWHISK_ROOT"
git -C "$OPENWHISK_ROOT" checkout --detach 579635176cc0d7ae53d8ca14502e6b8b4e58a2eb
git clone https://github.com/wasm-micro-runtime/wasm-micro-runtime.git "$WAMR_ROOT"
git -C "$WAMR_ROOT" checkout --detach 45e3e1ea984b26c076859c6e659cac6f42fffaed
./third-party/apply-patches.sh
```

Each patch reconstructs exactly the tree recorded for its component commit.
The helper checks both pinned bases and both patches before applying either.
The OpenWhisk patch includes the early confidential invocation, RID result
handling, and timing integration as well as the later FPC and Reusable changes.
Our environment inventories and deployment credentials are excluded. The legacy
host-invoker path uses the generic `/opt/asyncs` installation prefix; managed
runtime configuration remains separate.

Upstream authors, commit identities, licenses, NOTICE files, and public example
inventories remain unchanged. Only our integration commits use the anonymous
artifact author identity. No private development commits are their ancestors.
