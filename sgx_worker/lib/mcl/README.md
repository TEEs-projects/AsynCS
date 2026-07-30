# MCL Library for SGX Enclave

This directory contains the mcl library (https://github.com/herumi/mcl) built for SGX compatibility.

## Building libmcl.a

```bash
# Clone mcl
git clone https://github.com/herumi/mcl.git /tmp/mcl_test
cd /tmp/mcl_test

# Install nasm (required for assembly)
apt-get install -y nasm

# Build with SGX-compatible flags
make lib/libmcl.a MCL_STATIC_CODE=1 CFLAGS_USER=-DMCL_DONT_USE_CSPRNG -j4

# Copy to this directory
cp lib/libmcl.a /path/to/acsc/sgx_worker/lib/mcl/
cp -r include/mcl /path/to/acsc/sgx_worker/lib/mcl/include/
```

## Build Flags Explained

- `MCL_STATIC_CODE=1`: Use static code generation (required for SGX, no JIT/XBYAK)
- `MCL_DONT_USE_CSPRNG`: Disable OS-level CSPRNG calls (use SGX's sgx_read_rand instead)

## Library Size

- `libmcl.a`: ~11MB (static library with BLS12-381 curve support)

## Headers Used

- `mcl/bn.h`: Main C API for BN curves (BLS12-381)
- Defines used in Enclave:
  - `MCL_MAX_BIT_SIZE=384`
  - `MCL_STATIC_CODE`
  - `CYBOZU_DONT_USE_STRING`
  - `CYBOZU_DONT_USE_EXCEPTION`
