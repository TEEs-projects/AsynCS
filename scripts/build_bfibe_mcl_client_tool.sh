#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACSC_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MCL_ROOT="${ASYNCS_HOST_MCL_ROOT:-$ACSC_ROOT/_tmp/mcl-build/mcl}"
OUT="$ACSC_ROOT/_tmp/bfibe-mcl-client-tool/bfibe_mcl_client_tool"

usage() {
  cat <<USAGE
Usage: $0 [--out FILE]

Build the host-side BF-IBE MCL client tool used to generate ASBFIBE1 key
envelopes compatible with the SGX worker's trusted MCL parser.

Environment:
  ASYNCS_HOST_MCL_ROOT  default: $MCL_ROOT
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out)
      OUT="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

ARCHIVE="$MCL_ROOT/lib/libmcl.a"
if [[ ! -f "$ARCHIVE" ]]; then
  echo "ERROR: missing host MCL archive: $ARCHIVE" >&2
  echo "Run scripts/build_trusted_mcl.sh first; it leaves a host libmcl.a under _tmp/mcl-build." >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT")"

g++ -std=c++17 -O2 \
  -DMCL_FP_BIT=384 \
  -DMCL_FR_BIT=256 \
  -DMCL_DONT_USE_XBYAK \
  -DMCL_DONT_USE_CSPRNG \
  -DCYBOZU_DONT_USE_EXCEPTION \
  -DCYBOZU_DONT_USE_STRING \
  -DMCL_BINT_ASM=0 \
  -DMCL_MSM=0 \
  -I"$MCL_ROOT/include" \
  -I"$MCL_ROOT/cybozulib/include" \
  "$ACSC_ROOT/crypto_lib/bfibe_mcl_client_tool.cpp" \
  "$ARCHIVE" \
  -lcrypto \
  -o "$OUT"

echo "bfibe-mcl-client-tool-build=ok out=$OUT"
