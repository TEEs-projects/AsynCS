#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACSC_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

MCL_REPO="${MCL_REPO:-https://github.com/herumi/mcl.git}"
MCL_COMMIT="${MCL_COMMIT:-0499298adcfad3bbcebf77f17700ebbe97166060}"
BUILD_ROOT="${ASYNCS_TRUSTED_MCL_BUILD_ROOT:-$ACSC_ROOT/_tmp/mcl-build}"
PREFIX="${ASYNCS_TRUSTED_MCL_PREFIX:-$ACSC_ROOT/_tmp/trusted-mcl}"
JOBS="${JOBS:-$(nproc)}"

SGX_SAFE_CYBOZU="-DCYBOZU_HOST_UNKNOWN=0 -DCYBOZU_HOST_INTEL=1 -DCYBOZU_HOST_ARM=2 -DCYBOZU_HOST=0"
SGX_SAFE_CFLAGS=(
  "$SGX_SAFE_CYBOZU"
  "-DMCL_FP_BIT=384"
  "-DMCL_FR_BIT=256"
  "-DMCL_DONT_USE_XBYAK"
  "-DMCL_DONT_USE_CSPRNG"
  "-DCYBOZU_DONT_USE_EXCEPTION"
  "-DCYBOZU_DONT_USE_STRING"
  "-DMCL_BINT_ASM=0"
  "-DMCL_MSM=0"
  "-DNDEBUG"
  "-fno-exceptions"
  "-fno-rtti"
  "-fno-threadsafe-statics"
  "-fno-stack-protector"
)

FORBIDDEN_INSTRUCTIONS_RE="\\b(cpuid|syscall|xsave|xrstor)\\b"
FORBIDDEN_UNDEFINED_SYMBOLS_RE="\\b(__assert_fail)\\b"

usage() {
  cat <<USAGE
Usage: $0 [--prefix DIR] [--build-root DIR] [--check-only ARCHIVE]

Build a SGX-safe trusted MCL static archive for the AsynCS bfibe-mcl-bls12381
profile. Generated files are written outside git-tracked source by default.

Environment:
  MCL_REPO                       default: $MCL_REPO
  MCL_COMMIT                     default: $MCL_COMMIT
  ASYNCS_TRUSTED_MCL_BUILD_ROOT  default: $BUILD_ROOT
  ASYNCS_TRUSTED_MCL_PREFIX      default: $PREFIX
  JOBS                           default: $JOBS
USAGE
}

check_forbidden_instructions() {
  local archive="$1"
  if [[ "$archive" != /* ]]; then
    archive="$(cd "$(dirname "$archive")" && pwd)/$(basename "$archive")"
  fi
  if [[ ! -f "$archive" ]]; then
    echo "ERROR: archive not found: $archive" >&2
    exit 1
  fi
  local tmp
  tmp="$(mktemp -d)"
  local status=0
  (
    cd "$tmp"
    ar x "$archive"
    local found=0
    local hit_file="$tmp/forbidden-hit.txt"
    local obj
    shopt -s nullglob
    for obj in *.o; do
      if objdump -d "$obj" | grep -Eiw "$FORBIDDEN_INSTRUCTIONS_RE" >"$hit_file"; then
        echo "ERROR: forbidden instruction found in $archive object $obj" >&2
        cat "$hit_file" >&2
        found=1
      fi
    done
    if [[ "$found" != "0" ]]; then
      exit 1
    fi
  ) || status=$?
  rm -rf "$tmp"
  return "$status"
}

check_forbidden_undefined_symbols() {
  local archive="$1"
  if [[ "$archive" != /* ]]; then
    archive="$(cd "$(dirname "$archive")" && pwd)/$(basename "$archive")"
  fi
  if [[ ! -f "$archive" ]]; then
    echo "ERROR: archive not found: $archive" >&2
    exit 1
  fi
  local undefined
  undefined="$(nm -u "$archive" 2>/dev/null || true)"
  if grep -Eiw "$FORBIDDEN_UNDEFINED_SYMBOLS_RE" <<<"$undefined" >/dev/null; then
    echo "ERROR: forbidden unresolved trusted-MCL symbol found in $archive" >&2
    grep -Eiw "$FORBIDDEN_UNDEFINED_SYMBOLS_RE" <<<"$undefined" >&2
    exit 1
  fi
}

CHECK_ONLY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --prefix)
      PREFIX="$2"
      shift 2
      ;;
    --build-root)
      BUILD_ROOT="$2"
      shift 2
      ;;
    --check-only)
      CHECK_ONLY="$2"
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

if [[ -n "$CHECK_ONLY" ]]; then
  check_forbidden_instructions "$CHECK_ONLY"
  check_forbidden_undefined_symbols "$CHECK_ONLY"
  echo "trusted-mcl-forbidden-instruction-check=ok archive=$CHECK_ONLY"
  exit 0
fi

mkdir -p "$BUILD_ROOT" "$PREFIX/lib" "$PREFIX/include"

if [[ ! -d "$BUILD_ROOT/mcl/.git" ]]; then
  rm -rf "$BUILD_ROOT/mcl"
  git clone "$MCL_REPO" "$BUILD_ROOT/mcl"
fi

cd "$BUILD_ROOT/mcl"
git fetch --tags origin
git checkout "$MCL_COMMIT"
git submodule update --init --recursive
make clean >/dev/null 2>&1 || true

CFLAGS_JOINED="${SGX_SAFE_CFLAGS[*]}"

make lib/libmcl.a -j"$JOBS" \
  MCL_USE_LLVM=0 \
  MCL_USE_XBYAK=0 \
  MCL_BINT_ASM=0 \
  MCL_BINT_ASM_X64=0 \
  MCL_MSM=0 \
  MCL_USE_GMP=0 \
  MCL_USE_GMP_LIB=0 \
  CFLAGS_USER="$CFLAGS_JOINED" \
  CXXFLAGS_USER="$CFLAGS_JOINED"

check_forbidden_instructions "$BUILD_ROOT/mcl/lib/libmcl.a"
check_forbidden_undefined_symbols "$BUILD_ROOT/mcl/lib/libmcl.a"

cp "$BUILD_ROOT/mcl/lib/libmcl.a" "$PREFIX/lib/libmcl_trusted.a"
cp -R "$BUILD_ROOT/mcl/include/"* "$PREFIX/include/"
if [[ -d "$BUILD_ROOT/mcl/cybozulib/include" ]]; then
  cp -R "$BUILD_ROOT/mcl/cybozulib/include/"* "$PREFIX/include/"
fi

cat > "$PREFIX/build-manifest.txt" <<EOF
profile=bfibe-mcl-bls12381
mcl_repo=$MCL_REPO
mcl_commit=$MCL_COMMIT
archive=$PREFIX/lib/libmcl_trusted.a
flags=$CFLAGS_JOINED
forbidden_instruction_check=cpuid syscall xsave xrstor
forbidden_undefined_symbol_check=__assert_fail
EOF

echo "trusted-mcl-build=ok"
echo "prefix=$PREFIX"
echo "archive=$PREFIX/lib/libmcl_trusted.a"
