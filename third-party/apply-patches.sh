#!/usr/bin/env bash
set -euo pipefail

: "${OPENWHISK_ROOT:?set OPENWHISK_ROOT to a clean OpenWhisk base checkout}"
: "${WAMR_ROOT:?set WAMR_ROOT to a clean WAMR base checkout}"
HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"

check_base() {
  local root="$1" expected="$2"
  if [[ "$(git -C "$root" rev-parse HEAD)" != "$expected" ]]; then
    echo "Unexpected base in $root; see third-party/SOURCE-REFS.tsv" >&2
    exit 1
  fi
  if [[ -n "$(git -C "$root" status --porcelain)" ]]; then
    echo "Checkout is not clean: $root" >&2
    exit 1
  fi
}

check_base "$OPENWHISK_ROOT" 579635176cc0d7ae53d8ca14502e6b8b4e58a2eb
check_base "$WAMR_ROOT" 45e3e1ea984b26c076859c6e659cac6f42fffaed
git -C "$OPENWHISK_ROOT" apply --check "$HERE/openwhisk/asynccs-openwhisk.patch"
git -C "$WAMR_ROOT" apply --check "$HERE/wamr/asynccs-wamr.patch"
git -C "$OPENWHISK_ROOT" apply "$HERE/openwhisk/asynccs-openwhisk.patch"
git -C "$WAMR_ROOT" apply "$HERE/wamr/asynccs-wamr.patch"
