#!/usr/bin/env bash
set -euo pipefail

out=${1:?usage: generate_signing_key.sh OUTPUT_PEM}
umask 077
mkdir -p "$(dirname "$out")"
openssl genrsa -3 -out "$out" 3072
chmod 600 "$out"
printf 'Generated a local signing key at %s; do not commit it.\n' "$out"
