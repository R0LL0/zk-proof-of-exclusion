#!/usr/bin/env bash
# Compile the circuit and run the (demo) trusted setup end to end.
# Requires: circom on PATH (or ./bin/circom.exe on Windows), node.
set -euo pipefail
cd "$(dirname "$0")/.."

CIRCOM="circom"
if ! command -v circom >/dev/null 2>&1; then
  if [ -x "./bin/circom.exe" ]; then CIRCOM="./bin/circom.exe"; else
    echo "circom not found. Install from https://docs.circom.io or drop the binary in ./bin/"; exit 1
  fi
fi

mkdir -p build
echo "==> compiling circuit"
"$CIRCOM" circuits/exclusion.circom --r1cs --wasm --sym -o build -l node_modules

echo "==> trusted setup (downloads pot15 on first run)"
node scripts/setup.mjs

echo "==> done. Run 'npm run prove:demo' or 'npm test'."
