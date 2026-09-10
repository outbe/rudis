#!/usr/bin/env bash
set -euo pipefail

tree="$(cargo tree -p outbe-consensus --prefix none)"

if grep -Eq '^outbe-evm ' <<<"${tree}"; then
  echo "error: outbe-evm appears in outbe-consensus dependency tree" >&2
  exit 1
fi

if ! grep -Eq '^commonware-consensus ' <<<"${tree}"; then
  echo "error: commonware-consensus is missing from outbe-consensus dependency tree" >&2
  exit 1
fi

echo "consensus dependency boundary: OK"
