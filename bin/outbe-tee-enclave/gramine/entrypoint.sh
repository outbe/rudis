#!/usr/bin/env bash
# Launch an already rendered and signed Outbe SGX bundle.
# Signing is deliberately absent: release hosts receive immutable artifacts only.
set -euo pipefail

readonly ROOT=/opt/outbe/sgx
readonly LOADER="${ROOT}/gramine/loader"
readonly LIBPAL="${ROOT}/gramine/libpal.so"
readonly APP_PREFIX="${ROOT}/outbe-tee-enclave"

if [[ ! -e /dev/sgx_enclave && ! -e /dev/sgx/enclave ]]; then
  echo "outbe SGX release bundle requires an SGX enclave device" >&2
  exit 78
fi

for required in \
  "${LOADER}" \
  "${LIBPAL}" \
  "${ROOT}/bin/outbe-tee-enclave" \
  "${APP_PREFIX}.manifest.sgx" \
  "${APP_PREFIX}.sig"; do
  if [[ ! -f "${required}" ]]; then
    echo "outbe SGX release bundle is incomplete: ${required}" >&2
    exit 78
  fi
done

export LD_LIBRARY_PATH="${ROOT}/host-libs"
exec "${LOADER}" "${LIBPAL}" init "${APP_PREFIX}" "$@"
