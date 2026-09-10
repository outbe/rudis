#!/usr/bin/env bash
# TEST ONLY: render and sign the same test manifest used by entrypoint.test.sh,
# then print its exact SIGSTRUCT without launching an enclave.
set -euo pipefail

readonly ENTRY=/app/outbe-tee-enclave
readonly ARCH_LIBDIR=/lib/x86_64-linux-gnu
readonly TEST_SIGNING_KEY=/run/secrets/outbe-test-sgx-key.pem
readonly NETWORK_DESCRIPTOR=/opt/outbe/sgx/network-descriptor-v1.bin

if [[ ! -f "${NETWORK_DESCRIPTOR}" ]]; then
  echo "measurement inspection requires ${NETWORK_DESCRIPTOR}" >&2
  exit 2
fi

cd /app
gramine-manifest \
  -Dlog_level="${GRAMINE_LOG_LEVEL:-error}" \
  -Darch_libdir="${ARCH_LIBDIR}" \
  -Dentrypoint="${ENTRY}" \
  -Dtee_dir=/tee \
  -Dremote_attestation=dcap \
  -Dqvl_host_dir=/qvl \
  -Dnetwork_descriptor="${NETWORK_DESCRIPTOR}" \
  outbe-tee-enclave.manifest.template \
  outbe-tee-enclave.manifest
gramine-sgx-sign \
  --key "${TEST_SIGNING_KEY}" \
  --manifest outbe-tee-enclave.manifest \
  --output outbe-tee-enclave.manifest.sgx >/dev/null 2>&1
exec gramine-sgx-sigstruct-view outbe-tee-enclave.sig
