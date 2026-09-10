#!/usr/bin/env bash
# Internal adapter executed only inside the digest-pinned Gramine 1.9 image.
set -euo pipefail

export LC_ALL=C
export LANG=C
export TZ=UTC
umask 022

readonly install_root=/opt/outbe/sgx
readonly bundle_root=/out/rootfs
readonly installed="${bundle_root}${install_root}"

require_env() {
  local name="$1"
  [[ -n "${!name:-}" ]] || { echo "missing required environment: ${name}" >&2; exit 2; }
}

prepare() {
  for name in SGX_MAX_THREADS SGX_ISV_PROD_ID SGX_ISV_SVN; do require_env "${name}"; done
  [[ -f /elf/bin/outbe-tee-enclave ]] || { echo "missing enclave ELF" >&2; exit 2; }
  [[ -f /out/metadata/network-descriptor-v1.bin ]] || {
    echo "missing trusted network descriptor" >&2
    exit 2
  }

  mkdir -p "${installed}/bin" "${installed}/gramine/runtime/glibc" \
    "${installed}/host-libs" "${bundle_root}/var/lib/outbe/tee" /out/metadata
  chmod 0700 "${bundle_root}/var/lib/outbe/tee"

  install -m 0755 /elf/bin/outbe-tee-enclave "${installed}/bin/outbe-tee-enclave"
  install -m 0444 /out/metadata/network-descriptor-v1.bin \
    "${installed}/network-descriptor-v1.bin"
  install -m 0755 /source/bin/outbe-tee-enclave/gramine/entrypoint.sh \
    "${installed}/bin/outbe-tee-enclave-launch"
  install -m 0755 /usr/lib/x86_64-linux-gnu/gramine/sgx/loader \
    "${installed}/gramine/loader"
  install -m 0755 /usr/lib/x86_64-linux-gnu/gramine/sgx/libpal.so \
    "${installed}/gramine/libpal.so"
  cp -aL /usr/lib/x86_64-linux-gnu/gramine/runtime/glibc/. \
    "${installed}/gramine/runtime/glibc/"
  python3 /source/scripts/release/verify_dcap_native_qvl.py \
    --manifest /source/release/dcap-native-qvl-v1.json \
    --root / \
    --install-dir "${installed}/gramine/runtime/qvl"
  install -m 0644 /lib/x86_64-linux-gnu/libprotobuf-c.so.1 \
    "${installed}/host-libs/libprotobuf-c.so.1"
  install -m 0755 /lib/x86_64-linux-gnu/libc.so.6 \
    "${installed}/host-libs/libc.so.6"

  gramine-manifest \
    --chroot "${bundle_root}" \
    -Dinstall_root="${install_root}" \
    -Dmax_threads="${SGX_MAX_THREADS}" \
    -Disv_prod_id="${SGX_ISV_PROD_ID}" \
    -Disv_svn="${SGX_ISV_SVN}" \
    /source/bin/outbe-tee-enclave/gramine/outbe-tee-enclave.release.manifest.template \
    "${installed}/outbe-tee-enclave.manifest"
}

sign_bundle() {
  require_env SIGSTRUCT_DATE
  [[ -f /run/secrets/sgx-signing-key.pem ]] || { echo "missing SGX signing key" >&2; exit 2; }
  [[ -f /unsigned/SHA256SUMS.unsigned ]] || { echo "missing unsigned SGX bundle" >&2; exit 2; }

  cp -a /unsigned/. /out/
  (
    cd /out
    sha256sum --check SHA256SUMS.unsigned
  )
  gramine-sgx-sign \
    --date "${SIGSTRUCT_DATE}" \
    --key /run/secrets/sgx-signing-key.pem \
    --chroot "${bundle_root}" \
    --libpal "${installed}/gramine/libpal.so" \
    --manifest "${installed}/outbe-tee-enclave.manifest" \
    --output "${installed}/outbe-tee-enclave.manifest.sgx" >/dev/null
  gramine-sgx-sigstruct-view "${installed}/outbe-tee-enclave.sig" \
    > /out/metadata/sigstruct.txt
}

view_sigstruct() {
  [[ -f /bundle/rootfs/opt/outbe/sgx/outbe-tee-enclave.sig ]] || {
    echo "missing signed enclave SIGSTRUCT" >&2
    exit 2
  }
  gramine-sgx-sigstruct-view \
    /bundle/rootfs/opt/outbe/sgx/outbe-tee-enclave.sig
}

case "${1:-}" in
  prepare) prepare ;;
  sign) sign_bundle ;;
  view) view_sigstruct ;;
  *) echo "usage: $0 prepare|sign|view" >&2; exit 2 ;;
esac
