#!/usr/bin/env bash
# Hardware SGX smoke for outbe-tee-enclave - the ">=1 hw SGX smoke" acceptance
# check, runnable on any gramine-sgx box. It builds + signs the enclave, runs it
# under gramine-sgx, and asserts:
#   - the enclave loads under gramine-sgx (real SGX, not gramine-direct),
#   - /dev/attestation/keys exposes the EGETKEY MRSIGNER/MRENCLAVE sealing keys,
#   - sealing keys derive on hardware (WS-1 seal/unseal uses these).
# It additionally probes whether a real DCAP quote can be generated; quote
# generation needs a provisioned PCK (PCCS / Intel PCS), which a fresh box lacks -
# the smoke reports that as a platform-provisioning note, not a failure.
#
# Requires: gramine (gramine-manifest/-sgx/-sgx-sign), a built enclave binary,
# and access to /dev/sgx_enclave (sgx group, or run via sudo). Prereqs:
#   sudo usermod -aG sgx,sgx_prv "$USER"   # then re-login, or run this via sudo
#   sudo systemctl restart aesmd           # so the QE3 picks up sgx_prv access
#
# Usage: scripts/sgx-smoke.sh [path-to-enclave-binary]
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${1:-$REPO/target/release/outbe-tee-enclave}"

if [ ! -e /dev/sgx_enclave ] && [ ! -e /dev/sgx/enclave ]; then
    echo "SKIP: no SGX device (/dev/sgx_enclave) - this smoke requires SGX hardware." >&2
    exit 0
fi
command -v gramine-sgx >/dev/null || { echo "FAIL: gramine-sgx not installed" >&2; exit 1; }

if [ ! -x "$BIN" ]; then
    echo "Building enclave ($BIN)..." >&2
    ( cd "$REPO" && cargo build --release --bin outbe-tee-enclave >&2 )
fi
BIN="$(readlink -f "$BIN")"

# Run gramine-sgx with elevated privileges only if the device is not group-readable
# to us (so the script works both for sgx-group members and via sudo).
SGX_RUN=(env)
if [ ! -r /dev/sgx_enclave ]; then SGX_RUN=(sudo -E); fi

[ -f "$HOME/.config/gramine/enclave-key.pem" ] || gramine-sgx-gen-private-key >/dev/null 2>&1 || true

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cp "$REPO/bin/outbe-tee-enclave/gramine/outbe-tee-enclave.manifest.template" "$WORK/"
cd "$WORK"

mkdir -p "$WORK/tee"
mkdir -p "$WORK/qvl"
cp -f /lib/x86_64-linux-gnu/libsgx_dcap_quoteverify.so.1 "$WORK/qvl/"
cp -f /lib/x86_64-linux-gnu/libstdc++.so.6 "$WORK/qvl/"
cp -f /lib/x86_64-linux-gnu/libgcc_s.so.1 "$WORK/qvl/"
render_sign() {  # $1 = template, $2 = manifest base name, $3 = attestation mode
    gramine-manifest -Dlog_level=error -Darch_libdir=/lib/x86_64-linux-gnu \
        -Dentrypoint="$BIN" -Dtee_dir="$WORK/tee" \
        -Dremote_attestation="$3" -Dqvl_host_dir="$WORK/qvl" \
        "$1" "$2.manifest" >/dev/null
    gramine-sgx-sign --manifest "$2.manifest" --output "$2.manifest.sgx" >/dev/null 2>&1
}

echo "== SGX smoke: signing enclave (computes real MRENCLAVE/MRSIGNER) =="
render_sign outbe-tee-enclave.manifest.template outbe-tee-enclave none
gramine-sgx-sigstruct-view outbe-tee-enclave.sig 2>/dev/null \
    | grep -iE "mr_enclave|mr_signer|isv_prod|isv_svn" | sed 's/^/  /'

echo "== probing real DCAP quote (remote_attestation = dcap) =="
render_sign outbe-tee-enclave.manifest.template dcap dcap
DCAP_OUT="$("${SGX_RUN[@]}" timeout 90 gramine-sgx dcap --probe-attestation 2>&1 || true)"
if echo "$DCAP_OUT" | grep -q "dcap_quote: .*bytes"; then
    echo "  PASS: real DCAP quote generated ($(echo "$DCAP_OUT" | grep -oE 'dcap_quote: [0-9]+ bytes'))"
    echo "$DCAP_OUT" | grep -iE "mrenclave|mrsigner|attestation_type" | sed 's/^/  /'
    ATTESTED=1
else
    echo "  NOTE: DCAP quote unavailable on this box (PCK not provisioned - needs PCCS/Intel PCS)."
    echo "$DCAP_OUT" | grep -iE "AESM service returned error|missing on this machine" | sed 's/^/    /' | head -2 || true
    ATTESTED=0
fi

# Functional smoke: enclave executes under real SGX + EGETKEY sealing keys derive.
# The repository manifest already uses no remote attestation, so it loads even
# without a provisioned PCK while still exercising real SGX + EGETKEY.
echo "== functional smoke: SGX execution + EGETKEY sealing (no attestation needed) =="
render_sign outbe-tee-enclave.manifest.template smoke none
PROBE="$("${SGX_RUN[@]}" timeout 90 gramine-sgx smoke --probe-attestation 2>&1 || true)"
echo "$PROBE" | grep -iE "/dev/attestation|sealing_key|attestation_type" | sed 's/^/  /'

fail=0
echo "$PROBE" | grep -q "_sgx_mrsigner" || { echo "FAIL: no /dev/attestation/keys/_sgx_mrsigner (EGETKEY unavailable)"; fail=1; }
echo "$PROBE" | grep -qE "sealing_key\(mrsigner\): [0-9]+ bytes" || { echo "FAIL: MRSIGNER sealing key not derived"; fail=1; }
echo "$PROBE" | grep -qE "sealing_key\(mrenclave\): [0-9]+ bytes" || { echo "FAIL: MRENCLAVE sealing key not derived"; fail=1; }
# Regression guard: on real SGX the probe must NOT mislabel itself as gramine-direct/no-SGX.
# EGETKEY derived above, so attestation_type must resolve to the SgxNoAttest (gramine-sgx) label.
if echo "$PROBE" | grep -q "attestation_type:"; then
    echo "$PROBE" | grep "attestation_type:" | grep -q "gramine-direct / no SGX" \
        && { echo "FAIL: real-SGX run mislabeled as 'gramine-direct / no SGX'"; fail=1; }
fi

echo "================================================================"
if [ "$fail" -ne 0 ]; then
    echo "SGX SMOKE: FAIL"
    exit 1
fi
if [ "$ATTESTED" -eq 1 ]; then
    echo "SGX SMOKE: PASS (real SGX execution + EGETKEY sealing + real DCAP quote)"
else
    echo "SGX SMOKE: PASS (real SGX execution + EGETKEY sealing; DCAP quote needs PCK provisioning)"
fi
