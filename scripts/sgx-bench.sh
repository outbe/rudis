#!/usr/bin/env bash
# Production-figure throughput benchmark: drive tribute offers through the enclave
# running under REAL gramine-sgx (so the numbers include SGX enter/exit + gramine
# syscall emulation on the Noise/UDS->TCP transport, not just native CPU).
#
# It launches `outbe-tee-enclave` under gramine-sgx on a loopback TCP port (host
# processes cannot reach gramine pathname UDS, hence TCP), then runs the
# `transport_throughput_offers_per_sec` test as a native client pointed at it via
# OUTBE_TEE_BENCH_ENDPOINT. The enclave's compute runs in SGX; the test times it.
#
# A no-attestation manifest variant is used so the enclave loads without a
# provisioned PCK (DCAP quote generation is unrelated to throughput). It is still
# real SGX: memory encryption, real enclave transitions, EGETKEY - exactly the
# overhead we want to measure.
#
# Requires: gramine (gramine-manifest/-sgx/-sgx-sign), cargo, /dev/sgx_enclave.
# Usage: scripts/sgx-bench.sh [host:port] [path-to-enclave-binary]
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
ENDPOINT="${1:-127.0.0.1:7799}"
BIN="${2:-$REPO/target/release/outbe-tee-enclave}"

if [ ! -e /dev/sgx_enclave ] && [ ! -e /dev/sgx/enclave ]; then
    echo "SKIP: no SGX device (/dev/sgx_enclave) - this benchmark requires SGX hardware." >&2
    exit 0
fi
command -v gramine-sgx >/dev/null || { echo "FAIL: gramine-sgx not installed" >&2; exit 1; }
command -v cargo >/dev/null || { echo "FAIL: cargo not on PATH" >&2; exit 1; }

if [ ! -x "$BIN" ]; then
    echo "Building enclave ($BIN)..." >&2
    ( cd "$REPO" && cargo build --release --bin outbe-tee-enclave >&2 )
fi
BIN="$(readlink -f "$BIN")"

# Build the native test binary up front (outside the timed run).
echo "Building throughput test binary..." >&2
( cd "$REPO" && cargo test -p outbe-tee-enclave --release --test transport --no-run >&2 )

SGX_RUN=(env)
if [ ! -r /dev/sgx_enclave ]; then SGX_RUN=(sudo -E); fi
[ -f "$HOME/.config/gramine/enclave-key.pem" ] || gramine-sgx-gen-private-key >/dev/null 2>&1 || true

WORK="$(mktemp -d)"
ENCLAVE_PID=""
cleanup() {
    [ -n "$ENCLAVE_PID" ] && kill "$ENCLAVE_PID" 2>/dev/null || true
    [ -n "$ENCLAVE_PID" ] && "${SGX_RUN[@]}" pkill -P "$ENCLAVE_PID" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

cp "$REPO/bin/outbe-tee-enclave/gramine/outbe-tee-enclave.manifest.template" "$WORK/tmpl.template"
cd "$WORK"
mkdir -p "$WORK/tee"

# No-attestation manifest so it loads without a provisioned PCK (still real SGX).
sed 's/^sgx.remote_attestation = "dcap"/# bench: remote_attestation disabled/' \
    tmpl.template > bench.template
gramine-manifest -Dlog_level=error -Darch_libdir=/lib/x86_64-linux-gnu \
    -Dentrypoint="$BIN" -Dtee_dir="$WORK/tee" bench.template bench.manifest >/dev/null
gramine-sgx-sign --manifest bench.manifest --output bench.manifest.sgx >/dev/null 2>&1

echo "== launching outbe-tee-enclave under gramine-sgx on tcp://$ENDPOINT ==" >&2
"${SGX_RUN[@]}" gramine-sgx bench --socket "$ENDPOINT" >"$WORK/enclave.log" 2>&1 &
ENCLAVE_PID=$!

# Wait for the enclave to bind the port (gramine load + SGX init takes a moment).
host="${ENDPOINT%%:*}"; port="${ENDPOINT##*:}"
for _ in $(seq 1 60); do
    if (exec 3<>"/dev/tcp/$host/$port") 2>/dev/null; then exec 3>&- 3<&-; break; fi
    if ! kill -0 "$ENCLAVE_PID" 2>/dev/null; then
        echo "FAIL: enclave exited before binding. Log:" >&2; cat "$WORK/enclave.log" >&2; exit 1
    fi
    sleep 0.5
done
grep -qiE "gramine-sgx|hardware attestation|MODE = " "$WORK/enclave.log" && \
    sed -n '1,4p' "$WORK/enclave.log" | sed 's/^/  enclave: /' >&2 || true

echo "== running throughput client (native) against the SGX enclave ==" >&2
cd "$REPO"
OUTBE_TEE_BENCH_ENDPOINT="$ENDPOINT" \
    cargo test -p outbe-tee-enclave --release --test transport \
        transport_throughput_offers_per_sec -- --ignored --nocapture
