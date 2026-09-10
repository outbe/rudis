#!/usr/bin/env bash
# Compatibility entrypoint for the canonical network preparer.
#
# Usage:
#   ./scripts/bootstrap-testnet.sh 4 OUTPUT_DIR [SEED_FILE]
#
# OCOMP V1 fixes the founding committee at four members. This wrapper retains
# the localnet environment variables used by run-testnet.sh while delegating all
# genesis/key/command generation to prepare_network.py. There is intentionally
# no second genesis implementation here.

set -euo pipefail

readonly NUM_VALIDATORS="${1:?Usage: $0 4 OUTPUT_DIR [SEED_FILE]}"
readonly OUTPUT_DIR="${2:?Usage: $0 4 OUTPUT_DIR [SEED_FILE]}"
readonly SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
readonly REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
readonly STORAGE_TEMPLATE="${4:-}"
readonly SEED_FILE="${3:-$SCRIPT_DIR/seed-testnet.json}"

if [[ "$NUM_VALIDATORS" != "4" ]]; then
  echo "Error: OCOMP V1 requires exactly 4 founding validators, got $NUM_VALIDATORS" >&2
  exit 2
fi
if [[ "$SEED_FILE" == "none" ]]; then
  echo "Error: a runnable network requires a seed file; 'none' is not supported" >&2
  exit 2
fi

find_binary() {
  local explicit="$1"
  local name="$2"
  if [[ -n "$explicit" ]]; then
    [[ -x "$explicit" ]] || {
      echo "Error: configured $name binary is not executable: $explicit" >&2
      return 1
    }
    printf '%s\n' "$explicit"
    return
  fi
  local candidate
  for candidate in "$REPO_ROOT/target/debug/$name" "$REPO_ROOT/target/release/$name"; do
    if [[ -x "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return
    fi
  done
  echo "Error: $name not found; build it or set OUTBE_${name^^}_BINARY" >&2
  return 1
}

CHAIN_BINARY="$(find_binary "${OUTBE_CHAIN_BINARY:-}" outbe-chain)" || exit 1
KEYGEN_BINARY="$(find_binary "${OUTBE_KEYGEN_BINARY:-}" outbe-keygen)" || exit 1
ENCLAVE_BINARY="$(find_binary "${OUTBE_TEE_ENCLAVE_BINARY:-}" outbe-tee-enclave-mock)" || exit 1
readonly CHAIN_BINARY KEYGEN_BINARY ENCLAVE_BINARY

# Preserve the old safe re-bootstrap behavior: refuse to erase a live network,
# then recreate the exact requested output directory from scratch.
if [[ -d "$OUTPUT_DIR/pids" ]]; then
  for pid_file in "$OUTPUT_DIR"/pids/validator-*.pid; do
    [[ -f "$pid_file" ]] || continue
    pid="$(tr -cd '0-9' < "$pid_file")"
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      echo "Error: validator process $pid from $pid_file is still running." >&2
      echo "Run './scripts/run-testnet.sh stop $OUTPUT_DIR' first." >&2
      exit 1
    fi
  done
fi
rm -rf -- "$OUTPUT_DIR"

readonly PORT_OFFSET="${PORT_OFFSET:-0}"
readonly HOST_PATTERN="${OUTBE_CONSENSUS_HOST_PATTERN:-127.0.0.1}"
# Match prepare_network.py and the canonical E2E/final-artifact network.
readonly EPOCH_LENGTH="${TESTNET_EPOCH_LENGTH_BLOCKS:-300}"
readonly DKG_PREPARE_WINDOW="${TESTNET_DKG_PREPARE_WINDOW_BLOCKS:-30}"
readonly DKG_ACTIVATION_GRACE="${TESTNET_DKG_ACTIVATION_GRACE_BLOCKS:-30}"

storage_args=()
if [[ -n "$STORAGE_TEMPLATE" ]]; then storage_args+=(--storage-template "$STORAGE_TEMPLATE"); fi

python3 "$SCRIPT_DIR/prepare_network.py" "${storage_args[@]}" \
  --seed "$SEED_FILE" \
  --generate-validators 4 \
  --validator-hosts "$HOST_PATTERN" \
  --output-dir "$OUTPUT_DIR" \
  --runtime-base-dir "$OUTPUT_DIR" \
  --chain-binary "$CHAIN_BINARY" \
  --keygen-binary "$KEYGEN_BINARY" \
  --runtime-chain-binary "$CHAIN_BINARY" \
  --tee-mode gramine-direct-dev \
  --chain-id 424242 \
  --enclave-image "${OUTBE_TEE_GRAMINE_IMAGE:-outbe-tee-enclave-gramine-test}" \
  --runtime-enclave-binary "$ENCLAVE_BINARY" \
  --epoch-length-blocks "$EPOCH_LENGTH" \
  --dkg-prepare-window-blocks "$DKG_PREPARE_WINDOW" \
  --dkg-activation-grace-blocks "$DKG_ACTIVATION_GRACE" \
  --consensus-p2p-base-port "$((30400 + PORT_OFFSET))" \
  --reth-p2p-base-port "$((30303 + PORT_OFFSET))" \
  --reth-discv5-base-port "$((31303 + PORT_OFFSET))" \
  --rpc-base-port "$((18545 + PORT_OFFSET))" \
  --authrpc-base-port "$((8551 + PORT_OFFSET))" \
  --metrics-base-port "$((9101 + PORT_OFFSET))" \
  --tee-enclave-base-port "$((17000 + PORT_OFFSET))" \
  --use-local-defaults
