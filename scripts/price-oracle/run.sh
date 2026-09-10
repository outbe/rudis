#!/usr/bin/env bash
# Run outbe-feeder against a local bootstrap-testnet output directory.
#
# Usage:
#   scripts/price-oracle/run.sh [testnet_dir] [validator_index]
#
# Example:
#   ./scripts/bootstrap-testnet.sh 4 /tmp/outbe-testnet scripts/seed-testnet.json
#   ./scripts/run-testnet.sh start /tmp/outbe-testnet
#   ./scripts/price-oracle/run.sh /tmp/outbe-testnet 0

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

TESTNET_DIR="${1:-${OUTBE_TESTNET_DIR:-/tmp/outbe-testnet}}"
VALIDATOR_INDEX="${2:-${VALIDATOR_INDEX:-0}}"
RPC_URL="${RPC_URL:-http://127.0.0.1:$((18545 + VALIDATOR_INDEX))}"
CHAIN_ID="${CHAIN_ID:-70860602}"
HEALTH_BIND="${HEALTH_BIND:-0.0.0.0:$((9002 + VALIDATOR_INDEX))}"
PRICE_REST_URL="${PRICE_REST_URL:-https://prc.testnet.outbe.net}"
CONFIG_TEMPLATE="${OUTBE_PRICE_ORACLE_CONFIG:-$SCRIPT_DIR/config.toml}"
RUNTIME_CONFIG="${OUTBE_PRICE_ORACLE_RUNTIME_CONFIG:-$TESTNET_DIR/price-oracle-feeder-$VALIDATOR_INDEX.toml}"
OUTBE_FEEDER="${OUTBE_FEEDER:-$REPO_ROOT/target/release/outbe-feeder}"

KEY_FILE="$TESTNET_DIR/validator-$VALIDATOR_INDEX/evm-key.hex"
VALIDATORS_FILE="$TESTNET_DIR/validators.json"

if [ ! -f "$CONFIG_TEMPLATE" ]; then
    echo "error: config template not found: $CONFIG_TEMPLATE" >&2
    exit 1
fi

if [ ! -f "$KEY_FILE" ]; then
    echo "error: validator key not found: $KEY_FILE" >&2
    echo "run ./scripts/bootstrap-testnet.sh first" >&2
    exit 1
fi

if [ ! -f "$VALIDATORS_FILE" ]; then
    echo "error: validators file not found: $VALIDATORS_FILE" >&2
    echo "run ./scripts/bootstrap-testnet.sh first" >&2
    exit 1
fi

PRIVATE_KEY="$(tr -d '[:space:]' < "$KEY_FILE")"
case "$PRIVATE_KEY" in
    0x*) ;;
    *) PRIVATE_KEY="0x$PRIVATE_KEY" ;;
esac

VALIDATOR_ADDRESS="$(python3 - "$VALIDATORS_FILE" "$VALIDATOR_INDEX" <<'PY'
import json
import sys

path = sys.argv[1]
idx = int(sys.argv[2])
with open(path) as f:
    validators = json.load(f)
try:
    print(validators[idx]["address"])
except (IndexError, KeyError) as exc:
    raise SystemExit(f"invalid validator index {idx} in {path}") from exc
PY
)"

python3 - "$CONFIG_TEMPLATE" "$RUNTIME_CONFIG" "$PRIVATE_KEY" "$VALIDATOR_ADDRESS" "$RPC_URL" "$CHAIN_ID" "$HEALTH_BIND" "$PRICE_REST_URL" <<'PY'
import re
import sys
from pathlib import Path

template, output, private_key, validator, rpc_url, chain_id, health_bind, price_rest = sys.argv[1:]
text = Path(template).read_text()

replacements = {
    r'(?m)^rpc_endpoint = ".*"$': f'rpc_endpoint = "{rpc_url}"',
    r'(?m)^chain_id = \d+$': f'chain_id = {chain_id}',
    r'(?m)^private_key = ".*"$': f'private_key = "{private_key}"',
    r'(?m)^validator_address = ".*"$': f'validator_address = "{validator}"',
    r'(?m)^bind_address = ".*"$': f'bind_address = "{health_bind}"',
    r'(?m)^rest = ".*"$': f'rest = "{price_rest}"',
}

for pattern, replacement in replacements.items():
    text, count = re.subn(pattern, replacement, text, count=1)
    if count != 1:
        raise SystemExit(f"failed to patch runtime config line for pattern: {pattern}")

Path(output).parent.mkdir(parents=True, exist_ok=True)
Path(output).write_text(text)
PY

if [ ! -x "$OUTBE_FEEDER" ]; then
    echo "outbe-feeder binary not found at $OUTBE_FEEDER; building debug binary..."
    (cd "$REPO_ROOT" && cargo build -p outbe-feeder)
fi

echo "Starting outbe-feeder"
echo "  config:    $RUNTIME_CONFIG"
echo "  rpc:       $RPC_URL"
echo "  chain_id:  $CHAIN_ID"
echo "  validator: $VALIDATOR_ADDRESS"
echo "  prices:    $PRICE_REST_URL"
echo "  health:    http://$HEALTH_BIND/health"

exec "$OUTBE_FEEDER" --config "$RUNTIME_CONFIG"
