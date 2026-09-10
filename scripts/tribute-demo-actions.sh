#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

ACTION=${1:-}
STACK_DIR=$(realpath -m "${LOCALNET_STACK_DIR:-/tmp/outbe-localnet-stack}")
MONGO_NAME=${LOCALNET_STACK_MONGO_NAME:-outbe-localnet-stack-mongodb}
MONGO_PORT=${LOCALNET_STACK_MONGO_PORT:-27027}
PORT_OFFSET=${LOCALNET_STACK_PORT_OFFSET:-1000}
DATABASE_PREFIX=${LOCALNET_STACK_DATABASE_PREFIX:-outbe_localnet_stack}
RPC_URL="http://127.0.0.1:$((18545 + PORT_OFFSET))"
LAST_TX_FILE="$STACK_DIR/last-tribute-tx"

docker_cmd() {
  if docker info >/dev/null 2>&1; then
    docker "$@"
  else
    sudo docker "$@"
  fi
}

require_stack() {
  [[ -f "$STACK_DIR/validator-0/evm-key.hex" ]] || {
    echo "Localnet stack is not initialized. Run: mise run localnet-stack-start" >&2
    exit 1
  }
  cast block-number --rpc-url "$RPC_URL" >/dev/null 2>&1 || {
    echo "Localnet RPC is not reachable at $RPC_URL. Run: mise run localnet-stack-start" >&2
    exit 1
  }
}

case "$ACTION" in
  offer)
    require_stack
    tee_ready=0
    for _ in $(seq 1 60); do
      if cast call 0x000000000000000000000000000000000000EE0A \
        'isBootstrapped()(bool)' --rpc-url "$RPC_URL" 2>/dev/null | grep -q true; then
        tee_ready=1
        break
      fi
      sleep 1
    done
    [[ $tee_ready -eq 1 ]] || { echo "TEE registry did not bootstrap" >&2; exit 1; }

    key=$(tr -d '[:space:]' < "$STACK_DIR/validator-0/evm-key.hex")
    worldwide_day=$(date -u -d "@$(($(date +%s) + 50400))" +%Y%m%d)
    before=$(cast call 0x0000000000000000000000000000000000001101 \
      'totalSupply()(uint256)' --rpc-url "$RPC_URL" | tr -d '[:space:]')

    output=$(./target/release/outbe-cli --private-key "$key" --rpc-url "$RPC_URL" \
      tribute offer "$worldwide_day" --amount 100 --currency 840 2>&1)
    printf '%s\n' "$output"
    tx_hash=$(printf '%s\n' "$output" | sed -n \
      's/^offerTribute tx: \(0x[0-9a-fA-F]\{64\}\).*/\1/p' | head -n1)
    [[ -n "$tx_hash" ]] || { echo "outbe-cli did not return an offerTribute tx hash" >&2; exit 1; }

    receipt_ok=0
    for _ in $(seq 1 60); do
      receipt=$(cast receipt "$tx_hash" --json --rpc-url "$RPC_URL" 2>/dev/null || true)
      if printf '%s' "$receipt" | tr -d '[:space:]' | grep -q '"status":"0x1"'; then
        receipt_ok=1
        break
      fi
      sleep 0.5
    done
    [[ $receipt_ok -eq 1 ]] || { echo "Tribute receipt was not successful: $tx_hash" >&2; exit 1; }

    supply_ready=0
    for _ in $(seq 1 30); do
      after=$(cast call 0x0000000000000000000000000000000000001101 \
        'totalSupply()(uint256)' --rpc-url "$RPC_URL" | tr -d '[:space:]')
      if [[ "$after" != "$before" ]]; then
        supply_ready=1
        break
      fi
      sleep 0.5
    done
    [[ $supply_ready -eq 1 ]] || { echo "Tribute totalSupply did not increase" >&2; exit 1; }

    printf '%s\n' "$tx_hash" > "$LAST_TX_FILE"
    echo
    echo "Tribute created successfully"
    echo "tx_hash:     $tx_hash"
    echo "totalSupply: $before -> $after"
    ;;
  show-mongo)
    require_stack
    [[ -s "$LAST_TX_FILE" ]] || {
      echo "No recorded Tribute transaction. Run: mise run tribute-offer" >&2
      exit 1
    }
    tx_hash=$(tr -d '[:space:]' < "$LAST_TX_FILE")

    projection_ready=0
    for _ in $(seq 1 60); do
      if docker_cmd exec "$MONGO_NAME" mongosh --quiet --port "$MONGO_PORT" --eval "
        const tx = '$tx_hash';
        for (let i = 0; i < 4; i++) {
          const d = db.getSiblingDB('${DATABASE_PREFIX}_validator_' + i);
          if (d.tributes.countDocuments({'_projection.tx_hash': tx}) !== 1) quit(1);
          if (d.tributes_by_owner.countDocuments({}) < 1) quit(1);
          if (d.tributes_by_day.countDocuments({}) < 1) quit(1);
        }
      " >/dev/null 2>&1; then
        projection_ready=1
        break
      fi
      sleep 0.5
    done
    [[ $projection_ready -eq 1 ]] || {
      echo "Tribute projection did not appear on all four validators: $tx_hash" >&2
      exit 1
    }

    docker_cmd exec "$MONGO_NAME" mongosh --quiet --port "$MONGO_PORT" --eval "
      const tx = '$tx_hash';
      for (let i = 0; i < 4; i++) {
        const d = db.getSiblingDB('${DATABASE_PREFIX}_validator_' + i);
        print('DB=' + d.getName());
        print('tributes=' + d.tributes.countDocuments({})
          + ' owner_index=' + d.tributes_by_owner.countDocuments({})
          + ' day_index=' + d.tributes_by_day.countDocuments({}));
        print(EJSON.stringify(d.tributes.findOne({'_projection.tx_hash': tx}), {relaxed:false}));
      }
    "
    ;;
  *)
    echo "usage: $0 {offer|show-mongo}" >&2
    exit 2
    ;;
esac
