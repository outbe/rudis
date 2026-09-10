#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$ROOT_DIR"

ACTION=${1:-start}
STORAGE_TEMPLATE=${2:-}
STACK_DIR=$(realpath -m "${LOCALNET_STACK_DIR:-/tmp/outbe-localnet-stack}")
MONGO_NAME=${LOCALNET_STACK_MONGO_NAME:-outbe-localnet-stack-mongodb}
MONGO_VOLUME="${MONGO_NAME}-data"
MONGO_PORT=${LOCALNET_STACK_MONGO_PORT:-27027}
PORT_OFFSET=${LOCALNET_STACK_PORT_OFFSET:-1000}
RPC_PORT=$((18545 + PORT_OFFSET))
RPC_URL="http://127.0.0.1:${RPC_PORT}"
MONGO_URI="mongodb://127.0.0.1:${MONGO_PORT}/?replicaSet=rs0&directConnection=true"

# The MongoDB replica-set lifecycle lives in one shared script (also used by the
# plain `localnet-*` mise tasks); point it at this stack's dedicated container.
export OUTBE_LOCALNET_MONGO_NAME="$MONGO_NAME"
export OUTBE_LOCALNET_MONGO_PORT="$MONGO_PORT"
export OUTBE_LOCALNET_MONGO_VOLUME="$MONGO_VOLUME"

case "$STACK_DIR" in
  /tmp/outbe-?*) ;;
  *)
    echo "LOCALNET_STACK_DIR must resolve to a dedicated /tmp/outbe-* path (got: $STACK_DIR)" >&2
    exit 2
    ;;
esac

uses_managed_mongo() {
  python3 - "$STACK_DIR" "$MONGO_URI" <<'PYCODE'
from pathlib import Path
import sys, tomllib
for path in Path(sys.argv[1]).glob("validator-*/offchain-storage.toml"):
    with path.open("rb") as stream:
        storage = tomllib.load(stream)
    if storage["backend"] == "mongodb" and storage["mongodb"]["uri"] == sys.argv[2]:
        sys.exit(0)
sys.exit(1)
PYCODE
}

network_env() {
  export PORT_OFFSET
  export OUTBE_CHAIN_BINARY="$ROOT_DIR/target/release/outbe-chain"
  export OUTBE_TEE_ENCLAVE=1
  export OUTBE_TEE_ENCLAVE_MOCK=1
  # Persist each validator's permanent offer key across a whole-stack restart.
  # A missing/corrupt sealed key is terminal for that identity; localnet never
  # invokes a peer recovery or replacement path.
  export OUTBE_TEE_SEAL=1
  export OUTBE_TEE_ENCLAVE_BINARY="$ROOT_DIR/target/release/outbe-tee-enclave-mock"
}

stop_stack() {
  network_env
  if [[ -d "$STACK_DIR" ]]; then
    ./scripts/run-testnet.sh stop "$STACK_DIR" || true
  fi
  if uses_managed_mongo; then ./scripts/localnet-mongo.sh stop; fi
}

remove_stack() {
  stop_stack
  if uses_managed_mongo; then ./scripts/localnet-mongo.sh clean; fi
}

print_connection_info() {
  cat <<EOF

Localnet stack is ready.

Primary RPC:    $RPC_URL
Validator RPCs: $RPC_URL, http://127.0.0.1:$((RPC_PORT + 1)), http://127.0.0.1:$((RPC_PORT + 2)), http://127.0.0.1:$((RPC_PORT + 3))
Storage config: $STACK_DIR/validator-N/offchain-storage.toml
Data dir:       $STACK_DIR

Useful environment for manual flows:

  export OUT_DIR="$STACK_DIR"
  export RPC_PORT="$RPC_PORT"
  export RPC_URL="$RPC_URL"

Stop services but keep chain data:

  mise run localnet-stack-stop

Stop services and delete chain data:

  mise run localnet-stack-clean
EOF
}

case "$ACTION" in
  start)
    command -v cast >/dev/null || { echo "cast is required (mise install)" >&2; exit 1; }

    cargo build --release -p outbe-chain --features test-protocol-overrides --bin outbe-chain
    cargo build --release -p outbe-cli -p outbe-keygen -p outbe-radicle
    cargo build --release -p outbe-tee-enclave --features mock --bin outbe-tee-enclave-mock

    network_env
    if [[ ! -f "$STACK_DIR/genesis.json" ]]; then
      ./scripts/bootstrap-testnet.sh 4 "$STACK_DIR" "$ROOT_DIR/scripts/seed-testnet.json" "$STORAGE_TEMPLATE"
    elif [[ -n "$STORAGE_TEMPLATE" ]]; then
      echo "Storage template applies only to a new stack; edit existing per-node TOML files." >&2
      exit 2
    fi
    if uses_managed_mongo; then ./scripts/localnet-mongo.sh start; fi
    ./scripts/run-testnet.sh start "$STACK_DIR"

    rpc_ready=0
    for _ in $(seq 1 120); do
      if height=$(cast block-number --rpc-url "$RPC_URL" 2>/dev/null) && [[ ${height:-0} -ge 1 ]]; then
        rpc_ready=1
        break
      fi
      sleep 0.5
    done
    if [[ $rpc_ready -ne 1 ]]; then
      echo "Localnet RPC did not reach block 1 at $RPC_URL" >&2
      ./scripts/run-testnet.sh status "$STACK_DIR" >&2 || true
      exit 1
    fi

    for i in 0 1 2 3; do
      pid_file="$STACK_DIR/pids/validator-${i}.pid"
      pid=$(cat "$pid_file" 2>/dev/null || true)
      if [[ -z "$pid" ]] || ! kill -0 "$pid" 2>/dev/null; then
        echo "validator-$i is not running after RPC readiness" >&2
        exit 1
      fi
    done

    ./scripts/run-testnet.sh status "$STACK_DIR"
    echo "Localnet reached block $height"
    print_connection_info
    ;;
  stop)
    stop_stack
    echo "Localnet stack stopped; chain data kept at $STACK_DIR"
    ;;
  clean)
    remove_stack
    if ! rm -rf "$STACK_DIR" 2>/dev/null; then
      sudo rm -rf "$STACK_DIR"
    fi
    echo "Localnet stack stopped and removed: $STACK_DIR"
    ;;
  *)
    echo "usage: $0 {start|stop|clean} [storage-template.toml]" >&2
    exit 2
    ;;
esac
