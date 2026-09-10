#!/usr/bin/env bash
# Multi-node consensus smoke (M-24): bootstrap a 4-validator localnet, prove
# every node clears genesis DKG and finalizes blocks in lockstep, then RESTART
# the localnet (preserving chain state) and prove every node recovers and keeps
# advancing in lockstep - exercising the M-21 restart-recovery path end to end.
#
# This is the working replacement for the removed `localnet-chain244-smoke`
# task (which referenced a script that never existed). It is the CI signal for
# multi-node consensus: a non-zero, lock-stepped height on all nodes proves the
# DKG ceremony, leader election, payload build, and finalization path all work;
# the restart phase proves saved-DKG recovery and finalized-state resume work.
#
# Env:
#   OUT_DIR               localnet data dir (default: a fresh /tmp dir)
#   VALIDATORS            node count (default: 4)
#   OUTBE_CHAIN_BINARY    node binary (default: ./target/release/outbe-chain)
#   SMOKE_TARGET_HEIGHT   height every node must reach pre-restart (default: 5)
#   SMOKE_TIMEOUT_SECS    max wall-clock to reach it (default: 240; wide for DKG
#                         start variance under load)
#   SMOKE_RESTART         set to 0 to skip the restart-recovery phase (default: 1)
#   SMOKE_RESTART_ADVANCE blocks every node must advance PAST the pre-restart
#                         height after recovery (default: 3)
#   SMOKE_RESTART_TIMEOUT max wall-clock for the recovery phase (default: TIMEOUT)
set -euo pipefail

VALIDATORS="${VALIDATORS:-4}"
OUTBE_CHAIN_BINARY="${OUTBE_CHAIN_BINARY:-./target/release/outbe-chain}"
OUT_DIR="${OUT_DIR:-$(mktemp -d /tmp/outbe-localnet-smoke.XXXXXX)}"
TARGET="${SMOKE_TARGET_HEIGHT:-5}"
TIMEOUT="${SMOKE_TIMEOUT_SECS:-240}"
BASE_RPC_PORT=18545
export OUT_DIR OUTBE_CHAIN_BINARY

if [[ ! -x "$OUTBE_CHAIN_BINARY" ]]; then
  echo "smoke: node binary not found/executable: $OUTBE_CHAIN_BINARY" >&2
  echo "smoke: build it first (cargo build --release -p outbe-chain --features test-protocol-overrides --bin outbe-chain)" >&2
  exit 1
fi

cleanup() { ./scripts/run-testnet.sh stop "$OUT_DIR" >/dev/null 2>&1 || true; }
trap cleanup EXIT

height_of() {
  curl -s -m 2 -X POST "http://localhost:$1" \
    -H 'content-type: application/json' \
    --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' 2>/dev/null \
    | sed -n 's/.*"result":"\(0x[0-9a-f]*\)".*/\1/p'
}

# Highest height observed across all nodes right now (decimal).
max_height() {
  local max=0 i h hv
  for ((i = 0; i < VALIDATORS; i++)); do
    h="$(height_of $((BASE_RPC_PORT + i)))"
    hv=$((${h:-0}))
    [[ $hv -gt $max ]] && max=$hv
  done
  echo "$max"
}

# wait_all_reach <target> <timeout_secs> <label>: poll until every node is at
# height >= target in lockstep, or fail (dumping tail logs) on timeout.
wait_all_reach() {
  local target="$1" timeout="$2" label="$3"
  local elapsed=0 all_ok line i h hv
  echo "smoke: [$label] waiting up to ${timeout}s for every node to reach height >= $target"
  while [[ $elapsed -lt $timeout ]]; do
    sleep 3
    elapsed=$((elapsed + 3))
    all_ok=1
    line="[$label] t=${elapsed}s:"
    for ((i = 0; i < VALIDATORS; i++)); do
      h="$(height_of $((BASE_RPC_PORT + i)))"
      hv=$((${h:-0}))
      line="$line $hv"
      [[ $hv -lt $target ]] && all_ok=0
    done
    echo "$line"
    if [[ $all_ok -eq 1 ]]; then
      echo "smoke: [$label] PASS - all $VALIDATORS nodes reached height >= $target in lockstep"
      return 0
    fi
  done
  echo "smoke: [$label] FAIL - not all nodes reached height >= $target within ${timeout}s" >&2
  for ((i = 0; i < VALIDATORS; i++)); do
    echo "--- validator-$i last log lines ---" >&2
    tail -n 20 "$OUT_DIR/validator-$i/node.log" 2>/dev/null >&2 || true
  done
  return 1
}

echo "smoke: bootstrapping $VALIDATORS-validator localnet in $OUT_DIR"
./scripts/run-testnet.sh stop "$OUT_DIR" >/dev/null 2>&1 || true
rm -rf "$OUT_DIR"
./scripts/bootstrap-testnet.sh "$VALIDATORS" "$OUT_DIR" >/dev/null
./scripts/run-testnet.sh start "$OUT_DIR" >/dev/null

# Phase 1: fresh-start consensus reaches a lock-stepped non-zero height.
wait_all_reach "$TARGET" "$TIMEOUT" "fresh-start" || exit 1

# Phase 2: restart-recovery (M-21). Stop + start preserving chain state; every
# node must recover saved DKG material + finalized state and keep advancing in
# lockstep PAST the pre-restart height. A false-positive recovery (wrong
# committee, drift fail-fast) would stall a node here.
if [[ "${SMOKE_RESTART:-1}" != "0" ]]; then
  pre="$(max_height)"
  advance="${SMOKE_RESTART_ADVANCE:-3}"
  resume_target=$((pre + advance))
  echo "smoke: restarting localnet at height ~$pre to exercise restart recovery (M-21); must advance to >= $resume_target"
  ./scripts/run-testnet.sh stop "$OUT_DIR" >/dev/null
  # Brief settle so the OS fully releases MDBX/static_files locks before the
  # restart spawns fresh nodes (run-testnet.sh stop already kills node children
  # and clears stale locks; this is insurance against lock-release latency).
  sleep 3
  ./scripts/run-testnet.sh start "$OUT_DIR" >/dev/null
  if ! wait_all_reach "$resume_target" "${SMOKE_RESTART_TIMEOUT:-$TIMEOUT}" "restart-recovery"; then
    echo "smoke: FAIL - localnet did not recover + advance after restart (M-21 recovery regression?)" >&2
    exit 1
  fi
fi

echo "smoke: ALL PHASES PASS"
exit 0
