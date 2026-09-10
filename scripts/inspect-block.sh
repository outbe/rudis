#!/usr/bin/env bash
# Inspect an outbe-chain block - split system vs user transactions, identify
# each system tx by its name + body zone (begin_block / end_block), and
# surface any `OutbeFailure(uint16 indexed code, string reason)` logs
#
# Body layout:
#   begin_block system txs ---+
#                             | all addressed to OUTBE_SYSTEM_TX_ADDRESS
#   user txs                  | user txs go to any other address
#                             |
#   end_block system txs   ---+ currently empty in outbe-chain
#
# A system tx's name is decoded from the SystemTxInputV1 tag byte (input[1]):
#   01 FinalizationAndSlashing   (begin_block)
#   02 CycleTick                 (begin_block)
#   03 BoundaryOutcome           (begin_block, optional, only at epoch boundary)
#   04 OracleSlashWindow         (begin_block)
#
# Usage:
#   ./scripts/inspect-block.sh [block_number_or_tag] [rpc_url]
#
# Examples:
#   ./scripts/inspect-block.sh                       # latest, http://localhost:18545
#   ./scripts/inspect-block.sh 241771                # decimal block number
#   ./scripts/inspect-block.sh 0x3B0AB                # hex block number
#   ./scripts/inspect-block.sh latest http://peira-1.outbe.net:8545
#   ./scripts/inspect-block.sh latest http://peira-1.outbe.net:8545 --json
#
# Requires: curl, jq. Foundry's `cast` is optional (used for keccak if present).

set -euo pipefail

BLOCK="${1:-latest}"
RPC_URL="${2:-http://localhost:18545}"
JSON_OUT="${3:-}"

# ---------------------------------------------------------------------------
# Constants - mirror outbe-primitives::addresses + outbe-evm::failure_receipt
# ---------------------------------------------------------------------------
OUTBE_SYSTEM_TX_ADDRESS="0xff00000000000000000000000000000000000001"
SYSTEM_ADDRESS="0x0000000000000000000000000000000000000000"
ZERO_FEE_POLICY_LOG_ADDRESS="0x000000000000000000000000000000000000ee06"

# topic0 = keccak256("OutbeFailure(uint16,string)")
# If `cast` is available we recompute live; otherwise we use the pinned value
# verified by `outbe-evm/src/failure_receipt.rs::tests::topic0_matches_signature`.
OUTBE_FAILURE_TOPIC0_PINNED="0x00c785ee545291880c31c3203459694b9f39ddf8e8d74303301b633edde3121e"
if command -v cast >/dev/null 2>&1; then
    OUTBE_FAILURE_TOPIC0="$(cast keccak 'OutbeFailure(uint16,string)')"
else
    OUTBE_FAILURE_TOPIC0="$OUTBE_FAILURE_TOPIC0_PINNED"
fi

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

require() {
    command -v "$1" >/dev/null 2>&1 || { echo "missing required tool: $1" >&2; exit 1; }
}
require curl
require jq

# Normalise block tag to hex form for eth_getBlockByNumber.
normalise_block_tag() {
    local tag="$1"
    case "$tag" in
        latest|earliest|pending|safe|finalized) printf '%s' "$tag" ;;
        0x*) printf '%s' "$tag" ;;
        ''|*[!0-9]*)
            echo "invalid block tag: $tag" >&2; exit 1 ;;
        *) printf '0x%x' "$tag" ;;
    esac
}

rpc_call() {
    local method="$1" params="$2"
    curl -s -X POST -H 'Content-Type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}" \
        "$RPC_URL"
}

# Decode a system tx name from its SystemTxInputV1 tag byte (input[1] = 2-char
# hex after the leading "0x"). All four are begin_block txs today; end_block
# is reserved but currently empty.
system_tx_name() {
    case "$1" in
        01) printf 'FinalizationAndSlashing' ;;
        02) printf 'CycleTick' ;;
        03) printf 'BoundaryOutcome' ;;
        04) printf 'OracleSlashWindow' ;;
        *)  printf 'Unknown(0x%s)' "$1" ;;
    esac
}

# ---------------------------------------------------------------------------
# Fetch block + receipts
# ---------------------------------------------------------------------------

BLOCK_TAG="$(normalise_block_tag "$BLOCK")"

BLOCK_JSON="$(rpc_call eth_getBlockByNumber "[\"$BLOCK_TAG\",true]")"

# Sanity: did the node return a block?
if ! echo "$BLOCK_JSON" | jq -e '.result' >/dev/null 2>&1; then
    echo "RPC returned no block for tag '$BLOCK_TAG' against $RPC_URL" >&2
    echo "$BLOCK_JSON" | jq . >&2
    exit 1
fi

BLOCK_NUM_HEX="$(echo "$BLOCK_JSON" | jq -r '.result.number')"
BLOCK_NUM_DEC="$((BLOCK_NUM_HEX))"
BLOCK_HASH="$(echo "$BLOCK_JSON" | jq -r '.result.hash')"
BLOCK_GAS_USED_HEX="$(echo "$BLOCK_JSON" | jq -r '.result.gasUsed')"
BLOCK_GAS_USED_DEC="$((BLOCK_GAS_USED_HEX))"

# ---------------------------------------------------------------------------
# JSON mode - emit machine-readable summary and exit
# ---------------------------------------------------------------------------

if [ "$JSON_OUT" = "--json" ]; then
    echo "$BLOCK_JSON" | jq \
        --arg sys "$OUTBE_SYSTEM_TX_ADDRESS" \
        '
        ([.result.transactions[]
            | (.to // "" | ascii_downcase) == $sys]
         | (index(false) // -1)) as $first_user
        | {
            blockNumber: (.result.number | tonumber? // .result.number),
            blockHash: .result.hash,
            gasUsed: (.result.gasUsed | tonumber? // .result.gasUsed),
            txCount: (.result.transactions | length),
            systemTxCount: ([.result.transactions[] | select((.to // "" | ascii_downcase) == $sys)] | length),
            userTxCount: ([.result.transactions[] | select((.to // "" | ascii_downcase) != $sys)] | length),
            txs: [
                .result.transactions
                | to_entries[]
                | .value as $tx | .key as $idx
                | {
                    index: $idx,
                    hash: $tx.hash, from: $tx.from, to: $tx.to, gas: $tx.gas,
                    kind: (if ($tx.to // "" | ascii_downcase) == $sys then "system" else "user" end),
                    zone: (
                        if ($tx.to // "" | ascii_downcase) == $sys then
                            (if $first_user == -1 or $idx < $first_user then "begin_block" else "end_block" end)
                        else null end
                    ),
                    nameByte: (
                        if ($tx.to // "" | ascii_downcase) == $sys and ($tx.input | length) > 4
                        then ($tx.input | .[2:4]) else null end
                    )
                }
            ]
        }'
    exit 0
fi

# ---------------------------------------------------------------------------
# Human summary
# ---------------------------------------------------------------------------

echo "======================================================================="
echo "Block #$BLOCK_NUM_DEC  ($BLOCK_NUM_HEX)"
echo "Hash:    $BLOCK_HASH"
echo "Gas:     $BLOCK_GAS_USED_DEC ($BLOCK_GAS_USED_HEX)"
echo "RPC:     $RPC_URL"
echo "======================================================================="

TX_COUNT=$(echo "$BLOCK_JSON" | jq '.result.transactions | length')
SYS_COUNT=$(echo "$BLOCK_JSON" | jq --arg sys "$OUTBE_SYSTEM_TX_ADDRESS" \
    '[.result.transactions[] | select((.to // "" | ascii_downcase) == $sys)] | length')
USR_COUNT=$(echo "$BLOCK_JSON" | jq --arg sys "$OUTBE_SYSTEM_TX_ADDRESS" \
    '[.result.transactions[] | select((.to // "" | ascii_downcase) != $sys)] | length')

echo
echo "Transactions: total=$TX_COUNT  system=$SYS_COUNT  user=$USR_COUNT"
echo

if [ "$TX_COUNT" -eq 0 ]; then
    echo "(empty block - no transactions)"
else
    # Pre-scan to find the first user-tx index - system txs before it are
    # `begin_block`, system txs after it are `end_block`.
    FIRST_USER_IDX="$(echo "$BLOCK_JSON" \
        | jq --arg sys "$OUTBE_SYSTEM_TX_ADDRESS" -r '
            [.result.transactions[]
                | (.to // "" | ascii_downcase) == $sys]
            | (index(false) // -1)')"

    printf "%-3s  %-7s  %-11s  %-26s  %-66s\n" "#" "KIND" "ZONE" "NAME" "TX HASH"
    printf "%-3s  %-7s  %-11s  %-26s  %-66s\n" "---" "-------" "-----------" "--------------------------" "----------------------------------------------------------------"

    INDEX=0
    while read -r LINE; do
        TX_HASH=$(echo "$LINE" | jq -r '.hash')
        TX_TO=$(echo "$LINE" | jq -r '.to // "null"')
        TX_INPUT=$(echo "$LINE" | jq -r '.input')
        TX_TO_LC=$(echo "$TX_TO" | tr '[:upper:]' '[:lower:]')

        if [ "$TX_TO_LC" = "$OUTBE_SYSTEM_TX_ADDRESS" ]; then
            KIND="system"
            # SystemTxInputV1 layout: input[0]=version (0x01), input[1]=name tag
            # `eth_getBlockByNumber` returns input with leading "0x"; the name
            # tag is at positions 4-5 in the hex string.
            NAME_BYTE="${TX_INPUT:4:2}"
            NAME="$(system_tx_name "$NAME_BYTE")"
            if [ "$FIRST_USER_IDX" = "-1" ] || [ "$INDEX" -lt "$FIRST_USER_IDX" ]; then
                ZONE="begin_block"
            else
                ZONE="end_block"
            fi
        else
            KIND="user"
            ZONE="-"
            NAME="-"
        fi
        printf "%-3s  %-7s  %-11s  %-26s  %-66s\n" "$INDEX" "$KIND" "$ZONE" "$NAME" "$TX_HASH"
        INDEX=$((INDEX + 1))
    done < <(echo "$BLOCK_JSON" | jq -c '.result.transactions[]')
fi

# ---------------------------------------------------------------------------
# Soft-failure receipts
# ---------------------------------------------------------------------------

echo
echo "--- soft-failure receipts in this block ------------------------------"

# Fetch logs for OutbeFailure topic0 within this single block, then group by tx.
LOGS_JSON="$(rpc_call eth_getLogs \
    "[{\"fromBlock\":\"$BLOCK_NUM_HEX\",\"toBlock\":\"$BLOCK_NUM_HEX\",\"topics\":[\"$OUTBE_FAILURE_TOPIC0\"]}]")"
LOG_COUNT="$(echo "$LOGS_JSON" | jq '.result | length')"

if [ "$LOG_COUNT" = "0" ] || [ "$LOG_COUNT" = "null" ]; then
    echo "(none - all transactions succeeded)"
else
    echo "$LOG_COUNT OutbeFailure log(s):"
    echo "$LOGS_JSON" | jq -r --arg zerofee "$ZERO_FEE_POLICY_LOG_ADDRESS" --arg sys "$OUTBE_SYSTEM_TX_ADDRESS" '
        .result[] |
        {
            tx: .transactionHash,
            addr: (.address | ascii_downcase),
            code: (.topics[1] | .[58:] | tonumber),
            origin: (if (.address | ascii_downcase) == $zerofee then "zero-fee" elif (.address | ascii_downcase) == $sys then "system_tx" else "?" end)
        } |
        "  * tx=\(.tx)  code=\(.code)  origin=\(.origin)"
    '
fi

# ---------------------------------------------------------------------------
# Receipt status summary (status=1 vs status=0)
# ---------------------------------------------------------------------------

if [ "$TX_COUNT" -gt 0 ]; then
    echo
    echo "--- receipt statuses --------------------------------------------------"
    SUCCESS=0
    FAILED=0
    while read -r TX_HASH; do
        STATUS=$(rpc_call eth_getTransactionReceipt "[\"$TX_HASH\"]" \
            | jq -r '.result.status')
        if [ "$STATUS" = "0x1" ]; then
            SUCCESS=$((SUCCESS + 1))
        else
            FAILED=$((FAILED + 1))
        fi
    done < <(echo "$BLOCK_JSON" | jq -r '.result.transactions[].hash')
    echo "  success: $SUCCESS"
    echo "  failed:  $FAILED"
fi

echo "======================================================================="
