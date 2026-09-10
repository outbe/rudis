#!/usr/bin/env bash
# Scan a block range [FROM..TO] and print every event log emitted, grouped by
# block. Decodes topic0 against the outbe-chain event registry plus any extra
# signatures passed via --sig.
#
# Usage:
#   ./scripts/scan-events.sh <from> <to> [rpc_url] [options]
#
#   <from>, <to>     decimal, hex (0x...), or one of: latest|earliest|safe|finalized
#                    Use "latest" for <to> to scan up to the head.
#   rpc_url          default http://localhost:18545
#
# Options:
#   --address <hex>          filter by contract address (repeatable)
#   --topic0 <hex>           filter by topic0 (repeatable)
#   --sig <"Name(t1,t2)">    extra signature -> name decode (repeatable)
#   --json                   one JSON line per log (machine-readable)
#   --only-known             skip logs whose topic0 is not in the registry
#   --show-empty             also print blocks that emitted zero logs
#
# Examples:
#   ./scripts/scan-events.sh 1000 1050
#   ./scripts/scan-events.sh 0x3B0AB latest http://peira-1.outbe.net:8545
#   ./scripts/scan-events.sh 1000 latest --topic0 0x00c785ee... --json
#   ./scripts/scan-events.sh 1000 1050 --sig 'Transfer(address,address,uint256)'
#
# Requires: curl, jq. Optional: cast (foundry) - used to compute keccak256 of
# event signatures. Without cast, only the built-in pinned registry is used.

set -euo pipefail

# ---------------------------------------------------------------------------
# Parse positional args + options
# ---------------------------------------------------------------------------

if [ $# -lt 2 ]; then
    sed -n '2,30p' "$0" >&2
    exit 1
fi

FROM_RAW="$1"; shift
TO_RAW="$1"; shift

RPC_URL="http://localhost:18545"
ADDRESSES=()
TOPIC0_FILTERS=()
EXTRA_SIGS=()
JSON_OUT=0
ONLY_KNOWN=0
SHOW_EMPTY=0

if [ $# -gt 0 ] && [[ "$1" != --* ]]; then
    RPC_URL="$1"; shift
fi

while [ $# -gt 0 ]; do
    case "$1" in
        --address) ADDRESSES+=("$(echo "$2" | tr '[:upper:]' '[:lower:]')"); shift 2 ;;
        --topic0)  TOPIC0_FILTERS+=("$(echo "$2" | tr '[:upper:]' '[:lower:]')"); shift 2 ;;
        --sig)     EXTRA_SIGS+=("$2"); shift 2 ;;
        --json)    JSON_OUT=1; shift ;;
        --only-known) ONLY_KNOWN=1; shift ;;
        --show-empty) SHOW_EMPTY=1; shift ;;
        *) echo "unknown option: $1" >&2; exit 1 ;;
    esac
done

require() { command -v "$1" >/dev/null 2>&1 || { echo "missing required tool: $1" >&2; exit 1; }; }
require curl
require jq
HAVE_CAST=0
if command -v cast >/dev/null 2>&1; then HAVE_CAST=1; fi

# ---------------------------------------------------------------------------
# RPC helpers
# ---------------------------------------------------------------------------

rpc_call() {
    local method="$1" params="$2"
    curl -s -X POST -H 'Content-Type: application/json' \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":1}" \
        "$RPC_URL"
}

resolve_block() {
    local tag="$1"
    case "$tag" in
        latest|earliest|pending|safe|finalized)
            rpc_call eth_getBlockByNumber "[\"$tag\",false]" \
                | jq -r '.result.number' \
                | xargs printf '%d\n'
            ;;
        0x*) printf '%d\n' "$tag" ;;
        ''|*[!0-9]*) echo "invalid block tag: $tag" >&2; exit 1 ;;
        *) printf '%d\n' "$tag" ;;
    esac
}

FROM_DEC="$(resolve_block "$FROM_RAW")"
TO_DEC="$(resolve_block "$TO_RAW")"

if [ "$FROM_DEC" -gt "$TO_DEC" ]; then
    echo "from ($FROM_DEC) > to ($TO_DEC)" >&2; exit 1
fi

# ---------------------------------------------------------------------------
# Event signature registry
#
# Three parallel arrays keyed by topic0:
#   TOPIC_KEYS[i] = topic0 (lowercase hex)
#   TOPIC_VALS[i] = canonical "Name(t1,t2,...)" sig (used for display + jq)
#   TOPIC_META[i] = pipe-delimited "field=type[ indexed]" entries (decode info)
#
# Auto-populated by scanning interfaces/*.sol, contracts/precompiles/src/*.sol,
# and crates/**/*.rs sol! blocks.
# A small pinned set is added unconditionally for cast-less mode.
# ---------------------------------------------------------------------------

TOPIC_KEYS=()
TOPIC_VALS=()
TOPIC_META=()

lower() { echo "$1" | tr '[:upper:]' '[:lower:]'; }

set_entry() {
    local key="$(lower "$1")" sig="$2" meta="$3" i
    for i in "${!TOPIC_KEYS[@]}"; do
        if [ "${TOPIC_KEYS[$i]}" = "$key" ]; then
            TOPIC_VALS[$i]="$sig"
            [ -n "$meta" ] && TOPIC_META[$i]="$meta"
            return
        fi
    done
    TOPIC_KEYS+=("$key")
    TOPIC_VALS+=("$sig")
    TOPIC_META+=("$meta")
}

# Register a canonical "Name(t1,t2)" sig (no decode info).
register_canonical() {
    local sig="$1" topic
    [ "$HAVE_CAST" = "0" ] && return
    topic="$(cast keccak "$sig" 2>/dev/null || true)"
    [ -n "$topic" ] && set_entry "$topic" "$sig" ""
}

# Register a full event with field names + indexed annotations.
#   register_full Name "field1=type1[ indexed]" "field2=type2" ...
register_full() {
    [ "$HAVE_CAST" = "0" ] && return
    local name="$1"; shift
    local canonical_types="" meta="" p type
    for p in "$@"; do
        type="${p#*=}"
        case "$type" in
            *" indexed") canonical_types="${canonical_types:+$canonical_types,}${type% indexed}" ;;
            *)           canonical_types="${canonical_types:+$canonical_types,}$type" ;;
        esac
        meta="${meta:+$meta|}${p}"
    done
    local canonical="${name}(${canonical_types})"
    local topic
    topic="$(cast keccak "$canonical" 2>/dev/null || true)"
    [ -z "$topic" ] && return
    set_entry "$topic" "$canonical" "$meta"
}

# Awk parser: walks a file and emits one line per `event Foo(...);`
# Output format: Name|field1=type1[ indexed]|field2=type2|...
# Works on both Solidity files and Rust sol! blocks (same syntax).
parse_event_file() {
    awk '
        function flush() {
            if (!collecting) return
            if (match(buf, /event[[:space:]]+[A-Za-z_][A-Za-z0-9_]*[[:space:]]*\([^;]*\)[[:space:]]*;/)) {
                decl = substr(buf, RSTART, RLENGTH)
                sub(/^event[[:space:]]+/, "", decl)
                name = decl;  sub(/[[:space:]]*\(.*/, "", name)
                body = decl;  sub(/^[^(]*\(/, "", body);  sub(/\)[[:space:]]*;.*$/, "", body)
                n = split(body, parts, ",")
                out = name
                for (i = 1; i <= n; i++) {
                    p = parts[i]
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", p)
                    if (p == "") continue
                    m = split(p, toks, /[[:space:]]+/)
                    if (m == 0) continue
                    fname = (m >= 2 ? toks[m] : "arg")
                    type_str = toks[1]
                    indexed = ""
                    for (j = 2; j < m; j++) {
                        if (toks[j] == "indexed") indexed = " indexed"
                        else type_str = type_str " " toks[j]
                    }
                    out = out "|" fname "=" type_str indexed
                }
                print out
            }
            collecting = 0; buf = ""
        }
        /^[[:space:]]*event[[:space:]]+[A-Za-z_]/ {
            if (collecting) flush()
            collecting = 1; buf = $0
            if (buf ~ /\)[[:space:]]*;/) flush()
            next
        }
        collecting {
            buf = buf " " $0
            if (buf ~ /\)[[:space:]]*;/) flush()
        }
        END { if (collecting) flush() }
    ' "$1"
}

# Resolve repo root from script location so the script works wherever invoked.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Auto-discover event sources, then parse + register each.
if [ "$HAVE_CAST" = "1" ]; then
    SOURCE_FILES=""
    if [ -d "$REPO_ROOT/interfaces" ]; then
        SOURCE_FILES="$SOURCE_FILES $(grep -rl -E '^[[:space:]]*event[[:space:]]+[A-Za-z_]' "$REPO_ROOT/interfaces" 2>/dev/null || true)"
    fi
    if [ -d "$REPO_ROOT/contracts/precompiles/src" ]; then
        SOURCE_FILES="$SOURCE_FILES $(grep -rl -E '^[[:space:]]*event[[:space:]]+[A-Za-z_]' "$REPO_ROOT/contracts/precompiles/src" 2>/dev/null || true)"
    fi
    if [ -d "$REPO_ROOT/crates" ]; then
        SOURCE_FILES="$SOURCE_FILES $(grep -rl --include='*.rs' -E '^[[:space:]]*event[[:space:]]+[A-Za-z_]' "$REPO_ROOT/crates" 2>/dev/null || true)"
    fi
    for f in $SOURCE_FILES; do
        [ -f "$f" ] || continue
        while IFS= read -r line; do
            [ -z "$line" ] && continue
            OLD_IFS="$IFS"; IFS='|'; set -- $line; IFS="$OLD_IFS"
            ev_name="$1"; shift
            register_full "$ev_name" "$@"
        done < <(parse_event_file "$f")
    done
fi

# Always-on pinned entries (used even without cast).
set_entry "0x00c785ee545291880c31c3203459694b9f39ddf8e8d74303301b633edde3121e" \
    "OutbeFailure(uint16,string)" "code=uint16 indexed|reason=string"

# User-supplied --sig entries (canonical only).
for sig in "${EXTRA_SIGS[@]:-}"; do
    [ -n "$sig" ] && register_canonical "$sig"
done

# Look up canonical sig for a topic0.
decode_topic0() {
    local t0="$(lower "$1")" i
    for i in "${!TOPIC_KEYS[@]}"; do
        if [ "${TOPIC_KEYS[$i]}" = "$t0" ]; then
            printf '%s' "${TOPIC_VALS[$i]}"
            return
        fi
    done
}

# Look up decode meta for a topic0.
decode_meta() {
    local t0="$(lower "$1")" i
    for i in "${!TOPIC_KEYS[@]}"; do
        if [ "${TOPIC_KEYS[$i]}" = "$t0" ]; then
            printf '%s' "${TOPIC_META[$i]}"
            return
        fi
    done
}

# Render a single indexed topic value for a Solidity type. Dynamic types
# (string/bytes/array) are stored as keccak256(value) and cannot be recovered.
decode_indexed_value() {
    local type="$1" raw="$2" val
    case "$type" in
        address)
            val="$(cast parse-bytes32-address "$raw" 2>/dev/null || true)"
            [ -n "$val" ] && printf '%s' "$val" || printf '%s' "$raw"
            ;;
        bool)
            val="$(cast to-dec "$raw" 2>/dev/null || true)"
            if [ "$val" = "1" ]; then printf 'true'; else printf 'false'; fi
            ;;
        uint*|int*)
            val="$(cast to-dec "$raw" 2>/dev/null || true)"
            [ -n "$val" ] && printf '%s' "$val" || printf '%s' "$raw"
            ;;
        bytes32) printf '%s' "$raw" ;;
        string|bytes) printf '%s  (keccak hash - cannot recover)' "$raw" ;;
        *)
            case "$type" in
                *"["*"]"*|tuple*)
                    printf '%s  (keccak hash - cannot recover)' "$raw" ;;
                *)
                    printf '%s' "$raw" ;;
            esac
            ;;
    esac
}

# Pretty-print all args of one log line. Needs cast for abi-decode on data.
decode_log_args() {
    local t0="$1" topics_csv="$2" data="$3" indent="$4"
    local meta; meta="$(decode_meta "$t0")"
    [ -z "$meta" ] && return
    [ "$HAVE_CAST" = "0" ] && return

    local topics_arr=()
    if [ -n "$topics_csv" ]; then
        local OLD_IFS_T="$IFS"; IFS=','
        for t in $topics_csv; do
            t="$(echo "$t" | tr -d ' ')"
            [ -n "$t" ] && topics_arr+=("$t")
        done
        IFS="$OLD_IFS_T"
    fi

    local data_types="" data_fields=() indexed_idx=0
    local OLD_IFS_M="$IFS"; IFS='|'; set -- $meta; IFS="$OLD_IFS_M"

    for p in "$@"; do
        local field="${p%%=*}" type="${p#*=}"
        if [ "${type#* }" = "indexed" ] || [ "${type% indexed}" != "$type" ]; then
            local base_type="${type% indexed}"
            local raw="${topics_arr[$indexed_idx]:-0x}"
            indexed_idx=$((indexed_idx + 1))
            printf '%s%s (indexed %s) = %s\n' "$indent" "$field" "$base_type" \
                "$(decode_indexed_value "$base_type" "$raw")"
        else
            data_types="${data_types:+$data_types,}$type"
            data_fields+=("$field|$type")
        fi
    done

    if [ -n "$data_types" ] && [ "$data" != "0x" ] && [ -n "$data" ] && [ "$data" != "null" ]; then
        # cast abi-decode signature: `name(in-types)(out-types)` - we treat the
        # data section as a function "output" with no inputs.
        local decoded
        decoded="$(cast abi-decode "x()($data_types)" "$data" 2>/dev/null || true)"
        if [ -n "$decoded" ]; then
            local idx=0 entry field type_str
            while IFS= read -r line; do
                entry="${data_fields[$idx]:-arg$idx|?}"
                field="${entry%%|*}"
                type_str="${entry#*|}"
                printf '%s%s (%s) = %s\n' "$indent" "$field" "$type_str" "$line"
                idx=$((idx + 1))
            done <<< "$decoded"
        fi
    fi
}

# Build a JSON object once: { topic0_lowercase: "Name(t1,t2)", ... }
# Passed to jq as --argjson so each log line can be annotated cheaply.
build_registry_json() {
    local i first=1
    printf '{'
    for i in "${!TOPIC_KEYS[@]}"; do
        if [ "$first" = "1" ]; then first=0; else printf ','; fi
        printf '"%s":"%s"' "${TOPIC_KEYS[$i]}" "${TOPIC_VALS[$i]}"
    done
    printf '}'
}
REGISTRY_JSON="$(build_registry_json)"

# ---------------------------------------------------------------------------
# Iterate blocks and fetch logs
# ---------------------------------------------------------------------------

build_filter() {
    local from_hex="$1" to_hex="$2"
    local addr_json topics_json
    if [ "${#ADDRESSES[@]}" -gt 0 ]; then
        addr_json="[$(printf '"%s",' "${ADDRESSES[@]}" | sed 's/,$//')]"
    else
        addr_json='null'
    fi
    if [ "${#TOPIC0_FILTERS[@]}" -gt 0 ]; then
        topics_json="[[$(printf '"%s",' "${TOPIC0_FILTERS[@]}" | sed 's/,$//')]]"
    else
        topics_json='[]'
    fi
    if [ "$addr_json" = "null" ]; then
        printf '{"fromBlock":"%s","toBlock":"%s","topics":%s}' "$from_hex" "$to_hex" "$topics_json"
    else
        printf '{"fromBlock":"%s","toBlock":"%s","address":%s,"topics":%s}' \
            "$from_hex" "$to_hex" "$addr_json" "$topics_json"
    fi
}

format_human() {
    local block_dec="$1" log_json="$2"
    local addr tx_hash log_idx t0 name topics_rest data
    addr=$(echo "$log_json" | jq -r '.address')
    tx_hash=$(echo "$log_json" | jq -r '.transactionHash')
    log_idx=$(printf '%d' "$(echo "$log_json" | jq -r '.logIndex')")
    t0=$(echo "$log_json" | jq -r '.topics[0] // ""')
    name="$(decode_topic0 "$t0")"
    if [ -z "$name" ]; then
        if [ "$ONLY_KNOWN" = "1" ]; then return; fi
        name="<unknown topic0>"
    fi
    topics_rest=$(echo "$log_json" | jq -r '.topics[1:] | join(", ") // ""')
    data=$(echo "$log_json" | jq -r '.data // "0x"')

    printf '  [block=%d logIdx=%d] %s\n' "$block_dec" "$log_idx" "$name"
    printf '      addr:   %s\n' "$addr"
    printf '      tx:     %s\n' "$tx_hash"
    printf '      topic0: %s\n' "$t0"
    if [ -n "$topics_rest" ]; then
        printf '      topics: %s\n' "$topics_rest"
    fi
    if [ "$data" != "0x" ] && [ "$data" != "null" ]; then
        printf '      data:   %s\n' "$data"
    fi
    # Decoded args (best-effort; requires cast + a known signature).
    local decoded_block
    decoded_block="$(decode_log_args "$t0" "$topics_rest" "$data" '        ')"
    if [ -n "$decoded_block" ]; then
        printf '      args:\n%s\n' "$decoded_block"
    fi
}

if [ "$JSON_OUT" = "0" ]; then
    echo "======================================================================="
    echo "Scanning blocks $FROM_DEC..$TO_DEC  (rpc=$RPC_URL)"
    [ "${#ADDRESSES[@]}" -gt 0 ] && echo "Addresses: ${ADDRESSES[*]}"
    [ "${#TOPIC0_FILTERS[@]}" -gt 0 ] && echo "Topic0:    ${TOPIC0_FILTERS[*]}"
    [ "$HAVE_CAST" = "0" ] && echo "Note: cast not found - only pinned topic0s decoded."
    echo "======================================================================="
fi

TOTAL=0
for ((b=FROM_DEC; b<=TO_DEC; b++)); do
    HEX="$(printf '0x%x' "$b")"
    FILTER="$(build_filter "$HEX" "$HEX")"
    LOGS_JSON="$(rpc_call eth_getLogs "[$FILTER]")"
    if ! echo "$LOGS_JSON" | jq -e '.result' >/dev/null 2>&1; then
        echo "RPC error at block $b:" >&2
        echo "$LOGS_JSON" | jq . >&2
        exit 1
    fi
    COUNT="$(echo "$LOGS_JSON" | jq '.result | length')"
    if [ "$COUNT" = "0" ]; then
        if [ "$JSON_OUT" = "0" ] && [ "$SHOW_EMPTY" = "1" ]; then
            echo
            echo "--- block $b  ($HEX) - 0 log(s) ----------------------------"
        fi
        continue
    fi

    if [ "$JSON_OUT" = "1" ]; then
        echo "$LOGS_JSON" | jq -c \
            --argjson b "$b" \
            --argjson reg "$REGISTRY_JSON" \
            '.result[]
             | . + {
                 blockNumberDec: $b,
                 logIndexDec: (.logIndex | tonumber? // null),
                 eventSig: ($reg[(.topics[0] // "") | ascii_downcase] // null)
             }'
    else
        echo
        echo "--- block $b  ($HEX) - $COUNT log(s) ----------------------------"
        while read -r LINE; do
            format_human "$b" "$LINE"
        done < <(echo "$LOGS_JSON" | jq -c '.result[]')
    fi
    TOTAL=$((TOTAL + COUNT))
done

if [ "$JSON_OUT" = "0" ]; then
    echo
    echo "======================================================================="
    echo "Total logs: $TOTAL  across $((TO_DEC - FROM_DEC + 1)) block(s)"
    echo "======================================================================="
fi
