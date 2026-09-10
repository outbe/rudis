#!/usr/bin/env bash
# Start, stop, or check status of a local testnet bootstrapped by bootstrap-testnet.sh.
#
# Usage:
#   ./scripts/run-testnet.sh start  <OUTPUT_DIR>
#   ./scripts/run-testnet.sh stop   <OUTPUT_DIR>
#   ./scripts/run-testnet.sh status <OUTPUT_DIR>
#
# Example:
#   ./scripts/bootstrap-testnet.sh 4 /tmp/outbe-testnet
#   ./scripts/run-testnet.sh start /tmp/outbe-testnet
#   ./scripts/run-testnet.sh status /tmp/outbe-testnet
#   ./scripts/run-testnet.sh stop   /tmp/outbe-testnet

set -euo pipefail

ACTION="${1:?Usage: $0 <start|stop|status> <output_dir>}"
OUTPUT_DIR="${2:?Usage: $0 <start|stop|status> <output_dir>}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
VALIDATORS_JSON="$OUTPUT_DIR/validators.json"
PID_DIR="$OUTPUT_DIR/pids"
RETH_BOOTNODES="${RETH_BOOTNODES:-}"
RETH_BOOTNODES_FILE="${RETH_BOOTNODES_FILE:-$OUTPUT_DIR/reth-bootnodes.txt}"
# Uniform port shift so multiple localnets can run in parallel. Applied to every
# base port below (and the TEE socket). Must match the PORT_OFFSET the network was
# bootstrapped with - bootstrap-testnet.sh bakes the same shift into the consensus
# p2p addresses (validators.json/genesis) and reth bootnodes.
PORT_OFFSET="${PORT_OFFSET:-0}"
OUTBE_TEST_DROP_NEW_PAYLOAD_VALIDATOR="${OUTBE_TEST_DROP_NEW_PAYLOAD_VALIDATOR:-}"
OUTBE_TEST_DROP_NEW_PAYLOAD_HEIGHT="${OUTBE_TEST_DROP_NEW_PAYLOAD_HEIGHT:-}"
# Every genesis produced by bootstrap-testnet.sh is GramineDirectDev from block
# 1. The enclave is therefore mandatory; an unset flag cannot create a tee-less
# fallback network.
: "${OUTBE_TEE_ENCLAVE:=1}"

# --- Helpers ---

num_validators() {
    python3 -c "import json; print(len(json.load(open('$VALIDATORS_JSON'))))"
}

locate_binary() {
    if [ -n "${OUTBE_CHAIN_BINARY:-}" ]; then
        if [ ! -x "$OUTBE_CHAIN_BINARY" ]; then
            echo "Error: OUTBE_CHAIN_BINARY is set but not executable: $OUTBE_CHAIN_BINARY"
            exit 1
        fi
        echo "Using outbe-chain binary: $OUTBE_CHAIN_BINARY"
        return
    fi

    for candidate in ./target/release/outbe-chain; do
        if [ -x "$candidate" ]; then
            OUTBE_CHAIN_BINARY="$candidate"
            echo "Using outbe-chain binary: $OUTBE_CHAIN_BINARY"
            return
        fi
    done

    echo "Error: release outbe-chain binary not found. Build it with test-protocol-overrides or set OUTBE_CHAIN_BINARY."
    exit 1
}

locate_radicle_binary() {
    if [ -n "${OUTBE_RADICLE_BINARY:-}" ]; then
        if [ ! -x "$OUTBE_RADICLE_BINARY" ]; then
            echo "Error: OUTBE_RADICLE_BINARY is set but not executable: $OUTBE_RADICLE_BINARY"
            exit 1
        fi
        return
    fi
    for candidate in ./target/release/outbe-radicle; do
        if [ -x "$candidate" ]; then
            OUTBE_RADICLE_BINARY="$candidate"
            return
        fi
    done
    echo "Error: release outbe-radicle binary not found; set OUTBE_RADICLE_BINARY." >&2
    exit 1
}

load_bootnodes() {
    if [ -n "$RETH_BOOTNODES" ]; then
        printf '%s' "$RETH_BOOTNODES"
        return
    fi

    if [ -f "$RETH_BOOTNODES_FILE" ]; then
        RETH_BOOTNODES_FILE="$RETH_BOOTNODES_FILE" python3 -c '
import os
from pathlib import Path

path = Path(os.environ["RETH_BOOTNODES_FILE"])
nodes = [
    line.strip()
    for line in path.read_text().splitlines()
    if line.strip() and not line.lstrip().startswith("#")
]
print(",".join(nodes), end="")
'
    fi
}

# --- Commands ---

do_start() {
    if [ ! -f "$VALIDATORS_JSON" ]; then
        echo "Error: $VALIDATORS_JSON not found. Run bootstrap-testnet.sh first."
        exit 1
    fi

    locate_binary
    locate_radicle_binary
    mkdir -p "$PID_DIR"

    # WS-M2 M5: re-apply TEE flags persisted by a previous start for any var the
    # caller did not set this time, so a restart stays consistent. Dropping
    # OUTBE_TEE_SEAL across a restart would halt every node (expected seal vs none);
    # dropping OUTBE_TEE_ENCLAVE would silently resume the chain WITHOUT TEE. An
    # explicit env var still wins (the file uses `:=`, set-if-unset). Remove the file
    # (or `localnet-clean`) to switch modes.
    local tee_env_file="$OUTPUT_DIR/tee-env"
    if [ -f "$tee_env_file" ]; then
        # shellcheck disable=SC1090
        . "$tee_env_file"
    fi

    local n
    n=$(num_validators)
    echo "Starting $n validators from $OUTPUT_DIR"

    local bootnodes
    bootnodes="$(load_bootnodes)"
    if [ -n "$bootnodes" ]; then
        if [ -n "$RETH_BOOTNODES" ]; then
            echo "Using Reth bootnodes from RETH_BOOTNODES"
        else
            echo "Using Reth bootnodes from $RETH_BOOTNODES_FILE"
        fi
    fi

    local base_rpc=$((18545 + PORT_OFFSET))
    local base_p2p=$((30303 + PORT_OFFSET))
    local base_discv5=$((31303 + PORT_OFFSET))
    local base_consensus=$((30400 + PORT_OFFSET))
    local base_authrpc=$((8551 + PORT_OFFSET))
    local base_metrics=$((9101 + PORT_OFFSET))
    local base_radicle=$((8776 + PORT_OFFSET))
    local base_radicle_status=$((8876 + PORT_OFFSET))

    # Mandatory per-validator GramineDirectDev enclave. The binary is
    # auto-detected in ./target or supplied via OUTBE_TEE_ENCLAVE_BINARY.
    local tee_enclave_bin=""
    local tee_gramine_image="outbe-tee-enclave-gramine-test"
    local tee_test_signing_key=""
    if [ -z "${OUTBE_TEE_ENCLAVE:-}" ]; then
        echo "Error: GramineDirectDev genesis cannot run without an enclave." >&2
        exit 1
    fi
    if [ -n "${OUTBE_TEE_ENCLAVE_BARE:-}" ]; then
        echo "Error: bare-host enclave mode is not GramineDirectDev and is no longer supported." >&2
        exit 1
    fi
    if [ -n "${OUTBE_TEE_ENCLAVE:-}" ]; then
        # OUTBE_TEE_ENCLAVE_MOCK=1 selects the dev mock binary
        # (`outbe-tee-enclave-mock`, built `--features mock`): unattested quote +
        # stable sealing key, for localnet/CI without SGX. Node args are identical
        # - only which binary the container runs differs.
        local tee_bin_name="outbe-tee-enclave"
        local tee_build_hint="cargo build --release --bin outbe-tee-enclave"
        if [ -n "${OUTBE_TEE_ENCLAVE_MOCK:-}" ]; then
            tee_bin_name="outbe-tee-enclave-mock"
            tee_build_hint="cargo build --release --bin outbe-tee-enclave-mock --features mock"
        fi
        tee_enclave_bin="${OUTBE_TEE_ENCLAVE_BINARY:-}"
        if [ -z "$tee_enclave_bin" ]; then
            for cand in "./target/release/$tee_bin_name"; do
                if [ -x "$cand" ]; then tee_enclave_bin="$cand"; break; fi
            done
        fi
        if [ -z "$tee_enclave_bin" ]; then
            echo "Error: OUTBE_TEE_ENCLAVE set but $tee_bin_name binary not found." >&2
            echo "  Build it ($tee_build_hint) or set OUTBE_TEE_ENCLAVE_BINARY." >&2
            exit 1
        fi
        # The development enclave always runs under Gramine. It deliberately
        # uses gramine-direct even on an SGX host; real DcapRequired execution is
        # owned by the separate I9 release harness and production genesis.
        if ! command -v docker >/dev/null 2>&1; then
            echo "Error: OUTBE_TEE_ENCLAVE needs Docker to run the Gramine enclave." >&2
            echo "  Install Docker; there is no tee-less or bare-host fallback." >&2
            exit 1
        fi
        if ! docker info >/dev/null 2>&1; then
            echo "Error: Docker is installed but not reachable by this user." >&2
            echo "  Add your user to the 'docker' group (sudo usermod -aG docker \$USER; re-login)," >&2
            echo "  or run this script under sudo (note: it makes the validator data dirs root-owned)." >&2
            exit 1
        fi
        if ! docker image inspect "$tee_gramine_image" >/dev/null 2>&1; then
            echo "Test-only Gramine enclave image '$tee_gramine_image' missing - building it..."
            if ! docker build \
                -f bin/outbe-tee-enclave/gramine/Dockerfile.test \
                -t "$tee_gramine_image" \
                bin/outbe-tee-enclave/gramine; then
                echo "Error: failed to build the Gramine enclave image." >&2
                exit 1
            fi
        fi
        tee_test_signing_key="$OUTPUT_DIR/test-sgx-signing-key.pem"
        if [ -L "$tee_test_signing_key" ]; then
            echo "Error: unsafe symlink at test SGX signing key path: $tee_test_signing_key" >&2
            exit 1
        fi
        if [ ! -f "$tee_test_signing_key" ]; then
            if ! docker run --rm \
                --user "$(id -u):$(id -g)" \
                --entrypoint gramine-sgx-gen-private-key \
                -v "$(readlink -f "$OUTPUT_DIR"):/keys" \
                "$tee_gramine_image" \
                /keys/test-sgx-signing-key.pem; then
                echo "Error: failed to generate scenario-scoped test SGX signing key." >&2
                exit 1
            fi
            chmod 600 "$tee_test_signing_key"
        fi
        if [ -n "${OUTBE_TEE_SEAL:-}" ] && [ -z "${OUTBE_TEE_ENCLAVE_MOCK:-}" ]; then
            echo "Error: gramine-direct cannot EGETKEY-seal the production enclave; use the mock lane for restart tests or bootstrap a new dev genesis." >&2
            exit 1
        fi
        echo "TEE enclave enabled ($tee_bin_name; GramineDirectDev, not hardware evidence): $tee_enclave_bin"
        # WS-M2 M5: persist the resolved TEE flags so a later `start` that omits them
        # stays consistent with this one (see the re-apply note at the top of do_start).
        {
            printf ': "${OUTBE_TEE_ENCLAVE:=%s}"\n' "${OUTBE_TEE_ENCLAVE:-}"
            printf ': "${OUTBE_TEE_ENCLAVE_MOCK:=%s}"\n' "${OUTBE_TEE_ENCLAVE_MOCK:-}"
            printf ': "${OUTBE_TEE_SEAL:=%s}"\n' "${OUTBE_TEE_SEAL:-}"
        } > "$tee_env_file"
    fi

    local launched=()
    for i in $(seq 0 $((n - 1))); do
        local pid_file="$PID_DIR/validator-$i.pid"

        if [ -f "$pid_file" ] && kill -0 "$(cat "$pid_file")" 2>/dev/null; then
            echo "  Validator $i already running (PID $(cat "$pid_file")), skipping"
            continue
        fi

        local validator_dir="$OUTPUT_DIR/validator-$i"
        local log_file="$validator_dir/node.log"
        local exit_file="$validator_dir/node.exit"
        local reth_log_dir="$validator_dir/logs"

        # Clean stale lock file
        rm -f "$validator_dir/data/db/lock"
        rm -f "$exit_file"
        mkdir -p "$reth_log_dir"

        # Launch this validator's TEE enclave and wait for its socket so the node
        # can authenticate it at startup. The enclave always runs under
        # gramine-direct and this development lane is never hardware evidence.
        # Gramine pathname UDS are process-internal, so the
        # node reaches the enclave over TCP (--network host puts the port on the
        # host loopback). One container per validator.
        local -a tee_args=()
        if [ -n "$tee_enclave_bin" ]; then
            # Distinct DKG identity per validator (else the n enclaves would be
            # the same DKG participant - a degenerate ceremony). Deterministic
            # from the validator index; a validator-count/order change requires a
            # clean re-bootstrap. Offset by 1 so the seed is never all-zero.
            local tee_dkg_seed
            tee_dkg_seed=$(printf '%064x' "$((i + 1))")
            # Base 17000, NOT 7000: macOS AirPlay Receiver (Control Center) binds
            # *:7000 by default on Apple Silicon - the very platform `localnet`
            # targets - so the node would connect to AirPlay and fail-fast on a quote
            # timeout. 17000 is off that path. Endpoint is IPv4-literal (the enclave
            # binds 127.0.0.1 only; `localhost` could resolve to ::1).
            local tee_port=$((17000 + PORT_OFFSET + i))
            local tee_endpoint="127.0.0.1:$tee_port"
            # Tag the container with PORT_OFFSET so parallel localnets get
            # distinct names (`outbe-tee-gramine-<offset>-<i>`) and each run only
            # tears down its own enclaves.
            local tee_ctr="outbe-tee-gramine-${PORT_OFFSET}-$i"
            # Withhold SGX devices unconditionally so the entrypoint selects
            # gramine-direct. This chain is explicitly not hardware evidence.
            local -a sgx_dev=()
            # OUTBE_TEE_SEAL=1 enables the sealed restart fast-path: the enclave
            # seals its DKG-derived offer key + share to a PERSISTENT per-validator
            # dir (survives container restart), so a stop/start restores the offer
            # key from the mock lane's stable test sealing key instead of
            # re-running the ceremony, which is invalid on a non-fresh chain.
            # The production enclave under gramine-direct cannot EGETKEY and was
            # rejected above when OUTBE_TEE_SEAL was requested.
            # The enclave's resident chain id, bound on EVERY launch (independent of
            # sealing): it scopes state-key derivation and the owner-authorized
            # fidelity query, which cross-checks it against the node's chain. Gating
            # it on sealing left a non-sealing enclave at ZERO chain, so those
            # queries failed with "query authorization is for a different chain".
            local tee_chain_hex
            tee_chain_hex=0x$(printf '%064x' "$(python3 -c "import json;print(json.load(open('$OUTPUT_DIR/genesis.json'))['config']['chainId'])")")
            local -a tee_chain_args=(--chain-id "$tee_chain_hex")
            # OUTBE_TEE_SEAL adds the persistent seal dir on top (restart fast-path).
            local -a tee_seal_mount=() tee_seal_args=()
            if [ -n "${OUTBE_TEE_SEAL:-}" ]; then
                local tee_data_dir="$validator_dir/tee"
                mkdir -p "$tee_data_dir"
                tee_seal_mount=(-v "$(readlink -f "$tee_data_dir"):/tee")
                tee_seal_args=(--tee-dir /tee)
            fi
            # Deterministic development-only DKG identity source. A validator
            # count/order change requires a new genesis.
            local -a tee_dkg_arg=(--dkg-seed "$tee_dkg_seed")
            docker rm -f "$tee_ctr" >/dev/null 2>&1 || true
            # Auto-restart only when sealing is on: an auto-restarted enclave
            # WITHOUT a sealed offer key comes back keyless, turning a loud
            # dead-socket failure into a quiet decrypt-failure mode.
            local -a tee_restart_args=()
            if [ -n "${OUTBE_TEE_SEAL:-}" ]; then
                tee_restart_args=(--restart unless-stopped)
            fi
            docker run -d --name "$tee_ctr" \
                --security-opt seccomp=unconfined \
                --network host \
                --log-driver local --log-opt max-size=10m --log-opt max-file=3 \
                "${tee_restart_args[@]}" \
                "${sgx_dev[@]}" \
                "${tee_seal_mount[@]}" \
                -v "$(readlink -f "$tee_enclave_bin"):/app/outbe-tee-enclave:ro" \
                -v "$(readlink -f "$tee_test_signing_key"):/run/secrets/outbe-test-sgx-key.pem:ro" \
                "$tee_gramine_image" \
                --socket "$tee_endpoint" "${tee_dkg_arg[@]}" "${tee_chain_args[@]}" "${tee_seal_args[@]}" >/dev/null
            echo "$tee_ctr" > "$PID_DIR/validator-$i.enclave.docker"
            local tee_up=""
            for _ in $(seq 1 200); do
                (exec 3<>"/dev/tcp/127.0.0.1/$tee_port") 2>/dev/null && { exec 3>&- 2>/dev/null; tee_up=1; break; }
                sleep 0.1
            done
            # Persistent stdout/stderr: follow the container log for the whole
            # run (per-request telemetry lines + restarts land in enclave.log,
            # not just a one-shot boot snapshot).
            docker logs -f "$tee_ctr" > "$validator_dir/enclave.log" 2>&1 &
            echo $! > "$PID_DIR/validator-$i.enclave-log.pid"
            # WS-M2 M6: fail loudly instead of silently proceeding - otherwise the node
            # would later fail-fast on the missing socket with a less obvious cause.
            if [ -z "$tee_up" ]; then
                echo "Error: validator-$i TEE enclave did not open its socket 127.0.0.1:$tee_port within ~20s." >&2
                echo "  The node would fail-fast on the missing socket. Enclave output: $validator_dir/enclave.log" >&2
                docker rm -f "$tee_ctr" >/dev/null 2>&1 || true
                exit 1
            fi
            tee_args+=(--tee-enclave-socket "$tee_endpoint")
        fi

        local -a reth_p2p_args=()
        if [ -n "$bootnodes" ]; then
            reth_p2p_args+=(--bootnodes "$bootnodes")
        fi

        local radicle_pid_file="$PID_DIR/validator-$i.radicle.pid"
        local radicle_exit_file="$PID_DIR/validator-$i.radicle.exit"
        local radicle_log_file="$validator_dir/radicle.log"
        local radicle_home="$validator_dir/radicle"
        if [ -f "$radicle_pid_file" ] && kill -0 "$(cat "$radicle_pid_file")" 2>/dev/null; then
            echo "  Validator $i Radicle already running (PID $(cat "$radicle_pid_file")), reusing"
        else
            rm -f "$radicle_pid_file" "$radicle_exit_file"
            OUTBE_RADICLE_BINARY="$OUTBE_RADICLE_BINARY" \
                nohup "$SCRIPT_DIR/run-supervised.sh" "$radicle_exit_file" \
                "$SCRIPT_DIR/run-radicle.sh" \
                "$radicle_home" \
                "127.0.0.1:$((base_radicle + i))" \
                "127.0.0.1:$((base_radicle_status + i))" \
                "$n" \
                "127.0.0.1:$((base_radicle + i))" \
                > "$radicle_log_file" 2>&1 < /dev/null &
            local radicle_pid=$!
            echo "$radicle_pid" > "$radicle_pid_file"
            local radicle_up=""
            for _ in $(seq 1 100); do
                (exec 3<>"/dev/tcp/127.0.0.1/$((base_radicle_status + i))") 2>/dev/null \
                    && { exec 3>&- 2>/dev/null; radicle_up=1; break; }
                kill -0 "$radicle_pid" 2>/dev/null || break
                sleep 0.1
            done
            if [ -z "$radicle_up" ]; then
                echo "Error: validator-$i Radicle sidecar failed to start; see $radicle_log_file" >&2
                exit 1
            fi
            echo "  Validator $i Radicle started (PID $radicle_pid, log: $radicle_log_file)"
        fi
        if [ -f "$validator_dir/reth-p2p-secret.hex" ]; then
            # Pass the key as a FILE, never inline hex in argv: the command line
            # is world-readable via `ps`. reth parses the file contents without
            # trimming, so normalize it in place once (idempotent).
            local reth_p2p_secret
            reth_p2p_secret="$(tr -d '[:space:]' < "$validator_dir/reth-p2p-secret.hex")"
            printf '%s' "$reth_p2p_secret" > "$validator_dir/reth-p2p-secret.hex"
            reth_p2p_args+=(--p2p-secret-key "$validator_dir/reth-p2p-secret.hex")
        fi

        local -a consensus_material_args=()
        # if [ -f "$validator_dir/signing-share.hex" ] \
        #     && [ -f "$OUTPUT_DIR/polynomial.hex" ] \
        #     && [ -f "$OUTPUT_DIR/dkg-output.hex" ]; then
        #     consensus_material_args+=(
        #         --consensus.signing-share "$validator_dir/signing-share.hex"
        #         --consensus.public-polynomial "$OUTPUT_DIR/polynomial.hex"
        #         --consensus.dkg-output "$OUTPUT_DIR/dkg-output.hex"
        #     )
        # fi

        python3 "$SCRIPT_DIR/offchain_storage.py" ensure "$validator_dir/offchain-storage.toml"
        local -a cmd=(
            "$OUTBE_CHAIN_BINARY" node
            --validator
            --chain "$OUTPUT_DIR/genesis.json"
            --datadir "$validator_dir/data"
            --projection.storage-config "$validator_dir/offchain-storage.toml"
            --engine.persistence-threshold 0
            --engine.memory-block-buffer-target 0
            --http --http.addr 0.0.0.0 --http.port $((base_rpc + i))
            --http.api eth,net,web3,rudis
            --port $((base_p2p + i))
            --discovery.port $((base_p2p + i))
            --discovery.v5.addr 127.0.0.1
            --discovery.v5.port $((base_discv5 + i))
        )
        if [ ${#reth_p2p_args[@]} -gt 0 ]; then
            cmd+=("${reth_p2p_args[@]}")
        fi
        cmd+=(
            --authrpc.port $((base_authrpc + i))
            --ipcpath "$validator_dir/data/reth.ipc"
            --metrics "0.0.0.0:$((base_metrics + i))"
            --log.file.directory "$reth_log_dir"
            --consensus.signing-key "$validator_dir/signing-key.hex"
            --validator.evm-key "$validator_dir/evm-key.hex"
        )
        if [ ${#consensus_material_args[@]} -gt 0 ]; then
            cmd+=("${consensus_material_args[@]}")
        fi
        cmd+=(
            --consensus.listen-addr "127.0.0.1:$((base_consensus + i))"
            --consensus.use-local-defaults
            --radicle.control-socket "$radicle_home/node/outbe-control.sock"
            --radicle.status-address "127.0.0.1:$((base_radicle_status + i))"
        )
        if [ ${#tee_args[@]} -gt 0 ]; then
            cmd+=("${tee_args[@]}")
        fi
        # Debug builds need a larger thread stack: on block 1 the proposer signs
        # the begin-zone system txs, which lazily initializes k256's secp256k1
        # generator lookup table - a huge *unoptimized* stack frame that
        # overflows reth's ~2 MiB tokio blocking-pool thread (`thread '<unknown>'
        # has overflowed its stack`). Release builds optimize the frame away and
        # are unaffected. 16 MiB is ample headroom; operators may override.
        local -a env_args=(
            RUST_MIN_STACK="${RUST_MIN_STACK:-16777216}"
        )
        if [ -n "$OUTBE_TEST_DROP_NEW_PAYLOAD_VALIDATOR" ] \
            && [ -n "$OUTBE_TEST_DROP_NEW_PAYLOAD_HEIGHT" ] \
            && [ "$OUTBE_TEST_DROP_NEW_PAYLOAD_VALIDATOR" = "$i" ]; then
            env_args+=(OUTBE_TEST_DROP_NEW_PAYLOAD_HEIGHT="$OUTBE_TEST_DROP_NEW_PAYLOAD_HEIGHT")
            echo "  Validator $i test hook: drop new_payload at height $OUTBE_TEST_DROP_NEW_PAYLOAD_HEIGHT"
        elif [ -n "$OUTBE_TEST_DROP_NEW_PAYLOAD_HEIGHT" ]; then
            env_args+=(OUTBE_TEST_DROP_NEW_PAYLOAD_HEIGHT=)
        fi

        if [ ${#env_args[@]} -gt 0 ]; then
            nohup "$SCRIPT_DIR/run-supervised.sh" "$exit_file" env "${env_args[@]}" "${cmd[@]}" > "$log_file" 2>&1 < /dev/null &
        else
            nohup "$SCRIPT_DIR/run-supervised.sh" "$exit_file" "${cmd[@]}" > "$log_file" 2>&1 < /dev/null &
        fi

        local pid=$!
        echo "$pid" > "$pid_file"
        echo "  Validator $i started (PID $pid, log: $log_file)"
        launched+=("$i:$pid:$log_file")
    done

    # Verify the launched processes survived startup. Reth fails fast on
    # genesis-hash / DB mismatches and similar configuration errors, and a
    # backgrounded process that exits before we exit makes the launch look
    # successful. Sleep briefly, then re-check each PID.
    if [ ${#launched[@]} -gt 0 ]; then
        sleep 2
        local failed=0
        for entry in "${launched[@]}"; do
            local i="${entry%%:*}"
            local rest="${entry#*:}"
            local pid="${rest%%:*}"
            local log="${rest#*:}"
            if ! kill -0 "$pid" 2>/dev/null; then
                echo "  ERROR: Validator $i (PID $pid) exited during startup."
                echo "  --- Last lines of $log ---"
                tail -n 20 "$log" | sed 's/^/    /'
                echo "  --- end of log tail ---"
                rm -f "$PID_DIR/validator-$i.pid"
                failed=$((failed + 1))
            fi
        done
        if [ "$failed" -gt 0 ]; then
            echo "Error: $failed validator(s) failed to start. See logs above."
            exit 1
        fi
    fi

    echo "All validators launched. Use '$0 status $OUTPUT_DIR' to check."
}

do_stop() {
    if [ ! -d "$PID_DIR" ]; then
        echo "No PID directory found at $PID_DIR - nothing to stop."
        exit 0
    fi

    # Graceful shutdown: SIGTERM every node, then WAIT for each to exit before
    # tearing down enclaves/locks. A node must flush its execution AND consensus
    # (marshal) stores atomically on shutdown; killing it (or yanking its enclave)
    # mid-flush leaves execution one block ahead of consensus, which fails the next
    # restart with "marshal finalization missing for finalized execution height N".
    local -a stopping_pids=() stopping_names=()
    for pid_file in "$PID_DIR"/validator-*.pid; do
        [ -f "$pid_file" ] || continue
        local name pid
        name=$(basename "$pid_file" .pid)
        pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null
            stopping_pids+=("$pid")
            stopping_names+=("$name")
            echo "  Stopping $name (PID $pid) - waiting for clean shutdown..."
        else
            echo "  $name (PID $pid) already dead"
        fi
        rm -f "$pid_file"
    done
    # Wait up to ~60s per node for a clean exit; SIGKILL only as a last resort.
    local idx
    for idx in "${!stopping_pids[@]}"; do
        local pid="${stopping_pids[$idx]}" name="${stopping_names[$idx]}"
        local waited=0
        while kill -0 "$pid" 2>/dev/null && [ "$waited" -lt 600 ]; do
            sleep 0.1
            waited=$((waited + 1))
        done
        if kill -0 "$pid" 2>/dev/null; then
            echo "  $name did not exit in 60s - SIGKILL (restart may need resync)"
            # $pid is the run-supervised.sh wrapper; SIGKILL cannot be forwarded
            # to its node child, which would orphan a still-running reth process
            # holding the MDBX/static_files locks and fail the next restart with
            # "storage directory in use". Kill the child first, then the wrapper.
            pkill -KILL -P "$pid" 2>/dev/null || true
            kill -KILL "$pid" 2>/dev/null
        else
            echo "  Stopped $name"
        fi
    done

    for pid_file in "$PID_DIR"/validator-*.radicle.pid; do
        [ -e "$pid_file" ] || continue
        local pid name
        pid="$(cat "$pid_file")"
        name="$(basename "$pid_file" .pid)"
        if kill -0 "$pid" 2>/dev/null; then
            echo "  Stopping $name (PID $pid)..."
            kill "$pid" 2>/dev/null || true
            for _ in $(seq 1 150); do
                kill -0 "$pid" 2>/dev/null || break
                sleep 0.1
            done
            kill -9 "$pid" 2>/dev/null || true
        fi
        rm -f "$pid_file"
    done

    # Stop any gramine-direct enclave containers (OUTBE_TEE_GRAMINE=1) - AFTER the
    # nodes have exited, so a node is never mid-request to an enclave being removed.
    # Kill the enclave-log followers FIRST so no follower blocks on a removed
    # container's log stream.
    for lfile in "$PID_DIR"/validator-*.enclave-log.pid; do
        [ -f "$lfile" ] || continue
        local lpid
        lpid=$(cat "$lfile")
        kill "$lpid" 2>/dev/null || true
        rm -f "$lfile"
    done
    for dfile in "$PID_DIR"/validator-*.enclave.docker; do
        [ -f "$dfile" ] || continue
        local ctr
        ctr=$(cat "$dfile")
        docker rm -f "$ctr" >/dev/null 2>&1 && echo "  Stopped enclave container $ctr"
        rm -f "$dfile"
    done

    # Clean stale lock files (both the MDBX `db/lock` and reth's
    # `static_files/lock`) so a fast restart does not hit "storage directory in
    # use" if a node was SIGKILLed without releasing them.
    for lock in "$OUTPUT_DIR"/validator-*/data/db/lock \
        "$OUTPUT_DIR"/validator-*/data/static_files/lock; do
        [ -f "$lock" ] && rm -f "$lock"
    done

    echo "All validators stopped."
}

do_status() {
    if [ ! -d "$PID_DIR" ]; then
        echo "No PID directory found - testnet not started."
        exit 0
    fi

    for pid_file in "$PID_DIR"/validator-*.pid; do
        [ -f "$pid_file" ] || continue
        local name
        name=$(basename "$pid_file" .pid)
        local pid
        pid=$(cat "$pid_file")

        if kill -0 "$pid" 2>/dev/null; then
            echo "  $name: running (PID $pid)"
        else
            echo "  $name: dead (PID $pid)"
        fi
    done
}

# --- Main ---

case "$ACTION" in
    start)  do_start ;;
    stop)   do_stop ;;
    status) do_status ;;
    *)
        echo "Unknown action: $ACTION"
        echo "Usage: $0 <start|stop|status> <output_dir>"
        exit 1
        ;;
esac
