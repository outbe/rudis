#!/usr/bin/env bash
# Start one operator-owned Outbe Radicle sidecar in the foreground.

set -euo pipefail
umask 077

usage() {
    echo "Usage: $0 <rad-home> <listen> <status-listen> <max-validators> <advertise> [advertise ...]" >&2
    exit 2
}

[ "$#" -ge 5 ] || usage

RADICLE_HOME=$1
RADICLE_LISTEN=$2
RADICLE_STATUS_LISTEN=$3
RADICLE_MAX_VALIDATORS=$4
shift 4

RADICLE_BINARY=${OUTBE_RADICLE_BINARY:-./target/release/outbe-radicle}
RADICLE_CONTROL_SOCKET=${OUTBE_RADICLE_CONTROL_SOCKET:-$RADICLE_HOME/node/outbe-control.sock}
RADICLE_EXTERNAL_INBOUND_RESERVE=${OUTBE_RADICLE_EXTERNAL_INBOUND_RESERVE:-16}

if [ ! -x "$RADICLE_BINARY" ]; then
    echo "Error: release outbe-radicle binary is not executable: $RADICLE_BINARY" >&2
    exit 1
fi
if [ ! -d "$RADICLE_HOME" ] || [ -L "$RADICLE_HOME" ]; then
    echo "Error: Radicle home must be an existing non-symlink directory: $RADICLE_HOME" >&2
    exit 1
fi
if [ ! -d "$RADICLE_HOME/keys" ] || [ -L "$RADICLE_HOME/keys" ]; then
    echo "Error: Radicle keys must be an existing non-symlink directory: $RADICLE_HOME/keys" >&2
    exit 1
fi
if [ ! -f "$RADICLE_HOME/keys/radicle" ] || [ -L "$RADICLE_HOME/keys/radicle" ]; then
    echo "Error: generate the Radicle key first with outbe-keygen radicle --output-dir $RADICLE_HOME" >&2
    exit 1
fi
if [ ! -f "$RADICLE_HOME/keys/radicle.pub" ] || [ -L "$RADICLE_HOME/keys/radicle.pub" ]; then
    echo "Error: missing Heartwood public key: $RADICLE_HOME/keys/radicle.pub" >&2
    exit 1
fi

RADICLE_OWNER_UID=$(id -u)

# GNU stat spells this `-c '%u %a'`; BSD stat (macOS) spells it `-f '%u %Lp'`.
# Pick the dialect once instead of assuming the GNU one.
if stat -f '%u' . >/dev/null 2>&1; then
    stat_owner_and_mode() { stat -f '%u %Lp' "$1"; }
else
    stat_owner_and_mode() { stat -c '%u %a' "$1"; }
fi

require_owned_directory() {
    local path=$1
    local mode=$2
    if [ ! -d "$path" ] || [ -L "$path" ]; then
        echo "Error: expected non-symlink directory: $path" >&2
        exit 1
    fi
    read -r actual_uid actual_mode <<EOF
$(stat_owner_and_mode "$path")
EOF
    if [ "$actual_uid" != "$RADICLE_OWNER_UID" ] || [ "$actual_mode" != "$mode" ]; then
        echo "Error: $path must be owned by uid $RADICLE_OWNER_UID with mode $mode" >&2
        exit 1
    fi
}

require_owned_file() {
    local path=$1
    local mode=$2
    if [ ! -f "$path" ] || [ -L "$path" ]; then
        echo "Error: expected non-symlink regular file: $path" >&2
        exit 1
    fi
    read -r actual_uid actual_mode <<EOF
$(stat_owner_and_mode "$path")
EOF
    if [ "$actual_uid" != "$RADICLE_OWNER_UID" ] || [ "$actual_mode" != "$mode" ]; then
        echo "Error: $path must be owned by uid $RADICLE_OWNER_UID with mode $mode" >&2
        exit 1
    fi
}

require_owned_directory "$RADICLE_HOME" 700
require_owned_directory "$RADICLE_HOME/keys" 700
require_owned_file "$RADICLE_HOME/keys/radicle" 600
if [ "$(stat_owner_and_mode "$RADICLE_HOME/keys/radicle.pub" | cut -d' ' -f1)" != "$RADICLE_OWNER_UID" ]; then
    echo "Error: $RADICLE_HOME/keys/radicle.pub must be owned by uid $RADICLE_OWNER_UID" >&2
    exit 1
fi
# The public key is non-secret and older keygen versions inherited a group-write
# bit. Normalize it only after exclusive ownership; the private key remains
# strict and is never rewritten.
chmod 644 "$RADICLE_HOME/keys/radicle.pub"

for directory in storage node cobs; do
    path=$RADICLE_HOME/$directory
    if [ -e "$path" ] || [ -L "$path" ]; then
        require_owned_directory "$path" 700
    else
        mkdir -m 700 -- "$path"
    fi
done

# No config.json is written here. The sidecar builds its own runtime config
# from these command-line options (`Options::node_config` in the fork) and
# never reads config.json, so a second copy of those settings could only drift
# out of sync - and the `network: outbe` it used to write makes a stock `rad`
# refuse to start, since upstream accepts only `main` or `test`.
# A client that needs config.json gets it from `outbe-cli rad init`.

if [ -e "$RADICLE_CONTROL_SOCKET" ]; then
    if [ ! -S "$RADICLE_CONTROL_SOCKET" ]; then
        echo "Error: control socket path exists and is not a Unix socket: $RADICLE_CONTROL_SOCKET" >&2
        exit 1
    fi
    if RADICLE_CONTROL_SOCKET="$RADICLE_CONTROL_SOCKET" python3 -c '
import os
import socket

client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.settimeout(1.0)
client.connect(os.environ["RADICLE_CONTROL_SOCKET"])
' >/dev/null 2>&1; then
        echo "Error: a live sidecar already owns $RADICLE_CONTROL_SOCKET" >&2
        exit 1
    fi
    rm -f "$RADICLE_CONTROL_SOCKET"
fi

args=(
    --home "$RADICLE_HOME"
    --control-socket "$RADICLE_CONTROL_SOCKET"
    --listen "$RADICLE_LISTEN"
    --status-listen "$RADICLE_STATUS_LISTEN"
    --max-validators "$RADICLE_MAX_VALIDATORS"
    --external-inbound-reserve "$RADICLE_EXTERNAL_INBOUND_RESERVE"
)
for address in "$@"; do
    args+=(--advertise "$address")
done

exec "$RADICLE_BINARY" "${args[@]}"
