#!/usr/bin/env bash
# Run a command, forward termination to it, and write its exit status.

set -euo pipefail

EXIT_FILE="${1:?Usage: $0 <exit_file> <command> [args...]}"
shift

rm -f "$EXIT_FILE"

"$@" &
child_pid=$!

terminate_child() {
    if kill -0 "$child_pid" 2>/dev/null; then
        kill "$child_pid" 2>/dev/null || true
    fi
}

trap terminate_child TERM INT

set +e
wait "$child_pid"
status=$?
set -e

printf '%s\n' "$status" > "$EXIT_FILE"
exit "$status"
