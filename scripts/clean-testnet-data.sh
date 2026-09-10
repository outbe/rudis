#!/usr/bin/env bash
# Remove all validator-*/ subdirectories and the pids/ directory under OUTPUT_DIR.
#
# Usage:
#   ./scripts/clean-testnet-data.sh <OUTPUT_DIR>
#
# Example:
#   ./scripts/clean-testnet-data.sh /tmp/outbe-testnet
#
# Safe to run when OUTPUT_DIR does not exist or contains no validator data.

set -euo pipefail

OUTPUT_DIR="${1:?Usage: $0 <output_dir>}"

if [ -d "$OUTPUT_DIR" ]; then
    shopt -s nullglob
    stale=("$OUTPUT_DIR"/validator-*)
    if [ ${#stale[@]} -gt 0 ]; then
        echo "--- Reset stale validator state ---"
        for d in "${stale[@]}"; do
            echo "  Removing $d"
            rm -rf "$d"
        done
        rm -rf "$OUTPUT_DIR/pids"
        echo
    else
        echo "No validator-* directories found in $OUTPUT_DIR - nothing to clean."
    fi
    shopt -u nullglob
else
    echo "$OUTPUT_DIR does not exist - nothing to clean."
fi
