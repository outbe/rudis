#!/usr/bin/env bash
# Hardware-free checks for the pinned Intel QVL integration.
set -euo pipefail

task_script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
task_repo_root="$(cd -- "${task_script_dir}/../.." && pwd)"
cd "${task_repo_root}"

if [[ "$(uname -m)" != "x86_64" ]]; then
  echo "DCAP replay supports only x86_64" >&2
  exit 1
fi

# This lane exists to exercise the real pinned QVL: a missing Intel stack must
# fail the job, not silently downgrade to the fail-closed stub.
export OUTBE_NATIVE_DCAP=require

python3 scripts/release/tests/test_dcap_native_qvl.py
python3 scripts/release/verify_dcap_native_qvl.py

# Consensus-facing evidence caps, pre-allocation ordering and checked gas
# arithmetic live behind an explicit primitives feature and must not compile
# as an empty integration-test target.
cargo test --locked --offline -p outbe-primitives \
  --features tee-attestation-v1 --test tee_attestation_v1

# Exercise the remaining verifier tests and compile-time Intel ABI checks.
cargo test --locked --offline -p outbe-tee --features native-dcap
cargo test --locked --offline \
  -p outbe-tee \
  --features dcap-fixture-tool \
  --test dcap_fixture_tool
