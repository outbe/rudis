#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
vendor_dir="$repo_root/crates/core/compressed-entities/vendor/sparse-merkle-tree"
cd "$vendor_dir"

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum --check UPSTREAM.sha256
  sha256sum --check VENDORED.sha256
else
  shasum -a 256 --check UPSTREAM.sha256
  shasum -a 256 --check VENDORED.sha256
fi

actual_diff="$(mktemp)"
trap 'rm -f "$actual_diff"' EXIT
for file in \
  Cargo.toml \
  src/error.rs \
  src/h256.rs \
  src/lib.rs \
  src/merge.rs \
  src/merkle_proof.rs \
  src/traits.rs \
  src/tree.rs
do
  diff -U0 \
    --label "pristine/$file" \
    --label "production/$file" \
    "../sparse-merkle-tree-pristine/$file" \
    "$file" >> "$actual_diff" || status=$?
  if [[ ${status:-0} -gt 1 ]]; then
    echo "failed to compare vendored source $file" >&2
    exit 1
  fi
  unset status
done

if ! cmp -s ALLOWLIST.patch "$actual_diff"; then
  echo "vendored production SMT differs from the mechanically enforced allowlist" >&2
  diff -u ALLOWLIST.patch "$actual_diff" || true
  exit 1
fi

forbidden='panic![[:space:]]*\(|unreachable![[:space:]]*\(|\.unwrap[[:space:]]*\(|\.expect[[:space:]]*\(|debug_assert![[:space:]]*\(|assert_eq![[:space:]]*\(|assert![[:space:]]*\(|unsafe[[:space:]]+(fn|impl|trait|extern)|unsafe[[:space:]]*\{'
if grep -ERn "$forbidden" src; then
  echo "vendored production SMT contains a forbidden panic/unsafe construct" >&2
  exit 1
fi
