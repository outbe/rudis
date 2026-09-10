#!/usr/bin/env bash
# Internal half of reproducible-build.sh. This script is only run inside the
# pinned builder image at the fixed /workspace path.
set -euo pipefail

readonly SPEC=/workspace/release/reproducible-elf-build-v1.json
readonly TARGET=x86_64-unknown-linux-gnu
readonly PROFILE=release
readonly OUT=/out
# The builder image ships the exact-pinned Intel DCAP stack; refuse to produce
# release ELFs whose native QVL silently fell back to the fail-closed stub.
export OUTBE_NATIVE_DCAP=require

for required in SOURCE_COMMIT SOURCE_DATE_EPOCH SOURCE_DESCRIBE RELEASE_TAG; do
  if [[ -z "${!required:-}" ]]; then
    echo "missing required build identity: ${required}" >&2
    exit 2
  fi
done

mapfile -t artifact_rows < <(
  python3 - "${SPEC}" <<'PY'
import json
import sys

spec = json.load(open(sys.argv[1], encoding="utf-8"))
if spec["target"] != "x86_64-unknown-linux-gnu" or spec["profile"] != "release":
    raise SystemExit("unsupported target/profile in reproducible build spec")
for artifact in spec["artifacts"]:
    print(f'{artifact["package"]}\t{artifact["name"]}')
PY
)

python3 scripts/release/reproducible_build_inputs.py \
  --build-spec "${SPEC}" \
  --repo-root /workspace \
  --execute-artifact-build-plan

install -d -m 0755 "${OUT}/bin" "${OUT}/metadata"
for row in "${artifact_rows[@]}"; do
  name="${row#*$'\t'}"
  install -m 0755 "target/${TARGET}/${PROFILE}/${name}" "${OUT}/bin/${name}"
done

"${OUT}/bin/outbe-chain" --version > "${OUT}/metadata/outbe-chain.version.txt"
python3 scripts/release/verify_outbe_chain_version.py \
  --version-file "${OUT}/metadata/outbe-chain.version.txt" \
  --source-commit "${SOURCE_COMMIT}" \
  --source-date-epoch "${SOURCE_DATE_EPOCH}" \
  --target "${TARGET}" \
  --profile "${PROFILE}"

dpkg-query -W -f='${binary:Package}=${Version}\n' \
  | LC_ALL=C sort \
  > "${OUT}/metadata/builder-system-packages.txt"

python3 scripts/release/generate_release_manifest.py \
  --build-spec "${SPEC}" \
  --source-root /workspace \
  --artifact-dir "${OUT}/bin" \
  --release-tag "${RELEASE_TAG}" \
  --source-commit "${SOURCE_COMMIT}" \
  --source-date-epoch "${SOURCE_DATE_EPOCH}" \
  --lifecycle build-candidate \
  --verification-gates /workspace/release/reproducible-elf-candidate-gates-v1.json \
  --resolved-system-packages "${OUT}/metadata/builder-system-packages.txt" \
  --output "${OUT}/release-manifest.json"

cp /workspace/release/release-manifest-v1.schema.json \
  "${OUT}/metadata/release-manifest-v1.schema.json"
cp "${SPEC}" "${OUT}/metadata/reproducible-elf-build-v1.json"

(
  cd "${OUT}"
  sha256sum \
    bin/* \
    metadata/builder-system-packages.txt \
    metadata/outbe-chain.version.txt \
    metadata/release-manifest-v1.schema.json \
    metadata/reproducible-elf-build-v1.json \
    release-manifest.json \
    | LC_ALL=C sort -k2
) > "${OUT}/SHA256SUMS"
