#!/usr/bin/env bash
# Single public entrypoint for the deterministic Linux x86_64 ELF build.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/release/reproducible-build.sh --output DIR [options]

Options:
  --release-tag TAG  Immutable release identity (default: commit-<full-sha>).
  --no-cache         Disable Docker build cache (required for rebuild evidence).
  --help             Show this help.

The source checkout must be clean. DIR must be outside the source checkout and
must not contain prior output. Only Linux x86_64 is supported by recipe v1.
EOF
}

output_dir=""
release_tag=""
no_cache=0
while (($#)); do
  case "$1" in
    --output)
      [[ $# -ge 2 ]] || { echo "--output requires a value" >&2; exit 2; }
      output_dir="$2"
      shift 2
      ;;
    --release-tag)
      [[ $# -ge 2 ]] || { echo "--release-tag requires a value" >&2; exit 2; }
      release_tag="$2"
      shift 2
      ;;
    --no-cache)
      no_cache=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "unsupported argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

[[ -n "${output_dir}" ]] || { echo "--output is required" >&2; exit 2; }

for command in docker git mktemp python3 sha256sum tar; do
  command -v "${command}" >/dev/null || { echo "required command not found: ${command}" >&2; exit 2; }
done

repo_root="$(git rev-parse --show-toplevel)"
cd "${repo_root}"

if [[ -n "$(git status --porcelain=v1 --untracked-files=all)" ]]; then
  echo "reproducible release builds require a clean source tree" >&2
  git status --short >&2
  exit 2
fi

output_dir="$(python3 - "${output_dir}" "${repo_root}" <<'PY'
import pathlib
import sys

output = pathlib.Path(sys.argv[1]).expanduser().resolve()
root = pathlib.Path(sys.argv[2]).resolve()
try:
    output.relative_to(root)
except ValueError:
    print(output)
else:
    raise SystemExit("output directory must be outside the source checkout")
PY
)"

if [[ -e "${output_dir}" && -n "$(ls -A "${output_dir}")" ]]; then
  echo "output directory must be empty: ${output_dir}" >&2
  exit 2
fi
mkdir -p "${output_dir}"

readonly spec=release/reproducible-elf-build-v1.json
input_args=(--build-spec "${spec}" --repo-root "${repo_root}")
if [[ -n "${release_tag}" ]]; then
  input_args+=(--release-tag "${release_tag}")
fi
build_values_output="$(
  python3 scripts/release/reproducible_build_inputs.py "${input_args[@]}"
)"
mapfile -t build_values <<<"${build_values_output}"
if ((${#build_values[@]} != 7)); then
  echo "validated build input resolver returned an incomplete contract" >&2
  exit 2
fi

rustflags="${build_values[0]}"
cflags="${build_values[1]}"
cxxflags="${build_values[2]}"
source_commit="${build_values[3]}"
source_date_epoch="${build_values[4]}"
release_tag="${build_values[5]}"
source_describe="${build_values[6]}"

printf 'Reproducible ELF build inputs\n'
printf '  source_commit      = %s\n' "${source_commit}"
printf '  release_tag        = %s\n' "${release_tag}"
printf '  SOURCE_DATE_EPOCH  = %s\n' "${source_date_epoch}"
printf '  source_describe    = %s\n' "${source_describe}"
printf '  target             = x86_64-unknown-linux-gnu\n'
printf '  profile            = release\n'
printf '  builder_recipe     = Dockerfile.project-toolchain\n'
printf '  output_dir         = %s\n' "${output_dir}"

build_context="$(mktemp -d -t outbe-reproducible-source.XXXXXXXX)"
cleanup() {
  rm -rf "${build_context}"
}
trap cleanup EXIT
git archive --format=tar HEAD | tar -xf - -C "${build_context}"

docker_args=(
  build
  --platform linux/amd64
  --file "${build_context}/Dockerfile.project-toolchain"
  --target artifacts
  --build-arg "SOURCE_COMMIT=${source_commit}"
  --build-arg "SOURCE_DATE_EPOCH=${source_date_epoch}"
  --build-arg "SOURCE_DESCRIBE=${source_describe}"
  --build-arg "RELEASE_TAG=${release_tag}"
  --build-arg "REPRODUCIBLE_RUSTFLAGS=${rustflags}"
  --build-arg "REPRODUCIBLE_CFLAGS=${cflags}"
  --build-arg "REPRODUCIBLE_CXXFLAGS=${cxxflags}"
  --output "type=local,dest=${output_dir}"
)
if ((no_cache)); then
  docker_args+=(--no-cache)
fi
docker_args+=("${build_context}")

docker "${docker_args[@]}"
(
  cd "${output_dir}"
  sha256sum --check SHA256SUMS
)
printf 'Reproducible ELF candidate written to %s\n' "${output_dir}"
