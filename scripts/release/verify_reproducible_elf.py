#!/usr/bin/env python3
"""Compare two clean Outbe ELF build outputs and save canonical evidence."""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import importlib.util
import json
import subprocess
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator


EXPECTED_ARTIFACTS = (
    "outbe-chain",
    "outbe-cli",
    "outbe-keygen",
    "outbe-feeder",
    "outbe-tee-enclave",
    "outbe-ocomp",
)
FORBIDDEN_PATHS = (b"/workspace", b"/usr/local/cargo", b"/usr/local/rustup")
# Deliberately independent of the manifest generator's copy: the second-builder
# verifier must still reject a marker if generation was bypassed or regressed.
PRODUCTION_TEE_FORBIDDEN_MARKERS = (
    b"outbe-tee-enclave-mock: MOCK ENCLAVE",
    b"outbe-dcap-capture-enclave",
    b"OUTBE_QVL_TEST_TRACE",
    b"OUTBE_QVL_BEGIN",
    b"OUTBE_QVL_END",
    b"explicit development seed",
    b"development offer-secret fallback",
)
EXPECTED_CHECKSUM_PATHS = frozenset(
    [*(f"bin/{name}" for name in EXPECTED_ARTIFACTS)]
    + [
        "metadata/builder-system-packages.txt",
        "metadata/outbe-chain.version.txt",
        "metadata/release-manifest-v1.schema.json",
        "metadata/reproducible-elf-build-v1.json",
        "release-manifest.json",
    ]
)
PINNED_VERIFIER_DISTRIBUTIONS = {
    "attrs": "23.2.0",
    "jsonschema": "4.10.3",
    "pyrsistent": "0.20.0",
}


def _load_version_verifier():
    path = Path(__file__).with_name("verify_outbe_chain_version.py")
    spec = importlib.util.spec_from_file_location("outbe_chain_version_verifier", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load version verifier: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


version_verifier = _load_version_verifier()


def _canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_material_path(root: Path, relative: str) -> Path | None:
    candidate = Path(relative)
    if candidate.is_absolute():
        return None
    resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(root.resolve())
    except ValueError:
        return None
    return resolved


def _verify_material(
    root: Path,
    record: dict[str, Any],
    label: str,
    differences: list[str],
) -> None:
    relative = record.get("path", "")
    path = _safe_material_path(root, relative)
    if path is None or not path.is_file() or path.is_symlink():
        differences.append(f"{label}: missing or unsafe material path: {relative}")
        return
    raw = path.read_bytes()
    if record.get("size") != len(raw):
        differences.append(f"{label}: material size mismatch: {relative}")
    if record.get("digest", {}).get("value") != _sha256(raw):
        differences.append(f"{label}: material digest mismatch: {relative}")


def _verify_checksum_file(output: Path, label: str, differences: list[str]) -> bytes:
    checksum_path = output / "SHA256SUMS"
    if not checksum_path.is_file() or checksum_path.is_symlink():
        differences.append(f"{label}: missing regular SHA256SUMS")
        return b""
    raw = checksum_path.read_bytes()
    declared: dict[str, str] = {}
    try:
        for line in raw.decode("ascii").splitlines():
            digest, relative = line.split("  ", 1)
            if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
                raise ValueError(f"invalid digest for {relative}")
            if relative in declared:
                raise ValueError(f"duplicate path: {relative}")
            declared[relative] = digest
    except (UnicodeDecodeError, ValueError) as error:
        differences.append(f"{label}: invalid SHA256SUMS: {error}")
        return raw

    if frozenset(declared) != EXPECTED_CHECKSUM_PATHS:
        differences.append(f"{label}: SHA256SUMS does not declare the exact output matrix")
    for relative, expected in declared.items():
        path = _safe_material_path(output, relative)
        if path is None or not path.is_file() or path.is_symlink():
            differences.append(f"{label}: checksum path missing or unsafe: {relative}")
            continue
        if _sha256(path.read_bytes()) != expected:
            differences.append(f"{label}: checksum mismatch: {relative}")
    return raw


def _verify_environment(differences: list[str]) -> None:
    for distribution, expected in PINNED_VERIFIER_DISTRIBUTIONS.items():
        try:
            actual = importlib.metadata.version(distribution)
        except importlib.metadata.PackageNotFoundError:
            differences.append(f"verifier environment: missing {distribution}=={expected}")
            continue
        if actual != expected:
            differences.append(
                f"verifier environment: expected {distribution}=={expected}, found {actual}"
            )


def _read_manifest(
    output: Path,
    schema: dict[str, Any],
    label: str,
    differences: list[str],
) -> tuple[dict[str, Any] | None, bytes]:
    path = output / "release-manifest.json"
    if not path.is_file():
        differences.append(f"{label}: missing release-manifest.json")
        return None, b""
    raw = path.read_bytes()
    try:
        manifest = json.loads(raw)
        Draft202012Validator(schema).validate(manifest)
        if raw != _canonical_json(manifest):
            differences.append(f"{label}: release manifest is not canonical outbe JSON v1")
        return manifest, raw
    except Exception as error:  # json/parser/schema diagnostics belong in evidence.
        differences.append(f"{label}: invalid release manifest: {error}")
        return None, raw


def _manifest_artifacts(manifest: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    if manifest is None:
        return {}
    return {artifact["name"]: artifact for artifact in manifest.get("artifacts", [])}


def verify_outputs(
    first: Path,
    second: Path,
    repo_root: Path,
    *,
    check_git_identity: bool = False,
) -> dict[str, Any]:
    """Return evidence with every mismatch; never stop after the first one."""

    first = first.resolve()
    second = second.resolve()
    repo_root = repo_root.resolve()
    differences: list[str] = []
    _verify_environment(differences)

    schema = json.loads(
        (repo_root / "release/release-manifest-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator.check_schema(schema)
    first_manifest, first_manifest_raw = _read_manifest(first, schema, "builder-a", differences)
    second_manifest, second_manifest_raw = _read_manifest(second, schema, "builder-b", differences)

    if first_manifest_raw != second_manifest_raw:
        differences.append("release-manifest.json differs between builders")

    first_records = _manifest_artifacts(first_manifest)
    second_records = _manifest_artifacts(second_manifest)
    if tuple(first_records) != EXPECTED_ARTIFACTS:
        differences.append(
            "builder-a manifest does not declare the exact production ELF release matrix"
        )
    if tuple(second_records) != EXPECTED_ARTIFACTS:
        differences.append(
            "builder-b manifest does not declare the exact production ELF release matrix"
        )

    for label, output, manifest in (
        ("builder-a", first, first_manifest),
        ("builder-b", second, second_manifest),
    ):
        if manifest is None:
            continue
        for record in manifest.get("inputs", []):
            _verify_material(repo_root, record, f"{label} source input", differences)
        packages = manifest.get("build", {}).get("builder", {}).get(
            "resolved_system_packages"
        )
        if packages is None:
            differences.append(f"{label}: missing resolved system package material")
        else:
            _verify_material(output, packages, f"{label} package inventory", differences)

    checksum_values = [
        _verify_checksum_file(first, "builder-a", differences),
        _verify_checksum_file(second, "builder-b", differences),
    ]
    if checksum_values[0] != checksum_values[1]:
        differences.append("SHA256SUMS differs between builders")

    version_values: list[bytes] = []
    for label, output, manifest in (
        ("builder-a", first, first_manifest),
        ("builder-b", second, second_manifest),
    ):
        path = output / "metadata/outbe-chain.version.txt"
        if not path.is_file() or path.is_symlink():
            differences.append(f"{label}: missing regular outbe-chain version evidence")
            version_values.append(b"")
            continue
        raw = path.read_bytes()
        version_values.append(raw)
        if manifest is not None:
            try:
                version_differences = version_verifier.verify_version_text(
                    raw.decode("utf-8"),
                    source_commit=manifest["release"]["source"]["commit"],
                    source_date_epoch=manifest["build"]["source_date_epoch"],
                    target=manifest["build"]["target"],
                    profile=manifest["build"]["profile"],
                )
            except UnicodeDecodeError:
                differences.append(f"{label}: version evidence is not UTF-8")
            else:
                differences.extend(
                    f"{label}: version identity mismatch: {difference}"
                    for difference in version_differences
                )
    if version_values[0] != version_values[1]:
        differences.append("outbe-chain version evidence differs between builders")

    artifact_evidence = []
    for name in EXPECTED_ARTIFACTS:
        paths = (first / "bin" / name, second / "bin" / name)
        raw_values: list[bytes] = []
        hashes: list[str | None] = []
        sizes: list[int | None] = []
        for label, path in zip(("builder-a", "builder-b"), paths, strict=True):
            if not path.is_file() or path.is_symlink():
                differences.append(f"{label}: missing regular ELF: {name}")
                raw_values.append(b"")
                hashes.append(None)
                sizes.append(None)
                continue
            raw = path.read_bytes()
            raw_values.append(raw)
            hashes.append(_sha256(raw))
            sizes.append(len(raw))
            if not raw.startswith(b"\x7fELF"):
                differences.append(f"{label}: {name} is not an ELF file")
            for forbidden in FORBIDDEN_PATHS:
                if forbidden in raw:
                    differences.append(
                        f"{label}: forbidden absolute build path in {name}: {forbidden.decode()}"
                    )
            if name == "outbe-tee-enclave":
                for marker in PRODUCTION_TEE_FORBIDDEN_MARKERS:
                    if marker in raw:
                        differences.append(
                            f"{label}: forbidden production TEE marker: {marker.decode('ascii')}"
                        )

            record = (first_records if label == "builder-a" else second_records).get(name)
            if record is not None:
                recorded_hash = record.get("digest", {}).get("value")
                if recorded_hash != hashes[-1]:
                    differences.append(f"{label}: manifest digest mismatch for {name}")
                if record.get("size") != sizes[-1]:
                    differences.append(f"{label}: manifest size mismatch for {name}")

        if raw_values[0] != raw_values[1]:
            differences.append(f"ELF bytes differ between builders: {name}")
        artifact_evidence.append(
            {
                "builder_a_sha256": hashes[0],
                "builder_b_sha256": hashes[1],
                "byte_identical": raw_values[0] == raw_values[1],
                "name": name,
                "size": sizes[0] if sizes[0] == sizes[1] else None,
            }
        )

    identity: dict[str, Any] = {}
    if first_manifest is not None:
        identity = {
            "release_tag": first_manifest["release"]["tag"],
            "source_commit": first_manifest["release"]["source"]["commit"],
            "source_date_epoch": first_manifest["build"]["source_date_epoch"],
            "target": first_manifest["build"]["target"],
            "profile": first_manifest["build"]["profile"],
            "builder_base_images": first_manifest["build"]["builder"]["base_images"],
            "builder_recipe": first_manifest["build"]["builder"]["recipe"],
        }
        if check_git_identity:
            try:
                head = subprocess.run(
                    ["git", "-C", str(repo_root), "rev-parse", "--verify", "HEAD^{commit}"],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip()
                status = subprocess.run(
                    ["git", "-C", str(repo_root), "status", "--porcelain=v1", "--untracked-files=all"],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout
            except subprocess.CalledProcessError as error:
                differences.append(f"source identity check failed: {error}")
            else:
                if head != identity["source_commit"]:
                    differences.append(
                        f"source checkout HEAD {head} does not match manifest {identity['source_commit']}"
                    )
                if status:
                    differences.append("source checkout is dirty during independent verification")

    return {
        "artifacts": artifact_evidence,
        "build_identity": identity,
        "checks": [
            "manifest-schema-draft-2020-12",
            "manifest-canonical-bytes",
            "exact-production-elf-matrix",
            "per-artifact-manifest-digest-and-size",
            "source-input-manifest-digest-and-size",
            "resolved-package-inventory-digest-and-size",
            "exact-output-checksum-matrix",
            "elf-magic",
            "forbidden-absolute-build-paths",
            "forbidden-production-tee-markers",
            "pinned-verifier-environment",
            "outbe-chain-version-identity",
            "byte-for-byte-two-builder-comparison",
        ],
        "differences": differences,
        "manifest": {
            "builder_a_sha256": _sha256(first_manifest_raw) if first_manifest_raw else None,
            "builder_b_sha256": _sha256(second_manifest_raw) if second_manifest_raw else None,
            "byte_identical": first_manifest_raw == second_manifest_raw,
        },
        "output_checksums": {
            "builder_a_sha256": _sha256(checksum_values[0]) if checksum_values[0] else None,
            "builder_b_sha256": _sha256(checksum_values[1]) if checksum_values[1] else None,
            "byte_identical": checksum_values[0] == checksum_values[1],
        },
        "result": "passed" if not differences else "failed",
        "schema_version": "1.0.0",
        "verifier": {
            "requirements_sha256": _sha256(
                (repo_root / "release/reproducible-verifier-requirements.txt").read_bytes()
            ),
            "script_sha256": _sha256(Path(__file__).read_bytes()),
        },
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--first", required=True, type=Path)
    parser.add_argument("--second", required=True, type=Path)
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    evidence = verify_outputs(
        args.first,
        args.second,
        args.repo_root,
        check_git_identity=True,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(_canonical_json(evidence))
    print(f"reproducibility result: {evidence['result']}")
    for difference in evidence["differences"]:
        print(f"difference: {difference}")
    if evidence["result"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
