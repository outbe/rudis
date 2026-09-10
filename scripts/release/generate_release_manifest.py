#!/usr/bin/env python3
"""Generate the canonical v1 Outbe ReleaseManifest for reproducible ELF builds.

The generator deliberately uses only the Python standard library so the pinned
builder does not acquire a second package-manager dependency.  The v1 format
contains integers only (no JSON floating-point values), sorts object keys by
Unicode code point, emits the most compact RFC 8259 representation, escapes all
non-ASCII code points, and terminates the document with one LF byte.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
PINNED_IMAGE_RE = re.compile(r"^[^@\s]+@sha256:[0-9a-f]{64}$")
PRODUCTION_TEE_FORBIDDEN_MARKERS = (
    b"outbe-tee-enclave-mock: MOCK ENCLAVE",
    b"outbe-dcap-capture-enclave",
    b"OUTBE_QVL_TEST_TRACE",
    b"OUTBE_QVL_BEGIN",
    b"OUTBE_QVL_END",
    b"explicit development seed",
    b"development offer-secret fallback",
)


def canonical_json(value: Any) -> bytes:
    """Serialize a v1 manifest using the canonical encoding named by the schema."""

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


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_input(source_root: Path, relative: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute():
        raise ValueError(f"input path escapes source root: {relative}")
    root = source_root.resolve()
    resolved = (root / candidate).resolve()
    try:
        resolved.relative_to(root)
    except ValueError as error:
        raise ValueError(f"input path escapes source root: {relative}") from error
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError(f"missing or non-regular release input: {relative}")
    return resolved


def _artifact_record(spec: dict[str, Any], artifact_dir: Path, target: str) -> dict[str, Any]:
    name = spec["name"]
    path = artifact_dir / name
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"missing release artifact: {name}")

    features = sorted(spec.get("features", []))
    if (
        spec.get("role") == "tee-enclave"
        and spec.get("classification") == "production"
        and "mock" in features
    ):
        raise ValueError("production enclave must not enable the mock feature")
    if spec.get("role") == "tee-enclave" and spec.get("classification") == "production":
        raw = path.read_bytes()
        for marker in PRODUCTION_TEE_FORBIDDEN_MARKERS:
            if marker in raw:
                raise ValueError(
                    "production enclave contains forbidden test/dev marker: "
                    + marker.decode("ascii")
                )

    record: dict[str, Any] = {
        "classification": spec["classification"],
        "digest": {"algorithm": "sha256", "value": sha256_file(path)},
        "features": features,
        "install_profiles": sorted(spec["install_profiles"]),
        "kind": "elf",
        "media_type": "application/vnd.outbe.elf",
        "name": name,
        "network_compatibility": "network-manifest-required",
        "package": spec["package"],
        "path": f"bin/{name}",
        "platform": {"architecture": "x86_64", "os": "linux", "target": target},
        "role": spec["role"],
        "size": path.stat().st_size,
    }
    if spec.get("role") == "tee-enclave":
        record["tee"] = {"mock": False, "stage": "unsigned-bare-elf"}
    return record


def validate_build_spec(build_spec: dict[str, Any]) -> None:
    if build_spec.get("spec_version") != 1:
        raise ValueError("unsupported reproducible ELF build spec version")
    if build_spec.get("target") != "x86_64-unknown-linux-gnu":
        raise ValueError("unsupported release target")
    if build_spec.get("profile") != "release":
        raise ValueError("the v1 release recipe must preserve the release profile")
    if build_spec.get("rust_toolchain") != "1.96.0":
        raise ValueError("the v1 release recipe requires Rust 1.96.0")
    builder = build_spec.get("builder", {})
    base_images = builder.get("base_images", [])
    if (
        not isinstance(base_images, list)
        or len(base_images) != 2
        or len(set(base_images)) != 2
        or any(not PINNED_IMAGE_RE.fullmatch(image) for image in base_images)
    ):
        raise ValueError("builder base images must be two unique sha256-pinned images")
    if builder.get("recipe") != "Dockerfile.project-toolchain":
        raise ValueError("builder must use the canonical project toolchain recipe")
    system_packages = builder.get("system_packages", [])
    if not system_packages or any(
        "=" not in package or re.search(r"\s", package) for package in system_packages
    ):
        raise ValueError("every direct system package must have an exact version")
    if build_spec.get("cargo", {}).get("locked") is not True:
        raise ValueError("release dependency resolution must be locked")
    if build_spec.get("cargo", {}).get("auditable") is not False:
        raise ValueError("recipe v1 must explicitly record cargo-auditable as disabled")

    artifacts = build_spec.get("artifacts", [])
    names = [artifact.get("name") for artifact in artifacts]
    if not names or len(names) != len(set(names)):
        raise ValueError("release artifacts must have unique non-empty names")

    production_enclaves = [
        artifact
        for artifact in artifacts
        if artifact.get("role") == "tee-enclave"
        and artifact.get("classification") == "production"
    ]
    if len(production_enclaves) != 1:
        raise ValueError("release artifacts must contain exactly one production enclave")
    enclave = production_enclaves[0]
    if (
        enclave.get("name") != "outbe-tee-enclave"
        or enclave.get("package") != "outbe-tee-enclave"
    ):
        raise ValueError("production enclave package and binary must be outbe-tee-enclave")
    enclave_features = enclave.get("features")
    if enclave_features != ["production-dcap-release"]:
        feature_list = (
            ", ".join(str(feature) for feature in enclave_features)
            if isinstance(enclave_features, list)
            else "missing"
        )
        raise ValueError(
            "production enclave feature set must be exactly production-dcap-release "
            f"(got: {feature_list or 'empty'})"
        )
    for artifact in artifacts:
        if artifact is not enclave and artifact.get("features") != []:
            raise ValueError(
                "non-enclave release artifacts must not enable application features"
            )


def build_manifest(
    *,
    build_spec: dict[str, Any],
    source_root: Path,
    artifact_dir: Path,
    release_tag: str,
    source_commit: str,
    source_date_epoch: int,
    lifecycle: str,
    verification_gates: list[dict[str, Any]],
    resolved_system_packages: Path | None = None,
) -> dict[str, Any]:
    """Build a path-independent manifest value from one completed ELF build."""

    validate_build_spec(build_spec)
    if not release_tag or not release_tag.isascii():
        raise ValueError("release tag must be non-empty ASCII")
    if not COMMIT_RE.fullmatch(source_commit):
        raise ValueError("source commit must be a lowercase 40-character Git SHA")
    if isinstance(source_date_epoch, bool) or source_date_epoch < 0:
        raise ValueError("SOURCE_DATE_EPOCH must be a non-negative integer")
    if lifecycle not in {"build-candidate", "verified", "revoked"}:
        raise ValueError("unsupported release lifecycle")

    source_root = source_root.resolve()
    artifact_dir = artifact_dir.resolve()
    inputs = []
    for relative in sorted(build_spec["inputs"]):
        path = _safe_input(source_root, relative)
        inputs.append(
            {
                "digest": {"algorithm": "sha256", "value": sha256_file(path)},
                "media_type": "application/octet-stream",
                "path": relative,
                "size": path.stat().st_size,
            }
        )

    artifacts = [
        _artifact_record(spec, artifact_dir, build_spec["target"])
        for spec in build_spec["artifacts"]
    ]

    builder = {
        "base_images": build_spec["builder"]["base_images"],
        "id": build_spec["builder"]["id"],
        "recipe": build_spec["builder"]["recipe"],
        "system_packages": sorted(build_spec["builder"]["system_packages"]),
    }
    if resolved_system_packages is not None:
        packages_path = resolved_system_packages.resolve()
        if not packages_path.is_file() or packages_path.is_symlink():
            raise ValueError("missing resolved system package inventory")
        builder["resolved_system_packages"] = {
            "digest": {"algorithm": "sha256", "value": sha256_file(packages_path)},
            "media_type": "text/plain",
            "path": "metadata/builder-system-packages.txt",
            "size": packages_path.stat().st_size,
        }

    return {
        "$schema": "https://outbe.io/schemas/release-manifest-v1.json",
        "artifacts": artifacts,
        "build": {
            "builder": builder,
            "cargo": {
                "auditable": build_spec["cargo"]["auditable"],
                "locked": True,
                "packages": [artifact["package"] for artifact in build_spec["artifacts"]],
            },
            "environment": {
                "cflags": build_spec["environment"]["cflags"],
                "cxxflags": build_spec["environment"]["cxxflags"],
                "locale": build_spec["environment"]["locale"],
                "rustflags": build_spec["environment"]["rustflags"],
                "timezone": build_spec["environment"]["timezone"],
                "zero_ar_date": build_spec["environment"]["zero_ar_date"],
            },
            "profile": build_spec["profile"],
            "provenance": {
                "entrypoint": "scripts/release/reproducible-build.sh",
                "mode": "local-container",
            },
            "rust_toolchain": build_spec["rust_toolchain"],
            "source_date_epoch": source_date_epoch,
            "target": build_spec["target"],
        },
        "canonicalization": {
            "encoding": "UTF-8",
            "name": "outbe-canonical-json-v1",
            "non_ascii": "lowercase-hex-unicode-escape",
            "object_keys": "unicode-code-point-order",
            "trailing_newline": True,
            "whitespace": "none",
        },
        "inputs": inputs,
        "release": {
            "lifecycle": lifecycle,
            "source": {
                "clean_tree_policy": "required",
                "commit": source_commit,
                "tree_state": "clean",
            },
            "tag": release_tag,
        },
        "schema_version": "1.0.0",
        "verification_gates": verification_gates,
    }


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-spec", required=True, type=Path)
    parser.add_argument("--source-root", required=True, type=Path)
    parser.add_argument("--artifact-dir", required=True, type=Path)
    parser.add_argument("--release-tag", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument(
        "--lifecycle",
        choices=("build-candidate", "verified", "revoked"),
        default="build-candidate",
    )
    parser.add_argument("--verification-gates", type=Path)
    parser.add_argument("--resolved-system-packages", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    build_spec = json.loads(args.build_spec.read_text(encoding="utf-8"))
    gates: list[dict[str, Any]] = []
    if args.verification_gates is not None:
        gates = json.loads(args.verification_gates.read_text(encoding="utf-8"))
    manifest = build_manifest(
        build_spec=build_spec,
        source_root=args.source_root,
        artifact_dir=args.artifact_dir,
        release_tag=args.release_tag,
        source_commit=args.source_commit,
        source_date_epoch=args.source_date_epoch,
        lifecycle=args.lifecycle,
        verification_gates=gates,
        resolved_system_packages=args.resolved_system_packages,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(canonical_json(manifest))


if __name__ == "__main__":
    main()
