#!/usr/bin/env python3
"""Fail-closed verification of the active V1 native-QVL artifact contract."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import subprocess
from pathlib import Path
from typing import Any


EXPECTED_ROLES = ("qvl", "cxx-runtime", "gcc-runtime")
EXPECTED_STATUS = "active"


def _load_project_pin_verifier():
    path = Path(__file__).with_name("verify_project_toolchain.py")
    spec = importlib.util.spec_from_file_location("outbe_project_pin_verifier", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load project toolchain verifier: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _project_pin_path() -> Path:
    adjacent = Path(__file__).with_name("project-toolchain-v1.json")
    if adjacent.is_file():
        return adjacent
    return Path(__file__).resolve().parents[2] / "release/project-toolchain-v1.json"


PROJECT_VERSION_PIN = _load_project_pin_verifier().load_and_validate_pin(
    _project_pin_path()
)


def expected_dcap(pin: dict[str, Any]) -> dict[str, Any]:
    packages = pin["system_packages"]
    return {
        "runtime_package": "libsgx-dcap-quote-verify",
        "runtime_package_version": packages["libsgx-dcap-quote-verify"],
        "development_package": "libsgx-dcap-quote-verify-dev",
        "development_package_version": packages["libsgx-dcap-quote-verify-dev"],
        "headers_package": "libsgx-headers",
        "headers_package_version": packages["libsgx-headers"],
        "collateral_major_version": 3,
        "collateral_minor_version": 1,
        "qve_report_info": "null",
        "qve_enabled": False,
        "tvl_enabled": False,
        "qpl_or_pccs_during_consensus": False,
    }


_EXPECTED_ARTIFACT_BASE = (
    {
        "role": "qvl",
        "package": "libsgx-dcap-quote-verify",
        "path": "/usr/lib/x86_64-linux-gnu/libsgx_dcap_quoteverify.so.1.13.103.0",
        "install_name": "libsgx_dcap_quoteverify.so.1",
        "size": 5322424,
        "sha256": "4745bc5b46cbdc17a78119ae2db08f54b86ff9077c5ab480f378741396365aef",
        "elf_build_id": "663c0acf2b4673c22c66f01112c5f38d856fd5a5",
    },
    {
        "role": "cxx-runtime",
        "package": "libstdc++6",
        "path": "/usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.33",
        "install_name": "libstdc++.so.6",
        "size": 2592224,
        "sha256": "1fd75fe70354a416d75aef22bcae68c47bd25d20e2d0568c30b1a9838cf62f11",
    },
    {
        "role": "gcc-runtime",
        "package": "libgcc-s1",
        "path": "/usr/lib/x86_64-linux-gnu/libgcc_s.so.1",
        "install_name": "libgcc_s.so.1",
        "size": 183024,
        "sha256": "d93224d2b0dab4247598be683adca02f5cf00586f99c187579cd7e92058fb7cb",
    },
)


def expected_artifacts(pin: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    packages = pin["system_packages"]
    return tuple(
        {
            **artifact,
            "package_version": packages[artifact["package"]],
        }
        for artifact in _EXPECTED_ARTIFACT_BASE
    )


_EXPECTED_BUILD_INPUT_BASE = (
    {
        "role": "qvl-api-header",
        "package": "libsgx-dcap-quote-verify-dev",
        "path": "/usr/include/sgx_dcap_quoteverify.h",
        "size": 18643,
        "sha256": "22311e0b4332276c315fdc2f792b28197a3d9a7bfd376246fa5fa3c1bef870ef",
    },
    {
        "role": "qve-status-header",
        "package": "libsgx-headers",
        "path": "/usr/include/sgx_qve_header.h",
        "size": 10590,
        "sha256": "f8994fcb1b56ed938adbf923146b5fed8c3e8d5d7d6827f45342db0a23e56677",
    },
    {
        "role": "sgx-key-header",
        "package": "libsgx-headers",
        "path": "/usr/include/sgx_key.h",
        "size": 4211,
        "sha256": "8cf1a8ef06f5ede977b15392e23a368b4a78e895fabf9680018d81a8e014c21d",
    },
    {
        "role": "sgx-attributes-header",
        "package": "libsgx-headers",
        "path": "/usr/include/sgx_attributes.h",
        "size": 3773,
        "sha256": "ba8e81f44a76518920ab086546970d636c2379ca372e0dfb0fef4b3ce78ed8b5",
    },
    {
        "role": "qvl-quote-header",
        "package": "libsgx-headers",
        "path": "/usr/include/sgx_ql_quote.h",
        "size": 4630,
        "sha256": "d88804c288c15f03958ac6b54d56513ce790ffc190fe32563a178ba5360fc3df",
    },
    {
        "role": "qvl-common-header",
        "package": "libsgx-headers",
        "path": "/usr/include/sgx_ql_lib_common.h",
        "size": 20764,
        "sha256": "2bc3c7ef75c7230bc4b4a1b484800199e791fe78aee7a8161e78e6ebb6fc3c2d",
    },
    {
        "role": "sgx-quote-header",
        "package": "libsgx-headers",
        "path": "/usr/include/sgx_quote.h",
        "size": 6247,
        "sha256": "1c4582245fffb8b8ca409af2de5810f83ad15f79c17183634757bb913cb51d68",
    },
    {
        "role": "sgx-report-header",
        "package": "libsgx-headers",
        "path": "/usr/include/sgx_report.h",
        "size": 5273,
        "sha256": "2759b2579a5c62e8889b4296c3f9f6ff7fde2983823c67b825105585b796101b",
    },
    {
        "role": "sgx-defs-header",
        "package": "libsgx-headers",
        "path": "/usr/include/sgx_defs.h",
        "size": 2378,
        "sha256": "a2be53305ec098f18e9e62550781e7e405c6b4485f87e31d6446bec5a6eefa0b",
    },
    {
        "role": "sgx-quote3-header",
        "package": "libsgx-headers",
        "path": "/usr/include/sgx_quote_3.h",
        "size": 9724,
        "sha256": "d569890a4c1236e94c13a8673d4006e1542e04a313c26f8cdc2fdc8456a9d6ea",
    },
    {
        "role": "sgx-pce-header",
        "package": "libsgx-headers",
        "path": "/usr/include/sgx_pce.h",
        "size": 5748,
        "sha256": "ecc31a29dc046bcb6bfea6bc6427600e0d98b43310c6edcc4f9e82284dc70968",
    },
)


def expected_build_inputs(pin: dict[str, Any]) -> tuple[dict[str, Any], ...]:
    packages = pin["system_packages"]
    return tuple(
        {
            **build_input,
            "package_version": packages[build_input["package"]],
        }
        for build_input in _EXPECTED_BUILD_INPUT_BASE
    )


EXPECTED_DCAP = expected_dcap(PROJECT_VERSION_PIN)
EXPECTED_ARTIFACTS = expected_artifacts(PROJECT_VERSION_PIN)
EXPECTED_BUILD_INPUTS = expected_build_inputs(PROJECT_VERSION_PIN)


def load_manifest(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("native-QVL manifest must be a JSON object")
    return value


def artifact_path(root: Path, configured: str) -> Path:
    path = Path(configured)
    if not path.is_absolute():
        raise ValueError(f"native-QVL artifact path must be absolute: {configured}")
    root = root.resolve()
    candidate = (root / path.relative_to("/")).resolve()
    if candidate != root and root not in candidate.parents:
        raise ValueError(f"native-QVL artifact escapes root: {configured}")
    return candidate


def installed_package_version(package: str) -> str:
    process = subprocess.run(
        ["dpkg-query", "--show", "--showformat=${Version}", package],
        check=False,
        capture_output=True,
        text=True,
    )
    if process.returncode != 0:
        raise ValueError(f"required native-QVL package is not installed: {package}")
    return process.stdout


def verify_installed_packages(dcap: dict[str, Any]) -> None:
    packages = {
        dcap["runtime_package"]: dcap["runtime_package_version"],
        dcap["development_package"]: dcap["development_package_version"],
        dcap["headers_package"]: dcap["headers_package_version"],
    }
    packages.update(
        {
            artifact["package"]: artifact["package_version"]
            for artifact in EXPECTED_ARTIFACTS
        }
    )
    packages.update(
        {
            build_input["package"]: build_input["package_version"]
            for build_input in EXPECTED_BUILD_INPUTS
        }
    )
    for package, expected_version in packages.items():
        if installed_package_version(package) != expected_version:
            raise ValueError(
                f"native-QVL package version mismatch: {package} "
                f"(expected {expected_version})"
            )


def verify_manifest(
    manifest: dict[str, Any], root: Path, *, check_packages: bool = False
) -> None:
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported native-QVL manifest schema")
    if manifest.get("status") != EXPECTED_STATUS:
        raise ValueError(f"native-QVL status must be {EXPECTED_STATUS}")
    if manifest.get("target") != "x86_64-unknown-linux-gnu":
        raise ValueError("native-QVL V1 target must be x86_64-unknown-linux-gnu")
    gramine_version = PROJECT_VERSION_PIN["gramine"]["version"]
    if manifest.get("gramine_version") != gramine_version:
        raise ValueError(
            f"native-QVL V1 requires exact Gramine {gramine_version}"
        )

    dcap = manifest.get("intel_dcap")
    if not isinstance(dcap, dict):
        raise ValueError("native-QVL manifest is missing intel_dcap")
    if dcap != EXPECTED_DCAP:
        raise ValueError("native-QVL Intel DCAP metadata does not match the exact V1 contract")
    if check_packages:
        verify_installed_packages(dcap)

    build_inputs = manifest.get("build_inputs")
    if not isinstance(build_inputs, list):
        raise ValueError("native-QVL manifest build_inputs must be an array")
    if build_inputs != list(EXPECTED_BUILD_INPUTS):
        raise ValueError("native-QVL build input metadata does not match the exact V1 contract")
    build_input_roles = tuple(build_input.get("role") for build_input in build_inputs)
    expected_build_input_roles = tuple(
        build_input["role"] for build_input in EXPECTED_BUILD_INPUTS
    )
    if build_input_roles != expected_build_input_roles:
        raise ValueError(
            f"native-QVL build input roles must be {expected_build_input_roles}"
        )
    seen_build_input_paths: set[str] = set()
    for build_input in build_inputs:
        configured = build_input.get("path")
        expected_size = build_input.get("size")
        expected_sha256 = build_input.get("sha256")
        if not isinstance(configured, str) or configured in seen_build_input_paths:
            raise ValueError("native-QVL build input path is missing or duplicated")
        if not isinstance(expected_size, int) or expected_size <= 0:
            raise ValueError(f"invalid native-QVL build input size for {configured}")
        if (
            not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64
            or any(character not in "0123456789abcdef" for character in expected_sha256)
        ):
            raise ValueError(f"invalid native-QVL build input SHA-256 for {configured}")
        seen_build_input_paths.add(configured)

        path = artifact_path(root, configured)
        try:
            payload = path.read_bytes()
        except OSError as error:
            raise ValueError(f"missing native-QVL build input: {configured}") from error
        if len(payload) != expected_size:
            raise ValueError(f"native-QVL build input size mismatch: {configured}")
        if hashlib.sha256(payload).hexdigest() != expected_sha256:
            raise ValueError(f"native-QVL build input SHA-256 mismatch: {configured}")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise ValueError("native-QVL manifest artifacts must be an array")
    if artifacts != list(EXPECTED_ARTIFACTS):
        raise ValueError("native-QVL artifact metadata does not match the exact V1 contract")
    roles = tuple(artifact.get("role") for artifact in artifacts)
    if roles != EXPECTED_ROLES:
        raise ValueError(f"native-QVL artifact roles must be {EXPECTED_ROLES}")

    seen_paths: set[str] = set()
    seen_install_names: set[str] = set()
    for artifact in artifacts:
        configured = artifact.get("path")
        install_name = artifact.get("install_name")
        expected_size = artifact.get("size")
        expected_sha256 = artifact.get("sha256")
        if not isinstance(configured, str) or configured in seen_paths:
            raise ValueError("native-QVL artifact path is missing or duplicated")
        if not isinstance(install_name, str) or install_name in seen_install_names:
            raise ValueError("native-QVL install name is missing or duplicated")
        if not isinstance(expected_size, int) or expected_size <= 0:
            raise ValueError(f"invalid native-QVL artifact size for {configured}")
        if (
            not isinstance(expected_sha256, str)
            or len(expected_sha256) != 64
            or any(character not in "0123456789abcdef" for character in expected_sha256)
        ):
            raise ValueError(f"invalid native-QVL SHA-256 for {configured}")
        seen_paths.add(configured)
        seen_install_names.add(install_name)

        path = artifact_path(root, configured)
        try:
            payload = path.read_bytes()
        except OSError as error:
            raise ValueError(f"missing native-QVL artifact: {configured}") from error
        if len(payload) != expected_size:
            raise ValueError(f"native-QVL artifact size mismatch: {configured}")
        if hashlib.sha256(payload).hexdigest() != expected_sha256:
            raise ValueError(f"native-QVL artifact SHA-256 mismatch: {configured}")


def install_verified_artifacts(
    manifest: dict[str, Any],
    root: Path,
    destination: Path,
    *,
    check_packages: bool = False,
) -> None:
    """Install only exact verified artifacts under their contract install names."""
    verify_manifest(manifest, root, check_packages=check_packages)
    if destination.exists():
        if not destination.is_dir() or any(destination.iterdir()):
            raise ValueError("native-QVL install destination must be empty")
    else:
        destination.mkdir(parents=True)

    for artifact in manifest["artifacts"]:
        configured = artifact["path"]
        payload = artifact_path(root, configured).read_bytes()
        if len(payload) != artifact["size"]:
            raise ValueError(f"native-QVL artifact size mismatch: {configured}")
        if hashlib.sha256(payload).hexdigest() != artifact["sha256"]:
            raise ValueError(f"native-QVL artifact SHA-256 mismatch: {configured}")
        target = destination / artifact["install_name"]
        target.write_bytes(payload)
        target.chmod(0o644)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("release/dcap-native-qvl-v1.json"),
    )
    parser.add_argument("--root", type=Path, default=Path("/"))
    parser.add_argument(
        "--install-dir",
        type=Path,
        help="copy exact verified artifacts under their contract install names",
    )
    args = parser.parse_args()

    try:
        manifest = load_manifest(args.manifest)
        check_packages = args.root.resolve() == Path("/")
        if args.install_dir is None:
            verify_manifest(manifest, args.root, check_packages=check_packages)
        else:
            install_verified_artifacts(
                manifest,
                args.root,
                args.install_dir,
                check_packages=check_packages,
            )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    print("native-QVL artifact contract verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
