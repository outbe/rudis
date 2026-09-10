#!/usr/bin/env python3
"""Verify that release consumers match the single Outbe version pin."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tomllib
from pathlib import Path
from typing import Any


CONTRACT_PATH = "release/project-toolchain-v1.json"
APT_SOURCES_PATH = "release/apt/ubuntu.sources"
APT_SNAPSHOT_HOST = "https://snapshot.ubuntu.com/ubuntu/"
MUTABLE_APT_HOSTS = ("archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com")
EXPECTED_TOP_LEVEL_KEYS = {
    "activation",
    "apt_provenance",
    "gramine",
    "host_only_packages",
    "platform",
    "rust",
    "schema_version",
    "system_packages",
    "target",
}
SHA256_RE = re.compile(r"[0-9a-f]{64}")
EXPECTED_APT_SOURCE_PATHS = (
    "/etc/apt/sources.list.d/gramine.list",
    "/etc/apt/sources.list.d/intel-sgx.list",
    "/etc/apt/sources.list.d/ubuntu.sources",
    "/usr/share/keyrings/gramine-keyring.gpg",
    "/usr/share/keyrings/intel-sgx-deb.key",
    "/usr/share/keyrings/ubuntu-archive-keyring.gpg",
)
LOWER_GIT_SHA_RE = re.compile(r"[0-9a-f]{40}")
EXPECTED_SYSTEM_PACKAGES = (
    "build-essential",
    "clang",
    "cmake",
    "gcc-14-base",
    "git",
    "libc++-dev",
    "libc++abi-dev",
    "libgcc-s1",
    "libsgx-dcap-quote-verify",
    "libsgx-dcap-quote-verify-dev",
    "libsgx-headers",
    "libssl-dev",
    "libstdc++6",
    "pkg-config",
)
EXPECTED_HOST_ONLY_PACKAGES = ("libsgx-dcap-default-qpl",)


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_and_validate_pin(path: Path) -> dict[str, Any]:
    pin = _read_json(path)
    if set(pin) != EXPECTED_TOP_LEVEL_KEYS:
        raise ValueError("project toolchain pin has an unsupported shape")
    if pin["schema_version"] != 1:
        raise ValueError("unsupported project toolchain pin version")
    if pin["activation"] != "pending-container-delivery":
        raise ValueError("unsupported project toolchain activation state")
    if pin["target"] != "x86_64-unknown-linux-gnu":
        raise ValueError("project toolchain supports only x86_64 Linux")
    if pin["platform"] != "linux/amd64":
        raise ValueError("project toolchain supports only linux/amd64")

    apt = pin["apt_provenance"]
    if not isinstance(apt, dict) or set(apt) != {"deb_closure", "source_files"}:
        raise ValueError("project APT provenance has an unsupported shape")
    closure = apt["deb_closure"]
    if (
        not isinstance(closure, dict)
        or set(closure) != {"count", "format", "sha256"}
        or not isinstance(closure["count"], int)
        or isinstance(closure["count"], bool)
        or closure["count"] <= 0
        or closure["format"] != "sha256sum-lines-sorted-by-filename-v1"
        or not SHA256_RE.fullmatch(closure["sha256"])
    ):
        raise ValueError("project APT package closure must have an exact digest and count")
    source_files = apt["source_files"]
    if (
        not isinstance(source_files, list)
        or any(not isinstance(source, dict) for source in source_files)
        or tuple(source.get("path") for source in source_files)
        != EXPECTED_APT_SOURCE_PATHS
        or any(
            set(source) != {"path", "sha256"}
            or not SHA256_RE.fullmatch(source.get("sha256", ""))
            for source in source_files
        )
    ):
        raise ValueError("project APT source and key files must be hash-pinned")

    rust = pin["rust"]
    if not isinstance(rust, dict) or set(rust) != {"components", "version"}:
        raise ValueError("project Rust pin has an unsupported shape")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", rust["version"]):
        raise ValueError("project Rust version must be exact")
    components = rust["components"]
    if (
        not isinstance(components, list)
        or not components
        or components != sorted(set(components))
        or any(not isinstance(component, str) or not component for component in components)
    ):
        raise ValueError("project Rust components must be unique, sorted names")

    gramine = pin["gramine"]
    if not isinstance(gramine, dict) or set(gramine) != {"source_commit", "version"}:
        raise ValueError("project Gramine pin has an unsupported shape")
    if not re.fullmatch(r"[0-9]+\.[0-9]+", gramine["version"]):
        raise ValueError("project Gramine version must be exact")
    if not LOWER_GIT_SHA_RE.fullmatch(gramine["source_commit"]):
        raise ValueError("project Gramine source commit must be an exact lowercase Git SHA")

    packages = pin["system_packages"]
    if (
        not isinstance(packages, dict)
        or not packages
        or any(
            not isinstance(name, str)
            or not name
            or not isinstance(version, str)
            or not version
            or any(character.isspace() for character in version)
            for name, version in packages.items()
        )
    ):
        raise ValueError("project system packages must be sorted exact version pins")
    if tuple(packages) != EXPECTED_SYSTEM_PACKAGES:
        raise ValueError("project toolchain has an unsupported system package set")
    host_only_packages = pin["host_only_packages"]
    if (
        not isinstance(host_only_packages, dict)
        or tuple(host_only_packages) != EXPECTED_HOST_ONLY_PACKAGES
        or any(
            not isinstance(version, str)
            or not version
            or any(character.isspace() for character in version)
            for version in host_only_packages.values()
        )
    ):
        raise ValueError("project toolchain has an unsupported host-only package set")
    if set(host_only_packages).intersection(packages):
        raise ValueError("host-only packages must not enter the release build image")
    return pin


def apt_ledger(deb_dir: Path) -> tuple[str, str, int]:
    """Return the closure ledger, its digest and its package count."""

    debs = sorted(deb_dir.resolve().glob("*.deb"), key=lambda path: path.name)
    if any(not path.is_file() or path.is_symlink() for path in debs):
        raise ValueError("APT package closure contains a non-regular artifact")
    ledger = "".join(f"{_sha256_file(path)}  {path.name}\n" for path in debs)
    return ledger, hashlib.sha256(ledger.encode("ascii")).hexdigest(), len(debs)


def verify_apt_inputs(*, pin_path: Path, root: Path, deb_dir: Path) -> None:
    """Verify the base APT authority and downloaded package closure before install."""

    pin = load_and_validate_pin(pin_path)
    root = root.resolve()
    for source in pin["apt_provenance"]["source_files"]:
        candidate = root / source["path"].lstrip("/")
        if not candidate.is_file() or candidate.is_symlink():
            raise ValueError(f"missing or non-regular APT provenance input: {source['path']}")
        if _sha256_file(candidate) != source["sha256"]:
            raise ValueError(f"APT provenance digest mismatch: {source['path']}")

    ledger, actual_digest, count = apt_ledger(deb_dir)
    closure = pin["apt_provenance"]["deb_closure"]
    if count != closure["count"]:
        raise ValueError(
            f"APT package closure count mismatch: expected {closure['count']}, found {count}\n"
            f"resolved closure:\n{ledger}"
        )
    if actual_digest != closure["sha256"]:
        raise ValueError(
            "APT package closure digest mismatch: "
            f"expected {closure['sha256']}, found {actual_digest}\n"
            f"resolved closure:\n{ledger}"
        )


def _require_equal(
    differences: list[str],
    *,
    label: str,
    actual: object,
    expected: object,
) -> None:
    if actual != expected:
        differences.append(f"{label}: expected {expected!r}, found {actual!r}")


def repository_differences(repo_root: Path) -> list[str]:
    pin = load_and_validate_pin(repo_root / CONTRACT_PATH)
    differences: list[str] = []
    rust = pin["rust"]
    gramine = pin["gramine"]
    packages = pin["system_packages"]

    rust_toolchain = tomllib.loads(
        (repo_root / "rust-toolchain.toml").read_text(encoding="utf-8")
    )["toolchain"]
    _require_equal(
        differences,
        label="rust-toolchain channel",
        actual=rust_toolchain.get("channel"),
        expected=rust["version"],
    )
    _require_equal(
        differences,
        label="rust-toolchain components",
        actual=sorted(rust_toolchain.get("components", [])),
        expected=rust["components"],
    )

    elf = _read_json(repo_root / "release/reproducible-elf-build-v1.json")
    _require_equal(
        differences,
        label="ELF project toolchain contract",
        actual=elf.get("project_toolchain"),
        expected=CONTRACT_PATH,
    )
    _require_equal(
        differences,
        label="ELF Rust version",
        actual=elf.get("rust_toolchain"),
        expected=rust["version"],
    )
    elf_builder = elf.get("builder", {})
    _require_equal(
        differences,
        label="ELF builder recipe",
        actual=elf_builder.get("recipe"),
        expected="Dockerfile.project-toolchain",
    )
    elf_base_images = elf_builder.get("base_images", [])
    if not any(f"rust:{rust['version']}-" in image for image in elf_base_images):
        differences.append("ELF builder images do not use the pinned Rust version")
    if not any(f"gramineproject/gramine:{gramine['version']}-" in image for image in elf_base_images):
        differences.append("ELF builder images do not use the pinned Gramine version")
    _require_equal(
        differences,
        label="ELF builder system packages",
        actual=elf_builder.get("system_packages"),
        expected=[f"{name}={version}" for name, version in packages.items()],
    )
    for required_input in (
        CONTRACT_PATH,
        APT_SOURCES_PATH,
        "release/dcap-native-qvl-v1.json",
        "scripts/release/verify_dcap_native_qvl.py",
        "scripts/release/verify_project_toolchain.py",
    ):
        if required_input not in elf.get("inputs", []):
            differences.append(f"ELF release inputs do not bind {required_input}")

    sgx_profiles = {
        network: _read_json(repo_root / f"release/{network}-sgx-bundle-v1.json")
        for network in ("testnet", "mainnet")
    }
    for network, sgx in sgx_profiles.items():
        _require_equal(
            differences,
            label=f"{network} SGX project toolchain contract",
            actual=sgx.get("project_toolchain"),
            expected=CONTRACT_PATH,
        )
        _require_equal(
            differences,
            label=f"{network} SGX Gramine version",
            actual=sgx.get("gramine", {}).get("version"),
            expected=gramine["version"],
        )
        _require_equal(
            differences,
            label=f"{network} SGX Gramine source commit",
            actual=sgx.get("gramine", {}).get("source_commit"),
            expected=gramine["source_commit"],
        )
        for required_input in (CONTRACT_PATH, "scripts/release/verify_project_toolchain.py"):
            if required_input not in sgx.get("inputs", []):
                differences.append(
                    f"{network} SGX release inputs do not bind {required_input}"
                )
    for field in (
        "bundle_version",
        "gramine",
        "install_root",
        "platform",
        "sealed_state_schema",
        "sgx",
        "spec_version",
    ):
        _require_equal(
            differences,
            label=f"SGX physical profile parity for {field}",
            actual=sgx_profiles["mainnet"].get(field),
            expected=sgx_profiles["testnet"].get(field),
        )

    qvl = _read_json(repo_root / "release/dcap-native-qvl-v1.json")
    _require_equal(
        differences,
        label="QVL Gramine version",
        actual=qvl.get("gramine_version"),
        expected=gramine["version"],
    )
    qvl_packages = {
        "libsgx-dcap-quote-verify": qvl.get("intel_dcap", {}).get(
            "runtime_package_version"
        ),
        "libsgx-dcap-quote-verify-dev": qvl.get("intel_dcap", {}).get(
            "development_package_version"
        ),
        "libsgx-headers": qvl.get("intel_dcap", {}).get("headers_package_version"),
    }
    for package, actual in qvl_packages.items():
        _require_equal(
            differences,
            label=f"QVL {package}",
            actual=actual,
            expected=packages[package],
        )
    artifact_versions = {
        artifact.get("package"): artifact.get("package_version")
        for artifact in qvl.get("artifacts", [])
    }
    for package in ("libsgx-dcap-quote-verify", "libstdc++6", "libgcc-s1"):
        _require_equal(
            differences,
            label=f"QVL artifact {package}",
            actual=artifact_versions.get(package),
            expected=packages[package],
        )

    recipe = (repo_root / "Dockerfile.project-toolchain").read_text(encoding="utf-8")
    if f"rust:{rust['version']}-" not in recipe:
        differences.append("project toolchain recipe does not use the pinned Rust version")
    if f"gramineproject/gramine:{gramine['version']}-" not in recipe:
        differences.append("project toolchain recipe does not use the pinned Gramine version")
    for package, version in packages.items():
        if f"{package}={version}" not in recipe:
            differences.append(
                f"project toolchain recipe does not install {package}={version}"
            )
    for image in elf_base_images:
        if f"FROM {image} " not in recipe:
            differences.append(f"project toolchain recipe does not consume {image}")
    if "FROM toolchain AS builder" not in recipe or "FROM scratch AS artifacts" not in recipe:
        differences.append("project toolchain recipe does not own the release artifact stages")
    if f"COPY {APT_SOURCES_PATH} /etc/apt/sources.list.d/ubuntu.sources" not in recipe:
        differences.append("project toolchain recipe does not install the frozen APT sources")

    apt_sources = (repo_root / APT_SOURCES_PATH).read_text(encoding="utf-8")
    uris = [
        line.split(":", 1)[1].strip()
        for line in apt_sources.splitlines()
        if line.startswith("URIs:")
    ]
    if not uris:
        differences.append("frozen APT sources declare no URI")
    for uri in uris:
        if not uri.startswith(APT_SNAPSHOT_HOST):
            differences.append(f"frozen APT sources use a mutable archive URI: {uri}")
    for host in MUTABLE_APT_HOSTS:
        if any(host in line for line in apt_sources.splitlines() if not line.startswith("#")):
            differences.append(f"frozen APT sources still reach the mutable host {host}")

    tee_build = (repo_root / "crates/system/tee/build.rs").read_text(encoding="utf-8")
    for release_pin in (
        'include_str!("../../../release/project-toolchain-v1.json")',
        'include_str!("../../../release/dcap-native-qvl-v1.json")',
    ):
        if release_pin not in tee_build:
            differences.append(f"native-DCAP build contract does not consume {release_pin}")
    for version in packages.values():
        if f'"{version}"' in tee_build:
            differences.append(
                f"native-DCAP build contract duplicates project package version {version}"
            )
    return differences


def verify_repository(repo_root: Path) -> None:
    differences = repository_differences(repo_root.resolve())
    if differences:
        detail = "\n".join(f"- {difference}" for difference in differences)
        raise ValueError(f"project toolchain version drift:\n{detail}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--verify-apt-inputs", action="store_true")
    parser.add_argument("--emit-apt-ledger", action="store_true")
    parser.add_argument("--pin", type=Path)
    parser.add_argument("--apt-root", type=Path)
    parser.add_argument("--deb-dir", type=Path)
    args = parser.parse_args()
    if args.emit_apt_ledger:
        if args.deb_dir is None:
            parser.error("--emit-apt-ledger requires --deb-dir")
        ledger, digest, count = apt_ledger(args.deb_dir)
        print(ledger, end="")
        print(json.dumps({"count": count, "sha256": digest}))
        return
    if args.verify_apt_inputs:
        if args.pin is None or args.apt_root is None or args.deb_dir is None:
            parser.error("--verify-apt-inputs requires --pin, --apt-root and --deb-dir")
        verify_apt_inputs(pin_path=args.pin, root=args.apt_root, deb_dir=args.deb_dir)
        print("project APT source and package closure: OK")
        return
    verify_repository(args.repo_root)
    print(
        "project toolchain version pin: OK "
        f"(release activation: {load_and_validate_pin(args.repo_root / CONTRACT_PATH)['activation']})"
    )


if __name__ == "__main__":
    main()
