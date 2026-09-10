#!/usr/bin/env python3
"""Repository contract tests for the single Outbe project toolchain image."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
TEE_BUILD_SCRIPT = REPO_ROOT / "crates/system/tee/build.rs"
DOCKERFILE = REPO_ROOT / "Dockerfile.project-toolchain"
DOCKERIGNORE = REPO_ROOT / ".dockerignore"
PIN_PATH = REPO_ROOT / "release/project-toolchain-v1.json"
ELF_SPEC_PATH = REPO_ROOT / "release/reproducible-elf-build-v1.json"
REPRODUCIBLE_BUILD = REPO_ROOT / "scripts/release/reproducible-build.sh"
VERIFIER_PATH = REPO_ROOT / "scripts/release/verify_project_toolchain.py"
APT_SOURCES_PATH = REPO_ROOT / "release/apt/ubuntu.sources"


def load_verifier():
    spec = importlib.util.spec_from_file_location("verify_project_toolchain", VERIFIER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {VERIFIER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ProjectToolchainContractTests(unittest.TestCase):
    def test_release_context_includes_compile_time_solidity_inputs(self) -> None:
        imported_domains = set()
        import_pattern = re.compile(r'"(?:\.\./)+contracts/([^/]+)/')
        for source in (REPO_ROOT / "crates").rglob("*.rs"):
            imported_domains.update(
                import_pattern.findall(source.read_text(encoding="utf-8"))
            )

        rules = set(DOCKERIGNORE.read_text(encoding="utf-8").splitlines())
        self.assertTrue(imported_domains)
        for domain in sorted(imported_domains):
            self.assertIn(f"!contracts/{domain}", rules)
            self.assertIn(f"!contracts/{domain}/**", rules)

    def test_project_declares_one_version_pin_without_registry_delivery(self) -> None:
        pin = json.loads(PIN_PATH.read_text(encoding="utf-8"))

        self.assertEqual(pin["schema_version"], 1)
        self.assertEqual(pin["activation"], "pending-container-delivery")
        self.assertEqual(pin["target"], "x86_64-unknown-linux-gnu")
        self.assertEqual(pin["platform"], "linux/amd64")
        self.assertEqual(pin["rust"]["version"], "1.96.0")
        self.assertEqual(pin["gramine"]["version"], "1.9")
        self.assertEqual(
            pin["host_only_packages"]["libsgx-dcap-default-qpl"],
            "1.26.100.1-noble1",
        )
        self.assertEqual(
            pin["system_packages"]["libsgx-dcap-quote-verify"],
            "1.26.100.1-noble1",
        )
        self.assertEqual(pin["system_packages"]["libsgx-headers"], "2.29.100.1-noble1")
        self.assertNotIn("image", pin)
        self.assertNotIn("registry", pin)
        self.assertNotIn("digest", pin)

    def test_repository_consumers_follow_the_project_version_pin(self) -> None:
        load_verifier().verify_repository(REPO_ROOT)

    def test_consumer_version_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in (
                "Dockerfile.project-toolchain",
                "crates/system/tee/build.rs",
                "rust-toolchain.toml",
                "release/apt/ubuntu.sources",
                "release/dcap-native-qvl-v1.json",
                "release/project-toolchain-v1.json",
                "release/reproducible-elf-build-v1.json",
                "release/mainnet-sgx-bundle-v1.json",
                "release/testnet-sgx-bundle-v1.json",
            ):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(REPO_ROOT / relative, destination)

            sgx_path = root / "release/testnet-sgx-bundle-v1.json"
            sgx = json.loads(sgx_path.read_text(encoding="utf-8"))
            sgx["gramine"]["version"] = "1.8"
            sgx_path.write_text(json.dumps(sgx), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "SGX Gramine version"):
                load_verifier().verify_repository(root)

    def test_incomplete_project_package_pin_fails_closed(self) -> None:
        pin = json.loads(PIN_PATH.read_text(encoding="utf-8"))
        del pin["system_packages"]["libsgx-headers"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "project-toolchain-v1.json"
            path.write_text(json.dumps(pin), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "system package set"):
                load_verifier().load_and_validate_pin(path)

    def test_native_dcap_build_contract_reads_the_release_pins(self) -> None:
        pin = json.loads(PIN_PATH.read_text(encoding="utf-8"))
        source = TEE_BUILD_SCRIPT.read_text(encoding="utf-8")

        self.assertIn(
            'include_str!("../../../release/project-toolchain-v1.json")',
            source,
        )
        self.assertIn(
            'include_str!("../../../release/dcap-native-qvl-v1.json")',
            source,
        )
        for version in pin["system_packages"].values():
            self.assertNotIn(f'"{version}"', source)

    def test_toolchain_recipe_pins_every_critical_component(self) -> None:
        pin = json.loads(PIN_PATH.read_text(encoding="utf-8"))
        recipe = DOCKERFILE.read_text(encoding="utf-8")

        self.assertIn(f"rust:{pin['rust']['version']}-", recipe)
        self.assertIn(f"gramineproject/gramine:{pin['gramine']['version']}-", recipe)
        for package, version in pin["system_packages"].items():
            self.assertIn(f"{package}={version}", recipe)

        self.assertIn("/opt/outbe/toolchain/verify_dcap_native_qvl.py", recipe)
        self.assertIn("/opt/outbe/toolchain/project-toolchain-v1.json", recipe)
        self.assertIn("/opt/outbe/toolchain/verify_project_toolchain.py", recipe)
        self.assertIn("--root /", recipe)
        self.assertIn("ENTRYPOINT []", recipe)
        self.assertIn("rustup component add rustfmt clippy rust-src", recipe)
        self.assertIn(
            f"--toolchain {pin['rust']['version']}-x86_64-unknown-linux-gnu",
            recipe,
        )
        self.assertIn(
            f"""test "$(rustc --version | cut -d' ' -f1-2)" = "rustc {pin['rust']['version']}" """,
            recipe,
        )
        self.assertIn(
            f"""test "$(dpkg-query -W -f='${{Version}}' gramine)" = "{pin['gramine']['version']}" """,
            recipe,
        )

    def test_ci_stage_provides_the_python_command_used_by_actions(self) -> None:
        recipe = DOCKERFILE.read_text(encoding="utf-8")
        ci_stage = recipe.split("FROM toolchain AS ci", 1)[1].split(
            "FROM toolchain AS builder", 1
        )[0]
        ci_packages = ci_stage.split("RUN apt-get update", 1)[1].split(
            "rm -rf /var/lib/apt/lists/*", 1
        )[0]

        self.assertIn("      python-is-python3 \\\n", ci_packages)
        self.assertRegex(ci_stage, r"for tool in [^;]+ python; do")

    def test_reproducible_release_is_owned_by_the_project_toolchain_recipe(self) -> None:
        pin = json.loads(PIN_PATH.read_text(encoding="utf-8"))
        elf = json.loads(ELF_SPEC_PATH.read_text(encoding="utf-8"))
        recipe = DOCKERFILE.read_text(encoding="utf-8")
        entrypoint = REPRODUCIBLE_BUILD.read_text(encoding="utf-8")

        self.assertEqual(elf["builder"]["recipe"], "Dockerfile.project-toolchain")
        self.assertEqual(
            elf["builder"]["system_packages"],
            [f"{name}={version}" for name, version in pin["system_packages"].items()],
        )
        self.assertEqual(
            elf["builder"]["base_images"],
            [
                line.split()[1]
                for line in recipe.splitlines()
                if line.startswith("FROM ") and " AS rust" in line
                or line.startswith("FROM ") and " AS toolchain" in line
            ],
        )
        self.assertIn('FROM toolchain AS builder', recipe)
        self.assertIn('FROM scratch AS artifacts', recipe)
        self.assertIn('--file "${build_context}/Dockerfile.project-toolchain"', entrypoint)
        self.assertNotIn("Dockerfile.reproducible", entrypoint)

    def test_apt_source_and_package_closure_are_hash_pinned(self) -> None:
        pin = json.loads(PIN_PATH.read_text(encoding="utf-8"))
        recipe = DOCKERFILE.read_text(encoding="utf-8")

        provenance = pin["apt_provenance"]
        self.assertEqual(provenance["deb_closure"]["count"], 100)
        self.assertRegex(provenance["deb_closure"]["sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(len(provenance["source_files"]), 6)
        for source in provenance["source_files"]:
            self.assertTrue(source["path"].startswith("/"))
            self.assertRegex(source["sha256"], r"^[0-9a-f]{64}$")
        self.assertIn("--verify-apt-inputs", recipe)
        self.assertIn("--no-download", recipe)

    def test_ubuntu_archive_is_frozen_at_one_snapshot(self) -> None:
        pin = json.loads(PIN_PATH.read_text(encoding="utf-8"))
        recipe = DOCKERFILE.read_text(encoding="utf-8")
        sources = APT_SOURCES_PATH.read_text(encoding="utf-8")

        self.assertIn(
            "COPY release/apt/ubuntu.sources /etc/apt/sources.list.d/ubuntu.sources",
            recipe,
        )
        uris = [
            line.split(":", 1)[1].strip()
            for line in sources.splitlines()
            if line.startswith("URIs:")
        ]
        self.assertTrue(uris)
        snapshots = set()
        for uri in uris:
            match = re.fullmatch(
                r"https://snapshot\.ubuntu\.com/ubuntu/(\d{8}T\d{6}Z)", uri
            )
            if match is None:
                self.fail(f"mutable archive URI: {uri}")
            snapshots.add(match.group(1))
        self.assertEqual(len(snapshots), 1, "every suite must read one snapshot instant")
        for line in sources.splitlines():
            if line.startswith("#"):
                continue
            for host in ("archive.ubuntu.com", "security.ubuntu.com", "ports.ubuntu.com"):
                self.assertNotIn(host, line)

        pinned = {source["path"]: source["sha256"] for source in pin["apt_provenance"]["source_files"]}
        self.assertEqual(
            pinned["/etc/apt/sources.list.d/ubuntu.sources"],
            hashlib.sha256(APT_SOURCES_PATH.read_bytes()).hexdigest(),
            "the pin must bind the frozen APT sources actually shipped into the image",
        )

    def test_apt_closure_mismatch_names_the_resolved_packages(self) -> None:
        verifier = load_verifier()
        with tempfile.TemporaryDirectory() as directory:
            deb_dir = Path(directory)
            (deb_dir / "only_1_amd64.deb").write_bytes(b"payload")
            ledger, digest, count = verifier.apt_ledger(deb_dir)
            self.assertEqual(count, 1)
            self.assertIn("only_1_amd64.deb", ledger)
            self.assertEqual(
                digest, hashlib.sha256(ledger.encode("ascii")).hexdigest()
            )

    def test_apt_input_verifier_rejects_package_substitution(self) -> None:
        verifier = load_verifier()
        pin = json.loads(PIN_PATH.read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for source in pin["apt_provenance"]["source_files"]:
                path = root / source["path"].lstrip("/")
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(source["path"].encode("ascii"))
                source["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()

            deb_dir = root / "debs"
            deb_dir.mkdir()
            for name, content in (("a_1_amd64.deb", b"a"), ("b_1_amd64.deb", b"b")):
                (deb_dir / name).write_bytes(content)
            ledger = "".join(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n"
                for path in sorted(deb_dir.glob("*.deb"), key=lambda path: path.name)
            )
            pin["apt_provenance"]["deb_closure"] = {
                "count": 2,
                "format": "sha256sum-lines-sorted-by-filename-v1",
                "sha256": hashlib.sha256(ledger.encode("ascii")).hexdigest(),
            }
            pin_path = root / "project-toolchain-v1.json"
            pin_path.write_text(json.dumps(pin), encoding="utf-8")

            verifier.verify_apt_inputs(pin_path=pin_path, root=root, deb_dir=deb_dir)
            (deb_dir / "b_1_amd64.deb").write_bytes(b"substituted")
            with self.assertRaisesRegex(ValueError, "closure digest mismatch"):
                verifier.verify_apt_inputs(pin_path=pin_path, root=root, deb_dir=deb_dir)

    def test_toolchain_recipe_has_no_mutable_or_runtime_dcap_path(self) -> None:
        recipe = DOCKERFILE.read_text(encoding="utf-8").lower()

        self.assertRegex(
            recipe.splitlines()[0],
            r"^# syntax=docker/dockerfile:1\.7@sha256:[0-9a-f]{64}$",
        )
        self.assertNotIn("apt-get upgrade", recipe)
        self.assertNotIn("apt upgrade", recipe)
        self.assertNotIn("qpl", recipe)
        self.assertNotIn("pccs", recipe)
        self.assertNotRegex(recipe, r"from\s+\S+:(latest|main|master)(?:\s|$)")
        self.assertEqual(len(re.findall(r"^from\s+", recipe, re.MULTILINE)), 4)
        external_images = re.findall(
            r"^from\s+(\S+)\s+as\s+(?:rust|toolchain)$", recipe, re.MULTILINE
        )
        self.assertEqual(len(external_images), 2)
        for image in external_images:
            self.assertRegex(image, r"@sha256:[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
