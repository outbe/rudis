#!/usr/bin/env python3
"""Tests for the two-build reproducibility verifier."""

from __future__ import annotations

import importlib.util
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


generator = load_module(
    "release_manifest_for_verifier_tests",
    REPO_ROOT / "scripts/release/generate_release_manifest.py",
)
verifier = load_module(
    "verify_reproducible_elf",
    REPO_ROOT / "scripts/release/verify_reproducible_elf.py",
)


class ReproducibleElfVerifierTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        root = Path(self.tempdir.name)
        self.first = root / "first"
        self.second = root / "second"
        (self.first / "bin").mkdir(parents=True)
        (self.first / "metadata").mkdir()

        self.build_spec = json.loads(
            (REPO_ROOT / "release/reproducible-elf-build-v1.json").read_text(encoding="utf-8")
        )
        for index, artifact in enumerate(self.build_spec["artifacts"]):
            (self.first / "bin" / artifact["name"]).write_bytes(
                b"\x7fELF" + bytes([index]) + b"deterministic-test"
            )
        packages = self.first / "metadata/builder-system-packages.txt"
        packages.write_text("example=1.0\n", encoding="utf-8")
        version_text = "\n".join(
            [
                "Outbe 0.1.0 (test)",
                "Version: 0.1.0",
                f"Commit SHA: {'a' * 40}",
                "Build Timestamp: 2026-07-14T03:33:20.000000000Z",
                "Build Features: no features enabled",
                "Build Profile: release (x86_64-unknown-linux-gnu)",
                "",
                "Reth Version: test",
                f"Commit SHA: {'a' * 40}",
                "Build Timestamp: 2026-07-14T03:33:20.000000000Z",
                "Build Features:",
                "Build Profile: release",
                "",
            ]
        )
        (self.first / "metadata/outbe-chain.version.txt").write_text(
            version_text, encoding="utf-8"
        )
        shutil.copy2(
            REPO_ROOT / "release/release-manifest-v1.schema.json",
            self.first / "metadata/release-manifest-v1.schema.json",
        )
        shutil.copy2(
            REPO_ROOT / "release/reproducible-elf-build-v1.json",
            self.first / "metadata/reproducible-elf-build-v1.json",
        )
        manifest = generator.build_manifest(
            build_spec=self.build_spec,
            source_root=REPO_ROOT,
            artifact_dir=self.first / "bin",
            release_tag="test-rebuild",
            source_commit="a" * 40,
            source_date_epoch=1_784_000_000,
            lifecycle="build-candidate",
            verification_gates=[],
            resolved_system_packages=packages,
        )
        (self.first / "release-manifest.json").write_bytes(generator.canonical_json(manifest))
        self._write_checksums(self.first)
        shutil.copytree(self.first, self.second)

    @staticmethod
    def _write_checksums(output: Path) -> None:
        rows = []
        for relative in sorted(verifier.EXPECTED_CHECKSUM_PATHS):
            digest = hashlib.sha256((output / relative).read_bytes()).hexdigest()
            rows.append(f"{digest}  {relative}\n")
        (output / "SHA256SUMS").write_text("".join(rows), encoding="ascii")

    def test_identical_outputs_pass_with_per_artifact_evidence(self) -> None:
        evidence = verifier.verify_outputs(self.first, self.second, REPO_ROOT)
        self.assertEqual(evidence["result"], "passed")
        self.assertEqual(len(evidence["artifacts"]), 6)
        self.assertEqual(evidence["differences"], [])

    def test_changed_artifact_fails_with_named_difference(self) -> None:
        with (self.second / "bin/outbe-cli").open("ab") as output:
            output.write(b"changed")
        evidence = verifier.verify_outputs(self.first, self.second, REPO_ROOT)
        self.assertEqual(evidence["result"], "failed")
        self.assertTrue(any("outbe-cli" in difference for difference in evidence["differences"]))

    def test_embedded_builder_path_is_rejected_even_when_builds_match(self) -> None:
        for output in (self.first, self.second):
            path = output / "bin/outbe-feeder"
            path.write_bytes(path.read_bytes() + b"/workspace/secret")
            manifest = generator.build_manifest(
                build_spec=self.build_spec,
                source_root=REPO_ROOT,
                artifact_dir=output / "bin",
                release_tag="test-rebuild",
                source_commit="a" * 40,
                source_date_epoch=1_784_000_000,
                lifecycle="build-candidate",
                verification_gates=[],
            )
            (output / "release-manifest.json").write_bytes(generator.canonical_json(manifest))
        evidence = verifier.verify_outputs(self.first, self.second, REPO_ROOT)
        self.assertEqual(evidence["result"], "failed")
        self.assertTrue(any("forbidden absolute build path" in item for item in evidence["differences"]))

    def test_compiled_test_or_dev_marker_is_rejected_even_when_builds_match(self) -> None:
        for output in (self.first, self.second):
            path = output / "bin/outbe-tee-enclave"
            path.write_bytes(path.read_bytes() + b"outbe-tee-enclave-mock: MOCK ENCLAVE")
            self._write_checksums(output)
        evidence = verifier.verify_outputs(self.first, self.second, REPO_ROOT)
        self.assertEqual(evidence["result"], "failed")
        self.assertTrue(
            any("forbidden production TEE marker" in item for item in evidence["differences"])
        )

    def test_build_spec_remaps_cargo_git_checkout_paths(self) -> None:
        environment = self.build_spec["environment"]
        rustflags = environment["rustflags"]
        expected_rust_remap = "--remap-path-prefix=/usr/local/cargo/git=/cargo/git"
        expected_native_remap = "-ffile-prefix-map=/usr/local/cargo/git=/cargo/git"

        self.assertIn(expected_rust_remap, rustflags)
        self.assertIn(expected_native_remap, environment["cflags"])
        self.assertIn(expected_native_remap, environment["cxxflags"])

    def test_changed_resolved_package_inventory_is_rejected(self) -> None:
        (self.second / "metadata/builder-system-packages.txt").write_text(
            "example=2.0\n", encoding="utf-8"
        )
        evidence = verifier.verify_outputs(self.first, self.second, REPO_ROOT)
        self.assertEqual(evidence["result"], "failed")
        self.assertTrue(any("package inventory" in item for item in evidence["differences"]))

    def test_changed_version_identity_is_rejected(self) -> None:
        path = self.second / "metadata/outbe-chain.version.txt"
        path.write_text(path.read_text(encoding="utf-8").replace("release (", "debug ("))
        evidence = verifier.verify_outputs(self.first, self.second, REPO_ROOT)
        self.assertEqual(evidence["result"], "failed")
        self.assertTrue(any("version identity mismatch" in item for item in evidence["differences"]))


if __name__ == "__main__":
    unittest.main()
