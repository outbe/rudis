#!/usr/bin/env python3
"""Behavioral tests for the native-QVL artifact contract verifier."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[3]
VERIFIER_PATH = REPO_ROOT / "scripts/release/verify_dcap_native_qvl.py"


def load_verifier():
    spec = importlib.util.spec_from_file_location("verify_dcap_native_qvl", VERIFIER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {VERIFIER_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verifier = load_verifier()


class NativeQvlManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.artifacts = []
        for index, expected in enumerate(verifier.EXPECTED_ARTIFACTS):
            role = expected["role"]
            payload = f"artifact-{role}".encode()
            path = f"/native/{index}"
            target = self.root / path.removeprefix("/")
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            artifact = dict(expected)
            artifact["path"] = path
            artifact["size"] = len(payload)
            artifact["sha256"] = hashlib.sha256(payload).hexdigest()
            self.artifacts.append(artifact)
        header_payload = b"pinned-sgx-qve-header"
        header_path = "/native/sgx_qve_header.h"
        header_target = self.root / header_path.removeprefix("/")
        header_target.write_bytes(header_payload)
        self.build_inputs = [
            {
                **verifier.EXPECTED_BUILD_INPUTS[0],
                "path": header_path,
                "size": len(header_payload),
                "sha256": hashlib.sha256(header_payload).hexdigest(),
            }
        ]
        self.manifest = {
            "schema_version": 1,
            "status": verifier.EXPECTED_STATUS,
            "target": "x86_64-unknown-linux-gnu",
            "gramine_version": "1.9",
            "intel_dcap": dict(verifier.EXPECTED_DCAP),
            "build_inputs": self.build_inputs,
            "artifacts": self.artifacts,
        }

    def verify_synthetic_manifest(self, manifest=None) -> None:
        with (
            mock.patch.object(verifier, "EXPECTED_ARTIFACTS", tuple(self.artifacts)),
            mock.patch.object(
                verifier, "EXPECTED_BUILD_INPUTS", tuple(self.build_inputs)
            ),
        ):
            verifier.verify_manifest(manifest or self.manifest, self.root)

    def test_exact_artifacts_and_boundary_pass(self) -> None:
        self.verify_synthetic_manifest()

    def test_repository_contract_is_release_active(self) -> None:
        manifest = json.loads(
            (REPO_ROOT / "release/dcap-native-qvl-v1.json").read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["status"], "active")

    def test_expected_package_versions_come_from_the_project_pin(self) -> None:
        pin = copy.deepcopy(verifier.PROJECT_VERSION_PIN)
        pin["system_packages"]["libsgx-dcap-quote-verify"] = "test-qvl-version"
        pin["system_packages"]["libstdc++6"] = "test-cxx-version"

        self.assertEqual(
            verifier.expected_dcap(pin)["runtime_package_version"],
            "test-qvl-version",
        )
        self.assertEqual(
            verifier.expected_artifacts(pin)[1]["package_version"],
            "test-cxx-version",
        )
        build_inputs = verifier.expected_build_inputs(pin)
        self.assertEqual(
            build_inputs[0]["package_version"],
            pin["system_packages"]["libsgx-dcap-quote-verify-dev"],
        )
        self.assertEqual(
            build_inputs[1]["package_version"],
            pin["system_packages"]["libsgx-headers"],
        )

    def test_changed_qvl_header_fails_closed(self) -> None:
        (self.root / "native/sgx_qve_header.h").write_bytes(b"substituted")
        with self.assertRaisesRegex(ValueError, "build input size mismatch"):
            self.verify_synthetic_manifest()

    def test_missing_qvl_header_contract_fails_closed(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["build_inputs"] = []
        with self.assertRaisesRegex(ValueError, "build input metadata"):
            self.verify_synthetic_manifest(changed)

    def test_verified_artifacts_install_under_exact_contract_names(self) -> None:
        destination = self.root / "bundle-qvl"
        with (
            mock.patch.object(verifier, "EXPECTED_ARTIFACTS", tuple(self.artifacts)),
            mock.patch.object(
                verifier, "EXPECTED_BUILD_INPUTS", tuple(self.build_inputs)
            ),
        ):
            verifier.install_verified_artifacts(
                self.manifest,
                self.root,
                destination,
            )

        self.assertEqual(
            sorted(path.name for path in destination.iterdir()),
            sorted(artifact["install_name"] for artifact in self.artifacts),
        )
        for index, artifact in enumerate(self.artifacts):
            self.assertEqual(
                (destination / artifact["install_name"]).read_bytes(),
                f"artifact-{artifact['role']}".encode(),
            )
            self.assertEqual(
                (destination / artifact["install_name"]).stat().st_mode & 0o777,
                0o644,
                f"unexpected mode for artifact {index}",
            )

    def test_install_rejects_a_nonempty_destination(self) -> None:
        destination = self.root / "bundle-qvl"
        destination.mkdir()
        (destination / "uncontracted.so").write_bytes(b"host substitution")

        with (
            mock.patch.object(verifier, "EXPECTED_ARTIFACTS", tuple(self.artifacts)),
            mock.patch.object(
                verifier, "EXPECTED_BUILD_INPUTS", tuple(self.build_inputs)
            ),
            self.assertRaisesRegex(ValueError, "destination must be empty"),
        ):
            verifier.install_verified_artifacts(
                self.manifest,
                self.root,
                destination,
            )

    def test_changed_artifact_fails_closed(self) -> None:
        (self.root / "native/0").write_bytes(b"substituted")
        with self.assertRaisesRegex(ValueError, "size mismatch"):
            self.verify_synthetic_manifest()

    def test_status_change_fails_closed(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["status"] = "inactive-until-i9"
        with self.assertRaisesRegex(ValueError, "status"):
            self.verify_synthetic_manifest(changed)

    def test_qve_or_qpl_boundary_change_fails_closed(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["intel_dcap"]["qve_enabled"] = True
        with self.assertRaisesRegex(ValueError, "Intel DCAP metadata"):
            self.verify_synthetic_manifest(changed)

        changed = copy.deepcopy(self.manifest)
        changed["intel_dcap"]["qpl_or_pccs_during_consensus"] = True
        with self.assertRaisesRegex(ValueError, "Intel DCAP metadata"):
            self.verify_synthetic_manifest(changed)

    def test_package_or_build_id_change_fails_closed(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["intel_dcap"]["development_package_version"] = "substituted"
        with self.assertRaisesRegex(ValueError, "Intel DCAP metadata"):
            self.verify_synthetic_manifest(changed)

        changed = copy.deepcopy(self.manifest)
        changed["artifacts"][0]["elf_build_id"] = "substituted"
        with self.assertRaisesRegex(ValueError, "artifact metadata"):
            self.verify_synthetic_manifest(changed)


if __name__ == "__main__":
    unittest.main()
