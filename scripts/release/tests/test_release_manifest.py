#!/usr/bin/env python3
"""Behavioral tests for the versioned Outbe ReleaseManifest contract."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError


REPO_ROOT = Path(__file__).resolve().parents[3]
GENERATOR_PATH = REPO_ROOT / "scripts/release/generate_release_manifest.py"
SCHEMA_PATH = REPO_ROOT / "release/release-manifest-v1.schema.json"
BUILD_SPEC_PATH = REPO_ROOT / "release/reproducible-elf-build-v1.json"


def load_generator():
    spec = importlib.util.spec_from_file_location("release_manifest", GENERATOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {GENERATOR_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


release_manifest = load_generator()


class ReleaseManifestTests(unittest.TestCase):
    maxDiff = None

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.artifact_dir = self.root / "artifacts"
        self.artifact_dir.mkdir()
        self.input_dir = self.root / "source"
        self.input_dir.mkdir()

        self.spec = {
            "spec_version": 1,
            "target": "x86_64-unknown-linux-gnu",
            "profile": "release",
            "rust_toolchain": "1.96.0",
            "builder": {
                "id": "https://github.com/outbe/outbe-chain/reproducible-elf-builder/v1",
                "base_images": [
                    "rust:1.96.0-bookworm@sha256:" + "1" * 64,
                    "gramineproject/gramine:1.9-noble@sha256:" + "2" * 64,
                ],
                "recipe": "Dockerfile.project-toolchain",
                "system_packages": ["clang=1.0", "cmake=1.0"],
            },
            "environment": {
                "cflags": "-ffile-prefix-map=/workspace=/usr/src/outbe-chain",
                "cxxflags": "-ffile-prefix-map=/workspace=/usr/src/outbe-chain",
                "locale": "C",
                "timezone": "UTC",
                "rustflags": ["--remap-path-prefix=/workspace=.", "-C", "link-arg=-Wl,--build-id=sha1"],
                "zero_ar_date": "1",
            },
            "cargo": {"auditable": False, "locked": True},
            "inputs": ["Cargo.lock", "rust-toolchain.toml"],
            "artifacts": [
                {
                    "name": "outbe-chain",
                    "package": "outbe-chain",
                    "role": "node",
                    "classification": "production",
                    "features": [],
                    "install_profiles": ["full-node", "validator"],
                },
                {
                    "name": "outbe-tee-enclave",
                    "package": "outbe-tee-enclave",
                    "role": "tee-enclave",
                    "classification": "production",
                    "features": ["production-dcap-release"],
                    "install_profiles": ["full-node", "validator"],
                },
            ],
        }
        (self.input_dir / "Cargo.lock").write_bytes(b"locked\n")
        (self.input_dir / "rust-toolchain.toml").write_bytes(b"1.96.0\n")
        (self.artifact_dir / "outbe-chain").write_bytes(b"chain-elf")
        (self.artifact_dir / "outbe-tee-enclave").write_bytes(b"enclave-elf")

    def build(self, **overrides):
        kwargs = {
            "build_spec": self.spec,
            "source_root": self.input_dir,
            "artifact_dir": self.artifact_dir,
            "release_tag": "v0.1.0-test",
            "source_commit": "a" * 40,
            "source_date_epoch": 1_784_000_000,
            "lifecycle": "build-candidate",
            "verification_gates": [],
        }
        kwargs.update(overrides)
        return release_manifest.build_manifest(**kwargs)

    @staticmethod
    def network_identity(network: str) -> dict:
        if network == "mainnet":
            chain_id = 676
            chain_name = "outbe-mainnet-1"
            genesis_path = "mainnet-genesis.json"
        elif network == "testnet":
            chain_id = 70_860_602
            chain_name = "rudis-rehearsal"
            genesis_path = "testnet-genesis.json"
        else:
            raise AssertionError(f"unsupported fixture network: {network}")
        return {
            "chain_id": chain_id,
            "chain_name": chain_name,
            "genesis_hash": "0x" + "c" * 64,
            "genesis_file": {
                "digest": {"algorithm": "sha256", "value": "d" * 64},
                "path": genesis_path,
                "size": 1,
            },
        }

    def test_manifest_is_canonical_and_validates_against_schema(self) -> None:
        manifest = self.build()
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(manifest)

        first = release_manifest.canonical_json(manifest)
        second = release_manifest.canonical_json(self.build())
        self.assertEqual(first, second)
        self.assertEqual(
            hashlib.sha256(first).hexdigest(),
            "cdb3718fc6b60e09d232bcdcbd22b97c80d33b61a25d4b414d750a408aed4bc4",
        )
        self.assertTrue(first.endswith(b"\n"))
        self.assertNotIn(str(self.root).encode(), first)

    def test_missing_artifact_fails_closed(self) -> None:
        (self.artifact_dir / "outbe-chain").unlink()
        with self.assertRaisesRegex(ValueError, "missing release artifact: outbe-chain"):
            self.build()

    def test_production_enclave_rejects_mock_feature(self) -> None:
        self.spec["artifacts"][1]["features"] = ["mock"]
        with self.assertRaisesRegex(ValueError, "production enclave.*mock"):
            self.build()

    def test_production_enclave_rejects_compiled_test_or_dev_marker(self) -> None:
        path = self.artifact_dir / "outbe-tee-enclave"
        path.write_bytes(path.read_bytes() + b"outbe-tee-enclave-mock: MOCK ENCLAVE")
        with self.assertRaisesRegex(ValueError, "forbidden test/dev marker"):
            self.build()

    def test_production_enclave_requires_exact_production_dcap_release_feature(self) -> None:
        self.spec["artifacts"][1]["features"] = []
        with self.assertRaisesRegex(ValueError, "exactly production-dcap-release"):
            self.build()

    def test_non_enclave_artifact_rejects_application_features(self) -> None:
        self.spec["artifacts"][0]["features"] = ["production-dcap-release"]
        with self.assertRaisesRegex(ValueError, "non-enclave release artifacts"):
            self.build()

    def test_unsupported_release_architecture_fails_closed(self) -> None:
        self.spec["target"] = "aarch64-unknown-linux-gnu"
        with self.assertRaisesRegex(ValueError, "unsupported release target"):
            self.build()

    def test_production_enclave_identity_is_exact(self) -> None:
        self.spec["artifacts"][1]["package"] = "replacement-enclave"
        with self.assertRaisesRegex(ValueError, "package and binary"):
            self.build()

    def test_input_path_cannot_escape_source_root(self) -> None:
        self.spec["inputs"] = ["../outside"]
        with self.assertRaisesRegex(ValueError, "input path escapes source root"):
            self.build()

    def test_changed_source_identity_changes_canonical_manifest(self) -> None:
        first = release_manifest.canonical_json(self.build())
        second = release_manifest.canonical_json(self.build(source_commit="b" * 40))
        self.assertNotEqual(first, second)

    def test_signed_tee_artifact_requires_complete_measurement_identity(self) -> None:
        manifest = self.build()
        signed = copy.deepcopy(manifest["artifacts"][1])
        signed.update(
            {
                "kind": "archive",
                "media_type": "application/x-tar",
                "name": "outbe-tee-enclave-sgx-bundle",
                "path": "release/outbe-tee-enclave-sgx.tar",
                "tee": {
                    "authorization_scope": "testnet",
                    "isv_prod_id": 1,
                    "isv_svn": 1,
                    "mock": False,
                    "mrenclave": "a" * 64,
                    "mrsigner": "b" * 64,
                    "sealed_state_schema": 1,
                    "stage": "signed",
                },
            }
        )
        manifest["artifacts"].append(signed)
        manifest["network"] = self.network_identity("testnet")
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator(schema).validate(manifest)

        del signed["tee"]["mrsigner"]
        with self.assertRaises(ValidationError):
            Draft202012Validator(schema).validate(manifest)

    def test_signed_release_network_and_provenance_identity_are_atomic(self) -> None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        for network in ("testnet", "mainnet"):
            manifest = self.build()
            manifest["network"] = self.network_identity(network)
            workflow = f".github/workflows/{network}-release.yml"
            manifest["build"]["provenance"].update(
                {
                    "mode": "github-actions",
                    "workflow": workflow,
                    "certificate_identity": (
                        "https://github.com/outbe/outbe-chain/"
                        f".github/workflows/{network}-release.yml@refs/heads/main"
                    ),
                    "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
                    "certificate_workflow_sha": "a" * 40,
                }
            )
            signed = copy.deepcopy(manifest["artifacts"][1])
            signed["tee"] = {
                "authorization_scope": network,
                "isv_prod_id": 1,
                "isv_svn": 1,
                "mock": False,
                "mrenclave": "a" * 64,
                "mrsigner": "b" * 64,
                "sealed_state_schema": 1,
                "stage": "signed",
            }
            manifest["artifacts"].append(signed)
            Draft202012Validator(schema).validate(manifest)

            mixed = copy.deepcopy(manifest)
            mixed["artifacts"][-1]["tee"]["authorization_scope"] = (
                "mainnet" if network == "testnet" else "testnet"
            )
            with self.assertRaises(ValidationError):
                Draft202012Validator(schema).validate(mixed)

            mixed = copy.deepcopy(manifest)
            foreign = "mainnet" if network == "testnet" else "testnet"
            mixed["build"]["provenance"]["workflow"] = (
                f".github/workflows/{foreign}-release.yml"
            )
            with self.assertRaises(ValidationError):
                Draft202012Validator(schema).validate(mixed)

    def test_github_actions_provenance_requires_certificate_binding(self) -> None:
        manifest = self.build()
        manifest["build"]["provenance"]["mode"] = "github-actions"
        manifest["build"]["provenance"]["workflow"] = (
            ".github/workflows/testnet-release.yml"
        )
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        with self.assertRaises(ValidationError):
            Draft202012Validator(schema).validate(manifest)

        manifest["build"]["provenance"].update(
            {
                "certificate_identity": (
                    "https://github.com/outbe/outbe-chain/.github/workflows/"
                    "testnet-release.yml@refs/heads/main"
                ),
                "certificate_oidc_issuer": "https://token.actions.githubusercontent.com",
                "certificate_workflow_sha": "a" * 40,
            }
        )
        Draft202012Validator(schema).validate(manifest)

        manifest["build"]["provenance"]["certificate_identity"] = (
            "https://github.com/outbe/outbe-chain/untrusted-workflow"
        )
        with self.assertRaises(ValidationError):
            Draft202012Validator(schema).validate(manifest)

    def test_verified_lifecycle_requires_github_actions_provenance(self) -> None:
        manifest = self.build(lifecycle="verified")
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        with self.assertRaises(ValidationError):
            Draft202012Validator(schema).validate(manifest)


class RepositoryBuildSpecTests(unittest.TestCase):
    def test_spec_declares_exact_current_release_elf_matrix(self) -> None:
        spec = json.loads(BUILD_SPEC_PATH.read_text(encoding="utf-8"))
        artifacts = spec["artifacts"]
        self.assertEqual(
            [artifact["name"] for artifact in artifacts],
            [
                "outbe-chain",
                "outbe-cli",
                "outbe-keygen",
                "outbe-feeder",
                "outbe-tee-enclave",
                "outbe-ocomp",
            ],
        )
        enclave = next(artifact for artifact in artifacts if artifact["role"] == "tee-enclave")
        self.assertEqual(enclave["classification"], "production")
        self.assertNotIn("mock", enclave["features"])
        self.assertIs(spec["cargo"]["auditable"], False)
        self.assertIn("release/reproducible-verifier-requirements.txt", spec["inputs"])
        self.assertIn("release/dcap-native-qvl-v1.json", spec["inputs"])
        self.assertIn("scripts/release/verify_dcap_native_qvl.py", spec["inputs"])
        self.assertIn("scripts/release/verify_reproducible_elf.py", spec["inputs"])


if __name__ == "__main__":
    unittest.main()
