#!/usr/bin/env python3
"""Tests for host-side build-spec validation and immutable release identity."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / "scripts/release/reproducible_build_inputs.py"
BUILD_SPEC_PATH = REPO_ROOT / "release/reproducible-elf-build-v1.json"


def load_module():
    spec = importlib.util.spec_from_file_location("reproducible_build_inputs", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


build_inputs = load_module()


class ReproducibleBuildInputsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.repo = Path(self.tempdir.name)
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "config", "user.email", "release@example.test"],
            check=True,
        )
        subprocess.run(
            ["git", "-C", str(self.repo), "config", "user.name", "Release Test"],
            check=True,
        )
        (self.repo / "source").write_text("first\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "add", "source"], check=True)
        subprocess.run(
            ["git", "-C", str(self.repo), "commit", "-q", "-m", "first"], check=True
        )
        self.first = subprocess.run(
            ["git", "-C", str(self.repo), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()

    def test_ambient_tags_do_not_change_commit_identity(self) -> None:
        before = build_inputs.resolve_release_identity(self.repo, None)
        subprocess.run(["git", "-C", str(self.repo), "tag", "v99.0.0"], check=True)
        after = build_inputs.resolve_release_identity(self.repo, None)
        self.assertEqual(before, after)
        self.assertEqual(after["release_tag"], f"commit-{self.first}")
        self.assertEqual(after["source_describe"], after["release_tag"])

    def test_explicit_tag_must_resolve_to_head(self) -> None:
        subprocess.run(["git", "-C", str(self.repo), "tag", "v1.0.0"], check=True)
        identity = build_inputs.resolve_release_identity(self.repo, "v1.0.0")
        self.assertEqual(identity["release_tag"], "v1.0.0")
        self.assertEqual(identity["source_describe"], "v1.0.0")

        (self.repo / "source").write_text("second\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qam", "second"], check=True)
        with self.assertRaisesRegex(ValueError, "not HEAD"):
            build_inputs.resolve_release_identity(self.repo, "v1.0.0")

    def test_mutable_builder_is_rejected_by_host_loader(self) -> None:
        spec = json.loads(BUILD_SPEC_PATH.read_text(encoding="utf-8"))
        spec["builder"]["base_images"][0] = "rust:latest"
        path = self.repo / "invalid-spec.json"
        path.write_text(json.dumps(spec), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "sha256-pinned"):
            build_inputs.load_and_validate_build_spec(path)

    def test_project_toolchain_alignment_is_required_by_host_loader(self) -> None:
        loaded = build_inputs.load_and_validate_build_spec(
            BUILD_SPEC_PATH,
            repo_root=REPO_ROOT,
        )
        self.assertEqual(
            loaded["project_toolchain"],
            "release/project-toolchain-v1.json",
        )

    def test_production_enclave_has_exact_production_dcap_release_feature(self) -> None:
        loaded = build_inputs.load_and_validate_build_spec(BUILD_SPEC_PATH)
        enclave = next(
            artifact
            for artifact in loaded["artifacts"]
            if artifact["role"] == "tee-enclave"
        )

        self.assertEqual(enclave["features"], ["production-dcap-release"])

    def test_feature_matrix_rejects_missing_extra_or_non_enclave_features(self) -> None:
        base = json.loads(BUILD_SPEC_PATH.read_text(encoding="utf-8"))
        enclave = next(
            artifact for artifact in base["artifacts"] if artifact["role"] == "tee-enclave"
        )
        cases = (
            (enclave, []),
            (enclave, ["production-dcap-release", "dcap-fixture-capture"]),
            (base["artifacts"][0], ["production-dcap-release"]),
        )
        for artifact, features in cases:
            changed = json.loads(json.dumps(base))
            target = next(
                item for item in changed["artifacts"] if item["name"] == artifact["name"]
            )
            target["features"] = features
            path = self.repo / f"invalid-{artifact['name']}-{len(features)}.json"
            path.write_text(json.dumps(changed), encoding="utf-8")
            with self.subTest(artifact=artifact["name"], features=features):
                with self.assertRaisesRegex(ValueError, "feature"):
                    build_inputs.load_and_validate_build_spec(path)

    def test_enclave_dependency_graph_disables_outbe_tee_defaults(self) -> None:
        metadata = json.loads(
            subprocess.run(
                [
                    "cargo",
                    "metadata",
                    "--locked",
                    "--offline",
                    "--no-deps",
                    "--format-version",
                    "1",
                ],
                cwd=REPO_ROOT,
                check=True,
                capture_output=True,
                text=True,
            ).stdout
        )
        enclave = next(
            package for package in metadata["packages"] if package["name"] == "outbe-tee-enclave"
        )
        tee = next(
            dependency for dependency in enclave["dependencies"] if dependency["name"] == "outbe-tee"
        )

        self.assertIs(tee["uses_default_features"], False)

    def test_artifact_build_plan_isolated_native_dcap_to_the_enclave_binary(self) -> None:
        loaded = build_inputs.load_and_validate_build_spec(BUILD_SPEC_PATH)

        plan = build_inputs.artifact_build_plan(loaded)

        self.assertEqual(len(plan), 2)
        common = [
            "cargo",
            "build",
            "--locked",
            "--release",
            "--no-default-features",
            "--target",
            "x86_64-unknown-linux-gnu",
        ]
        without_features = [
            artifact
            for artifact in loaded["artifacts"]
            if artifact["features"] == []
        ]
        expected_without_features = common.copy()
        for artifact in without_features:
            expected_without_features.extend(
                ["--package", artifact["package"], "--bin", artifact["name"]]
            )
        self.assertEqual(plan[0], expected_without_features)
        self.assertEqual(
            plan[1],
            common
            + [
                "--package",
                "outbe-tee-enclave",
                "--bin",
                "outbe-tee-enclave",
                "--features",
                "production-dcap-release",
            ],
        )
        for command in plan:
            self.assertNotIn("--all-features", command)
            self.assertNotIn("--all-targets", command)


if __name__ == "__main__":
    unittest.main()
