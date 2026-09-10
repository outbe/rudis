#!/usr/bin/env python3
"""Validate the build spec on the host and resolve one immutable source identity."""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
from pathlib import Path
from typing import Any


def _load_generator_module():
    path = Path(__file__).with_name("generate_release_manifest.py")
    spec = importlib.util.spec_from_file_location("outbe_release_manifest_generator", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load release manifest generator: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


manifest_generator = _load_generator_module()


def _load_project_toolchain_verifier():
    path = Path(__file__).with_name("verify_project_toolchain.py")
    spec = importlib.util.spec_from_file_location("outbe_project_toolchain_verifier", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load project toolchain verifier: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


project_toolchain_verifier = _load_project_toolchain_verifier()
EXPECTED_ARTIFACTS = (
    "outbe-chain",
    "outbe-cli",
    "outbe-keygen",
    "outbe-feeder",
    "outbe-tee-enclave",
    "outbe-ocomp",
)


def load_and_validate_build_spec(
    path: Path,
    *,
    repo_root: Path | None = None,
) -> dict[str, Any]:
    build_spec = json.loads(path.read_text(encoding="utf-8"))
    manifest_generator.validate_build_spec(build_spec)
    names = tuple(artifact.get("name") for artifact in build_spec.get("artifacts", []))
    if names != EXPECTED_ARTIFACTS:
        raise ValueError("build spec must declare the exact production ELF release matrix")
    enclave = next(
        artifact
        for artifact in build_spec["artifacts"]
        if artifact.get("role") == "tee-enclave"
    )
    if enclave.get("classification") != "production":
        raise ValueError("production enclave must be a production ELF subject")
    if enclave.get("features") != ["production-dcap-release"]:
        raise ValueError(
            "production enclave must enable exactly the production-dcap-release application feature"
        )
    for artifact in build_spec["artifacts"]:
        expected_features = ["production-dcap-release"] if artifact is enclave else []
        if artifact.get("features") != expected_features:
            raise ValueError(
                "production ELF feature matrix must isolate production-dcap-release to "
                "outbe-tee-enclave"
            )
    if repo_root is not None:
        project_toolchain_verifier.verify_repository(repo_root)
    return build_spec


def artifact_build_plan(build_spec: dict[str, Any]) -> list[list[str]]:
    """Return exact Cargo invocations grouped only by identical feature sets."""

    target = build_spec["target"]
    common = [
        "cargo",
        "build",
        "--locked",
        "--release",
        "--no-default-features",
        "--target",
        target,
    ]
    cohorts: dict[tuple[str, ...], list[str]] = {}
    for artifact in build_spec["artifacts"]:
        features = tuple(artifact["features"])
        command = cohorts.setdefault(features, common.copy())
        command.extend(
            ("--package", artifact["package"], "--bin", artifact["name"])
        )
    for features, command in cohorts.items():
        if features:
            command.extend(("--features", ",".join(features)))
    return list(cohorts.values())


def execute_artifact_build_plan(build_spec: dict[str, Any]) -> None:
    for command in artifact_build_plan(build_spec):
        subprocess.run(command, check=True)


def _git(repo_root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo_root), *args],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def resolve_release_identity(repo_root: Path, requested_tag: str | None) -> dict[str, str]:
    source_commit = _git(repo_root, "rev-parse", "--verify", "HEAD^{commit}")
    source_date_epoch = _git(repo_root, "show", "-s", "--format=%ct", "HEAD")
    commit_identity = f"commit-{source_commit}"
    release_tag = requested_tag or commit_identity

    if any(ord(character) < 0x20 or ord(character) > 0x7E for character in release_tag):
        raise ValueError("release tag must contain printable ASCII only")
    if release_tag != commit_identity:
        try:
            tag_commit = _git(
                repo_root,
                "rev-parse",
                "--verify",
                f"refs/tags/{release_tag}^{{commit}}",
            )
        except subprocess.CalledProcessError as error:
            raise ValueError(f"release tag does not resolve to a commit: {release_tag}") from error
        if tag_commit != source_commit:
            raise ValueError(
                f"release tag {release_tag} resolves to {tag_commit}, not HEAD {source_commit}"
            )

    return {
        "release_tag": release_tag,
        "source_commit": source_commit,
        "source_date_epoch": source_date_epoch,
        # Never consult ambient local tags.  This exact value is bound as release.tag.
        "source_describe": release_tag,
    }


def resolved_values(
    build_spec: dict[str, Any],
    identity: dict[str, str],
) -> list[str]:
    return [
        " ".join(build_spec["environment"]["rustflags"]),
        build_spec["environment"]["cflags"],
        build_spec["environment"]["cxxflags"],
        identity["source_commit"],
        identity["source_date_epoch"],
        identity["release_tag"],
        identity["source_describe"],
    ]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build-spec", required=True, type=Path)
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--release-tag")
    parser.add_argument("--execute-artifact-build-plan", action="store_true")
    args = parser.parse_args()

    build_spec = load_and_validate_build_spec(args.build_spec, repo_root=args.repo_root)
    if args.execute_artifact_build_plan:
        if args.release_tag is not None:
            parser.error("--release-tag cannot be used with --execute-artifact-build-plan")
        execute_artifact_build_plan(build_spec)
        return
    identity = resolve_release_identity(args.repo_root, args.release_tag)
    for value in resolved_values(build_spec, identity):
        print(value)


if __name__ == "__main__":
    main()
