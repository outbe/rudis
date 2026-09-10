#!/usr/bin/env python3
"""Tests for deterministic outbe-chain version evidence."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
MODULE_PATH = REPO_ROOT / "scripts/release/verify_outbe_chain_version.py"


def load_module():
    spec = importlib.util.spec_from_file_location("verify_outbe_chain_version", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


version = load_module()


class OutbeChainVersionTests(unittest.TestCase):
    def test_exact_commit_time_profile_and_target_pass(self) -> None:
        commit = "a" * 40
        timestamp = "2026-07-15T03:33:20.000000000Z"
        text = (
            f"Commit SHA: {commit}\nBuild Timestamp: {timestamp}\n"
            "Build Features: no features enabled\n"
            "Build Profile: release (x86_64-unknown-linux-gnu)\n"
            f"Commit SHA: {commit}\nBuild Timestamp: {timestamp}\n"
        )
        self.assertEqual(
            version.verify_version_text(
                text,
                source_commit=commit,
                source_date_epoch=1_784_086_400,
                target="x86_64-unknown-linux-gnu",
                profile="release",
            ),
            [],
        )

    def test_wall_clock_or_profile_drift_fails(self) -> None:
        differences = version.verify_version_text(
            "Commit SHA: bad\nBuild Timestamp: now\nBuild Profile: debug\n",
            source_commit="a" * 40,
            source_date_epoch=1_784_086_400,
            target="x86_64-unknown-linux-gnu",
            profile="release",
        )
        self.assertGreaterEqual(len(differences), 3)

    def test_default_feature_drift_fails(self) -> None:
        commit = "a" * 40
        timestamp = "2026-07-15T03:33:20.000000000Z"
        differences = version.verify_version_text(
            (
                f"Commit SHA: {commit}\nBuild Timestamp: {timestamp}\n"
                "Build Features: default\n"
                "Build Profile: release (x86_64-unknown-linux-gnu)\n"
                f"Commit SHA: {commit}\nBuild Timestamp: {timestamp}\n"
            ),
            source_commit=commit,
            source_date_epoch=1_784_086_400,
            target="x86_64-unknown-linux-gnu",
            profile="release",
        )
        self.assertIn(
            "expected one exact Outbe feature line: Build Features: no features enabled",
            differences,
        )


if __name__ == "__main__":
    unittest.main()
