#!/usr/bin/env python3
"""Public parser tests for capture-only Intel DCAP collateral acquisition."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
CAPTURE_PATH = REPO_ROOT / "scripts/release/capture_dcap_collateral.py"


def load_capture():
    spec = importlib.util.spec_from_file_location("capture_dcap_collateral", CAPTURE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {CAPTURE_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CaptureDcapCollateralTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.capture = load_capture()

    def test_text_collateral_requires_one_terminal_nul(self) -> None:
        self.assertEqual(
            self.capture.canonical_text_component(b'{"value":1}\0', "test"),
            b'{"value":1}',
        )
        for malformed in (b'{"value":1}', b'{"value":\0}\0', b'{"value":1}\0\0'):
            with self.subTest(malformed=malformed):
                with self.assertRaises(ValueError):
                    self.capture.canonical_text_component(malformed, "test")

    def test_host_qpl_must_match_the_single_project_pin(self) -> None:
        pin = self.capture.load_host_qpl_pin()

        self.assertEqual(pin["package"], "libsgx-dcap-default-qpl")
        self.assertEqual(pin["version"], "1.26.100.1-noble1")


if __name__ == "__main__":
    unittest.main()
