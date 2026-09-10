#!/usr/bin/env python3
"""Normalization tests for the two Intel PCS v3 collateral encodings."""

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


class CaptureDcapCollateralVersionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.capture = load_capture()

    def test_v3_0_hex_crl_is_normalized_to_raw_der(self) -> None:
        raw_der = bytes.fromhex("3003020101")
        self.assertEqual(
            self.capture.canonical_crl_component(
                raw_der.hex().encode("ascii") + b"\0", 0, "test CRL"
            ),
            raw_der,
        )

    def test_v3_1_raw_crl_is_preserved(self) -> None:
        raw_der = bytes.fromhex("3003020101")
        self.assertEqual(
            self.capture.canonical_crl_component(raw_der, 1, "test CRL"),
            raw_der,
        )

    def test_unknown_minor_and_noncanonical_hex_fail_closed(self) -> None:
        for value, minor in ((b"300\0", 0), (b"zz\0", 0), (b"\x30\x00", 2)):
            with self.subTest(value=value, minor=minor):
                with self.assertRaises(ValueError):
                    self.capture.canonical_crl_component(value, minor, "test CRL")


if __name__ == "__main__":
    unittest.main()
