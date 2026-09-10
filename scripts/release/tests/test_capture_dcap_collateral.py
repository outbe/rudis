#!/usr/bin/env python3
"""Public parser tests for capture-only Intel DCAP collateral acquisition."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]
CAPTURE_PATH = REPO_ROOT / "scripts/release/capture_dcap_collateral.py"
QUOTE_PATH = (
    REPO_ROOT
    / "crates/system/tee/tests/fixtures/intel-dcap-1.26/sgx-processor-quote-v3.bin"
)
CRL_FIXTURE_ROOT = (
    REPO_ROOT
    / "crates/system/tee/tests/fixtures/intel-dcap-1.26-intent-bound-processor"
)


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
        cls.quote = QUOTE_PATH.read_bytes()

    def test_extracts_the_exact_type_five_pck_chain(self) -> None:
        pck_chain = self.capture.extract_type5_pck_chain(self.quote)

        self.assertTrue(pck_chain.startswith(b"-----BEGIN CERTIFICATE-----\n"))
        self.assertTrue(pck_chain.endswith(b"\0"))
        self.assertEqual(pck_chain.count(b"-----BEGIN CERTIFICATE-----"), 3)
        self.assertNotIn(b"\0", pck_chain[:-1])

    def test_quote_parser_rejects_bytes_after_the_declared_quote(self) -> None:
        with self.assertRaisesRegex(ValueError, "trailing"):
            self.capture.extract_type5_pck_chain(self.quote + b"\xa5")

    def test_text_collateral_requires_one_terminal_nul(self) -> None:
        self.assertEqual(
            self.capture.canonical_text_component(b'{"value":1}\0', "test"),
            b'{"value":1}',
        )
        for malformed in (b'{"value":1}', b'{"value":\0}\0', b'{"value":1}\0\0'):
            with self.subTest(malformed=malformed):
                with self.assertRaises(ValueError):
                    self.capture.canonical_text_component(malformed, "test")

    def test_crl_provenance_records_issuer_type_and_validity(self) -> None:
        metadata = self.capture.crl_provenance(
            CRL_FIXTURE_ROOT / "pck.crl.der", "processor"
        )

        self.assertEqual(metadata["type"], "processor")
        self.assertIn("Intel SGX PCK Processor CA", metadata["issuer"])
        self.assertEqual(metadata["this_update"], "2026-08-26T23:46:46Z")
        self.assertEqual(metadata["next_update"], "2026-09-25T23:46:46Z")
        self.assertGreater(metadata["size"], 0)
        self.assertRegex(metadata["sha256"], r"^[0-9a-f]{64}$")

    def test_host_qpl_must_match_the_single_project_pin(self) -> None:
        pin = self.capture.load_host_qpl_pin()

        self.assertEqual(pin["package"], "libsgx-dcap-default-qpl")
        self.assertEqual(pin["version"], "1.26.100.1-noble1")


if __name__ == "__main__":
    unittest.main()
