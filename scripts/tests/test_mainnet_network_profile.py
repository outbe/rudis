#!/usr/bin/env python3

import importlib.util
import tempfile
import types
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "scripts" / "prepare_network.py"
SPEC = importlib.util.spec_from_file_location("prepare_network", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
PN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PN)


class MainnetNetworkProfileTests(unittest.TestCase):
    def test_mainnet_profile_is_canonical(self) -> None:
        self.assertEqual(
            PN.resolve_network_profile("mainnet", 676, "dcap-required"),
            ("mainnet", 676, "outbe-mainnet-1"),
        )

    def test_mainnet_profile_rejects_mismatch_and_unknown_ids(self) -> None:
        with self.assertRaisesRegex(ValueError, "mainnet.*676"):
            PN.resolve_network_profile("mainnet", 70860602, "dcap-required")
        with self.assertRaisesRegex(ValueError, "unknown Outbe chain id"):
            PN.resolve_network_profile(None, 999999, "dcap-required")

    def test_mainnet_rejects_key_generation_private_export_and_local_defaults(self) -> None:
        for field in (
            "generate_validators",
            "include_private_keys",
            "use_local_defaults",
            "force_reth_secrets",
        ):
            args = types.SimpleNamespace(
                generate_validators=None,
                include_private_keys=False,
                use_local_defaults=False,
                force_reth_secrets=False,
            )
            setattr(args, field, 4 if field == "generate_validators" else True)
            with self.assertRaisesRegex(ValueError, field.replace("_", "-")):
                PN.validate_mainnet_options(args)

    def test_mainnet_requires_operator_owned_ocomp_material(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            material = Path(tmp)
            for index in range(4):
                (material / f"validator-{index}").mkdir()
            with self.assertRaisesRegex(ValueError, "OCOMP material"):
                PN.require_mainnet_ocomp_material(material, 4)


if __name__ == "__main__":
    unittest.main()
