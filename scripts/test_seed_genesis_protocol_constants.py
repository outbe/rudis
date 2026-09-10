import importlib.util
import json
import pathlib
import unittest


MODULE_PATH = pathlib.Path(__file__).with_name("seed_genesis.py")
REPO_ROOT = MODULE_PATH.parents[1]
SEED_PROFILES = {
    "seed-testnet-lowstake.json": {
        "min_stake": "1000000000000000000000",
        "validator_stake": "100000000000000000000000",
    },
    "seed-testnet.json": {
        "min_stake": "100000000000000000000000",
        "validator_stake": "100000000000000000000000",
    },
    "churn-seed.json": {
        "min_stake": "1000000000000000000000",
        "validator_stake": "1000000000000000000000",
    },
}
SPEC = importlib.util.spec_from_file_location("seed_genesis", MODULE_PATH)
seed_genesis = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(seed_genesis)


class ProtocolConstantsSeedTests(unittest.TestCase):
    def test_native_aliases_produce_identical_oracle_state(self):
        states = []
        for alias in ("rudis", "RUDIS", "COEN", "native"):
            storage = seed_genesis.StorageBuilder()
            seed_genesis.seed_oracle(storage, {
                "pairs": [{"base": alias, "quote": "840"}],
                "initial_rates": [{"base": "rudis", "quote": "840", "rate": "1000000"}],
                "scurve_seeds": [{"pair_base": "rudis", "pair_quote": "840", "peak_day": 20260907, "peak_price": "1000000"}],
            })
            states.append(storage.entries)
        for state in states[1:]:
            self.assertEqual(state, states[0])

    def test_oracle_seed_preserves_configured_generic_pair_orientation(self):
        storage = seed_genesis.StorageBuilder()
        token = "0x1111111111111111111111111111111111111111"

        seed_genesis.seed_oracle(
            storage,
            {"pairs": [{"base": token, "quote": "840"}]},
        )

        slot = int(seed_genesis.mapping_key(seed_genesis.u32_bytes(1), 43), 16)
        self.assertEqual(
            storage.entries[seed_genesis.hex32(slot)],
            seed_genesis.hex32(int.from_bytes(seed_genesis.asset_address(token), "big")),
        )
        self.assertEqual(
            storage.entries[seed_genesis.hex32(slot + 1)],
            seed_genesis.hex32(int.from_bytes(seed_genesis.asset_address("840"), "big")),
        )

    def test_oracle_seed_rejects_iso_to_coen_and_inverse_duplicates(self):
        with self.assertRaisesRegex(ValueError, "COEN base"):
            seed_genesis.seed_oracle(
                seed_genesis.StorageBuilder(),
                {"pairs": [{"base": "840", "quote": "COEN"}]},
            )

        with self.assertRaisesRegex(ValueError, "inverted"):
            seed_genesis.seed_oracle(
                seed_genesis.StorageBuilder(),
                {
                    "pairs": [
                        {"base": "840", "quote": "0x1111111111111111111111111111111111111111"},
                        {"base": "0x1111111111111111111111111111111111111111", "quote": "840"},
                    ]
                },
            )

    def test_oracle_seed_rejects_pairs_whose_assets_resolve_to_the_same_address(self):
        token = "0x1111111111111111111111111111111111111111"
        for base, quote in (("COEN", "native"), ("840", "840"), (token, token)):
            with self.subTest(base=base, quote=quote):
                storage = seed_genesis.StorageBuilder()
                with self.assertRaisesRegex(ValueError, "same asset"):
                    seed_genesis.seed_oracle(
                        storage,
                        {"pairs": [{"base": base, "quote": quote}]},
                    )
                self.assertEqual(storage.entries, {})

    def test_checked_in_genesis_fixtures_use_scale18_native_balances(self):
        node_fixture = json.loads(
            (REPO_ROOT / "crates/blockchain/node/tests/assets/genesis.json").read_text()
        )
        node_balances = [entry["balance"] for entry in node_fixture["alloc"].values()]
        self.assertEqual(node_balances.count("0xd3c21bcecceda1000000"), 21)
        self.assertEqual(set(node_balances), {"0x0", "0xd3c21bcecceda1000000"})

        release = json.loads((REPO_ROOT / "release/testnet-genesis.json").read_text())
        self.assertEqual(release["alloc"], {})

    def test_checked_in_seed_profiles_split_native_and_protocol_units(self):
        for filename, staking_expected in SEED_PROFILES.items():
            with self.subTest(filename=filename):
                seed = json.loads(MODULE_PATH.with_name(filename).read_text())

                self.assertEqual(set(seed["balance"].values()), {"1000000000000000000000"})
                self.assertEqual(seed["gems"][0]["promis_load"], "1000000000")
                if filename.startswith("seed-testnet"):
                    # A network profile seeds no worldwide day: the runtime
                    # creates the first one at block 1, and a seeded day gets
                    # no formation record, so reaching MissedOffering would
                    # kill the ProtocolCycle and stop block production.
                    self.assertNotIn("metadosis", seed)
                else:
                    day = seed["metadosis"]["worldwide_days"][0]
                    self.assertEqual(day["current_vwap"], "1000000")
                    self.assertEqual(day["day_limit"], "500000000")
                self.assertEqual(seed["staking"]["min_stake"], staking_expected["min_stake"])
                self.assertEqual(
                    seed["staking"]["genesis_validator_stake"],
                    staking_expected["validator_stake"],
                )
                self.assertEqual(seed["oracle"]["pairs"][0]["initial_rate"], "1000000")
                self.assertEqual(seed["oracle"]["scurve_seeds"][0]["peak_price"], "1000000")

                for nod in seed.get("nods", []):
                    self.assertEqual(nod["gratis_load"], "100000")
                    self.assertEqual(nod["floor_price"], "540000")

    def test_default_reference_and_policy_registries_use_the_frozen_slots(self):
        storage = seed_genesis.StorageBuilder()

        seed_genesis.seed_oracle(storage, {})

        self.assertEqual(storage.entries[seed_genesis.hex32(55)], seed_genesis.hex32(6))
        for index, iso_code in enumerate((156, 344, 392, 826, 840, 978)):
            self.assertEqual(
                storage.entries[seed_genesis.hex32(seed_genesis.data_slot(55) + index)],
                seed_genesis.hex32(iso_code),
            )

        self.assertNotIn(seed_genesis.mapping_key(seed_genesis.u32_bytes(840), 60), storage.entries)
        self.assertEqual(storage.entries[seed_genesis.hex32(74)], seed_genesis.hex32(1))
        self.assertEqual(
            storage.entries[seed_genesis.hex32(seed_genesis.data_slot(74))],
            seed_genesis.hex32(840),
        )
        slot = seed_genesis.mapping_key(seed_genesis.u32_bytes(840), 75)
        self.assertEqual(storage.entries[slot], seed_genesis.hex32(36_300))

    def test_optional_seed_profile_is_copied_to_genesis_config(self):
        genesis = {"config": {"chainId": 1}, "alloc": {}}
        profile = {
            "schemaVersion": 1,
            "metadosis": {"formingPeriodSeconds": 60},
            "ocomp": {"computeVoteWindowBlocks": 120},
        }

        seed_genesis.seed_protocol_constants(genesis, {"protocol_constants": profile})

        self.assertEqual(genesis["config"]["outbeProtocol"], profile)

    def test_absent_profile_preserves_existing_genesis_config(self):
        existing = {"metadosis": {"formingPeriodSeconds": 60}}
        genesis = {"config": {"outbeProtocol": existing}, "alloc": {}}

        seed_genesis.seed_protocol_constants(genesis, {})

        self.assertEqual(genesis["config"]["outbeProtocol"], existing)

    def test_conflicting_profile_and_non_object_values_are_rejected(self):
        genesis = {
            "config": {"outbeProtocol": {"metadosis": {"formingPeriodSeconds": 60}}},
            "alloc": {},
        }
        with self.assertRaisesRegex(ValueError, "conflicts"):
            seed_genesis.seed_protocol_constants(
                genesis,
                {"protocol_constants": {"metadosis": {"formingPeriodSeconds": 61}}},
            )
        with self.assertRaisesRegex(ValueError, "JSON object"):
            seed_genesis.seed_protocol_constants(
                {"config": {}, "alloc": {}}, {"protocol_constants": []}
            )

    def test_fresh_metadosis_removes_only_preseeded_worldwide_days(self):
        seed = {
            "metadosis": {"worldwide_days": [{"wwd": 20260807}], "other": 7},
            "oracle": {"scurve_seeds": [{"peak_day": 20260807}]},
        }

        seed_genesis.clear_seeded_metadosis_days(seed)

        self.assertEqual(seed["metadosis"]["worldwide_days"], [])
        self.assertEqual(seed["metadosis"]["other"], 7)
        self.assertEqual(seed["oracle"]["scurve_seeds"], [{"peak_day": 20260807}])

    def test_nod_materialization_fifo_is_initialized_without_seeded_nods(self):
        storage = seed_genesis.StorageBuilder()

        seed_genesis.seed_nod_materialization_fifo(storage)

        self.assertEqual(storage.entries[seed_genesis.hex32(19)], seed_genesis.hex32(1))
        self.assertEqual(storage.entries[seed_genesis.hex32(20)], seed_genesis.hex32(1))

    def test_cycle_active_day_is_seeded_from_header_timestamp(self):
        genesis = {
            "timestamp": hex(1_704_103_200),  # 2024-01-01 10:00:00 UTC
            "config": {"genesisTime": "2099-12-31T23:59:59Z"},
        }
        storage = seed_genesis.StorageBuilder()

        seed_genesis.seed_cycle(storage, seed_genesis.parse_header_timestamp(genesis))

        self.assertEqual(storage.entries[seed_genesis.hex32(2)], seed_genesis.hex32(20240101))

    def test_founder_radicle_bindings_are_complete_unique_and_bidirectional(self):
        validators = [
            {
                "address": "0x1111111111111111111111111111111111111111",
                "public_key": "11" * 48,
                "radicle_node_id": "21" * 32,
            },
            {
                "address": "0x2222222222222222222222222222222222222222",
                "public_key": "12" * 48,
                "radicle_node_id": "22" * 32,
            },
        ]
        storage = seed_genesis.StorageBuilder()

        seed_genesis.seed_validator_set(
            storage,
            validators,
            {},
            epoch_length_blocks=300,
            epoch_start_timestamp=1,
            min_stake=1,
            validator_stake=1,
        )

        for validator in validators:
            address = seed_genesis.address_bytes(validator["address"])
            node_id = bytes.fromhex(validator["radicle_node_id"])
            self.assertEqual(
                storage.entries[seed_genesis.mapping_key(address, 59)],
                "0x" + node_id.hex(),
            )
            self.assertEqual(
                storage.entries[seed_genesis.mapping_key(node_id, 60)],
                seed_genesis.hex32(seed_genesis.address_as_u256(validator["address"])),
            )

        missing = [dict(validators[0])]
        missing[0].pop("radicle_node_id")
        with self.assertRaisesRegex(ValueError, "radicle_node_id"):
            seed_genesis.seed_validator_set(
                seed_genesis.StorageBuilder(),
                missing,
                {},
                epoch_length_blocks=300,
                epoch_start_timestamp=1,
                min_stake=1,
                validator_stake=1,
            )

        duplicate = [dict(validators[0]), dict(validators[1])]
        duplicate[1]["radicle_node_id"] = duplicate[0]["radicle_node_id"]
        with self.assertRaisesRegex(ValueError, "duplicate Radicle NodeId"):
            seed_genesis.seed_validator_set(
                seed_genesis.StorageBuilder(),
                duplicate,
                {},
                epoch_length_blocks=300,
                epoch_start_timestamp=1,
                min_stake=1,
                validator_stake=1,
            )

        zero = [dict(validators[0])]
        zero[0]["radicle_node_id"] = "00" * 32
        with self.assertRaisesRegex(ValueError, "must not be zero"):
            seed_genesis.seed_validator_set(
                seed_genesis.StorageBuilder(),
                zero,
                {},
                epoch_length_blocks=300,
                epoch_start_timestamp=1,
                min_stake=1,
                validator_stake=1,
            )


if __name__ == "__main__":
    unittest.main()
