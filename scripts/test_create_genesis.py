"""Tests for scripts/create_genesis.py: the yaml subset parser, config
validation, key-material discovery, the seed merge, and the python seeding
stage. Stages that need the compiled binaries are skipped when those are
absent (and exercised by the create_genesis smoke run instead)."""

import base64
import importlib.util
import json
import pathlib
import re
import subprocess
import tempfile
import time
import unittest

MODULE_PATH = pathlib.Path(__file__).with_name("create_genesis.py")


def load_module(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CG = load_module("create_genesis", MODULE_PATH)
LB = load_module("launch_bundle", MODULE_PATH.with_name("launch_bundle.py"))
SEED_GENESIS = load_module("seed_genesis", MODULE_PATH.with_name("seed_genesis.py"))

REPO_ROOT = MODULE_PATH.parents[1]


def binary_path(name: str) -> pathlib.Path | None:
    for build in ("release", "debug"):
        candidate = REPO_ROOT / "target" / build / name
        if candidate.is_file():
            return candidate
    return None


def parse(text: str) -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
        handle.write(text)
        path = pathlib.Path(handle.name)
    try:
        return CG.load_yaml(path)
    finally:
        path.unlink()


def parse_error(text: str) -> str:
    try:
        parse(text)
    except ValueError as error:
        return str(error)
    raise AssertionError("expected a parse error")


def minimal_config(keys_dir: str) -> dict:
    return {
        "chain_id": 424242,
        "validators": ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"],
        "keys_dir": keys_dir,
        "tee": {"mode": "gramine-direct-dev"},
    }


def write_ssh_ed25519_pub(path: pathlib.Path, node_id: bytes) -> None:
    def field(value: bytes) -> bytes:
        return len(value).to_bytes(4, "big") + value

    payload = field(b"ssh-ed25519") + field(node_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"ssh-ed25519 {base64.b64encode(payload).decode()} outbe\n")


class YamlParserTests(unittest.TestCase):
    def test_scalars_lists_and_nesting(self):
        config = parse(
            "a: 1\n"
            "b: true\n"
            "c: plain string\n"
            'd: "quoted: string"\n'
            "nested:\n"
            "  x: 2\n"
            "  deeper:\n"
            "    y: false\n"
            "hosts:\n"
            "  - 10.0.0.1\n"
            "  - 10.0.0.2\n"
            "items:\n"
            '  - base: COEN\n'
            '    quote: "840"\n'
            "  - base: XYZ\n"
            '    quote: "978"\n'
        )
        self.assertEqual(config["a"], 1)
        self.assertIs(config["b"], True)
        self.assertEqual(config["c"], "plain string")
        self.assertEqual(config["d"], "quoted: string")
        self.assertEqual(config["nested"]["deeper"]["y"], False)
        self.assertEqual(config["hosts"], ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(
            config["items"],
            [{"base": "COEN", "quote": "840"}, {"base": "XYZ", "quote": "978"}],
        )

    def test_comments_and_blank_lines(self):
        self.assertEqual(parse("# leading\n\na: 1  # trailing\n\n# done\n"), {"a": 1})

    def test_quoted_hex_keys(self):
        self.assertEqual(parse('balance:\n  "0xAb": "10"\n')["balance"], {"0xAb": "10"})

    def test_empty_list_literal(self):
        self.assertEqual(parse("tributes: []\n"), {"tributes": []})

    def test_tab_rejected(self):
        self.assertIn("tabs", parse_error("a:\n\tb: 1\n"))

    def test_duplicate_key_rejected(self):
        self.assertIn("duplicate", parse_error("a: 1\na: 2\n"))

    def test_anchor_rejected(self):
        self.assertIn("unsupported", parse_error("a: &anchor 1\n"))

    def test_inline_mapping_rejected(self):
        self.assertIn("unsupported", parse_error("a: {b: 1}\n"))

    def test_dangling_key_rejected(self):
        self.assertIn("has no value", parse_error("a:\n"))

    def test_nested_structure_in_list_item_rejected(self):
        self.assertIn(
            "not supported", parse_error("items:\n  - a: 1\n    b:\n      c: 2\n")
        )


class ConfigValidationTests(unittest.TestCase):
    def test_minimal_config_passes(self):
        CG.validate_config(minimal_config("./keys"))

    def test_unknown_top_level_key_rejected(self):
        config = minimal_config("./keys")
        config["bogus"] = 1
        with self.assertRaisesRegex(ValueError, "bogus"):
            CG.validate_config(config)

    def test_wrong_validator_count_rejected(self):
        config = minimal_config("./keys")
        config["validators"] = config["validators"][:3]
        with self.assertRaisesRegex(ValueError, "exactly 4"):
            CG.validate_config(config)

    def test_missing_keys_dir_rejected(self):
        config = minimal_config("./keys")
        del config["keys_dir"]
        with self.assertRaisesRegex(ValueError, "keys_dir"):
            CG.validate_config(config)

    def test_non_string_validator_rejected(self):
        config = minimal_config("./keys")
        config["validators"][1] = {"host": "10.0.0.2"}
        with self.assertRaisesRegex(ValueError, "host or IP string"):
            CG.validate_config(config)

    def test_bad_tee_mode_rejected(self):
        config = minimal_config("./keys")
        config["tee"]["mode"] = "trust-me"
        with self.assertRaisesRegex(ValueError, "tee.mode"):
            CG.validate_config(config)

    def test_networks_expose_the_canonical_attestation_matrix(self):
        for network, chain_id in (
            ("devnet", 424242),
            ("testnet", 70860602),
        ):
            for tee_mode in ("dcap-required", "gramine-direct-dev"):
                config = minimal_config("./keys") | {
                    "network": network,
                    "chain_id": chain_id,
                    "tee": {"mode": tee_mode},
                }
                if tee_mode == "dcap-required":
                    config["enclave_image"] = (
                        "outbe-tee-enclave@sha256:" + "ab" * 32
                    )
                CG.validate_config(config)

        mainnet = minimal_config("./keys") | {
            "network": "mainnet",
            "chain_id": 676,
            "tee": {"mode": "dcap-required"},
            "enclave_image": "outbe-tee-enclave@sha256:" + "ab" * 32,
            "price_feed_rest": "https://prices.outbe.net",
        }
        CG.validate_config(mainnet)

        mainnet["tee"] = {"mode": "gramine-direct-dev"}
        with self.assertRaisesRegex(ValueError, "Mainnet requires"):
            CG.validate_config(mainnet)

    def test_testnet_direct_dev_needs_no_secondary_opt_in(self):
        config = minimal_config("./keys") | {"chain_id": 70860602}
        CG.validate_config(config)

    def test_mainnet_rejects_direct_dev(self):
        config = minimal_config("./keys") | {
            "network": "mainnet",
            "chain_id": 676,
        }
        with self.assertRaisesRegex(ValueError, "Mainnet requires"):
            CG.validate_config(config)

    def test_dcap_requires_a_pinned_digest_on_every_approved_network(self):
        config = minimal_config("./keys") | {
            "chain_id": 424242,
            "tee": {"mode": "dcap-required"},
        }
        with self.assertRaisesRegex(ValueError, "immutable digest"):
            CG.validate_config(config)

        config["enclave_image"] = "outbe-tee-enclave@sha256:" + "ab" * 32
        CG.validate_config(config)

    def test_mainnet_profile_uses_the_canonical_identity_and_production_inputs(self):
        config = minimal_config("./keys") | {
            "network": "mainnet",
            "chain_id": 676,
            "tee": {"mode": "dcap-required"},
            "enclave_image": "outbe-tee-enclave@sha256:" + "ab" * 32,
            "price_feed_rest": "https://prices.outbe.net",
        }

        CG.validate_config(config)
        self.assertEqual(
            CG.network_identity(config),
            ("mainnet", 676, "outbe-mainnet-1"),
        )

    def test_mainnet_profile_rejects_identity_and_test_shortcut_drift(self):
        config = minimal_config("./keys") | {
            "network": "mainnet",
            "chain_id": 70860602,
            "tee": {"mode": "dcap-required"},
            "enclave_image": "outbe-tee-enclave@sha256:" + "ab" * 32,
            "price_feed_rest": "https://prc.testnet.outbe.net",
        }
        with self.assertRaisesRegex(ValueError, "mainnet.*676"):
            CG.validate_config(config)

        config["chain_id"] = 676
        with self.assertRaisesRegex(ValueError, "testnet price endpoint"):
            CG.validate_config(config)

        config["price_feed_rest"] = "https://prices.outbe.net"
        config["protocol_constants"] = {"schemaVersion": 1}
        with self.assertRaisesRegex(ValueError, "protocol_constants"):
            CG.validate_config(config)

    def test_unknown_chain_identity_is_rejected(self):
        config = minimal_config("./keys") | {"chain_id": 999999}
        with self.assertRaisesRegex(ValueError, "unknown Outbe chain id"):
            CG.validate_config(config)

    def test_mainnet_requires_preexisting_ocomp_registrations(self):
        with tempfile.TemporaryDirectory() as tmp:
            keys = pathlib.Path(tmp)
            for index in range(4):
                (keys / f"validator-{index}").mkdir()
            with self.assertRaisesRegex(ValueError, "Mainnet.*OCOMP registration"):
                CG.validate_ocomp_registration_inventory(
                    keys_dir=keys,
                    validator_count=4,
                    allow_generation=False,
                )

    def test_port_collisions_are_rejected(self):
        config = minimal_config("./keys") | {"rpc_port": 9101}  # same as metrics
        with self.assertRaisesRegex(ValueError, "port collision"):
            CG.validate_config(config)
        config = minimal_config("./keys") | {"rpc_port": 70000}
        with self.assertRaisesRegex(ValueError, "outside 1..65535"):
            CG.validate_config(config)

    def test_dcap_without_measurements_rejected_at_the_tee_stage(self):
        config = minimal_config("./keys")
        config["tee"] = {"mode": "dcap-required"}
        with self.assertRaisesRegex(ValueError, "mrenclave"):
            CG.run_tee_stage(
                chain_binary="/nonexistent",
                ocomp_genesis=pathlib.Path("/nonexistent"),
                output=pathlib.Path("/nonexistent"),
                config=config,
            )


class KeyDerivationTests(unittest.TestCase):
    def test_evm_address_matches_known_secp256k1_vectors(self):
        # Canonical secp256k1 vectors: private key 1 is the generator point.
        vectors = {
            1: "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
            2: "0x2b5ad5c4795c026514f8317c7a215e218dccd6cf",
        }
        with tempfile.TemporaryDirectory() as tmp:
            for scalar, expected in vectors.items():
                path = pathlib.Path(tmp) / f"key-{scalar}.hex"
                path.write_text(f"{scalar:064x}\n")
                self.assertEqual(
                    CG.evm_address_from_key_file(path, SEED_GENESIS.keccak256), expected
                )

    def test_evm_key_length_is_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "evm-key.hex"
            path.write_text("dead\n")
            with self.assertRaisesRegex(ValueError, "32-byte"):
                CG.evm_address_from_key_file(path, SEED_GENESIS.keccak256)

    def test_radicle_node_id_round_trips(self):
        node_id = bytes(range(32))
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "radicle.pub"
            write_ssh_ed25519_pub(path, node_id)
            self.assertEqual(
                CG.radicle_node_id_from_public_key(path), node_id.hex()
            )

    def test_radicle_wrong_algorithm_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "radicle.pub"
            path.write_text("ssh-rsa AAAA outbe\n")
            with self.assertRaisesRegex(ValueError, "ssh-ed25519"):
                CG.radicle_node_id_from_public_key(path)

    def test_discover_reports_the_missing_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = minimal_config(tmp)
            with self.assertRaisesRegex(ValueError, "missing key directory"):
                CG.discover_validators(
                    config=config,
                    keys_dir=pathlib.Path(tmp),
                    keygen_binary="/nonexistent",
                    keccak256=SEED_GENESIS.keccak256,
                )

    def test_discover_reports_the_missing_key_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            keys_dir = pathlib.Path(tmp)
            (keys_dir / "validator-0").mkdir()
            config = minimal_config(tmp)
            with self.assertRaisesRegex(ValueError, "signing-key.hex"):
                CG.discover_validators(
                    config=config,
                    keys_dir=keys_dir,
                    keygen_binary="/nonexistent",
                    keccak256=SEED_GENESIS.keccak256,
                )

    @unittest.skipIf(binary_path("outbe-keygen") is None, "outbe-keygen not built")
    def test_discover_reads_a_real_keygen_bundle(self):
        import subprocess

        keygen = str(binary_path("outbe-keygen"))
        with tempfile.TemporaryDirectory() as tmp:
            keys_dir = pathlib.Path(tmp)
            for index in range(4):
                subprocess.run(
                    [
                        keygen,
                        "validator",
                        "--output-dir",
                        str(keys_dir / f"validator-{index}"),
                        "--chain-id",
                        "424242",
                    ],
                    check=True,
                    capture_output=True,
                )
            validators = CG.discover_validators(
                config=minimal_config(tmp),
                keys_dir=keys_dir,
                keygen_binary=keygen,
                keccak256=SEED_GENESIS.keccak256,
            )
            self.assertEqual(len(validators), 4)
            # Founders sit on separate machines, so they share one port.
            self.assertEqual(validators[0]["p2p_address"], "10.0.0.1:30400")
            self.assertEqual(validators[3]["p2p_address"], "10.0.0.4:30400")
            for validator in validators:
                self.assertEqual(len(validator["public_key"]), 96)
                self.assertEqual(len(validator["address"]), 42)
                self.assertEqual(len(validator["radicle_node_id"]), 66)
            addresses = {validator["address"] for validator in validators}
            self.assertEqual(len(addresses), 4)

    @unittest.skipIf(binary_path("outbe-keygen") is None, "outbe-keygen not built")
    def test_a_validator_entry_may_pin_its_own_port(self):
        import subprocess

        keygen = str(binary_path("outbe-keygen"))
        with tempfile.TemporaryDirectory() as tmp:
            keys_dir = pathlib.Path(tmp)
            for index in range(4):
                subprocess.run(
                    [keygen, "validator", "--output-dir",
                     str(keys_dir / f"validator-{index}"), "--chain-id", "424242"],
                    check=True, capture_output=True,
                )
            config = minimal_config(tmp)
            config["validators"][2] = "10.0.0.3:31555"
            validators = CG.discover_validators(
                config=config, keys_dir=keys_dir, keygen_binary=keygen,
                keccak256=SEED_GENESIS.keccak256,
            )
            self.assertEqual(validators[2]["p2p_address"], "10.0.0.3:31555")
            self.assertEqual(validators[1]["p2p_address"], "10.0.0.2:30400")


class SeedMergeTests(unittest.TestCase):
    def test_scalar_override_replaces_and_keeps_siblings(self):
        seed = CG.build_seed({"staking": {"min_stake": "7"}})
        base = CG.load_yaml(CG.BASE_PROFILE_PATH)
        self.assertEqual(seed["staking"]["min_stake"], "7")
        self.assertEqual(
            seed["staking"]["unbonding_period"], base["staking"]["unbonding_period"]
        )

    def test_list_override_replaces_whole_list(self):
        pairs = [{"base": "COEN", "quote": "978", "initial_rate": "2"}]
        seed = CG.build_seed({"oracle": {"pairs": pairs}})
        base = CG.load_yaml(CG.BASE_PROFILE_PATH)
        self.assertEqual(seed["oracle"]["pairs"], pairs)
        self.assertEqual(seed["oracle"]["config"], base["oracle"]["config"])

    def test_untouched_sections_equal_the_baseline(self):
        seed = CG.build_seed({})
        base = CG.load_yaml(CG.BASE_PROFILE_PATH)
        for section in ("rewards", "validator_set"):
            self.assertEqual(seed[section], base[section])

    def test_the_baseline_seeds_no_worldwide_day(self):
        # The runtime creates the first day at block 1, and the live testnet
        # genesis carries no metadosis storage. A seeded day would also be
        # unusable: the seeder writes its limit amount but not the formation
        # record `apply_missed_offering` requires, so reaching MissedOffering
        # would kill the ProtocolCycle and stop block production.
        base = CG.load_yaml(CG.BASE_PROFILE_PATH)
        self.assertNotIn("metadosis", base)
        self.assertNotIn("metadosis", CG.build_seed({}))


class SeedStageTests(unittest.TestCase):
    """The python half of the pipeline runs for real: base genesis, prefund,
    and seed_genesis.py storage seeding. The OCOMP and TEE stages need the node
    binary; the smoke run covers those."""

    def fake_validators(self) -> list[dict]:
        return [
            {
                "address": f"0x{str(index + 1) * 40}",
                "public_key": f"{index + 1:02x}" * 48,
                "radicle_node_id": "0x" + f"{index + 9:02x}" * 32,
                "p2p_address": f"10.0.0.{index + 1}:30400",
            }
            for index in range(4)
        ]

    def seed_once(self, work_dir: pathlib.Path, config: dict) -> dict:
        validators = self.fake_validators()
        base_genesis = CG.build_base_genesis(config)
        CG.prefund_validators(base_genesis, config, validators)
        path = CG.run_seed_stage(
            module=SEED_GENESIS,
            work_dir=work_dir,
            base_genesis=base_genesis,
            seed=CG.build_seed(config),
            validators=validators,
            config=config,
            quiet=True,
        )
        return json.loads(path.read_text())

    def test_seed_stage_produces_a_valid_seeded_genesis(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = minimal_config(tmp) | {"prefund_coen_units": 5_000_000}
            seeded = self.seed_once(pathlib.Path(tmp), config)

            self.assertEqual(seeded["config"]["chainId"], 424242)
            self.assertEqual(seeded["config"]["epochLengthBlocks"], 300)
            alloc = seeded["alloc"]
            for validator in self.fake_validators():
                self.assertEqual(alloc[validator["address"]]["balance"], hex(5_000_000))
            validator_set = alloc[SEED_GENESIS.VALIDATOR_SET_ADDRESS]
            slot20 = "0x" + f"{20:064x}"  # validator_count
            self.assertEqual(int(validator_set["storage"][slot20], 16), 4)

    def test_production_seed_stage_preserves_oracle_orientation_and_wire_scales(self):
        token = "0x1111111111111111111111111111111111111111"
        pairs = [
            {"base": "COEN", "quote": "840", "initial_rate": "1250000"},
            {
                "base": token,
                "quote": "840",
                "initial_rate": str(65_000 * 10**18),
            },
        ]

        with tempfile.TemporaryDirectory() as tmp:
            config = minimal_config(tmp) | {"oracle": {"pairs": pairs}}
            seeded = self.seed_once(pathlib.Path(tmp), config)

        storage = seeded["alloc"][SEED_GENESIS.ORACLE_ADDRESS]["storage"]
        for pair_id, pair in enumerate(pairs, start=1):
            pair_slot = int(
                SEED_GENESIS.mapping_key(SEED_GENESIS.u32_bytes(pair_id), 43), 16
            )
            self.assertEqual(
                storage[SEED_GENESIS.hex32(pair_slot)],
                SEED_GENESIS.hex32(
                    int.from_bytes(SEED_GENESIS.asset_address(pair["base"]), "big")
                ),
            )
            self.assertEqual(
                storage[SEED_GENESIS.hex32(pair_slot + 1)],
                SEED_GENESIS.hex32(
                    int.from_bytes(SEED_GENESIS.asset_address(pair["quote"]), "big")
                ),
            )
            rate_slot = SEED_GENESIS.mapping_key(SEED_GENESIS.u32_bytes(pair_id), 12)
            self.assertEqual(
                storage[rate_slot], SEED_GENESIS.hex32(int(pair["initial_rate"]))
            )

    def test_production_seed_stage_rejects_iso_to_coen_oracle_pair(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = minimal_config(tmp) | {
                "oracle": {
                    "pairs": [
                        {"base": "840", "quote": "COEN", "initial_rate": "1000000"}
                    ]
                }
            }
            with self.assertRaisesRegex(ValueError, "COEN base"):
                self.seed_once(pathlib.Path(tmp), config)

    def test_production_seed_stage_rejects_oracle_pair_with_the_same_resolved_asset(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = minimal_config(tmp) | {
                "oracle": {
                    "pairs": [
                        {"base": "COEN", "quote": "native", "initial_rate": "1000000"}
                    ]
                }
            }
            with self.assertRaisesRegex(ValueError, "same asset"):
                self.seed_once(pathlib.Path(tmp), config)

    def test_mainnet_profile_seeds_chain_676_with_canonical_production_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = minimal_config(tmp) | {
                "network": "mainnet",
                "chain_id": 676,
                "tee": {"mode": "dcap-required"},
                "enclave_image": "outbe-tee-enclave@sha256:" + "ab" * 32,
                "price_feed_rest": "https://prices.outbe.net",
            }
            CG.validate_config(config)
            seeded = self.seed_once(pathlib.Path(tmp), config)

            self.assertEqual(seeded["config"]["chainId"], 676)
            self.assertNotIn("protocolConstants", seeded["config"])
            baseline = CG.load_yaml(CG.BASE_PROFILE_PATH)
            rewards_storage = seeded["alloc"][SEED_GENESIS.REWARDS_ADDRESS]["storage"]
            self.assertTrue(rewards_storage)
            self.assertEqual(CG.build_seed(config)["rewards"], baseline["rewards"])

    def test_seeded_genesis_is_reproducible_for_a_pinned_timestamp(self):
        """The OCOMP registrations sign the seeded genesis hash, so the same
        yaml must always seed byte-identical state."""
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            config = minimal_config(first) | {"timestamp": 1_756_032_000, "allow_stale_timestamp": True}
            a = self.seed_once(pathlib.Path(first), config)
            b = self.seed_once(pathlib.Path(second), config)
            self.assertEqual(a, b)

    def test_a_stale_timestamp_is_refused(self):
        """A genesis stamped in the past fails at block 1 with an unrelated-
        looking revert; catch it while it is still cheap to fix."""
        stale = int(time.time()) - 48 * 3600
        with self.assertRaisesRegex(ValueError, "lease is already expired"):
            CG.build_base_genesis(minimal_config("./keys") | {"timestamp": stale})
        # Reproducing an existing genesis is legitimate, but must be deliberate.
        pinned = CG.build_base_genesis(
            minimal_config("./keys") | {"timestamp": stale, "allow_stale_timestamp": True}
        )
        self.assertEqual(int(pinned["timestamp"], 16), stale)
        # A fresh stamp always passes.
        CG.build_base_genesis(minimal_config("./keys"))

    def test_genesis_time_is_pinned_to_the_header_timestamp(self):
        config = minimal_config("./keys") | {"timestamp": 1_756_032_000, "allow_stale_timestamp": True}
        genesis = CG.build_base_genesis(config)
        self.assertEqual(genesis["timestamp"], hex(1_756_032_000))
        self.assertEqual(genesis["config"]["genesisTime"], "2025-08-24T10:40:00Z")


class ExampleFileTests(unittest.TestCase):
    EXAMPLE = MODULE_PATH.with_name("network.example.yaml")

    def test_example_parses_and_validates(self):
        config = CG.load_yaml(self.EXAMPLE)
        CG.validate_config(config)
        self.assertEqual(len(config["validators"]), 4)
        self.assertEqual(config["keys_dir"], "./keys")

    def test_example_commented_defaults_match_the_baseline(self):
        """Uncomment the commented parameter block and check every section
        equals the baseline profile, so the example can never show a stale
        default."""
        lines = []
        for line in self.EXAMPLE.read_text().splitlines():
            stripped = line.lstrip()
            indent = line[: len(line) - len(stripped)]
            if stripped.startswith("#") and not stripped.startswith("# -"):
                candidate = stripped[1:].removeprefix(" ")
                token = candidate.lstrip().split(" ")[0]
                if token.endswith(":") or candidate.lstrip().startswith("- "):
                    lines.append(indent + candidate.split("  #")[0].rstrip())
                    continue
            if not stripped.startswith("#"):
                lines.append(line.split("  #")[0].rstrip())
        with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as handle:
            handle.write("\n".join(lines) + "\n")
            path = pathlib.Path(handle.name)
        try:
            config = CG.load_yaml(path)
        finally:
            path.unlink()

        base = CG.load_yaml(CG.BASE_PROFILE_PATH)
        for section in (
            "staking",
            "rewards",
            "validator_set",
            "radicle_registry",
            "intex_factory",
            "vault_router",
            "oracle",
        ):
            self.assertEqual(
                config[section],
                base[section],
                f"example default for `{section}` differs from the baseline seed",
            )
        self.assertEqual(config["gas_limit"], CG.DEFAULT_GAS_LIMIT)
        self.assertEqual(config["epoch_length_blocks"], CG.DEFAULT_EPOCH_LENGTH_BLOCKS)
        self.assertEqual(config["prefund_coen_units"], CG.DEFAULT_PREFUND_COEN_UNITS)
        self.assertEqual(config["consensus_p2p_port"], CG.DEFAULT_CONSENSUS_P2P_PORT)


class BaselineProfileTests(unittest.TestCase):
    def test_baseline_is_the_testnet_yaml(self):
        self.assertEqual(CG.BASE_PROFILE_PATH.name, "testnet.yaml")
        config = CG.load_yaml(CG.BASE_PROFILE_PATH)
        CG.validate_config(config)
        self.assertEqual(sorted(set(config) - CG.TOP_LEVEL_KEYS), [])

    def test_baseline_still_matches_the_json_profile(self):
        """`seed-testnet.json` still feeds prepare_network.py and the localnet
        harness. Until those move over, the two must not drift."""
        legacy = json.loads(
            (CG.BASE_PROFILE_PATH.with_name("seed-testnet.json")).read_text()
        )
        baseline = CG.load_yaml(CG.BASE_PROFILE_PATH)
        for section, value in legacy.items():
            self.assertEqual(
                baseline.get(section),
                value,
                f"`{section}` drifted between testnet.yaml and seed-testnet.json",
            )

    def test_every_seed_section_is_present_in_the_baseline(self):
        baseline = CG.load_yaml(CG.BASE_PROFILE_PATH)
        seed = CG.build_seed({})
        for section in CG.SEED_SECTIONS:
            if section in baseline:
                self.assertEqual(seed[section], baseline[section])

    def test_baseline_runs_as_its_own_network_file(self):
        """testnet.yaml is not just a defaults bag: seeding it against itself
        must be a fixed point."""
        config = CG.load_yaml(CG.BASE_PROFILE_PATH)
        self.assertEqual(CG.build_seed(config), CG.build_seed({}))


class LaunchBundleTests(unittest.TestCase):
    def fake_validators(self) -> list[dict]:
        return [
            {
                "address": f"0x{str(index + 1) * 40}",
                "public_key": f"{index + 1:02x}" * 48,
                "radicle_node_id": "0x" + f"{index + 9:02x}" * 32,
                "p2p_address": f"10.0.0.{index + 1}:30400",
            }
            for index in range(4)
        ]

    def render(self, tmp: str, config_overrides: dict | None = None):
        root = pathlib.Path(tmp)
        keys_dir = root / "keys"
        output_dir = root / "net"
        output_dir.mkdir(parents=True)
        for index in range(4):
            directory = keys_dir / f"validator-{index}"
            directory.mkdir(parents=True)
            (directory / "evm-key.hex").write_text(f"{index + 1:064x}\n")
        genesis = output_dir / "genesis.json"
        # render() reads the OCOMP identity out of the install document, and
        # locates the bundle hash by anchoring on the genesis hash, so the
        # fixture has to carry a well-formed one.
        genesis_hash = "0x" + "ab" * 32
        canonical = ("00" * 33) + "ab" * 32 + "01" * 32 + "cd" * 32 + "0c" * 32
        genesis.write_text(json.dumps({
            "config": {
                "chainId": 424242,
                "ocompForkInstallV1": {
                    "canonicalBytes": "0x" + canonical,
                    "installHash": "0x" + "ee" * 32,
                },
            },
        }))
        marker = keys_dir / "validator-0" / "ocomp-registration-v1.genesis-hash"
        marker.write_text(genesis_hash + "\n")
        (output_dir / "protocol-bundle-v1.ocb1").write_bytes(b"canonical-ocomp-v1")
        config = minimal_config(str(keys_dir)) | (config_overrides or {})
        LB.render(
            config=config,
            validators=self.fake_validators(),
            genesis_path=genesis,
            keys_dir=keys_dir,
            repo_root=REPO_ROOT,
        )
        return root, keys_dir, output_dir

    def test_radicle_sidecar_ceiling_does_not_track_the_founder_count(self):
        # The sidecar tracks the validator set from chain state, but its
        # connection limits are fixed at start-up (outbound = ceiling - 1).
        # Sizing them by the founding four would cap every node at three
        # peers, so a fifth validator joining would need the whole network
        # restarted. Size by the protocol ceiling instead.
        def rendered(overrides):
            return LB.radicle_script(
                config=minimal_config("/keys") | overrides,
                index=0,
                host="10.0.0.1",
                keys_dir="/keys",
                repo_root=str(REPO_ROOT),
            )

        self.assertIn(
            f"--max-validators {LB.DEFAULT_MAX_VALIDATORS}", rendered({})
        )
        self.assertIn(
            "--max-validators 64",
            rendered({"validator_set": {"max_validators": 64}}),
        )
        # Never the size of the founding committee.
        self.assertNotIn("--max-validators 4 ", rendered({}))

    def test_radicle_sidecar_does_not_write_a_config_file(self):
        # The sidecar builds its runtime config from the command line and
        # never reads config.json; a second copy could only drift, and the
        # `network: outbe` it used to contain stops a stock `rad` from
        # starting at all.
        script = LB.radicle_script(
            config=minimal_config("/keys"),
            index=0,
            host="10.0.0.1",
            keys_dir="/keys",
            repo_root=str(REPO_ROOT),
        )
        self.assertNotIn("config.json", script)

    def test_render_writes_every_script_and_they_are_valid_bash(self):
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            _, _, output_dir = self.render(tmp)
            self.assertTrue((output_dir / "reth-bootnodes.txt").is_file())
            self.assertTrue((output_dir / "DEPLOY.md").is_file())
            for index in range(4):
                directory = output_dir / f"validator-{index}"
                for name in (
                    "run-storage.sh",
                    "run-enclave.sh",
                    "run-radicle.sh",
                    "run-node.sh",
                    "run-feeder.sh",
                    "run-ocomp-exporter.sh",
                    "run-ocomp-worker.sh",
                    "start-all.sh",
                    "stop-all.sh",
                ):
                    script = directory / name
                    self.assertTrue(script.is_file(), f"{name} missing")
                    self.assertTrue(script.stat().st_mode & 0o111, f"{name} not executable")
                    subprocess.run(["bash", "-n", str(script)], check=True)
                self.assertEqual(
                    {path.name for path in directory.glob("run-ocomp-*.sh")},
                    {
                        "run-ocomp-exporter.sh",
                        "run-ocomp-worker.sh",
                        "run-ocomp-successor-worker.sh",
                    },
                )
                self.assertTrue((directory / "feeder.toml").is_file())

    def test_ocomp_identity_is_read_from_the_install_document(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, output_dir = self.render(tmp)
            script = (output_dir / "validator-2" / "run-ocomp-worker.sh").read_text()
            # The bundle hash sits after the genesis hash and the fork id.
            self.assertIn("--protocol-bundle-hash \"$OCOMP_ACTIVE_PROTOCOL_BUNDLE_HASH\"", script)
            self.assertIn("ocomp-active.env", script)
            self.assertIn("--chain-id 424242", script)
            self.assertIn("--genesis-hash 0x" + "ab" * 32, script)
            # Each host gets a distinct boot nonce, ordinal in the low bytes.
            self.assertIn("--boot-nonce 0x03" + "00" * 27 + "00000000", script)

    def test_every_ocomp_role_gets_the_shared_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, output_dir = self.render(tmp)
            for role in ("exporter", "worker", "successor-worker"):
                script = (output_dir / "validator-0" / f"run-ocomp-{role}.sh").read_text()
                for var in ("OUTBE_OCOMP_BASE_PATH", "OCOMP_VALIDATOR_INDEX",
                            "OCOMP_CHAIN_ID", "OCOMP_GENESIS_HASH", "OCOMP_BOOT_NONCE",
                            "OCOMP_PROTOCOL_BUNDLE_HASH", "OCOMP_REGISTRY_GENERATION"):
                    self.assertIn(var, script, f"{role} script is missing {var}")

    def test_storage_launcher_obeys_current_toml_and_never_starts_mongo_for_rocks(self):
        import subprocess
        with tempfile.TemporaryDirectory() as tmp:
            _, _, output_dir = self.render(tmp)
            directory = output_dir / "validator-0"
            self.assertFalse((directory / "run-mongodb.sh").exists())
            # A stale script from an older Mongo deployment must not activate the service.
            mongo = directory / "run-mongodb.sh"
            mongo.write_text("#!/bin/sh\ntouch mongo-started\n")
            mongo.chmod(0o700)
            subprocess.run(["bash", str(directory / "run-storage.sh")], check=True, capture_output=True)
            self.assertFalse((directory / "mongo-started").exists())
            config = directory / "offchain-storage.toml"
            source = 'version=1\nbackend="mongodb"\n[mongodb]\nuri="mongodb://remote:27017/?replicaSet=rs0"\ndatabase="operator"\n'
            config.write_text(source)
            subprocess.run(["bash", str(directory / "run-storage.sh")], check=True, capture_output=True)
            self.assertFalse((directory / "mongo-started").exists())
            config.write_text(source.replace("remote:27017", "127.0.0.1:27017"))
            subprocess.run(["bash", str(directory / "run-storage.sh")], check=True, capture_output=True)
            self.assertTrue((directory / "mongo-started").exists())

    def test_mongo_bundle_selects_distinct_databases_and_packages_storage_helper(self):
        import tarfile
        import tomllib
        with tempfile.TemporaryDirectory() as tmp:
            _, _, output_dir = self.render(tmp, {"offchain_storage": {"backend": "mongodb", "mongodb": {"database": "network"}}})
            databases = set()
            for index in range(4):
                directory = output_dir / f"validator-{index}"
                document = tomllib.loads((directory / "offchain-storage.toml").read_text())
                databases.add(document["mongodb"]["database"])
                self.assertTrue((directory / "run-mongodb.sh").exists())
                with tarfile.open(output_dir / "dist" / f"validator-{index}.tgz") as archive:
                    self.assertIn("offchain_storage.py", archive.getnames())
                    self.assertIn(f"validator-{index}/offchain-storage.toml", archive.getnames())
            self.assertEqual(len(databases), 4)

    def test_exporter_uses_node_projection(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, output_dir = self.render(tmp)
            exporter = (output_dir / "validator-0" / "run-ocomp-exporter.sh").read_text()
            self.assertIn(
                "/validator-0/offchain-storage.toml",
                exporter,
            )
            self.assertNotIn("OUTBE_OCOMP_PROJECTION_MONGODB", exporter)
            node = (output_dir / "validator-0" / "run-node.sh").read_text()
            self.assertIn("/validator-0/offchain-storage.toml", node)
            self.assertNotIn("--projection.start-block", node)

    def test_successor_bundle_catalog_and_dormant_worker_are_release_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, output_dir = self.render(tmp)
            bundle_hash = "cd" * 32
            catalog_bundle = output_dir / "protocol-bundles-v1" / f"{bundle_hash}.ocb1"
            self.assertEqual(
                catalog_bundle.read_bytes(),
                (output_dir / "protocol-bundle-v1.ocb1").read_bytes(),
            )
            node = (output_dir / "validator-0" / "run-node.sh").read_text()
            self.assertIn("protocol-bundles-v1/${BUNDLE_HASH#0x}.ocb1", node)
            self.assertIn("ocomp-bundles.env", node)
            active = output_dir / "validator-0" / "ocomp-active.env"
            self.assertEqual(
                active.read_text(),
                "OCOMP_ACTIVE_PROTOCOL_BUNDLE_HASH=0x" + bundle_hash + "\n",
            )
            exporter = (output_dir / "validator-0" / "run-ocomp-exporter.sh").read_text()
            self.assertIn("ocomp-bundles.env", exporter)
            successor = (
                output_dir / "validator-0" / "run-ocomp-successor-worker.sh"
            ).read_text()
            self.assertIn("OCOMP_SUCCESSOR_PROTOCOL_BUNDLE_HASH", successor)
            self.assertIn("--supervisor-address 127.0.0.1:30407", successor)
            unit = output_dir / "systemd" / "outbe-ocomp-successor-worker@.service"
            self.assertTrue(unit.is_file())
            installer = (output_dir / "install-systemd.sh").read_text()
            self.assertNotIn(
                "for role in enclave radicle node ocomp-exporter ocomp-worker "
                "ocomp-successor-worker feeder",
                installer,
            )

    def test_start_all_waits_for_the_node_owned_endpoint_before_the_worker(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, output_dir = self.render(tmp)
            start = (output_dir / "validator-0" / "start-all.sh").read_text()
            self.assertLess(
                start.index("/dev/tcp/127.0.0.1/30401"),
                start.index("run-ocomp-worker.sh"),
                "the worker must not start before the embedded Supervisor endpoint",
            )
            self.assertIn("did not become ready", start)
            stop = (output_dir / "validator-0" / "stop-all.sh").read_text()
            self.assertIn("ocomp-worker", stop)

    def test_feeder_provider_name_is_one_the_binary_accepts(self):
        """outbe-feeder validates provider names against a fixed list and
        refuses to start on anything else."""
        known = {"mock", "pyth", "chainlink", "binance", "kraken", "okx",
                 "gate", "huobi", "mexc", "coinbase", "mock_http"}
        with tempfile.TemporaryDirectory() as tmp:
            _, _, output_dir = self.render(tmp)
            toml = (output_dir / "validator-0" / "feeder.toml").read_text()
            names = re.findall(r'name = "([^"]+)"', toml)
            providers = re.findall(r'provider = "([^"]+)"', toml)
            self.assertTrue(names and providers)
            for value in names + providers:
                self.assertIn(value, known, f"{value} is not a provider the feeder knows")
            # And the two must agree, or the pair references a missing endpoint.
            self.assertEqual(set(names), set(providers))
            self.assertNotIn("chain_denom", toml)
            self.assertNotIn("providers =", toml)
            self.assertNotIn("websocket =", toml)

    def test_exchange_feeder_emits_websocket_override_without_legacy_pair_fields(self):
        config = minimal_config("/keys") | {
            "price_provider": "binance",
            "price_feed_websocket": "wss://stream.binance.com:9443/ws",
        }
        toml = LB.feeder_config(
            config=config,
            index=0,
            validator={"address": "0x" + "11" * 20},
            signer_key="22" * 32,
        )
        self.assertIn('name = "binance"', toml)
        self.assertIn(
            'websocket = "wss://stream.binance.com:9443/ws"',
            toml,
        )
        self.assertNotIn("chain_denom", toml)
        self.assertNotIn("rest =", toml)

    def test_distribution_is_one_self_contained_archive_per_machine(self):
        """The whole point: after one run there is nothing left to assemble by
        hand, and no machine receives another validator's key material."""
        import tarfile as tf

        with tempfile.TemporaryDirectory() as tmp:
            _, _, output_dir = self.render(tmp)
            dist = output_dir / "dist"
            self.assertTrue((dist / "SHA256SUMS").is_file())
            self.assertTrue((dist / "unpack.sh").stat().st_mode & 0o111)

            for index in range(4):
                archive = dist / f"validator-{index}.tgz"
                self.assertTrue(archive.is_file(), f"validator-{index}.tgz missing")
                with tf.open(archive) as tar:
                    names = tar.getnames()
                joined = "\n".join(names)
                for required in ("genesis.json", "reth-bootnodes.txt",
                                 f"validator-{index}", "systemd", "install-systemd.sh"):
                    self.assertIn(required, joined, f"{required} missing from archive {index}")
                # Only this validator's keys travel in this archive.
                self.assertIn(f"keys/validator-{index}", joined)
                for other in range(4):
                    if other != index:
                        self.assertNotIn(f"keys/validator-{other}", joined)

            # The manifest must actually match the archives.
            for line in (dist / "SHA256SUMS").read_text().splitlines():
                digest, name = line.split("  ")
                import hashlib as hl
                self.assertEqual(hl.sha256((dist / name).read_bytes()).hexdigest(), digest)

    def test_a_private_signing_key_never_reaches_the_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            signed = pathlib.Path(tmp) / "signed"
            signed.mkdir()
            for name in LB.SIGNED_ENCLAVE_FILES:
                (signed / name).write_bytes(b"x")
            (signed / "enclave-key.pem").write_bytes(b"PRIVATE")
            _, _, output_dir = self.render(tmp, {"signed_enclave_dir": str(signed)})
            staged = list((output_dir / "enclave").iterdir())
            self.assertEqual(
                sorted(p.name for p in staged), sorted(LB.SIGNED_ENCLAVE_FILES)
            )
            self.assertNotIn("enclave-key.pem", [p.name for p in staged])

    def test_caddy_publishes_rpc_without_exposing_the_node(self):
        """The node binds RPC to loopback, so caddy is what makes it reachable;
        the raw Radicle replication port is p2p and must not be proxied."""
        with tempfile.TemporaryDirectory() as tmp:
            _, _, output_dir = self.render(tmp)
            caddyfile = (output_dir / "validator-0" / "Caddyfile").read_text()
            self.assertIn("reverse_proxy 127.0.0.1:8545", caddyfile)
            self.assertIn("reverse_proxy 127.0.0.1:8876", caddyfile)
            self.assertNotIn("8776", caddyfile)
            # No certificate names here: these hosts are addressed by IP.
            self.assertIn("auto_https off", caddyfile)
            installer = output_dir / "validator-0" / "install-caddy.sh"
            self.assertTrue(installer.stat().st_mode & 0o111)
            node = (output_dir / "validator-0" / "run-node.sh").read_text()
            self.assertIn("--http.addr 127.0.0.1", node)

    def test_systemd_units_are_generated_and_ordered(self):
        """A shell-launched background process dies with its session; systemd
        units are what actually survives, restarts and orders the stack."""
        with tempfile.TemporaryDirectory() as tmp:
            _, _, output_dir = self.render(tmp)
            unit_dir = output_dir / "systemd"
            for role in (
                "enclave",
                "radicle",
                "node",
                "ocomp-exporter",
                "ocomp-worker",
                "ocomp-successor-worker",
                "feeder",
            ):
                unit = unit_dir / f"outbe-{role}@.service"
                self.assertTrue(unit.is_file(), f"{role} unit missing")
                text = unit.read_text()
                self.assertIn("Restart=on-failure", text)
                self.assertIn(f"run-{role}.sh", text)
            self.assertEqual(
                {path.name for path in unit_dir.glob("*.service")},
                {
                    "outbe-enclave@.service",
                    "outbe-radicle@.service",
                    "outbe-node@.service",
                    "outbe-ocomp-exporter@.service",
                    "outbe-ocomp-worker@.service",
                    "outbe-ocomp-successor-worker@.service",
                    "outbe-feeder@.service",
                },
            )
            # The node must not start before the enclave and Radicle it needs.
            node = (unit_dir / "outbe-node@.service").read_text()
            self.assertIn("outbe-radicle@%i.service", node)
            radicle = (unit_dir / "outbe-radicle@.service").read_text()
            self.assertIn("outbe-enclave@%i.service", radicle)
            for role in ("ocomp-exporter", "ocomp-worker", "ocomp-successor-worker"):
                unit = (unit_dir / f"outbe-{role}@.service").read_text()
                self.assertIn("Requires=outbe-node@%i.service", unit)
            # The enclave needs root for /dev/sgx_*.
            self.assertIn("User=root", (unit_dir / "outbe-enclave@.service").read_text())
            installer = output_dir / "install-systemd.sh"
            self.assertTrue(installer.stat().st_mode & 0o111)

    def test_bootnodes_are_stable_across_renders(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, output_dir = self.render(tmp)
            first = (output_dir / "reth-bootnodes.txt").read_text()
            config = minimal_config(str(pathlib.Path(tmp) / "keys"))
            LB.render(
                config=config,
                validators=self.fake_validators(),
                genesis_path=output_dir / "genesis.json",
                keys_dir=pathlib.Path(tmp) / "keys",
                repo_root=REPO_ROOT,
            )
            self.assertEqual(first, (output_dir / "reth-bootnodes.txt").read_text())
            self.assertEqual(len(first.strip().splitlines()), 4)
            for line, validator in zip(
                first.strip().splitlines(), self.fake_validators(), strict=True
            ):
                host = validator["p2p_address"].split(":")[0]
                self.assertTrue(line.startswith("enode://"))
                self.assertTrue(line.endswith(f"@{host}:30303"))

    def test_ocomp_evm_key_defaults_to_the_validator_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, keys_dir, _ = self.render(tmp)
            for index in range(4):
                directory = keys_dir / f"validator-{index}"
                self.assertEqual(
                    (directory / "ocomp-evm-key.hex").read_text().strip(),
                    (directory / "evm-key.hex").read_text().strip(),
                )

    def test_remote_paths_are_used_in_the_scripts(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, output_dir = self.render(
                tmp, {"remote_base_dir": "/opt/outbe", "remote_keys_dir": "/opt/outbe/keys"}
            )
            node_script = (output_dir / "validator-1" / "run-node.sh").read_text()
            self.assertIn("/opt/outbe/genesis.json", node_script)
            self.assertIn("/opt/outbe/keys/validator-1", node_script)
            self.assertIn("--consensus.listen-addr 0.0.0.0:30400", node_script)

    def test_dcap_enclave_script_mounts_the_sgx_devices(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = {
                "tee": {
                    "mode": "dcap-required",
                    "mrenclave": "aa" * 32,
                    "mrsigner": "bb" * 32,
                    "isv_prod_id": 0,
                    "minimum_isv_svn": 0,
                    "minimum_tcb_evaluation_data_number": 0,
                }
            }
            _, _, output_dir = self.render(tmp, config)
            script = (output_dir / "validator-0" / "run-enclave.sh").read_text()
            self.assertIn("/dev/sgx_enclave", script)
            self.assertIn("/dev/sgx_provision", script)
            self.assertNotIn("--dkg-seed", script)

    def test_production_enclave_runs_natively_not_in_a_container(self):
        """The live network runs gramine-sgx on the host: the SGX driver, the
        AESM socket and the sealed state are all host-side."""
        with tempfile.TemporaryDirectory() as tmp:
            config = {
                "chain_id": 70860602,
                "tee": {
                    "mode": "dcap-required",
                    "mrenclave": "ab" * 32,
                    "mrsigner": "cd" * 32,
                    "isv_prod_id": 0,
                    "minimum_isv_svn": 3,
                    "minimum_tcb_evaluation_data_number": 17,
                },
            }
            _, _, output_dir = self.render(tmp, config)
            script = (output_dir / "validator-0" / "run-enclave.sh").read_text()
            self.assertNotIn("docker run", script)
            self.assertIn("/dev/sgx_enclave", script)
            self.assertIn("aesmd.service", script)
            node = (output_dir / "validator-0" / "run-node.sh").read_text()
            self.assertIn("--tee-session-mode production-node-host", node)

    def test_node_advertises_its_own_address_and_places_consensus_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, output_dir = self.render(tmp)
            node = (output_dir / "validator-2" / "run-node.sh").read_text()
            # Without --nat a machine behind one advertises the wrong address
            # and its peers never dial back.
            self.assertIn("--nat extip:10.0.0.3", node)
            self.assertIn("--consensus.storage-dir", node)
            # A real gramine-sgx enclave speaks the production session even on
            # the dev genesis profile; only a mock enclave uses the development
            # transport, and that is what `enclave_sgx: false` selects.
            self.assertIn("--tee-session-mode production-node-host", node)
            # All three OCOMP roles read the bundle from the domain directory.
            self.assertIn("protocol-bundle-v1.ocb1", node)

    def test_a_mock_enclave_keeps_the_development_transport(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, output_dir = self.render(tmp, {"enclave_sgx": False})
            node = (output_dir / "validator-0" / "run-node.sh").read_text()
            self.assertNotIn("--tee-session-mode", node)

    def test_dev_enclave_script_is_marked_unattested(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, output_dir = self.render(tmp, {"enclave_sgx": False})
            script = (output_dir / "validator-0" / "run-enclave.sh").read_text()
            self.assertIn("--dkg-seed", script)
            self.assertIn("unattested", script.lower())
            deploy = (output_dir / "DEPLOY.md").read_text()
            self.assertIn("unattested", deploy)

    @unittest.skipIf(
        pathlib.Path("/dev/sgx_enclave").exists() or pathlib.Path("/dev/sgx/enclave").exists(),
        "this negative launch test needs a host without SGX",
    )
    def test_explicit_sgx_launch_fails_without_hardware_before_any_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, _, output_dir = self.render(tmp, {"enclave_sgx": True})
            result = subprocess.run(
                ["bash", str(output_dir / "validator-0" / "run-enclave.sh")],
                capture_output=True, text=True, timeout=10,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("SGX hardware required", result.stderr)


if __name__ == "__main__":
    unittest.main()
