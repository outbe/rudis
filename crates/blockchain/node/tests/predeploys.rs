//! Integration tests for genesis pre-deployed external contracts.
//!
//! These contracts are placed at well-known addresses by the genesis pipeline
//! (`scripts/seed_genesis.py` consuming `seed-testnet.json:contracts[]`, which
//! references the bytecode/state triplet under `scripts/contracts/` produced
//! by `scripts/fetch_contract.py`). They are ordinary EVM accounts holding
//! canonical third-party (or Outbe-internal) runtime bytecode - not Outbe
//! stateful precompiles.
//!
//! Coverage:
//!  * `predeployed_bytecode_matches_vendored_artifacts` - the test genesis
//!    `alloc` carries byte-identical bytecode to the canonical `*.code.hex`
//!    files under `scripts/contracts/`. The corresponding `*.meta.json`
//!    is cross-checked against the address constant in `addresses.rs`,
//!    catching artifacts fetched from the wrong address.
//!  * `entrypoint_v07_inlines_sender_creator_immutable` - the SenderCreator
//!    address is encoded as an immutable inside EntryPoint v0.7's runtime
//!    bytecode. Catches the v0.7 constructor side-effect gotcha: if the
//!    SenderCreator we pre-deploy lives at a different address than the one
//!    EntryPoint expects, UserOperation `initCode` flows would silently
//!    revert.
//!  * `handleops_end_to_end` (`#[ignore]`) - stretch goal tracked.

use alloy_primitives::Address;
use outbe_primitives::addresses::{
    CREATE2_DEPLOYER_ADDRESS, ENTRY_POINT_V07_ADDRESS, SENDER_CREATOR_V07_ADDRESS,
};
use serde_json::Value;
use std::path::PathBuf;
use std::str::FromStr;

struct Predeploy {
    address: Address,
    name: &'static str,
    label: &'static str,
}

const PREDEPLOYS: &[Predeploy] = &[
    Predeploy {
        address: CREATE2_DEPLOYER_ADDRESS,
        name: "create2_deployer",
        label: "Arachnid CREATE2 deployer",
    },
    Predeploy {
        address: ENTRY_POINT_V07_ADDRESS,
        name: "entrypoint_v07",
        label: "ERC-4337 EntryPoint v0.7",
    },
    Predeploy {
        address: SENDER_CREATOR_V07_ADDRESS,
        name: "sender_creator_v07",
        label: "ERC-4337 SenderCreator v0.7",
    },
];

fn workspace_root() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("../../..");
    p.canonicalize()
        .expect("workspace root should canonicalize")
}

fn load_test_genesis_alloc() -> serde_json::Map<String, Value> {
    let path = workspace_root().join("crates/blockchain/node/tests/assets/genesis.json");
    let bytes = std::fs::read(&path).expect("test genesis.json should be readable");
    let v: Value = serde_json::from_slice(&bytes).expect("test genesis.json should parse");
    v["alloc"]
        .as_object()
        .expect("test genesis.alloc should be an object")
        .clone()
}

fn load_bytecode(name: &str) -> String {
    let path = workspace_root()
        .join("scripts/contracts")
        .join(format!("{name}.code.hex"));
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("bytecode file {path:?} should be readable: {e}"))
        .trim()
        .to_string()
}

fn load_meta(name: &str) -> Value {
    let path = workspace_root()
        .join("scripts/contracts")
        .join(format!("{name}.meta.json"));
    serde_json::from_slice(&std::fs::read(&path).expect("meta file should be readable"))
        .expect("meta file should parse")
}

fn alloc_key(addr: Address) -> String {
    // The test asset stores alloc keys as lowercase hex without 0x prefix
    // (matching the convention in scripts/seed_genesis.py).
    format!("{addr:x}")
}

fn decode_hex(s: &str) -> Vec<u8> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(stripped).expect("hex decode")
}

#[test]
fn predeployed_bytecode_matches_vendored_artifacts() {
    let alloc = load_test_genesis_alloc();
    for p in PREDEPLOYS {
        let key = alloc_key(p.address);
        let entry = alloc.get(&key).unwrap_or_else(|| {
            panic!(
                "test genesis alloc missing pre-deploy {} ({} at 0x{key})",
                p.label, p.name
            )
        });
        let asset_code = entry["code"]
            .as_str()
            .unwrap_or_else(|| panic!("{}: alloc entry missing 'code' field", p.label));

        let vendored_code = load_bytecode(p.name);
        assert_eq!(
            asset_code, vendored_code,
            "{}: test genesis bytecode drifted from canonical artifact at scripts/contracts/{}.code.hex",
            p.label, p.name
        );

        // Cross-check the meta.json address against the Rust constant. Guards
        // against an artifact accidentally fetched from a different address
        // than the predeploy is supposed to live at.
        let meta = load_meta(p.name);
        let meta_addr = meta["address"]
            .as_str()
            .unwrap_or_else(|| panic!("{}: meta missing 'address' field", p.label));
        let parsed = Address::from_str(meta_addr)
            .unwrap_or_else(|e| panic!("{}: meta address parse failed: {e}", p.label));
        assert_eq!(
            parsed, p.address,
            "{}: meta.address ({meta_addr}) does not match predeploy address ({:?})",
            p.label, p.address
        );
    }
}

#[test]
fn entrypoint_v07_inlines_sender_creator_immutable() {
    // Solidity inlines `immutable` address values directly into runtime
    // bytecode (typically as `PUSH20 <address>`), not into storage. If the
    // SenderCreator we pre-deploy is at a different address than the one
    // EntryPoint v0.7's compiled bytecode expects, UserOperation `initCode`
    // flows would route through a contract that does not exist and silently
    // revert. Verifying the address pattern occurs in the EntryPoint runtime
    // catches that mismatch in CI rather than in production.
    let entrypoint_code = decode_hex(&load_bytecode("entrypoint_v07"));

    let sender_creator_bytes: [u8; 20] = SENDER_CREATOR_V07_ADDRESS.0.into();
    let occurrences = entrypoint_code
        .windows(20)
        .filter(|w| *w == sender_creator_bytes)
        .count();

    assert!(
        occurrences > 0,
        "SenderCreator v0.7 address {SENDER_CREATOR_V07_ADDRESS:?} not found inside EntryPoint v0.7 runtime bytecode \
         - pre-deployed SenderCreator address does not match EntryPoint's compiled immutable. \
         Verify the address derivation: keccak256(rlp([entrypoint, 1]))[12:]"
    );
}
