use std::{fs, path::Path, process::Command};

use serde_json::json;
use tempfile::TempDir;
use xtask::stablecoin::{check_abi_exports, check_namespace};

const FACTORY: &str = "000000000000000000000000000000000000ee0f";
const POLICY: &str = "000000000000000000000000000000000000ee10";

#[test]
fn repository_namespace_is_collision_free() {
    let report = check_namespace(repository_root(), &[], false).unwrap();
    assert!(report.declared_addresses > 30);
    assert_eq!(report.ethereum_builtins, 10);
    assert!(report.genesis_files >= 1);
    assert!(report.predeploy_addresses >= 6);
    assert_eq!(report.planned_classes, 1);
}

#[test]
fn complete_abi_exports_match_compiled_solidity_interfaces() {
    let report = check_abi_exports(repository_root()).unwrap();
    assert_eq!(report.interfaces, 4);
}

#[test]
fn genesis_rejects_dynamic_class_and_fixed_account_collisions() {
    let directory = TempDir::new().unwrap();
    let prefix_path = directory.path().join("prefix.json");
    write_json(
        &prefix_path,
        &json!({"alloc": {"53c0000000000000000000000000000000000000": {"balance": "0x1"}}}),
    );
    let error = check_namespace(repository_root(), &[prefix_path], true).unwrap_err();
    assert!(error
        .to_string()
        .contains("planned address class stablecoin-v1"));

    let fixed_path = directory.path().join("fixed.json");
    write_json(
        &fixed_path,
        &json!({"alloc": {"000000000000000000000000000000000000ee0f": {"code": "0x00"}}}),
    );
    let error = check_namespace(repository_root(), &[fixed_path], true).unwrap_err();
    assert!(error.to_string().contains("conflicting code"));
}

#[test]
fn seed_predeploy_rejects_both_stablecoin_fixed_addresses() {
    for reserved in [
        "0x000000000000000000000000000000000000EE0F",
        "0x000000000000000000000000000000000000EE10",
    ] {
        let directory = TempDir::new().unwrap();
        let root = directory.path();
        let fixture_dir = root.join("crates/blockchain/primitives/testdata/stablecoin/v1");
        fs::create_dir_all(&fixture_dir).unwrap();
        for fixture in [
            "network-address-vectors.json",
            "planned-address-classes.json",
        ] {
            fs::copy(
                repository_root()
                    .join("crates/blockchain/primitives/testdata/stablecoin/v1")
                    .join(fixture),
                fixture_dir.join(fixture),
            )
            .unwrap();
        }
        let addresses = root.join("crates/blockchain/primitives/src");
        fs::create_dir_all(&addresses).unwrap();
        fs::write(
            addresses.join("addresses.rs"),
            concat!(
                "const FACTORY: Address = address!(\"0x000000000000000000000000000000000000ee0f\");\n",
                "const POLICY: Address = address!(\"0x000000000000000000000000000000000000ee10\");\n"
            ),
        )
        .unwrap();
        let scripts = root.join("scripts");
        fs::create_dir_all(&scripts).unwrap();
        write_json(
            &scripts.join("seed-conflict.json"),
            &json!({"contracts": [{"address": reserved}]}),
        );

        let error = check_namespace(root, &[], true).unwrap_err();
        assert!(error
            .to_string()
            .contains("seed predeploy collides with stablecoin fixed address"));
    }
}

#[test]
fn complete_python_seeder_output_passes_xtask_validation() {
    let directory = TempDir::new().unwrap();
    let genesis = directory.path().join("genesis.json");
    let seed = directory.path().join("seed.json");
    let output = directory.path().join("output.json");
    write_json(
        &genesis,
        &json!({"config": {}, "alloc": {}, "timestamp": "0x0"}),
    );
    write_json(&seed, &json!({}));

    let result = Command::new("python3")
        .arg(repository_root().join("scripts/seed_genesis.py"))
        .arg("--genesis")
        .arg(&genesis)
        .arg("--seed")
        .arg(&seed)
        .arg("--output")
        .arg(&output)
        .current_dir(repository_root())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "seed_genesis.py failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );

    let report = check_namespace(repository_root(), std::slice::from_ref(&output), false).unwrap();
    assert!(report.genesis_files >= 2);

    let generated: serde_json::Value = serde_json::from_slice(&fs::read(output).unwrap()).unwrap();
    assert_eq!(generated["alloc"][FACTORY]["code"], "0xef");
    assert_eq!(generated["alloc"][POLICY]["code"], "0xef");
}

fn repository_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask must live directly under repository root")
}

fn write_json(path: &Path, value: &serde_json::Value) {
    let bytes = serde_json::to_vec(value).unwrap();
    fs::write(path, bytes).unwrap();
}
