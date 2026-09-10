use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use eyre::{bail, eyre, Result, WrapErr};
use serde::Deserialize;
use serde_json::{Map, Value};
use walkdir::{DirEntry, WalkDir};

const ETHEREUM_BUILTIN_MAX: u8 = 10;
const STABLECOIN_INTERFACES: [&str; 4] = [
    "IStablecoin",
    "IStablecoinFactory",
    "IStablecoinPolicyRegistry",
    "IVote",
];

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct StablecoinAddressManifest {
    factory: String,
    policy_registry: String,
    prefix: String,
    marker: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlannedAddressClasses {
    schema_version: u32,
    classes: Vec<PlannedAddressClass>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PlannedAddressClass {
    name: String,
    prefix: String,
    prefix_bits: u16,
    owner: String,
}

#[derive(Debug)]
struct CheckedAddressClass {
    name: String,
    prefix: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceReport {
    pub declared_addresses: usize,
    pub ethereum_builtins: usize,
    pub genesis_files: usize,
    pub predeploy_addresses: usize,
    pub planned_classes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbiReport {
    pub interfaces: usize,
}

pub fn check_namespace(
    repo_root: &Path,
    genesis_paths: &[PathBuf],
    preseed: bool,
) -> Result<NamespaceReport> {
    let manifest = load_address_manifest(repo_root)?;
    let classes = load_planned_classes(repo_root, &manifest)?;
    let declared = scan_declared_addresses(repo_root, &manifest, &classes)?;
    let predeploy_addresses = scan_seed_predeploys(repo_root, &manifest, &classes)?;

    let repository_geneses = repository_genesis_paths(repo_root)?;
    for path in &repository_geneses {
        scan_genesis(path, &manifest, &classes, true)?;
    }
    for path in genesis_paths {
        scan_genesis(path, &manifest, &classes, preseed)?;
    }

    let all_geneses: BTreeSet<PathBuf> = repository_geneses
        .into_iter()
        .chain(genesis_paths.iter().cloned())
        .collect();
    Ok(NamespaceReport {
        declared_addresses: declared.len(),
        ethereum_builtins: usize::from(ETHEREUM_BUILTIN_MAX),
        genesis_files: all_geneses.len(),
        predeploy_addresses,
        planned_classes: classes.len(),
    })
}

pub fn check_abi_exports(repo_root: &Path) -> Result<AbiReport> {
    let contracts_root = repo_root.join("contracts/precompiles");
    for interface in STABLECOIN_INTERFACES {
        let output = Command::new("forge")
            .args(["inspect", interface, "abi", "--json"])
            .current_dir(&contracts_root)
            .output()
            .wrap_err_with(|| format!("run forge inspect for {interface}"))?;
        if !output.status.success() {
            bail!(
                "forge inspect {interface} failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let compiled: Value = serde_json::from_slice(&output.stdout)
            .wrap_err_with(|| format!("parse compiled ABI for {interface}"))?;
        let export_path = contracts_root
            .join("abi-export")
            .join(format!("{interface}.json"));
        let exported: Value = serde_json::from_slice(
            &fs::read(&export_path)
                .wrap_err_with(|| format!("read ABI export {}", export_path.display()))?,
        )
        .wrap_err_with(|| format!("parse ABI export {}", export_path.display()))?;
        if compiled != exported {
            bail!(
                "ABI export {} does not match compiled Solidity interface {interface}",
                export_path.display()
            );
        }
    }
    Ok(AbiReport {
        interfaces: STABLECOIN_INTERFACES.len(),
    })
}

fn load_address_manifest(repo_root: &Path) -> Result<StablecoinAddressManifest> {
    let path = repo_root
        .join("crates/blockchain/primitives/testdata/stablecoin/v1/network-address-vectors.json");
    let bytes = fs::read(&path).wrap_err_with(|| format!("read {}", path.display()))?;
    serde_json::from_slice(&bytes).wrap_err_with(|| format!("parse {}", path.display()))
}

fn load_planned_classes(
    repo_root: &Path,
    manifest: &StablecoinAddressManifest,
) -> Result<Vec<CheckedAddressClass>> {
    let path = repo_root
        .join("crates/blockchain/primitives/testdata/stablecoin/v1/planned-address-classes.json");
    let bytes = fs::read(&path).wrap_err_with(|| format!("read {}", path.display()))?;
    let registry: PlannedAddressClasses =
        serde_json::from_slice(&bytes).wrap_err_with(|| format!("parse {}", path.display()))?;
    if registry.schema_version != 1 {
        bail!("unsupported planned address-class schema version");
    }
    if registry.classes.is_empty() {
        bail!("planned address-class registry must not be empty");
    }

    let mut checked = Vec::with_capacity(registry.classes.len());
    let mut names = BTreeSet::new();
    for class in registry.classes {
        if !names.insert(class.name.clone()) {
            bail!("duplicate planned address class {}", class.name);
        }
        if class.owner.is_empty() {
            bail!("planned address class {} has no owner", class.name);
        }
        if class.prefix_bits == 0 || class.prefix_bits % 8 != 0 {
            bail!(
                "planned address class {} prefixBits must be nonzero and byte-aligned",
                class.name
            );
        }
        let prefix = canonical_variable_prefix(&class.prefix, class.prefix_bits)?;
        checked.push(CheckedAddressClass {
            name: class.name,
            prefix,
        });
    }

    for (index, left) in checked.iter().enumerate() {
        for right in checked.iter().skip(index + 1) {
            if left.prefix.starts_with(&right.prefix) || right.prefix.starts_with(&left.prefix) {
                bail!(
                    "planned address classes {} and {} overlap",
                    left.name,
                    right.name
                );
            }
        }
    }

    let stablecoin_prefix = canonical_prefix(&manifest.prefix)?;
    if !checked
        .iter()
        .any(|class| class.name == "stablecoin-v1" && class.prefix == stablecoin_prefix)
    {
        bail!("stablecoin network prefix is absent from the planned class registry");
    }
    Ok(checked)
}

fn scan_declared_addresses(
    repo_root: &Path,
    manifest: &StablecoinAddressManifest,
    classes: &[CheckedAddressClass],
) -> Result<BTreeSet<String>> {
    let path = repo_root.join("crates/blockchain/primitives/src/addresses.rs");
    let source = fs::read_to_string(&path).wrap_err_with(|| format!("read {}", path.display()))?;
    let addresses = address_literals(&source)?;
    let unique: BTreeSet<String> = addresses.iter().cloned().collect();
    if unique.len() != addresses.len() {
        bail!("duplicate address! literal in {}", path.display());
    }

    let factory = canonical_address(&manifest.factory)?;
    let policy = canonical_address(&manifest.policy_registry)?;
    if !unique.contains(&factory) || !unique.contains(&policy) {
        bail!(
            "stablecoin fixed addresses are missing from {}",
            path.display()
        );
    }
    reject_class_collision(unique.iter().map(String::as_str), classes, "fixed address")?;

    for suffix in 1..=ETHEREUM_BUILTIN_MAX {
        let builtin = format!("{:040x}", suffix);
        if unique.contains(&builtin) {
            bail!("Outbe address collides with Ethereum built-in 0x{builtin}");
        }
        reject_class_collision(
            std::iter::once(builtin.as_str()),
            classes,
            "Ethereum built-in",
        )?;
    }
    marker_byte(&manifest.marker)?;
    Ok(unique)
}

fn scan_seed_predeploys(
    repo_root: &Path,
    manifest: &StablecoinAddressManifest,
    classes: &[CheckedAddressClass],
) -> Result<usize> {
    let scripts = repo_root.join("scripts");
    let mut predeploys = BTreeSet::new();
    for entry in fs::read_dir(&scripts).wrap_err_with(|| format!("read {}", scripts.display()))? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };
        if !name.contains("seed") || path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        let value: Value = serde_json::from_slice(
            &fs::read(&path).wrap_err_with(|| format!("read {}", path.display()))?,
        )
        .wrap_err_with(|| format!("parse {}", path.display()))?;
        let Some(contracts) = value.get("contracts").and_then(Value::as_array) else {
            continue;
        };
        for contract in contracts {
            let raw = contract
                .get("address")
                .and_then(Value::as_str)
                .ok_or_else(|| eyre!("{} contract entry has no address", path.display()))?;
            predeploys.insert(canonical_address(raw)?);
        }
    }
    reject_class_collision(
        predeploys.iter().map(String::as_str),
        classes,
        "seed predeploy",
    )?;
    for reserved in [
        canonical_address(&manifest.factory)?,
        canonical_address(&manifest.policy_registry)?,
    ] {
        if predeploys.contains(&reserved) {
            bail!("seed predeploy collides with stablecoin fixed address 0x{reserved}");
        }
    }
    // A seed predeploy may intentionally have a matching canonical constant in
    // addresses.rs (for example EntryPoint). Exact aliases are one address identity;
    // overlap with a planned dynamic class remains forbidden above.
    Ok(predeploys.len())
}

fn repository_genesis_paths(repo_root: &Path) -> Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for entry in WalkDir::new(repo_root)
        .into_iter()
        .filter_entry(include_repository_entry)
    {
        let entry = entry.wrap_err("walk repository genesis files")?;
        if entry.file_type().is_file() && entry.file_name() == "genesis.json" {
            paths.push(entry.into_path());
        }
    }
    paths.sort();
    Ok(paths)
}

fn include_repository_entry(entry: &DirEntry) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    !matches!(
        entry.file_name().to_str(),
        Some(".git" | ".pi" | "target" | "node_modules" | "worktrees")
    )
}

fn scan_genesis(
    path: &Path,
    manifest: &StablecoinAddressManifest,
    classes: &[CheckedAddressClass],
    preseed: bool,
) -> Result<()> {
    let bytes = fs::read(path).wrap_err_with(|| format!("read genesis {}", path.display()))?;
    let genesis: Value = serde_json::from_slice(&bytes)
        .wrap_err_with(|| format!("parse genesis {}", path.display()))?;
    let alloc = genesis
        .get("alloc")
        .and_then(Value::as_object)
        .ok_or_else(|| eyre!("genesis {} alloc must be an object", path.display()))?;

    let factory = canonical_address(&manifest.factory)?;
    let policy = canonical_address(&manifest.policy_registry)?;
    let marker = manifest.marker.to_ascii_lowercase();
    let mut normalized = BTreeSet::new();
    let mut fixed_entries = Map::new();

    for (raw_address, account) in alloc {
        let address = canonical_address(raw_address)?;
        if !normalized.insert(address.clone()) {
            bail!("duplicate normalized genesis alloc address 0x{address}");
        }
        reject_class_collision(
            std::iter::once(address.as_str()),
            classes,
            "genesis address",
        )?;
        if address == factory || address == policy {
            fixed_entries.insert(address, account.clone());
        }
    }

    for address in [&factory, &policy] {
        let Some(account) = fixed_entries.get(address) else {
            if preseed {
                continue;
            }
            bail!("genesis is missing stablecoin reserved account 0x{address}");
        };
        validate_fixed_account(address, account, &marker, preseed)?;
    }
    Ok(())
}

fn reject_class_collision<'a>(
    addresses: impl Iterator<Item = &'a str>,
    classes: &[CheckedAddressClass],
    kind: &str,
) -> Result<()> {
    for address in addresses {
        if let Some(class) = classes
            .iter()
            .find(|class| address.starts_with(&class.prefix))
        {
            bail!(
                "{kind} 0x{address} collides with planned address class {} (0x{})",
                class.name,
                class.prefix
            );
        }
    }
    Ok(())
}

fn validate_fixed_account(
    address: &str,
    account: &Value,
    marker: &str,
    preseed: bool,
) -> Result<()> {
    let account = account
        .as_object()
        .ok_or_else(|| eyre!("genesis account 0x{address} must be an object"))?;
    match account.get("code").and_then(Value::as_str) {
        Some(code) if code.eq_ignore_ascii_case(marker) => {}
        Some(_) => {
            bail!("stablecoin reserved account 0x{address} has conflicting code");
        }
        None if preseed => {}
        None => {
            bail!("stablecoin reserved account 0x{address} is missing marker code");
        }
    }
    if account
        .get("storage")
        .and_then(Value::as_object)
        .is_some_and(|storage| !storage.is_empty())
    {
        bail!("stablecoin reserved account 0x{address} has conflicting storage");
    }
    for field in ["balance", "nonce"] {
        if account
            .get(field)
            .is_some_and(|value| !is_zero_quantity(value))
        {
            bail!("stablecoin reserved account 0x{address} has nonzero or invalid {field}");
        }
    }
    Ok(())
}

fn is_zero_quantity(value: &Value) -> bool {
    match value {
        Value::Number(number) => number.as_u64() == Some(0),
        Value::String(value) => {
            let digits = value
                .strip_prefix("0x")
                .or_else(|| value.strip_prefix("0X"))
                .unwrap_or(value);
            !digits.is_empty()
                && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
                && digits.bytes().all(|byte| byte == b'0')
        }
        _ => false,
    }
}

fn address_literals(source: &str) -> Result<Vec<String>> {
    let marker = "address!(\"0x";
    let mut remaining = source;
    let mut addresses = Vec::new();
    while let Some(offset) = remaining.find(marker) {
        let start = offset + marker.len();
        let end = start + 40;
        let value = remaining
            .get(start..end)
            .ok_or_else(|| eyre!("truncated address! literal"))?;
        addresses.push(canonical_address(value)?);
        remaining = remaining
            .get(end..)
            .ok_or_else(|| eyre!("truncated addresses source"))?;
    }
    Ok(addresses)
}

fn canonical_address(value: &str) -> Result<String> {
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    if value.len() != 40 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid EVM address: {value}");
    }
    Ok(value.to_ascii_lowercase())
}

fn canonical_prefix(value: &str) -> Result<String> {
    canonical_variable_prefix(value, 16)
}

fn canonical_variable_prefix(value: &str, prefix_bits: u16) -> Result<String> {
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    let expected_hex = usize::from(prefix_bits / 4);
    if value.len() != expected_hex || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("invalid {prefix_bits}-bit address prefix: {value}");
    }
    Ok(value.to_ascii_lowercase())
}

fn marker_byte(value: &str) -> Result<u8> {
    let value = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    let bytes = hex::decode(value).wrap_err("decode stablecoin marker")?;
    match bytes.as_slice() {
        [byte] => Ok(*byte),
        _ => {
            bail!("stablecoin marker must contain exactly one byte");
        }
    }
}
