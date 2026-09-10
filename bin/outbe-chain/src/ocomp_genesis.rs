use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write as _,
    path::{Path, PathBuf},
    str::FromStr as _,
};

use alloy_primitives::{Address, B256};
use clap::{Parser, Subcommand};
use eyre::{ensure, WrapErr as _};
use outbe_metadosis::{
    config::{OcompForkInstallClassification, OcompForkInstallV1, OcompRequestProfile},
    proof_layout::METADOSIS_STORAGE_LAYOUT_V1_HASH,
};
use outbe_ocomp_protocol::{
    committee::{
        validator_identity_hash_v1, OcompKeyRegistrationV1, POC_KEY_EPOCH,
        RESULT_SIGNATURE_PURPOSE_BITMAP,
    },
    profile::{CapacityProfileV1, ProtocolBundleV1},
    registry::{FIDELITY_OPENING_CODEC_ID, ORACLE_OPENING_CODEC_ID, TRIBUTE_BODY_CODEC_ID},
};
use outbe_primitives::OutbeHeader;
use reth_chainspec::ChainSpec;
use reth_ethereum::chainspec::EthChainSpec as _;
use serde::Serialize;

const ACTIVATION_HEIGHT: u64 = outbe_node::ocomp::fork::GENESIS_ACTIVE_OCOMP_HEIGHT;
const OCOMP_FIELD: &str = outbe_node::ocomp::fork::OCOMP_FORK_INSTALL_GENESIS_KEY;
const LAYOUT_FIELD: &str = outbe_node::ocomp::fork::METADOSIS_STORAGE_LAYOUT_GENESIS_KEY;

#[derive(Debug, Parser)]
#[command(name = "outbe-chain-ocomp")]
struct OcompCli {
    #[command(subcommand)]
    command: OcompCommand,
}

#[derive(Debug, Subcommand)]
enum OcompCommand {
    /// Derive the exact chain bindings needed to generate founder OCOMP registrations.
    Bindings(OcompBindingsArgs),
    /// Install a block-1 Measurement OCOMP profile using all founder registrations.
    Genesis(OcompGenesisArgs),
    /// Build a predecessor-bound OCOMP successor and ready-to-submit Update payload.
    Successor(OcompSuccessorArgs),
}

#[derive(Debug, clap::Args)]
struct OcompBindingsArgs {
    /// Seeded genesis JSON without OCOMP or TEE extensions.
    #[arg(long)]
    input: PathBuf,
    /// Ordered public bootstrap manifest for every genesis validator.
    #[arg(long)]
    validators: PathBuf,
    /// New JSON document consumed by network preparation tooling.
    #[arg(long)]
    output: PathBuf,
}

#[derive(Debug, clap::Args)]
struct OcompGenesisArgs {
    /// Seeded genesis JSON without OCOMP or TEE extensions.
    #[arg(long)]
    input: PathBuf,
    /// Ordered public bootstrap manifest for every genesis validator.
    #[arg(long)]
    validators: PathBuf,
    /// Directory containing validator-N/ocomp-registration-v1.ocb1.
    #[arg(long)]
    registrations_dir: PathBuf,
    /// New OCOMP-armed genesis JSON.
    #[arg(long)]
    output: PathBuf,
    /// New canonical protocol-bundle-v1.ocb1 file.
    #[arg(long)]
    protocol_bundle_output: PathBuf,
}

#[derive(Debug, clap::Args)]
struct OcompSuccessorArgs {
    /// Existing OCOMP-armed chain genesis (supplies immutable network policy).
    #[arg(long)]
    genesis: PathBuf,
    /// Canonical bundle currently active on-chain.
    #[arg(long)]
    predecessor_bundle: PathBuf,
    /// Canonical bundle produced by the successor release build.
    #[arg(long)]
    successor_bundle: PathBuf,
    /// Fixed block at which Update activates this successor.
    #[arg(long)]
    activation_height: u64,
    /// Software protocol version carried by the enclosing Update proposal.
    #[arg(long)]
    update_version: String,
    /// Human-readable Update proposal note.
    #[arg(long, default_value = "OCOMP protocol successor")]
    info: String,
    /// New canonical OCS1 evidence file.
    #[arg(long)]
    successor_output: PathBuf,
    /// New ready-to-submit Update proposal JSON.
    #[arg(long)]
    proposal_output: PathBuf,
    /// Existing directory where the hash-named successor .ocb1 is installed.
    #[arg(long)]
    bundle_catalog_dir: PathBuf,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OcompBindingsDocumentV1 {
    schema_version: u16,
    chain_id: u64,
    genesis_hash: B256,
    validator_identity_hashes: Vec<B256>,
}

pub(crate) fn run(arguments: &[String]) -> eyre::Result<()> {
    let mut ocomp_arguments = vec![arguments[0].clone()];
    ocomp_arguments.extend_from_slice(&arguments[2..]);
    match OcompCli::parse_from(ocomp_arguments).command {
        OcompCommand::Bindings(args) => write_bindings(&args),
        OcompCommand::Genesis(args) => generate_genesis(&args),
        OcompCommand::Successor(args) => generate_successor(&args),
    }
}

fn generate_successor(args: &OcompSuccessorArgs) -> eyre::Result<()> {
    ensure!(
        args.activation_height > 1,
        "successor activation height must be above genesis"
    );
    require_new_output(&args.successor_output, "OCOMP successor")?;
    require_new_output(&args.proposal_output, "Update proposal")?;
    ensure!(
        args.bundle_catalog_dir.is_dir(),
        "OCOMP bundle catalog directory does not exist: {}",
        args.bundle_catalog_dir.display()
    );

    let limits = outbe_ocomp_protocol::profile::poc_schema_limits();
    let chain_spec: ChainSpec<OutbeHeader> = reth_ethereum::cli::chainspec::chain_value_parser(
        utf8_path(&args.genesis, "OCOMP genesis")?,
    )?
    .as_ref()
    .clone()
    .map_header(OutbeHeader::new);
    let install = outbe_node::ocomp::fork::require_startup_ocomp_fork_install(&chain_spec)?;
    let predecessor_bytes = fs::read(&args.predecessor_bundle).wrap_err_with(|| {
        format!(
            "read predecessor OCOMP bundle {}",
            args.predecessor_bundle.display()
        )
    })?;
    let successor_bytes = fs::read(&args.successor_bundle).wrap_err_with(|| {
        format!(
            "read successor OCOMP bundle {}",
            args.successor_bundle.display()
        )
    })?;
    let predecessor = ProtocolBundleV1::decode_canonical(&predecessor_bytes, &limits)?;
    let successor_bundle = ProtocolBundleV1::decode_canonical(&successor_bytes, &limits)?;
    ensure!(
        predecessor.encode_canonical(&limits)? == predecessor_bytes,
        "predecessor OCOMP bundle is not canonical"
    );
    ensure!(
        successor_bundle.encode_canonical(&limits)? == successor_bytes,
        "successor OCOMP bundle is not canonical"
    );
    let predecessor_hash = predecessor.protocol_bundle_hash(&limits)?;
    if predecessor.protocol_version == 1 {
        ensure!(
            predecessor_hash == install.request_profile.protocol_bundle_hash,
            "version-1 predecessor does not match the genesis OCOMP authority"
        );
    }
    let successor_hash = successor_bundle.protocol_bundle_hash(&limits)?;
    let base_profile = outbe_ocompregistry::OcompRequestProfile::decode_canonical(
        &install.request_profile.encode_canonical(&limits)?,
        &limits,
    )?;
    let predecessor_authority = outbe_ocompregistry::OcompProtocolAuthorityV1 {
        request_profile: outbe_ocompregistry::OcompRequestProfile {
            fork_id: predecessor.fork_id,
            protocol_bundle_hash: predecessor_hash,
            correctness_profile_id: predecessor.correctness_profile_id,
            ..base_profile.clone()
        },
        protocol_bundle: predecessor,
    };
    let successor = outbe_ocompregistry::OcompSuccessorV1 {
        activation_height: args.activation_height,
        predecessor_protocol_bundle_hash: predecessor_hash,
        authority: outbe_ocompregistry::OcompProtocolAuthorityV1 {
            request_profile: outbe_ocompregistry::OcompRequestProfile {
                fork_id: successor_bundle.fork_id,
                protocol_bundle_hash: successor_hash,
                correctness_profile_id: successor_bundle.correctness_profile_id,
                ..base_profile
            },
            protocol_bundle: successor_bundle,
        },
    };
    successor.validate_against(&predecessor_authority, args.activation_height - 1, &limits)?;
    let successor_canonical = successor.encode_canonical(&limits)?;
    let update_version = outbe_update::version::try_parse_protocol_version(&args.update_version)
        .map_err(|error| eyre::eyre!("invalid Update protocol version: {error}"))?;
    let payload = outbe_update::ScheduleUpdatePayload::new(
        update_version,
        args.activation_height,
        args.info.clone(),
    )
    .with_ocomp_successor(&successor)
    .map_err(|error| eyre::eyre!("build Update payload: {error}"))?;
    let catalog_path = args
        .bundle_catalog_dir
        .join(format!("{}.ocb1", hex::encode(successor_hash.as_slice())));
    require_new_output(&catalog_path, "hash-named OCOMP successor bundle")?;

    write_new_file(
        &args.successor_output,
        &successor_canonical,
        "OCOMP successor",
    )?;
    if let Err(error) = write_new_file(
        &args.proposal_output,
        &pretty_json(&payload)?,
        "Update proposal",
    )
    .and_then(|()| {
        write_new_file(
            &catalog_path,
            &successor_bytes,
            "hash-named OCOMP successor bundle",
        )
    }) {
        let _ = fs::remove_file(&args.successor_output);
        let _ = fs::remove_file(&args.proposal_output);
        let _ = fs::remove_file(&catalog_path);
        return Err(error);
    }
    println!(
        "wrote OCOMP successor: predecessor={predecessor_hash}, successor={successor_hash}, activation={}, payload={}, bundle={}",
        args.activation_height,
        args.proposal_output.display(),
        catalog_path.display()
    );
    Ok(())
}

fn write_bindings(args: &OcompBindingsArgs) -> eyre::Result<()> {
    require_new_output(&args.output, "OCOMP bindings")?;
    let (chain_id, genesis_hash) = parse_base_identity(&args.input)?;
    let input_genesis: serde_json::Value = serde_json::from_slice(
        &fs::read(&args.input)
            .wrap_err_with(|| format!("read input genesis {}", args.input.display()))?,
    )
    .wrap_err("decode input genesis JSON")?;
    let _protocol_constants = selected_protocol_parameters(&input_genesis)?;
    let validator_identity_hashes = validator_identities(&args.validators)?;
    let document = OcompBindingsDocumentV1 {
        schema_version: 1,
        chain_id,
        genesis_hash,
        validator_identity_hashes,
    };
    write_new_file(&args.output, &pretty_json(&document)?, "OCOMP bindings")?;
    println!(
        "wrote OCOMP registration bindings: {}",
        args.output.display()
    );
    Ok(())
}

fn generate_genesis(args: &OcompGenesisArgs) -> eyre::Result<()> {
    ensure!(
        args.input != args.output,
        "--input and --output must differ"
    );
    require_new_output(&args.output, "OCOMP genesis")?;
    require_new_output(&args.protocol_bundle_output, "OCOMP protocol bundle")?;

    let (chain_id, genesis_hash) = parse_base_identity(&args.input)?;
    let input_genesis: serde_json::Value = serde_json::from_slice(
        &fs::read(&args.input)
            .wrap_err_with(|| format!("read input genesis {}", args.input.display()))?,
    )
    .wrap_err("decode input genesis JSON")?;
    let protocol_constants = selected_protocol_parameters(&input_genesis)?;
    let validator_identity_hashes = validator_identities(&args.validators)?;
    let protocol_bundle = measurement_protocol_bundle();
    let limits = outbe_ocomp_protocol::profile::poc_schema_limits();
    let registrations =
        load_registrations(&args.registrations_dir, validator_identity_hashes.len())?;
    validate_founder_registrations(
        chain_id,
        genesis_hash,
        &validator_identity_hashes,
        &registrations,
    )?;
    let protocol_bundle_hash = protocol_bundle.protocol_bundle_hash(&limits)?;
    let install = OcompForkInstallV1 {
        classification: OcompForkInstallClassification::Measurement,
        activation_height: ACTIVATION_HEIGHT,
        request_profile: OcompRequestProfile {
            chain_id,
            genesis_hash,
            fork_id: protocol_bundle.fork_id,
            protocol_bundle_hash,
            correctness_profile_id: protocol_bundle.correctness_profile_id,
            capacity_profile: measurement_capacity_profile(
                protocol_constants.ocomp_compute_vote_window_blocks,
            ),
            source_availability_policy_id: B256::repeat_byte(44),
        },
        protocol_bundle,
        founder_registrations: registrations,
    };
    install.validate_for_chain(chain_id, genesis_hash, &limits)?;
    let canonical_install = install.encode_canonical(&limits)?;
    let install_hash = install.install_hash(&limits)?;

    let mut genesis: serde_json::Value = serde_json::from_slice(
        &fs::read(&args.input)
            .wrap_err_with(|| format!("read input genesis {}", args.input.display()))?,
    )
    .wrap_err("decode input genesis JSON")?;
    let config = genesis
        .get_mut("config")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| eyre::eyre!("input genesis config must be a JSON object"))?;
    ensure!(
        !config.contains_key(OCOMP_FIELD) && !config.contains_key(LAYOUT_FIELD),
        "input genesis already contains an OCOMP or Metadosis layout extension"
    );
    config.insert(
        OCOMP_FIELD.to_owned(),
        serde_json::json!({
            "canonicalBytes": format!("0x{}", hex::encode(canonical_install)),
            "installHash": install_hash,
        }),
    );
    config.insert(
        LAYOUT_FIELD.to_owned(),
        serde_json::json!({ "layoutHash": METADOSIS_STORAGE_LAYOUT_V1_HASH }),
    );

    let genesis_bytes = pretty_json(&genesis)?;
    let protocol_bundle_bytes = install.protocol_bundle.encode_canonical(&limits)?;
    write_new_file(&args.output, &genesis_bytes, "OCOMP genesis")?;
    if let Err(error) = write_new_file(
        &args.protocol_bundle_output,
        &protocol_bundle_bytes,
        "OCOMP protocol bundle",
    )
    .and_then(|()| validate_output(&args.output, chain_id, genesis_hash, &install))
    {
        let _ = fs::remove_file(&args.output);
        let _ = fs::remove_file(&args.protocol_bundle_output);
        return Err(error);
    }
    println!(
        "wrote block-1 Measurement OCOMP genesis: chain_id={chain_id}, genesis_hash={genesis_hash}, output={}",
        args.output.display()
    );
    Ok(())
}

fn parse_base_identity(path: &Path) -> eyre::Result<(u64, B256)> {
    let path = utf8_path(path, "input genesis")?;
    let spec = reth_ethereum::cli::chainspec::chain_value_parser(path)
        .wrap_err_with(|| format!("parse input genesis {path}"))?;
    let extra = &spec.genesis.config.extra_fields;
    ensure!(
        !extra.contains_key(OCOMP_FIELD) && !extra.contains_key(LAYOUT_FIELD),
        "input genesis must not already contain OCOMP extensions"
    );
    Ok((spec.chain().id(), spec.genesis_hash()))
}

fn validator_identities(path: &Path) -> eyre::Result<Vec<B256>> {
    let validators: serde_json::Value = serde_json::from_slice(
        &fs::read(path).wrap_err_with(|| format!("read validators {}", path.display()))?,
    )
    .wrap_err("decode validators JSON")?;
    let validators = validators
        .as_array()
        .ok_or_else(|| eyre::eyre!("validators manifest must be a JSON array"))?;
    let max_validators = usize::try_from(outbe_consensus::bls::MAX_VALIDATORS)
        .map_err(|_| eyre::eyre!("consensus validator bound does not fit usize"))?;
    ensure!(
        !validators.is_empty(),
        "validators manifest must not be empty"
    );
    ensure!(
        validators.len() <= max_validators,
        "validators manifest contains {} entries, above consensus bound {max_validators}",
        validators.len()
    );
    let mut identities = Vec::with_capacity(validators.len());
    for (index, validator) in validators.iter().enumerate() {
        let address = validator
            .get("address")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| eyre::eyre!("validator-{index} has no address"))
            .and_then(|value| Address::from_str(value).map_err(Into::into))?;
        let public_key = validator
            .get("public_key")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| eyre::eyre!("validator-{index} has no public_key"))?;
        let public_key = hex::decode(public_key.strip_prefix("0x").unwrap_or(public_key))?;
        ensure!(
            public_key.len() == 48,
            "validator-{index} public key must be 48 bytes"
        );
        let public_key: [u8; 48] = public_key
            .try_into()
            .map_err(|_| eyre::eyre!("validator-{index} public key must be 48 bytes"))?;
        identities.push(validator_identity_hash_v1(address, &public_key)?);
    }
    Ok(identities)
}

fn load_registrations(directory: &Path, count: usize) -> eyre::Result<Vec<OcompKeyRegistrationV1>> {
    let limits = outbe_ocomp_protocol::profile::poc_schema_limits();
    for entry in fs::read_dir(directory)
        .wrap_err_with(|| format!("read OCOMP registrations directory {}", directory.display()))?
    {
        let entry = entry.wrap_err("read OCOMP registration directory entry")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| eyre::eyre!("OCOMP registration directory entry is not UTF-8"))?;
        let Some(index) = name.strip_prefix("validator-") else {
            continue;
        };
        let index = index
            .parse::<usize>()
            .wrap_err_with(|| format!("invalid OCOMP registration directory {name}"))?;
        ensure!(
            index < count,
            "extra OCOMP registration directory {name} for {count} validators"
        );
        ensure!(
            entry
                .file_type()
                .wrap_err_with(|| format!("inspect OCOMP registration directory {name}"))?
                .is_dir(),
            "OCOMP registration entry {name} is not a directory"
        );
    }
    let mut registrations = Vec::with_capacity(count);
    for index in 0..count {
        let path = directory
            .join(format!("validator-{index}"))
            .join("ocomp-registration-v1.ocb1");
        registrations.push(
            OcompKeyRegistrationV1::decode_canonical(
                &fs::read(&path)
                    .wrap_err_with(|| format!("read OCOMP registration {}", path.display()))?,
                &limits,
            )
            .wrap_err_with(|| format!("decode OCOMP registration {}", path.display()))?,
        );
    }
    Ok(registrations)
}

fn validate_founder_registrations(
    chain_id: u64,
    genesis_hash: B256,
    validator_identity_hashes: &[B256],
    registrations: &[OcompKeyRegistrationV1],
) -> eyre::Result<()> {
    ensure!(
        registrations.len() == validator_identity_hashes.len(),
        "founder registration count {} does not match validator count {}",
        registrations.len(),
        validator_identity_hashes.len()
    );
    let limits = outbe_ocomp_protocol::profile::poc_schema_limits();
    let mut keys = BTreeSet::new();
    for (index, (identity, registration)) in validator_identity_hashes
        .iter()
        .zip(registrations)
        .enumerate()
    {
        ensure!(
            registration.core.chain_id == chain_id
                && registration.core.genesis_hash == genesis_hash
                && registration.core.validator_identity_hash == *identity
                && registration.core.key_epoch == POC_KEY_EPOCH
                && registration.core.allowed_purpose_bitmap == RESULT_SIGNATURE_PURPOSE_BITMAP,
            "validator-{index} OCOMP registration does not match this genesis"
        );
        registration
            .validate_proof_of_possession(&limits)
            .wrap_err_with(|| format!("verify validator-{index} OCOMP registration"))?;
        ensure!(
            keys.insert(registration.core.ocomp_public_key_sec1),
            "validator-{index} reuses an OCOMP public key"
        );
    }
    Ok(())
}

fn validate_output(
    output: &Path,
    expected_chain_id: u64,
    expected_genesis_hash: B256,
    expected_install: &OcompForkInstallV1,
) -> eyre::Result<()> {
    let parsed: ChainSpec<OutbeHeader> =
        reth_ethereum::cli::chainspec::chain_value_parser(utf8_path(output, "output genesis")?)?
            .as_ref()
            .clone()
            .map_header(OutbeHeader::new);
    ensure!(
        parsed.chain().id() == expected_chain_id,
        "generated genesis changed chain ID"
    );
    ensure!(
        parsed.genesis_hash() == expected_genesis_hash,
        "OCOMP extension changed genesis hash"
    );
    let loaded = outbe_node::ocomp::fork::require_startup_ocomp_fork_install(&parsed)?;
    ensure!(
        loaded.as_ref() == expected_install,
        "node parser returned a different OCOMP install"
    );
    Ok(())
}

fn measurement_capacity_profile(result_deadline_blocks: u64) -> CapacityProfileV1 {
    CapacityProfileV1 {
        profile_id: B256::repeat_byte(13),
        max_tributes_per_work_shard: 256,
        max_workers_per_domain: 4,
        max_intents_per_block: 1,
        max_activations_per_block: 1,
        max_ready_inspections_per_block: 1,
        max_expirations_per_block: 1,
        ready_backoff_blocks: 1,
        max_reference_currencies: 256,
        max_oracle_wwd_pair_entries: 256,
        max_active_scurve_entries: 256,
        result_deadline_blocks,
        source_retention_after_terminal_blocks: 64,
        generated_limits_manifest_hash: B256::repeat_byte(23),
    }
}

fn selected_protocol_parameters(
    genesis: &serde_json::Value,
) -> eyre::Result<outbe_chain_constants::GenesisProtocolParametersV1> {
    let config = genesis
        .get("config")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| eyre::eyre!("input genesis config must be a JSON object"))?;
    outbe_chain_constants::GenesisProtocolParametersV1::select_for_build(
        config.get(outbe_chain_constants::GENESIS_CONFIG_KEY),
    )
    .map_err(Into::into)
}

fn measurement_protocol_bundle() -> ProtocolBundleV1 {
    let hash = B256::repeat_byte;
    ProtocolBundleV1 {
        protocol_version: 1,
        fork_id: hash(1),
        intent_codec_id: hash(2),
        finalized_intent_proof_codec_id: hash(3),
        tribute_body_codec_id: TRIBUTE_BODY_CODEC_ID,
        fidelity_opening_codec_id: FIDELITY_OPENING_CODEC_ID,
        oracle_opening_codec_id: ORACLE_OPENING_CODEC_ID,
        result_codec_id: hash(4),
        action_codec_id: hash(5),
        activation_codec_id: hash(6),
        evidence_codec_id: hash(7),
        request_semantics_version: 1,
        lysis_program_semantics_hash: hash(8),
        planner_spec_version: 1,
        reducer_spec_version: 1,
        activation_apply_semantics_hash: hash(9),
        effect_contract_registry_hash: hash(10),
        object_codec_registry_hash: hash(11),
        correctness_profile_id: hash(12),
        capacity_profile_id: hash(13),
        result_signature_profile_id: hash(14),
        finality_verifier_and_vote_domain_id: hash(15),
        consensus_committee_history_schema_version: 1,
        ocomp_committee_schema_version: 1,
        proof_system_and_verifier_key_id: None,
        da_codec_and_binding_verifier_id: None,
        anti_equivocation_journal_schema_hash: hash(16),
        mode_pause_revocation_semantics_hash: hash(17),
        upgrade_fsm_semantics_hash: hash(18),
        release_requirement_catalog_sequence: 1,
        release_requirement_catalog_hash: hash(19),
        release_requirement_catalog_parent_hash: hash(20),
        release_gate_authority_envelope_hash: hash(21),
        release_approval_policy_hash: hash(22),
        release_validator_command_artifact_hash: hash(23),
        consensus_state_schema_version: 1,
        migration_manifest_hash: hash(24),
        required_upgrade_handler_set_hash: hash(25),
    }
}

fn require_new_output(path: &Path, description: &str) -> eyre::Result<()> {
    ensure!(
        !path.exists(),
        "refusing to overwrite existing {description}: {}",
        path.display()
    );
    ensure!(
        path.parent().is_some_and(Path::exists),
        "{description} parent does not exist: {}",
        path.display()
    );
    Ok(())
}

fn write_new_file(path: &Path, bytes: &[u8], description: &str) -> eyre::Result<()> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .wrap_err_with(|| format!("create {description} {}", path.display()))?;
    output
        .write_all(bytes)
        .and_then(|()| output.sync_all())
        .wrap_err_with(|| format!("write {description} {}", path.display()))
}

fn pretty_json(value: &impl Serialize) -> eyre::Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn utf8_path<'a>(path: &'a Path, description: &str) -> eyre::Result<&'a str> {
    path.to_str()
        .ok_or_else(|| eyre::eyre!("{description} path is not UTF-8: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::{signature::hazmat::PrehashSigner, Signature, SigningKey};

    fn registration(identity: B256, key_byte: u8) -> OcompKeyRegistrationV1 {
        let limits = outbe_ocomp_protocol::profile::poc_schema_limits();
        let key = SigningKey::from_bytes(
            (&outbe_primitives::test_keys::secret((key_byte) as u64)).into(),
        )
        .unwrap();
        let mut registration = OcompKeyRegistrationV1 {
            core: outbe_ocomp_protocol::committee::OcompKeyRegistrationCoreV1 {
                chain_id: 42,
                genesis_hash: B256::repeat_byte(0x42),
                validator_identity_hash: identity,
                ocomp_public_key_sec1: key
                    .verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .try_into()
                    .unwrap(),
                key_epoch: POC_KEY_EPOCH,
                allowed_purpose_bitmap: RESULT_SIGNATURE_PURPOSE_BITMAP,
            },
            proof_of_possession: [0; 64],
        };
        let digest = registration.proof_of_possession_digest(&limits).unwrap();
        let signature: Signature = key.sign_prehash(digest.as_slice()).unwrap();
        registration.proof_of_possession = signature.to_bytes().into();
        registration
    }

    #[cfg(not(feature = "test-protocol-overrides"))]
    #[test]
    fn production_ocomp_profile_rejects_genesis_overrides() {
        let genesis = serde_json::json!({
            "config": {
                "outbeProtocol": {
                    "ocomp": { "computeVoteWindowBlocks": 120 }
                }
            }
        });

        let error = selected_protocol_parameters(&genesis).unwrap_err();
        assert!(error
            .to_string()
            .contains("supported only by test-protocol-overrides builds"));
    }

    #[cfg(feature = "test-protocol-overrides")]
    #[test]
    fn test_ocomp_profile_uses_genesis_override() {
        let genesis = serde_json::json!({
            "config": {
                "outbeProtocol": {
                    "ocomp": { "computeVoteWindowBlocks": 120 }
                }
            }
        });

        let selected = selected_protocol_parameters(&genesis).unwrap();
        assert_eq!(selected.ocomp_compute_vote_window_blocks, 120);
    }

    #[test]
    fn validator_bindings_follow_the_manifest_length_and_shared_identity_helper() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("validators.json");
        let validators = (0..5_u8)
            .map(|index| {
                serde_json::json!({
                    "address": Address::repeat_byte(index.saturating_add(1)),
                    "public_key": format!("0x{}", hex::encode([index.saturating_add(0x31); 48])),
                })
            })
            .collect::<Vec<_>>();
        fs::write(&path, serde_json::to_vec(&validators).unwrap()).unwrap();

        let identities = validator_identities(&path).unwrap();
        assert_eq!(identities.len(), validators.len());
        for (index, identity) in identities.into_iter().enumerate() {
            assert_eq!(
                identity,
                validator_identity_hash_v1(
                    Address::repeat_byte(u8::try_from(index).unwrap().saturating_add(1)),
                    &[u8::try_from(index).unwrap().saturating_add(0x31); 48],
                )
                .unwrap()
            );
        }
    }

    #[test]
    fn genesis_founder_registration_set_is_exact_ordered_and_unique() {
        let identities = [B256::repeat_byte(0x11), B256::repeat_byte(0x22)];
        let first = registration(identities[0], 1);
        let second = registration(identities[1], 2);

        validate_founder_registrations(
            42,
            B256::repeat_byte(0x42),
            &identities,
            &[first.clone(), second.clone()],
        )
        .unwrap();
        assert!(validate_founder_registrations(
            42,
            B256::repeat_byte(0x42),
            &identities,
            &[second.clone(), first.clone()],
        )
        .is_err());
        assert!(validate_founder_registrations(
            42,
            B256::repeat_byte(0x42),
            &identities,
            std::slice::from_ref(&first),
        )
        .is_err());
        assert!(validate_founder_registrations(
            42,
            B256::repeat_byte(0x42),
            &identities,
            &[
                first.clone(),
                second.clone(),
                registration(B256::repeat_byte(0x33), 3)
            ],
        )
        .is_err());

        let duplicate_key = registration(identities[1], 1);
        assert!(validate_founder_registrations(
            42,
            B256::repeat_byte(0x42),
            &identities,
            &[first, duplicate_key],
        )
        .is_err());
    }

    #[test]
    fn registration_directory_rejects_extra_validator_material() {
        let directory = tempfile::tempdir().unwrap();
        let limits = outbe_ocomp_protocol::profile::poc_schema_limits();
        for index in 0..2_u8 {
            let validator_dir = directory.path().join(format!("validator-{index}"));
            fs::create_dir(&validator_dir).unwrap();
            fs::write(
                validator_dir.join("ocomp-registration-v1.ocb1"),
                registration(
                    B256::repeat_byte(index.saturating_add(1)),
                    index.saturating_add(1),
                )
                .encode_canonical(&limits)
                .unwrap(),
            )
            .unwrap();
        }

        assert!(load_registrations(directory.path(), 1).is_err());
    }
}
