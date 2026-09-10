//! Deterministic OCM-26 final bundle and chain-manifest generation.
//!
//! Capacity is measured first. This module then binds that exact profile to
//! implementation semantic digests, a fresh base genesis and one public OCOMP
//! registration for every ordered genesis validator. Registrations bootstrap
//! keys only; runtime voting membership comes exclusively from ValidatorSet
//! snapshots. Deterministic keys generated without `--registrations-dir` are
//! reference-E2E fixture material, never production secrets.

use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    str::FromStr as _,
};

use alloy_primitives::{Address, B256};
use eyre::{ensure, Context as _, Result};
use k256::ecdsa::{signature::hazmat::PrehashSigner as _, Signature, SigningKey};
use outbe_metadosis::config::{
    OcompForkInstallClassification, OcompForkInstallV1, OcompRequestProfile,
    OCOMP_POC_FINAL_ACTIVATION_HEIGHT,
};
use outbe_ocomp_protocol::{
    committee::{
        validator_identity_hash_v1, OcompKeyRegistrationCoreV1, OcompKeyRegistrationV1,
        POC_KEY_EPOCH, RESULT_SIGNATURE_PURPOSE_BITMAP,
    },
    generated_shape::{
        OCOMP_CAPACITY_PROFILE_ID_HEX, OCOMP_CORRECTNESS_PROFILE_ID_HEX, OCOMP_POC_FORK_ID_HEX,
    },
    profile::{
        poc_schema_limits, CapacityProfileV1, CorrectnessProfileV1, ProgramId, ProtocolBundleV1,
    },
    registry::{FIDELITY_OPENING_CODEC_ID, ORACLE_OPENING_CODEC_ID, TRIBUTE_BODY_CODEC_ID},
};
use outbe_primitives::OutbeHeader;
use reth_chainspec::ChainSpec;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tempfile::NamedTempFile;
use walkdir::WalkDir;

const FINAL_ARTIFACT_SCHEMA_VERSION: u16 = 1;
const FINAL_ARTIFACT_KIND: &str = "outbe-ocomp-final-artifacts-v1";
const FINAL_ARTIFACT_DOMAIN: &[u8] = b"OUTBE_OCOMP_FINAL_ARTIFACT_V1\0";
const SEMANTIC_DESCRIPTOR_PATH: &str =
    "crates/system/ocomp-protocol/registry/semantic-artifacts-v1.tsv";
const REGISTRY_SOURCES: &[&str] = &[
    "crates/system/ocomp-protocol/registry/ocomp-v1.tsv",
    "crates/system/ocomp-protocol/registry/preimages-v1.tsv",
    "crates/system/ocomp-protocol/registry/schema-v1.tsv",
    "crates/system/ocomp-protocol/registry/input-codecs-v1.tsv",
    SEMANTIC_DESCRIPTOR_PATH,
    "crates/system/ocomp-protocol/registry/generated-shape-manifest.json",
];
const GENERATOR_SOURCES: &[&str] = &["xtask/src/ocomp/capacity.rs", "xtask/src/ocomp/finalize.rs"];

const CAPACITY_FILE: &str = "capacity-profile-v1.ocb1";
const GENERATED_CAPACITY_FILE: &str = "generated-capacity-v1.json";
const CORRECTNESS_FILE: &str = "correctness-profile-v1.ocb1";
const BUNDLE_FILE: &str = "protocol-bundle-v1.ocb1";
const INSTALL_FILE: &str = "fork-install-v1.ocb1";
const CHAIN_MANIFEST_FILE: &str = "genesis-final.json";
const NETWORK_MANIFEST_FILE: &str = "network-binding-v1.json";
const SEMANTICS_MANIFEST_FILE: &str = "semantic-artifacts-v1.json";

#[derive(Clone, Copy, Debug, Default)]
pub struct FinalArtifactOverrides<'a> {
    pub registrations_dir: Option<&'a Path>,
    pub release_artifacts_dir: Option<&'a Path>,
}

struct LoadedReleaseArtifacts {
    correctness_bytes: Vec<u8>,
    protocol_bundle: ProtocolBundleV1,
    protocol_bundle_bytes: Vec<u8>,
    source_availability_policy_id: B256,
    semantic_bytes: Vec<u8>,
}

#[derive(Debug, Deserialize)]
struct GeneratedCapacityInputV1 {
    schema_version: u16,
    kind: String,
    source_revision: B256,
    artifact_set_hash: B256,
    capacity_evidence_sha256: B256,
    generated_limits_manifest_sha256: B256,
    capacity_profile_id: B256,
    capacity_profile_ocb1_sha256: B256,
    capacity_profile_ocb1_hex: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
struct SemanticArtifactsV1 {
    intent_codec_id: B256,
    finalized_intent_proof_codec_id: B256,
    result_codec_id: B256,
    action_codec_id: B256,
    activation_codec_id: B256,
    evidence_codec_id: B256,
    arithmetic_profile_id: B256,
    lysis_program_semantics_hash: B256,
    activation_apply_semantics_hash: B256,
    effect_contract_registry_hash: B256,
    object_codec_registry_hash: B256,
    list_root_scheme_id: B256,
    result_signature_profile_id: B256,
    finality_verifier_and_vote_domain_id: B256,
    anti_equivocation_journal_schema_hash: B256,
    mode_pause_revocation_semantics_hash: B256,
    upgrade_fsm_semantics_hash: B256,
    release_placeholder_hash: B256,
    source_availability_policy_id: B256,
}

#[derive(Debug, Deserialize)]
struct FrozenSemanticArtifactsDocumentV1 {
    schema_version: u16,
    kind: String,
    artifacts: SemanticArtifactsV1,
}

#[derive(Debug, Deserialize)]
struct FrozenReleaseBindingV1 {
    schema_version: u16,
    kind: String,
    classification: String,
    fork_id: B256,
    correctness_profile_id: B256,
    capacity_profile_id: B256,
    protocol_bundle_hash: B256,
    correctness_profile_ocb1_sha256: B256,
    protocol_bundle_ocb1_sha256: B256,
    semantic_artifacts_sha256: B256,
}

#[derive(Debug, Serialize)]
struct SemanticArtifactsDocumentV1 {
    schema_version: u16,
    kind: &'static str,
    source_sets: BTreeMap<&'static str, B256>,
    artifacts: SemanticArtifactsV1,
}

#[derive(Debug, Serialize)]
struct NetworkBindingDocumentV1 {
    schema_version: u16,
    kind: &'static str,
    classification: &'static str,
    activation_height: u64,
    measurement_source_revision: B256,
    measurement_artifact_set_hash: B256,
    generated_capacity_manifest_sha256: B256,
    capacity_evidence_sha256: B256,
    generated_limits_manifest_sha256: B256,
    generator_source_sha256: B256,
    base_genesis_sha256: B256,
    validators_manifest_sha256: B256,
    chain_id: u64,
    genesis_hash: B256,
    fork_id: B256,
    correctness_profile_id: B256,
    correctness_profile_ocb1_sha256: B256,
    capacity_profile_id: B256,
    capacity_profile_ocb1_sha256: B256,
    protocol_bundle_hash: B256,
    protocol_bundle_ocb1_sha256: B256,
    founder_registration_count: u16,
    fork_install_hash: B256,
    fork_install_ocb1_sha256: B256,
    chain_manifest_sha256: B256,
    semantic_artifacts_sha256: B256,
}

pub fn run(
    repository_root: &Path,
    capacity_path: &Path,
    base_genesis_path: &Path,
    validators_path: &Path,
    overrides: FinalArtifactOverrides<'_>,
    output_dir: &Path,
    check: bool,
) -> Result<()> {
    let capacity_path = resolve(repository_root, capacity_path);
    let base_genesis_path = resolve(repository_root, base_genesis_path);
    let validators_path = resolve(repository_root, validators_path);
    let registrations_dir = overrides
        .registrations_dir
        .map(|path| resolve(repository_root, path));
    let release_artifacts_dir = overrides
        .release_artifacts_dir
        .map(|path| resolve(repository_root, path));
    let output_dir = resolve(repository_root, output_dir);
    ensure!(
        output_dir != Path::new("/") && output_dir.parent().is_some(),
        "final artifact output must be a non-root directory"
    );

    let capacity_input_bytes = fs::read(&capacity_path)
        .wrap_err_with(|| format!("read generated capacity {}", capacity_path.display()))?;
    let capacity_input: GeneratedCapacityInputV1 = serde_json::from_slice(&capacity_input_bytes)
        .wrap_err("decode generated capacity manifest")?;
    let capacity_bytes = decode_and_verify_capacity(&capacity_input, &capacity_input_bytes)?;
    let limits = poc_schema_limits();
    let capacity_profile = CapacityProfileV1::decode_canonical(&capacity_bytes, &limits)
        .wrap_err("decode generated capacity profile")?;

    let (source_sets, generated_semantic) = semantic_artifacts(repository_root)?;
    let generator_source_sha256 = *source_sets
        .get("generator")
        .ok_or_else(|| eyre::eyre!("semantic source set omitted the generator"))?;
    let correctness_profile_id = parse_b256(OCOMP_CORRECTNESS_PROFILE_ID_HEX)?;
    let capacity_profile_id = parse_b256(OCOMP_CAPACITY_PROFILE_ID_HEX)?;
    let fork_id = parse_b256(OCOMP_POC_FORK_ID_HEX)?;
    ensure!(
        capacity_profile.profile_id == capacity_profile_id,
        "capacity profile id differs from the frozen profile id"
    );
    let release = if let Some(release_artifacts_dir) = release_artifacts_dir.as_deref() {
        load_release_artifacts(
            release_artifacts_dir,
            fork_id,
            correctness_profile_id,
            capacity_profile_id,
            &limits,
        )?
    } else {
        let correctness_profile = CorrectnessProfileV1 {
            profile_id: correctness_profile_id,
            program: ProgramId::LysisV1,
            arithmetic_profile_id: generated_semantic.arithmetic_profile_id,
            object_codec_registry_hash: generated_semantic.object_codec_registry_hash,
            list_root_scheme_id: generated_semantic.list_root_scheme_id,
            result_signature_profile_id: generated_semantic.result_signature_profile_id,
            finality_verifier_profile_id: generated_semantic.finality_verifier_and_vote_domain_id,
        };
        let correctness_bytes = correctness_profile
            .encode_canonical(&limits)
            .wrap_err("encode correctness profile")?;
        let protocol_bundle = protocol_bundle(fork_id, capacity_profile_id, generated_semantic);
        let protocol_bundle_bytes = protocol_bundle
            .encode_canonical(&limits)
            .wrap_err("encode final protocol bundle")?;
        let semantic_document = SemanticArtifactsDocumentV1 {
            schema_version: FINAL_ARTIFACT_SCHEMA_VERSION,
            kind: "outbe-ocomp-semantic-artifacts-v1",
            source_sets: source_sets.clone(),
            artifacts: generated_semantic,
        };
        let semantic_bytes = pretty_json(&semantic_document)?;
        LoadedReleaseArtifacts {
            correctness_bytes,
            protocol_bundle,
            protocol_bundle_bytes,
            source_availability_policy_id: generated_semantic.source_availability_policy_id,
            semantic_bytes,
        }
    };
    let LoadedReleaseArtifacts {
        correctness_bytes,
        protocol_bundle,
        protocol_bundle_bytes,
        source_availability_policy_id,
        semantic_bytes,
    } = release;
    protocol_bundle
        .validate_lysis_v1_input_codecs()
        .wrap_err("validate final Lysis input codec bundle")?;
    let protocol_bundle_hash = protocol_bundle
        .protocol_bundle_hash(&limits)
        .wrap_err("hash final protocol bundle")?;

    let base_genesis_bytes = fs::read(&base_genesis_path)
        .wrap_err_with(|| format!("read base genesis {}", base_genesis_path.display()))?;
    let mut chain_manifest: serde_json::Value =
        serde_json::from_slice(&base_genesis_bytes).wrap_err("decode base genesis JSON")?;
    let config = chain_manifest
        .get("config")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| eyre::eyre!("base genesis config is not an object"))?;
    ensure!(
        !config.contains_key(outbe_node::ocomp::fork::OCOMP_FORK_INSTALL_GENESIS_KEY),
        "base genesis already contains an OCOMP fork install"
    );
    let base_spec = parse_chain_spec(&base_genesis_path)?;
    let chain_id = base_spec.chain().id();
    let genesis_hash = base_spec.genesis_hash();
    let validator_identities = validator_identities(&validators_path)?;
    let supplied_registrations = registrations_dir
        .as_deref()
        .map(|directory| load_registrations(directory, validator_identities.len(), &limits))
        .transpose()?;
    let founder_registrations = founder_registrations(
        chain_id,
        genesis_hash,
        validator_identities,
        supplied_registrations.as_deref(),
        &limits,
    )?;
    let install = OcompForkInstallV1 {
        classification: OcompForkInstallClassification::Final,
        activation_height: OCOMP_POC_FINAL_ACTIVATION_HEIGHT,
        request_profile: OcompRequestProfile {
            chain_id,
            genesis_hash,
            fork_id,
            protocol_bundle_hash,
            correctness_profile_id,
            capacity_profile,
            source_availability_policy_id,
        },
        protocol_bundle,
        founder_registrations,
    };
    install
        .validate_for_chain(chain_id, genesis_hash, &limits)
        .wrap_err("validate final fork install")?;
    let install_bytes = install
        .encode_canonical(&limits)
        .wrap_err("encode final fork install")?;
    let install_hash = install
        .install_hash(&limits)
        .wrap_err("hash final fork install")?;

    let config = chain_manifest
        .get_mut("config")
        .and_then(serde_json::Value::as_object_mut)
        .expect("base genesis config validated above");
    config.insert(
        outbe_node::ocomp::fork::OCOMP_FORK_INSTALL_GENESIS_KEY.to_owned(),
        serde_json::json!({
            "canonicalBytes": format!("0x{}", hex::encode(&install_bytes)),
            "installHash": install_hash,
        }),
    );
    let chain_manifest_bytes = pretty_json(&chain_manifest)?;
    validate_armed_manifest(&chain_manifest_bytes, genesis_hash, &install)?;

    let network_document = NetworkBindingDocumentV1 {
        schema_version: FINAL_ARTIFACT_SCHEMA_VERSION,
        kind: FINAL_ARTIFACT_KIND,
        classification: "final",
        activation_height: OCOMP_POC_FINAL_ACTIVATION_HEIGHT,
        measurement_source_revision: capacity_input.source_revision,
        measurement_artifact_set_hash: capacity_input.artifact_set_hash,
        generated_capacity_manifest_sha256: sha256(&capacity_input_bytes),
        capacity_evidence_sha256: capacity_input.capacity_evidence_sha256,
        generated_limits_manifest_sha256: capacity_input.generated_limits_manifest_sha256,
        generator_source_sha256,
        base_genesis_sha256: sha256(&base_genesis_bytes),
        validators_manifest_sha256: sha256(
            &fs::read(&validators_path).wrap_err("read validators manifest for binding")?,
        ),
        chain_id,
        genesis_hash,
        fork_id,
        correctness_profile_id,
        correctness_profile_ocb1_sha256: sha256(&correctness_bytes),
        capacity_profile_id,
        capacity_profile_ocb1_sha256: sha256(&capacity_bytes),
        protocol_bundle_hash,
        protocol_bundle_ocb1_sha256: sha256(&protocol_bundle_bytes),
        founder_registration_count: u16::try_from(install.founder_registrations.len())?,
        fork_install_hash: install_hash,
        fork_install_ocb1_sha256: sha256(&install_bytes),
        chain_manifest_sha256: sha256(&chain_manifest_bytes),
        semantic_artifacts_sha256: sha256(&semantic_bytes),
    };
    let network_bytes = pretty_json(&network_document)?;

    for (name, bytes) in [
        (CAPACITY_FILE, capacity_bytes.as_slice()),
        (GENERATED_CAPACITY_FILE, capacity_input_bytes.as_slice()),
        (CORRECTNESS_FILE, correctness_bytes.as_slice()),
        (BUNDLE_FILE, protocol_bundle_bytes.as_slice()),
        (INSTALL_FILE, install_bytes.as_slice()),
        (CHAIN_MANIFEST_FILE, chain_manifest_bytes.as_slice()),
        (NETWORK_MANIFEST_FILE, network_bytes.as_slice()),
        (SEMANTICS_MANIFEST_FILE, semantic_bytes.as_slice()),
    ] {
        update_or_check(&output_dir.join(name), bytes, check)?;
    }
    Ok(())
}

fn load_release_artifacts(
    directory: &Path,
    fork_id: B256,
    correctness_profile_id: B256,
    capacity_profile_id: B256,
    limits: &outbe_ocomp_protocol::SchemaLimits,
) -> Result<LoadedReleaseArtifacts> {
    let binding_path = directory.join(NETWORK_MANIFEST_FILE);
    let binding_bytes = fs::read(&binding_path)
        .wrap_err_with(|| format!("read frozen release binding {}", binding_path.display()))?;
    let binding: FrozenReleaseBindingV1 =
        serde_json::from_slice(&binding_bytes).wrap_err("decode frozen release binding")?;
    ensure!(
        binding.schema_version == FINAL_ARTIFACT_SCHEMA_VERSION
            && binding.kind == FINAL_ARTIFACT_KIND
            && binding.classification == "final"
            && binding.fork_id == fork_id
            && binding.correctness_profile_id == correctness_profile_id
            && binding.capacity_profile_id == capacity_profile_id,
        "frozen release binding does not match the OCOMP V1 release"
    );

    let correctness_path = directory.join(CORRECTNESS_FILE);
    let correctness_bytes = fs::read(&correctness_path).wrap_err_with(|| {
        format!(
            "read frozen correctness profile {}",
            correctness_path.display()
        )
    })?;
    let correctness_profile = CorrectnessProfileV1::decode_canonical(&correctness_bytes, limits)
        .wrap_err("decode frozen correctness profile")?;
    ensure!(
        sha256(&correctness_bytes) == binding.correctness_profile_ocb1_sha256
            && correctness_profile.profile_id == correctness_profile_id
            && correctness_profile.program == ProgramId::LysisV1,
        "frozen correctness profile does not match the OCOMP V1 release"
    );

    let bundle_path = directory.join(BUNDLE_FILE);
    let protocol_bundle_bytes = fs::read(&bundle_path)
        .wrap_err_with(|| format!("read frozen protocol bundle {}", bundle_path.display()))?;
    let protocol_bundle = ProtocolBundleV1::decode_canonical(&protocol_bundle_bytes, limits)
        .wrap_err("decode frozen protocol bundle")?;
    let protocol_bundle_hash = protocol_bundle
        .protocol_bundle_hash(limits)
        .wrap_err("hash frozen protocol bundle")?;
    ensure!(
        sha256(&protocol_bundle_bytes) == binding.protocol_bundle_ocb1_sha256
            && protocol_bundle_hash == binding.protocol_bundle_hash
            && protocol_bundle.fork_id == fork_id
            && protocol_bundle.correctness_profile_id == correctness_profile_id
            && protocol_bundle.capacity_profile_id == capacity_profile_id
            && protocol_bundle.object_codec_registry_hash
                == correctness_profile.object_codec_registry_hash
            && protocol_bundle.result_signature_profile_id
                == correctness_profile.result_signature_profile_id
            && protocol_bundle.finality_verifier_and_vote_domain_id
                == correctness_profile.finality_verifier_profile_id,
        "frozen protocol bundle and correctness profile are inconsistent"
    );

    let semantic_path = directory.join(SEMANTICS_MANIFEST_FILE);
    let semantic_bytes = fs::read(&semantic_path)
        .wrap_err_with(|| format!("read frozen semantic manifest {}", semantic_path.display()))?;
    let semantic: FrozenSemanticArtifactsDocumentV1 =
        serde_json::from_slice(&semantic_bytes).wrap_err("decode frozen semantic manifest")?;
    ensure!(
        sha256(&semantic_bytes) == binding.semantic_artifacts_sha256
            && semantic.schema_version == FINAL_ARTIFACT_SCHEMA_VERSION
            && semantic.kind == "outbe-ocomp-semantic-artifacts-v1",
        "frozen semantic manifest has an invalid identity"
    );
    validate_release_semantics(semantic.artifacts, &correctness_profile, &protocol_bundle)?;
    let source_availability_policy_id = semantic.artifacts.source_availability_policy_id;
    ensure!(
        !source_availability_policy_id.is_zero(),
        "frozen source availability policy id is zero"
    );

    Ok(LoadedReleaseArtifacts {
        correctness_bytes,
        protocol_bundle,
        protocol_bundle_bytes,
        source_availability_policy_id,
        semantic_bytes,
    })
}

fn validate_release_semantics(
    semantic: SemanticArtifactsV1,
    correctness: &CorrectnessProfileV1,
    bundle: &ProtocolBundleV1,
) -> Result<()> {
    ensure!(
        semantic.intent_codec_id == bundle.intent_codec_id
            && semantic.finalized_intent_proof_codec_id == bundle.finalized_intent_proof_codec_id
            && semantic.result_codec_id == bundle.result_codec_id
            && semantic.action_codec_id == bundle.action_codec_id
            && semantic.activation_codec_id == bundle.activation_codec_id
            && semantic.evidence_codec_id == bundle.evidence_codec_id
            && semantic.arithmetic_profile_id == correctness.arithmetic_profile_id
            && semantic.lysis_program_semantics_hash == bundle.lysis_program_semantics_hash
            && semantic.activation_apply_semantics_hash == bundle.activation_apply_semantics_hash
            && semantic.effect_contract_registry_hash == bundle.effect_contract_registry_hash
            && semantic.object_codec_registry_hash == bundle.object_codec_registry_hash
            && semantic.object_codec_registry_hash == correctness.object_codec_registry_hash
            && semantic.list_root_scheme_id == correctness.list_root_scheme_id
            && semantic.result_signature_profile_id == bundle.result_signature_profile_id
            && semantic.result_signature_profile_id == correctness.result_signature_profile_id
            && semantic.finality_verifier_and_vote_domain_id
                == bundle.finality_verifier_and_vote_domain_id
            && semantic.finality_verifier_and_vote_domain_id
                == correctness.finality_verifier_profile_id
            && semantic.anti_equivocation_journal_schema_hash
                == bundle.anti_equivocation_journal_schema_hash
            && semantic.mode_pause_revocation_semantics_hash
                == bundle.mode_pause_revocation_semantics_hash
            && semantic.upgrade_fsm_semantics_hash == bundle.upgrade_fsm_semantics_hash
            && semantic.release_placeholder_hash == bundle.release_requirement_catalog_hash
            && semantic.release_placeholder_hash == bundle.release_requirement_catalog_parent_hash
            && semantic.release_placeholder_hash == bundle.release_gate_authority_envelope_hash
            && semantic.release_placeholder_hash == bundle.release_approval_policy_hash
            && semantic.release_placeholder_hash == bundle.release_validator_command_artifact_hash
            && semantic.release_placeholder_hash == bundle.migration_manifest_hash
            && semantic.release_placeholder_hash == bundle.required_upgrade_handler_set_hash,
        "frozen semantic manifest is inconsistent with its correctness profile or protocol bundle"
    );
    Ok(())
}

fn decode_and_verify_capacity(
    input: &GeneratedCapacityInputV1,
    input_bytes: &[u8],
) -> Result<Vec<u8>> {
    ensure!(
        input.schema_version == 1
            && input.kind == "outbe-ocomp-generated-capacity-v1"
            && !input.source_revision.is_zero()
            && !input.artifact_set_hash.is_zero()
            && !input.capacity_evidence_sha256.is_zero()
            && !input.generated_limits_manifest_sha256.is_zero(),
        "generated capacity manifest has an invalid identity"
    );
    ensure!(
        input.capacity_profile_id == parse_b256(OCOMP_CAPACITY_PROFILE_ID_HEX)?,
        "generated capacity profile id differs from the frozen id"
    );
    let bytes = hex::decode(&input.capacity_profile_ocb1_hex)
        .wrap_err("decode generated capacity OCB1 hex")?;
    ensure!(
        sha256(&bytes) == input.capacity_profile_ocb1_sha256,
        "generated capacity canonical bytes do not match their SHA-256"
    );
    ensure!(
        !input_bytes.is_empty(),
        "generated capacity manifest is empty"
    );
    Ok(bytes)
}

fn semantic_artifacts(
    repository_root: &Path,
) -> Result<(BTreeMap<&'static str, B256>, SemanticArtifactsV1)> {
    let mut sources = BTreeMap::new();
    let registry = hash_source_set(repository_root, REGISTRY_SOURCES)?;
    let generator = hash_source_set(repository_root, GENERATOR_SOURCES)?;
    sources.insert("generator", generator);
    sources.insert("registry", registry);
    let descriptors = semantic_descriptors(repository_root)?;
    let digest = |field: &'static str| -> Result<B256> {
        let descriptor = descriptors
            .get(field)
            .ok_or_else(|| eyre::eyre!("missing semantic descriptor {field}"))?;
        Ok(semantic_digest(field, descriptor, &[registry]))
    };
    let artifacts = SemanticArtifactsV1 {
        intent_codec_id: digest("intent_codec_id")?,
        finalized_intent_proof_codec_id: digest("finalized_intent_proof_codec_id")?,
        result_codec_id: digest("result_codec_id")?,
        action_codec_id: digest("action_codec_id")?,
        activation_codec_id: digest("activation_codec_id")?,
        evidence_codec_id: digest("evidence_codec_id")?,
        arithmetic_profile_id: digest("arithmetic_profile_id")?,
        lysis_program_semantics_hash: digest("lysis_program_semantics_hash")?,
        activation_apply_semantics_hash: digest("activation_apply_semantics_hash")?,
        effect_contract_registry_hash: digest("effect_contract_registry_hash")?,
        object_codec_registry_hash: digest("object_codec_registry_hash")?,
        list_root_scheme_id: digest("list_root_scheme_id")?,
        result_signature_profile_id: digest("result_signature_profile_id")?,
        finality_verifier_and_vote_domain_id: digest("finality_verifier_and_vote_domain_id")?,
        anti_equivocation_journal_schema_hash: digest("anti_equivocation_journal_schema_hash")?,
        mode_pause_revocation_semantics_hash: digest("mode_pause_revocation_semantics_hash")?,
        upgrade_fsm_semantics_hash: digest("upgrade_fsm_semantics_hash")?,
        release_placeholder_hash: digest("release_placeholder_hash")?,
        source_availability_policy_id: digest("source_availability_policy_id")?,
    };
    ensure!(
        descriptors.len() == 19,
        "semantic descriptor registry has unexpected rows"
    );
    ensure!(
        artifacts.all_nonzero(),
        "semantic artifact generation produced zero"
    );
    Ok((sources, artifacts))
}

impl SemanticArtifactsV1 {
    fn all_nonzero(self) -> bool {
        [
            self.intent_codec_id,
            self.finalized_intent_proof_codec_id,
            self.result_codec_id,
            self.action_codec_id,
            self.activation_codec_id,
            self.evidence_codec_id,
            self.arithmetic_profile_id,
            self.lysis_program_semantics_hash,
            self.activation_apply_semantics_hash,
            self.effect_contract_registry_hash,
            self.object_codec_registry_hash,
            self.list_root_scheme_id,
            self.result_signature_profile_id,
            self.finality_verifier_and_vote_domain_id,
            self.anti_equivocation_journal_schema_hash,
            self.mode_pause_revocation_semantics_hash,
            self.upgrade_fsm_semantics_hash,
            self.release_placeholder_hash,
            self.source_availability_policy_id,
        ]
        .into_iter()
        .all(|value| !value.is_zero())
    }
}

fn protocol_bundle(
    fork_id: B256,
    capacity_profile_id: B256,
    semantic: SemanticArtifactsV1,
) -> ProtocolBundleV1 {
    ProtocolBundleV1 {
        protocol_version: 1,
        fork_id,
        intent_codec_id: semantic.intent_codec_id,
        finalized_intent_proof_codec_id: semantic.finalized_intent_proof_codec_id,
        tribute_body_codec_id: TRIBUTE_BODY_CODEC_ID,
        fidelity_opening_codec_id: FIDELITY_OPENING_CODEC_ID,
        oracle_opening_codec_id: ORACLE_OPENING_CODEC_ID,
        result_codec_id: semantic.result_codec_id,
        action_codec_id: semantic.action_codec_id,
        activation_codec_id: semantic.activation_codec_id,
        evidence_codec_id: semantic.evidence_codec_id,
        request_semantics_version: 1,
        lysis_program_semantics_hash: semantic.lysis_program_semantics_hash,
        planner_spec_version: 1,
        reducer_spec_version: 1,
        activation_apply_semantics_hash: semantic.activation_apply_semantics_hash,
        effect_contract_registry_hash: semantic.effect_contract_registry_hash,
        object_codec_registry_hash: semantic.object_codec_registry_hash,
        correctness_profile_id: parse_b256(OCOMP_CORRECTNESS_PROFILE_ID_HEX)
            .expect("generated correctness profile id is valid"),
        capacity_profile_id,
        result_signature_profile_id: semantic.result_signature_profile_id,
        finality_verifier_and_vote_domain_id: semantic.finality_verifier_and_vote_domain_id,
        consensus_committee_history_schema_version: 1,
        ocomp_committee_schema_version: 1,
        proof_system_and_verifier_key_id: None,
        da_codec_and_binding_verifier_id: None,
        anti_equivocation_journal_schema_hash: semantic.anti_equivocation_journal_schema_hash,
        mode_pause_revocation_semantics_hash: semantic.mode_pause_revocation_semantics_hash,
        upgrade_fsm_semantics_hash: semantic.upgrade_fsm_semantics_hash,
        release_requirement_catalog_sequence: 1,
        release_requirement_catalog_hash: semantic.release_placeholder_hash,
        release_requirement_catalog_parent_hash: semantic.release_placeholder_hash,
        release_gate_authority_envelope_hash: semantic.release_placeholder_hash,
        release_approval_policy_hash: semantic.release_placeholder_hash,
        release_validator_command_artifact_hash: semantic.release_placeholder_hash,
        consensus_state_schema_version: 1,
        migration_manifest_hash: semantic.release_placeholder_hash,
        required_upgrade_handler_set_hash: semantic.release_placeholder_hash,
    }
}

pub fn validator_identities(path: &Path) -> Result<Vec<B256>> {
    let validators: serde_json::Value =
        serde_json::from_slice(&fs::read(path).wrap_err("read validators manifest")?)
            .wrap_err("decode validators manifest")?;
    let validators = validators
        .as_array()
        .ok_or_else(|| eyre::eyre!("validators manifest is not an array"))?;
    let max_validators = usize::try_from(outbe_consensus::bls::MAX_VALIDATORS)
        .map_err(|_| eyre::eyre!("consensus validator bound does not fit usize"))?;
    ensure!(!validators.is_empty(), "validators manifest is empty");
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
            "validator-{index} consensus public key is not 48 bytes"
        );
        let public_key: [u8; 48] = public_key.try_into().map_err(|value: Vec<u8>| {
            eyre::eyre!(
                "validator-{index} consensus public key is not 48 bytes: got {}",
                value.len()
            )
        })?;
        identities.push(validator_identity_hash_v1(address, &public_key)?);
    }
    ensure!(
        identities.iter().all(|identity| !identity.is_zero()),
        "validator identity generation produced zero"
    );
    Ok(identities)
}

fn founder_registrations(
    chain_id: u64,
    genesis_hash: B256,
    validator_identities: Vec<B256>,
    registrations: Option<&[OcompKeyRegistrationV1]>,
    limits: &outbe_ocomp_protocol::SchemaLimits,
) -> Result<Vec<OcompKeyRegistrationV1>> {
    if let Some(registrations) = registrations {
        ensure!(
            registrations.len() == validator_identities.len(),
            "founder registration count does not match validators manifest"
        );
    }
    let mut founders = Vec::with_capacity(validator_identities.len());
    for (index, validator_identity_hash) in validator_identities.into_iter().enumerate() {
        let signing_key_index = u8::try_from(index)?;
        let registration = if let Some(registrations) = registrations {
            registrations[index].clone()
        } else {
            let key = reference_signing_key(signing_key_index);
            let public_key: [u8; 33] = key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()?;
            let mut registration = OcompKeyRegistrationV1 {
                core: OcompKeyRegistrationCoreV1 {
                    chain_id,
                    genesis_hash,
                    validator_identity_hash,
                    ocomp_public_key_sec1: public_key,
                    key_epoch: POC_KEY_EPOCH,
                    allowed_purpose_bitmap: RESULT_SIGNATURE_PURPOSE_BITMAP,
                },
                proof_of_possession: [0; 64],
            };
            registration.proof_of_possession = sign_digest(
                &key,
                registration
                    .proof_of_possession_digest(limits)
                    .wrap_err("derive final OCOMP proof-of-possession digest")?,
            )?;
            registration
        };
        ensure!(
            registration.core.chain_id == chain_id
                && registration.core.genesis_hash == genesis_hash
                && registration.core.validator_identity_hash == validator_identity_hash
                && registration.core.key_epoch == POC_KEY_EPOCH
                && registration.core.allowed_purpose_bitmap == RESULT_SIGNATURE_PURPOSE_BITMAP,
            "validator-{index} OCOMP registration does not match the requested chain binding"
        );
        registration
            .validate_proof_of_possession(limits)
            .wrap_err("verify OCOMP proof of possession")?;
        founders.push(registration);
    }
    Ok(founders)
}

fn load_registrations(
    directory: &Path,
    count: usize,
    limits: &outbe_ocomp_protocol::SchemaLimits,
) -> Result<Vec<OcompKeyRegistrationV1>> {
    let mut registrations = Vec::with_capacity(count);
    for index in 0..count {
        let path = directory
            .join(format!("validator-{index}"))
            .join("ocomp-registration-v1.ocb1");
        let bytes = fs::read(&path)
            .wrap_err_with(|| format!("read OCOMP registration {}", path.display()))?;
        registrations.push(
            OcompKeyRegistrationV1::decode_canonical(&bytes, limits)
                .wrap_err_with(|| format!("decode OCOMP registration {}", path.display()))?,
        );
    }
    Ok(registrations)
}

fn reference_signing_key(validator_index: u8) -> SigningKey {
    SigningKey::from_bytes(
        (&outbe_primitives::test_keys::secret((validator_index.saturating_add(1)) as u64)).into(),
    )
    .expect("consensus-bounded reference validator index produces a valid scalar")
}

fn sign_digest(key: &SigningKey, digest: B256) -> Result<[u8; 64]> {
    let signature: Signature = key.sign_prehash(digest.as_slice())?;
    Ok(signature
        .normalize_s()
        .unwrap_or(signature)
        .to_bytes()
        .into())
}

fn validate_armed_manifest(
    bytes: &[u8],
    expected_genesis_hash: B256,
    expected_install: &OcompForkInstallV1,
) -> Result<()> {
    let mut temporary = NamedTempFile::new().wrap_err("create final chain-manifest verifier")?;
    temporary
        .write_all(bytes)
        .wrap_err("write final chain-manifest verifier")?;
    temporary.flush().wrap_err("flush final chain manifest")?;
    let spec = parse_chain_spec(temporary.path())?;
    ensure!(
        spec.genesis_hash() == expected_genesis_hash,
        "chain-manifest extension changed the base genesis hash"
    );
    let loaded = outbe_node::ocomp::fork::load_ocomp_fork_install(&spec)?
        .ok_or_else(|| eyre::eyre!("final chain manifest omitted its OCOMP install"))?;
    ensure!(
        loaded.as_ref() == expected_install,
        "node loader returned a different final OCOMP install"
    );
    Ok(())
}

fn parse_chain_spec(path: &Path) -> Result<ChainSpec<OutbeHeader>> {
    let path = path
        .to_str()
        .ok_or_else(|| eyre::eyre!("chain manifest path is not UTF-8"))?;
    Ok(reth_ethereum::cli::chainspec::chain_value_parser(path)?
        .as_ref()
        .clone()
        .map_header(OutbeHeader::new))
}

fn hash_source_set(repository_root: &Path, inputs: &[&str]) -> Result<B256> {
    let mut files = Vec::new();
    for input in inputs {
        let path = repository_root.join(input);
        let metadata = fs::symlink_metadata(&path)
            .wrap_err_with(|| format!("inspect semantic source {}", path.display()))?;
        ensure!(
            !metadata.file_type().is_symlink(),
            "semantic source must not be a symlink: {}",
            path.display()
        );
        if metadata.is_file() {
            files.push(path);
        } else {
            for entry in WalkDir::new(&path).follow_links(false) {
                let entry = entry?;
                if entry.file_type().is_file()
                    && entry.path().extension().and_then(|value| value.to_str()) == Some("rs")
                {
                    files.push(entry.into_path());
                }
            }
        }
    }
    files.sort();
    files.dedup();
    ensure!(!files.is_empty(), "semantic source set is empty");
    let mut hasher = Sha256::new();
    hasher.update(b"OUTBE_OCOMP_SEMANTIC_SOURCE_SET_V1\0");
    for path in files {
        let relative = path
            .strip_prefix(repository_root)
            .wrap_err("semantic source is outside repository")?;
        let name = relative
            .to_str()
            .ok_or_else(|| eyre::eyre!("semantic source path is not UTF-8"))?
            .as_bytes();
        let bytes =
            fs::read(&path).wrap_err_with(|| format!("read semantic source {}", path.display()))?;
        hasher.update(u32::try_from(name.len())?.to_be_bytes());
        hasher.update(name);
        hasher.update(u64::try_from(bytes.len())?.to_be_bytes());
        hasher.update(&bytes);
    }
    Ok(B256::from_slice(&hasher.finalize()))
}

fn semantic_descriptors(repository_root: &Path) -> Result<BTreeMap<String, String>> {
    let path = repository_root.join(SEMANTIC_DESCRIPTOR_PATH);
    let text = fs::read_to_string(&path)
        .wrap_err_with(|| format!("read semantic descriptor registry {}", path.display()))?;
    let mut descriptors = BTreeMap::new();
    for (index, line) in text.lines().enumerate() {
        ensure!(
            !line.is_empty() && !line.starts_with('#'),
            "semantic descriptor line {} is empty or commented",
            index + 1
        );
        let mut fields = line.split('\t');
        let field = fields
            .next()
            .ok_or_else(|| eyre::eyre!("semantic descriptor line {} has no field", index + 1))?;
        let descriptor = fields.next().ok_or_else(|| {
            eyre::eyre!("semantic descriptor line {} has no descriptor", index + 1)
        })?;
        ensure!(
            fields.next().is_none()
                && !field.is_empty()
                && !descriptor.is_empty()
                && field
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte == b'_')
                && descriptor
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() && byte != b'\t'),
            "semantic descriptor line {} is non-canonical",
            index + 1
        );
        ensure!(
            descriptors
                .insert(field.to_owned(), descriptor.to_owned())
                .is_none(),
            "duplicate semantic descriptor {field}"
        );
    }
    Ok(descriptors)
}

fn semantic_digest(label: &str, descriptor: &str, inputs: &[B256]) -> B256 {
    let mut hasher = Sha256::new();
    hasher.update(FINAL_ARTIFACT_DOMAIN);
    hasher.update(u32::try_from(label.len()).unwrap_or(u32::MAX).to_be_bytes());
    hasher.update(label.as_bytes());
    hasher.update(
        u32::try_from(descriptor.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    hasher.update(descriptor.as_bytes());
    hasher.update(
        u32::try_from(inputs.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    for input in inputs {
        hasher.update(input.as_slice());
    }
    B256::from_slice(&hasher.finalize())
}

fn parse_b256(value: &str) -> Result<B256> {
    let bytes = hex::decode(value.strip_prefix("0x").unwrap_or(value))?;
    ensure!(bytes.len() == 32, "expected 32-byte hexadecimal digest");
    Ok(B256::from_slice(&bytes))
}

fn pretty_json(value: &impl Serialize) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn sha256(bytes: &[u8]) -> B256 {
    B256::from_slice(&Sha256::digest(bytes))
}

fn update_or_check(path: &Path, bytes: &[u8], check: bool) -> Result<()> {
    if check {
        let existing =
            fs::read(path).wrap_err_with(|| format!("read final artifact {}", path.display()))?;
        ensure!(
            existing == bytes,
            "final artifact is stale: {}",
            path.display()
        );
        return Ok(());
    }
    let parent = path
        .parent()
        .ok_or_else(|| eyre::eyre!("final artifact has no parent"))?;
    fs::create_dir_all(parent)
        .wrap_err_with(|| format!("create final artifact directory {}", parent.display()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| eyre::eyre!("final artifact has no file name"))?
        .to_string_lossy();
    let temporary = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));
    ensure!(
        !temporary.exists(),
        "final artifact temporary file already exists: {}",
        temporary.display()
    );
    fs::write(&temporary, bytes)
        .wrap_err_with(|| format!("write final artifact temporary {}", temporary.display()))?;
    fs::rename(&temporary, path)
        .wrap_err_with(|| format!("publish final artifact {}", path.display()))
}

fn resolve(repository_root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        repository_root.join(path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask has repository parent")
            .to_path_buf()
    }

    fn capacity_manifest() -> Vec<u8> {
        let limits = poc_schema_limits();
        let profile = CapacityProfileV1 {
            profile_id: parse_b256(OCOMP_CAPACITY_PROFILE_ID_HEX).unwrap(),
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
            result_deadline_blocks: outbe_chain_constants::DEFAULT_OCOMP_COMPUTE_VOTE_WINDOW_BLOCKS,
            source_retention_after_terminal_blocks: 64,
            generated_limits_manifest_hash: B256::repeat_byte(0x31),
        };
        let canonical = profile.encode_canonical(&limits).unwrap();
        pretty_json(&serde_json::json!({
            "schema_version": 1,
            "kind": "outbe-ocomp-generated-capacity-v1",
            "source_revision": B256::repeat_byte(0x41),
            "artifact_set_hash": B256::repeat_byte(0x42),
            "capacity_evidence_sha256": B256::repeat_byte(0x43),
            "generated_limits_manifest_sha256": B256::repeat_byte(0x31),
            "capacity_profile_id": profile.profile_id,
            "capacity_profile_ocb1_sha256": sha256(&canonical),
            "capacity_profile_ocb1_hex": hex::encode(canonical),
        }))
        .unwrap()
    }

    fn validators_manifest(count: u8) -> Vec<u8> {
        let validators = (0_u8..count)
            .map(|index| {
                serde_json::json!({
                    "address": format!("0x{:040x}", u64::from(index) + 1),
                    "public_key": format!("0x{}", hex::encode([index.saturating_add(1); 48])),
                })
            })
            .collect::<Vec<_>>();
        pretty_json(&validators).unwrap()
    }

    fn write_registrations(
        directory: &Path,
        chain_id: u64,
        genesis_hash: B256,
        validator_identities: Vec<B256>,
    ) {
        let limits = poc_schema_limits();
        for (index, validator_identity_hash) in validator_identities.into_iter().enumerate() {
            let validator_index = u8::try_from(index).unwrap();
            let key = reference_signing_key(validator_index);
            let public_key = key
                .verifying_key()
                .to_encoded_point(true)
                .as_bytes()
                .try_into()
                .unwrap();
            let mut registration = OcompKeyRegistrationV1 {
                core: OcompKeyRegistrationCoreV1 {
                    chain_id,
                    genesis_hash,
                    validator_identity_hash,
                    ocomp_public_key_sec1: public_key,
                    key_epoch: POC_KEY_EPOCH,
                    allowed_purpose_bitmap: RESULT_SIGNATURE_PURPOSE_BITMAP,
                },
                proof_of_possession: [0; 64],
            };
            registration.proof_of_possession = sign_digest(
                &key,
                registration.proof_of_possession_digest(&limits).unwrap(),
            )
            .unwrap();
            let validator_dir = directory.join(format!("validator-{index}"));
            fs::create_dir_all(&validator_dir).unwrap();
            fs::write(
                validator_dir.join("ocomp-registration-v1.ocb1"),
                registration.encode_canonical(&limits).unwrap(),
            )
            .unwrap();
        }
    }

    #[test]
    fn frozen_release_accepts_external_public_registrations_and_rejects_rebinding() {
        let repository_root = repository_root();
        let temporary = tempfile::tempdir().unwrap();
        let artifacts = temporary.path().join("artifacts");
        let base_genesis = repository_root.join("crates/blockchain/node/tests/assets/genesis.json");
        let validators = temporary.path().join("validators.json");
        let capacity = temporary.path().join("capacity.json");
        fs::write(&capacity, capacity_manifest()).unwrap();
        fs::write(&validators, validators_manifest(4)).unwrap();
        run(
            &repository_root,
            &capacity,
            &base_genesis,
            &validators,
            FinalArtifactOverrides::default(),
            &artifacts,
            false,
        )
        .unwrap();
        let registrations = temporary.path().join("registrations");
        let output = temporary.path().join("final");

        let chain_spec = parse_chain_spec(&base_genesis).unwrap();
        let limits = poc_schema_limits();
        let bundle = ProtocolBundleV1::decode_canonical(
            &fs::read(artifacts.join(BUNDLE_FILE)).unwrap(),
            &limits,
        )
        .unwrap();
        write_registrations(
            &registrations,
            chain_spec.chain().id(),
            chain_spec.genesis_hash(),
            validator_identities(&validators).unwrap(),
        );

        run(
            &repository_root,
            &artifacts.join(GENERATED_CAPACITY_FILE),
            &base_genesis,
            &validators,
            FinalArtifactOverrides {
                registrations_dir: Some(&registrations),
                release_artifacts_dir: Some(&artifacts),
            },
            &output,
            false,
        )
        .unwrap();
        let generated_spec = parse_chain_spec(&output.join(CHAIN_MANIFEST_FILE)).unwrap();
        let install = outbe_node::ocomp::fork::load_ocomp_fork_install(&generated_spec)
            .unwrap()
            .unwrap();
        assert_eq!(install.founder_registrations.len(), 4);
        assert_eq!(
            install.request_profile.protocol_bundle_hash,
            bundle.protocol_bundle_hash(&limits).unwrap()
        );

        let path = registrations.join("validator-0/ocomp-registration-v1.ocb1");
        let mut rebound =
            OcompKeyRegistrationV1::decode_canonical(&fs::read(&path).unwrap(), &limits).unwrap();
        rebound.core.chain_id = rebound.core.chain_id.saturating_add(1);
        rebound.proof_of_possession = sign_digest(
            &reference_signing_key(0),
            rebound.proof_of_possession_digest(&limits).unwrap(),
        )
        .unwrap();
        fs::write(path, rebound.encode_canonical(&limits).unwrap()).unwrap();
        let error = run(
            &repository_root,
            &artifacts.join(GENERATED_CAPACITY_FILE),
            &base_genesis,
            &validators,
            FinalArtifactOverrides {
                registrations_dir: Some(&registrations),
                release_artifacts_dir: Some(&artifacts),
            },
            &temporary.path().join("rebound"),
            false,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match the requested chain binding"),
            "unexpected error: {error:?}"
        );
    }

    #[test]
    fn ocm_cap_001_final_artifacts_are_chain_bound_reproducible_and_node_loadable() {
        let repository_root = repository_root();
        let temporary = tempfile::tempdir().unwrap();
        let capacity = temporary.path().join("capacity.json");
        let validators = temporary.path().join("validators.json");
        let output = temporary.path().join("final");
        fs::write(&capacity, capacity_manifest()).unwrap();
        fs::write(&validators, validators_manifest(5)).unwrap();
        let base_genesis = repository_root.join("crates/blockchain/node/tests/assets/genesis.json");

        run(
            &repository_root,
            &capacity,
            &base_genesis,
            &validators,
            FinalArtifactOverrides::default(),
            &output,
            false,
        )
        .unwrap();
        run(
            &repository_root,
            &capacity,
            &base_genesis,
            &validators,
            FinalArtifactOverrides::default(),
            &output,
            true,
        )
        .unwrap();

        let chain_spec = parse_chain_spec(&output.join(CHAIN_MANIFEST_FILE)).unwrap();
        let install = outbe_node::ocomp::fork::load_ocomp_fork_install(&chain_spec)
            .unwrap()
            .unwrap();
        assert_eq!(
            install.classification,
            OcompForkInstallClassification::Final
        );
        assert_eq!(install.activation_height, OCOMP_POC_FINAL_ACTIVATION_HEIGHT);
        assert_eq!(install.founder_registrations.len(), 5);
        assert!(!output.join("result-committee-v1.ocb1").exists());
        assert!(!output.join("result-committee-public-v1.json").exists());
        assert_eq!(
            install
                .request_profile
                .capacity_profile
                .max_tributes_per_work_shard,
            256
        );
        assert_eq!(
            fs::read(output.join(GENERATED_CAPACITY_FILE)).unwrap(),
            fs::read(&capacity).unwrap(),
            "the exact capacity manifest used for Final generation must be retained"
        );

        let network: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join(NETWORK_MANIFEST_FILE)).unwrap()).unwrap();
        assert_eq!(network["classification"], "final");
        assert_eq!(network["activation_height"], 32);
        assert_ne!(network["protocol_bundle_hash"], serde_json::Value::Null);

        let semantic: serde_json::Value =
            serde_json::from_slice(&fs::read(output.join(SEMANTICS_MANIFEST_FILE)).unwrap())
                .unwrap();
        assert_eq!(semantic["source_sets"].as_object().unwrap().len(), 2);
        assert!(semantic["source_sets"].get("generator").is_some());
        assert!(semantic["source_sets"].get("registry").is_some());
        assert!(semantic["source_sets"].get("normative").is_none());

        fs::write(output.join(BUNDLE_FILE), b"changed").unwrap();
        assert!(
            run(
                &repository_root,
                &capacity,
                &base_genesis,
                &validators,
                FinalArtifactOverrides::default(),
                &output,
                true,
            )
            .is_err(),
            "check mode must reject a modified final artifact"
        );
    }
}
