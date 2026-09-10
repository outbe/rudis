//! Network-bound SGX release bundle preparation, signing and verification.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{BufReader, Read, Write as _},
    os::unix::fs::PermissionsExt,
    path::{Component, Path, PathBuf},
    process::{Command, Output},
};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use clap::ValueEnum;
use eyre::{bail, eyre, Result, WrapErr};
use filetime::FileTime;
use outbe_evm::tee_attestation_activation::{DcapChainSpecBindingV1, DcapSeededChainSpecBindingV1};
use outbe_primitives::chain::{OutbeNetwork, MAINNET_CHAIN_ID, MAINNET_CHAIN_NAME, TESTNET_CHAIN_ID, TESTNET_CHAIN_NAME};
use outbe_primitives::tee_attestation_v1::{
    AttestationMode, NetworkBindingV1, TrustedNetworkDescriptorV1,
};
use outbe_primitives::tee_genesis_v1::{
    initial_tee_policy_v1, tee_attestation_v1_genesis_field, InitialTeeProfileV1,
    ProductionSgxMeasurementV1,
};
use outbe_tee::release_dcap_artifacts::ReleaseDcapArtifactSetV1;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use walkdir::WalkDir;

const REQUIRED_BUNDLE_FILES: [&str; 8] = [
    "metadata/network-descriptor-v1.bin",
    "rootfs/opt/outbe/sgx/bin/outbe-tee-enclave",
    "rootfs/opt/outbe/sgx/gramine/libpal.so",
    "rootfs/opt/outbe/sgx/gramine/loader",
    "rootfs/opt/outbe/sgx/network-descriptor-v1.bin",
    "rootfs/opt/outbe/sgx/outbe-tee-enclave.manifest",
    "rootfs/opt/outbe/sgx/outbe-tee-enclave.manifest.sgx",
    "rootfs/opt/outbe/sgx/outbe-tee-enclave.sig",
];

const EXCLUDED_BUNDLE_FILES: [&str; 4] = [
    "metadata/testnet-sgx-bundle.json",
    "metadata/mainnet-sgx-bundle.json",
    "SHA256SUMS",
    "SHA256SUMS.unsigned",
];

const GITHUB_ACTIONS_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum SgxReleaseNetwork {
    Testnet,
    Mainnet,
}

impl SgxReleaseNetwork {
    #[must_use]
    pub const fn chain_id(self) -> u64 {
        match self {
            Self::Testnet => TESTNET_CHAIN_ID,
            Self::Mainnet => MAINNET_CHAIN_ID,
        }
    }

    #[must_use]
    pub const fn chain_name(self) -> &'static str {
        match self {
            Self::Testnet => TESTNET_CHAIN_NAME,
            Self::Mainnet => MAINNET_CHAIN_NAME,
        }
    }

    #[must_use]
    pub const fn authorization_scope(self) -> &'static str {
        match self {
            Self::Testnet => "testnet",
            Self::Mainnet => "mainnet",
        }
    }

    #[must_use]
    pub const fn bundle_spec_path(self) -> &'static str {
        match self {
            Self::Testnet => "release/testnet-sgx-bundle-v1.json",
            Self::Mainnet => "release/mainnet-sgx-bundle-v1.json",
        }
    }

    #[must_use]
    pub const fn bundle_manifest_path(self) -> &'static str {
        match self {
            Self::Testnet => "metadata/testnet-sgx-bundle.json",
            Self::Mainnet => "metadata/mainnet-sgx-bundle.json",
        }
    }

    #[must_use]
    pub const fn workflow_path(self) -> &'static str {
        match self {
            Self::Testnet => ".github/workflows/testnet-release.yml",
            Self::Mainnet => ".github/workflows/mainnet-release.yml",
        }
    }

    #[must_use]
    pub const fn certificate_identity(self) -> &'static str {
        match self {
            Self::Testnet => "https://github.com/outbe/outbe-chain/.github/workflows/testnet-release.yml@refs/heads/main",
            Self::Mainnet => "https://github.com/outbe/outbe-chain/.github/workflows/mainnet-release.yml@refs/heads/main",
        }
    }

    #[must_use]
    pub const fn genesis_artifact_name(self) -> &'static str {
        self.dcap_artifact_set().genesis_artifact_path()
    }

    #[must_use]
    pub const fn outbe_network(self) -> OutbeNetwork {
        match self {
            Self::Testnet => OutbeNetwork::Testnet,
            Self::Mainnet => OutbeNetwork::Mainnet,
        }
    }

    #[must_use]
    pub const fn dcap_artifact_set(self) -> ReleaseDcapArtifactSetV1 {
        match ReleaseDcapArtifactSetV1::for_network(self.outbe_network()) {
            Some(contract) => contract,
            None => unreachable!(),
        }
    }

    #[must_use]
    pub const fn oci_name(self) -> &'static str {
        match self {
            Self::Testnet => "outbe-tee-enclave-testnet",
            Self::Mainnet => "outbe-tee-enclave-mainnet",
        }
    }

    fn from_spec(spec: &BundleSpec) -> Result<Self> {
        let network = match spec.network.as_str() {
            "testnet" => Self::Testnet,
            "mainnet" => Self::Mainnet,
            _ => {
                bail!("unsupported SGX release network {}", spec.network);
            }
        };
        if spec.chain_id != network.chain_id()
            || spec.network_name != network.chain_name()
            || spec.authorization_scope != network.authorization_scope()
        {
            bail!("SGX bundle network identity is inconsistent");
        }
        Ok(network)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct BundleSpec {
    pub authorization_scope: String,
    pub bundle_version: u32,
    pub chain_id: u64,
    pub gramine: GramineIdentity,
    pub inputs: Vec<String>,
    pub install_root: String,
    pub network: String,
    pub network_name: String,
    pub platform: String,
    pub project_toolchain: String,
    pub sealed_state_schema: u32,
    pub sgx: SgxPolicy,
    pub spec_version: u32,
}

impl BundleSpec {
    pub fn read(path: &Path) -> Result<Self> {
        let metadata = fs::symlink_metadata(path)
            .wrap_err_with(|| format!("read SGX bundle spec metadata: {}", path.display()))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            bail!("missing or unsafe SGX bundle spec: {}", path.display());
        }
        let bytes =
            fs::read(path).wrap_err_with(|| format!("read SGX bundle spec: {}", path.display()))?;
        let spec: Self = serde_json::from_slice(&bytes)
            .wrap_err_with(|| format!("parse SGX bundle spec: {}", path.display()))?;
        spec.validate()?;
        Ok(spec)
    }

    pub fn validate(&self) -> Result<()> {
        if self.spec_version != 1 || self.bundle_version != 1 {
            bail!("unsupported SGX bundle contract");
        }
        SgxReleaseNetwork::from_spec(self)?;
        let Some((image, digest)) = self.gramine.builder_image.split_once("@sha256:") else {
            bail!("Gramine builder image must be pinned by sha256 digest");
        };
        if image.is_empty() || image.chars().any(char::is_whitespace) || !is_lower_hex(digest, 64) {
            bail!("Gramine builder image must be pinned by sha256 digest");
        }
        if !is_lower_hex(&self.gramine.source_commit, 40) {
            bail!("Gramine source commit must be a lowercase 40-character Git SHA");
        }
        if self.platform != "linux/amd64" {
            bail!("SGX bundle supports only linux/amd64");
        }
        if self.project_toolchain != "release/project-toolchain-v1.json" {
            bail!("SGX bundle must bind the project toolchain version pin");
        }
        if self.install_root != "/opt/outbe/sgx" {
            bail!("SGX install root must remain /opt/outbe/sgx");
        }
        if self.sealed_state_schema != u32::from(outbe_tee::SEALED_STATE_SCHEMA_V1) {
            bail!("SGX bundle sealed-state schema does not match the enclave wire format");
        }
        if self.sgx.debug {
            bail!("release SGX bundle must use a non-debug enclave");
        }
        if self.sgx.remote_attestation != "dcap" {
            bail!("production SGX bundle must enable DCAP remote attestation");
        }
        if self.sgx.minimum_tcb_evaluation_data_number == 0 {
            bail!(
                "production SGX bundle must pin a non-zero minimum Intel TCB evaluation data number"
            );
        }
        if self.sgx.sigstruct_date_source != "source-date-epoch-utc" {
            bail!("SIGSTRUCT date must derive from SOURCE_DATE_EPOCH in UTC");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct GramineIdentity {
    pub builder_image: String,
    pub source_commit: String,
    pub version: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SgxPolicy {
    pub debug: bool,
    pub edmm_enable: bool,
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    pub max_threads: u32,
    pub minimum_tcb_evaluation_data_number: u32,
    pub remote_attestation: String,
    pub sigstruct_date_source: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct SourceIdentity {
    pub release_tag: String,
    pub source_commit: String,
    pub source_date_epoch: i64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Measurements {
    pub debug: bool,
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    pub mrenclave: String,
    pub mrsigner: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct Sha256Digest {
    pub algorithm: String,
    pub value: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct BundleFile {
    pub digest: Sha256Digest,
    pub mode: String,
    pub path: String,
    pub size: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ManifestSource {
    pub commit: String,
    pub source_date_epoch: i64,
    pub tag: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct BundleManifest {
    pub authorization_scope: String,
    pub bundle_version: u32,
    pub chain_id: u64,
    pub files: Vec<BundleFile>,
    pub gramine: GramineIdentity,
    pub install_root: String,
    pub measurements: Measurements,
    pub network: String,
    pub network_name: String,
    pub platform: String,
    pub schema_version: String,
    pub sealed_state_schema: u32,
    pub sigstruct_date: String,
    pub source: ManifestSource,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct ComparisonEvidence {
    pub entry_count: usize,
    pub result: String,
    pub schema_version: String,
    pub tree_digest: Sha256Digest,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct OciDescriptor {
    pub digest: Sha256Digest,
    pub media_type: String,
    pub size: u64,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
pub struct OciBuildEvidence {
    pub bundle_manifest_digest: Sha256Digest,
    pub image: OciDescriptor,
    pub image_reference: String,
    pub measurements: Measurements,
    pub platform: String,
    pub provenance_attestation: bool,
    pub sbom_attestation: bool,
    pub schema_version: String,
    pub source: ManifestSource,
}

#[derive(Clone, Debug)]
pub struct VerifiedReleaseInputs {
    pub network: SgxReleaseNetwork,
    pub bundle: PathBuf,
    pub bundle_archive: PathBuf,
    pub cosign_image_verification: PathBuf,
    pub cosign_provenance_verification: PathBuf,
    pub cosign_sbom_verification: PathBuf,
    pub elf_evidence: PathBuf,
    pub elf_manifest: PathBuf,
    pub hardware_evidence: PathBuf,
    pub processor_dcap_archive: PathBuf,
    pub processor_dcap_evidence: PathBuf,
    pub oci_evidence: PathBuf,
    pub sbom: PathBuf,
    pub sgx_evidence: PathBuf,
    pub seeded_genesis: PathBuf,
    pub network_binding_evidence: PathBuf,
    pub genesis: PathBuf,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct TreeEntry {
    #[serde(skip_serializing_if = "Option::is_none")]
    digest: Option<Sha256Digest>,
    mode: String,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<u64>,
    kind: String,
}

pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value).wrap_err("serialize canonical JSON value")?;
    let value = sort_json(value);
    let mut encoded = serde_json::to_vec(&value).wrap_err("encode canonical JSON")?;
    encoded.push(b'\n');
    Ok(encoded)
}

/// Build a structurally validated candidate for tests and diagnostics.
///
/// This function never emits the terminal `verified` lifecycle. Only
/// [`finalize_release_manifest`] can do that after it invokes Cosign itself.
pub fn build_release_manifest_candidate(inputs: &VerifiedReleaseInputs) -> Result<Value> {
    build_release_manifest_from_evidence(inputs, "build-candidate")
}

fn build_release_manifest_from_evidence(
    inputs: &VerifiedReleaseInputs,
    lifecycle: &str,
) -> Result<Value> {
    let network = inputs.network;
    let mut release: Value = read_canonical_json(&inputs.elf_manifest)?;
    let bundle_manifest_path = inputs.bundle.join(network.bundle_manifest_path());
    let bundle: BundleManifest = read_canonical_json(&bundle_manifest_path)?;
    require_bundle_network(&bundle, network)?;
    let oci: OciBuildEvidence = read_canonical_json(&inputs.oci_evidence)?;
    validate_final_release_identity(&release, &bundle, &oci)?;
    require_nonempty_regular_file(&inputs.genesis, "release genesis ChainSpec")?;
    let chain_binding = DcapChainSpecBindingV1::from_genesis_path(&inputs.genesis)
        .map_err(|error| eyre!("release ChainSpec binding is invalid: {error}"))?;
    if chain_binding.chain_id != network.chain_id() {
        bail!("release genesis belongs to a foreign network");
    }
    require_measured_network_descriptor(&inputs.bundle, &inputs.genesis, &chain_binding)?;
    require_bundle_measurement_binding(&chain_binding, &bundle)?;
    require_seeded_genesis_release_evidence(inputs, &bundle, &chain_binding)?;

    if !oci.provenance_attestation || !oci.sbom_attestation {
        bail!("OCI image must carry BuildKit provenance and SBOM attestations");
    }
    if oci.bundle_manifest_digest != file_digest(&bundle_manifest_path)? {
        bail!("OCI evidence does not bind the signed SGX bundle manifest");
    }
    verify_cosign_image_signature(&inputs.cosign_image_verification, &oci.image.digest.value)?;
    require_evidence_result(&inputs.elf_evidence, &["passed"])?;
    require_evidence_result(&inputs.sgx_evidence, &["identical"])?;
    let hardware: Value = require_evidence_result(&inputs.hardware_evidence, &["passed"])?;
    if hardware
        .pointer("/environment/backend")
        .and_then(Value::as_str)
        != Some("gramine-sgx")
        || hardware
            .pointer("/environment/hardware_sgx")
            .and_then(Value::as_bool)
            != Some(true)
        || hardware.get("measurements") != Some(&serde_json::to_value(&bundle.measurements)?)
        || hardware
            .pointer("/image/digest/value")
            .and_then(Value::as_str)
            != Some(oci.image.digest.value.as_str())
    {
        bail!("hardware SGX evidence does not bind the release image and measurements");
    }
    let processor_dcap = require_fresh_dcap_hardware_evidence(
        &inputs.processor_dcap_evidence,
        "processor",
        &bundle,
        &oci,
        &chain_binding,
        &inputs.genesis,
        network,
    )?;
    verify_processor_dcap_archive(
        &inputs.processor_dcap_archive,
        &inputs.processor_dcap_evidence,
        &processor_dcap,
        network.dcap_artifact_set(),
        bundle.source.source_date_epoch,
    )?;
    require_nonempty_regular_file(&inputs.bundle_archive, "signed SGX bundle archive")?;
    verify_bundle_archive(
        &inputs.bundle,
        &inputs.bundle_archive,
        bundle.source.source_date_epoch,
    )?;
    require_nonempty_regular_file(&inputs.sbom, "SPDX SBOM")?;
    let sbom: Value =
        serde_json::from_slice(&fs::read(&inputs.sbom)?).wrap_err("parse SPDX SBOM")?;
    if sbom.get("spdxVersion").and_then(Value::as_str) != Some("SPDX-2.3") {
        bail!("release SBOM must use SPDX-2.3");
    }
    let attested_sbom = verified_cosign_attestation(
        &inputs.cosign_sbom_verification,
        &oci.image.digest.value,
        "https://spdx.dev/Document",
    )?;
    if attested_sbom.get("predicate") != Some(&sbom) {
        bail!("attested SBOM does not match the exact release SBOM");
    }
    let attested_provenance = verified_cosign_attestation(
        &inputs.cosign_provenance_verification,
        &oci.image.digest.value,
        "https://slsa.dev/provenance/v0.2",
    )?;
    let predicate = attested_provenance
        .get("predicate")
        .ok_or_else(|| eyre!("verified provenance attestation lacks a predicate"))?;
    if predicate.get("buildType").and_then(Value::as_str)
        != Some("https://mobyproject.org/buildkit@v1")
        || predicate
            .get("materials")
            .and_then(Value::as_array)
            .is_none_or(Vec::is_empty)
    {
        bail!("verified provenance is not a material-bearing BuildKit statement");
    }

    let release_object = release
        .as_object_mut()
        .ok_or_else(|| eyre!("ELF release manifest must be a JSON object"))?;
    release_object
        .get_mut("release")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| eyre!("ELF release manifest lacks release metadata"))?
        .insert("lifecycle".to_owned(), Value::String(lifecycle.to_owned()));
    let provenance = release_object
        .get_mut("build")
        .and_then(Value::as_object_mut)
        .and_then(|build| build.get_mut("provenance"))
        .and_then(Value::as_object_mut)
        .ok_or_else(|| eyre!("ELF release manifest lacks build provenance"))?;
    provenance.insert(
        "mode".to_owned(),
        Value::String("github-actions".to_owned()),
    );
    provenance.insert(
        "workflow".to_owned(),
        Value::String(network.workflow_path().to_owned()),
    );
    provenance.insert(
        "certificate_identity".to_owned(),
        Value::String(network.certificate_identity().to_owned()),
    );
    provenance.insert(
        "certificate_oidc_issuer".to_owned(),
        Value::String(GITHUB_ACTIONS_OIDC_ISSUER.to_owned()),
    );
    provenance.insert(
        "certificate_workflow_sha".to_owned(),
        Value::String(bundle.source.commit.clone()),
    );
    release_object.insert(
        "network".to_owned(),
        serde_json::json!({
            "chain_id": network.chain_id(),
            "chain_name": network.chain_name(),
            "genesis_hash": format!("{:#x}", chain_binding.genesis_hash),
            "genesis_file": {
                "path": network.genesis_artifact_name(),
                "digest": file_digest(&inputs.genesis)?,
                "size": fs::metadata(&inputs.genesis)?.len()
            }
        }),
    );

    let artifacts = release_object
        .get_mut("artifacts")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| eyre!("ELF release manifest lacks artifacts"))?;
    let tee = signed_tee_metadata(&bundle);
    artifacts.push(file_artifact(
        &inputs.bundle_archive,
        "outbe-tee-enclave-sgx-bundle",
        "archive",
        "application/x-tar",
        tee.clone(),
    )?);
    artifacts.push(serde_json::json!({
        "classification": "production",
        "digest": oci.image.digest,
        "features": [],
        "install_profiles": ["full-node", "validator"],
        "kind": "oci-manifest",
        "media_type": oci.image.media_type,
        "name": format!("{}-oci", network.oci_name()),
        "network_compatibility": "network-manifest-required",
        "package": "outbe-tee-enclave",
        "path": format!("oci/{}@sha256:{}", network.oci_name(), oci.image.digest.value),
        "platform": release_platform(),
        "role": "tee-enclave",
        "size": oci.image.size,
        "tee": tee.clone()
    }));
    artifacts.push(file_artifact(
        &inputs.sbom,
        "outbe-tee-enclave-sbom",
        "sbom",
        "application/spdx+json",
        tee,
    )?);

    let gates = vec![
        passed_gate(
            "independent-byte-for-byte-elf-rebuild",
            &inputs.elf_evidence,
        )?,
        passed_gate(
            "release-manifest-schema-and-canonicalization",
            &inputs.elf_manifest,
        )?,
        passed_gate("independent-unsigned-sgx-bundle", &inputs.sgx_evidence)?,
        passed_gate("signed-sgx-sigstruct-verification", &bundle_manifest_path)?,
        passed_gate_many(
            "seeded-genesis-to-signed-enclave-policy",
            &[&inputs.seeded_genesis, &inputs.network_binding_evidence],
        )?,
        passed_gate_many(
            "immutable-oci-sbom-and-provenance",
            &[
                &inputs.oci_evidence,
                &inputs.cosign_image_verification,
                &inputs.cosign_sbom_verification,
                &inputs.cosign_provenance_verification,
            ],
        )?,
        passed_gate("hardware-sgx-release-smoke", &inputs.hardware_evidence)?,
        passed_gate_many(
            "fresh-accepted-processor-dcap",
            &[
                &inputs.processor_dcap_evidence,
                &inputs.processor_dcap_archive,
            ],
        )?,
    ];
    release_object.insert("verification_gates".to_owned(), Value::Array(gates));
    Ok(release)
}

fn require_seeded_genesis_release_evidence(
    inputs: &VerifiedReleaseInputs,
    bundle: &BundleManifest,
    chain_binding: &DcapChainSpecBindingV1,
) -> Result<()> {
    require_nonempty_regular_file(&inputs.seeded_genesis, "approved seeded release genesis")?;
    let seeded = DcapSeededChainSpecBindingV1::from_genesis_path(&inputs.seeded_genesis)
        .map_err(|error| eyre!("seeded release ChainSpec binding is invalid: {error}"))?;
    if seeded.chain_id != inputs.network.chain_id() {
        bail!("seeded release genesis belongs to a foreign network");
    }
    let final_seeded = DcapSeededChainSpecBindingV1::from_genesis_path(&inputs.genesis)
        .map_err(|error| eyre!("final seeded release ChainSpec binding is invalid: {error}"))?;
    if final_seeded != seeded
        || seeded.chain_id != chain_binding.chain_id
        || seeded.genesis_hash != chain_binding.genesis_hash
    {
        bail!("final genesis changed the approved seeded chain identity or epoch-0 committee");
    }

    let seeded_bytes = fs::read(&inputs.seeded_genesis).wrap_err_with(|| {
        format!(
            "read approved seeded release genesis: {}",
            inputs.seeded_genesis.display()
        )
    })?;
    let mut expected_final: Value =
        serde_json::from_slice(&seeded_bytes).wrap_err("parse approved seeded genesis JSON")?;
    let config = expected_final
        .get_mut("config")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| eyre!("seeded genesis config must be a JSON object"))?;
    if config.contains_key("teeAttestationV1") {
        bail!("seeded genesis already contains teeAttestationV1");
    }
    config.insert(
        "teeAttestationV1".to_owned(),
        tee_attestation_v1_genesis_field(&chain_binding.policy).map_err(eyre::Report::msg)?,
    );
    let expected_final = canonical_json(&expected_final)?;
    let actual_final = fs::read(&inputs.genesis)
        .wrap_err_with(|| format!("read final release genesis: {}", inputs.genesis.display()))?;
    if actual_final != expected_final {
        bail!("final genesis is not the exact allowed seeded-genesis policy insertion");
    }

    let evidence = require_evidence_result(&inputs.network_binding_evidence, &["passed"])?;
    let expected_evidence = serde_json::json!({
        "schema": "outbe-sgx-final-genesis-evidence-v1",
        "network": inputs.network.authorization_scope(),
        "chain_id": chain_binding.chain_id,
        "genesis_hash": format!("{:#x}", chain_binding.genesis_hash),
        "seeded_genesis": file_digest(&inputs.seeded_genesis)?,
        "final_genesis": file_digest(&inputs.genesis)?,
        "bundle_manifest": file_digest(&inputs.bundle.join(inputs.network.bundle_manifest_path()))?,
        "measured_descriptor": file_digest(&inputs.bundle.join("metadata/network-descriptor-v1.bin"))?,
        "measurements": bundle.measurements,
        "minimum_tcb_evaluation_data_number": chain_binding.policy.minimum_tcb_evaluation_data_number,
        "mutation": "insert-config-teeAttestationV1-only",
        "result": "passed"
    });
    if evidence != expected_evidence {
        bail!("network-binding evidence does not exactly bind the seed, final genesis and signed bundle");
    }
    Ok(())
}

fn require_bundle_network(bundle: &BundleManifest, network: SgxReleaseNetwork) -> Result<()> {
    if bundle.authorization_scope != network.authorization_scope()
        || bundle.chain_id != network.chain_id()
        || bundle.network != network.authorization_scope()
        || bundle.network_name != network.chain_name()
    {
        bail!("signed SGX bundle belongs to a foreign release network");
    }
    Ok(())
}

fn require_fresh_dcap_hardware_evidence(
    path: &Path,
    expected_pck_ca: &str,
    bundle: &BundleManifest,
    oci: &OciBuildEvidence,
    chain_binding: &DcapChainSpecBindingV1,
    genesis: &Path,
    network: SgxReleaseNetwork,
) -> Result<Value> {
    let evidence = require_evidence_result(path, &["passed"])?;
    let string_at = |pointer: &str| {
        evidence
            .pointer(pointer)
            .and_then(Value::as_str)
            .ok_or_else(|| eyre!("{expected_pck_ca} DCAP evidence lacks {pointer}"))
    };
    let u64_at = |pointer: &str| {
        evidence
            .pointer(pointer)
            .and_then(Value::as_u64)
            .ok_or_else(|| eyre!("{expected_pck_ca} DCAP evidence lacks {pointer}"))
    };
    if string_at("/environment/architecture")? != "x86_64"
        || string_at("/environment/backend")? != "gramine-sgx"
        || evidence
            .pointer("/environment/hardware_sgx")
            .and_then(Value::as_bool)
            != Some(true)
        || evidence
            .pointer("/environment/dcap")
            .and_then(Value::as_bool)
            != Some(true)
        || string_at("/attestation/pck_ca")? != expected_pck_ca
        || string_at("/attestation/public_verifier")? != "enclave-resident-begin-chunk-finish-v1"
        || evidence.get("measurements") != Some(&serde_json::to_value(&bundle.measurements)?)
        || string_at("/image/digest/algorithm")? != "sha256"
        || string_at("/image/digest/value")? != oci.image.digest.value
        || string_at("/source_commit")? != bundle.source.commit
    {
        bail!(
            "{expected_pck_ca} DCAP evidence does not bind the exact release and public verifier"
        );
    }
    require_chain_spec_evidence(&evidence, chain_binding, genesis, network)
        .wrap_err("release ChainSpec binding does not match retained DCAP evidence")?;
    // Guest-visible socket topology is retained as provenance only. The
    // enclave-verified Intel PCK issuer above is the PCK CA authority.
    let _ = u64_at("/environment/physical_package_count")?;
    if evidence
        .pointer("/freshness/binding_id_nonzero")
        .and_then(Value::as_bool)
        != Some(true)
    {
        bail!("{expected_pck_ca} DCAP evidence did not use a non-zero one-use binding");
    }
    let run_started = u64_at("/freshness/run_started_at")?;
    let quote_generated = u64_at("/freshness/quote_generated_at")?;
    let collateral_started = u64_at("/freshness/collateral_started_at")?;
    let collateral_completed = u64_at("/freshness/collateral_completed_at")?;
    let consensus_timestamp = u64_at("/freshness/consensus_timestamp")?;
    let verified = u64_at("/freshness/verified_at")?;
    if run_started == 0
        || !(run_started <= quote_generated
            && quote_generated <= collateral_started
            && collateral_started <= collateral_completed
            && collateral_completed <= consensus_timestamp
            && consensus_timestamp <= verified)
    {
        bail!("{expected_pck_ca} DCAP freshness order is invalid");
    }
    let platform_status = string_at("/attestation/platform_tcb_status")?;
    if !matches!(
        platform_status,
        "up-to-date" | "sw-hardening-needed" | "configuration-and-sw-hardening-needed"
    ) || u64_at("/attestation/collateral_valid_until")? <= consensus_timestamp
    {
        bail!("{expected_pck_ca} DCAP accepted verdict provenance is invalid");
    }
    let consensus_timestamp_i64 = i64::try_from(consensus_timestamp)
        .map_err(|_| eyre!("{expected_pck_ca} consensus timestamp exceeds i64"))?;
    if u64_at("/collateral/component_count")? != 8
        || string_at("/collateral/pck_crl/kind")? != expected_pck_ca
        || string_at("/collateral/root_crl/kind")? != "root"
    {
        bail!("{expected_pck_ca} DCAP evidence lacks the exact collateral matrix");
    }
    for (label, pointer) in [
        ("PCK CRL", "/collateral/pck_crl"),
        ("root CRL", "/collateral/root_crl"),
    ] {
        let issuer = string_at(&format!("{pointer}/issuer"))?;
        let this_update = string_at(&format!("{pointer}/this_update"))?;
        let next_update = string_at(&format!("{pointer}/next_update"))?;
        let size = u64_at(&format!("{pointer}/size"))?;
        let sha256 = string_at(&format!("{pointer}/sha256"))?;
        let retained_path = string_at(&format!("{pointer}/path"))?;
        let expected_path = if pointer.ends_with("pck_crl") {
            "collateral/pck.crl.der"
        } else {
            "collateral/root-ca.crl.der"
        };
        if size == 0
            || !is_lower_hex(sha256, 64)
            || issuer.is_empty()
            || !issuer.is_ascii()
            || !is_utc_second(this_update)
            || !is_utc_second(next_update)
            || this_update >= next_update
        {
            bail!("{expected_pck_ca} {label} provenance is invalid");
        }
        let expected_issuer_marker = if pointer.ends_with("pck_crl") {
            if expected_pck_ca == "processor" {
                "Intel SGX PCK Processor CA"
            } else {
                "Intel SGX PCK Platform CA"
            }
        } else {
            "Intel SGX Root CA"
        };
        if !issuer.contains(expected_issuer_marker) {
            bail!("{expected_pck_ca} {label} provenance has the wrong issuer");
        }
        let this_update_time = OffsetDateTime::parse(this_update, &Rfc3339)
            .wrap_err_with(|| format!("parse {expected_pck_ca} {label} this_update"))?;
        let next_update_time = OffsetDateTime::parse(next_update, &Rfc3339)
            .wrap_err_with(|| format!("parse {expected_pck_ca} {label} next_update"))?;
        if this_update_time.unix_timestamp() > consensus_timestamp_i64
            || consensus_timestamp_i64 >= next_update_time.unix_timestamp()
        {
            bail!("{expected_pck_ca} {label} was not current at the consensus timestamp");
        }
        let artifact = evidence
            .get("artifacts")
            .and_then(Value::as_object)
            .and_then(|artifacts| artifacts.get(expected_path));
        if retained_path != expected_path
            || artifact
                .and_then(|record| record.get("size"))
                .and_then(Value::as_u64)
                != Some(size)
            || artifact
                .and_then(|record| record.get("sha256"))
                .and_then(Value::as_str)
                != Some(sha256)
        {
            bail!("{expected_pck_ca} retained {label} does not match its provenance record");
        }
    }
    Ok(evidence)
}

fn require_bundle_measurement_binding(
    binding: &DcapChainSpecBindingV1,
    bundle: &BundleManifest,
) -> Result<()> {
    if bundle.measurements.debug {
        bail!("release ChainSpec binding cannot authorize a debug enclave");
    }
    let measurement = |value: &str, label: &str| -> Result<alloy_primitives::B256> {
        if !is_lower_hex(value, 64) {
            bail!("signed bundle {label} is not 32 lowercase hexadecimal bytes");
        }
        let bytes = hex::decode(value).wrap_err_with(|| format!("decode signed bundle {label}"))?;
        Ok(alloy_primitives::B256::from_slice(&bytes))
    };
    binding
        .ensure_exact_release_measurements(
            measurement(&bundle.measurements.mrenclave, "MRENCLAVE")?,
            measurement(&bundle.measurements.mrsigner, "MRSIGNER")?,
            bundle.measurements.isv_prod_id,
            bundle.measurements.isv_svn,
        )
        .map_err(|error| eyre!("release ChainSpec binding is invalid: {error}"))
}

fn require_chain_spec_evidence(
    evidence: &Value,
    binding: &DcapChainSpecBindingV1,
    genesis: &Path,
    network: SgxReleaseNetwork,
) -> Result<()> {
    let string_at = |pointer: &str| {
        evidence
            .pointer(pointer)
            .and_then(Value::as_str)
            .ok_or_else(|| eyre!("DCAP evidence lacks {pointer}"))
    };
    let u64_at = |pointer: &str| {
        evidence
            .pointer(pointer)
            .and_then(Value::as_u64)
            .ok_or_else(|| eyre!("DCAP evidence lacks {pointer}"))
    };
    let policy_sha256 = hex::encode(Sha256::digest(&binding.policy_bytes));
    let schedule_sha256 = hex::encode(Sha256::digest(&binding.policy_schedule_bytes));
    if u64_at("/policy/chain_id")? != binding.chain_id
        || string_at("/policy/genesis_hash")? != hex::encode(binding.genesis_hash)
        || u64_at("/policy/activation_height")? != binding.activation_height
        || u64_at("/policy/policy_version")? != binding.policy_version
        || string_at("/policy/policy_hash")? != hex::encode(binding.policy_hash)
        || string_at("/policy/sha256")? != policy_sha256
        || string_at("/policy/policy_schedule_hash")? != hex::encode(binding.policy_schedule_hash)
        || string_at("/policy/policy_schedule_sha256")? != schedule_sha256
    {
        bail!("DCAP evidence policy does not equal the block-1 release policy");
    }

    let genesis_digest = file_digest(genesis)?;
    let genesis_size = fs::metadata(genesis)?.len();
    require_retained_binding(
        evidence,
        network.genesis_artifact_name(),
        genesis_size,
        &genesis_digest.value,
    )?;
    require_retained_binding(
        evidence,
        "policy-v1.bin",
        binding.policy_bytes.len() as u64,
        &policy_sha256,
    )?;
    require_retained_binding(
        evidence,
        "policy-schedule-v1.bin",
        binding.policy_schedule_bytes.len() as u64,
        &schedule_sha256,
    )
}

fn require_retained_binding(
    evidence: &Value,
    name: &str,
    expected_size: u64,
    expected_sha256: &str,
) -> Result<()> {
    let pointer = format!("/artifacts/{name}");
    let artifact = evidence
        .pointer(&pointer)
        .ok_or_else(|| eyre!("DCAP evidence lacks retained {name}"))?;
    if artifact.get("size").and_then(Value::as_u64) != Some(expected_size)
        || artifact.get("sha256").and_then(Value::as_str) != Some(expected_sha256)
    {
        bail!("retained {name} does not match its exact input bytes");
    }
    Ok(())
}

fn verify_processor_dcap_archive(
    archive_path: &Path,
    summary_path: &Path,
    evidence: &Value,
    artifact_set: ReleaseDcapArtifactSetV1,
    source_date_epoch: i64,
) -> Result<()> {
    if source_date_epoch < 0 {
        bail!("Processor DCAP archive SOURCE_DATE_EPOCH must be non-negative");
    }
    require_nonempty_regular_file(archive_path, "Processor DCAP evidence archive")?;

    let records = evidence
        .get("artifacts")
        .and_then(Value::as_object)
        .ok_or_else(|| eyre!("Processor DCAP evidence lacks retained artifact records"))?;
    let required = artifact_set.paths();
    let declared = records.keys().map(String::as_str).collect::<BTreeSet<_>>();
    if declared != required {
        bail!("Processor DCAP evidence does not declare the exact canonical artifact set");
    }
    let mut expected = BTreeMap::new();
    for (path, record) in records {
        validate_archive_member_path(path)?;
        let size = record
            .get("size")
            .and_then(Value::as_u64)
            .ok_or_else(|| eyre!("Processor DCAP artifact {path} lacks size"))?;
        let sha256 = record
            .get("sha256")
            .and_then(Value::as_str)
            .ok_or_else(|| eyre!("Processor DCAP artifact {path} lacks sha256"))?;
        if !is_lower_hex(sha256, 64) {
            bail!("Processor DCAP artifact {path} has invalid sha256");
        }
        if expected
            .insert(path.clone(), (size, sha256.to_owned()))
            .is_some()
        {
            bail!("Processor DCAP evidence contains duplicate artifact {path}");
        }
    }
    let summary_size = fs::metadata(summary_path)?.len();
    let summary_digest = file_digest(summary_path)?;
    if expected
        .insert(
            "hardware-dcap-evidence.json".to_owned(),
            (summary_size, summary_digest.value),
        )
        .is_some()
    {
        bail!("Processor DCAP artifact records contain the reserved summary path");
    }

    let input = File::open(archive_path)
        .wrap_err_with(|| format!("open Processor DCAP archive: {}", archive_path.display()))?;
    let mut archive = tar::Archive::new(input);
    let mut observed = BTreeSet::new();
    let mut previous = None::<String>;
    for item in archive
        .entries()
        .wrap_err("read Processor DCAP evidence archive")?
    {
        let mut item = item.wrap_err("read Processor DCAP evidence archive entry")?;
        let raw_path = item
            .path()
            .wrap_err("read Processor DCAP evidence archive path")?
            .to_string_lossy()
            .into_owned();
        let path = if raw_path == "." {
            if !item.header().entry_type().is_dir() {
                bail!("Processor DCAP archive root entry is not a directory");
            }
            continue;
        } else {
            raw_path
                .strip_prefix("./")
                .unwrap_or(&raw_path)
                .trim_end_matches('/')
                .to_owned()
        };
        validate_archive_member_path(&path)?;
        if previous.as_ref().is_some_and(|value| value >= &path) {
            bail!("Processor DCAP archive members are not in canonical order");
        }
        previous = Some(path.clone());
        if !observed.insert(path.clone()) {
            bail!("Processor DCAP archive contains duplicate path: {path}");
        }
        let header = item.header();
        if header.uid()? != 0 || header.gid()? != 0 || header.mtime()? != source_date_epoch as u64 {
            bail!("Processor DCAP archive has non-deterministic ownership/time: {path}");
        }
        if header.entry_type().is_dir() {
            let prefix = format!("{path}/");
            if !expected.keys().any(|member| member.starts_with(&prefix)) {
                bail!("Processor DCAP archive contains unrecorded directory: {path}");
            }
            continue;
        }
        if !header.entry_type().is_file() {
            bail!("Processor DCAP archive contains non-file entry: {path}");
        }
        let (expected_size, expected_sha256) = expected
            .remove(&path)
            .ok_or_else(|| eyre!("Processor DCAP archive contains unrecorded file: {path}"))?;
        if header.size()? != expected_size {
            bail!("Processor DCAP archive member size mismatch: {path}");
        }
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 64 * 1024];
        let mut size = 0_u64;
        loop {
            let count = item.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
            size += count as u64;
        }
        if size != expected_size || hex::encode(hasher.finalize()) != expected_sha256 {
            bail!("Processor DCAP archive member digest mismatch: {path}");
        }
    }
    if !expected.is_empty() {
        bail!(
            "Processor DCAP archive lacks retained files: {}",
            expected.keys().cloned().collect::<Vec<_>>().join(", ")
        );
    }
    Ok(())
}

fn validate_archive_member_path(path: &str) -> Result<()> {
    let path = Path::new(path);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path.to_string_lossy().contains('\\')
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!(
            "Processor DCAP archive contains unsafe path: {}",
            path.display()
        );
    }
    Ok(())
}

fn is_utc_second(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 20
        && bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':'
        && bytes[19] == b'Z'
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 4 | 7 | 10 | 13 | 16 | 19) || byte.is_ascii_digit()
        })
        && OffsetDateTime::parse(value, &Rfc3339).is_ok()
}

fn validate_final_release_identity(
    release: &Value,
    bundle: &BundleManifest,
    oci: &OciBuildEvidence,
) -> Result<()> {
    let commit = release
        .pointer("/release/source/commit")
        .and_then(Value::as_str)
        .ok_or_else(|| eyre!("ELF release manifest lacks source commit"))?;
    let tag = release
        .pointer("/release/tag")
        .and_then(Value::as_str)
        .ok_or_else(|| eyre!("ELF release manifest lacks release tag"))?;
    let epoch = release
        .pointer("/build/source_date_epoch")
        .and_then(Value::as_i64)
        .ok_or_else(|| eyre!("ELF release manifest lacks SOURCE_DATE_EPOCH"))?;
    if commit != bundle.source.commit
        || tag != bundle.source.tag
        || epoch != bundle.source.source_date_epoch
        || bundle.source != oci.source
        || bundle.measurements != oci.measurements
        || oci.platform != "linux/amd64"
    {
        bail!("ELF, SGX bundle and OCI evidence do not share one release identity");
    }
    Ok(())
}

fn signed_tee_metadata(bundle: &BundleManifest) -> Value {
    serde_json::json!({
        "authorization_scope": bundle.authorization_scope,
        "isv_prod_id": bundle.measurements.isv_prod_id,
        "isv_svn": bundle.measurements.isv_svn,
        "mock": false,
        "mrenclave": bundle.measurements.mrenclave,
        "mrsigner": bundle.measurements.mrsigner,
        "sealed_state_schema": bundle.sealed_state_schema,
        "stage": "signed"
    })
}

fn release_platform() -> Value {
    serde_json::json!({
        "architecture": "x86_64",
        "os": "linux",
        "target": "x86_64-unknown-linux-gnu"
    })
}

fn file_artifact(
    path: &Path,
    name: &str,
    kind: &str,
    media_type: &str,
    tee: Value,
) -> Result<Value> {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            eyre!(
                "release artifact needs a UTF-8 file name: {}",
                path.display()
            )
        })?;
    require_nonempty_regular_file(path, name)?;
    let metadata = fs::metadata(path)?;
    Ok(serde_json::json!({
        "classification": "production",
        "digest": file_digest(path)?,
        "features": [],
        "install_profiles": ["full-node", "validator"],
        "kind": kind,
        "media_type": media_type,
        "name": name,
        "network_compatibility": "network-manifest-required",
        "package": "outbe-tee-enclave",
        "path": format!("release/{file_name}"),
        "platform": release_platform(),
        "role": "tee-enclave",
        "size": metadata.len(),
        "tee": tee
    }))
}

fn require_evidence_result(path: &Path, allowed: &[&str]) -> Result<Value> {
    require_nonempty_regular_file(path, "release evidence")?;
    let value: Value = read_canonical_json(path)?;
    let result = value
        .get("result")
        .and_then(Value::as_str)
        .ok_or_else(|| eyre!("release evidence lacks result: {}", path.display()))?;
    if !allowed.contains(&result) {
        bail!("release evidence is not successful: {}", path.display());
    }
    Ok(value)
}

fn passed_gate(name: &str, evidence: &Path) -> Result<Value> {
    passed_gate_many(name, &[evidence])
}

fn passed_gate_many(name: &str, evidence: &[&Path]) -> Result<Value> {
    let evidence = evidence
        .iter()
        .map(|path| {
            require_nonempty_regular_file(path, "release evidence")?;
            let file_name = path
                .file_name()
                .and_then(|value| value.to_str())
                .ok_or_else(|| eyre!("release evidence needs a UTF-8 file name"))?;
            let media_type = if path.extension().and_then(|value| value.to_str()) == Some("tar") {
                "application/x-tar"
            } else {
                "application/json"
            };
            Ok(serde_json::json!({
                "digest": file_digest(path)?,
                "media_type": media_type,
                "uri": format!("release://evidence/{file_name}")
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(serde_json::json!({
        "evidence": evidence,
        "name": name,
        "status": "passed"
    }))
}

fn verify_cosign_image_signature(path: &Path, expected_digest: &str) -> Result<()> {
    let verification: Value = read_canonical_json(path)?;
    let entries = verification
        .as_array()
        .ok_or_else(|| eyre!("Cosign image verification must be a JSON array"))?;
    let expected = format!("sha256:{expected_digest}");
    let matched = entries.iter().any(|entry| {
        entry
            .pointer("/critical/image/docker-manifest-digest")
            .and_then(Value::as_str)
            == Some(expected.as_str())
            && entry.pointer("/critical/type").and_then(Value::as_str)
                == Some("cosign container image signature")
    });
    if !matched {
        bail!("Cosign image verification does not bind the exact OCI digest");
    }
    Ok(())
}

fn verified_cosign_attestation(
    path: &Path,
    expected_digest: &str,
    expected_predicate_type: &str,
) -> Result<Value> {
    require_nonempty_regular_file(path, "release evidence")?;
    let verification: Value = read_canonical_json(path)?;
    let envelopes = verification
        .as_array()
        .ok_or_else(|| eyre!("Cosign attestation verification must be a JSON array"))?;
    for envelope in envelopes {
        let Some(payload) = envelope.get("payload").and_then(Value::as_str) else {
            continue;
        };
        let decoded = BASE64
            .decode(payload)
            .wrap_err("decode verified Cosign DSSE payload")?;
        let statement: Value =
            serde_json::from_slice(&decoded).wrap_err("parse verified Cosign statement")?;
        let subject_matches = statement
            .get("subject")
            .and_then(Value::as_array)
            .is_some_and(|subjects| {
                subjects.iter().any(|subject| {
                    subject.pointer("/digest/sha256").and_then(Value::as_str)
                        == Some(expected_digest)
                })
            });
        if statement.get("_type").and_then(Value::as_str)
            == Some("https://in-toto.io/Statement/v0.1")
            && statement.get("predicateType").and_then(Value::as_str)
                == Some(expected_predicate_type)
            && subject_matches
        {
            return Ok(statement);
        }
    }
    Err(eyre!(
        "Cosign attestation verification does not bind predicate {expected_predicate_type} to the exact OCI digest"
    ))
}

fn require_nonempty_regular_file(path: &Path, label: &str) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).wrap_err_with(|| format!("read {label}: {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() || metadata.len() == 0 {
        bail!(
            "{label} must be a non-empty regular file: {}",
            path.display()
        );
    }
    Ok(())
}

fn sort_json(value: Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.into_iter().map(sort_json).collect()),
        Value::Object(values) => {
            let sorted = values
                .into_iter()
                .map(|(key, value)| (key, sort_json(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect())
        }
        scalar => scalar,
    }
}

pub fn parse_sigstruct_view(output: &str) -> Result<Measurements> {
    let values = output
        .lines()
        .filter_map(|raw| raw.trim().split_once(':'))
        .map(|(key, value)| (key.trim().to_ascii_lowercase(), value.trim().to_owned()))
        .collect::<BTreeMap<_, _>>();

    let field = |name: &str| {
        values
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| eyre!("SIGSTRUCT output missing field: {name}"))
    };
    let mrsigner = field("mr_signer")?.to_ascii_lowercase();
    let mrenclave = field("mr_enclave")?.to_ascii_lowercase();
    if !is_lower_hex(&mrsigner, 64) {
        bail!("SIGSTRUCT MRSIGNER must be 32 lowercase hexadecimal bytes");
    }
    if !is_lower_hex(&mrenclave, 64) {
        bail!("SIGSTRUCT MRENCLAVE must be 32 lowercase hexadecimal bytes");
    }
    let debug = match field("debug_enclave")?.to_ascii_lowercase().as_str() {
        "true" => true,
        "false" => false,
        _ => return Err(eyre!("SIGSTRUCT debug_enclave must be True or False")),
    };

    Ok(Measurements {
        debug,
        isv_prod_id: field("isv_prod_id")?
            .parse()
            .wrap_err("parse SIGSTRUCT isv_prod_id")?,
        isv_svn: field("isv_svn")?
            .parse()
            .wrap_err("parse SIGSTRUCT isv_svn")?,
        mrenclave,
        mrsigner,
    })
}

pub fn parse_oci_descriptor(metadata: &str) -> Result<OciDescriptor> {
    let value: Value = serde_json::from_str(metadata).wrap_err("parse BuildKit metadata")?;
    let descriptor = value
        .get("containerimage.descriptor")
        .and_then(Value::as_object)
        .ok_or_else(|| eyre!("BuildKit metadata lacks OCI descriptor"))?;
    let digest = descriptor
        .get("digest")
        .and_then(Value::as_str)
        .or_else(|| value.get("containerimage.digest").and_then(Value::as_str))
        .ok_or_else(|| eyre!("BuildKit metadata lacks OCI descriptor digest"))?;
    let Some(digest) = digest.strip_prefix("sha256:") else {
        bail!("OCI descriptor digest must use sha256");
    };
    if !is_lower_hex(digest, 64) {
        bail!("OCI descriptor digest must contain 32 lowercase hexadecimal bytes");
    }
    let media_type = descriptor
        .get("mediaType")
        .and_then(Value::as_str)
        .ok_or_else(|| eyre!("BuildKit metadata lacks OCI descriptor media type"))?;
    if media_type.is_empty() || !media_type.is_ascii() {
        bail!("OCI descriptor media type must be non-empty ASCII");
    }
    let size = descriptor
        .get("size")
        .and_then(Value::as_u64)
        .ok_or_else(|| eyre!("BuildKit metadata lacks OCI descriptor size"))?;
    Ok(OciDescriptor {
        digest: Sha256Digest {
            algorithm: "sha256".to_owned(),
            value: digest.to_owned(),
        },
        media_type: media_type.to_owned(),
        size,
    })
}

pub fn compare_unsigned_trees(first: &Path, second: &Path) -> Result<ComparisonEvidence> {
    let first_entries = tree_entries(first)?;
    let second_entries = tree_entries(second)?;
    if first_entries != second_entries {
        bail!("unsigned SGX bundle mismatch");
    }
    let digest = Sha256::digest(canonical_json(&first_entries)?);
    Ok(ComparisonEvidence {
        entry_count: first_entries.len(),
        result: "identical".to_owned(),
        schema_version: "1.0.0".to_owned(),
        tree_digest: Sha256Digest {
            algorithm: "sha256".to_owned(),
            value: hex::encode(digest),
        },
    })
}

pub fn build_bundle_manifest(
    bundle_root: &Path,
    bundle_spec: &BundleSpec,
    source: &SourceIdentity,
    sigstruct_view: &str,
) -> Result<BundleManifest> {
    bundle_spec.validate()?;
    if !is_lower_hex(&source.source_commit, 40) {
        bail!("source commit must be a lowercase 40-character Git SHA");
    }
    if source.release_tag.is_empty() || !source.release_tag.is_ascii() {
        bail!("release tag must be non-empty ASCII");
    }
    let measurements = parse_sigstruct_view(sigstruct_view)?;
    validate_measurements(bundle_spec, &measurements)?;

    Ok(BundleManifest {
        authorization_scope: bundle_spec.authorization_scope.clone(),
        bundle_version: bundle_spec.bundle_version,
        chain_id: bundle_spec.chain_id,
        files: bundle_files(bundle_root)?,
        gramine: bundle_spec.gramine.clone(),
        install_root: bundle_spec.install_root.clone(),
        measurements,
        network: bundle_spec.network.clone(),
        network_name: bundle_spec.network_name.clone(),
        platform: bundle_spec.platform.clone(),
        schema_version: "1.0.0".to_owned(),
        sealed_state_schema: bundle_spec.sealed_state_schema,
        sigstruct_date: sigstruct_date(source.source_date_epoch)?,
        source: ManifestSource {
            commit: source.source_commit.clone(),
            source_date_epoch: source.source_date_epoch,
            tag: source.release_tag.clone(),
        },
    })
}

pub fn verify_signed_bundle(
    bundle_root: &Path,
    manifest: &BundleManifest,
    bundle_spec: &BundleSpec,
    sigstruct_view: &str,
) -> Result<()> {
    bundle_spec.validate()?;
    if manifest.schema_version != "1.0.0"
        || manifest.authorization_scope != bundle_spec.authorization_scope
        || manifest.bundle_version != bundle_spec.bundle_version
        || manifest.chain_id != bundle_spec.chain_id
        || manifest.gramine != bundle_spec.gramine
        || manifest.install_root != bundle_spec.install_root
        || manifest.network != bundle_spec.network
        || manifest.network_name != bundle_spec.network_name
        || manifest.platform != bundle_spec.platform
        || manifest.sealed_state_schema != bundle_spec.sealed_state_schema
    {
        bail!("bundle metadata does not match the SGX network contract");
    }
    if manifest.files != bundle_files(bundle_root)? {
        bail!("bundle file matrix mismatch");
    }
    let descriptor = read_measured_network_descriptor(bundle_root)?;
    if descriptor.network_binding.chain_id
        != alloy_primitives::U256::from(bundle_spec.chain_id).to_be_bytes()
    {
        bail!("measured network descriptor belongs to a foreign chain");
    }
    let measurements = parse_sigstruct_view(sigstruct_view)?;
    validate_measurements(bundle_spec, &measurements)?;
    if manifest.measurements != measurements {
        bail!("SIGSTRUCT measurements do not match bundle metadata");
    }
    if manifest.sigstruct_date != sigstruct_date(manifest.source.source_date_epoch)? {
        bail!("SIGSTRUCT date does not match SOURCE_DATE_EPOCH");
    }
    Ok(())
}

fn read_measured_network_descriptor(bundle_root: &Path) -> Result<TrustedNetworkDescriptorV1> {
    let metadata_path = bundle_root.join("metadata/network-descriptor-v1.bin");
    let measured_path = bundle_root.join("rootfs/opt/outbe/sgx/network-descriptor-v1.bin");
    let metadata = fs::read(&metadata_path).wrap_err_with(|| {
        format!(
            "read trusted network descriptor: {}",
            metadata_path.display()
        )
    })?;
    let measured = fs::read(&measured_path).wrap_err_with(|| {
        format!(
            "read measured network descriptor: {}",
            measured_path.display()
        )
    })?;
    if metadata != measured {
        bail!("trusted network descriptor differs from the file measured into MRENCLAVE");
    }
    TrustedNetworkDescriptorV1::decode_canonical(&measured)
        .map_err(|error| eyre!("trusted network descriptor is invalid: {error}"))
}

fn require_measured_network_descriptor(
    bundle_root: &Path,
    genesis: &Path,
    binding: &DcapChainSpecBindingV1,
) -> Result<()> {
    let actual = read_measured_network_descriptor(bundle_root)?;
    let seeded = DcapSeededChainSpecBindingV1::from_genesis_path(genesis)
        .map_err(|error| eyre!("release seeded ChainSpec binding is invalid: {error}"))?;
    let expected = TrustedNetworkDescriptorV1 {
        network_binding: NetworkBindingV1 {
            chain_id: alloy_primitives::U256::from(binding.chain_id).to_be_bytes(),
            genesis_hash: binding.genesis_hash,
            attestation_mode: AttestationMode::DcapRequired,
        },
        genesis_consensus_keys: seeded.genesis_consensus_keys,
    };
    if actual != expected {
        bail!("measured network descriptor does not match the release genesis ChainSpec");
    }
    Ok(())
}

fn validate_measurements(spec: &BundleSpec, measurements: &Measurements) -> Result<()> {
    if measurements.debug != spec.sgx.debug
        || measurements.isv_prod_id != spec.sgx.isv_prod_id
        || measurements.isv_svn != spec.sgx.isv_svn
    {
        bail!("SIGSTRUCT identity does not match the SGX bundle contract");
    }
    Ok(())
}

fn sigstruct_date(source_date_epoch: i64) -> Result<String> {
    if source_date_epoch < 0 {
        bail!("SOURCE_DATE_EPOCH must be non-negative");
    }
    let date = OffsetDateTime::from_unix_timestamp(source_date_epoch)
        .wrap_err("SOURCE_DATE_EPOCH is outside the supported range")?
        .date();
    Ok(format!(
        "{:04}-{:02}-{:02}",
        date.year(),
        u8::from(date.month()),
        date.day()
    ))
}

fn tree_entries(root: &Path) -> Result<Vec<TreeEntry>> {
    if !root.is_dir() {
        bail!("bundle tree is not a directory: {}", root.display());
    }
    let mut entries = Vec::new();
    for item in WalkDir::new(root).min_depth(1).sort_by_file_name() {
        let item = item.wrap_err_with(|| format!("walk bundle tree: {}", root.display()))?;
        let path = item.path();
        let relative = path
            .strip_prefix(root)
            .wrap_err("derive bundle tree relative path")?
            .to_string_lossy()
            .replace('\\', "/");
        let metadata = fs::symlink_metadata(path)
            .wrap_err_with(|| format!("read bundle tree metadata: {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            bail!("bundle tree contains symlink: {relative}");
        }
        let mode = format!("{:04o}", metadata.permissions().mode() & 0o7777);
        if metadata.is_dir() {
            entries.push(TreeEntry {
                digest: None,
                mode,
                path: relative,
                size: None,
                kind: "directory".to_owned(),
            });
        } else if metadata.is_file() {
            entries.push(TreeEntry {
                digest: Some(file_digest(path)?),
                mode,
                path: relative,
                size: Some(metadata.len()),
                kind: "file".to_owned(),
            });
        } else {
            bail!("bundle tree contains unsupported entry: {relative}");
        }
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(entries)
}

fn bundle_files(root: &Path) -> Result<Vec<BundleFile>> {
    if !root.is_dir() {
        bail!("SGX bundle is not a directory: {}", root.display());
    }
    let mut files = Vec::new();
    let mut found = BTreeSet::new();
    for item in WalkDir::new(root).min_depth(1).sort_by_file_name() {
        let item = item.wrap_err_with(|| format!("walk SGX bundle: {}", root.display()))?;
        let path = item.path();
        let relative = path
            .strip_prefix(root)
            .wrap_err("derive SGX bundle relative path")?
            .to_string_lossy()
            .replace('\\', "/");
        let metadata = fs::symlink_metadata(path)
            .wrap_err_with(|| format!("read SGX bundle metadata: {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            bail!("bundle contains symlink: {relative}");
        }
        if !metadata.is_file() || EXCLUDED_BUNDLE_FILES.contains(&relative.as_str()) {
            continue;
        }
        let lowered = relative.to_ascii_lowercase();
        if lowered.ends_with(".pem") || lowered.ends_with(".key") || lowered.contains("private-key")
        {
            bail!("bundle contains forbidden private-key material: {relative}");
        }
        found.insert(relative.clone());
        files.push(BundleFile {
            digest: file_digest(path)?,
            mode: format!("{:04o}", metadata.permissions().mode() & 0o7777),
            path: relative,
            size: metadata.len(),
        });
    }
    let missing = REQUIRED_BUNDLE_FILES
        .iter()
        .filter(|path| !found.contains(**path))
        .copied()
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        bail!("SGX bundle missing required files: {}", missing.join(", "));
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(files)
}

fn file_digest(path: &Path) -> Result<Sha256Digest> {
    let file =
        File::open(path).wrap_err_with(|| format!("open for hashing: {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .wrap_err_with(|| format!("hash file: {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(Sha256Digest {
        algorithm: "sha256".to_owned(),
        value: hex::encode(hasher.finalize()),
    })
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub fn prepare(
    repo_root: &Path,
    network: SgxReleaseNetwork,
    genesis: &Path,
    elf_output: &Path,
    output: &Path,
) -> Result<()> {
    let spec = BundleSpec::read(&repo_root.join(network.bundle_spec_path()))?;
    require_release_checkout(repo_root, network)?;
    verify_checksums(elf_output, "SHA256SUMS")?;
    let identity = read_elf_identity(elf_output)?;
    require_clean_source(repo_root, &identity.source_commit)?;
    let toolchain_image = build_project_toolchain_image(repo_root, &spec, &identity.source_commit)?;
    let output = create_empty_output(repo_root, output)?;
    let genesis = fs::canonicalize(genesis)
        .wrap_err_with(|| format!("resolve release genesis ChainSpec: {}", genesis.display()))?;
    let seeded = DcapSeededChainSpecBindingV1::from_genesis_path(&genesis)
        .map_err(|error| eyre!("release seeded ChainSpec binding is invalid: {error}"))?;
    if seeded.chain_id != network.chain_id() {
        bail!("release genesis belongs to a foreign SGX network");
    }
    let trusted_network_descriptor = TrustedNetworkDescriptorV1 {
        network_binding: NetworkBindingV1 {
            chain_id: alloy_primitives::U256::from(seeded.chain_id).to_be_bytes(),
            genesis_hash: seeded.genesis_hash,
            attestation_mode: AttestationMode::DcapRequired,
        },
        genesis_consensus_keys: seeded.genesis_consensus_keys,
    }
    .encode_canonical()
    .map_err(|error| eyre!("encode trusted network descriptor: {error}"))?;
    let descriptor_path = output.join("metadata/network-descriptor-v1.bin");
    fs::create_dir_all(
        descriptor_path
            .parent()
            .expect("network descriptor path has a parent"),
    )?;
    fs::write(&descriptor_path, trusted_network_descriptor)
        .wrap_err("write trusted network descriptor")?;
    let elf_output = fs::canonicalize(elf_output)
        .wrap_err_with(|| format!("resolve ELF output: {}", elf_output.display()))?;

    let mut command = docker_command(&spec, repo_root)?;
    command
        .args(["-e", &format!("SGX_MAX_THREADS={}", spec.sgx.max_threads)])
        .args(["-e", &format!("SGX_ISV_PROD_ID={}", spec.sgx.isv_prod_id)])
        .args(["-e", &format!("SGX_ISV_SVN={}", spec.sgx.isv_svn)])
        .args(["-v", &format!("{}:/elf:ro", elf_output.display())])
        .args(["-v", &format!("{}:/out", output.display())])
        .arg(&toolchain_image)
        .args([container_adapter(), "prepare"]);
    run_status(&mut command, "prepare unsigned SGX bundle")?;

    write_canonical(&output.join("metadata/source-identity.json"), &identity)?;
    write_checksums(&output, "SHA256SUMS.unsigned")?;
    normalize_tree_mtime(&output, identity.source_date_epoch)?;
    verify_checksums(&output, "SHA256SUMS.unsigned")?;
    Ok(())
}

pub fn compare(first: &Path, second: &Path, output: &Path) -> Result<()> {
    let first = fs::canonicalize(first)
        .wrap_err_with(|| format!("resolve first unsigned bundle: {}", first.display()))?;
    let second = fs::canonicalize(second)
        .wrap_err_with(|| format!("resolve second unsigned bundle: {}", second.display()))?;
    verify_checksums(&first, "SHA256SUMS.unsigned")?;
    verify_checksums(&second, "SHA256SUMS.unsigned")?;
    let output = absolute_path(output)?;
    if output.starts_with(&first) || output.starts_with(&second) {
        bail!("comparison evidence must be outside both input trees");
    }
    if output.exists() {
        bail!("comparison evidence already exists: {}", output.display());
    }
    let evidence = compare_unsigned_trees(&first, &second)?;
    write_canonical(&output, &evidence)
}

pub fn sign(
    repo_root: &Path,
    network: SgxReleaseNetwork,
    unsigned: &Path,
    key_file: &Path,
    output: &Path,
) -> Result<()> {
    let spec = BundleSpec::read(&repo_root.join(network.bundle_spec_path()))?;
    require_release_checkout(repo_root, network)?;
    validate_signing_key(key_file)?;
    let unsigned = fs::canonicalize(unsigned)
        .wrap_err_with(|| format!("resolve unsigned SGX bundle: {}", unsigned.display()))?;
    let key_file = fs::canonicalize(key_file)
        .wrap_err_with(|| format!("resolve SGX signing key: {}", key_file.display()))?;
    verify_checksums(&unsigned, "SHA256SUMS.unsigned")?;
    let identity: SourceIdentity =
        read_canonical_json(&unsigned.join("metadata/source-identity.json"))?;
    validate_source_identity(&identity)?;
    require_clean_source(repo_root, &identity.source_commit)?;
    let toolchain_image = build_project_toolchain_image(repo_root, &spec, &identity.source_commit)?;
    let output = create_empty_output(repo_root, output)?;
    let date = sigstruct_date(identity.source_date_epoch)?;

    let mut command = docker_command(&spec, repo_root)?;
    command
        .args(["-e", &format!("SIGSTRUCT_DATE={date}")])
        .args(["-v", &format!("{}:/unsigned:ro", unsigned.display())])
        .args([
            "-v",
            &format!("{}:/run/secrets/sgx-signing-key.pem:ro", key_file.display()),
        ])
        .args(["-v", &format!("{}:/out", output.display())])
        .arg(&toolchain_image)
        .args([container_adapter(), "sign"]);
    run_status(&mut command, "sign SGX bundle")?;

    let sigstruct_view = fs::read_to_string(output.join("metadata/sigstruct.txt"))
        .wrap_err("read signed bundle SIGSTRUCT evidence")?;
    let manifest = build_bundle_manifest(&output, &spec, &identity, &sigstruct_view)?;
    write_canonical(&output.join(network.bundle_manifest_path()), &manifest)?;
    verify_signed_bundle(&output, &manifest, &spec, &sigstruct_view)?;
    write_checksums(&output, "SHA256SUMS")?;
    normalize_tree_mtime(&output, identity.source_date_epoch)?;
    verify_checksums(&output, "SHA256SUMS")?;
    Ok(())
}

/// Creates the final network genesis from one approved seeded genesis and the
/// exact measurements of an already signed bundle. The only JSON mutation is
/// insertion of `config.teeAttestationV1`; the measured descriptor remains
/// rooted in the unchanged chain identity and epoch-0 committee.
pub fn finalize_genesis(
    repo_root: &Path,
    network: SgxReleaseNetwork,
    seeded_genesis: &Path,
    bundle: &Path,
    output: &Path,
    evidence_output: &Path,
) -> Result<()> {
    if output == evidence_output || output.exists() || evidence_output.exists() {
        bail!("final genesis and evidence outputs must be distinct new paths");
    }
    let spec = BundleSpec::read(&repo_root.join(network.bundle_spec_path()))?;
    require_release_checkout(repo_root, network)?;
    let bundle = fs::canonicalize(bundle)
        .wrap_err_with(|| format!("resolve signed SGX bundle: {}", bundle.display()))?;
    verify_checksums(&bundle, "SHA256SUMS")?;
    let manifest_path = bundle.join(network.bundle_manifest_path());
    let manifest: BundleManifest = read_canonical_json(&manifest_path)?;
    require_bundle_network(&manifest, network)?;
    require_clean_source(repo_root, &manifest.source.commit)?;

    let seeded = DcapSeededChainSpecBindingV1::from_genesis_path(seeded_genesis)
        .map_err(|error| eyre!("seeded release ChainSpec binding is invalid: {error}"))?;
    if seeded.chain_id != network.chain_id() {
        bail!("seeded release genesis belongs to a foreign network");
    }
    let descriptor = read_measured_network_descriptor(&bundle)?;
    let expected_descriptor = TrustedNetworkDescriptorV1 {
        network_binding: NetworkBindingV1 {
            chain_id: alloy_primitives::U256::from(seeded.chain_id).to_be_bytes(),
            genesis_hash: seeded.genesis_hash,
            attestation_mode: AttestationMode::DcapRequired,
        },
        genesis_consensus_keys: seeded.genesis_consensus_keys.clone(),
    };
    if descriptor != expected_descriptor {
        bail!("signed bundle descriptor does not match the approved seeded genesis");
    }

    let measurement = |value: &str, label: &str| -> Result<alloy_primitives::B256> {
        if !is_lower_hex(value, 64) {
            bail!("signed bundle {label} is not 32 lowercase hexadecimal bytes");
        }
        let bytes = hex::decode(value).wrap_err_with(|| format!("decode signed bundle {label}"))?;
        Ok(alloy_primitives::B256::from_slice(&bytes))
    };
    let profile = InitialTeeProfileV1::DcapRequired(ProductionSgxMeasurementV1 {
        mrenclave: measurement(&manifest.measurements.mrenclave, "MRENCLAVE")?,
        mrsigner: measurement(&manifest.measurements.mrsigner, "MRSIGNER")?,
        isv_prod_id: manifest.measurements.isv_prod_id,
        minimum_isv_svn: manifest.measurements.isv_svn,
        minimum_tcb_evaluation_data_number: spec.sgx.minimum_tcb_evaluation_data_number,
    });
    let policy = initial_tee_policy_v1(profile, seeded.chain_id, seeded.genesis_hash)
        .map_err(eyre::Report::msg)?;
    let policy_field = tee_attestation_v1_genesis_field(&policy).map_err(eyre::Report::msg)?;

    let seeded_bytes = fs::read(seeded_genesis)
        .wrap_err_with(|| format!("read approved seeded genesis: {}", seeded_genesis.display()))?;
    let mut final_value: Value =
        serde_json::from_slice(&seeded_bytes).wrap_err("parse approved seeded genesis JSON")?;
    let config = final_value
        .get_mut("config")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| eyre!("seeded genesis config must be a JSON object"))?;
    if config.contains_key("teeAttestationV1") {
        bail!("seeded genesis already contains teeAttestationV1");
    }
    config.insert("teeAttestationV1".to_owned(), policy_field);
    let final_bytes = canonical_json(&final_value)?;
    write_new_file(output, &final_bytes, "final genesis")?;

    let validate_result = (|| -> Result<DcapChainSpecBindingV1> {
        let final_binding = DcapChainSpecBindingV1::from_genesis_path(output)
            .map_err(|error| eyre!("generated final ChainSpec binding is invalid: {error}"))?;
        if final_binding.chain_id != seeded.chain_id
            || final_binding.genesis_hash != seeded.genesis_hash
        {
            bail!("final genesis changed the seeded chain identity");
        }
        let final_seeded = DcapSeededChainSpecBindingV1::from_genesis_path(output)
            .map_err(|error| eyre!("generated final seeded binding is invalid: {error}"))?;
        if final_seeded != seeded {
            bail!("final genesis changed the seeded epoch-0 committee or chain identity");
        }
        require_measured_network_descriptor(&bundle, output, &final_binding)?;
        require_bundle_measurement_binding(&final_binding, &manifest)?;
        Ok(final_binding)
    })();
    let final_binding = match validate_result {
        Ok(binding) => binding,
        Err(error) => {
            let _ = fs::remove_file(output);
            return Err(error);
        }
    };

    let evidence = serde_json::json!({
        "schema": "outbe-sgx-final-genesis-evidence-v1",
        "network": network.authorization_scope(),
        "chain_id": final_binding.chain_id,
        "genesis_hash": format!("{:#x}", final_binding.genesis_hash),
        "seeded_genesis": file_digest(seeded_genesis)?,
        "final_genesis": file_digest(output)?,
        "bundle_manifest": file_digest(&manifest_path)?,
        "measured_descriptor": file_digest(&bundle.join("metadata/network-descriptor-v1.bin"))?,
        "measurements": manifest.measurements,
        "minimum_tcb_evaluation_data_number": spec.sgx.minimum_tcb_evaluation_data_number,
        "mutation": "insert-config-teeAttestationV1-only",
        "result": "passed"
    });
    if let Err(error) = write_new_file(
        evidence_output,
        &canonical_json(&evidence)?,
        "final genesis evidence",
    ) {
        let _ = fs::remove_file(output);
        return Err(error);
    }
    Ok(())
}

pub fn verify(repo_root: &Path, network: SgxReleaseNetwork, bundle: &Path) -> Result<()> {
    let spec = BundleSpec::read(&repo_root.join(network.bundle_spec_path()))?;
    require_release_checkout(repo_root, network)?;
    let bundle = fs::canonicalize(bundle)
        .wrap_err_with(|| format!("resolve signed SGX bundle: {}", bundle.display()))?;
    verify_checksums(&bundle, "SHA256SUMS")?;
    let manifest_path = bundle.join(network.bundle_manifest_path());
    let manifest: BundleManifest = read_canonical_json(&manifest_path)?;
    require_clean_source(repo_root, &manifest.source.commit)?;
    let toolchain_image = build_project_toolchain_image(repo_root, &spec, &manifest.source.commit)?;

    let mut command = docker_command(&spec, repo_root)?;
    command
        .args(["-v", &format!("{}:/bundle:ro", bundle.display())])
        .arg(&toolchain_image)
        .args([container_adapter(), "view"]);
    let sigstruct_view = run_output(&mut command, "read signed SGX SIGSTRUCT")?;
    verify_signed_bundle(&bundle, &manifest, &spec, &sigstruct_view)
}

pub fn verify_with_genesis(
    repo_root: &Path,
    network: SgxReleaseNetwork,
    bundle: &Path,
    genesis: &Path,
) -> Result<()> {
    verify(repo_root, network, bundle)?;
    let bundle = fs::canonicalize(bundle)
        .wrap_err_with(|| format!("resolve signed SGX bundle: {}", bundle.display()))?;
    let manifest: BundleManifest =
        read_canonical_json(&bundle.join(network.bundle_manifest_path()))?;
    let chain_binding = DcapChainSpecBindingV1::from_genesis_path(genesis)
        .map_err(|error| eyre!("final release ChainSpec binding is invalid: {error}"))?;
    if chain_binding.chain_id != network.chain_id() {
        bail!("final release genesis belongs to a foreign network");
    }
    require_measured_network_descriptor(&bundle, genesis, &chain_binding)?;
    require_bundle_measurement_binding(&chain_binding, &manifest)
}

pub fn archive(
    repo_root: &Path,
    network: SgxReleaseNetwork,
    bundle: &Path,
    output: &Path,
) -> Result<()> {
    verify(repo_root, network, bundle)?;
    let bundle = fs::canonicalize(bundle)
        .wrap_err_with(|| format!("resolve signed SGX bundle: {}", bundle.display()))?;
    let manifest: BundleManifest =
        read_canonical_json(&bundle.join(network.bundle_manifest_path()))?;
    let output = absolute_path(output)?;
    if output.starts_with(repo_root) || output.starts_with(&bundle) {
        bail!("signed SGX archive must be outside the checkout and bundle");
    }
    write_deterministic_bundle_archive(&bundle, &output, manifest.source.source_date_epoch)?;
    verify_bundle_archive(&bundle, &output, manifest.source.source_date_epoch)
}

pub fn write_deterministic_bundle_archive(
    bundle: &Path,
    output: &Path,
    source_date_epoch: i64,
) -> Result<()> {
    if source_date_epoch < 0 {
        bail!("SOURCE_DATE_EPOCH must be non-negative");
    }
    if output.exists() {
        bail!("signed SGX archive already exists: {}", output.display());
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .wrap_err_with(|| format!("create archive directory: {}", parent.display()))?;
    }
    let file = File::create(output)
        .wrap_err_with(|| format!("create signed SGX archive: {}", output.display()))?;
    let mut archive = tar::Builder::new(file);
    archive.follow_symlinks(false);
    for item in WalkDir::new(bundle).min_depth(1).sort_by_file_name() {
        let item =
            item.wrap_err_with(|| format!("walk signed SGX bundle: {}", bundle.display()))?;
        let path = item.path();
        let relative = path
            .strip_prefix(bundle)
            .wrap_err("derive archive relative path")?;
        let metadata = fs::symlink_metadata(path)
            .wrap_err_with(|| format!("read archive input: {}", path.display()))?;
        if metadata.file_type().is_symlink() {
            bail!("signed SGX bundle contains symlink: {}", relative.display());
        }
        let mut header = tar::Header::new_gnu();
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(source_date_epoch as u64);
        header.set_mode(metadata.permissions().mode() & 0o7777);
        if metadata.is_dir() {
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_cksum();
            archive
                .append_data(&mut header, relative, std::io::empty())
                .wrap_err_with(|| format!("archive directory: {}", relative.display()))?;
        } else if metadata.is_file() {
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(metadata.len());
            header.set_cksum();
            let mut input = File::open(path)
                .wrap_err_with(|| format!("open archive input: {}", path.display()))?;
            archive
                .append_data(&mut header, relative, &mut input)
                .wrap_err_with(|| format!("archive file: {}", relative.display()))?;
        } else {
            bail!(
                "signed SGX bundle contains unsupported entry: {}",
                relative.display()
            );
        }
    }
    archive.finish().wrap_err("finish signed SGX archive")?;
    Ok(())
}

fn verify_bundle_archive(bundle: &Path, archive_path: &Path, source_date_epoch: i64) -> Result<()> {
    require_nonempty_regular_file(archive_path, "signed SGX bundle archive")?;
    let input = File::open(archive_path)
        .wrap_err_with(|| format!("open signed SGX archive: {}", archive_path.display()))?;
    let mut archive = tar::Archive::new(input);
    let mut observed = Vec::new();
    let mut paths = BTreeSet::new();
    for item in archive.entries().wrap_err("read signed SGX archive")? {
        let mut item = item.wrap_err("read signed SGX archive entry")?;
        let path = item.path().wrap_err("read signed SGX archive path")?;
        if path.as_os_str().is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|component| !matches!(component, Component::Normal(_)))
        {
            bail!(
                "signed SGX archive contains unsafe path: {}",
                path.display()
            );
        }
        let path = path.to_string_lossy().replace('\\', "/");
        if !paths.insert(path.clone()) {
            bail!("signed SGX archive contains duplicate path: {path}");
        }
        let header = item.header();
        if header.uid()? != 0 || header.gid()? != 0 || header.mtime()? != source_date_epoch as u64 {
            bail!("signed SGX archive has non-deterministic ownership/time: {path}");
        }
        let mode = format!("{:04o}", header.mode()? & 0o7777);
        if header.entry_type().is_dir() {
            observed.push(TreeEntry {
                digest: None,
                mode,
                path,
                size: None,
                kind: "directory".to_owned(),
            });
        } else if header.entry_type().is_file() {
            let size = header.size()?;
            let mut hasher = Sha256::new();
            let mut buffer = [0u8; 64 * 1024];
            let mut read = 0u64;
            loop {
                let count = item.read(&mut buffer)?;
                if count == 0 {
                    break;
                }
                hasher.update(&buffer[..count]);
                read += count as u64;
            }
            if read != size {
                bail!("signed SGX archive entry size mismatch: {path}");
            }
            observed.push(TreeEntry {
                digest: Some(Sha256Digest {
                    algorithm: "sha256".to_owned(),
                    value: hex::encode(hasher.finalize()),
                }),
                mode,
                path,
                size: Some(size),
                kind: "file".to_owned(),
            });
        } else {
            bail!("signed SGX archive contains non-file entry: {path}");
        }
    }
    observed.sort_by(|left, right| left.path.cmp(&right.path));
    if observed != tree_entries(bundle)? {
        bail!("signed SGX archive does not exactly reproduce the verified bundle tree");
    }
    Ok(())
}

pub fn build_image(
    repo_root: &Path,
    network: SgxReleaseNetwork,
    bundle: &Path,
    image_reference: &str,
    output: &Path,
    push: bool,
) -> Result<()> {
    if image_reference.is_empty()
        || !image_reference.is_ascii()
        || image_reference.chars().any(char::is_whitespace)
    {
        bail!("OCI image reference must be non-empty ASCII without whitespace");
    }
    let output = absolute_path(output)?;
    if output.exists() {
        bail!("OCI build evidence already exists: {}", output.display());
    }
    verify(repo_root, network, bundle)?;
    let bundle = fs::canonicalize(bundle)
        .wrap_err_with(|| format!("resolve signed SGX bundle: {}", bundle.display()))?;
    if output.starts_with(&bundle) {
        bail!("OCI build evidence must be outside the signed bundle");
    }
    let manifest_path = bundle.join(network.bundle_manifest_path());
    let manifest: BundleManifest = read_canonical_json(&manifest_path)?;
    let metadata_file = tempfile::NamedTempFile::new().wrap_err("create BuildKit metadata file")?;
    let dockerfile = repo_root.join("bin/outbe-tee-enclave/gramine/Dockerfile");
    let mut command = Command::new("docker");
    command
        .args(["buildx", "build", "--platform", "linux/amd64", "--file"])
        .arg(&dockerfile)
        .args(["--tag", image_reference, "--metadata-file"])
        .arg(metadata_file.path());
    if push {
        command.args([
            "--push",
            "--provenance=mode=max,version=v0.2",
            "--sbom=true",
        ]);
    } else {
        command.args(["--load", "--provenance=false", "--sbom=false"]);
    }
    command.arg(&bundle);
    run_status(&mut command, "build immutable SGX OCI image")?;
    let buildkit_metadata =
        fs::read_to_string(metadata_file.path()).wrap_err("read BuildKit OCI metadata")?;
    let descriptor = parse_oci_descriptor(&buildkit_metadata)?;
    let evidence = OciBuildEvidence {
        bundle_manifest_digest: file_digest(&manifest_path)?,
        image: descriptor,
        image_reference: image_reference.to_owned(),
        measurements: manifest.measurements,
        platform: "linux/amd64".to_owned(),
        provenance_attestation: push,
        sbom_attestation: push,
        schema_version: "1.0.0".to_owned(),
        source: manifest.source,
    };
    write_canonical(&output, &evidence)
}

pub fn finalize_release_manifest(
    repo_root: &Path,
    inputs: &VerifiedReleaseInputs,
    output: &Path,
) -> Result<()> {
    verify(repo_root, inputs.network, &inputs.bundle)?;
    let output = absolute_path(output)?;
    if output.exists() {
        bail!(
            "verified ReleaseManifest already exists: {}",
            output.display()
        );
    }
    refresh_cosign_evidence(inputs)?;
    let manifest = build_release_manifest_from_evidence(inputs, "verified")?;
    write_canonical(&output, &manifest)
}

fn refresh_cosign_evidence(inputs: &VerifiedReleaseInputs) -> Result<()> {
    let oci: OciBuildEvidence = read_canonical_json(&inputs.oci_evidence)?;
    let bundle: BundleManifest =
        read_canonical_json(&inputs.bundle.join(inputs.network.bundle_manifest_path()))?;
    let exact_image = exact_image_reference(&oci)?;
    let workflow_sha = bundle.source.commit.as_str();

    let mut image = Command::new("cosign");
    image
        .args([
            "verify",
            "--certificate-identity",
            inputs.network.certificate_identity(),
            "--certificate-oidc-issuer",
            GITHUB_ACTIONS_OIDC_ISSUER,
            "--certificate-github-workflow-sha",
            workflow_sha,
        ])
        .arg(&exact_image);
    let image_output = run_output(&mut image, "cryptographically verify exact OCI image")?;
    write_canonical(
        &inputs.cosign_image_verification,
        &normalize_cosign_json_output(&image_output, "Cosign image verification")?,
    )?;

    refresh_cosign_attestation(
        inputs.network,
        &exact_image,
        workflow_sha,
        "spdxjson",
        &inputs.cosign_sbom_verification,
    )?;
    refresh_cosign_attestation(
        inputs.network,
        &exact_image,
        workflow_sha,
        "slsaprovenance02",
        &inputs.cosign_provenance_verification,
    )
}

fn refresh_cosign_attestation(
    network: SgxReleaseNetwork,
    exact_image: &str,
    workflow_sha: &str,
    predicate_type: &str,
    output: &Path,
) -> Result<()> {
    let mut command = Command::new("cosign");
    command
        .args([
            "verify-attestation",
            "--type",
            predicate_type,
            "--certificate-identity",
            network.certificate_identity(),
            "--certificate-oidc-issuer",
            GITHUB_ACTIONS_OIDC_ISSUER,
            "--certificate-github-workflow-sha",
            workflow_sha,
        ])
        .arg(exact_image);
    let value = run_output(
        &mut command,
        &format!("cryptographically verify {predicate_type} OCI attestation"),
    )?;
    write_canonical(
        output,
        &normalize_cosign_json_output(&value, "Cosign attestation")?,
    )
}

fn exact_image_reference(oci: &OciBuildEvidence) -> Result<String> {
    if oci.image_reference.contains('@') {
        bail!("OCI build evidence image reference must be a tag before digest promotion");
    }
    let slash = oci.image_reference.rfind('/').unwrap_or(0);
    let colon = oci
        .image_reference
        .rfind(':')
        .filter(|position| *position > slash)
        .ok_or_else(|| eyre!("OCI build evidence image reference lacks a release tag"))?;
    Ok(format!(
        "{}@sha256:{}",
        &oci.image_reference[..colon],
        oci.image.digest.value
    ))
}

pub fn normalize_cosign_json_output(output: &str, label: &str) -> Result<Value> {
    let mut flattened = Vec::new();
    for value in serde_json::Deserializer::from_str(output).into_iter::<Value>() {
        match value.wrap_err_with(|| format!("parse {label} JSON output"))? {
            Value::Array(values) => flattened.extend(values),
            value => flattened.push(value),
        }
    }
    if flattened.is_empty() {
        bail!("{label} emitted no JSON evidence");
    }
    Ok(Value::Array(flattened))
}

pub fn repository_root() -> Result<PathBuf> {
    let mut command = Command::new("git");
    command.args(["rev-parse", "--show-toplevel"]);
    let value = run_output(&mut command, "resolve repository root")?;
    fs::canonicalize(value.trim()).wrap_err("canonicalize repository root")
}

fn require_release_checkout(repo_root: &Path, network: SgxReleaseNetwork) -> Result<()> {
    for relative in [
        network.bundle_spec_path(),
        "scripts/release/build-sgx-bundle-in-container.sh",
        "xtask/Cargo.toml",
    ] {
        if !repo_root.join(relative).is_file() {
            bail!("repository is missing SGX release input: {relative}");
        }
    }
    Ok(())
}

fn read_elf_identity(elf_output: &Path) -> Result<SourceIdentity> {
    let manifest: Value = read_canonical_json(&elf_output.join("release-manifest.json"))?;
    let source = manifest
        .pointer("/release/source")
        .and_then(Value::as_object)
        .ok_or_else(|| eyre!("ELF manifest lacks release source identity"))?;
    if source.get("tree_state").and_then(Value::as_str) != Some("clean")
        || source.get("clean_tree_policy").and_then(Value::as_str) != Some("required")
    {
        bail!("ELF manifest does not bind a required clean tree");
    }
    let source_commit = source
        .get("commit")
        .and_then(Value::as_str)
        .ok_or_else(|| eyre!("ELF manifest lacks source commit"))?
        .to_owned();
    let source_date_epoch = manifest
        .pointer("/build/source_date_epoch")
        .and_then(Value::as_i64)
        .ok_or_else(|| eyre!("ELF manifest lacks SOURCE_DATE_EPOCH"))?;
    let release_tag = manifest
        .pointer("/release/tag")
        .and_then(Value::as_str)
        .ok_or_else(|| eyre!("ELF manifest lacks release tag"))?
        .to_owned();
    let enclave = manifest
        .get("artifacts")
        .and_then(Value::as_array)
        .and_then(|artifacts| {
            artifacts.iter().find(|artifact| {
                artifact.get("name").and_then(Value::as_str) == Some("outbe-tee-enclave")
            })
        })
        .ok_or_else(|| eyre!("ELF manifest lacks the production enclave subject"))?;
    if enclave.get("tee") != Some(&serde_json::json!({"mock": false, "stage": "unsigned-bare-elf"}))
    {
        bail!("ELF manifest lacks the production enclave subject");
    }
    let enclave_path = elf_output.join("bin/outbe-tee-enclave");
    let metadata = fs::symlink_metadata(&enclave_path)
        .wrap_err("read enclave ELF from reproducible output")?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        bail!("reproducible output contains an unsafe enclave ELF");
    }
    let expected_digest = enclave
        .pointer("/digest/value")
        .and_then(Value::as_str)
        .ok_or_else(|| eyre!("ELF manifest lacks enclave digest"))?;
    let expected_size = enclave
        .get("size")
        .and_then(Value::as_u64)
        .ok_or_else(|| eyre!("ELF manifest lacks enclave size"))?;
    if file_digest(&enclave_path)?.value != expected_digest || metadata.len() != expected_size {
        bail!("enclave ELF does not match its release manifest");
    }
    let identity = SourceIdentity {
        release_tag,
        source_commit,
        source_date_epoch,
    };
    validate_source_identity(&identity)?;
    Ok(identity)
}

fn validate_source_identity(identity: &SourceIdentity) -> Result<()> {
    if !is_lower_hex(&identity.source_commit, 40) {
        bail!("source commit must be a lowercase 40-character Git SHA");
    }
    if identity.source_date_epoch < 0 {
        bail!("SOURCE_DATE_EPOCH must be non-negative");
    }
    if identity.release_tag.is_empty() || !identity.release_tag.is_ascii() {
        bail!("release tag must be non-empty ASCII");
    }
    Ok(())
}

fn require_clean_source(repo_root: &Path, expected_commit: &str) -> Result<()> {
    let mut status = Command::new("git");
    status
        .arg("-C")
        .arg(repo_root)
        .args(["status", "--porcelain=v1", "--untracked-files=all"]);
    if !run_output(&mut status, "inspect source tree state")?.is_empty() {
        bail!("SGX release operations require a clean source tree");
    }
    let mut head = Command::new("git");
    head.arg("-C").arg(repo_root).args(["rev-parse", "HEAD"]);
    let head = run_output(&mut head, "resolve source commit")?;
    if head.trim() != expected_commit {
        bail!(
            "SGX source identity {expected_commit} does not match checkout {}",
            head.trim()
        );
    }
    Ok(())
}

fn validate_signing_key(key_file: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(key_file)
        .wrap_err_with(|| format!("read signing key metadata: {}", key_file.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        bail!("missing or unsafe SGX signing key: {}", key_file.display());
    }
    let mode = metadata.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!("unsafe SGX signing key permissions: {mode:03o}; expected no group/other access");
    }
    if metadata.len() == 0 {
        bail!("SGX signing key is empty");
    }
    Ok(())
}

fn create_empty_output(repo_root: &Path, output: &Path) -> Result<PathBuf> {
    let output = absolute_path(output)?;
    if output.starts_with(repo_root) {
        bail!("output directory must be outside the source checkout");
    }
    if output.exists() {
        if !output.is_dir() {
            bail!("output path is not a directory: {}", output.display());
        }
        if fs::read_dir(&output)
            .wrap_err("read output directory")?
            .next()
            .is_some()
        {
            bail!("output directory must be empty: {}", output.display());
        }
    } else {
        fs::create_dir_all(&output)
            .wrap_err_with(|| format!("create output directory: {}", output.display()))?;
    }
    fs::canonicalize(&output).wrap_err("canonicalize output directory")
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    let path = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()
            .wrap_err("resolve current directory")?
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => normalized.push(prefix.as_os_str()),
            Component::RootDir => normalized.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                if !normalized.pop() {
                    bail!("path escapes filesystem root: {}", path.display());
                }
            }
            Component::Normal(value) => normalized.push(value),
        }
    }
    Ok(normalized)
}

fn verify_checksums(root: &Path, name: &str) -> Result<()> {
    let checksum_path = root.join(name);
    let content = fs::read_to_string(&checksum_path)
        .wrap_err_with(|| format!("read checksums: {}", checksum_path.display()))?;
    if content.is_empty() {
        bail!("checksum file is empty: {}", checksum_path.display());
    }
    for (index, line) in content.lines().enumerate() {
        let Some((digest, relative)) = line.split_once("  ") else {
            bail!(
                "invalid checksum row {} in {}",
                index + 1,
                checksum_path.display()
            );
        };
        if !is_lower_hex(digest, 64) {
            bail!("invalid checksum digest at row {}", index + 1);
        }
        let relative = safe_relative_path(relative)?;
        let path = root.join(relative);
        let metadata = fs::symlink_metadata(&path)
            .wrap_err_with(|| format!("checksum input is missing: {}", path.display()))?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            bail!(
                "checksum input is not a safe regular file: {}",
                path.display()
            );
        }
        if file_digest(&path)?.value != digest {
            bail!("checksum mismatch: {}", path.display());
        }
    }
    Ok(())
}

fn safe_relative_path(value: &str) -> Result<&Path> {
    let path = Path::new(value);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("unsafe relative artifact path: {value}");
    }
    Ok(path)
}

fn write_checksums(root: &Path, name: &str) -> Result<()> {
    let mut rows = Vec::new();
    for item in WalkDir::new(root).min_depth(1).sort_by_file_name() {
        let item = item.wrap_err("walk output for checksums")?;
        let path = item.path();
        let relative = path
            .strip_prefix(root)
            .wrap_err("derive checksum path")?
            .to_string_lossy()
            .replace('\\', "/");
        let metadata = fs::symlink_metadata(path).wrap_err("read checksum input metadata")?;
        if metadata.file_type().is_symlink() {
            bail!("output contains symlink: {relative}");
        }
        if metadata.is_file() && relative != name {
            rows.push((relative, file_digest(path)?.value));
        }
    }
    rows.sort_by(|left, right| left.0.cmp(&right.0));
    let content = rows
        .into_iter()
        .map(|(path, digest)| format!("{digest}  {path}\n"))
        .collect::<String>();
    fs::write(root.join(name), content).wrap_err("write output checksums")
}

fn write_canonical<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .wrap_err_with(|| format!("create metadata directory: {}", parent.display()))?;
    }
    fs::write(path, canonical_json(value)?)
        .wrap_err_with(|| format!("write canonical metadata: {}", path.display()))
}

fn write_new_file(path: &Path, bytes: &[u8], label: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .wrap_err_with(|| format!("create {label} directory: {}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .wrap_err_with(|| format!("create new {label}: {}", path.display()))?;
    file.write_all(bytes)
        .and_then(|()| file.sync_all())
        .wrap_err_with(|| format!("write {label}: {}", path.display()))
}

fn read_canonical_json<T>(path: &Path) -> Result<T>
where
    T: for<'de> Deserialize<'de> + Serialize,
{
    let metadata = fs::symlink_metadata(path)
        .wrap_err_with(|| format!("read JSON metadata: {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        bail!("missing or unsafe JSON input: {}", path.display());
    }
    let bytes = fs::read(path).wrap_err_with(|| format!("read JSON input: {}", path.display()))?;
    let value: T = serde_json::from_slice(&bytes)
        .wrap_err_with(|| format!("parse JSON input: {}", path.display()))?;
    if bytes != canonical_json(&value)? {
        bail!(
            "JSON input is not canonical outbe-canonical-json-v1: {}",
            path.display()
        );
    }
    Ok(value)
}

fn normalize_tree_mtime(root: &Path, source_date_epoch: i64) -> Result<()> {
    if source_date_epoch < 0 {
        bail!("SOURCE_DATE_EPOCH must be non-negative");
    }
    let timestamp = FileTime::from_unix_time(source_date_epoch, 0);
    let mut entries = WalkDir::new(root)
        .into_iter()
        .collect::<std::result::Result<Vec<_>, _>>()
        .wrap_err("walk output for timestamp normalization")?;
    entries.sort_by_key(|entry| std::cmp::Reverse(entry.depth()));
    for entry in entries {
        let metadata = fs::symlink_metadata(entry.path()).wrap_err("read timestamp target")?;
        if metadata.file_type().is_symlink() {
            bail!(
                "cannot normalize symlink timestamp: {}",
                entry.path().display()
            );
        }
        filetime::set_file_times(entry.path(), timestamp, timestamp)
            .wrap_err_with(|| format!("normalize timestamp: {}", entry.path().display()))?;
    }
    Ok(())
}

fn build_project_toolchain_image(
    repo_root: &Path,
    spec: &BundleSpec,
    source_commit: &str,
) -> Result<String> {
    if !is_lower_hex(source_commit, 40) {
        bail!("project toolchain image requires an exact source commit");
    }
    let image = format!("outbe-project-toolchain:{source_commit}");
    let dockerfile = repo_root.join("Dockerfile.project-toolchain");
    let mut command = Command::new("docker");
    command
        .args(["build", "--platform", &spec.platform, "--file"])
        .arg(&dockerfile)
        .args(["--target", "toolchain", "--tag", &image])
        .arg(repo_root);
    run_status(&mut command, "build project toolchain image")?;
    Ok(image)
}

fn docker_command(spec: &BundleSpec, repo_root: &Path) -> Result<Command> {
    let uid = current_id("-u")?;
    let gid = current_id("-g")?;
    let mut command = Command::new("docker");
    command
        .args(["run", "--rm", "--platform", &spec.platform])
        .args(["--user", &format!("{uid}:{gid}")])
        .args(["--entrypoint", "bash"])
        .args(["-v", &format!("{}:/source:ro", repo_root.display())]);
    Ok(command)
}

fn current_id(flag: &str) -> Result<String> {
    let mut command = Command::new("id");
    command.arg(flag);
    Ok(run_output(&mut command, "resolve current Unix identity")?
        .trim()
        .to_owned())
}

fn container_adapter() -> &'static str {
    "/source/scripts/release/build-sgx-bundle-in-container.sh"
}

fn run_status(command: &mut Command, description: &str) -> Result<()> {
    let status = command
        .status()
        .wrap_err_with(|| format!("failed to start command: {description}"))?;
    if !status.success() {
        bail!("{description} failed with {status}");
    }
    Ok(())
}

fn run_output(command: &mut Command, description: &str) -> Result<String> {
    let Output {
        status,
        stdout,
        stderr,
    } = command
        .output()
        .wrap_err_with(|| format!("failed to start command: {description}"))?;
    if !status.success() {
        bail!(
            "{description} failed with {status}: {}",
            String::from_utf8_lossy(&stderr).trim()
        );
    }
    String::from_utf8(stdout).wrap_err_with(|| format!("{description} emitted non-UTF-8 output"))
}
