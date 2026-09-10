//! Durable supervisor authority for one published input manifest.
//!
//! The exporter may construct CAS objects, but they do not become computation
//! authority by existing on disk. This store binds the exact finalized job
//! journal record, local reconstruction lease, closed manifest/catalog and
//! publication receipt into one content-addressed record. A cold restart must reload
//! and revalidate the same bytes before planning or finalization.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use alloy_primitives::{keccak256, B256};
use outbe_ocomp_protocol::{
    input::{CheckpointIdentityV1, InputManifestV1},
    intent::JobIntentV1,
    profile::ProtocolBundleV1,
    CasObjectRefV1, CommitSnapshotExportV1, ObjectKind, ProtocolError, SchemaLimits,
    SnapshotExportCommittedV1,
};
use thiserror::Error;

use crate::{
    cas::{CasError, FilesystemCas, FilesystemCasReader},
    export_receipt::VerifiedExportReceipt,
    input_ref_catalog::{InputRefCatalogError, VerifiedInputChunkRefCatalog},
    supervisor::DiscoveryRecord,
};

const BINDING_MAGIC: [u8; 8] = *b"OUTBEMB1";
const LOCATOR_MAGIC: [u8; 8] = *b"OUTBEML1";
const CONFLICT_MAGIC: [u8; 8] = *b"OUTBEMC1";
const FORMAT_VERSION: u16 = 1;
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const LOCATOR_FILE: &str = "binding.ref";
const LOCATOR_TEMP_FILE: &str = "binding.ref.tmp";
const CONFLICT_FILE: &str = "binding.abstained";
const LOCK_FILE: &str = "binding.lock";
const BINDING_CHECKPOINT_OFFSET: usize = 142;
const BINDING_MANIFEST_REF_OFFSET: usize = 248;
const BINDING_MANIFEST_HASH_OFFSET: usize = 290;
const BINDING_EXPORTED_GENERATION_OFFSET: usize = 322;
const BINDING_EXPORT_RECORD_HASH_OFFSET: usize = 330;
const BINDING_CHECKSUM_OFFSET: usize = 362;
const BINDING_FIXED_BYTES: usize = BINDING_CHECKSUM_OFFSET + 32;
const LOCATOR_FIXED_BYTES: usize = 8 + 2 + 32 + 8 + 32;
const CONFLICT_FIXED_BYTES: usize = 8 + 32 + 32 + 32;

pub struct ExportBindingCandidate<'a> {
    pub discovery: &'a DiscoveryRecord,
    pub job_id: B256,
    pub source_pin_generation: u64,
    pub lease_generation: u64,
    pub checkpoint: &'a CheckpointIdentityV1,
    pub manifest_ref: &'a CasObjectRefV1,
    pub committed: &'a SnapshotExportCommittedV1,
    pub bundle: &'a ProtocolBundleV1,
    pub input_refs: &'a VerifiedInputChunkRefCatalog,
}

pub struct ExportReceiptBindingCandidate<'a> {
    pub discovery: &'a DiscoveryRecord,
    pub receipt: &'a VerifiedExportReceipt,
    pub bundle: &'a ProtocolBundleV1,
    pub input_refs: &'a VerifiedInputChunkRefCatalog,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExportBindingSealOutcome {
    NewlySealed,
    ExactReplay,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExportedManifestBindingV1 {
    discovery_generation: u64,
    finalized_cursor: u64,
    finalized_job_spec_hash: B256,
    job_id: B256,
    attempt: u32,
    protocol_bundle_hash: B256,
    source_pin_generation: u64,
    lease_generation: u64,
    checkpoint: CheckpointIdentityV1,
    manifest_ref: CasObjectRefV1,
    manifest_hash: B256,
    exported_pin_generation: u64,
    export_record_hash: B256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedExportedManifestBinding {
    binding_ref: CasObjectRefV1,
    binding: ExportedManifestBindingV1,
    manifest: InputManifestV1,
}

impl VerifiedExportedManifestBinding {
    #[must_use]
    pub fn binding_ref(&self) -> CasObjectRefV1 {
        self.binding_ref.clone()
    }

    #[must_use]
    pub fn manifest_ref(&self) -> CasObjectRefV1 {
        self.binding.manifest_ref.clone()
    }

    #[must_use]
    pub const fn manifest(&self) -> &InputManifestV1 {
        &self.manifest
    }

    #[must_use]
    pub const fn job_id(&self) -> B256 {
        self.binding.job_id
    }

    #[must_use]
    pub const fn export_record_hash(&self) -> B256 {
        self.binding.export_record_hash
    }

    #[must_use]
    pub fn commit_replay_request(&self) -> CommitSnapshotExportV1 {
        CommitSnapshotExportV1 {
            job_id: self.binding.job_id,
            pin_generation: self.binding.source_pin_generation,
            lease_generation: self.binding.lease_generation,
            manifest_hash: self.binding.manifest_hash,
        }
    }

    pub fn require_exact_node_replay(
        &self,
        replayed: &SnapshotExportCommittedV1,
    ) -> Result<(), ExportBindingError> {
        require(replayed.job_id == self.binding.job_id, "node replay job id")?;
        require(
            replayed.pin_generation == self.binding.exported_pin_generation,
            "node replay exported pin generation",
        )?;
        require(
            replayed.record_hash == self.binding.export_record_hash,
            "node replay record hash",
        )
    }
}

pub struct ExportedManifestBindingStore {
    root: PathBuf,
    limits: SchemaLimits,
    abstained: bool,
    _lock: BindingLock,
}

impl ExportedManifestBindingStore {
    pub fn open(root: impl AsRef<Path>, limits: SchemaLimits) -> Result<Self, ExportBindingError> {
        let root = root.as_ref().to_path_buf();
        create_private_directory(&root)?;
        let lock = BindingLock::acquire(&root)?;
        if path_exists(&root.join(LOCATOR_TEMP_FILE))? {
            return Err(ExportBindingError::AmbiguousTemporary(
                root.join(LOCATOR_TEMP_FILE),
            ));
        }
        inspect_known_entries(&root)?;
        let abstained = path_exists(&root.join(CONFLICT_FILE))?;
        Ok(Self {
            root,
            limits,
            abstained,
            _lock: lock,
        })
    }

    pub fn seal(
        &mut self,
        cas: &FilesystemCas,
        reader: &FilesystemCasReader,
        candidate: ExportBindingCandidate<'_>,
    ) -> Result<(ExportBindingSealOutcome, VerifiedExportedManifestBinding), ExportBindingError>
    {
        self.require_active()?;
        let binding = derive_binding(reader, &candidate, &self.limits)?;
        let canonical = encode_binding(&binding);
        let binding_ref = cas.publish_bytes(&canonical)?;
        require(
            binding_ref.expected_ocb1_kind.is_none(),
            "local export binding CAS kind",
        )?;
        let published = reader.read_verified(&binding_ref)?;
        require(
            published.bytes() == canonical,
            "supervisor reads the exact published binding",
        )?;

        let locator_path = self.root.join(LOCATOR_FILE);
        if path_exists(&locator_path)? {
            let existing_ref = decode_locator(&read_bounded(&locator_path, LOCATOR_FIXED_BYTES)?)?;
            if existing_ref != binding_ref {
                self.latch_conflict(existing_ref.transport_digest, binding_ref.transport_digest)?;
                return Err(ExportBindingError::ConflictingBinding);
            }
            let verified = self.load_exact(
                reader,
                candidate.discovery,
                candidate.bundle,
                candidate.input_refs,
            )?;
            require(verified.binding == binding, "exact export binding replay")?;
            return Ok((ExportBindingSealOutcome::ExactReplay, verified));
        }

        persist_atomic(
            &self.root,
            &self.root.join(LOCATOR_TEMP_FILE),
            &locator_path,
            &encode_locator(&binding_ref)?,
        )?;
        let verified = self.load_exact(
            reader,
            candidate.discovery,
            candidate.bundle,
            candidate.input_refs,
        )?;
        Ok((ExportBindingSealOutcome::NewlySealed, verified))
    }

    pub fn seal_receipt(
        &mut self,
        cas: &FilesystemCas,
        reader: &FilesystemCasReader,
        candidate: ExportReceiptBindingCandidate<'_>,
    ) -> Result<(ExportBindingSealOutcome, VerifiedExportedManifestBinding), ExportBindingError>
    {
        let manifest_ref = candidate.receipt.manifest_ref();
        let committed = candidate.receipt.committed();
        self.seal(
            cas,
            reader,
            ExportBindingCandidate {
                discovery: candidate.discovery,
                job_id: candidate.receipt.job_id(),
                source_pin_generation: candidate.receipt.source_pin_generation(),
                lease_generation: candidate.receipt.lease_generation(),
                checkpoint: candidate.receipt.checkpoint(),
                manifest_ref: &manifest_ref,
                committed: &committed,
                bundle: candidate.bundle,
                input_refs: candidate.input_refs,
            },
        )
    }

    pub fn load_exact(
        &self,
        reader: &FilesystemCasReader,
        discovery: &DiscoveryRecord,
        bundle: &ProtocolBundleV1,
        input_refs: &VerifiedInputChunkRefCatalog,
    ) -> Result<VerifiedExportedManifestBinding, ExportBindingError> {
        self.require_active()?;
        inspect_known_entries(&self.root)?;
        let locator_path = self.root.join(LOCATOR_FILE);
        if !path_exists(&locator_path)? {
            return Err(ExportBindingError::MissingBinding);
        }
        let binding_ref = decode_locator(&read_bounded(&locator_path, LOCATOR_FIXED_BYTES)?)?;
        let binding_object = reader.read_verified(&binding_ref)?;
        let binding = decode_binding(binding_object.bytes())?;
        require(
            encode_binding(&binding) == binding_object.bytes(),
            "canonical export binding encoding",
        )?;
        let manifest_object = reader.read_verified(&binding.manifest_ref)?;
        require(
            binding.manifest_ref.expected_ocb1_kind == Some(ObjectKind::InputManifestV1.tag()),
            "typed input manifest reference",
        )?;
        let manifest = InputManifestV1::decode_canonical(manifest_object.bytes(), &self.limits)?;
        manifest.validate_against_bundle(bundle, &self.limits)?;
        validate_binding_authority(&binding, discovery, &manifest, &self.limits)?;
        validate_closed_input_catalog(
            input_refs,
            reader,
            bundle,
            &binding.manifest_ref,
            &manifest,
        )?;
        Ok(VerifiedExportedManifestBinding {
            binding_ref,
            binding,
            manifest,
        })
    }

    fn require_active(&self) -> Result<(), ExportBindingError> {
        if self.abstained || path_exists(&self.root.join(CONFLICT_FILE))? {
            Err(ExportBindingError::Abstained)
        } else {
            Ok(())
        }
    }

    fn latch_conflict(
        &mut self,
        existing: B256,
        candidate: B256,
    ) -> Result<(), ExportBindingError> {
        let path = self.root.join(CONFLICT_FILE);
        if !path_exists(&path)? {
            let mut encoded = Vec::with_capacity(CONFLICT_FIXED_BYTES);
            encoded.extend_from_slice(&CONFLICT_MAGIC);
            encoded.extend_from_slice(existing.as_slice());
            encoded.extend_from_slice(candidate.as_slice());
            encoded.extend_from_slice(keccak256(&encoded).as_slice());
            persist_new(&self.root, &path, &encoded)?;
        }
        self.abstained = true;
        Ok(())
    }
}

fn derive_binding(
    reader: &FilesystemCasReader,
    candidate: &ExportBindingCandidate<'_>,
    limits: &SchemaLimits,
) -> Result<ExportedManifestBindingV1, ExportBindingError> {
    let manifest_object = reader.read_verified(candidate.manifest_ref)?;
    require(
        candidate.manifest_ref.expected_ocb1_kind == Some(ObjectKind::InputManifestV1.tag()),
        "typed input manifest reference",
    )?;
    let manifest = InputManifestV1::decode_canonical(manifest_object.bytes(), limits)?;
    manifest.validate_against_bundle(candidate.bundle, limits)?;
    validate_closed_input_catalog(
        candidate.input_refs,
        reader,
        candidate.bundle,
        candidate.manifest_ref,
        &manifest,
    )?;

    let spec_bytes = candidate.discovery.spec.encode_body(limits)?;
    let intent =
        JobIntentV1::decode_canonical(&candidate.discovery.spec.canonical_job_intent.0, limits)?;
    validate_manifest_job_authority(
        candidate.discovery,
        &intent,
        candidate.job_id,
        candidate.source_pin_generation,
        candidate.lease_generation,
        candidate.checkpoint,
        &manifest,
    )?;
    let manifest_hash = manifest.manifest_hash(limits)?;
    require(
        candidate.committed.job_id == manifest.job_id,
        "export commit job id",
    )?;
    require(
        candidate.committed.pin_generation
            == candidate
                .source_pin_generation
                .checked_add(1)
                .ok_or(ExportBindingError::IntegerOverflow)?,
        "exported pin generation",
    )?;
    require(
        !candidate.committed.record_hash.is_zero(),
        "export commit record hash",
    )?;

    Ok(ExportedManifestBindingV1 {
        discovery_generation: candidate.discovery.generation,
        finalized_cursor: candidate.discovery.cursor,
        finalized_job_spec_hash: keccak256(spec_bytes),
        job_id: manifest.job_id,
        attempt: manifest.attempt,
        protocol_bundle_hash: manifest.protocol_bundle_hash,
        source_pin_generation: candidate.source_pin_generation,
        lease_generation: candidate.lease_generation,
        checkpoint: manifest.checkpoint.clone(),
        manifest_ref: candidate.manifest_ref.clone(),
        manifest_hash,
        exported_pin_generation: candidate.committed.pin_generation,
        export_record_hash: candidate.committed.record_hash,
    })
}

fn validate_binding_authority(
    binding: &ExportedManifestBindingV1,
    discovery: &DiscoveryRecord,
    manifest: &InputManifestV1,
    limits: &SchemaLimits,
) -> Result<(), ExportBindingError> {
    let intent = JobIntentV1::decode_canonical(&discovery.spec.canonical_job_intent.0, limits)?;
    // `discovery_generation` belongs to the legacy single-current local
    // journal. It is retained for decoding old local artifacts, but it is not
    // authority in the embedded multi-job path. The exact finalized cursor and
    // full spec hash below bind this receipt more strongly and independently of
    // local discovery order.
    require(
        binding.finalized_cursor == discovery.cursor,
        "finalized cursor",
    )?;
    require(
        binding.finalized_job_spec_hash == keccak256(discovery.spec.encode_body(limits)?),
        "finalized job spec hash",
    )?;
    require(binding.job_id == manifest.job_id, "binding manifest job id")?;
    require(binding.attempt == manifest.attempt, "binding attempt")?;
    require(
        binding.protocol_bundle_hash == manifest.protocol_bundle_hash,
        "binding protocol bundle",
    )?;
    require(
        binding.checkpoint == manifest.checkpoint,
        "binding checkpoint",
    )?;
    require(
        binding.manifest_hash == manifest.manifest_hash(limits)?,
        "binding manifest hash",
    )?;
    require(
        binding.manifest_ref.expected_ocb1_kind == Some(ObjectKind::InputManifestV1.tag()),
        "binding manifest kind",
    )?;
    require(
        binding.source_pin_generation != 0
            && binding.lease_generation != 0
            && binding.exported_pin_generation
                == binding
                    .source_pin_generation
                    .checked_add(1)
                    .ok_or(ExportBindingError::IntegerOverflow)?
            && !binding.export_record_hash.is_zero(),
        "binding export generations and record",
    )?;
    validate_manifest_job_fields(discovery, &intent, manifest)
}

fn validate_manifest_job_authority(
    discovery: &DiscoveryRecord,
    intent: &JobIntentV1,
    job_id: B256,
    source_pin_generation: u64,
    lease_generation: u64,
    checkpoint: &CheckpointIdentityV1,
    manifest: &InputManifestV1,
) -> Result<(), ExportBindingError> {
    require(
        job_id == discovery.spec.summary.job_id,
        "snapshot handoff job id",
    )?;
    require(
        source_pin_generation != 0 && lease_generation != 0,
        "snapshot handoff generations",
    )?;
    require(
        checkpoint == &manifest.checkpoint,
        "snapshot handoff checkpoint",
    )?;
    validate_manifest_job_fields(discovery, intent, manifest)
}

fn validate_manifest_job_fields(
    discovery: &DiscoveryRecord,
    intent: &JobIntentV1,
    manifest: &InputManifestV1,
) -> Result<(), ExportBindingError> {
    let summary = &discovery.spec.summary;
    require(discovery.cursor == summary.cursor, "discovery cursor")?;
    require(manifest.job_id == summary.job_id, "manifest job id")?;
    require(
        manifest.protocol_bundle_hash == summary.protocol_bundle_hash
            && manifest.protocol_bundle_hash == intent.protocol_bundle_hash,
        "manifest protocol bundle",
    )?;
    require(manifest.attempt == intent.attempt, "manifest attempt")?;
    require(manifest.wwd == intent.wwd, "manifest WWD")?;
    require(
        manifest.sealed_tribute_collection_key == intent.sealed_tribute_collection_key,
        "manifest Tribute collection key",
    )?;
    require(
        manifest.sealed_tribute_collection_root == intent.sealed_tribute_collection_root,
        "manifest Tribute collection root",
    )?;
    require(
        manifest.tribute_count == intent.authenticated_day_count,
        "manifest Tribute count",
    )?;
    require(
        manifest.tribute_nominal_total == intent.authenticated_day_nominal,
        "manifest Tribute nominal total",
    )?;
    require(
        manifest.checkpoint.finalized_block_hash == summary.finalized_block_hash,
        "manifest finalized block hash",
    )?;
    require(
        manifest.checkpoint.finalized_state_root == summary.finalized_state_root,
        "manifest finalized state root",
    )?;
    require(
        manifest.checkpoint.finalized_ce_root == intent.ce_sealed_root,
        "manifest finalized CE root",
    )
}

fn validate_closed_input_catalog(
    input_refs: &VerifiedInputChunkRefCatalog,
    reader: &FilesystemCasReader,
    bundle: &ProtocolBundleV1,
    manifest_ref: &CasObjectRefV1,
    manifest: &InputManifestV1,
) -> Result<(), ExportBindingError> {
    input_refs.require_manifest_authority(manifest_ref, manifest)?;
    for reference in input_refs.exact_verified_cursor(reader, bundle)? {
        let _ = reference?;
    }
    Ok(())
}

fn encode_binding(binding: &ExportedManifestBindingV1) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(BINDING_FIXED_BYTES);
    encoded.extend_from_slice(&BINDING_MAGIC);
    encoded.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    encoded.extend_from_slice(&binding.discovery_generation.to_be_bytes());
    encoded.extend_from_slice(&binding.finalized_cursor.to_be_bytes());
    encoded.extend_from_slice(binding.finalized_job_spec_hash.as_slice());
    encoded.extend_from_slice(binding.job_id.as_slice());
    encoded.extend_from_slice(&binding.attempt.to_be_bytes());
    encoded.extend_from_slice(binding.protocol_bundle_hash.as_slice());
    encoded.extend_from_slice(&binding.source_pin_generation.to_be_bytes());
    encoded.extend_from_slice(&binding.lease_generation.to_be_bytes());
    encode_checkpoint(&mut encoded, &binding.checkpoint);
    encoded.extend_from_slice(binding.manifest_ref.transport_digest.as_slice());
    encoded.extend_from_slice(&binding.manifest_ref.encoded_bytes.to_be_bytes());
    encoded.extend_from_slice(
        &binding
            .manifest_ref
            .expected_ocb1_kind
            .unwrap_or_default()
            .to_be_bytes(),
    );
    encoded.extend_from_slice(binding.manifest_hash.as_slice());
    encoded.extend_from_slice(&binding.exported_pin_generation.to_be_bytes());
    encoded.extend_from_slice(binding.export_record_hash.as_slice());
    encoded.extend_from_slice(keccak256(&encoded).as_slice());
    encoded
}

fn decode_binding(encoded: &[u8]) -> Result<ExportedManifestBindingV1, ExportBindingError> {
    if encoded.len() != BINDING_FIXED_BYTES
        || encoded[..8] != BINDING_MAGIC
        || read_u16(encoded, 8)? != FORMAT_VERSION
    {
        return Err(ExportBindingError::InvalidEnvelope);
    }
    if keccak256(&encoded[..BINDING_CHECKSUM_OFFSET])
        != B256::from_slice(&encoded[BINDING_CHECKSUM_OFFSET..])
    {
        return Err(ExportBindingError::InvalidEnvelope);
    }
    let checkpoint = CheckpointIdentityV1 {
        finalized_block_number: read_u64(encoded, BINDING_CHECKPOINT_OFFSET)?,
        finalized_block_hash: read_b256(encoded, BINDING_CHECKPOINT_OFFSET + 8)?,
        finalized_state_root: read_b256(encoded, BINDING_CHECKPOINT_OFFSET + 40)?,
        finalized_ce_root: read_b256(encoded, BINDING_CHECKPOINT_OFFSET + 72)?,
        ce_schema_version: read_u16(encoded, BINDING_CHECKPOINT_OFFSET + 104)?,
    };
    let expected_kind = read_u16(encoded, BINDING_MANIFEST_REF_OFFSET + 40)?;
    if expected_kind == 0 {
        return Err(ExportBindingError::InvalidEnvelope);
    }
    let binding = ExportedManifestBindingV1 {
        discovery_generation: read_u64(encoded, 10)?,
        finalized_cursor: read_u64(encoded, 18)?,
        finalized_job_spec_hash: read_b256(encoded, 26)?,
        job_id: read_b256(encoded, 58)?,
        attempt: read_u32(encoded, 90)?,
        protocol_bundle_hash: read_b256(encoded, 94)?,
        source_pin_generation: read_u64(encoded, 126)?,
        lease_generation: read_u64(encoded, 134)?,
        checkpoint,
        manifest_ref: CasObjectRefV1 {
            transport_digest: read_b256(encoded, BINDING_MANIFEST_REF_OFFSET)?,
            encoded_bytes: read_u64(encoded, BINDING_MANIFEST_REF_OFFSET + 32)?,
            expected_ocb1_kind: Some(expected_kind),
        },
        manifest_hash: read_b256(encoded, BINDING_MANIFEST_HASH_OFFSET)?,
        exported_pin_generation: read_u64(encoded, BINDING_EXPORTED_GENERATION_OFFSET)?,
        export_record_hash: read_b256(encoded, BINDING_EXPORT_RECORD_HASH_OFFSET)?,
    };
    require(
        binding.discovery_generation != 0
            && binding.finalized_cursor != 0
            && !binding.finalized_job_spec_hash.is_zero()
            && !binding.job_id.is_zero()
            && !binding.protocol_bundle_hash.is_zero()
            && binding.source_pin_generation != 0
            && binding.lease_generation != 0
            && !binding.manifest_ref.transport_digest.is_zero()
            && binding.manifest_ref.encoded_bytes != 0
            && !binding.manifest_hash.is_zero()
            && binding.exported_pin_generation != 0
            && !binding.export_record_hash.is_zero(),
        "export binding non-zero fields",
    )?;
    Ok(binding)
}

fn encode_checkpoint(output: &mut Vec<u8>, checkpoint: &CheckpointIdentityV1) {
    output.extend_from_slice(&checkpoint.finalized_block_number.to_be_bytes());
    output.extend_from_slice(checkpoint.finalized_block_hash.as_slice());
    output.extend_from_slice(checkpoint.finalized_state_root.as_slice());
    output.extend_from_slice(checkpoint.finalized_ce_root.as_slice());
    output.extend_from_slice(&checkpoint.ce_schema_version.to_be_bytes());
}

fn encode_locator(reference: &CasObjectRefV1) -> Result<Vec<u8>, ExportBindingError> {
    require(
        reference.expected_ocb1_kind.is_none()
            && !reference.transport_digest.is_zero()
            && reference.encoded_bytes != 0,
        "export binding locator reference",
    )?;
    let mut encoded = Vec::with_capacity(LOCATOR_FIXED_BYTES);
    encoded.extend_from_slice(&LOCATOR_MAGIC);
    encoded.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    encoded.extend_from_slice(reference.transport_digest.as_slice());
    encoded.extend_from_slice(&reference.encoded_bytes.to_be_bytes());
    encoded.extend_from_slice(keccak256(&encoded).as_slice());
    Ok(encoded)
}

fn decode_locator(encoded: &[u8]) -> Result<CasObjectRefV1, ExportBindingError> {
    if encoded.len() != LOCATOR_FIXED_BYTES
        || encoded[..8] != LOCATOR_MAGIC
        || read_u16(encoded, 8)? != FORMAT_VERSION
        || keccak256(&encoded[..50]) != B256::from_slice(&encoded[50..])
    {
        return Err(ExportBindingError::InvalidEnvelope);
    }
    let reference = CasObjectRefV1 {
        transport_digest: read_b256(encoded, 10)?,
        encoded_bytes: read_u64(encoded, 42)?,
        expected_ocb1_kind: None,
    };
    require(
        !reference.transport_digest.is_zero() && reference.encoded_bytes != 0,
        "export binding locator",
    )?;
    Ok(reference)
}

fn read_bounded(path: &Path, cap: usize) -> Result<Vec<u8>, ExportBindingError> {
    let mut file = open_regular_nofollow(path)?;
    let len = usize::try_from(
        file.metadata()
            .map_err(|source| io_error("stat file", path, source))?
            .len(),
    )
    .map_err(|_| ExportBindingError::InvalidEnvelope)?;
    if len > cap {
        return Err(ExportBindingError::InvalidEnvelope);
    }
    let mut encoded = Vec::with_capacity(len);
    file.read_to_end(&mut encoded)
        .map_err(|source| io_error("read file", path, source))?;
    if encoded.len() != len {
        return Err(ExportBindingError::InvalidEnvelope);
    }
    Ok(encoded)
}

fn create_private_directory(path: &Path) -> Result<(), ExportBindingError> {
    fs::create_dir_all(path).map_err(|source| io_error("create directory", path, source))?;
    let metadata =
        fs::symlink_metadata(path).map_err(|source| io_error("inspect directory", path, source))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(ExportBindingError::UnsafePath(path.to_path_buf()));
    }
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(DIRECTORY_MODE))
        .map_err(|source| io_error("set directory permissions", path, source))
}

fn inspect_known_entries(root: &Path) -> Result<(), ExportBindingError> {
    for entry in fs::read_dir(root).map_err(|source| io_error("list directory", root, source))? {
        let entry = entry.map_err(|source| io_error("read directory", root, source))?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| ExportBindingError::UnsafePath(entry.path()))?;
        if !matches!(
            name.as_str(),
            LOCATOR_FILE | LOCATOR_TEMP_FILE | CONFLICT_FILE | LOCK_FILE
        ) {
            return Err(ExportBindingError::UnexpectedEntry(entry.path()));
        }
        let metadata = entry
            .metadata()
            .map_err(|source| io_error("inspect entry", &entry.path(), source))?;
        if !metadata.file_type().is_file() {
            return Err(ExportBindingError::UnsafePath(entry.path()));
        }
    }
    Ok(())
}

fn path_exists(path: &Path) -> Result<bool, ExportBindingError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() && !metadata.file_type().is_symlink() => {
            Ok(true)
        }
        Ok(_) => Err(ExportBindingError::UnsafePath(path.to_path_buf())),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error("stat path", path, source)),
    }
}

fn open_regular_nofollow(path: &Path) -> Result<File, ExportBindingError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_error("open file", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect file", path, source))?;
    if !metadata.file_type().is_file() {
        return Err(ExportBindingError::UnsafePath(path.to_path_buf()));
    }
    Ok(file)
}

fn persist_atomic(
    root: &Path,
    temp: &Path,
    final_path: &Path,
    encoded: &[u8],
) -> Result<(), ExportBindingError> {
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(temp)
            .map_err(|source| io_error("create temporary file", temp, source))?;
        file.write_all(encoded)
            .map_err(|source| io_error("write temporary file", temp, source))?;
        file.sync_all()
            .map_err(|source| io_error("fsync temporary file", temp, source))?;
        fs::rename(temp, final_path)
            .map_err(|source| io_error("publish file", final_path, source))?;
        sync_directory(root)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

fn persist_new(root: &Path, path: &Path, encoded: &[u8]) -> Result<(), ExportBindingError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_error("create file", path, source))?;
    file.write_all(encoded)
        .map_err(|source| io_error("write file", path, source))?;
    file.sync_all()
        .map_err(|source| io_error("fsync file", path, source))?;
    sync_directory(root)
}

fn sync_directory(path: &Path) -> Result<(), ExportBindingError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("fsync directory", path, source))
}

fn read_u16(encoded: &[u8], start: usize) -> Result<u16, ExportBindingError> {
    Ok(u16::from_be_bytes(
        encoded
            .get(start..start + 2)
            .ok_or(ExportBindingError::InvalidEnvelope)?
            .try_into()
            .map_err(|_| ExportBindingError::InvalidEnvelope)?,
    ))
}

fn read_u32(encoded: &[u8], start: usize) -> Result<u32, ExportBindingError> {
    Ok(u32::from_be_bytes(
        encoded
            .get(start..start + 4)
            .ok_or(ExportBindingError::InvalidEnvelope)?
            .try_into()
            .map_err(|_| ExportBindingError::InvalidEnvelope)?,
    ))
}

fn read_u64(encoded: &[u8], start: usize) -> Result<u64, ExportBindingError> {
    Ok(u64::from_be_bytes(
        encoded
            .get(start..start + 8)
            .ok_or(ExportBindingError::InvalidEnvelope)?
            .try_into()
            .map_err(|_| ExportBindingError::InvalidEnvelope)?,
    ))
}

fn read_b256(encoded: &[u8], start: usize) -> Result<B256, ExportBindingError> {
    let bytes = encoded
        .get(start..start + 32)
        .ok_or(ExportBindingError::InvalidEnvelope)?;
    Ok(B256::from_slice(bytes))
}

fn require(condition: bool, what: &'static str) -> Result<(), ExportBindingError> {
    if condition {
        Ok(())
    } else {
        Err(ExportBindingError::AuthorityMismatch(what))
    }
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> ExportBindingError {
    ExportBindingError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

struct BindingLock {
    file: File,
}

impl BindingLock {
    #[allow(unsafe_code)]
    fn acquire(root: &Path) -> Result<Self, ExportBindingError> {
        let path = root.join(LOCK_FILE);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(FILE_MODE)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|source| io_error("open binding lock", &path, source))?;
        // SAFETY: `file` owns a live descriptor for the complete flock call.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(ExportBindingError::LockHeld(path));
        }
        Ok(Self { file })
    }
}

impl Drop for BindingLock {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: `self.file` remains open for the complete flock call.
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[derive(Debug, Error)]
pub enum ExportBindingError {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    Cas(#[from] CasError),
    #[error(transparent)]
    InputCatalog(#[from] InputRefCatalogError),
    #[error("export binding authority mismatch: {0}")]
    AuthorityMismatch(&'static str),
    #[error("export binding integer overflow")]
    IntegerOverflow,
    #[error("export binding is missing")]
    MissingBinding,
    #[error("a different export binding was observed; this domain must abstain")]
    ConflictingBinding,
    #[error("export binding store is permanently abstained")]
    Abstained,
    #[error("export binding envelope is malformed")]
    InvalidEnvelope,
    #[error("export binding store contains an ambiguous temporary file at {0}")]
    AmbiguousTemporary(PathBuf),
    #[error("export binding store contains an unexpected entry at {0}")]
    UnexpectedEntry(PathBuf),
    #[error("export binding path is unsafe: {0}")]
    UnsafePath(PathBuf),
    #[error("export binding store lock is already held at {0}")]
    LockHeld(PathBuf),
    #[error("export binding I/O failed while trying to {operation} at {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> ExportedManifestBindingV1 {
        ExportedManifestBindingV1 {
            discovery_generation: 7,
            finalized_cursor: 11,
            finalized_job_spec_hash: B256::repeat_byte(0x11),
            job_id: B256::repeat_byte(0x12),
            attempt: 0,
            protocol_bundle_hash: B256::repeat_byte(0x13),
            source_pin_generation: 5,
            lease_generation: 9,
            checkpoint: CheckpointIdentityV1 {
                finalized_block_number: 101,
                finalized_block_hash: B256::repeat_byte(0x14),
                finalized_state_root: B256::repeat_byte(0x15),
                finalized_ce_root: B256::repeat_byte(0x16),
                ce_schema_version: 2,
            },
            manifest_ref: CasObjectRefV1 {
                transport_digest: B256::repeat_byte(0x17),
                encoded_bytes: 1234,
                expected_ocb1_kind: Some(ObjectKind::InputManifestV1.tag()),
            },
            manifest_hash: B256::repeat_byte(0x18),
            exported_pin_generation: 6,
            export_record_hash: B256::repeat_byte(0x19),
        }
    }

    #[test]
    fn export_binding_fixed_encoding_round_trips_every_authority_field() {
        let expected = binding();
        let encoded = encode_binding(&expected);
        assert_eq!(encoded.len(), BINDING_FIXED_BYTES);
        assert_eq!(decode_binding(&encoded).unwrap(), expected);

        let mut changed = encoded;
        changed[BINDING_MANIFEST_HASH_OFFSET] ^= 1;
        assert!(matches!(
            decode_binding(&changed),
            Err(ExportBindingError::InvalidEnvelope)
        ));
    }
}
