//! Direct, restart-safe construction of proof-backed NOD materialization batches.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use alloy_primitives::B256;
use outbe_lysis::program_v1::{
    planner::{LysisPlanTopologyV1, PlannedUnitPositionV1, PRIMARY_WORK_SHARD_SIZE},
    result::{decode_root_reduce_output, LysisListSubtreeCarrierV1, RootReduceOutputV1},
};
use outbe_ocomp_protocol::{
    list::{leaf_hash, node_hash, pad_hash},
    nod_materialization::{NodMaterializationBatchV1, NodMaterializationHeadV1},
    result::NodActionV1,
    unit::UnitPhase,
    CasObjectRefV1, ListKind, ProtocolError,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    lysis_plan_audit::{ExactLysisPlanError, LocalLysisPlanAuditV1},
    lysis_result_catalog::{verified_result_chunk_at, LysisResultCatalogError},
};

const REFERENCE_VERSION: u16 = 1;
const REFERENCE_SUFFIX: &str = ".materialization-refs-v1.json";
const TEMP_SUFFIX: &str = ".tmp";
const MAX_REFERENCE_FILE_BYTES: u64 = 128 * 1024;
const MAX_DEPENDENCY_COUNT: usize = 64;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuiltNodMaterializationBatchV1 {
    pub batch: NodMaterializationBatchV1,
    pub dependencies: Vec<CasObjectRefV1>,
}

pub fn build_nod_materialization_batch(
    audit: &LocalLysisPlanAuditV1<'_>,
    head: &NodMaterializationHeadV1,
    configured_subtree_height: u8,
) -> Result<NodMaterializationBatchV1, NodMaterializationBuildErrorV1> {
    Ok(
        build_nod_materialization_batch_with_references(audit, head, configured_subtree_height)?
            .batch,
    )
}

pub fn build_nod_materialization_batch_with_references(
    audit: &LocalLysisPlanAuditV1<'_>,
    head: &NodMaterializationHeadV1,
    configured_subtree_height: u8,
) -> Result<BuiltNodMaterializationBatchV1, NodMaterializationBuildErrorV1> {
    if head.job_id != audit.plan().job_id
        || head.program_semantics_hash != audit.bundle().bundle().lysis_program_semantics_hash
        || head.worldwide_day != audit.plan().wwd
        || head.nod_count != audit.plan().tribute_count
        || head.next_nod_ordinal >= head.nod_count
    {
        return Err(NodMaterializationBuildErrorV1::AuthorityMismatch);
    }
    let padded_count =
        head.nod_count
            .checked_next_power_of_two()
            .ok_or(ProtocolError::IntegerOverflow {
                what: "materialization padded NOD count",
            })?;
    let tree_height = padded_count.trailing_zeros() as u16;
    let effective_height = configured_subtree_height.min(tree_height as u8);
    let capacity =
        1_u32
            .checked_shl(u32::from(effective_height))
            .ok_or(ProtocolError::IntegerOverflow {
                what: "materialization batch capacity",
            })?;
    if capacity == 0 || capacity > PRIMARY_WORK_SHARD_SIZE {
        return Err(ProtocolError::InvalidInvariant("materialization batch capacity").into());
    }

    let chunk_ordinal = head.next_nod_ordinal / PRIMARY_WORK_SHARD_SIZE;
    let chunk = verified_result_chunk_at(audit, chunk_ordinal)?;
    let page_start = chunk_ordinal.checked_mul(PRIMARY_WORK_SHARD_SIZE).ok_or(
        ProtocolError::IntegerOverflow {
            what: "materialization page start",
        },
    )?;
    let local_start =
        head.next_nod_ordinal
            .checked_sub(page_start)
            .ok_or(ProtocolError::InvalidInvariant(
                "materialization chunk cursor",
            ))?;
    let action_count = head
        .nod_count
        .checked_sub(head.next_nod_ordinal)
        .ok_or(ProtocolError::InvalidInvariant(
            "materialization remaining NOD count",
        ))?
        .min(capacity);
    let local_end =
        local_start
            .checked_add(action_count)
            .ok_or(ProtocolError::IntegerOverflow {
                what: "materialization page end",
            })?;
    let actions = chunk
        .chunk()
        .ordered_nod_actions
        .get(local_start as usize..local_end as usize)
        .ok_or(NodMaterializationBuildErrorV1::MissingActions)?
        .to_vec();
    require_action_ordinals(&actions, head.next_nod_ordinal, head.worldwide_day)?;

    let page_height = tree_height.min(PRIMARY_WORK_SHARD_SIZE.trailing_zeros() as u16);
    let page_capacity =
        1_u32
            .checked_shl(u32::from(page_height))
            .ok_or(ProtocolError::IntegerOverflow {
                what: "materialization page capacity",
            })?;
    let mut levels = vec![Vec::<B256>::new(); usize::from(page_height) + 1];
    levels[0].reserve(page_capacity as usize);
    for offset in 0..page_capacity {
        let ordinal = page_start
            .checked_add(offset)
            .ok_or(ProtocolError::IntegerOverflow {
                what: "materialization page ordinal",
            })?;
        let local = offset as usize;
        if let Some(action) = chunk.chunk().ordered_nod_actions.get(local) {
            if action.raw_ordinal != ordinal || action.wwd != head.worldwide_day {
                return Err(NodMaterializationBuildErrorV1::ActionOrder);
            }
            levels[0].push(leaf_hash(
                ListKind::NodActions,
                ordinal,
                &action.encode_canonical_record(audit.limits())?,
            )?);
        } else {
            levels[0].push(pad_hash(ListKind::NodActions, ordinal)?);
        }
    }
    for level in 1..=page_height {
        let previous = levels[usize::from(level - 1)].clone();
        let mut parents = Vec::with_capacity(previous.len() / 2);
        let global_start = page_start >> level;
        for (index, pair) in previous.chunks_exact(2).enumerate() {
            let global_index = global_start
                .checked_add(
                    u32::try_from(index).map_err(|_| ProtocolError::IntegerOverflow {
                        what: "materialization page node index",
                    })?,
                )
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "materialization page node index",
                })?;
            parents.push(node_hash(
                ListKind::NodActions,
                level,
                global_index,
                pair[0],
                pair[1],
            )?);
        }
        levels[usize::from(level)] = parents;
    }

    let mut root_path = Vec::with_capacity(usize::from(tree_height - u16::from(effective_height)));
    for child_level in u16::from(effective_height)..page_height {
        let local_index = (local_start >> child_level) as usize;
        root_path.push(
            *levels[usize::from(child_level)]
                .get(local_index ^ 1)
                .ok_or(NodMaterializationBuildErrorV1::MissingSibling)?,
        );
    }

    let topology = LysisPlanTopologyV1::new(audit.plan().primary_work_unit_count)?;
    let mut dependencies = vec![
        chunk.producer_artifact_ref().clone(),
        chunk.output_manifest_entry().result_chunk_ref.clone(),
    ];
    let upper_path_levels =
        tree_height
            .checked_sub(page_height)
            .ok_or(ProtocolError::InvalidInvariant(
                "materialization upper path height",
            ))?;
    for reducer_level in 0..upper_path_levels {
        let sibling_index = (chunk_ordinal >> reducer_level) ^ 1;
        let sibling_root =
            if reducer_level == 0 && sibling_index >= audit.plan().primary_work_unit_count {
                LysisListSubtreeCarrierV1::canonical_empty_primary_page(
                    ListKind::NodActions,
                    sibling_index,
                )?
                .tree_root
            } else {
                let position = PlannedUnitPositionV1::TreeNode {
                    phase: UnitPhase::RootReduce,
                    level: reducer_level,
                    index: sibling_index,
                };
                let ordinal = topology.plan_ordinal_of(position)?;
                let artifact = audit.verified_artifact_at(ordinal)?;
                let output = decode_root_reduce_output(
                    artifact.artifact().phase_payload(audit.limits())?,
                    audit.limits(),
                )?;
                let summary = match output {
                    RootReduceOutputV1::Leaf { summary, .. }
                    | RootReduceOutputV1::Node { summary } => summary,
                };
                let expected_height = (PRIMARY_WORK_SHARD_SIZE.trailing_zeros() as u16)
                    .checked_add(reducer_level)
                    .ok_or(ProtocolError::IntegerOverflow {
                        what: "materialization upper sibling height",
                    })?;
                if summary.nod_actions.list_kind != ListKind::NodActions
                    || summary.nod_actions.subtree_height != expected_height
                    || summary.nod_actions.subtree_index != sibling_index
                {
                    return Err(NodMaterializationBuildErrorV1::UpperSiblingMismatch);
                }
                dependencies.push(artifact.admission().artifact_ref.clone());
                summary.nod_actions.tree_root
            };
        root_path.push(sibling_root);
    }
    normalize_dependencies(&mut dependencies)?;

    let batch = NodMaterializationBatchV1 {
        queue_sequence: head.queue_sequence,
        first_nod_ordinal: head.next_nod_ordinal,
        actions,
        root_path,
    };
    outbe_ocomp_protocol::nod_materialization::verify_nod_materialization_batch(
        &batch,
        head,
        configured_subtree_height,
        audit.limits(),
    )?;
    Ok(BuiltNodMaterializationBatchV1 {
        batch,
        dependencies,
    })
}

fn require_action_ordinals(
    actions: &[NodActionV1],
    first: u32,
    worldwide_day: u32,
) -> Result<(), NodMaterializationBuildErrorV1> {
    for (offset, action) in actions.iter().enumerate() {
        let ordinal = first
            .checked_add(
                u32::try_from(offset).map_err(|_| ProtocolError::IntegerOverflow {
                    what: "materialization action offset",
                })?,
            )
            .ok_or(ProtocolError::IntegerOverflow {
                what: "materialization action ordinal",
            })?;
        if action.raw_ordinal != ordinal || action.wwd != worldwide_day {
            return Err(NodMaterializationBuildErrorV1::ActionOrder);
        }
    }
    Ok(())
}

fn normalize_dependencies(
    dependencies: &mut Vec<CasObjectRefV1>,
) -> Result<(), NodMaterializationBuildErrorV1> {
    dependencies.sort_by_key(|reference| reference.transport_digest);
    dependencies.dedup();
    if dependencies.is_empty()
        || dependencies.len() > MAX_DEPENDENCY_COUNT
        || dependencies
            .iter()
            .any(|reference| reference.transport_digest.is_zero() || reference.encoded_bytes == 0)
    {
        return Err(NodMaterializationBuildErrorV1::InvalidDependencies);
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MaterializationReferenceRecordV1 {
    version: u16,
    job_id: B256,
    dependencies: Vec<MaterializationReferenceV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MaterializationReferenceV1 {
    transport_digest: B256,
    encoded_bytes: u64,
    expected_ocb1_kind: Option<u16>,
}

impl From<CasObjectRefV1> for MaterializationReferenceV1 {
    fn from(reference: CasObjectRefV1) -> Self {
        Self {
            transport_digest: reference.transport_digest,
            encoded_bytes: reference.encoded_bytes,
            expected_ocb1_kind: reference.expected_ocb1_kind,
        }
    }
}

impl From<MaterializationReferenceV1> for CasObjectRefV1 {
    fn from(reference: MaterializationReferenceV1) -> Self {
        Self {
            transport_digest: reference.transport_digest,
            encoded_bytes: reference.encoded_bytes,
            expected_ocb1_kind: reference.expected_ocb1_kind,
        }
    }
}

pub struct MaterializationReferenceStoreV1 {
    root: PathBuf,
}

impl MaterializationReferenceStoreV1 {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, MaterializationReferenceErrorV1> {
        let root = root.as_ref().to_path_buf();
        create_private_directory(&root)?;
        reject_orphaned_temps(&root)?;
        Ok(Self { root })
    }

    pub fn pin_exact(
        &self,
        job_id: B256,
        dependencies: &[CasObjectRefV1],
    ) -> Result<(), MaterializationReferenceErrorV1> {
        if job_id.is_zero() {
            return Err(MaterializationReferenceErrorV1::InvalidRecord);
        }
        let mut dependencies = dependencies.to_vec();
        normalize_dependencies(&mut dependencies)
            .map_err(|_| MaterializationReferenceErrorV1::InvalidRecord)?;
        if let Some(existing) = self.load_exact(job_id)? {
            return if existing == dependencies {
                Ok(())
            } else {
                Err(MaterializationReferenceErrorV1::ConflictingReplay)
            };
        }
        let record = MaterializationReferenceRecordV1 {
            version: REFERENCE_VERSION,
            job_id,
            dependencies: dependencies.into_iter().map(Into::into).collect(),
        };
        persist_atomic(
            &self.root,
            &self.path(job_id),
            &serde_json::to_vec(&record)?,
        )
    }

    pub fn load_exact(
        &self,
        job_id: B256,
    ) -> Result<Option<Vec<CasObjectRefV1>>, MaterializationReferenceErrorV1> {
        let path = self.path(job_id);
        let bytes = match read_bounded(&path) {
            Ok(bytes) => bytes,
            Err(MaterializationReferenceErrorV1::Missing) => return Ok(None),
            Err(error) => return Err(error),
        };
        let record: MaterializationReferenceRecordV1 = serde_json::from_slice(&bytes)?;
        let mut dependencies = record
            .dependencies
            .iter()
            .cloned()
            .map(Into::into)
            .collect::<Vec<CasObjectRefV1>>();
        normalize_dependencies(&mut dependencies)
            .map_err(|_| MaterializationReferenceErrorV1::InvalidRecord)?;
        if record.version != REFERENCE_VERSION
            || record.job_id != job_id
            || dependencies
                != record
                    .dependencies
                    .into_iter()
                    .map(Into::into)
                    .collect::<Vec<CasObjectRefV1>>()
        {
            return Err(MaterializationReferenceErrorV1::InvalidRecord);
        }
        Ok(Some(dependencies))
    }

    pub fn release(&self, job_id: B256) -> Result<(), MaterializationReferenceErrorV1> {
        let path = self.path(job_id);
        match fs::remove_file(&path) {
            Ok(()) => sync_directory(&self.root),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(io_error(&path, source)),
        }
    }

    fn path(&self, job_id: B256) -> PathBuf {
        self.root.join(format!(
            "{}{}",
            hex::encode(job_id.as_slice()),
            REFERENCE_SUFFIX
        ))
    }
}

fn create_private_directory(path: &Path) -> Result<(), MaterializationReferenceErrorV1> {
    fs::create_dir_all(path).map_err(|source| io_error(path, source))?;
    let metadata = fs::symlink_metadata(path).map_err(|source| io_error(path, source))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(MaterializationReferenceErrorV1::UnsafePath(
            path.to_path_buf(),
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
        .map_err(|source| io_error(path, source))
}

fn reject_orphaned_temps(path: &Path) -> Result<(), MaterializationReferenceErrorV1> {
    for entry in fs::read_dir(path).map_err(|source| io_error(path, source))? {
        let entry = entry.map_err(|source| io_error(path, source))?;
        if entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.ends_with(TEMP_SUFFIX))
        {
            return Err(MaterializationReferenceErrorV1::AmbiguousTemp(entry.path()));
        }
    }
    Ok(())
}

fn persist_atomic(
    root: &Path,
    target: &Path,
    bytes: &[u8],
) -> Result<(), MaterializationReferenceErrorV1> {
    if bytes.len() as u64 > MAX_REFERENCE_FILE_BYTES {
        return Err(MaterializationReferenceErrorV1::InvalidRecord);
    }
    let temp = target.with_extension("tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temp)
        .map_err(|source| io_error(&temp, source))?;
    file.write_all(bytes)
        .map_err(|source| io_error(&temp, source))?;
    file.sync_all().map_err(|source| io_error(&temp, source))?;
    fs::rename(&temp, target).map_err(|source| io_error(target, source))?;
    sync_directory(root)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, MaterializationReferenceErrorV1> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| {
            if source.kind() == std::io::ErrorKind::NotFound {
                MaterializationReferenceErrorV1::Missing
            } else {
                io_error(path, source)
            }
        })?;
    let metadata = file.metadata().map_err(|source| io_error(path, source))?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_REFERENCE_FILE_BYTES {
        return Err(MaterializationReferenceErrorV1::UnsafePath(
            path.to_path_buf(),
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.read_to_end(&mut bytes)
        .map_err(|source| io_error(path, source))?;
    Ok(bytes)
}

fn sync_directory(path: &Path) -> Result<(), MaterializationReferenceErrorV1> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error(path, source))
}

fn io_error(path: &Path, source: std::io::Error) -> MaterializationReferenceErrorV1 {
    MaterializationReferenceErrorV1::Io {
        path: path.to_path_buf(),
        source,
    }
}

#[derive(Debug, Error)]
pub enum NodMaterializationBuildErrorV1 {
    #[error("materialization head does not match the exact audited Lysis job")]
    AuthorityMismatch,
    #[error("the exact result chunk does not contain the requested actions")]
    MissingActions,
    #[error("materialization actions are not the exact ordered WWD slice")]
    ActionOrder,
    #[error("materialization proof is missing a required sibling")]
    MissingSibling,
    #[error("ROOT_REDUCE sibling does not match its exact plan position")]
    UpperSiblingMismatch,
    #[error("materialization dependency set is invalid")]
    InvalidDependencies,
    #[error(transparent)]
    ResultCatalog(#[from] LysisResultCatalogError),
    #[error(transparent)]
    Plan(#[from] ExactLysisPlanError),
    #[error(transparent)]
    Planner(#[from] outbe_lysis::program_v1::planner::PlannerErrorV1),
    #[error(transparent)]
    Artifact(#[from] outbe_lysis::program_v1::artifacts::LysisArtifactErrorV1),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}

#[derive(Debug, Error)]
pub enum MaterializationReferenceErrorV1 {
    #[error("materialization reference record is missing")]
    Missing,
    #[error("materialization reference record is invalid")]
    InvalidRecord,
    #[error("materialization reference exact replay conflicts with the durable record")]
    ConflictingReplay,
    #[error("materialization reference path is unsafe: {0}")]
    UnsafePath(PathBuf),
    #[error("materialization reference store has an ambiguous temporary file: {0}")]
    AmbiguousTemp(PathBuf),
    #[error("materialization reference JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("materialization reference I/O at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}
