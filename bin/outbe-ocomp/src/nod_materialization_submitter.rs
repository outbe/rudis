//! Restart-safe submission of one proof-backed NOD materialization batch.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use alloy_consensus::TxEip1559;
use alloy_eips::eip2718::Encodable2718 as _;
use alloy_primitives::{keccak256, Address, Bytes, TxKind, B256, U256};
use outbe_ocomp_protocol::{
    abi::{encode_materialize_certified_nods_calldata, NOD_FACTORY_ADDRESS},
    nod_materialization::NodMaterializationBatchV1,
    system_carrier::{MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS, OCOMP_SYSTEM_CARRIER_GAS_LIMIT},
    SchemaLimits,
};
use outbe_primitives::signer::{OutbeEvmSigner, SignerError};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::nod_materialization::{
    MaterializationReferenceErrorV1, MaterializationReferenceStoreV1,
};
use crate::vote_submitter::{
    fee_within_envelope, VoteBlockV1, VoteReceiptV1, VoteSubmissionRpcV1,
    MAX_OCOMP_SIGNER_MAX_FEE_PER_GAS,
};

const RECORD_VERSION: u16 = 1;
const RECORD_FILE: &str = "submission-v1.json";
const TEMP_FILE: &str = "submission-v1.tmp";
const MAX_RECORD_BYTES: u64 = 128 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
enum StageV1 {
    Prepared,
    Submitted,
    Included,
    Finalized,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RecordV1 {
    version: u16,
    generation: u64,
    stage: StageV1,
    job_id: B256,
    queue_sequence: u64,
    first_nod_ordinal: u32,
    batch_digest: B256,
    sender: Address,
    nonce: u64,
    max_fee_per_gas: u128,
    transaction_hash: B256,
    raw_transaction: Vec<u8>,
    inclusion: Option<InclusionV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InclusionV1 {
    block_number: u64,
    block_hash: B256,
    success: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodMaterializationSubmissionOutcomeV1 {
    Pending,
    Finalized { success: bool },
}

#[derive(Clone, Debug)]
pub struct NodMaterializationSubmissionConfigV1 {
    pub journal_root: PathBuf,
    pub expected_chain_id: u64,
    pub sender_address: Address,
    pub limits: SchemaLimits,
}

pub struct NodMaterializationSubmitterV1<R> {
    config: NodMaterializationSubmissionConfigV1,
    rpc: R,
    signer: OutbeEvmSigner,
}

impl<R: VoteSubmissionRpcV1> NodMaterializationSubmitterV1<R> {
    pub fn open(
        config: NodMaterializationSubmissionConfigV1,
        rpc: R,
        signer: OutbeEvmSigner,
    ) -> Result<Self, NodMaterializationSubmissionErrorV1> {
        if config.expected_chain_id == 0 || signer.address() != config.sender_address {
            return Err(NodMaterializationSubmissionErrorV1::InvalidConfig);
        }
        ensure_private_directory(&config.journal_root)?;
        if config.journal_root.join(TEMP_FILE).try_exists()? {
            return Err(NodMaterializationSubmissionErrorV1::AmbiguousJournal);
        }
        Ok(Self {
            config,
            rpc,
            signer,
        })
    }

    pub fn reconcile(
        &mut self,
        job_id: B256,
        batch: &NodMaterializationBatchV1,
    ) -> Result<NodMaterializationSubmissionOutcomeV1, NodMaterializationSubmissionErrorV1> {
        let canonical = batch.encode_canonical(&self.config.limits)?;
        let batch_digest = keccak256(&canonical);
        let record = self.load()?;
        let Some(record) = record else {
            self.prepare(job_id, batch, batch_digest)?;
            return Ok(NodMaterializationSubmissionOutcomeV1::Pending);
        };
        self.require_binding(&record, job_id, batch, batch_digest)?;
        match record.stage {
            StageV1::Prepared => self.submit(record),
            StageV1::Submitted => self.observe_submission(record),
            StageV1::Included => self.observe_inclusion(record),
            StageV1::Finalized => Ok(NodMaterializationSubmissionOutcomeV1::Finalized {
                success: record
                    .inclusion
                    .ok_or(NodMaterializationSubmissionErrorV1::InvalidJournal)?
                    .success,
            }),
        }
    }

    fn prepare(
        &mut self,
        job_id: B256,
        batch: &NodMaterializationBatchV1,
        batch_digest: B256,
    ) -> Result<(), NodMaterializationSubmissionErrorV1> {
        let chain_id = self.rpc.chain_id().map_err(rpc_error)?;
        if chain_id != self.config.expected_chain_id {
            return Err(NodMaterializationSubmissionErrorV1::WrongRpcChain {
                expected: self.config.expected_chain_id,
                actual: chain_id,
            });
        }
        let nonce = self
            .rpc
            .canonical_nonce(self.config.sender_address)
            .map_err(rpc_error)?;
        let max_fee_per_gas = fee_within_envelope(
            self.rpc.gas_price().map_err(rpc_error)?,
            MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS,
            MAX_OCOMP_SIGNER_MAX_FEE_PER_GAS,
        );
        let calldata = encode_materialize_certified_nods_calldata(batch, &self.config.limits)?;
        let signed = self.signer.sign_eip1559(TxEip1559 {
            chain_id,
            nonce,
            gas_limit: OCOMP_SYSTEM_CARRIER_GAS_LIMIT,
            max_fee_per_gas,
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(NOD_FACTORY_ADDRESS),
            value: U256::ZERO,
            input: Bytes::from(calldata),
            access_list: Default::default(),
        })?;
        let transaction_hash = *signed.hash();
        let mut raw_transaction = Vec::with_capacity(signed.encode_2718_len());
        signed.encode_2718(&mut raw_transaction);
        self.persist(&RecordV1 {
            version: RECORD_VERSION,
            generation: 1,
            stage: StageV1::Prepared,
            job_id,
            queue_sequence: batch.queue_sequence,
            first_nod_ordinal: batch.first_nod_ordinal,
            batch_digest,
            sender: self.config.sender_address,
            nonce,
            max_fee_per_gas,
            transaction_hash,
            raw_transaction,
            inclusion: None,
        })
    }

    fn submit(
        &mut self,
        mut record: RecordV1,
    ) -> Result<NodMaterializationSubmissionOutcomeV1, NodMaterializationSubmissionErrorV1> {
        self.broadcast(&record)?;
        record.stage = StageV1::Submitted;
        record.generation = next_generation(record.generation)?;
        self.persist(&record)?;
        Ok(NodMaterializationSubmissionOutcomeV1::Pending)
    }

    fn observe_submission(
        &mut self,
        mut record: RecordV1,
    ) -> Result<NodMaterializationSubmissionOutcomeV1, NodMaterializationSubmissionErrorV1> {
        let Some(receipt) = self
            .rpc
            .transaction_receipt(record.transaction_hash)
            .map_err(rpc_error)?
        else {
            self.broadcast(&record)?;
            return Ok(NodMaterializationSubmissionOutcomeV1::Pending);
        };
        self.require_receipt(&record, receipt)?;
        if !self.receipt_is_canonical(receipt)? {
            self.broadcast(&record)?;
            return Ok(NodMaterializationSubmissionOutcomeV1::Pending);
        }
        record.stage = StageV1::Included;
        record.inclusion = Some(inclusion_from(receipt));
        record.generation = next_generation(record.generation)?;
        self.persist(&record)?;
        Ok(NodMaterializationSubmissionOutcomeV1::Pending)
    }

    fn observe_inclusion(
        &mut self,
        mut record: RecordV1,
    ) -> Result<NodMaterializationSubmissionOutcomeV1, NodMaterializationSubmissionErrorV1> {
        let prior = record
            .inclusion
            .ok_or(NodMaterializationSubmissionErrorV1::InvalidJournal)?;
        let Some(receipt) = self
            .rpc
            .transaction_receipt(record.transaction_hash)
            .map_err(rpc_error)?
        else {
            return self.demote(record);
        };
        self.require_receipt(&record, receipt)?;
        if !self.receipt_is_canonical(receipt)? {
            return self.demote(record);
        }
        let inclusion = inclusion_from(receipt);
        if inclusion != prior {
            record.inclusion = Some(inclusion);
            record.generation = next_generation(record.generation)?;
            self.persist(&record)?;
        }
        if self.rpc.finalized_block().map_err(rpc_error)?.number < inclusion.block_number {
            return Ok(NodMaterializationSubmissionOutcomeV1::Pending);
        }
        record.stage = StageV1::Finalized;
        record.inclusion = Some(inclusion);
        record.generation = next_generation(record.generation)?;
        self.persist(&record)?;
        Ok(NodMaterializationSubmissionOutcomeV1::Finalized {
            success: inclusion.success,
        })
    }

    fn demote(
        &mut self,
        mut record: RecordV1,
    ) -> Result<NodMaterializationSubmissionOutcomeV1, NodMaterializationSubmissionErrorV1> {
        record.stage = StageV1::Submitted;
        record.inclusion = None;
        record.generation = next_generation(record.generation)?;
        self.persist(&record)?;
        self.broadcast(&record)?;
        Ok(NodMaterializationSubmissionOutcomeV1::Pending)
    }

    fn broadcast(&self, record: &RecordV1) -> Result<(), NodMaterializationSubmissionErrorV1> {
        let actual = self
            .rpc
            .send_raw_transaction(&record.raw_transaction, record.transaction_hash)
            .map_err(rpc_error)?;
        if actual != record.transaction_hash {
            return Err(NodMaterializationSubmissionErrorV1::TransactionHashMismatch);
        }
        Ok(())
    }

    fn receipt_is_canonical(
        &self,
        receipt: VoteReceiptV1,
    ) -> Result<bool, NodMaterializationSubmissionErrorV1> {
        Ok(self
            .rpc
            .canonical_block(receipt.block_number)
            .map_err(rpc_error)?
            .is_some_and(|block: VoteBlockV1| block.hash == receipt.block_hash))
    }

    fn require_receipt(
        &self,
        record: &RecordV1,
        receipt: VoteReceiptV1,
    ) -> Result<(), NodMaterializationSubmissionErrorV1> {
        if receipt.transaction_hash != record.transaction_hash {
            return Err(NodMaterializationSubmissionErrorV1::TransactionHashMismatch);
        }
        Ok(())
    }

    fn require_binding(
        &self,
        record: &RecordV1,
        job_id: B256,
        batch: &NodMaterializationBatchV1,
        batch_digest: B256,
    ) -> Result<(), NodMaterializationSubmissionErrorV1> {
        if record.version != RECORD_VERSION
            || record.job_id != job_id
            || record.queue_sequence != batch.queue_sequence
            || record.first_nod_ordinal != batch.first_nod_ordinal
            || record.batch_digest != batch_digest
            || record.sender != self.config.sender_address
        {
            return Err(NodMaterializationSubmissionErrorV1::ConflictingReplay);
        }
        Ok(())
    }

    fn load(&self) -> Result<Option<RecordV1>, NodMaterializationSubmissionErrorV1> {
        let path = self.config.journal_root.join(RECORD_FILE);
        load_record(&path)
    }

    fn persist(&self, record: &RecordV1) -> Result<(), NodMaterializationSubmissionErrorV1> {
        let bytes = serde_json::to_vec(record)?;
        if bytes.len() as u64 > MAX_RECORD_BYTES {
            return Err(NodMaterializationSubmissionErrorV1::InvalidJournal);
        }
        let temp = self.config.journal_root.join(TEMP_FILE);
        let target = self.config.journal_root.join(RECORD_FILE);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(temp, target)?;
        File::open(&self.config.journal_root)?.sync_all()?;
        Ok(())
    }
}

/// Releases local CAS references whose durable submission journal already
/// proves finalized inclusion. This closes the crash window between persisting
/// `Finalized` and deleting the batch reference record.
pub fn reconcile_finalized_materialization_references(
    submission_root: &Path,
    reference_root: &Path,
) -> Result<usize, NodMaterializationSubmissionErrorV1> {
    let job_directories = match fs::read_dir(submission_root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    require_directory(submission_root)?;
    let mut released = 0usize;
    for job_entry in job_directories {
        let job_entry = job_entry?;
        require_directory(&job_entry.path())?;
        let job_component = job_entry
            .file_name()
            .into_string()
            .map_err(|_| NodMaterializationSubmissionErrorV1::InvalidJournal)?;
        if job_component.len() != 64 {
            return Err(NodMaterializationSubmissionErrorV1::InvalidJournal);
        }
        let job_id_bytes = hex::decode(&job_component)
            .map_err(|_| NodMaterializationSubmissionErrorV1::InvalidJournal)?;
        if job_id_bytes.len() != 32 {
            return Err(NodMaterializationSubmissionErrorV1::InvalidJournal);
        }
        let job_id = B256::from_slice(&job_id_bytes);
        for ordinal_entry in fs::read_dir(job_entry.path())? {
            let ordinal_entry = ordinal_entry?;
            require_directory(&ordinal_entry.path())?;
            let ordinal_component = ordinal_entry
                .file_name()
                .into_string()
                .map_err(|_| NodMaterializationSubmissionErrorV1::InvalidJournal)?;
            let ordinal = ordinal_component
                .parse::<u32>()
                .map_err(|_| NodMaterializationSubmissionErrorV1::InvalidJournal)?;
            if ordinal.to_string() != ordinal_component
                || ordinal_entry.path().join(TEMP_FILE).try_exists()?
            {
                return Err(NodMaterializationSubmissionErrorV1::InvalidJournal);
            }
            let Some(record) = load_record(&ordinal_entry.path().join(RECORD_FILE))? else {
                continue;
            };
            if record.job_id != job_id || record.first_nod_ordinal != ordinal {
                return Err(NodMaterializationSubmissionErrorV1::InvalidJournal);
            }
            if record.stage != StageV1::Finalized {
                continue;
            }
            let references = MaterializationReferenceStoreV1::open(
                reference_root.join(&job_component).join(&ordinal_component),
            )?;
            if references.load_exact(job_id)?.is_some() {
                references.release(job_id)?;
                released = released
                    .checked_add(1)
                    .ok_or(NodMaterializationSubmissionErrorV1::GenerationOverflow)?;
            }
        }
    }
    Ok(released)
}

fn load_record(path: &Path) -> Result<Option<RecordV1>, NodMaterializationSubmissionErrorV1> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if file.metadata()?.len() > MAX_RECORD_BYTES {
        return Err(NodMaterializationSubmissionErrorV1::InvalidJournal);
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let record: RecordV1 = serde_json::from_slice(&bytes)?;
    let inclusion_is_valid = match record.stage {
        StageV1::Prepared | StageV1::Submitted => record.inclusion.is_none(),
        StageV1::Included | StageV1::Finalized => record.inclusion.is_some(),
    };
    if record.version != RECORD_VERSION || record.generation == 0 || !inclusion_is_valid {
        return Err(NodMaterializationSubmissionErrorV1::InvalidJournal);
    }
    Ok(Some(record))
}

fn require_directory(path: &Path) -> Result<(), NodMaterializationSubmissionErrorV1> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(NodMaterializationSubmissionErrorV1::UnsafePath);
    }
    Ok(())
}

fn inclusion_from(receipt: VoteReceiptV1) -> InclusionV1 {
    InclusionV1 {
        block_number: receipt.block_number,
        block_hash: receipt.block_hash,
        success: receipt.success,
    }
}

fn next_generation(generation: u64) -> Result<u64, NodMaterializationSubmissionErrorV1> {
    generation
        .checked_add(1)
        .ok_or(NodMaterializationSubmissionErrorV1::GenerationOverflow)
}

fn ensure_private_directory(path: &Path) -> Result<(), NodMaterializationSubmissionErrorV1> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(NodMaterializationSubmissionErrorV1::UnsafePath);
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn rpc_error(error: impl std::error::Error) -> NodMaterializationSubmissionErrorV1 {
    NodMaterializationSubmissionErrorV1::Rpc(error.to_string())
}

#[derive(Debug, Error)]
pub enum NodMaterializationSubmissionErrorV1 {
    #[error("NOD materialization submitter configuration is invalid")]
    InvalidConfig,
    #[error("NOD materialization journal path is unsafe")]
    UnsafePath,
    #[error("NOD materialization journal has an ambiguous temporary record")]
    AmbiguousJournal,
    #[error("NOD materialization journal is invalid")]
    InvalidJournal,
    #[error("NOD materialization replay conflicts with the durable batch")]
    ConflictingReplay,
    #[error("NOD materialization RPC chain mismatch: expected {expected}, got {actual}")]
    WrongRpcChain { expected: u64, actual: u64 },
    #[error("NOD materialization transaction hash mismatch")]
    TransactionHashMismatch,
    #[error("NOD materialization journal generation overflow")]
    GenerationOverflow,
    #[error("NOD materialization RPC failed: {0}")]
    Rpc(String),
    #[error(transparent)]
    Protocol(#[from] outbe_ocomp_protocol::ProtocolError),
    #[error(transparent)]
    Signer(#[from] SignerError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
    #[error(transparent)]
    MaterializationReference(#[from] MaterializationReferenceErrorV1),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nod_materialization::MaterializationReferenceStoreV1;
    use outbe_ocomp_protocol::CasObjectRefV1;

    fn record(job_id: B256, stage: StageV1) -> RecordV1 {
        RecordV1 {
            version: RECORD_VERSION,
            generation: 4,
            stage,
            job_id,
            queue_sequence: 7,
            first_nod_ordinal: 16,
            batch_digest: B256::repeat_byte(0x31),
            sender: Address::repeat_byte(0x41),
            nonce: 9,
            max_fee_per_gas: MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS,
            transaction_hash: B256::repeat_byte(0x51),
            raw_transaction: vec![0x61],
            inclusion: matches!(stage, StageV1::Included | StageV1::Finalized).then_some(
                InclusionV1 {
                    block_number: 100,
                    block_hash: B256::repeat_byte(0x71),
                    success: true,
                },
            ),
        }
    }

    fn write_record(root: &Path, record: &RecordV1) {
        let directory = root
            .join(hex::encode(record.job_id.as_slice()))
            .join(record.first_nod_ordinal.to_string());
        fs::create_dir_all(&directory).unwrap();
        fs::write(
            directory.join(RECORD_FILE),
            serde_json::to_vec(record).unwrap(),
        )
        .unwrap();
    }

    fn pin_reference(root: &Path, job_id: B256, ordinal: u32) {
        let store = MaterializationReferenceStoreV1::open(
            root.join(hex::encode(job_id.as_slice()))
                .join(ordinal.to_string()),
        )
        .unwrap();
        store
            .pin_exact(
                job_id,
                &[CasObjectRefV1 {
                    transport_digest: B256::repeat_byte(0x81),
                    encoded_bytes: 8,
                    expected_ocb1_kind: None,
                }],
            )
            .unwrap();
    }

    fn reference_exists(root: &Path, job_id: B256, ordinal: u32) -> bool {
        MaterializationReferenceStoreV1::open(
            root.join(hex::encode(job_id.as_slice()))
                .join(ordinal.to_string()),
        )
        .unwrap()
        .load_exact(job_id)
        .unwrap()
        .is_some()
    }

    #[test]
    fn startup_reconciliation_releases_a_reference_after_the_finalized_journal() {
        let directory = tempfile::tempdir().unwrap();
        let submissions = directory.path().join("submissions");
        let references = directory.path().join("references");
        let job_id = B256::repeat_byte(0x21);
        let finalized = record(job_id, StageV1::Finalized);
        write_record(&submissions, &finalized);
        pin_reference(&references, job_id, finalized.first_nod_ordinal);

        assert_eq!(
            reconcile_finalized_materialization_references(&submissions, &references).unwrap(),
            1
        );
        assert!(!reference_exists(
            &references,
            job_id,
            finalized.first_nod_ordinal
        ));
        assert_eq!(
            reconcile_finalized_materialization_references(&submissions, &references).unwrap(),
            0
        );
    }

    #[test]
    fn startup_reconciliation_keeps_nonfinalized_references() {
        let directory = tempfile::tempdir().unwrap();
        let submissions = directory.path().join("submissions");
        let references = directory.path().join("references");
        let job_id = B256::repeat_byte(0x22);
        let included = record(job_id, StageV1::Included);
        write_record(&submissions, &included);
        pin_reference(&references, job_id, included.first_nod_ordinal);

        assert_eq!(
            reconcile_finalized_materialization_references(&submissions, &references).unwrap(),
            0
        );
        assert!(reference_exists(
            &references,
            job_id,
            included.first_nod_ordinal
        ));
    }

    #[test]
    fn startup_reconciliation_keeps_a_reference_when_the_journal_is_not_prepared_yet() {
        let directory = tempfile::tempdir().unwrap();
        let submissions = directory.path().join("submissions");
        let references = directory.path().join("references");
        let job_id = B256::repeat_byte(0x25);
        let ordinal = 16;
        fs::create_dir_all(
            submissions
                .join(hex::encode(job_id.as_slice()))
                .join(ordinal.to_string()),
        )
        .unwrap();
        pin_reference(&references, job_id, ordinal);

        assert_eq!(
            reconcile_finalized_materialization_references(&submissions, &references).unwrap(),
            0
        );
        assert!(reference_exists(&references, job_id, ordinal));
    }

    #[test]
    fn startup_reconciliation_rejects_a_journal_bound_to_the_wrong_directory() {
        let directory = tempfile::tempdir().unwrap();
        let submissions = directory.path().join("submissions");
        let references = directory.path().join("references");
        let actual_job_id = B256::repeat_byte(0x23);
        let mut finalized = record(actual_job_id, StageV1::Finalized);
        finalized.job_id = B256::repeat_byte(0x24);
        write_record(&submissions, &record(actual_job_id, StageV1::Finalized));
        let record_path = submissions
            .join(hex::encode(actual_job_id.as_slice()))
            .join("16")
            .join(RECORD_FILE);
        fs::write(record_path, serde_json::to_vec(&finalized).unwrap()).unwrap();

        assert!(reconcile_finalized_materialization_references(&submissions, &references).is_err());
    }
}
