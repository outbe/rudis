//! Restart-safe public submission of one validator-domain OCOMP result vote.
//!
//! The Supervisor owns the validator's role-delegated EVM key, validates the
//! result binding, and locally builds the fixed-shape EIP-1559 transaction.
//! This module durably
//! records every delivery transition and only treats a receipt as final after
//! checking the canonical block at its height and the public finalized head.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    },
    path::{Path, PathBuf},
    str::FromStr,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime},
};

use alloy_consensus::{
    transaction::SignerRecoverable as _, EthereumTxEnvelope, Transaction as _, TxEip1559, TxEip4844,
};
use alloy_eips::eip2718::{Decodable2718 as _, Encodable2718 as _};
use alloy_primitives::{keccak256, Address, Bytes, TxKind, B256, U256};
use outbe_ocomp_protocol::{
    abi::encode_submit_lysis_result_calldata,
    common::BoundedBytes,
    control::FinalizedJobSpecV1,
    system_carrier::{
        MAX_OCOMP_SYSTEM_CARRIER_CALLDATA_BYTES, MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS,
        OCOMP_SYSTEM_CARRIER_GAS_LIMIT,
    },
    vote::ResultVoteV1,
    PreparedVoteTransactionV1, ProtocolError, SchemaLimits,
};
use outbe_primitives::addresses::METADOSIS_ADDRESS;
use outbe_primitives::signer::{OutbeEvmSigner, SignerError};
use thiserror::Error;

use crate::result_attestation::{LocalResultAttestationErrorV1, LocalResultVoteAttesterV1};

const JOURNAL_MAGIC: [u8; 8] = *b"OUTBVOT1";
const JOURNAL_VERSION: u16 = 1;
const JOURNAL_LOCK_FILE: &str = "vote-submissions.lock";
const MAX_RAW_TRANSACTION_BYTES: usize = 4 * 1024;
const JOURNAL_FIXED_BYTES_WITHOUT_RAW: usize =
    8 + 2 + 8 + 1 + 32 + 32 + 20 + 8 + 16 + 32 + 4 + 1 + 8 + 32 + 1 + 32;
const RPC_TIMEOUT: Duration = Duration::from_secs(10);
/// Operational ceiling for the outer OCOMP transaction's fee cap.
///
/// ZeroFee waives the canonical execution debit, but a compromised RPC must
/// still be unable to induce the supervisor to sign an unbounded fee promise.
pub const MAX_OCOMP_SIGNER_MAX_FEE_PER_GAS: u128 = MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS * 2;

/// The price a submitter signs with, held inside the envelope it is about to be
/// checked against. The node's suggestion follows the base fee, which moves with
/// traffic; signing it unclamped makes a submitter reject its own transaction.
pub fn fee_within_envelope(suggested: u128, min_fee: u128, max_fee: u128) -> u128 {
    suggested.clamp(min_fee, max_fee)
}

#[derive(Clone, Debug)]
pub struct VoteSubmissionConfigV1 {
    pub journal_root: PathBuf,
    pub expected_chain_id: u64,
    pub sender_address: Address,
    pub limits: SchemaLimits,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum VoteSubmissionStageV1 {
    Prepared = 1,
    Submitted = 2,
    Included = 3,
    Finalized = 4,
}

impl VoteSubmissionStageV1 {
    fn decode(value: u8) -> Result<Self, VoteSubmissionErrorV1> {
        match value {
            1 => Ok(Self::Prepared),
            2 => Ok(Self::Submitted),
            3 => Ok(Self::Included),
            4 => Ok(Self::Finalized),
            _ => Err(VoteSubmissionErrorV1::InvalidJournal),
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Submitted => "submitted",
            Self::Included => "included",
            Self::Finalized => "finalized",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VoteInclusionV1 {
    pub block_number: u64,
    pub block_hash: B256,
    pub success: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VoteSubmissionRecordV1 {
    pub generation: u64,
    pub stage: VoteSubmissionStageV1,
    pub job_id: B256,
    pub result_digest: B256,
    pub sender_address: Address,
    pub nonce: u64,
    pub max_fee_per_gas: u128,
    pub transaction_hash: B256,
    pub raw_transaction: Vec<u8>,
    pub inclusion: Option<VoteInclusionV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VoteSubmissionOutcomeV1 {
    Prepared,
    Submitted,
    Included(VoteInclusionV1),
    Finalized(VoteInclusionV1),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VoteSubmissionFailureClassV1 {
    Retryable,
    Unrecoverable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VoteReceiptV1 {
    pub transaction_hash: B256,
    pub block_number: u64,
    pub block_hash: B256,
    pub success: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VoteBlockV1 {
    pub number: u64,
    pub hash: B256,
}

pub trait VoteTransactionPreparerV1 {
    type Error: std::error::Error + Send + Sync + 'static;

    fn prepare_vote_transaction(
        &self,
        canonical_result: &[u8],
        finalized: &FinalizedJobSpecV1,
        canonical_height: u64,
        nonce: u64,
        max_fee_per_gas: u128,
        gas_limit: u64,
    ) -> Result<PreparedVoteTransactionV1, Self::Error>;
}

pub struct LocalVoteTransactionPreparerV1 {
    signer: OutbeEvmSigner,
    attester: LocalResultVoteAttesterV1,
    chain_id: u64,
    limits: SchemaLimits,
}

impl LocalVoteTransactionPreparerV1 {
    pub fn new(
        signer: OutbeEvmSigner,
        attester: LocalResultVoteAttesterV1,
        chain_id: u64,
        limits: SchemaLimits,
    ) -> Result<Self, LocalVotePreparationErrorV1> {
        if chain_id == 0 {
            return Err(LocalVotePreparationErrorV1::InvalidChainId);
        }
        Ok(Self {
            signer,
            attester,
            chain_id,
            limits,
        })
    }

    pub const fn sender_address(&self) -> Address {
        self.signer.address()
    }
}

impl VoteTransactionPreparerV1 for LocalVoteTransactionPreparerV1 {
    type Error = LocalVotePreparationErrorV1;

    fn prepare_vote_transaction(
        &self,
        canonical_result: &[u8],
        finalized: &FinalizedJobSpecV1,
        canonical_height: u64,
        nonce: u64,
        max_fee_per_gas: u128,
        gas_limit: u64,
    ) -> Result<PreparedVoteTransactionV1, Self::Error> {
        if canonical_result.is_empty() {
            return Err(LocalVotePreparationErrorV1::EmptyCanonicalResult);
        }
        if gas_limit != OCOMP_SYSTEM_CARRIER_GAS_LIMIT
            || !(MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS..=MAX_OCOMP_SIGNER_MAX_FEE_PER_GAS)
                .contains(&max_fee_per_gas)
        {
            return Err(LocalVotePreparationErrorV1::InvalidFeeEnvelope {
                max_fee_per_gas,
                min_fee: MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS,
                max_fee: MAX_OCOMP_SIGNER_MAX_FEE_PER_GAS,
                gas_limit,
                expected_gas_limit: OCOMP_SYSTEM_CARRIER_GAS_LIMIT,
            });
        }

        let vote = self
            .attester
            .attest(canonical_result, finalized, canonical_height)?;
        let canonical_vote = vote.encode_canonical(&self.limits)?;
        let calldata = encode_submit_lysis_result_calldata(&vote, &self.limits)?;
        if calldata.len() > MAX_OCOMP_SYSTEM_CARRIER_CALLDATA_BYTES {
            return Err(LocalVotePreparationErrorV1::CalldataTooLarge);
        }

        let signed = self.signer.sign_eip1559(TxEip1559 {
            chain_id: self.chain_id,
            nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(METADOSIS_ADDRESS),
            value: U256::ZERO,
            input: Bytes::from(calldata),
            access_list: Default::default(),
        })?;
        let transaction_hash = *signed.hash();
        let mut raw_transaction = Vec::new();
        raw_transaction
            .try_reserve_exact(signed.encode_2718_len())
            .map_err(|_| LocalVotePreparationErrorV1::Allocation)?;
        signed.encode_2718(&mut raw_transaction);
        Ok(PreparedVoteTransactionV1 {
            canonical_vote: BoundedBytes(canonical_vote),
            raw_transaction: BoundedBytes(raw_transaction),
            transaction_hash,
        })
    }
}

#[derive(Debug, Error)]
pub enum LocalVotePreparationErrorV1 {
    #[error("OCOMP vote transaction chain id must not be zero")]
    InvalidChainId,
    #[error("OCOMP vote transaction result is empty")]
    EmptyCanonicalResult,
    #[error(
        "OCOMP vote transaction fee envelope is invalid: max fee {max_fee_per_gas} outside \
         {min_fee}..={max_fee}, gas limit {gas_limit} (expected {expected_gas_limit})"
    )]
    InvalidFeeEnvelope {
        max_fee_per_gas: u128,
        min_fee: u128,
        max_fee: u128,
        gas_limit: u64,
        expected_gas_limit: u64,
    },
    #[error("OCOMP vote transaction calldata exceeds the protocol cap")]
    CalldataTooLarge,
    #[error("OCOMP vote transaction allocation failed")]
    Allocation,
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error(transparent)]
    Attestation(#[from] LocalResultAttestationErrorV1),
    #[error(transparent)]
    Signer(#[from] SignerError),
}

pub trait VoteSubmissionRpcV1 {
    type Error: std::error::Error + Send + Sync + 'static;

    fn chain_id(&self) -> Result<u64, Self::Error>;
    fn canonical_nonce(&self, address: Address) -> Result<u64, Self::Error>;
    fn gas_price(&self) -> Result<u128, Self::Error>;
    fn send_raw_transaction(
        &self,
        raw_transaction: &[u8],
        expected_hash: B256,
    ) -> Result<B256, Self::Error>;
    fn transaction_receipt(
        &self,
        transaction_hash: B256,
    ) -> Result<Option<VoteReceiptV1>, Self::Error>;
    fn canonical_block(&self, number: u64) -> Result<Option<VoteBlockV1>, Self::Error>;
    fn finalized_block(&self) -> Result<VoteBlockV1, Self::Error>;
}

pub struct SupervisorVoteSubmitterV1<R> {
    config: VoteSubmissionConfigV1,
    rpc: R,
    journal: VoteSubmissionJournalV1,
}

impl<R: VoteSubmissionRpcV1> SupervisorVoteSubmitterV1<R> {
    pub fn open(config: VoteSubmissionConfigV1, rpc: R) -> Result<Self, VoteSubmissionErrorV1> {
        let journal = VoteSubmissionJournalV1::open(&config.journal_root)?;
        Ok(Self {
            config,
            rpc,
            journal,
        })
    }

    pub fn reconcile<P: VoteTransactionPreparerV1>(
        &mut self,
        preparer: &P,
        job_id: B256,
        result_digest: B256,
        canonical_result: &[u8],
        finalized: &FinalizedJobSpecV1,
    ) -> Result<VoteSubmissionOutcomeV1, VoteSubmissionErrorV1> {
        let record = self.journal.load(job_id)?;
        let Some(record) = record else {
            return self.prepare(
                preparer,
                job_id,
                result_digest,
                canonical_result,
                finalized,
                1,
            );
        };
        self.require_record_binding(&record, result_digest)?;
        if matches!(
            record.stage,
            VoteSubmissionStageV1::Prepared | VoteSubmissionStageV1::Submitted
        ) {
            if let Some(canonical_nonce) = self.bypassed_canonical_nonce(&record)? {
                record_nonce_bypass(
                    &record,
                    canonical_nonce,
                    self.journal.stage_age(record.job_id),
                );
                // Same vote, fresh envelope: the pinned nonce was consumed elsewhere.
                return self.prepare(
                    preparer,
                    job_id,
                    result_digest,
                    canonical_result,
                    finalized,
                    next_generation(record.generation)?,
                );
            }
        }
        match record.stage {
            VoteSubmissionStageV1::Prepared => self.submit(record),
            VoteSubmissionStageV1::Submitted => self.observe_submission(record),
            VoteSubmissionStageV1::Included => self.observe_inclusion(
                preparer,
                job_id,
                result_digest,
                canonical_result,
                finalized,
                record,
            ),
            VoteSubmissionStageV1::Finalized => {
                let inclusion = record
                    .inclusion
                    .ok_or(VoteSubmissionErrorV1::InvalidJournal)?;
                if inclusion.success {
                    Ok(VoteSubmissionOutcomeV1::Finalized(inclusion))
                } else {
                    self.prepare(
                        preparer,
                        job_id,
                        result_digest,
                        canonical_result,
                        finalized,
                        next_generation(record.generation)?,
                    )
                }
            }
        }
    }

    fn prepare<P: VoteTransactionPreparerV1>(
        &mut self,
        preparer: &P,
        job_id: B256,
        result_digest: B256,
        canonical_result: &[u8],
        finalized: &FinalizedJobSpecV1,
        generation: u64,
    ) -> Result<VoteSubmissionOutcomeV1, VoteSubmissionErrorV1> {
        if canonical_result.is_empty() {
            return Err(VoteSubmissionErrorV1::EmptyCanonicalResult);
        }
        let chain_id = self.rpc.chain_id().map_err(rpc_error)?;
        if chain_id != self.config.expected_chain_id {
            return Err(VoteSubmissionErrorV1::WrongRpcChain {
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
        let canonical_height = self.rpc.finalized_block().map_err(rpc_error)?.number;
        let prepared = preparer
            .prepare_vote_transaction(
                canonical_result,
                finalized,
                canonical_height,
                nonce,
                max_fee_per_gas,
                OCOMP_SYSTEM_CARRIER_GAS_LIMIT,
            )
            .map_err(preparer_error)?;
        self.validate_prepared(&prepared, job_id, result_digest, nonce, max_fee_per_gas)?;
        let record = VoteSubmissionRecordV1 {
            generation,
            stage: VoteSubmissionStageV1::Prepared,
            job_id,
            result_digest,
            sender_address: self.config.sender_address,
            nonce,
            max_fee_per_gas,
            transaction_hash: prepared.transaction_hash,
            raw_transaction: prepared.raw_transaction.0,
            inclusion: None,
        };
        self.journal.persist(record.clone())?;
        record_stage_transition(&record, None, None);
        Ok(VoteSubmissionOutcomeV1::Prepared)
    }

    fn submit(
        &mut self,
        mut record: VoteSubmissionRecordV1,
    ) -> Result<VoteSubmissionOutcomeV1, VoteSubmissionErrorV1> {
        let prior_stage = record.stage;
        let prior_age = self.journal.stage_age(record.job_id);
        self.broadcast(&record)?;
        record.stage = VoteSubmissionStageV1::Submitted;
        record.generation = next_generation(record.generation)?;
        self.journal.persist(record.clone())?;
        record_stage_transition(&record, Some(prior_stage), prior_age);
        Ok(VoteSubmissionOutcomeV1::Submitted)
    }

    fn observe_submission(
        &mut self,
        mut record: VoteSubmissionRecordV1,
    ) -> Result<VoteSubmissionOutcomeV1, VoteSubmissionErrorV1> {
        let Some(receipt) = self
            .rpc
            .transaction_receipt(record.transaction_hash)
            .map_err(rpc_error)?
        else {
            self.broadcast(&record)?;
            return Ok(VoteSubmissionOutcomeV1::Submitted);
        };
        self.require_receipt_hash(&record, receipt)?;
        if !self.receipt_is_canonical(receipt)? {
            self.broadcast(&record)?;
            return Ok(VoteSubmissionOutcomeV1::Submitted);
        }
        let inclusion = inclusion_from(receipt);
        let prior_stage = record.stage;
        let prior_age = self.journal.stage_age(record.job_id);
        record.stage = VoteSubmissionStageV1::Included;
        record.inclusion = Some(inclusion);
        record.generation = next_generation(record.generation)?;
        self.journal.persist(record.clone())?;
        record_stage_transition(&record, Some(prior_stage), prior_age);
        Ok(VoteSubmissionOutcomeV1::Included(inclusion))
    }

    fn observe_inclusion<P: VoteTransactionPreparerV1>(
        &mut self,
        preparer: &P,
        job_id: B256,
        result_digest: B256,
        canonical_result: &[u8],
        finalized_job: &FinalizedJobSpecV1,
        mut record: VoteSubmissionRecordV1,
    ) -> Result<VoteSubmissionOutcomeV1, VoteSubmissionErrorV1> {
        let prior = record
            .inclusion
            .ok_or(VoteSubmissionErrorV1::InvalidJournal)?;
        let current = self
            .rpc
            .transaction_receipt(record.transaction_hash)
            .map_err(rpc_error)?;
        let Some(receipt) = current else {
            return self.demote_and_rebroadcast(record);
        };
        self.require_receipt_hash(&record, receipt)?;
        if !self.receipt_is_canonical(receipt)? {
            return self.demote_and_rebroadcast(record);
        }
        let inclusion = inclusion_from(receipt);
        if inclusion != prior {
            let prior_age = self.journal.stage_age(record.job_id);
            record.inclusion = Some(inclusion);
            record.generation = next_generation(record.generation)?;
            self.journal.persist(record.clone())?;
            record_stage_transition(&record, Some(VoteSubmissionStageV1::Included), prior_age);
        }
        let finalized = self.rpc.finalized_block().map_err(rpc_error)?;
        if finalized.number < inclusion.block_number {
            return Ok(VoteSubmissionOutcomeV1::Included(inclusion));
        }
        if !inclusion.success {
            return self.prepare(
                preparer,
                job_id,
                result_digest,
                canonical_result,
                finalized_job,
                next_generation(record.generation)?,
            );
        }
        let prior_stage = record.stage;
        let prior_age = self.journal.stage_age(record.job_id);
        record.stage = VoteSubmissionStageV1::Finalized;
        record.inclusion = Some(inclusion);
        record.generation = next_generation(record.generation)?;
        self.journal.persist(record.clone())?;
        record_stage_transition(&record, Some(prior_stage), prior_age);
        Ok(VoteSubmissionOutcomeV1::Finalized(inclusion))
    }

    fn demote_and_rebroadcast(
        &mut self,
        mut record: VoteSubmissionRecordV1,
    ) -> Result<VoteSubmissionOutcomeV1, VoteSubmissionErrorV1> {
        let prior_stage = record.stage;
        let prior_age = self.journal.stage_age(record.job_id);
        record.stage = VoteSubmissionStageV1::Submitted;
        record.inclusion = None;
        record.generation = next_generation(record.generation)?;
        self.journal.persist(record.clone())?;
        record_stage_transition(&record, Some(prior_stage), prior_age);
        self.broadcast(&record)?;
        Ok(VoteSubmissionOutcomeV1::Submitted)
    }

    fn broadcast(&self, record: &VoteSubmissionRecordV1) -> Result<(), VoteSubmissionErrorV1> {
        let actual = self
            .rpc
            .send_raw_transaction(&record.raw_transaction, record.transaction_hash)
            .map_err(rpc_error)?;
        if actual != record.transaction_hash {
            return Err(VoteSubmissionErrorV1::TransactionHashMismatch {
                expected: record.transaction_hash,
                actual,
            });
        }
        Ok(())
    }

    /// Receipt is checked after the nonce read, so a racing inclusion keeps
    /// the record.
    fn bypassed_canonical_nonce(
        &self,
        record: &VoteSubmissionRecordV1,
    ) -> Result<Option<u64>, VoteSubmissionErrorV1> {
        let canonical_nonce = self
            .rpc
            .canonical_nonce(record.sender_address)
            .map_err(rpc_error)?;
        if canonical_nonce <= record.nonce {
            return Ok(None);
        }
        let receipt = self
            .rpc
            .transaction_receipt(record.transaction_hash)
            .map_err(rpc_error)?;
        Ok(receipt.is_none().then_some(canonical_nonce))
    }

    fn receipt_is_canonical(&self, receipt: VoteReceiptV1) -> Result<bool, VoteSubmissionErrorV1> {
        Ok(self
            .rpc
            .canonical_block(receipt.block_number)
            .map_err(rpc_error)?
            .is_some_and(|block| {
                block.number == receipt.block_number && block.hash == receipt.block_hash
            }))
    }

    fn require_receipt_hash(
        &self,
        record: &VoteSubmissionRecordV1,
        receipt: VoteReceiptV1,
    ) -> Result<(), VoteSubmissionErrorV1> {
        if receipt.transaction_hash != record.transaction_hash {
            return Err(VoteSubmissionErrorV1::TransactionHashMismatch {
                expected: record.transaction_hash,
                actual: receipt.transaction_hash,
            });
        }
        Ok(())
    }

    fn require_record_binding(
        &self,
        record: &VoteSubmissionRecordV1,
        result_digest: B256,
    ) -> Result<(), VoteSubmissionErrorV1> {
        if record.result_digest != result_digest
            || record.sender_address != self.config.sender_address
        {
            return Err(VoteSubmissionErrorV1::DifferentResultForJournaledJob);
        }
        Ok(())
    }

    fn validate_prepared(
        &self,
        prepared: &PreparedVoteTransactionV1,
        job_id: B256,
        result_digest: B256,
        nonce: u64,
        max_fee_per_gas: u128,
    ) -> Result<(), VoteSubmissionErrorV1> {
        let vote = ResultVoteV1::decode_canonical(&prepared.canonical_vote.0, &self.config.limits)?;
        if vote.job_id != job_id || vote.result_digest(&self.config.limits)? != result_digest {
            return Err(VoteSubmissionErrorV1::PreparerChangedResult);
        }
        let expected_calldata = encode_submit_lysis_result_calldata(&vote, &self.config.limits)?;
        if prepared.raw_transaction.0.len() > MAX_RAW_TRANSACTION_BYTES {
            return Err(VoteSubmissionErrorV1::RawTransactionTooLarge);
        }
        let mut raw = prepared.raw_transaction.0.as_slice();
        let transaction =
            EthereumTxEnvelope::<TxEip4844>::decode_2718(&mut raw).map_err(|error| {
                VoteSubmissionErrorV1::InvalidPreparedTransaction(error.to_string())
            })?;
        if !raw.is_empty() || !matches!(&transaction, EthereumTxEnvelope::Eip1559(_)) {
            return Err(VoteSubmissionErrorV1::InvalidPreparedTransaction(
                "not one exact EIP-1559 envelope".to_owned(),
            ));
        }
        let recovered = transaction.recover_signer().map_err(|error| {
            VoteSubmissionErrorV1::InvalidPreparedTransaction(error.to_string())
        })?;
        if recovered != self.config.sender_address
            || transaction.chain_id() != Some(self.config.expected_chain_id)
            || transaction.nonce() != nonce
            || transaction.gas_limit() != OCOMP_SYSTEM_CARRIER_GAS_LIMIT
            || transaction.max_fee_per_gas() != max_fee_per_gas
            || transaction.max_priority_fee_per_gas() != Some(0)
            || transaction.kind() != TxKind::Call(METADOSIS_ADDRESS)
            || transaction.value() != U256::ZERO
            || transaction.input().as_ref() != expected_calldata.as_slice()
        {
            return Err(VoteSubmissionErrorV1::InvalidPreparedTransaction(
                "restricted vote transaction fields changed".to_owned(),
            ));
        }
        let decoded_hash = *transaction.tx_hash();
        if decoded_hash != prepared.transaction_hash {
            return Err(VoteSubmissionErrorV1::TransactionHashMismatch {
                expected: prepared.transaction_hash,
                actual: decoded_hash,
            });
        }
        Ok(())
    }
}

fn inclusion_from(receipt: VoteReceiptV1) -> VoteInclusionV1 {
    VoteInclusionV1 {
        block_number: receipt.block_number,
        block_hash: receipt.block_hash,
        success: receipt.success,
    }
}

fn next_generation(generation: u64) -> Result<u64, VoteSubmissionErrorV1> {
    generation
        .checked_add(1)
        .ok_or(VoteSubmissionErrorV1::JournalGenerationOverflow)
}

fn rpc_error(error: impl std::error::Error + 'static) -> VoteSubmissionErrorV1 {
    let retryable = (&error as &dyn std::error::Error)
        .downcast_ref::<PublicVoteRpcErrorV1>()
        .is_none_or(|error| error.is_retryable());
    if retryable {
        VoteSubmissionErrorV1::RetryableRpc(error.to_string())
    } else {
        VoteSubmissionErrorV1::UnrecoverableRpc(error.to_string())
    }
}

fn preparer_error(error: impl std::error::Error) -> VoteSubmissionErrorV1 {
    VoteSubmissionErrorV1::Preparer(error.to_string())
}

pub struct PublicVoteRpcClientV1 {
    endpoint: String,
    client: reqwest::blocking::Client,
    next_id: AtomicU64,
    max_response_bytes: usize,
}

impl PublicVoteRpcClientV1 {
    pub fn new(
        endpoint: impl Into<String>,
        max_response_bytes: usize,
    ) -> Result<Self, PublicVoteRpcErrorV1> {
        if max_response_bytes == 0 {
            return Err(PublicVoteRpcErrorV1::InvalidConfiguration);
        }
        let endpoint = endpoint.into();
        reqwest::Url::parse(&endpoint)
            .map_err(|error| PublicVoteRpcErrorV1::Transport(error.to_string()))?;
        let client = reqwest::blocking::Client::builder()
            .timeout(RPC_TIMEOUT)
            .build()
            .map_err(|error| PublicVoteRpcErrorV1::Transport(error.to_string()))?;
        Ok(Self {
            endpoint,
            client,
            next_id: AtomicU64::new(1),
            max_response_bytes,
        })
    }

    fn call(
        &self,
        method: &'static str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, PublicVoteRpcErrorV1> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let response = self
            .client
            .post(&self.endpoint)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "method": method,
                "params": params,
                "id": id,
            }))
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .map_err(|error| PublicVoteRpcErrorV1::Transport(error.to_string()))?;
        if response
            .content_length()
            .is_some_and(|length| length > self.max_response_bytes as u64)
        {
            return Err(PublicVoteRpcErrorV1::ResponseTooLarge);
        }
        let read_limit = u64::try_from(self.max_response_bytes)
            .map_err(|_| PublicVoteRpcErrorV1::InvalidConfiguration)?;
        let mut bytes = Vec::new();
        response
            .take(read_limit.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|error| PublicVoteRpcErrorV1::Transport(error.to_string()))?;
        if bytes.len() > self.max_response_bytes {
            return Err(PublicVoteRpcErrorV1::ResponseTooLarge);
        }
        parse_rpc_response(&bytes, id)
    }

    /// Executes a read-only `eth_call` against finalized state.
    pub(crate) fn call_contract_finalized(
        &self,
        to: Address,
        data: &[u8],
    ) -> Result<Vec<u8>, PublicVoteRpcErrorV1> {
        let value = self.call(
            "eth_call",
            serde_json::json!([
                { "to": format!("{to:#x}"), "data": format!("0x{}", hex::encode(data)) },
                "finalized",
            ]),
        )?;
        let text = value.as_str().ok_or_else(|| {
            PublicVoteRpcErrorV1::Malformed("eth_call result is not a string".to_owned())
        })?;
        let stripped = text.strip_prefix("0x").ok_or_else(|| {
            PublicVoteRpcErrorV1::Malformed("eth_call result is not 0x-prefixed".to_owned())
        })?;
        hex::decode(stripped).map_err(|error| PublicVoteRpcErrorV1::Malformed(error.to_string()))
    }

    fn block_for_tag(&self, tag: serde_json::Value) -> Result<VoteBlockV1, PublicVoteRpcErrorV1> {
        let value = self.call("eth_getBlockByNumber", serde_json::json!([tag, false]))?;
        if value.is_null() {
            return Err(PublicVoteRpcErrorV1::MissingBlock);
        }
        Ok(VoteBlockV1 {
            number: parse_quantity_field(&value, "number")?,
            hash: parse_b256_field(&value, "hash")?,
        })
    }
}

fn parse_rpc_response(
    bytes: &[u8],
    expected_id: u64,
) -> Result<serde_json::Value, PublicVoteRpcErrorV1> {
    #[derive(serde::Deserialize)]
    struct RpcError {
        code: i64,
        message: String,
    }

    let envelope: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|error| PublicVoteRpcErrorV1::Malformed(error.to_string()))?;
    if envelope.get("jsonrpc").and_then(serde_json::Value::as_str) != Some("2.0")
        || envelope.get("id").and_then(serde_json::Value::as_u64) != Some(expected_id)
    {
        return Err(PublicVoteRpcErrorV1::Malformed(
            "JSON-RPC envelope mismatch".to_owned(),
        ));
    }
    if let Some(error) = envelope.get("error").filter(|error| !error.is_null()) {
        let error: RpcError = serde_json::from_value(error.clone())
            .map_err(|error| PublicVoteRpcErrorV1::Malformed(error.to_string()))?;
        return Err(PublicVoteRpcErrorV1::Remote {
            code: error.code,
            message: error.message,
        });
    }
    envelope
        .get("result")
        .cloned()
        .ok_or_else(|| PublicVoteRpcErrorV1::Malformed("missing result".to_owned()))
}

impl VoteSubmissionRpcV1 for PublicVoteRpcClientV1 {
    type Error = PublicVoteRpcErrorV1;

    fn chain_id(&self) -> Result<u64, Self::Error> {
        parse_quantity(self.call("eth_chainId", serde_json::json!([]))?, "chain id")
    }

    fn canonical_nonce(&self, address: Address) -> Result<u64, Self::Error> {
        parse_quantity(
            self.call("eth_getTransactionCount", canonical_nonce_params(address))?,
            "canonical nonce",
        )
    }

    fn gas_price(&self) -> Result<u128, Self::Error> {
        parse_quantity_u128(
            self.call("eth_gasPrice", serde_json::json!([]))?,
            "gas price",
        )
    }

    fn send_raw_transaction(
        &self,
        raw_transaction: &[u8],
        expected_hash: B256,
    ) -> Result<B256, Self::Error> {
        match self.call(
            "eth_sendRawTransaction",
            serde_json::json!([format!("0x{}", hex::encode(raw_transaction))]),
        ) {
            Ok(value) => parse_b256(value, "submitted transaction hash"),
            Err(PublicVoteRpcErrorV1::Remote { message, .. })
                if message.to_ascii_lowercase().contains("already known")
                    || message.to_ascii_lowercase().contains("known transaction") =>
            {
                Ok(expected_hash)
            }
            Err(error) => Err(error),
        }
    }

    fn transaction_receipt(
        &self,
        transaction_hash: B256,
    ) -> Result<Option<VoteReceiptV1>, Self::Error> {
        let value = self.call(
            "eth_getTransactionReceipt",
            serde_json::json!([format!("{transaction_hash:#x}")]),
        )?;
        if value.is_null() {
            return Ok(None);
        }
        Ok(Some(VoteReceiptV1 {
            transaction_hash: parse_b256_field(&value, "transactionHash")?,
            block_number: parse_quantity_field(&value, "blockNumber")?,
            block_hash: parse_b256_field(&value, "blockHash")?,
            success: parse_quantity_field(&value, "status")? == 1,
        }))
    }

    fn canonical_block(&self, number: u64) -> Result<Option<VoteBlockV1>, Self::Error> {
        let value = self.call(
            "eth_getBlockByNumber",
            serde_json::json!([format!("0x{number:x}"), false]),
        )?;
        if value.is_null() {
            return Ok(None);
        }
        Ok(Some(VoteBlockV1 {
            number: parse_quantity_field(&value, "number")?,
            hash: parse_b256_field(&value, "hash")?,
        }))
    }

    fn finalized_block(&self) -> Result<VoteBlockV1, Self::Error> {
        self.block_for_tag(serde_json::Value::String("finalized".to_owned()))
    }
}

fn canonical_nonce_params(address: Address) -> serde_json::Value {
    serde_json::json!([format!("{address:#x}"), "latest"])
}

fn parse_quantity(
    value: serde_json::Value,
    field: &'static str,
) -> Result<u64, PublicVoteRpcErrorV1> {
    let encoded = value
        .as_str()
        .ok_or(PublicVoteRpcErrorV1::InvalidQuantity(field))?;
    let digits = encoded
        .strip_prefix("0x")
        .ok_or(PublicVoteRpcErrorV1::InvalidQuantity(field))?;
    if digits.is_empty() {
        return Err(PublicVoteRpcErrorV1::InvalidQuantity(field));
    }
    u64::from_str_radix(digits, 16).map_err(|_| PublicVoteRpcErrorV1::InvalidQuantity(field))
}

fn parse_quantity_u128(
    value: serde_json::Value,
    field: &'static str,
) -> Result<u128, PublicVoteRpcErrorV1> {
    let encoded = value
        .as_str()
        .ok_or(PublicVoteRpcErrorV1::InvalidQuantity(field))?;
    let digits = encoded
        .strip_prefix("0x")
        .ok_or(PublicVoteRpcErrorV1::InvalidQuantity(field))?;
    if digits.is_empty() {
        return Err(PublicVoteRpcErrorV1::InvalidQuantity(field));
    }
    u128::from_str_radix(digits, 16).map_err(|_| PublicVoteRpcErrorV1::InvalidQuantity(field))
}

fn parse_quantity_field(
    value: &serde_json::Value,
    field: &'static str,
) -> Result<u64, PublicVoteRpcErrorV1> {
    parse_quantity(
        value
            .get(field)
            .cloned()
            .ok_or_else(|| PublicVoteRpcErrorV1::Malformed(format!("missing {field}")))?,
        field,
    )
}

fn parse_b256(value: serde_json::Value, field: &'static str) -> Result<B256, PublicVoteRpcErrorV1> {
    value
        .as_str()
        .ok_or_else(|| PublicVoteRpcErrorV1::Malformed(format!("{field} is not a string")))
        .and_then(|encoded| {
            B256::from_str(encoded)
                .map_err(|error| PublicVoteRpcErrorV1::Malformed(error.to_string()))
        })
}

fn parse_b256_field(
    value: &serde_json::Value,
    field: &'static str,
) -> Result<B256, PublicVoteRpcErrorV1> {
    parse_b256(
        value
            .get(field)
            .cloned()
            .ok_or_else(|| PublicVoteRpcErrorV1::Malformed(format!("missing {field}")))?,
        field,
    )
}

struct VoteSubmissionJournalV1 {
    root: PathBuf,
    _lock: File,
}

impl VoteSubmissionJournalV1 {
    #[allow(unsafe_code)]
    fn open(root: &Path) -> Result<Self, VoteSubmissionErrorV1> {
        ensure_private_directory(root)?;
        let lock_path = root.join(JOURNAL_LOCK_FILE);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|source| io_error("open vote submission lock", &lock_path, source))?;
        // SAFETY: `lock` owns a live descriptor for the complete `flock` call.
        let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(io_error(
                "lock vote submission journal",
                &lock_path,
                std::io::Error::last_os_error(),
            ));
        }
        Ok(Self {
            root: root.to_path_buf(),
            _lock: lock,
        })
    }

    fn load(&self, job_id: B256) -> Result<Option<VoteSubmissionRecordV1>, VoteSubmissionErrorV1> {
        let path = self.record_path(job_id);
        let temp = self.temp_path(job_id);
        if path_exists(&temp)? {
            return Err(VoteSubmissionErrorV1::AmbiguousJournal(temp));
        }
        if !path_exists(&path)? {
            return Ok(None);
        }
        let mut file = open_regular_nofollow(&path)?;
        let metadata = file
            .metadata()
            .map_err(|source| io_error("stat vote submission journal", &path, source))?;
        let len =
            usize::try_from(metadata.len()).map_err(|_| VoteSubmissionErrorV1::JournalTooLarge)?;
        if !(JOURNAL_FIXED_BYTES_WITHOUT_RAW
            ..=JOURNAL_FIXED_BYTES_WITHOUT_RAW + MAX_RAW_TRANSACTION_BYTES)
            .contains(&len)
        {
            return Err(VoteSubmissionErrorV1::JournalTooLarge);
        }
        let mut bytes = Vec::with_capacity(len);
        file.read_to_end(&mut bytes)
            .map_err(|source| io_error("read vote submission journal", &path, source))?;
        let record = decode_record(&bytes)?;
        if record.job_id != job_id {
            return Err(VoteSubmissionErrorV1::InvalidJournal);
        }
        Ok(Some(record))
    }

    fn persist(&self, record: VoteSubmissionRecordV1) -> Result<(), VoteSubmissionErrorV1> {
        validate_record(&record)?;
        let encoded = encode_record(&record)?;
        let temp = self.temp_path(record.job_id);
        let final_path = self.record_path(record.job_id);
        if path_exists(&temp)? {
            return Err(VoteSubmissionErrorV1::AmbiguousJournal(temp));
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&temp)
            .map_err(|source| io_error("create vote journal temp", &temp, source))?;
        file.write_all(&encoded)
            .map_err(|source| io_error("write vote journal temp", &temp, source))?;
        file.sync_all()
            .map_err(|source| io_error("fsync vote journal temp", &temp, source))?;
        fs::rename(&temp, &final_path)
            .map_err(|source| io_error("publish vote submission journal", &final_path, source))?;
        sync_directory(&self.root)
    }

    /// Best-effort operational age of the current durable stage. Filesystem
    /// clocks are never part of submission control flow or journal validity.
    fn stage_age(&self, job_id: B256) -> Option<Duration> {
        let metadata = fs::symlink_metadata(self.record_path(job_id)).ok()?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return None;
        }
        SystemTime::now()
            .duration_since(metadata.modified().ok()?)
            .ok()
    }

    fn record_path(&self, job_id: B256) -> PathBuf {
        self.root
            .join(format!("{}.vote.v1", hex::encode(job_id.as_slice())))
    }

    fn temp_path(&self, job_id: B256) -> PathBuf {
        self.root
            .join(format!("{}.vote.v1.tmp", hex::encode(job_id.as_slice())))
    }
}

fn record_stage_transition(
    record: &VoteSubmissionRecordV1,
    prior_stage: Option<VoteSubmissionStageV1>,
    prior_age: Option<Duration>,
) {
    metrics::counter!(
        "outbe_ocomp_vote_submission_transitions_total",
        "stage" => record.stage.label()
    )
    .increment(1);
    if let (Some(stage), Some(age)) = (prior_stage, prior_age) {
        metrics::histogram!(
            "outbe_ocomp_vote_submission_stage_age_seconds",
            "stage" => stage.label()
        )
        .record(age.as_secs_f64());
    }
    tracing::info!(
        target: "outbe::ocomp::vote_submission",
        job_id = %record.job_id,
        stage = record.stage.label(),
        prior_stage = prior_stage.map(VoteSubmissionStageV1::label).unwrap_or("absent"),
        prior_stage_age_seconds = prior_age.map(|age| age.as_secs_f64()),
        generation = record.generation,
        nonce = record.nonce,
        transaction_hash = %record.transaction_hash,
        "OCOMP vote submission stage advanced"
    );
}

fn record_nonce_bypass(
    record: &VoteSubmissionRecordV1,
    canonical_nonce: u64,
    stage_age: Option<Duration>,
) {
    metrics::counter!(
        "outbe_ocomp_vote_nonce_bypassed_total",
        "stage" => record.stage.label()
    )
    .increment(1);
    if let Some(age) = stage_age {
        metrics::histogram!(
            "outbe_ocomp_vote_submission_stage_age_seconds",
            "stage" => record.stage.label()
        )
        .record(age.as_secs_f64());
    }
    tracing::warn!(
        target: "outbe::ocomp::vote_submission",
        job_id = %record.job_id,
        stage = record.stage.label(),
        stage_age_seconds = stage_age.map(|age| age.as_secs_f64()),
        generation = record.generation,
        pinned_nonce = record.nonce,
        canonical_nonce,
        transaction_hash = %record.transaction_hash,
        "OCOMP vote nonce was bypassed; rebuilding the same vote in a fresh envelope"
    );
}

fn validate_record(record: &VoteSubmissionRecordV1) -> Result<(), VoteSubmissionErrorV1> {
    if record.generation == 0
        || record.raw_transaction.is_empty()
        || record.raw_transaction.len() > MAX_RAW_TRANSACTION_BYTES
        || matches!(
            record.stage,
            VoteSubmissionStageV1::Prepared | VoteSubmissionStageV1::Submitted
        ) != record.inclusion.is_none()
    {
        return Err(VoteSubmissionErrorV1::InvalidJournal);
    }
    Ok(())
}

fn encode_record(record: &VoteSubmissionRecordV1) -> Result<Vec<u8>, VoteSubmissionErrorV1> {
    validate_record(record)?;
    let raw_len = u32::try_from(record.raw_transaction.len())
        .map_err(|_| VoteSubmissionErrorV1::JournalTooLarge)?;
    let mut bytes =
        Vec::with_capacity(JOURNAL_FIXED_BYTES_WITHOUT_RAW + record.raw_transaction.len());
    bytes.extend_from_slice(&JOURNAL_MAGIC);
    bytes.extend_from_slice(&JOURNAL_VERSION.to_be_bytes());
    bytes.extend_from_slice(&record.generation.to_be_bytes());
    bytes.push(record.stage as u8);
    bytes.extend_from_slice(record.job_id.as_slice());
    bytes.extend_from_slice(record.result_digest.as_slice());
    bytes.extend_from_slice(record.sender_address.as_slice());
    bytes.extend_from_slice(&record.nonce.to_be_bytes());
    bytes.extend_from_slice(&record.max_fee_per_gas.to_be_bytes());
    bytes.extend_from_slice(record.transaction_hash.as_slice());
    bytes.extend_from_slice(&raw_len.to_be_bytes());
    bytes.extend_from_slice(&record.raw_transaction);
    match record.inclusion {
        Some(inclusion) => {
            bytes.push(1);
            bytes.extend_from_slice(&inclusion.block_number.to_be_bytes());
            bytes.extend_from_slice(inclusion.block_hash.as_slice());
            bytes.push(u8::from(inclusion.success));
        }
        None => {
            bytes.push(0);
            bytes.extend_from_slice(&0_u64.to_be_bytes());
            bytes.extend_from_slice(B256::ZERO.as_slice());
            bytes.push(0);
        }
    }
    let checksum = keccak256(&bytes);
    bytes.extend_from_slice(checksum.as_slice());
    Ok(bytes)
}

fn decode_record(bytes: &[u8]) -> Result<VoteSubmissionRecordV1, VoteSubmissionErrorV1> {
    if bytes.len() < JOURNAL_FIXED_BYTES_WITHOUT_RAW || bytes.get(..8) != Some(&JOURNAL_MAGIC) {
        return Err(VoteSubmissionErrorV1::InvalidJournal);
    }
    let version = read_u16(bytes, 8)?;
    if version != JOURNAL_VERSION {
        return Err(VoteSubmissionErrorV1::UnsupportedJournalVersion(version));
    }
    let generation = read_u64(bytes, 10)?;
    let stage = VoteSubmissionStageV1::decode(read_u8(bytes, 18)?)?;
    let job_id = read_b256(bytes, 19)?;
    let result_digest = read_b256(bytes, 51)?;
    let sender_address = Address::from_slice(read_slice(bytes, 83, 20)?);
    let nonce = read_u64(bytes, 103)?;
    let max_fee_per_gas = read_u128(bytes, 111)?;
    let transaction_hash = read_b256(bytes, 127)?;
    let raw_len = usize::try_from(read_u32(bytes, 159)?)
        .map_err(|_| VoteSubmissionErrorV1::JournalTooLarge)?;
    if raw_len == 0 || raw_len > MAX_RAW_TRANSACTION_BYTES {
        return Err(VoteSubmissionErrorV1::JournalTooLarge);
    }
    let raw_start: usize = 163;
    let raw_end = raw_start
        .checked_add(raw_len)
        .ok_or(VoteSubmissionErrorV1::JournalTooLarge)?;
    let trailer_end = raw_end
        .checked_add(1 + 8 + 32 + 1)
        .ok_or(VoteSubmissionErrorV1::JournalTooLarge)?;
    let expected_len = trailer_end
        .checked_add(32)
        .ok_or(VoteSubmissionErrorV1::JournalTooLarge)?;
    if expected_len != bytes.len() {
        return Err(VoteSubmissionErrorV1::InvalidJournal);
    }
    let checksum = read_b256(bytes, trailer_end)?;
    if keccak256(&bytes[..trailer_end]) != checksum {
        return Err(VoteSubmissionErrorV1::JournalChecksumMismatch);
    }
    let has_inclusion = read_u8(bytes, raw_end)?;
    let block_number = read_u64(bytes, raw_end + 1)?;
    let block_hash = read_b256(bytes, raw_end + 9)?;
    let success = read_u8(bytes, raw_end + 41)?;
    let inclusion = match (has_inclusion, success) {
        (0, 0) if block_number == 0 && block_hash == B256::ZERO => None,
        (1, 0 | 1) => Some(VoteInclusionV1 {
            block_number,
            block_hash,
            success: success == 1,
        }),
        _ => return Err(VoteSubmissionErrorV1::InvalidJournal),
    };
    let record = VoteSubmissionRecordV1 {
        generation,
        stage,
        job_id,
        result_digest,
        sender_address,
        nonce,
        max_fee_per_gas,
        transaction_hash,
        raw_transaction: read_slice(bytes, raw_start, raw_len)?.to_vec(),
        inclusion,
    };
    validate_record(&record)?;
    Ok(record)
}

fn read_slice(bytes: &[u8], start: usize, len: usize) -> Result<&[u8], VoteSubmissionErrorV1> {
    bytes
        .get(start..start.saturating_add(len))
        .ok_or(VoteSubmissionErrorV1::InvalidJournal)
}

fn read_u8(bytes: &[u8], start: usize) -> Result<u8, VoteSubmissionErrorV1> {
    bytes
        .get(start)
        .copied()
        .ok_or(VoteSubmissionErrorV1::InvalidJournal)
}

fn read_u16(bytes: &[u8], start: usize) -> Result<u16, VoteSubmissionErrorV1> {
    Ok(u16::from_be_bytes(
        read_slice(bytes, start, 2)?
            .try_into()
            .map_err(|_| VoteSubmissionErrorV1::InvalidJournal)?,
    ))
}

fn read_u32(bytes: &[u8], start: usize) -> Result<u32, VoteSubmissionErrorV1> {
    Ok(u32::from_be_bytes(
        read_slice(bytes, start, 4)?
            .try_into()
            .map_err(|_| VoteSubmissionErrorV1::InvalidJournal)?,
    ))
}

fn read_u64(bytes: &[u8], start: usize) -> Result<u64, VoteSubmissionErrorV1> {
    Ok(u64::from_be_bytes(
        read_slice(bytes, start, 8)?
            .try_into()
            .map_err(|_| VoteSubmissionErrorV1::InvalidJournal)?,
    ))
}

fn read_u128(bytes: &[u8], start: usize) -> Result<u128, VoteSubmissionErrorV1> {
    Ok(u128::from_be_bytes(
        read_slice(bytes, start, 16)?
            .try_into()
            .map_err(|_| VoteSubmissionErrorV1::InvalidJournal)?,
    ))
}

fn read_b256(bytes: &[u8], start: usize) -> Result<B256, VoteSubmissionErrorV1> {
    Ok(B256::from_slice(read_slice(bytes, start, 32)?))
}

fn ensure_private_directory(path: &Path) -> Result<(), VoteSubmissionErrorV1> {
    fs::create_dir_all(path)
        .map_err(|source| io_error("create vote submission directory", path, source))?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("stat vote submission directory", path, source))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(VoteSubmissionErrorV1::UnsafePath(path.to_path_buf()));
    }
    if metadata.permissions().mode() & 0o077 != 0 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|source| io_error("chmod vote submission directory", path, source))?;
    }
    Ok(())
}

fn path_exists(path: &Path) -> Result<bool, VoteSubmissionErrorV1> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err(VoteSubmissionErrorV1::UnsafePath(path.to_path_buf()));
            }
            Ok(true)
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error("stat vote submission path", path, source)),
    }
}

fn open_regular_nofollow(path: &Path) -> Result<File, VoteSubmissionErrorV1> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_error("open vote submission journal", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("stat vote submission journal", path, source))?;
    if !metadata.file_type().is_file() {
        return Err(VoteSubmissionErrorV1::UnsafePath(path.to_path_buf()));
    }
    Ok(file)
}

fn sync_directory(path: &Path) -> Result<(), VoteSubmissionErrorV1> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("fsync vote submission directory", path, source))
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> VoteSubmissionErrorV1 {
    VoteSubmissionErrorV1::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[derive(Debug, Error)]
pub enum VoteSubmissionErrorV1 {
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("vote transaction preparation failed: {0}")]
    Preparer(String),
    #[error("vote submission public RPC temporarily failed: {0}")]
    RetryableRpc(String),
    #[error("vote submission public RPC returned an unrecoverable response: {0}")]
    UnrecoverableRpc(String),
    #[error("vote submission RPC is for chain {actual}, expected {expected}")]
    WrongRpcChain { expected: u64, actual: u64 },
    #[error("transaction preparer returned a result for another job or digest")]
    PreparerChangedResult,
    #[error("transaction preparer returned an invalid restricted vote transaction: {0}")]
    InvalidPreparedTransaction(String),
    #[error("transaction preparer returned an oversized raw vote transaction")]
    RawTransactionTooLarge,
    #[error("empty canonical result cannot prepare a vote transaction")]
    EmptyCanonicalResult,
    #[error("vote transaction hash mismatch: expected {expected}, got {actual}")]
    TransactionHashMismatch { expected: B256, actual: B256 },
    #[error("another result is already journaled for this job")]
    DifferentResultForJournaledJob,
    #[error("vote submission journal generation overflow")]
    JournalGenerationOverflow,
    #[error("vote submission journal is malformed")]
    InvalidJournal,
    #[error("vote submission journal checksum mismatch")]
    JournalChecksumMismatch,
    #[error("unsupported vote submission journal version {0}")]
    UnsupportedJournalVersion(u16),
    #[error("vote submission journal exceeds its fixed bound")]
    JournalTooLarge,
    #[error("vote submission journal has an ambiguous temporary file at {0}")]
    AmbiguousJournal(PathBuf),
    #[error("vote submission path is unsafe: {0}")]
    UnsafePath(PathBuf),
    #[error("vote submission I/O while trying to {operation} at {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

impl VoteSubmissionErrorV1 {
    #[must_use]
    pub const fn class(&self) -> VoteSubmissionFailureClassV1 {
        match self {
            Self::RetryableRpc(_) => VoteSubmissionFailureClassV1::Retryable,
            Self::Protocol(_)
            | Self::Preparer(_)
            | Self::UnrecoverableRpc(_)
            | Self::WrongRpcChain { .. }
            | Self::PreparerChangedResult
            | Self::InvalidPreparedTransaction(_)
            | Self::RawTransactionTooLarge
            | Self::EmptyCanonicalResult
            | Self::TransactionHashMismatch { .. }
            | Self::DifferentResultForJournaledJob
            | Self::JournalGenerationOverflow
            | Self::InvalidJournal
            | Self::JournalChecksumMismatch
            | Self::UnsupportedJournalVersion(_)
            | Self::JournalTooLarge
            | Self::AmbiguousJournal(_)
            | Self::UnsafePath(_)
            | Self::Io { .. } => VoteSubmissionFailureClassV1::Unrecoverable,
        }
    }
}

#[derive(Debug, Error)]
pub enum PublicVoteRpcErrorV1 {
    #[error("invalid public vote RPC configuration")]
    InvalidConfiguration,
    #[error("public vote RPC transport failed: {0}")]
    Transport(String),
    #[error("public vote RPC response exceeds its byte cap")]
    ResponseTooLarge,
    #[error("public vote RPC response is malformed: {0}")]
    Malformed(String),
    #[error("public vote RPC returned error {code}: {message}")]
    Remote { code: i64, message: String },
    #[error("public vote RPC returned no block")]
    MissingBlock,
    #[error("public vote RPC field {0} is not a canonical hex quantity")]
    InvalidQuantity(&'static str),
}

impl PublicVoteRpcErrorV1 {
    const fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Transport(_) | Self::Remote { .. } | Self::MissingBlock
        )
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_suggestion_above_the_ceiling_is_signed_at_the_ceiling() {
        let suggested = MAX_OCOMP_SIGNER_MAX_FEE_PER_GAS + 2;
        let fee = fee_within_envelope(
            suggested,
            MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS,
            MAX_OCOMP_SIGNER_MAX_FEE_PER_GAS,
        );
        assert_eq!(fee, MAX_OCOMP_SIGNER_MAX_FEE_PER_GAS);
    }

    #[test]
    fn a_suggestion_below_the_floor_is_signed_at_the_floor() {
        let fee = fee_within_envelope(
            0,
            MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS,
            MAX_OCOMP_SIGNER_MAX_FEE_PER_GAS,
        );
        assert_eq!(fee, MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS);
    }

    #[test]
    fn every_suggestion_lands_inside_the_envelope_the_submitter_validates() {
        for suggested in [0, 1, 7, 13, 14, 15, 1_000_000, u128::MAX] {
            let fee = fee_within_envelope(
                suggested,
                MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS,
                MAX_OCOMP_SIGNER_MAX_FEE_PER_GAS,
            );
            assert!(
                (MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS..=MAX_OCOMP_SIGNER_MAX_FEE_PER_GAS)
                    .contains(&fee),
                "suggestion {suggested} left the envelope as {fee}"
            );
        }
    }

    use std::sync::{Arc, Mutex};

    use alloy_consensus::TxEip1559;
    use alloy_primitives::Bytes;
    use outbe_ocomp_protocol::{
        common::BoundedBytes,
        hash::hash_framed,
        intent::DayType,
        profile::poc_schema_limits,
        registry::HashDomain,
        result::{
            lysis_v1_empty_semantic_event_root, CarryOverCreditActionV1, CarryOverReason,
            CompletionStatus, ConservationTotalsV1, ExactCountsV1, LysisArithmeticSummaryV1,
            LysisResultV1, MetadosisCompletionSummaryV1, ResultRootsV1,
        },
    };
    use outbe_primitives::signer::OutbeEvmSigner;

    use super::*;

    const JOB_ID: B256 = B256::repeat_byte(0x21);
    const BLOCK_A: B256 = B256::repeat_byte(0x31);
    const BLOCK_B: B256 = B256::repeat_byte(0x32);

    #[test]
    fn signer_fee_cap_is_twice_the_native_protocol_floor() {
        assert_eq!(
            MAX_OCOMP_SIGNER_MAX_FEE_PER_GAS,
            MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS * 2
        );
    }

    #[test]
    fn public_rpc_preserves_null_result_for_pending_receipt() {
        let response = br#"{"jsonrpc":"2.0","id":7,"result":null}"#;

        assert_eq!(
            parse_rpc_response(response, 7).expect("valid pending receipt response"),
            serde_json::Value::Null
        );
    }

    #[test]
    fn public_rpc_rejects_success_response_without_result_field() {
        let response = br#"{"jsonrpc":"2.0","id":7}"#;

        assert!(matches!(
            parse_rpc_response(response, 7),
            Err(PublicVoteRpcErrorV1::Malformed(message)) if message == "missing result"
        ));
    }

    fn test_result(limits: &SchemaLimits) -> LysisResultV1 {
        let roots = ResultRootsV1 {
            nod_root: B256::repeat_byte(0x31),
            bucket_root: B256::repeat_byte(0x32),
            contributor_root: B256::repeat_byte(0x33),
            output_manifest_root: B256::repeat_byte(0x34),
        };
        let counts = ExactCountsV1 {
            tribute_count: 1,
            nod_count: 1,
            bucket_count: 0,
            contributor_count: 0,
            semantic_event_count: 0,
        };
        let conservation = ConservationTotalsV1 {
            tribute_nominal_total: U256::ZERO,
            eligible_nominal_total: U256::ZERO,
            day_limit: U256::ZERO,
            gratis_demand: U256::ZERO,
            gratis_supply: U256::ZERO,
            lysis_budget: U256::ZERO,
            auction_base: U256::ZERO,
            nod_gratis_consumed: U256::ZERO,
            unused_lysis: U256::ZERO,
            carry_over_credit: U256::ZERO,
            nod_cost_total: U256::ZERO,
        };
        let summary = LysisArithmeticSummaryV1 {
            input_manifest_hash: B256::repeat_byte(0x35),
            plan_hash: B256::repeat_byte(0x36),
            unit_artifact_root: B256::repeat_byte(0x37),
            fidelity_fraction_root: B256::repeat_byte(0x38),
            gratis_prefix_root: B256::repeat_byte(0x39),
            roots: roots.clone(),
            counts: counts.clone(),
            conservation: conservation.clone(),
            first_error_ordinal: None,
        };
        LysisResultV1 {
            protocol_bundle_hash: B256::repeat_byte(0x20),
            job_id: JOB_ID,
            attempt: 0,
            input_manifest_hash: summary.input_manifest_hash,
            plan_hash: summary.plan_hash,
            unit_artifact_root: summary.unit_artifact_root,
            fidelity_fraction_root: summary.fidelity_fraction_root,
            gratis_prefix_root: summary.gratis_prefix_root,
            result_chunk_count: 1,
            result_chunk_list_root: B256::repeat_byte(0x3a),
            carry_over_credit: CarryOverCreditActionV1 {
                source_wwd: 1,
                reason: CarryOverReason::UnusedLysis,
                amount: U256::ZERO,
            },
            metadosis_completion_summary: MetadosisCompletionSummaryV1 {
                wwd: 1,
                pending_nonce: 0,
                day_type: DayType::Green,
                tribute_nominal_total: U256::ZERO,
                day_limit: U256::ZERO,
                gratis_demand: U256::ZERO,
                gratis_supply: U256::ZERO,
                lysis_budget: U256::ZERO,
                auction_base: U256::ZERO,
                nod_gratis_consumed: U256::ZERO,
                unused_lysis: U256::ZERO,
                carry_over_credit: U256::ZERO,
                status: CompletionStatus::Completed,
                logical_evaluation_height: 1,
                logical_evaluation_time: 1,
            },
            tribute_count: 1,
            tribute_nominal_total: U256::ZERO,
            unused_lysis: U256::ZERO,
            roots,
            counts,
            conservation,
            arithmetic_commitment: hash_framed(
                HashDomain::LysisArithmetic,
                &summary.encode_canonical(limits).unwrap(),
            )
            .unwrap(),
            event_summary_hash: lysis_v1_empty_semantic_event_root().unwrap(),
        }
    }

    fn canonical_result() -> Vec<u8> {
        let limits = poc_schema_limits();
        test_result(&limits).encode_canonical(&limits).unwrap()
    }

    fn result_digest() -> B256 {
        let limits = poc_schema_limits();
        test_result(&limits).result_digest(&limits).unwrap()
    }

    fn finalized_job_spec() -> FinalizedJobSpecV1 {
        use outbe_ocomp_protocol::control::FinalizedJobSummaryV1;

        FinalizedJobSpecV1 {
            summary: FinalizedJobSummaryV1 {
                cursor: 1,
                job_id: JOB_ID,
                intent_id: B256::repeat_byte(0x40),
                finalized_block_hash: B256::repeat_byte(0x41),
                finalized_state_root: B256::repeat_byte(0x42),
                protocol_bundle_hash: B256::repeat_byte(0x20),
                open_height: 1,
                deadline_height: 100,
            },
            canonical_job_intent: BoundedBytes(Vec::new()),
        }
    }

    struct FakePreparer {
        signer: OutbeEvmSigner,
        target: Address,
        calls: Arc<AtomicU64>,
        limits: SchemaLimits,
    }

    impl VoteTransactionPreparerV1 for FakePreparer {
        type Error = std::io::Error;

        fn prepare_vote_transaction(
            &self,
            _canonical_result: &[u8],
            _finalized: &FinalizedJobSpecV1,
            _canonical_height: u64,
            nonce: u64,
            max_fee_per_gas: u128,
            gas_limit: u64,
        ) -> Result<PreparedVoteTransactionV1, Self::Error> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let result = test_result(&self.limits);
            let vote = ResultVoteV1 {
                protocol_bundle_hash: result.protocol_bundle_hash,
                job_id: result.job_id,
                attempt: result.attempt,
                result_validator_set_epoch: 7,
                result_committee_set_hash: B256::repeat_byte(0x41),
                result_ocomp_binding_hash: B256::repeat_byte(0x42),
                ocomp_key_hash: B256::repeat_byte(0x43),
                key_epoch: 1,
                result,
                signature_rs: [0; 64],
            };
            let canonical_vote = vote
                .encode_canonical(&self.limits)
                .map_err(std::io::Error::other)?;
            let calldata = encode_submit_lysis_result_calldata(&vote, &self.limits)
                .map_err(std::io::Error::other)?;
            let signed = self
                .signer
                .sign_eip1559(TxEip1559 {
                    chain_id: 42,
                    nonce,
                    gas_limit,
                    max_fee_per_gas,
                    max_priority_fee_per_gas: 0,
                    to: TxKind::Call(self.target),
                    value: U256::ZERO,
                    input: Bytes::from(calldata),
                    access_list: Default::default(),
                })
                .map_err(std::io::Error::other)?;
            let transaction_hash = *signed.hash();
            let mut raw_transaction = Vec::with_capacity(signed.encode_2718_len());
            signed.encode_2718(&mut raw_transaction);
            Ok(PreparedVoteTransactionV1 {
                canonical_vote: BoundedBytes(canonical_vote),
                raw_transaction: BoundedBytes(raw_transaction),
                transaction_hash,
            })
        }
    }

    #[derive(Clone)]
    struct FakeRpc {
        state: Arc<Mutex<FakeRpcState>>,
    }

    struct FakeRpcState {
        receipt: Option<VoteReceiptV1>,
        canonical: Option<VoteBlockV1>,
        finalized: VoteBlockV1,
        broadcasts: usize,
    }

    impl FakeRpc {
        fn new() -> Self {
            Self {
                state: Arc::new(Mutex::new(FakeRpcState {
                    receipt: None,
                    canonical: None,
                    finalized: VoteBlockV1 {
                        number: 0,
                        hash: B256::ZERO,
                    },
                    broadcasts: 0,
                })),
            }
        }

        fn orphan(&self) {
            let mut state = self.state.lock().expect("fake RPC state");
            state.receipt = None;
            state.canonical = None;
        }

        fn finalize(&self, number: u64, hash: B256) {
            self.state.lock().expect("fake RPC state").finalized = VoteBlockV1 { number, hash };
        }

        fn broadcasts(&self) -> usize {
            self.state.lock().expect("fake RPC state").broadcasts
        }
    }

    impl VoteSubmissionRpcV1 for FakeRpc {
        type Error = std::io::Error;

        fn chain_id(&self) -> Result<u64, Self::Error> {
            Ok(42)
        }

        fn canonical_nonce(&self, _address: Address) -> Result<u64, Self::Error> {
            Ok(7)
        }

        fn gas_price(&self) -> Result<u128, Self::Error> {
            Ok(MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS)
        }

        fn send_raw_transaction(
            &self,
            raw_transaction: &[u8],
            expected_hash: B256,
        ) -> Result<B256, Self::Error> {
            if raw_transaction.is_empty() {
                return Err(std::io::Error::other("empty transaction"));
            }
            let mut state = self.state.lock().expect("fake RPC state");
            state.broadcasts += 1;
            if let Some(receipt) = state.receipt.as_mut() {
                receipt.transaction_hash = expected_hash;
            }
            Ok(expected_hash)
        }

        fn transaction_receipt(
            &self,
            _transaction_hash: B256,
        ) -> Result<Option<VoteReceiptV1>, Self::Error> {
            Ok(self.state.lock().expect("fake RPC state").receipt)
        }

        fn canonical_block(&self, _number: u64) -> Result<Option<VoteBlockV1>, Self::Error> {
            Ok(self.state.lock().expect("fake RPC state").canonical)
        }

        fn finalized_block(&self) -> Result<VoteBlockV1, Self::Error> {
            Ok(self.state.lock().expect("fake RPC state").finalized)
        }
    }

    fn fixture(
        root: &Path,
        target: Address,
    ) -> (
        SupervisorVoteSubmitterV1<FakeRpc>,
        FakeRpc,
        FakePreparer,
        Arc<AtomicU64>,
    ) {
        let signer = OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(9))
            .expect("validator EVM test signer");
        let sender_address = signer.address();
        let rpc = FakeRpc::new();
        let calls = Arc::new(AtomicU64::new(0));
        let preparer = FakePreparer {
            signer,
            target,
            calls: calls.clone(),
            limits: poc_schema_limits(),
        };
        let submitter = SupervisorVoteSubmitterV1::open(
            VoteSubmissionConfigV1 {
                journal_root: root.to_path_buf(),
                expected_chain_id: 42,
                sender_address,
                limits: poc_schema_limits(),
            },
            rpc.clone(),
        )
        .expect("vote submitter");
        (submitter, rpc, preparer, calls)
    }

    #[test]
    fn ocm_pub_001_journals_prepare_submit_include_and_finalize_across_restart() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (mut submitter, rpc, preparer, calls) = fixture(directory.path(), METADOSIS_ADDRESS);

        assert_eq!(
            submitter
                .reconcile(
                    &preparer,
                    JOB_ID,
                    result_digest(),
                    &canonical_result(),
                    &finalized_job_spec(),
                )
                .unwrap(),
            VoteSubmissionOutcomeV1::Prepared
        );
        assert_eq!(rpc.broadcasts(), 0);
        assert_eq!(
            submitter
                .reconcile(
                    &preparer,
                    JOB_ID,
                    result_digest(),
                    &canonical_result(),
                    &finalized_job_spec(),
                )
                .unwrap(),
            VoteSubmissionOutcomeV1::Submitted
        );
        assert_eq!(rpc.broadcasts(), 1);

        let transaction_hash = submitter
            .journal
            .load(JOB_ID)
            .unwrap()
            .unwrap()
            .transaction_hash;
        {
            let mut state = rpc.state.lock().expect("fake RPC state");
            state.receipt = Some(VoteReceiptV1 {
                transaction_hash,
                block_number: 10,
                block_hash: BLOCK_A,
                success: true,
            });
            state.canonical = Some(VoteBlockV1 {
                number: 10,
                hash: BLOCK_A,
            });
        }
        assert_eq!(
            submitter
                .reconcile(
                    &preparer,
                    JOB_ID,
                    result_digest(),
                    &canonical_result(),
                    &finalized_job_spec(),
                )
                .unwrap(),
            VoteSubmissionOutcomeV1::Included(VoteInclusionV1 {
                block_number: 10,
                block_hash: BLOCK_A,
                success: true,
            })
        );
        rpc.finalize(9, B256::repeat_byte(9));
        assert!(matches!(
            submitter
                .reconcile(
                    &preparer,
                    JOB_ID,
                    result_digest(),
                    &canonical_result(),
                    &finalized_job_spec(),
                )
                .unwrap(),
            VoteSubmissionOutcomeV1::Included(_)
        ));
        rpc.finalize(10, BLOCK_A);
        assert!(matches!(
            submitter
                .reconcile(
                    &preparer,
                    JOB_ID,
                    result_digest(),
                    &canonical_result(),
                    &finalized_job_spec(),
                )
                .unwrap(),
            VoteSubmissionOutcomeV1::Finalized(VoteInclusionV1 { success: true, .. })
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        drop(submitter);
        let signer = OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(9))
            .expect("validator EVM test signer");
        let mut restarted = SupervisorVoteSubmitterV1::open(
            VoteSubmissionConfigV1 {
                journal_root: directory.path().to_path_buf(),
                expected_chain_id: 42,
                sender_address: signer.address(),
                limits: poc_schema_limits(),
            },
            rpc,
        )
        .expect("restarted vote submitter");
        assert!(matches!(
            restarted
                .reconcile(
                    &preparer,
                    JOB_ID,
                    result_digest(),
                    &canonical_result(),
                    &finalized_job_spec(),
                )
                .unwrap(),
            VoteSubmissionOutcomeV1::Finalized(_)
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ocm_pub_001_orphaned_inclusion_demotes_and_rebroadcasts_identical_transaction() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (mut submitter, rpc, preparer, _) = fixture(directory.path(), METADOSIS_ADDRESS);
        submitter
            .reconcile(
                &preparer,
                JOB_ID,
                result_digest(),
                &canonical_result(),
                &finalized_job_spec(),
            )
            .unwrap();
        submitter
            .reconcile(
                &preparer,
                JOB_ID,
                result_digest(),
                &canonical_result(),
                &finalized_job_spec(),
            )
            .unwrap();
        let transaction_hash = submitter
            .journal
            .load(JOB_ID)
            .unwrap()
            .unwrap()
            .transaction_hash;
        {
            let mut state = rpc.state.lock().expect("fake RPC state");
            state.receipt = Some(VoteReceiptV1 {
                transaction_hash,
                block_number: 10,
                block_hash: BLOCK_A,
                success: true,
            });
            state.canonical = Some(VoteBlockV1 {
                number: 10,
                hash: BLOCK_A,
            });
        }
        submitter
            .reconcile(
                &preparer,
                JOB_ID,
                result_digest(),
                &canonical_result(),
                &finalized_job_spec(),
            )
            .unwrap();
        rpc.orphan();
        assert_eq!(
            submitter
                .reconcile(
                    &preparer,
                    JOB_ID,
                    result_digest(),
                    &canonical_result(),
                    &finalized_job_spec(),
                )
                .unwrap(),
            VoteSubmissionOutcomeV1::Submitted
        );
        assert_eq!(rpc.broadcasts(), 2);

        {
            let mut state = rpc.state.lock().expect("fake RPC state");
            state.receipt = Some(VoteReceiptV1 {
                transaction_hash,
                block_number: 12,
                block_hash: BLOCK_B,
                success: true,
            });
            state.canonical = Some(VoteBlockV1 {
                number: 12,
                hash: BLOCK_B,
            });
        }
        assert!(matches!(
            submitter
                .reconcile(
                    &preparer,
                    JOB_ID,
                    result_digest(),
                    &canonical_result(),
                    &finalized_job_spec(),
                )
                .unwrap(),
            VoteSubmissionOutcomeV1::Included(VoteInclusionV1 {
                block_number: 12,
                block_hash: BLOCK_B,
                ..
            })
        ));
        rpc.finalize(12, BLOCK_B);
        assert!(matches!(
            submitter
                .reconcile(
                    &preparer,
                    JOB_ID,
                    result_digest(),
                    &canonical_result(),
                    &finalized_job_spec(),
                )
                .unwrap(),
            VoteSubmissionOutcomeV1::Finalized(_)
        ));
    }

    #[test]
    fn ocm_pub_001_rejects_a_locally_signed_transaction_with_any_other_target() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let wrong_target = Address::repeat_byte(0x44);
        let (mut submitter, rpc, preparer, _) = fixture(directory.path(), wrong_target);
        assert!(matches!(
            submitter.reconcile(
                &preparer,
                JOB_ID,
                result_digest(),
                &canonical_result(),
                &finalized_job_spec(),
            ),
            Err(VoteSubmissionErrorV1::InvalidPreparedTransaction(_))
        ));
        assert_eq!(rpc.broadcasts(), 0);
        assert!(submitter.journal.load(JOB_ID).unwrap().is_none());
    }

    #[test]
    fn vote_submission_journal_rejects_one_byte_tampering() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (mut submitter, _, preparer, _) = fixture(directory.path(), METADOSIS_ADDRESS);
        submitter
            .reconcile(
                &preparer,
                JOB_ID,
                result_digest(),
                &canonical_result(),
                &finalized_job_spec(),
            )
            .unwrap();
        let path = submitter.journal.record_path(JOB_ID);
        drop(submitter);
        let mut bytes = fs::read(&path).expect("journal bytes");
        bytes[40] ^= 1;
        fs::write(&path, bytes).expect("tamper journal");
        let signer = OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(9))
            .expect("validator EVM test signer");
        let rpc = FakeRpc::new();
        let submitter = SupervisorVoteSubmitterV1::open(
            VoteSubmissionConfigV1 {
                journal_root: directory.path().to_path_buf(),
                expected_chain_id: 42,
                sender_address: signer.address(),
                limits: poc_schema_limits(),
            },
            rpc,
        )
        .expect("reopen journal root");
        assert!(matches!(
            submitter.journal.load(JOB_ID),
            Err(VoteSubmissionErrorV1::JournalChecksumMismatch)
        ));
    }

    #[test]
    fn public_vote_nonce_targets_canonical_state_instead_of_pending_state() {
        assert_eq!(
            canonical_nonce_params(Address::repeat_byte(0x44)),
            serde_json::json!([format!("{:#x}", Address::repeat_byte(0x44)), "latest"])
        );
    }

    struct NonceRecordingPreparer {
        inner: FakePreparer,
        last_nonce: Arc<AtomicU64>,
    }

    impl VoteTransactionPreparerV1 for NonceRecordingPreparer {
        type Error = std::io::Error;

        fn prepare_vote_transaction(
            &self,
            canonical_result: &[u8],
            finalized: &FinalizedJobSpecV1,
            canonical_height: u64,
            nonce: u64,
            max_fee_per_gas: u128,
            gas_limit: u64,
        ) -> Result<PreparedVoteTransactionV1, Self::Error> {
            self.last_nonce.store(nonce, Ordering::SeqCst);
            self.inner.prepare_vote_transaction(
                canonical_result,
                finalized,
                canonical_height,
                nonce,
                max_fee_per_gas,
                gas_limit,
            )
        }
    }

    /// Unlike [`FakeRpc`], the account nonce can move under a journaled envelope.
    #[derive(Clone)]
    struct NonceRpc {
        state: Arc<Mutex<NonceRpcState>>,
    }

    struct NonceRpcState {
        nonce: u64,
        fail_chain_id_once: bool,
        receipt: Option<VoteReceiptV1>,
        canonical: Option<VoteBlockV1>,
        finalized: VoteBlockV1,
        broadcasts: usize,
    }

    impl NonceRpc {
        fn new() -> Self {
            Self {
                state: Arc::new(Mutex::new(NonceRpcState {
                    nonce: 7,
                    fail_chain_id_once: false,
                    receipt: None,
                    canonical: None,
                    finalized: VoteBlockV1 {
                        number: 0,
                        hash: B256::ZERO,
                    },
                    broadcasts: 0,
                })),
            }
        }

        fn bypass_nonce(&self, nonce: u64) {
            self.state.lock().unwrap().nonce = nonce;
        }

        fn fail_next_chain_id(&self) {
            self.state.lock().unwrap().fail_chain_id_once = true;
        }

        fn include(&self, transaction_hash: B256) {
            self.include_with_status(transaction_hash, true);
        }

        fn include_with_status(&self, transaction_hash: B256, success: bool) {
            let mut state = self.state.lock().unwrap();
            state.receipt = Some(VoteReceiptV1 {
                transaction_hash,
                block_number: 1,
                block_hash: BLOCK_A,
                success,
            });
            state.canonical = Some(VoteBlockV1 {
                number: 1,
                hash: BLOCK_A,
            });
        }

        fn finalize(&self, number: u64, hash: B256) {
            self.state.lock().unwrap().finalized = VoteBlockV1 { number, hash };
        }

        fn broadcasts(&self) -> usize {
            self.state.lock().unwrap().broadcasts
        }
    }

    impl VoteSubmissionRpcV1 for NonceRpc {
        type Error = std::io::Error;

        fn chain_id(&self) -> Result<u64, Self::Error> {
            let mut state = self.state.lock().unwrap();
            if state.fail_chain_id_once {
                state.fail_chain_id_once = false;
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "transient RPC outage",
                ));
            }
            Ok(42)
        }

        fn canonical_nonce(&self, _address: Address) -> Result<u64, Self::Error> {
            Ok(self.state.lock().unwrap().nonce)
        }

        fn gas_price(&self) -> Result<u128, Self::Error> {
            Ok(outbe_ocomp_protocol::system_carrier::MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS)
        }

        fn send_raw_transaction(
            &self,
            _raw_transaction: &[u8],
            expected_hash: B256,
        ) -> Result<B256, Self::Error> {
            self.state.lock().unwrap().broadcasts += 1;
            Ok(expected_hash)
        }

        fn transaction_receipt(
            &self,
            _transaction_hash: B256,
        ) -> Result<Option<VoteReceiptV1>, Self::Error> {
            Ok(self.state.lock().unwrap().receipt)
        }

        fn canonical_block(&self, _number: u64) -> Result<Option<VoteBlockV1>, Self::Error> {
            Ok(self.state.lock().unwrap().canonical)
        }

        fn finalized_block(&self) -> Result<VoteBlockV1, Self::Error> {
            Ok(self.state.lock().unwrap().finalized)
        }
    }

    fn nonce_fixture(
        root: &Path,
    ) -> (
        SupervisorVoteSubmitterV1<NonceRpc>,
        NonceRpc,
        NonceRecordingPreparer,
        Arc<AtomicU64>,
        Arc<AtomicU64>,
    ) {
        let signer = OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(9))
            .expect("test signer");
        let sender_address = signer.address();
        let rpc = NonceRpc::new();
        let calls = Arc::new(AtomicU64::new(0));
        let last_nonce = Arc::new(AtomicU64::new(u64::MAX));
        let preparer = NonceRecordingPreparer {
            inner: FakePreparer {
                signer,
                target: METADOSIS_ADDRESS,
                calls: calls.clone(),
                limits: poc_schema_limits(),
            },
            last_nonce: last_nonce.clone(),
        };
        let submitter = SupervisorVoteSubmitterV1::open(
            VoteSubmissionConfigV1 {
                journal_root: root.to_path_buf(),
                expected_chain_id: 42,
                sender_address,
                limits: poc_schema_limits(),
            },
            rpc.clone(),
        )
        .expect("vote submitter");
        (submitter, rpc, preparer, calls, last_nonce)
    }

    fn heal_reconcile(
        submitter: &mut SupervisorVoteSubmitterV1<NonceRpc>,
        preparer: &NonceRecordingPreparer,
    ) -> VoteSubmissionOutcomeV1 {
        submitter
            .reconcile(
                preparer,
                JOB_ID,
                result_digest(),
                &canonical_result(),
                &finalized_job_spec(),
            )
            .expect("reconcile")
    }

    fn journaled_calldata(record: &VoteSubmissionRecordV1) -> Bytes {
        let mut encoded = record.raw_transaction.as_slice();
        let transaction = EthereumTxEnvelope::<TxEip4844>::decode_2718(&mut encoded)
            .expect("journaled transaction decodes");
        assert!(encoded.is_empty());
        transaction.input().clone()
    }

    #[test]
    fn a_bypassed_nonce_rebuilds_the_vote_from_the_prepared_stage() {
        let directory = tempfile::tempdir().unwrap();
        let (mut submitter, rpc, preparer, calls, last_nonce) = nonce_fixture(directory.path());

        assert_eq!(
            heal_reconcile(&mut submitter, &preparer),
            VoteSubmissionOutcomeV1::Prepared
        );
        assert_eq!(last_nonce.load(Ordering::SeqCst), 7);
        let first = submitter.journal.load(JOB_ID).unwrap().unwrap();

        rpc.bypass_nonce(8);
        assert_eq!(
            heal_reconcile(&mut submitter, &preparer),
            VoteSubmissionOutcomeV1::Prepared
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(last_nonce.load(Ordering::SeqCst), 8);
        let replacement = submitter.journal.load(JOB_ID).unwrap().unwrap();
        assert_eq!(journaled_calldata(&replacement), journaled_calldata(&first));
        assert_ne!(replacement.transaction_hash, first.transaction_hash);
        assert!(replacement.generation > first.generation);

        assert_eq!(
            heal_reconcile(&mut submitter, &preparer),
            VoteSubmissionOutcomeV1::Submitted
        );
        assert_eq!(rpc.broadcasts(), 1);
    }

    #[test]
    fn durable_journal_exposes_stage_age_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let (mut submitter, rpc, preparer, _, _) = nonce_fixture(directory.path());

        assert_eq!(
            heal_reconcile(&mut submitter, &preparer),
            VoteSubmissionOutcomeV1::Prepared
        );
        assert!(submitter.journal.stage_age(JOB_ID).is_some());

        drop(submitter);
        let signer = OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(9))
            .expect("test signer");
        let restarted = SupervisorVoteSubmitterV1::open(
            VoteSubmissionConfigV1 {
                journal_root: directory.path().to_path_buf(),
                expected_chain_id: 42,
                sender_address: signer.address(),
                limits: poc_schema_limits(),
            },
            rpc,
        )
        .expect("restarted vote submitter");
        assert!(restarted.journal.stage_age(JOB_ID).is_some());
    }

    #[test]
    fn a_bypassed_nonce_rebuilds_the_vote_from_the_submitted_stage() {
        let directory = tempfile::tempdir().unwrap();
        let (mut submitter, rpc, preparer, calls, last_nonce) = nonce_fixture(directory.path());

        assert_eq!(
            heal_reconcile(&mut submitter, &preparer),
            VoteSubmissionOutcomeV1::Prepared
        );
        assert_eq!(
            heal_reconcile(&mut submitter, &preparer),
            VoteSubmissionOutcomeV1::Submitted
        );
        let first = submitter.journal.load(JOB_ID).unwrap().unwrap();

        rpc.bypass_nonce(9);
        assert_eq!(
            heal_reconcile(&mut submitter, &preparer),
            VoteSubmissionOutcomeV1::Prepared
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(last_nonce.load(Ordering::SeqCst), 9);
        let replacement = submitter.journal.load(JOB_ID).unwrap().unwrap();
        assert_eq!(journaled_calldata(&replacement), journaled_calldata(&first));
        assert_ne!(replacement.transaction_hash, first.transaction_hash);
        assert!(replacement.generation > first.generation);
    }

    #[test]
    fn an_included_receipt_wins_over_the_advanced_nonce() {
        let directory = tempfile::tempdir().unwrap();
        let (mut submitter, rpc, preparer, calls, _) = nonce_fixture(directory.path());

        assert_eq!(
            heal_reconcile(&mut submitter, &preparer),
            VoteSubmissionOutcomeV1::Prepared
        );
        assert_eq!(
            heal_reconcile(&mut submitter, &preparer),
            VoteSubmissionOutcomeV1::Submitted
        );

        // Our own envelope landed: the receipt must keep the record.
        let transaction_hash = preparer
            .prepare_vote_transaction(
                &canonical_result(),
                &finalized_job_spec(),
                1,
                7,
                outbe_ocomp_protocol::system_carrier::MIN_OCOMP_SYSTEM_CARRIER_MAX_FEE_PER_GAS,
                outbe_ocomp_protocol::system_carrier::OCOMP_SYSTEM_CARRIER_GAS_LIMIT,
            )
            .unwrap()
            .transaction_hash;
        rpc.bypass_nonce(8);
        rpc.include(transaction_hash);

        assert!(matches!(
            heal_reconcile(&mut submitter, &preparer),
            VoteSubmissionOutcomeV1::Included(_)
        ));
        // Two prepare calls: the fixture one plus the hash probe above.
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_healthy_nonce_keeps_rebroadcasting_the_same_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let (mut submitter, rpc, preparer, calls, _) = nonce_fixture(directory.path());

        assert_eq!(
            heal_reconcile(&mut submitter, &preparer),
            VoteSubmissionOutcomeV1::Prepared
        );
        assert_eq!(
            heal_reconcile(&mut submitter, &preparer),
            VoteSubmissionOutcomeV1::Submitted
        );
        assert_eq!(
            heal_reconcile(&mut submitter, &preparer),
            VoteSubmissionOutcomeV1::Submitted
        );
        assert_eq!(rpc.broadcasts(), 2);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_finalized_revert_prepares_a_fresh_vote_envelope() {
        let directory = tempfile::tempdir().unwrap();
        let (mut submitter, rpc, preparer, calls, last_nonce) = nonce_fixture(directory.path());

        assert_eq!(
            heal_reconcile(&mut submitter, &preparer),
            VoteSubmissionOutcomeV1::Prepared
        );
        assert_eq!(
            heal_reconcile(&mut submitter, &preparer),
            VoteSubmissionOutcomeV1::Submitted
        );
        let first = submitter.journal.load(JOB_ID).unwrap().unwrap();
        rpc.include_with_status(first.transaction_hash, false);
        assert!(matches!(
            heal_reconcile(&mut submitter, &preparer),
            VoteSubmissionOutcomeV1::Included(VoteInclusionV1 { success: false, .. })
        ));

        rpc.bypass_nonce(8);
        rpc.finalize(1, BLOCK_A);
        assert_eq!(
            heal_reconcile(&mut submitter, &preparer),
            VoteSubmissionOutcomeV1::Prepared
        );
        let replacement = submitter.journal.load(JOB_ID).unwrap().unwrap();
        assert_eq!(replacement.stage, VoteSubmissionStageV1::Prepared);
        assert!(replacement.generation > first.generation);
        assert_eq!(replacement.nonce, 8);
        assert_ne!(replacement.transaction_hash, first.transaction_hash);
        assert_eq!(last_nonce.load(Ordering::SeqCst), 8);
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        drop(submitter);
        let signer = OutbeEvmSigner::from_secret_bytes(outbe_primitives::test_keys::secret(9))
            .expect("test signer");
        let restarted = SupervisorVoteSubmitterV1::open(
            VoteSubmissionConfigV1 {
                journal_root: directory.path().to_path_buf(),
                expected_chain_id: 42,
                sender_address: signer.address(),
                limits: poc_schema_limits(),
            },
            rpc,
        )
        .expect("restarted vote submitter");
        assert_eq!(
            restarted.journal.load(JOB_ID).unwrap().unwrap(),
            replacement
        );
    }

    #[test]
    fn submission_error_classification_is_fail_closed() {
        assert_eq!(
            rpc_error(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "temporarily unavailable",
            ))
            .class(),
            VoteSubmissionFailureClassV1::Retryable
        );
        assert_eq!(
            rpc_error(PublicVoteRpcErrorV1::Malformed(
                "invalid receipt".to_owned()
            ))
            .class(),
            VoteSubmissionFailureClassV1::Unrecoverable
        );
        for error in [
            VoteSubmissionErrorV1::Preparer("invalid attestation".to_owned()),
            VoteSubmissionErrorV1::InvalidJournal,
            VoteSubmissionErrorV1::JournalChecksumMismatch,
            VoteSubmissionErrorV1::DifferentResultForJournaledJob,
        ] {
            assert_eq!(error.class(), VoteSubmissionFailureClassV1::Unrecoverable);
        }
    }

    #[test]
    fn a_retryable_rpc_failure_recovers_without_journaling_partial_state() {
        let directory = tempfile::tempdir().unwrap();
        let (mut submitter, rpc, preparer, calls, _) = nonce_fixture(directory.path());
        rpc.fail_next_chain_id();

        let error = submitter
            .reconcile(
                &preparer,
                JOB_ID,
                result_digest(),
                &canonical_result(),
                &finalized_job_spec(),
            )
            .expect_err("first RPC probe fails");
        assert_eq!(error.class(), VoteSubmissionFailureClassV1::Retryable);
        assert!(submitter.journal.load(JOB_ID).unwrap().is_none());

        assert_eq!(
            heal_reconcile(&mut submitter, &preparer),
            VoteSubmissionOutcomeV1::Prepared
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
