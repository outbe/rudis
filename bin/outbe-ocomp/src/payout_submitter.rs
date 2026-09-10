//! Restart-safe public submission of certified contributor payout batches.
//!
//! Discovery is stateless: candidate days are dates, finalized chain state
//! answers everything else, and the paid-leaf bitmap is the only progress.
//! A day is refused unless the artifact's root, count and total match the
//! certified values. Payouts share the role-delegated key with result votes,
//! so the caller must not run a tick while vote work is pending, and one tick
//! drives its batch to finality before yielding the nonce. The gate is
//! best-effort across a restart; the nonce self-heal on both machines closes
//! the residual overlap.

use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    },
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use alloy_consensus::{
    transaction::SignerRecoverable as _, EthereumTxEnvelope, Transaction as _, TxEip1559, TxEip4844,
};
use alloy_eips::eip2718::{Decodable2718 as _, Encodable2718 as _};
use alloy_primitives::{keccak256, Address, Bytes, TxKind, B256, U256};
use alloy_sol_types::SolCall;
use outbe_intex::payout::{
    contributor_list_root, decode_contributor_leaf, CONTRIBUTOR_CHUNK_CAPACITY,
    CONTRIBUTOR_LEAF_BYTES,
};
use outbe_intex::precompile::IIntex;
use outbe_intexfactory::precompile::IIntexFactory;
use outbe_metadosis::precompile::IMetadosis;
use outbe_ocomp_protocol::state::ActiveGenerationV1;
use outbe_ocomp_protocol::SchemaLimits;
use outbe_primitives::addresses::{INTEX_ADDRESS, INTEX_FACTORY_ADDRESS, METADOSIS_ADDRESS};
use outbe_primitives::signer::{OutbeEvmSigner, SignerError};
use thiserror::Error;

use crate::payout_artifact::CONTRIBUTOR_PAYOUT_ARTIFACT_FILE;
use crate::vote_submitter::{
    fee_within_envelope, PublicVoteRpcClientV1, VoteInclusionV1, VoteSubmissionRpcV1,
    MAX_OCOMP_SIGNER_MAX_FEE_PER_GAS,
};

const JOURNAL_MAGIC: [u8; 8] = *b"OUTBPAY1";
const JOURNAL_VERSION: u16 = 1;
const JOURNAL_LOCK_FILE: &str = "payout-submissions.lock";
/// One full 256-leaf batch is ~34 KiB of calldata before the envelope.
const MAX_RAW_PAYOUT_TRANSACTION_BYTES: usize = 64 * 1024;
const JOURNAL_FIXED_BYTES_WITHOUT_RAW: usize = 8 + 2 + 8 + 1 + 4 + 4 + 4 + 20 + 8 + 16 + 32 + 4 + 1;
const INCLUSION_BYTES: usize = 8 + 32 + 1;
const JOURNAL_CHECKSUM_BYTES: usize = 32;
const REVERT_BACKOFF_CAP: Duration = Duration::from_secs(600);
/// One tick drives its batch to finality so the shared nonce is never left
/// pinned under a pending payout when vote work arrives.
const FINALITY_WAIT: Duration = Duration::from_secs(30);
const FINALITY_POLL: Duration = Duration::from_millis(500);

#[derive(Clone, Debug)]
pub struct PayoutSubmissionConfigV1 {
    pub journal_root: PathBuf,
    pub job_root: PathBuf,
    pub expected_chain_id: u64,
    pub sender_address: Address,
    pub limits: SchemaLimits,
}

/// State reads the payout sender needs on top of the vote delivery surface.
pub trait PayoutSubmissionRpcV1: VoteSubmissionRpcV1 {
    fn call_contract(&self, to: Address, data: &[u8]) -> Result<Vec<u8>, Self::Error>;
}

impl PayoutSubmissionRpcV1 for PublicVoteRpcClientV1 {
    fn call_contract(&self, to: Address, data: &[u8]) -> Result<Vec<u8>, Self::Error> {
        self.call_contract_finalized(to, data)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayoutSubmissionStageV1 {
    Prepared,
    Submitted,
    Included,
    Finalized,
}

impl PayoutSubmissionStageV1 {
    const fn code(self) -> u8 {
        match self {
            Self::Prepared => 1,
            Self::Submitted => 2,
            Self::Included => 3,
            Self::Finalized => 4,
        }
    }

    const fn from_code(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Prepared),
            2 => Some(Self::Submitted),
            3 => Some(Self::Included),
            4 => Some(Self::Finalized),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PayoutSubmissionRecordV1 {
    pub generation: u64,
    pub stage: PayoutSubmissionStageV1,
    pub worldwide_day: u32,
    pub start_index: u32,
    pub leaf_count: u32,
    pub sender_address: Address,
    pub nonce: u64,
    pub max_fee_per_gas: u128,
    pub transaction_hash: B256,
    pub raw_transaction: Vec<u8>,
    pub inclusion: Option<VoteInclusionV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PayoutTickOutcomeV1 {
    /// No open round with unpaid leaves inside the lookback window.
    Idle,
    /// A batch is being delivered and the tick ended before finality.
    InFlight {
        worldwide_day: u32,
        start_index: u32,
    },
    /// The batch receipt is final; `success` is the receipt status. A reverted
    /// receipt is the normal lost first-wins race against another validator.
    Finalized {
        worldwide_day: u32,
        start_index: u32,
        success: bool,
    },
}

#[derive(Debug, Error)]
pub enum PayoutSubmissionErrorV1 {
    #[error("payout journal {context} at {path}: {source}")]
    Io {
        context: &'static str,
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("payout RPC failed: {0}")]
    Rpc(String),
    #[error("payout RPC chain id mismatch: expected {expected}, actual {actual}")]
    WrongRpcChain { expected: u64, actual: u64 },
    #[error("payout journal record is invalid")]
    InvalidJournal,
    #[error("payout journal is ambiguous at {0}")]
    AmbiguousJournal(PathBuf),
    #[error("payout journal record too large")]
    JournalTooLarge,
    #[error("payout journal record checksum mismatch")]
    JournalChecksumMismatch,
    #[error("payout journal generation overflow")]
    GenerationOverflow,
    #[error("payout transaction hash mismatch: expected {expected}, actual {actual}")]
    TransactionHashMismatch { expected: B256, actual: B256 },
    #[error("payout preparation failed: {0}")]
    Preparation(String),
    #[error("prepared payout transaction is invalid: {0}")]
    InvalidPreparedTransaction(String),
    #[error("payout state decode failed: {0}")]
    StateDecode(String),
}

fn io_error(context: &'static str, path: &Path, source: std::io::Error) -> PayoutSubmissionErrorV1 {
    PayoutSubmissionErrorV1::Io {
        context,
        path: path.to_path_buf(),
        source,
    }
}

fn rpc_error(error: impl std::error::Error) -> PayoutSubmissionErrorV1 {
    PayoutSubmissionErrorV1::Rpc(error.to_string())
}

fn state_error(error: impl std::fmt::Display) -> PayoutSubmissionErrorV1 {
    PayoutSubmissionErrorV1::StateDecode(error.to_string())
}

/// Signs one fixed-shape zero-fee `payContributorBatch` transaction.
pub trait PayoutTransactionPreparerV1 {
    type Error: std::error::Error;

    fn prepare_payout_transaction(
        &self,
        calldata: &[u8],
        nonce: u64,
        max_fee_per_gas: u128,
    ) -> Result<PreparedPayoutTransactionV1, Self::Error>;
}

#[derive(Clone, Debug)]
pub struct PreparedPayoutTransactionV1 {
    pub raw_transaction: Vec<u8>,
    pub transaction_hash: B256,
}

pub struct LocalPayoutTransactionPreparerV1 {
    signer: OutbeEvmSigner,
    chain_id: u64,
}

#[derive(Debug, Error)]
pub enum LocalPayoutPreparationErrorV1 {
    #[error("payout transaction chain id must not be zero")]
    InvalidChainId,
    #[error("payout transaction calldata is empty")]
    EmptyCalldata,
    #[error(
        "payout transaction fee envelope is invalid: max fee {max_fee_per_gas} outside \
         {min_fee}..={max_fee}"
    )]
    InvalidFeeEnvelope {
        max_fee_per_gas: u128,
        min_fee: u128,
        max_fee: u128,
    },
    #[error("payout transaction calldata exceeds the zero-fee cap")]
    CalldataTooLarge,
    #[error("payout transaction allocation failed")]
    Allocation,
    #[error(transparent)]
    Signer(#[from] SignerError),
}

impl LocalPayoutTransactionPreparerV1 {
    pub fn new(
        signer: OutbeEvmSigner,
        chain_id: u64,
    ) -> Result<Self, LocalPayoutPreparationErrorV1> {
        if chain_id == 0 {
            return Err(LocalPayoutPreparationErrorV1::InvalidChainId);
        }
        Ok(Self { signer, chain_id })
    }

    pub const fn sender_address(&self) -> Address {
        self.signer.address()
    }
}

impl PayoutTransactionPreparerV1 for LocalPayoutTransactionPreparerV1 {
    type Error = LocalPayoutPreparationErrorV1;

    fn prepare_payout_transaction(
        &self,
        calldata: &[u8],
        nonce: u64,
        max_fee_per_gas: u128,
    ) -> Result<PreparedPayoutTransactionV1, Self::Error> {
        if calldata.is_empty() {
            return Err(LocalPayoutPreparationErrorV1::EmptyCalldata);
        }
        if calldata.len() > outbe_zerofee::MAX_ZERO_FEE_CONTRIBUTOR_BATCH_CALLDATA_BYTES {
            return Err(LocalPayoutPreparationErrorV1::CalldataTooLarge);
        }
        if !(outbe_zerofee::MIN_ZERO_FEE_CONTRIBUTOR_BATCH_MAX_FEE_PER_GAS
            ..=MAX_OCOMP_SIGNER_MAX_FEE_PER_GAS)
            .contains(&max_fee_per_gas)
        {
            return Err(LocalPayoutPreparationErrorV1::InvalidFeeEnvelope {
                max_fee_per_gas,
                min_fee: outbe_zerofee::MIN_ZERO_FEE_CONTRIBUTOR_BATCH_MAX_FEE_PER_GAS,
                max_fee: MAX_OCOMP_SIGNER_MAX_FEE_PER_GAS,
            });
        }
        let signed = self.signer.sign_eip1559(TxEip1559 {
            chain_id: self.chain_id,
            nonce,
            gas_limit: outbe_zerofee::MAX_ZERO_FEE_CONTRIBUTOR_BATCH_GAS_LIMIT,
            max_fee_per_gas,
            max_priority_fee_per_gas: 0,
            to: TxKind::Call(INTEX_FACTORY_ADDRESS),
            value: U256::ZERO,
            input: Bytes::copy_from_slice(calldata),
            access_list: Default::default(),
        })?;
        let transaction_hash = *signed.hash();
        let mut raw_transaction = Vec::new();
        raw_transaction
            .try_reserve_exact(signed.encode_2718_len())
            .map_err(|_| LocalPayoutPreparationErrorV1::Allocation)?;
        signed.encode_2718(&mut raw_transaction);
        Ok(PreparedPayoutTransactionV1 {
            raw_transaction,
            transaction_hash,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CertifiedDayViewV1 {
    contributor_root: B256,
    contributor_count: u32,
    eligible_nominal_total: U256,
}

struct PayoutWorkV1 {
    worldwide_day: u32,
    start_index: u32,
    leaf_count: u32,
    calldata: Vec<u8>,
}

/// On-chain payments land only as whole aligned windows, so a word is either
/// fully paid for its expected bits or holds the first unpaid batch.
fn first_unpaid_batch(words: &[U256], contributor_count: u32) -> Option<(u32, u32)> {
    let mut remaining = contributor_count;
    for (index, word) in (0_u32..).zip(words.iter()) {
        let bits = remaining.min(CONTRIBUTOR_CHUNK_CAPACITY);
        if bits == 0 {
            return None;
        }
        let expected = if bits == CONTRIBUTOR_CHUNK_CAPACITY {
            U256::MAX
        } else {
            (U256::from(1_u8) << bits) - U256::from(1_u8)
        };
        if *word & expected != expected {
            return Some((index * CONTRIBUTOR_CHUNK_CAPACITY, bits));
        }
        remaining -= bits;
    }
    None
}

pub struct SupervisorPayoutSubmitterV1<R> {
    config: PayoutSubmissionConfigV1,
    rpc: R,
    journal: PayoutSubmissionJournalV1,
    open_submission: Option<(u32, u32)>,
    day_cache: Option<VerifiedDayCacheV1>,
    scan_frontier: HashMap<u32, u32>,
    skip_log: HashMap<u32, String>,
    revert_backoff: HashMap<(u32, u32), RevertBackoffV1>,
    cleaned_days: HashSet<u32>,
}

struct VerifiedDayCacheV1 {
    worldwide_day: u32,
    contributor_root: B256,
    leaves: Vec<[u8; CONTRIBUTOR_LEAF_BYTES]>,
}

struct RevertBackoffV1 {
    attempts: u32,
    retry_at: Instant,
}

impl<R: PayoutSubmissionRpcV1> SupervisorPayoutSubmitterV1<R> {
    pub fn open(config: PayoutSubmissionConfigV1, rpc: R) -> Result<Self, PayoutSubmissionErrorV1> {
        let journal = PayoutSubmissionJournalV1::open(&config.journal_root)?;
        let open_submission = journal.find_open_submission()?;
        Ok(Self {
            config,
            rpc,
            journal,
            open_submission,
            day_cache: None,
            scan_frontier: HashMap::new(),
            skip_log: HashMap::new(),
            revert_backoff: HashMap::new(),
            cleaned_days: HashSet::new(),
        })
    }

    /// Advances payout work by at most one batch.
    pub fn tick<P: PayoutTransactionPreparerV1>(
        &mut self,
        preparer: &P,
        candidate_days: &[u32],
    ) -> Result<PayoutTickOutcomeV1, PayoutSubmissionErrorV1> {
        self.skip_log.retain(|day, _| candidate_days.contains(day));
        self.scan_frontier
            .retain(|day, _| candidate_days.contains(day));
        self.cleaned_days.retain(|day| candidate_days.contains(day));
        self.revert_backoff
            .retain(|(day, _), _| candidate_days.contains(day));
        if let Some((worldwide_day, start_index)) = self.open_submission {
            let record = self
                .journal
                .load(worldwide_day, start_index)?
                .ok_or(PayoutSubmissionErrorV1::InvalidJournal)?;
            let dead = matches!(
                record.stage,
                PayoutSubmissionStageV1::Prepared | PayoutSubmissionStageV1::Submitted
            ) && self.nonce_was_bypassed(&record)?;
            if !dead {
                return self.drive_to_finality(worldwide_day, start_index);
            }
            self.open_submission = None;
        }
        let Some(work) = self.discover(candidate_days)? else {
            return Ok(PayoutTickOutcomeV1::Idle);
        };
        if let Some(prior) = self.journal.load(work.worldwide_day, work.start_index)? {
            let adoptable = match prior.stage {
                PayoutSubmissionStageV1::Included => true,
                PayoutSubmissionStageV1::Prepared | PayoutSubmissionStageV1::Submitted => {
                    !self.nonce_was_bypassed(&prior)?
                }
                PayoutSubmissionStageV1::Finalized => false,
            };
            // A live record for this window (a receipt racing the nonce view)
            // is resumed, not replaced.
            if adoptable {
                self.open_submission = Some((work.worldwide_day, work.start_index));
                return self.drive_to_finality(work.worldwide_day, work.start_index);
            }
        }
        self.prepare_and_persist(preparer, &work)?;
        self.open_submission = Some((work.worldwide_day, work.start_index));
        self.drive_to_finality(work.worldwide_day, work.start_index)
    }

    fn drive_to_finality(
        &mut self,
        worldwide_day: u32,
        start_index: u32,
    ) -> Result<PayoutTickOutcomeV1, PayoutSubmissionErrorV1> {
        let deadline = Instant::now() + FINALITY_WAIT;
        loop {
            let outcome = self.reconcile_once(worldwide_day, start_index)?;
            if let PayoutTickOutcomeV1::Finalized { success, .. } = outcome {
                self.open_submission = None;
                if success {
                    self.revert_backoff.remove(&(worldwide_day, start_index));
                    self.journal.remove(worldwide_day, start_index)?;
                } else {
                    let backoff = self
                        .revert_backoff
                        .entry((worldwide_day, start_index))
                        .or_insert(RevertBackoffV1 {
                            attempts: 0,
                            retry_at: Instant::now(),
                        });
                    backoff.attempts = backoff.attempts.saturating_add(1);
                    // A lost race resolves through the bitmap; only a
                    // deterministic revert keeps hitting the same window.
                    let delay = FINALITY_WAIT.saturating_mul(1 << backoff.attempts.min(5));
                    backoff.retry_at = Instant::now() + delay.min(REVERT_BACKOFF_CAP);
                }
                return Ok(outcome);
            }
            if Instant::now() >= deadline {
                self.open_submission = Some((worldwide_day, start_index));
                return Ok(outcome);
            }
            std::thread::sleep(FINALITY_POLL);
        }
    }

    fn reconcile_once(
        &mut self,
        worldwide_day: u32,
        start_index: u32,
    ) -> Result<PayoutTickOutcomeV1, PayoutSubmissionErrorV1> {
        let record = self
            .journal
            .load(worldwide_day, start_index)?
            .ok_or(PayoutSubmissionErrorV1::InvalidJournal)?;
        if record.sender_address != self.config.sender_address {
            return Err(PayoutSubmissionErrorV1::InvalidJournal);
        }
        match record.stage {
            PayoutSubmissionStageV1::Prepared => self.submit(record),
            PayoutSubmissionStageV1::Submitted => self.observe_submission(record),
            PayoutSubmissionStageV1::Included => self.observe_inclusion(record),
            PayoutSubmissionStageV1::Finalized => {
                let inclusion = record
                    .inclusion
                    .ok_or(PayoutSubmissionErrorV1::InvalidJournal)?;
                Ok(PayoutTickOutcomeV1::Finalized {
                    worldwide_day,
                    start_index,
                    success: inclusion.success,
                })
            }
        }
    }

    fn submit(
        &mut self,
        mut record: PayoutSubmissionRecordV1,
    ) -> Result<PayoutTickOutcomeV1, PayoutSubmissionErrorV1> {
        self.broadcast(&record)?;
        record.stage = PayoutSubmissionStageV1::Submitted;
        record.generation = next_generation(record.generation)?;
        let key = (record.worldwide_day, record.start_index);
        self.journal.persist(record)?;
        Ok(PayoutTickOutcomeV1::InFlight {
            worldwide_day: key.0,
            start_index: key.1,
        })
    }

    fn observe_submission(
        &mut self,
        mut record: PayoutSubmissionRecordV1,
    ) -> Result<PayoutTickOutcomeV1, PayoutSubmissionErrorV1> {
        let Some(receipt) = self
            .rpc
            .transaction_receipt(record.transaction_hash)
            .map_err(rpc_error)?
        else {
            self.broadcast(&record)?;
            return Ok(PayoutTickOutcomeV1::InFlight {
                worldwide_day: record.worldwide_day,
                start_index: record.start_index,
            });
        };
        self.require_receipt_hash(&record, receipt.transaction_hash)?;
        if !self.receipt_is_canonical(receipt.block_number, receipt.block_hash)? {
            self.broadcast(&record)?;
            return Ok(PayoutTickOutcomeV1::InFlight {
                worldwide_day: record.worldwide_day,
                start_index: record.start_index,
            });
        }
        record.stage = PayoutSubmissionStageV1::Included;
        record.inclusion = Some(VoteInclusionV1 {
            block_number: receipt.block_number,
            block_hash: receipt.block_hash,
            success: receipt.success,
        });
        record.generation = next_generation(record.generation)?;
        let key = (record.worldwide_day, record.start_index);
        self.journal.persist(record)?;
        Ok(PayoutTickOutcomeV1::InFlight {
            worldwide_day: key.0,
            start_index: key.1,
        })
    }

    fn observe_inclusion(
        &mut self,
        mut record: PayoutSubmissionRecordV1,
    ) -> Result<PayoutTickOutcomeV1, PayoutSubmissionErrorV1> {
        let prior = record
            .inclusion
            .ok_or(PayoutSubmissionErrorV1::InvalidJournal)?;
        let Some(receipt) = self
            .rpc
            .transaction_receipt(record.transaction_hash)
            .map_err(rpc_error)?
        else {
            return self.demote_and_rebroadcast(record);
        };
        self.require_receipt_hash(&record, receipt.transaction_hash)?;
        if !self.receipt_is_canonical(receipt.block_number, receipt.block_hash)? {
            return self.demote_and_rebroadcast(record);
        }
        let inclusion = VoteInclusionV1 {
            block_number: receipt.block_number,
            block_hash: receipt.block_hash,
            success: receipt.success,
        };
        if inclusion != prior {
            record.inclusion = Some(inclusion);
            record.generation = next_generation(record.generation)?;
            self.journal.persist(record.clone())?;
        }
        let finalized = self.rpc.finalized_block().map_err(rpc_error)?;
        if finalized.number < inclusion.block_number {
            return Ok(PayoutTickOutcomeV1::InFlight {
                worldwide_day: record.worldwide_day,
                start_index: record.start_index,
            });
        }
        record.stage = PayoutSubmissionStageV1::Finalized;
        record.inclusion = Some(inclusion);
        record.generation = next_generation(record.generation)?;
        let key = (record.worldwide_day, record.start_index);
        self.journal.persist(record)?;
        Ok(PayoutTickOutcomeV1::Finalized {
            worldwide_day: key.0,
            start_index: key.1,
            success: inclusion.success,
        })
    }

    fn demote_and_rebroadcast(
        &mut self,
        mut record: PayoutSubmissionRecordV1,
    ) -> Result<PayoutTickOutcomeV1, PayoutSubmissionErrorV1> {
        record.stage = PayoutSubmissionStageV1::Submitted;
        record.inclusion = None;
        record.generation = next_generation(record.generation)?;
        let key = (record.worldwide_day, record.start_index);
        self.journal.persist(record.clone())?;
        self.broadcast(&record)?;
        Ok(PayoutTickOutcomeV1::InFlight {
            worldwide_day: key.0,
            start_index: key.1,
        })
    }

    fn broadcast(&self, record: &PayoutSubmissionRecordV1) -> Result<(), PayoutSubmissionErrorV1> {
        let actual = self
            .rpc
            .send_raw_transaction(&record.raw_transaction, record.transaction_hash)
            .map_err(rpc_error)?;
        if actual != record.transaction_hash {
            return Err(PayoutSubmissionErrorV1::TransactionHashMismatch {
                expected: record.transaction_hash,
                actual,
            });
        }
        Ok(())
    }

    /// Receipt is checked after the nonce read, so a racing inclusion keeps
    /// the record.
    fn nonce_was_bypassed(
        &self,
        record: &PayoutSubmissionRecordV1,
    ) -> Result<bool, PayoutSubmissionErrorV1> {
        if self
            .rpc
            .canonical_nonce(record.sender_address)
            .map_err(rpc_error)?
            <= record.nonce
        {
            return Ok(false);
        }
        Ok(self
            .rpc
            .transaction_receipt(record.transaction_hash)
            .map_err(rpc_error)?
            .is_none())
    }

    fn receipt_is_canonical(
        &self,
        block_number: u64,
        block_hash: B256,
    ) -> Result<bool, PayoutSubmissionErrorV1> {
        Ok(self
            .rpc
            .canonical_block(block_number)
            .map_err(rpc_error)?
            .is_some_and(|block| block.number == block_number && block.hash == block_hash))
    }

    fn require_receipt_hash(
        &self,
        record: &PayoutSubmissionRecordV1,
        actual: B256,
    ) -> Result<(), PayoutSubmissionErrorV1> {
        if actual != record.transaction_hash {
            return Err(PayoutSubmissionErrorV1::TransactionHashMismatch {
                expected: record.transaction_hash,
                actual,
            });
        }
        Ok(())
    }

    fn prepare_and_persist<P: PayoutTransactionPreparerV1>(
        &mut self,
        preparer: &P,
        work: &PayoutWorkV1,
    ) -> Result<(), PayoutSubmissionErrorV1> {
        let chain_id = self.rpc.chain_id().map_err(rpc_error)?;
        if chain_id != self.config.expected_chain_id {
            return Err(PayoutSubmissionErrorV1::WrongRpcChain {
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
            outbe_zerofee::MIN_ZERO_FEE_CONTRIBUTOR_BATCH_MAX_FEE_PER_GAS,
            MAX_OCOMP_SIGNER_MAX_FEE_PER_GAS,
        );
        let prepared = preparer
            .prepare_payout_transaction(&work.calldata, nonce, max_fee_per_gas)
            .map_err(|error| PayoutSubmissionErrorV1::Preparation(error.to_string()))?;
        self.validate_prepared(&prepared, work, nonce, max_fee_per_gas)?;
        let generation = match self.journal.load(work.worldwide_day, work.start_index)? {
            None => 1,
            Some(prior) => {
                let replaceable = prior.stage == PayoutSubmissionStageV1::Finalized
                    || (matches!(
                        prior.stage,
                        PayoutSubmissionStageV1::Prepared | PayoutSubmissionStageV1::Submitted
                    ) && self.nonce_was_bypassed(&prior)?);
                if !replaceable {
                    return Err(PayoutSubmissionErrorV1::InvalidJournal);
                }
                next_generation(prior.generation)?
            }
        };
        self.journal.persist(PayoutSubmissionRecordV1 {
            generation,
            stage: PayoutSubmissionStageV1::Prepared,
            worldwide_day: work.worldwide_day,
            start_index: work.start_index,
            leaf_count: work.leaf_count,
            sender_address: self.config.sender_address,
            nonce,
            max_fee_per_gas,
            transaction_hash: prepared.transaction_hash,
            raw_transaction: prepared.raw_transaction,
            inclusion: None,
        })
    }

    fn validate_prepared(
        &self,
        prepared: &PreparedPayoutTransactionV1,
        work: &PayoutWorkV1,
        nonce: u64,
        max_fee_per_gas: u128,
    ) -> Result<(), PayoutSubmissionErrorV1> {
        if prepared.raw_transaction.len() > MAX_RAW_PAYOUT_TRANSACTION_BYTES {
            return Err(PayoutSubmissionErrorV1::JournalTooLarge);
        }
        let mut raw = prepared.raw_transaction.as_slice();
        let transaction =
            EthereumTxEnvelope::<TxEip4844>::decode_2718(&mut raw).map_err(|error| {
                PayoutSubmissionErrorV1::InvalidPreparedTransaction(error.to_string())
            })?;
        if !raw.is_empty() || !matches!(&transaction, EthereumTxEnvelope::Eip1559(_)) {
            return Err(PayoutSubmissionErrorV1::InvalidPreparedTransaction(
                "not one exact EIP-1559 envelope".to_owned(),
            ));
        }
        let recovered = transaction.recover_signer().map_err(|error| {
            PayoutSubmissionErrorV1::InvalidPreparedTransaction(error.to_string())
        })?;
        if recovered != self.config.sender_address
            || transaction.chain_id() != Some(self.config.expected_chain_id)
            || transaction.nonce() != nonce
            || transaction.gas_limit() != outbe_zerofee::MAX_ZERO_FEE_CONTRIBUTOR_BATCH_GAS_LIMIT
            || transaction.max_fee_per_gas() != max_fee_per_gas
            || transaction.max_priority_fee_per_gas() != Some(0)
            || transaction.kind() != TxKind::Call(INTEX_FACTORY_ADDRESS)
            || transaction.value() != U256::ZERO
            || transaction.input().as_ref() != work.calldata.as_slice()
        {
            return Err(PayoutSubmissionErrorV1::InvalidPreparedTransaction(
                "restricted payout transaction fields changed".to_owned(),
            ));
        }
        let decoded_hash = *transaction.tx_hash();
        if decoded_hash != prepared.transaction_hash {
            return Err(PayoutSubmissionErrorV1::TransactionHashMismatch {
                expected: prepared.transaction_hash,
                actual: decoded_hash,
            });
        }
        Ok(())
    }

    fn discover(
        &mut self,
        candidate_days: &[u32],
    ) -> Result<Option<PayoutWorkV1>, PayoutSubmissionErrorV1> {
        for &worldwide_day in candidate_days {
            let round = self.read_round(worldwide_day)?;
            if round.contributorCount == 0 {
                continue;
            }
            if round.paidLeafCount >= round.contributorCount {
                self.clean_day(worldwide_day)?;
                continue;
            }
            let certified = self.read_certified_generation(worldwide_day)?;
            if certified.contributor_count != round.contributorCount {
                // Two finalized reads raced a recertification; retry next tick.
                self.log_skip(worldwide_day, "certified and round counts disagree");
                continue;
            }
            let Some((start_index, expected_len)) =
                self.find_first_unpaid(worldwide_day, certified.contributor_count)?
            else {
                self.clean_day(worldwide_day)?;
                continue;
            };
            if self
                .revert_backoff
                .get(&(worldwide_day, start_index))
                .is_some_and(|backoff| Instant::now() < backoff.retry_at)
            {
                continue;
            }
            let cached = self.day_cache.as_ref().is_some_and(|cache| {
                cache.worldwide_day == worldwide_day
                    && cache.contributor_root == certified.contributor_root
            });
            if !cached {
                let Some(leaves) = self.load_verified_day(worldwide_day, &certified)? else {
                    continue;
                };
                self.day_cache = Some(VerifiedDayCacheV1 {
                    worldwide_day,
                    contributor_root: certified.contributor_root,
                    leaves,
                });
            }
            let leaves = &self.day_cache.as_ref().expect("day cache is warm").leaves;
            let calldata = build_batch_calldata(
                worldwide_day,
                start_index,
                expected_len,
                certified.contributor_count,
                leaves,
            )?;
            return Ok(Some(PayoutWorkV1 {
                worldwide_day,
                start_index,
                leaf_count: expected_len,
                calldata,
            }));
        }
        Ok(None)
    }

    fn read_round(
        &self,
        worldwide_day: u32,
    ) -> Result<IIntexFactory::ContributorRound, PayoutSubmissionErrorV1> {
        let data = IIntexFactory::contributorPayoutRoundCall {
            worldwideDay: worldwide_day,
        }
        .abi_encode();
        let out = self
            .rpc
            .call_contract(INTEX_FACTORY_ADDRESS, &data)
            .map_err(rpc_error)?;
        IIntexFactory::contributorPayoutRoundCall::abi_decode_returns(&out).map_err(state_error)
    }

    fn read_certified_generation(
        &self,
        worldwide_day: u32,
    ) -> Result<CertifiedDayViewV1, PayoutSubmissionErrorV1> {
        let data = IIntex::certifiedContributorGenerationCall {
            worldwideDay: worldwide_day,
        }
        .abi_encode();
        let out = self
            .rpc
            .call_contract(INTEX_ADDRESS, &data)
            .map_err(rpc_error)?;
        let generation = IIntex::certifiedContributorGenerationCall::abi_decode_returns(&out)
            .map_err(state_error)?;
        Ok(CertifiedDayViewV1 {
            contributor_root: generation.contributorRoot,
            contributor_count: generation.contributorCount,
            eligible_nominal_total: generation.eligibleNominalTotal,
        })
    }

    fn find_first_unpaid(
        &mut self,
        worldwide_day: u32,
        contributor_count: u32,
    ) -> Result<Option<(u32, u32)>, PayoutSubmissionErrorV1> {
        let word_count = contributor_count.div_ceil(CONTRIBUTOR_CHUNK_CAPACITY);
        // Words before the frontier were observed fully paid; bits never clear.
        let frontier = self
            .scan_frontier
            .get(&worldwide_day)
            .copied()
            .unwrap_or(0)
            .min(word_count);
        let mut remaining =
            contributor_count.saturating_sub(frontier.saturating_mul(CONTRIBUTOR_CHUNK_CAPACITY));
        for word_index in frontier..word_count {
            let bits = remaining.min(CONTRIBUTOR_CHUNK_CAPACITY);
            let data = IIntexFactory::contributorPaidWordCall {
                worldwideDay: worldwide_day,
                wordIndex: word_index,
            }
            .abi_encode();
            let out = self
                .rpc
                .call_contract(INTEX_FACTORY_ADDRESS, &data)
                .map_err(rpc_error)?;
            let word = IIntexFactory::contributorPaidWordCall::abi_decode_returns(&out)
                .map_err(state_error)?;
            if let Some(found) = first_unpaid_batch(&[word], remaining) {
                self.scan_frontier.insert(worldwide_day, word_index);
                return Ok(Some((
                    word_index * CONTRIBUTOR_CHUNK_CAPACITY + found.0,
                    found.1,
                )));
            }
            remaining -= bits;
        }
        self.scan_frontier.insert(worldwide_day, word_count);
        Ok(None)
    }

    fn clean_day(&mut self, worldwide_day: u32) -> Result<(), PayoutSubmissionErrorV1> {
        if !self.cleaned_days.insert(worldwide_day) {
            return Ok(());
        }
        self.journal.remove_day(worldwide_day)
    }

    fn log_skip(&mut self, worldwide_day: u32, reason: &str) {
        if self
            .skip_log
            .get(&worldwide_day)
            .is_some_and(|last| last == reason)
        {
            return;
        }
        eprintln!("OCOMP payout: day {worldwide_day}: {reason}; skipping");
        self.skip_log.insert(worldwide_day, reason.to_owned());
    }

    /// Any mismatch with the certified values - missing file, wrong size,
    /// different root or total - disqualifies this validator for the day.
    fn load_verified_day(
        &mut self,
        worldwide_day: u32,
        certified: &CertifiedDayViewV1,
    ) -> Result<Option<Vec<[u8; CONTRIBUTOR_LEAF_BYTES]>>, PayoutSubmissionErrorV1> {
        let job_id = self.read_job_id(worldwide_day)?;
        let path = self
            .config
            .job_root
            .join(hex::encode(job_id.as_slice()))
            .join(CONTRIBUTOR_PAYOUT_ARTIFACT_FILE);
        let mut file = match open_regular_nofollow(&path) {
            Ok(file) => file,
            Err(PayoutSubmissionErrorV1::Io { ref source, .. })
                if source.kind() == std::io::ErrorKind::NotFound =>
            {
                self.log_skip(worldwide_day, &format!("no artifact at {}", path.display()));
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        let len = file
            .metadata()
            .map_err(|source| io_error("stat artifact", &path, source))?
            .len();
        let expected_len = u64::from(certified.contributor_count) * CONTRIBUTOR_LEAF_BYTES as u64;
        if len != expected_len {
            self.log_skip(
                worldwide_day,
                &format!("artifact is {len} bytes, certified count needs {expected_len}"),
            );
            return Ok(None);
        }
        let mut bytes = Vec::with_capacity(expected_len as usize);
        file.read_to_end(&mut bytes)
            .map_err(|source| io_error("read artifact", &path, source))?;
        if bytes.len() as u64 != expected_len {
            self.log_skip(worldwide_day, "artifact changed size mid-read");
            return Ok(None);
        }
        let mut leaves = Vec::with_capacity(certified.contributor_count as usize);
        let mut total = U256::ZERO;
        for record in bytes.chunks_exact(CONTRIBUTOR_LEAF_BYTES) {
            let mut leaf = [0u8; CONTRIBUTOR_LEAF_BYTES];
            leaf.copy_from_slice(record);
            let Some(next) = total.checked_add(decode_contributor_leaf(&leaf).nominal) else {
                self.log_skip(worldwide_day, "records overflow the nominal total");
                return Ok(None);
            };
            total = next;
            leaves.push(leaf);
        }
        let root = contributor_list_root(certified.contributor_count, leaves.iter())
            .map_err(state_error)?;
        if root != certified.contributor_root || total != certified.eligible_nominal_total {
            self.log_skip(
                worldwide_day,
                "local records diverge from the certified values",
            );
            return Ok(None);
        }
        Ok(Some(leaves))
    }

    fn read_job_id(&self, worldwide_day: u32) -> Result<B256, PayoutSubmissionErrorV1> {
        let data = IMetadosis::getActiveLysisGenerationCall { wwd: worldwide_day }.abi_encode();
        let out = self
            .rpc
            .call_contract(METADOSIS_ADDRESS, &data)
            .map_err(rpc_error)?;
        let encoded = IMetadosis::getActiveLysisGenerationCall::abi_decode_returns(&out)
            .map_err(state_error)?;
        let generation = ActiveGenerationV1::decode_canonical(&encoded, &self.config.limits)
            .map_err(state_error)?;
        Ok(generation.job_id)
    }
}

fn build_batch_calldata(
    worldwide_day: u32,
    start_index: u32,
    leaf_count: u32,
    contributor_count: u32,
    leaves: &[[u8; CONTRIBUTOR_LEAF_BYTES]],
) -> Result<Vec<u8>, PayoutSubmissionErrorV1> {
    let start = start_index as usize;
    let end = start + leaf_count as usize;
    if end > leaves.len() {
        return Err(PayoutSubmissionErrorV1::StateDecode(
            "unpaid batch reaches past the verified records".to_owned(),
        ));
    }
    let proof = outbe_intex::payout::build_contributor_range_proof(
        contributor_count,
        start_index,
        leaves.iter(),
    )
    .map_err(state_error)?;
    let batch = leaves[start..end]
        .iter()
        .map(|record| {
            let leaf = decode_contributor_leaf(record);
            IIntexFactory::ContributorLeaf {
                owner: leaf.owner,
                sourceTributeId: leaf.source_tribute_id,
                nominal: leaf.nominal,
            }
        })
        .collect();
    Ok(IIntexFactory::payContributorBatchCall {
        worldwideDay: worldwide_day,
        startIndex: start_index,
        leaves: batch,
        proof,
    }
    .abi_encode())
}

fn next_generation(generation: u64) -> Result<u64, PayoutSubmissionErrorV1> {
    generation
        .checked_add(1)
        .ok_or(PayoutSubmissionErrorV1::GenerationOverflow)
}

struct PayoutSubmissionJournalV1 {
    root: PathBuf,
    _lock: File,
}

impl PayoutSubmissionJournalV1 {
    #[allow(unsafe_code)]
    fn open(root: &Path) -> Result<Self, PayoutSubmissionErrorV1> {
        ensure_private_directory(root)?;
        let lock_path = root.join(JOURNAL_LOCK_FILE);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|source| io_error("open lock", &lock_path, source))?;
        // SAFETY: `lock` owns a live descriptor for the complete `flock` call.
        let result = unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
        if result != 0 {
            return Err(io_error(
                "lock journal",
                &lock_path,
                std::io::Error::last_os_error(),
            ));
        }
        Ok(Self {
            root: root.to_path_buf(),
            _lock: lock,
        })
    }

    fn load(
        &self,
        worldwide_day: u32,
        start_index: u32,
    ) -> Result<Option<PayoutSubmissionRecordV1>, PayoutSubmissionErrorV1> {
        let path = self.record_path(worldwide_day, start_index);
        let temp = self.temp_path(worldwide_day, start_index);
        if path_exists(&temp)? {
            return Err(PayoutSubmissionErrorV1::AmbiguousJournal(temp));
        }
        if !path_exists(&path)? {
            return Ok(None);
        }
        let record = self.load_path(&path)?;
        if record.worldwide_day != worldwide_day || record.start_index != start_index {
            return Err(PayoutSubmissionErrorV1::InvalidJournal);
        }
        Ok(Some(record))
    }

    fn load_path(&self, path: &Path) -> Result<PayoutSubmissionRecordV1, PayoutSubmissionErrorV1> {
        let mut file = open_regular_nofollow(path)?;
        let metadata = file
            .metadata()
            .map_err(|source| io_error("stat record", path, source))?;
        let len = usize::try_from(metadata.len())
            .map_err(|_| PayoutSubmissionErrorV1::JournalTooLarge)?;
        if !(JOURNAL_FIXED_BYTES_WITHOUT_RAW + 1 + JOURNAL_CHECKSUM_BYTES
            ..=JOURNAL_FIXED_BYTES_WITHOUT_RAW
                + INCLUSION_BYTES
                + MAX_RAW_PAYOUT_TRANSACTION_BYTES
                + JOURNAL_CHECKSUM_BYTES)
            .contains(&len)
        {
            return Err(PayoutSubmissionErrorV1::JournalTooLarge);
        }
        let mut bytes = Vec::with_capacity(len);
        file.read_to_end(&mut bytes)
            .map_err(|source| io_error("read record", path, source))?;
        decode_record(&bytes)
    }

    fn persist(&self, record: PayoutSubmissionRecordV1) -> Result<(), PayoutSubmissionErrorV1> {
        validate_record(&record)?;
        let encoded = encode_record(&record);
        let temp = self.temp_path(record.worldwide_day, record.start_index);
        let final_path = self.record_path(record.worldwide_day, record.start_index);
        if path_exists(&temp)? {
            return Err(PayoutSubmissionErrorV1::AmbiguousJournal(temp));
        }
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&temp)
            .map_err(|source| io_error("create record temp", &temp, source))?;
        file.write_all(&encoded)
            .map_err(|source| io_error("write record temp", &temp, source))?;
        file.sync_all()
            .map_err(|source| io_error("fsync record temp", &temp, source))?;
        fs::rename(&temp, &final_path)
            .map_err(|source| io_error("publish record", &final_path, source))?;
        sync_directory(&self.root)
    }

    fn find_open_submission(&self) -> Result<Option<(u32, u32)>, PayoutSubmissionErrorV1> {
        let entries = fs::read_dir(&self.root)
            .map_err(|source| io_error("scan journal", &self.root, source))?;
        for entry in entries {
            let entry =
                entry.map_err(|source| io_error("scan journal entry", &self.root, source))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !name.ends_with(".payout.v1") {
                continue;
            }
            let record = self.load_path(&entry.path())?;
            if record.stage != PayoutSubmissionStageV1::Finalized {
                return Ok(Some((record.worldwide_day, record.start_index)));
            }
        }
        Ok(None)
    }

    fn remove(&self, worldwide_day: u32, start_index: u32) -> Result<(), PayoutSubmissionErrorV1> {
        let path = self.record_path(worldwide_day, start_index);
        match fs::remove_file(&path) {
            Ok(()) => sync_directory(&self.root),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(io_error("remove record", &path, source)),
        }
    }

    /// Drops every record of a fully paid day; none can be needed again.
    fn remove_day(&self, worldwide_day: u32) -> Result<(), PayoutSubmissionErrorV1> {
        let prefix = format!("{worldwide_day}-");
        let entries = fs::read_dir(&self.root)
            .map_err(|source| io_error("scan journal", &self.root, source))?;
        let mut removed = false;
        for entry in entries {
            let entry =
                entry.map_err(|source| io_error("scan journal entry", &self.root, source))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !name.starts_with(&prefix) || !name.ends_with(".payout.v1") {
                continue;
            }
            let path = entry.path();
            fs::remove_file(&path).map_err(|source| io_error("remove record", &path, source))?;
            removed = true;
        }
        if removed {
            sync_directory(&self.root)?;
        }
        Ok(())
    }

    fn record_path(&self, worldwide_day: u32, start_index: u32) -> PathBuf {
        self.root
            .join(format!("{worldwide_day}-{start_index}.payout.v1"))
    }

    fn temp_path(&self, worldwide_day: u32, start_index: u32) -> PathBuf {
        self.root
            .join(format!("{worldwide_day}-{start_index}.payout.v1.tmp"))
    }
}

fn validate_record(record: &PayoutSubmissionRecordV1) -> Result<(), PayoutSubmissionErrorV1> {
    if record.generation == 0
        || record.leaf_count == 0
        || record.leaf_count > CONTRIBUTOR_CHUNK_CAPACITY
        || !record
            .start_index
            .is_multiple_of(CONTRIBUTOR_CHUNK_CAPACITY)
        || record.raw_transaction.is_empty()
        || record.raw_transaction.len() > MAX_RAW_PAYOUT_TRANSACTION_BYTES
        || matches!(
            record.stage,
            PayoutSubmissionStageV1::Prepared | PayoutSubmissionStageV1::Submitted
        ) != record.inclusion.is_none()
    {
        return Err(PayoutSubmissionErrorV1::InvalidJournal);
    }
    Ok(())
}

fn encode_record(record: &PayoutSubmissionRecordV1) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        JOURNAL_FIXED_BYTES_WITHOUT_RAW + INCLUSION_BYTES + record.raw_transaction.len(),
    );
    out.extend_from_slice(&JOURNAL_MAGIC);
    out.extend_from_slice(&JOURNAL_VERSION.to_be_bytes());
    out.extend_from_slice(&record.generation.to_be_bytes());
    out.push(record.stage.code());
    out.extend_from_slice(&record.worldwide_day.to_be_bytes());
    out.extend_from_slice(&record.start_index.to_be_bytes());
    out.extend_from_slice(&record.leaf_count.to_be_bytes());
    out.extend_from_slice(record.sender_address.as_slice());
    out.extend_from_slice(&record.nonce.to_be_bytes());
    out.extend_from_slice(&record.max_fee_per_gas.to_be_bytes());
    out.extend_from_slice(record.transaction_hash.as_slice());
    let raw_len = u32::try_from(record.raw_transaction.len()).expect("raw length is capped");
    out.extend_from_slice(&raw_len.to_be_bytes());
    out.extend_from_slice(&record.raw_transaction);
    match record.inclusion {
        None => out.push(0),
        Some(inclusion) => {
            out.push(1);
            out.extend_from_slice(&inclusion.block_number.to_be_bytes());
            out.extend_from_slice(inclusion.block_hash.as_slice());
            out.push(u8::from(inclusion.success));
        }
    }
    let checksum = keccak256(&out);
    out.extend_from_slice(checksum.as_slice());
    out
}

fn decode_record(bytes: &[u8]) -> Result<PayoutSubmissionRecordV1, PayoutSubmissionErrorV1> {
    let Some(body_len) = bytes.len().checked_sub(JOURNAL_CHECKSUM_BYTES) else {
        return Err(PayoutSubmissionErrorV1::InvalidJournal);
    };
    if keccak256(&bytes[..body_len]).as_slice() != &bytes[body_len..] {
        return Err(PayoutSubmissionErrorV1::JournalChecksumMismatch);
    }
    let bytes = &bytes[..body_len];
    let mut cursor = Cursor { bytes, offset: 0 };
    if cursor.take(8)? != JOURNAL_MAGIC {
        return Err(PayoutSubmissionErrorV1::InvalidJournal);
    }
    if u16::from_be_bytes(cursor.take(2)?.try_into().expect("2 bytes")) != JOURNAL_VERSION {
        return Err(PayoutSubmissionErrorV1::InvalidJournal);
    }
    let generation = u64::from_be_bytes(cursor.take(8)?.try_into().expect("8 bytes"));
    let stage = PayoutSubmissionStageV1::from_code(cursor.take(1)?[0])
        .ok_or(PayoutSubmissionErrorV1::InvalidJournal)?;
    let worldwide_day = u32::from_be_bytes(cursor.take(4)?.try_into().expect("4 bytes"));
    let start_index = u32::from_be_bytes(cursor.take(4)?.try_into().expect("4 bytes"));
    let leaf_count = u32::from_be_bytes(cursor.take(4)?.try_into().expect("4 bytes"));
    let sender_address = Address::from_slice(cursor.take(20)?);
    let nonce = u64::from_be_bytes(cursor.take(8)?.try_into().expect("8 bytes"));
    let max_fee_per_gas = u128::from_be_bytes(cursor.take(16)?.try_into().expect("16 bytes"));
    let transaction_hash = B256::from_slice(cursor.take(32)?);
    let raw_len = usize::try_from(u32::from_be_bytes(
        cursor.take(4)?.try_into().expect("4 bytes"),
    ))
    .map_err(|_| PayoutSubmissionErrorV1::InvalidJournal)?;
    if raw_len > MAX_RAW_PAYOUT_TRANSACTION_BYTES {
        return Err(PayoutSubmissionErrorV1::JournalTooLarge);
    }
    let raw_transaction = cursor.take(raw_len)?.to_vec();
    let inclusion = match cursor.take(1)?[0] {
        0 => None,
        1 => {
            let block_number = u64::from_be_bytes(cursor.take(8)?.try_into().expect("8 bytes"));
            let block_hash = B256::from_slice(cursor.take(32)?);
            let success = match cursor.take(1)?[0] {
                0 => false,
                1 => true,
                _ => return Err(PayoutSubmissionErrorV1::InvalidJournal),
            };
            Some(VoteInclusionV1 {
                block_number,
                block_hash,
                success,
            })
        }
        _ => return Err(PayoutSubmissionErrorV1::InvalidJournal),
    };
    if cursor.offset != bytes.len() {
        return Err(PayoutSubmissionErrorV1::InvalidJournal);
    }
    let record = PayoutSubmissionRecordV1 {
        generation,
        stage,
        worldwide_day,
        start_index,
        leaf_count,
        sender_address,
        nonce,
        max_fee_per_gas,
        transaction_hash,
        raw_transaction,
        inclusion,
    };
    validate_record(&record)?;
    Ok(record)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8], PayoutSubmissionErrorV1> {
        let end = self
            .offset
            .checked_add(len)
            .filter(|end| *end <= self.bytes.len())
            .ok_or(PayoutSubmissionErrorV1::InvalidJournal)?;
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }
}

fn path_exists(path: &Path) -> Result<bool, PayoutSubmissionErrorV1> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error("probe path", path, source)),
    }
}

fn ensure_private_directory(path: &Path) -> Result<(), PayoutSubmissionErrorV1> {
    fs::create_dir_all(path).map_err(|source| io_error("create journal root", path, source))?;
    let metadata =
        fs::metadata(path).map_err(|source| io_error("stat journal root", path, source))?;
    let mut permissions = metadata.permissions();
    if permissions.mode() & 0o077 != 0 {
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions)
            .map_err(|source| io_error("restrict journal root", path, source))?;
    }
    Ok(())
}

fn open_regular_nofollow(path: &Path) -> Result<File, PayoutSubmissionErrorV1> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_error("open record", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| io_error("stat record", path, source))?;
    if !metadata.is_file() {
        return Err(PayoutSubmissionErrorV1::InvalidJournal);
    }
    Ok(file)
}

fn sync_directory(path: &Path) -> Result<(), PayoutSubmissionErrorV1> {
    File::open(path)
        .and_then(|dir| dir.sync_all())
        .map_err(|source| io_error("fsync journal root", path, source))
}

#[cfg(test)]
mod tests {
    use outbe_ocomp_protocol::profile::poc_schema_limits;

    use crate::vote_submitter::{VoteBlockV1, VoteReceiptV1};

    use super::*;

    struct NonceProbeRpc {
        nonce: u64,
        receipt: Option<VoteReceiptV1>,
    }

    impl VoteSubmissionRpcV1 for NonceProbeRpc {
        type Error = std::io::Error;

        fn chain_id(&self) -> Result<u64, Self::Error> {
            unimplemented!()
        }

        fn canonical_nonce(&self, _address: Address) -> Result<u64, Self::Error> {
            Ok(self.nonce)
        }

        fn gas_price(&self) -> Result<u128, Self::Error> {
            unimplemented!()
        }

        fn send_raw_transaction(
            &self,
            _raw_transaction: &[u8],
            _expected_hash: B256,
        ) -> Result<B256, Self::Error> {
            unimplemented!()
        }

        fn transaction_receipt(
            &self,
            _transaction_hash: B256,
        ) -> Result<Option<VoteReceiptV1>, Self::Error> {
            Ok(self.receipt)
        }

        fn canonical_block(&self, _number: u64) -> Result<Option<VoteBlockV1>, Self::Error> {
            unimplemented!()
        }

        fn finalized_block(&self) -> Result<VoteBlockV1, Self::Error> {
            unimplemented!()
        }
    }

    impl PayoutSubmissionRpcV1 for NonceProbeRpc {
        fn call_contract(&self, _to: Address, _data: &[u8]) -> Result<Vec<u8>, Self::Error> {
            unimplemented!()
        }
    }

    fn probe_submitter(
        root: &Path,
        nonce: u64,
        receipt: Option<VoteReceiptV1>,
    ) -> SupervisorPayoutSubmitterV1<NonceProbeRpc> {
        SupervisorPayoutSubmitterV1::open(
            PayoutSubmissionConfigV1 {
                journal_root: root.to_path_buf(),
                job_root: root.to_path_buf(),
                expected_chain_id: 42,
                sender_address: Address::repeat_byte(0x42),
                limits: poc_schema_limits(),
            },
            NonceProbeRpc { nonce, receipt },
        )
        .unwrap()
    }

    #[test]
    fn a_nonce_is_bypassed_only_when_it_moved_and_no_receipt_exists() {
        let submitted = record(PayoutSubmissionStageV1::Submitted);

        let fresh = tempfile::tempdir().unwrap();
        let same_nonce = probe_submitter(fresh.path(), submitted.nonce, None);
        assert!(!same_nonce.nonce_was_bypassed(&submitted).unwrap());

        let moved = tempfile::tempdir().unwrap();
        let bypassed = probe_submitter(moved.path(), submitted.nonce + 1, None);
        assert!(bypassed.nonce_was_bypassed(&submitted).unwrap());

        let landed = tempfile::tempdir().unwrap();
        let with_receipt = probe_submitter(
            landed.path(),
            submitted.nonce + 1,
            Some(VoteReceiptV1 {
                transaction_hash: submitted.transaction_hash,
                block_number: 1,
                block_hash: B256::repeat_byte(0x11),
                success: true,
            }),
        );
        assert!(!with_receipt.nonce_was_bypassed(&submitted).unwrap());
    }

    fn record(stage: PayoutSubmissionStageV1) -> PayoutSubmissionRecordV1 {
        PayoutSubmissionRecordV1 {
            generation: 3,
            stage,
            worldwide_day: 20_260_725,
            start_index: 512,
            leaf_count: 88,
            sender_address: Address::repeat_byte(0x42),
            nonce: 9,
            max_fee_per_gas: 1_000_000_000,
            transaction_hash: B256::repeat_byte(0x77),
            raw_transaction: vec![0xAB; 40],
            inclusion: match stage {
                PayoutSubmissionStageV1::Prepared | PayoutSubmissionStageV1::Submitted => None,
                _ => Some(VoteInclusionV1 {
                    block_number: 1234,
                    block_hash: B256::repeat_byte(0x11),
                    success: true,
                }),
            },
        }
    }

    #[test]
    fn journal_record_round_trips_through_the_codec() {
        for stage in [
            PayoutSubmissionStageV1::Prepared,
            PayoutSubmissionStageV1::Submitted,
            PayoutSubmissionStageV1::Included,
            PayoutSubmissionStageV1::Finalized,
        ] {
            let original = record(stage);
            assert_eq!(decode_record(&encode_record(&original)).unwrap(), original);
        }
    }

    #[test]
    fn malformed_journal_bytes_are_rejected() {
        let encoded = encode_record(&record(PayoutSubmissionStageV1::Submitted));

        let mut wrong_magic = encoded.clone();
        wrong_magic[0] ^= 1;
        assert!(decode_record(&wrong_magic).is_err());

        let truncated = &encoded[..encoded.len() - 1];
        assert!(decode_record(truncated).is_err());

        let mut trailing = encoded.clone();
        trailing.push(0);
        assert!(decode_record(&trailing).is_err());

        let mut misaligned = record(PayoutSubmissionStageV1::Prepared);
        misaligned.start_index = 100;
        assert!(validate_record(&misaligned).is_err());

        let mut staged_wrong = record(PayoutSubmissionStageV1::Prepared);
        staged_wrong.inclusion = Some(VoteInclusionV1 {
            block_number: 1,
            block_hash: B256::ZERO,
            success: true,
        });
        assert!(validate_record(&staged_wrong).is_err());
    }

    #[test]
    fn journal_persists_and_reloads_records() {
        let dir = tempfile::tempdir().unwrap();
        let journal = PayoutSubmissionJournalV1::open(dir.path()).unwrap();
        assert!(journal.load(20_260_725, 512).unwrap().is_none());
        assert!(journal.find_open_submission().unwrap().is_none());

        let original = record(PayoutSubmissionStageV1::Submitted);
        journal.persist(original.clone()).unwrap();
        assert_eq!(journal.load(20_260_725, 512).unwrap().unwrap(), original);
        assert_eq!(
            journal.find_open_submission().unwrap(),
            Some((20_260_725, 512))
        );

        let finalized = record(PayoutSubmissionStageV1::Finalized);
        journal.persist(finalized.clone()).unwrap();
        assert_eq!(journal.load(20_260_725, 512).unwrap().unwrap(), finalized);
        assert!(journal.find_open_submission().unwrap().is_none());
    }

    #[test]
    fn first_unpaid_batch_walks_full_and_tail_words() {
        let full = U256::MAX;
        let tail_mask = (U256::from(1_u8) << 88_u32) - U256::from(1_u8);
        // 600 leaves: words carry 256, 256 and 88 expected bits.
        assert_eq!(first_unpaid_batch(&[U256::ZERO], 600), Some((0, 256)));
        assert_eq!(
            first_unpaid_batch(&[full, U256::ZERO, tail_mask], 600),
            Some((256, 256))
        );
        assert_eq!(
            first_unpaid_batch(&[full, full, U256::ZERO], 600),
            Some((512, 88))
        );
        assert_eq!(first_unpaid_batch(&[full, full, tail_mask], 600), None);
        assert_eq!(first_unpaid_batch(&[tail_mask], 88), None);
        assert_eq!(first_unpaid_batch(&[U256::ZERO], 88), Some((0, 88)));
    }

    #[test]
    fn a_corrupted_record_fails_the_checksum() {
        let mut encoded = encode_record(&record(PayoutSubmissionStageV1::Submitted));
        let flip = encoded.len() - JOURNAL_CHECKSUM_BYTES - 1;
        encoded[flip] ^= 1;
        assert!(matches!(
            decode_record(&encoded),
            Err(PayoutSubmissionErrorV1::JournalChecksumMismatch)
        ));
    }

    #[test]
    fn finished_days_are_swept_from_the_journal() {
        let dir = tempfile::tempdir().unwrap();
        let journal = PayoutSubmissionJournalV1::open(dir.path()).unwrap();
        let mut first = record(PayoutSubmissionStageV1::Submitted);
        first.worldwide_day = 20_260_101;
        let mut second = record(PayoutSubmissionStageV1::Submitted);
        second.worldwide_day = 20_260_102;
        let start = first.start_index;
        journal.persist(first).unwrap();
        journal.persist(second).unwrap();

        journal.remove_day(20_260_101).unwrap();
        assert!(journal.load(20_260_101, start).unwrap().is_none());
        assert!(journal.load(20_260_102, start).unwrap().is_some());

        journal.remove(20_260_102, start).unwrap();
        journal.remove(20_260_102, start).unwrap();
        assert!(journal.load(20_260_102, start).unwrap().is_none());
    }
}
