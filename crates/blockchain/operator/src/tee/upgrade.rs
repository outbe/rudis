//! Owner-only, crash-consistent same-platform enclave upgrade checkpoints.
//!
//! The operator never starts or stops Gramine. It records externally completed
//! checkpoints and copies only the MRSIGNER-sealed permanent offer-key blob.

use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{
        DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _,
    },
    path::{Path, PathBuf},
};

use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_sol_types::SolCall as _;
use eyre::{Result, WrapErr as _};
use outbe_primitives::{
    addresses::TEE_REGISTRY_ADDRESS,
    tee_attestation_v1::{
        AttestationEvidenceV1, AttestationMode, AttestationOperationV1, DcapEvidenceV1,
        RegistrationIntentV1, RegistryMutatorV1, TeeRegistryGasScheduleV1,
        TransitionKeyReadyProofV1,
    },
    tee_registry_abi_v1::ITeeRegistryV1,
};
use outbe_tee::{
    acquire_dcap_collateral_v1, dcap_collateral_validity_window_v1,
    dcap_protocol::dcap_evidence_hash_v1, load_replacement_candidate_submission,
    persist_replacement_candidate_submission, ReplacementCandidateEnclaveV1,
    ReplacementCandidateSubmissionV1,
};
use serde::{Deserialize, Serialize};

use crate::{
    rpc::RenewalRpc,
    tx::{buffered_gas_price, RawRelayTransactionV1, RelaySignerV1},
};

use super::{
    read_finalized_staged_successor_policy_v1,
    registry::{read_finalized_renewal_view_v1, NodeBindingSelectorV1},
};

const DIRECTORY: &str = "tee-upgrade-v1";
const JOURNAL: &str = "journal.json";
const NEXT: &str = "journal.next";
const LOCK: &str = "state.lock";
const SEALED_ROOT: &str = "sealed_root.bin";
const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const MAX_JOURNAL_BYTES: u64 = 4 * 1024 * 1024;
const MAX_SEALED_ROOT_BYTES: u64 = 1024 * 1024;
const MAX_RELAY_VARIANTS: usize = 8;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpgradeContextV1 {
    pub predecessor_manifest_hash: B256,
    pub candidate_manifest_hash: B256,
    pub successor_policy_hash: B256,
    pub activation_height: u64,
    pub active_tee_dir: PathBuf,
    pub candidate_tee_dir: PathBuf,
}

impl UpgradeContextV1 {
    fn validate(&self) -> Result<()> {
        if self.predecessor_manifest_hash.is_zero()
            || self.candidate_manifest_hash.is_zero()
            || self.predecessor_manifest_hash == self.candidate_manifest_hash
            || self.successor_policy_hash.is_zero()
            || self.activation_height == 0
            || self.active_tee_dir.as_os_str().is_empty()
            || self.candidate_tee_dir.as_os_str().is_empty()
            || self.active_tee_dir == self.candidate_tee_dir
        {
            eyre::bail!("upgrade context is incomplete or self-referential");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PreparedUpgradeSubmissionV1 {
    pub intent_hash: B256,
    pub evidence_hash: B256,
    pub calldata_hash: B256,
    pub relay: Address,
    pub relay_variants: Vec<RawRelayTransactionV1>,
}

pub trait UpgradeNodeSignerV1 {
    fn sign_node_hash(&self, hash: B256) -> Result<[u8; 65]>;
}

impl<F> UpgradeNodeSignerV1 for F
where
    F: Fn(B256) -> Result<[u8; 65]>,
{
    fn sign_node_hash(&self, hash: B256) -> Result<[u8; 65]> {
        self(hash)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpgradeSubmissionOutcomeV1 {
    Submitted {
        transaction_hash: B256,
        replayed: bool,
    },
    AlreadySubmitted {
        transaction_hash: B256,
    },
    Finalized {
        transaction_hash: B256,
        finalized_height: u64,
    },
    Promoted {
        transaction_hash: B256,
        finalized_height: u64,
    },
}

impl PreparedUpgradeSubmissionV1 {
    fn validate(&self) -> Result<()> {
        if self.intent_hash.is_zero()
            || self.evidence_hash.is_zero()
            || self.calldata_hash.is_zero()
            || self.relay.is_zero()
            || self.relay_variants.is_empty()
            || self.relay_variants.len() > MAX_RELAY_VARIANTS
        {
            eyre::bail!("upgrade submission is incomplete or exceeds its variant cap");
        }
        let first = &self.relay_variants[0];
        if first.relay != self.relay || first.calldata_hash != self.calldata_hash {
            eyre::bail!("upgrade submission relay binding mismatch");
        }
        for variant in &self.relay_variants {
            if variant.relay != self.relay
                || variant.chain_id != first.chain_id
                || variant.account_nonce != first.account_nonce
                || variant.gas_limit != first.gas_limit
                || variant.calldata_hash != self.calldata_hash
                || keccak256(&variant.raw_transaction) != variant.transaction_hash
            {
                eyre::bail!("upgrade submission contains a competing relay variant");
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "camelCase", deny_unknown_fields)]
pub enum UpgradeJournalStateV1 {
    CandidatePrepared {
        context: UpgradeContextV1,
    },
    RootCopied {
        context: UpgradeContextV1,
        sealed_root_hash: B256,
    },
    CandidateKeyReady {
        context: UpgradeContextV1,
        sealed_root_hash: B256,
        resident_offer_public: B256,
        proof_hash: B256,
    },
    SubmissionPrepared {
        context: UpgradeContextV1,
        sealed_root_hash: B256,
        resident_offer_public: B256,
        proof_hash: B256,
        submission: PreparedUpgradeSubmissionV1,
    },
    Submitted {
        context: UpgradeContextV1,
        sealed_root_hash: B256,
        resident_offer_public: B256,
        proof_hash: B256,
        submission: PreparedUpgradeSubmissionV1,
        submitted_at_finalized_height: u64,
        transaction_hashes: Vec<B256>,
    },
    Finalized {
        context: UpgradeContextV1,
        sealed_root_hash: B256,
        resident_offer_public: B256,
        proof_hash: B256,
        submission: PreparedUpgradeSubmissionV1,
        finalized_height: u64,
        finalized_hash: B256,
    },
    Promoted {
        context: UpgradeContextV1,
        sealed_root_hash: B256,
        resident_offer_public: B256,
        proof_hash: B256,
        submission: PreparedUpgradeSubmissionV1,
        finalized_height: u64,
        finalized_hash: B256,
    },
    TerminalMissedCutoff {
        context: UpgradeContextV1,
        finalized_height: u64,
        activation_height: u64,
    },
}

impl UpgradeJournalStateV1 {
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::CandidatePrepared { .. } => "candidatePrepared",
            Self::RootCopied { .. } => "rootCopied",
            Self::CandidateKeyReady { .. } => "candidateKeyReady",
            Self::SubmissionPrepared { .. } => "submissionPrepared",
            Self::Submitted { .. } => "submitted",
            Self::Finalized { .. } => "finalized",
            Self::Promoted { .. } => "promoted",
            Self::TerminalMissedCutoff { .. } => "terminalMissedCutoff",
        }
    }

    pub const fn context(&self) -> &UpgradeContextV1 {
        match self {
            Self::CandidatePrepared { context }
            | Self::RootCopied { context, .. }
            | Self::CandidateKeyReady { context, .. }
            | Self::SubmissionPrepared { context, .. }
            | Self::Submitted { context, .. }
            | Self::Finalized { context, .. }
            | Self::Promoted { context, .. }
            | Self::TerminalMissedCutoff { context, .. } => context,
        }
    }

    fn validate(&self) -> Result<()> {
        self.context().validate()?;
        match self {
            Self::CandidatePrepared { .. } => Ok(()),
            Self::RootCopied {
                sealed_root_hash, ..
            } => validate_root(*sealed_root_hash),
            Self::CandidateKeyReady {
                sealed_root_hash,
                resident_offer_public,
                proof_hash,
                ..
            } => validate_key_ready(*sealed_root_hash, *resident_offer_public, *proof_hash),
            Self::SubmissionPrepared {
                sealed_root_hash,
                resident_offer_public,
                proof_hash,
                submission,
                ..
            } => {
                validate_key_ready(*sealed_root_hash, *resident_offer_public, *proof_hash)?;
                submission.validate()
            }
            Self::Submitted {
                sealed_root_hash,
                resident_offer_public,
                proof_hash,
                submission,
                transaction_hashes,
                ..
            } => {
                validate_key_ready(*sealed_root_hash, *resident_offer_public, *proof_hash)?;
                submission.validate()?;
                if transaction_hashes.is_empty()
                    || transaction_hashes.len() > submission.relay_variants.len()
                    || transaction_hashes.iter().enumerate().any(|(index, hash)| {
                        submission.relay_variants[index].transaction_hash != *hash
                    })
                {
                    eyre::bail!("submitted upgrade transaction list is non-canonical");
                }
                Ok(())
            }
            Self::Finalized {
                sealed_root_hash,
                resident_offer_public,
                proof_hash,
                submission,
                finalized_hash,
                ..
            }
            | Self::Promoted {
                sealed_root_hash,
                resident_offer_public,
                proof_hash,
                submission,
                finalized_hash,
                ..
            } => {
                validate_key_ready(*sealed_root_hash, *resident_offer_public, *proof_hash)?;
                submission.validate()?;
                if finalized_hash.is_zero() {
                    eyre::bail!("finalized upgrade checkpoint has a zero block hash");
                }
                Ok(())
            }
            Self::TerminalMissedCutoff {
                finalized_height,
                activation_height,
                ..
            } => {
                if *activation_height == 0 || finalized_height < activation_height {
                    eyre::bail!("terminal cutoff checkpoint precedes policy activation");
                }
                Ok(())
            }
        }
    }
}

fn validate_root(sealed_root_hash: B256) -> Result<()> {
    if sealed_root_hash.is_zero() {
        eyre::bail!("upgrade checkpoint has a zero sealed-root hash");
    }
    Ok(())
}

fn validate_key_ready(
    sealed_root_hash: B256,
    resident_offer_public: B256,
    proof_hash: B256,
) -> Result<()> {
    validate_root(sealed_root_hash)?;
    if resident_offer_public.is_zero() || proof_hash.is_zero() {
        eyre::bail!("key-ready checkpoint has a zero offer key or proof hash");
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct UpgradeJournalSnapshotV1 {
    pub version: u8,
    pub generation: u64,
    pub lifecycle: UpgradeJournalStateV1,
}

impl UpgradeJournalSnapshotV1 {
    pub fn new(lifecycle: UpgradeJournalStateV1) -> Self {
        Self {
            version: 1,
            generation: 1,
            lifecycle,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.version != 1 || self.generation == 0 {
            eyre::bail!("unsupported upgrade journal version or generation");
        }
        self.lifecycle.validate()
    }
}

pub struct UpgradeJournalGuardV1 {
    paths: JournalPaths,
    _lock: File,
}

impl UpgradeJournalGuardV1 {
    pub fn acquire(node_data_dir: &Path) -> Result<Self> {
        let paths = JournalPaths::new(node_data_dir);
        create_or_validate_directory(&paths.root)?;
        let lock = open_private_file(&paths.lock, true, MAX_JOURNAL_BYTES)?;
        if let Err(error) =
            rustix::fs::flock(&lock, rustix::fs::FlockOperation::NonBlockingLockExclusive)
        {
            let error = std::io::Error::from(error);
            if error.kind() == std::io::ErrorKind::WouldBlock {
                eyre::bail!("another upgrade operator owns the journal lock");
            }
            return Err(error).wrap_err("lock upgrade journal");
        }
        reconcile_scratch(&paths)?;
        Ok(Self { paths, _lock: lock })
    }

    pub fn load(&self) -> Result<Option<UpgradeJournalSnapshotV1>> {
        read_snapshot(&self.paths.journal)
    }

    pub fn store(&self, mut snapshot: UpgradeJournalSnapshotV1) -> Result<()> {
        if let Some(current) = self.load()? {
            if snapshot.lifecycle.context() != current.lifecycle.context() {
                eyre::bail!("upgrade journal context cannot change after preparation");
            }
            validate_checkpoint_transition(&current.lifecycle, &snapshot.lifecycle)?;
            snapshot.generation = current
                .generation
                .checked_add(1)
                .ok_or_else(|| eyre::eyre!("upgrade journal generation exhausted"))?;
        }
        snapshot.validate()?;
        let encoded = serde_json::to_vec(&snapshot).wrap_err("encode upgrade journal")?;
        if encoded.len() as u64 > MAX_JOURNAL_BYTES {
            eyre::bail!("upgrade journal exceeds its size cap");
        }
        let mut next = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&self.paths.next)
            .wrap_err("create upgrade journal scratch")?;
        next.write_all(&encoded)
            .wrap_err("write upgrade journal scratch")?;
        next.sync_all().wrap_err("fsync upgrade journal scratch")?;
        fs::rename(&self.paths.next, &self.paths.journal).wrap_err("commit upgrade journal")?;
        sync_directory(&self.paths.root)
    }
}

fn validate_checkpoint_transition(
    current: &UpgradeJournalStateV1,
    next: &UpgradeJournalStateV1,
) -> Result<()> {
    use UpgradeJournalStateV1::{
        CandidateKeyReady, CandidatePrepared, Finalized, Promoted, RootCopied, SubmissionPrepared,
        Submitted, TerminalMissedCutoff,
    };
    let allowed = matches!(
        (current, next),
        (CandidatePrepared { .. }, RootCopied { .. })
            | (CandidatePrepared { .. }, TerminalMissedCutoff { .. })
            | (RootCopied { .. }, CandidateKeyReady { .. })
            | (CandidateKeyReady { .. }, SubmissionPrepared { .. })
            | (SubmissionPrepared { .. }, Submitted { .. })
            | (Submitted { .. }, Submitted { .. })
            | (Submitted { .. }, Finalized { .. })
            | (Finalized { .. }, Promoted { .. })
            | (Promoted { .. }, Promoted { .. })
            | (TerminalMissedCutoff { .. }, TerminalMissedCutoff { .. })
            | (RootCopied { .. }, TerminalMissedCutoff { .. })
            | (CandidateKeyReady { .. }, TerminalMissedCutoff { .. })
            | (SubmissionPrepared { .. }, TerminalMissedCutoff { .. })
            | (Submitted { .. }, TerminalMissedCutoff { .. })
    );
    if !allowed {
        eyre::bail!(
            "invalid upgrade checkpoint transition {} -> {}",
            current.label(),
            next.label()
        );
    }
    if let (Some(current), Some(next)) = (security_material(current), security_material(next)) {
        if current.0 != next.0
            || (!current.1.is_zero() && current.1 != next.1)
            || (!current.2.is_zero() && current.2 != next.2)
            || current
                .3
                .is_some_and(|submission| Some(submission) != next.3)
        {
            eyre::bail!("upgrade security material changed across checkpoints");
        }
    }
    Ok(())
}

fn security_material(
    state: &UpgradeJournalStateV1,
) -> Option<(B256, B256, B256, Option<&PreparedUpgradeSubmissionV1>)> {
    match state {
        UpgradeJournalStateV1::CandidatePrepared { .. }
        | UpgradeJournalStateV1::TerminalMissedCutoff { .. } => None,
        UpgradeJournalStateV1::RootCopied {
            sealed_root_hash, ..
        } => Some((*sealed_root_hash, B256::ZERO, B256::ZERO, None)),
        UpgradeJournalStateV1::CandidateKeyReady {
            sealed_root_hash,
            resident_offer_public,
            proof_hash,
            ..
        } => Some((*sealed_root_hash, *resident_offer_public, *proof_hash, None)),
        UpgradeJournalStateV1::SubmissionPrepared {
            sealed_root_hash,
            resident_offer_public,
            proof_hash,
            submission,
            ..
        }
        | UpgradeJournalStateV1::Submitted {
            sealed_root_hash,
            resident_offer_public,
            proof_hash,
            submission,
            ..
        }
        | UpgradeJournalStateV1::Finalized {
            sealed_root_hash,
            resident_offer_public,
            proof_hash,
            submission,
            ..
        }
        | UpgradeJournalStateV1::Promoted {
            sealed_root_hash,
            resident_offer_public,
            proof_hash,
            submission,
            ..
        } => Some((
            *sealed_root_hash,
            *resident_offer_public,
            *proof_hash,
            Some(submission),
        )),
    }
}

pub fn inspect_upgrade_journal_v1(
    node_data_dir: &Path,
) -> Result<Option<UpgradeJournalSnapshotV1>> {
    let paths = JournalPaths::new(node_data_dir);
    if !paths.root.exists() {
        return Ok(None);
    }
    validate_directory(&paths.root)?;
    read_snapshot(&paths.journal)
}

pub fn prepare_upgrade_journal_v1(
    node_data_dir: &Path,
    context: UpgradeContextV1,
) -> Result<UpgradeJournalSnapshotV1> {
    context.validate()?;
    let guard = UpgradeJournalGuardV1::acquire(node_data_dir)?;
    if let Some(existing) = guard.load()? {
        if existing.lifecycle.context() != &context {
            eyre::bail!("another enclave upgrade is already journaled");
        }
        return Ok(existing);
    }
    if let Some(renewal) = super::renewal_journal::inspect_journal(node_data_dir)? {
        if matches!(
            renewal.lifecycle,
            super::renewal_journal::RenewalJournalStateV1::Prepared { .. }
                | super::renewal_journal::RenewalJournalStateV1::Submitted { .. }
        ) {
            eyre::bail!(
                "cannot prepare enclave upgrade while an exact renewal submission is pending"
            );
        }
    }
    let snapshot =
        UpgradeJournalSnapshotV1::new(UpgradeJournalStateV1::CandidatePrepared { context });
    guard.store(snapshot)?;
    guard
        .load()?
        .ok_or_else(|| eyre::eyre!("prepared upgrade journal disappeared"))
}

pub fn copy_same_platform_sealed_root_and_checkpoint_v1(
    node_data_dir: &Path,
) -> Result<UpgradeJournalSnapshotV1> {
    let guard = UpgradeJournalGuardV1::acquire(node_data_dir)?;
    let current = guard
        .load()?
        .ok_or_else(|| eyre::eyre!("upgrade candidate is not prepared"))?;
    match current.lifecycle {
        UpgradeJournalStateV1::CandidatePrepared { context } => {
            let sealed_root_hash = copy_same_platform_sealed_root_v1(&context)?;
            guard.store(UpgradeJournalSnapshotV1::new(
                UpgradeJournalStateV1::RootCopied {
                    context,
                    sealed_root_hash,
                },
            ))?;
            guard
                .load()?
                .ok_or_else(|| eyre::eyre!("root-copied checkpoint disappeared"))
        }
        UpgradeJournalStateV1::RootCopied {
            context,
            sealed_root_hash,
        } => {
            let actual = copy_same_platform_sealed_root_v1(&context)?;
            if actual != sealed_root_hash {
                eyre::bail!("candidate sealed root changed after its durable checkpoint");
            }
            Ok(UpgradeJournalSnapshotV1 {
                lifecycle: UpgradeJournalStateV1::RootCopied {
                    context,
                    sealed_root_hash,
                },
                ..current
            })
        }
        _ => {
            eyre::bail!("sealed root can be copied only at candidate-prepared checkpoint");
        }
    }
}

pub fn record_candidate_key_ready_v1(
    node_data_dir: &Path,
    intent: &RegistrationIntentV1,
    proof: &TransitionKeyReadyProofV1,
    expected_offer_public: [u8; 32],
) -> Result<UpgradeJournalSnapshotV1> {
    proof
        .verify_for_transition(intent, expected_offer_public)
        .map_err(|error| eyre::eyre!("candidate key-ready proof is invalid: {error}"))?;
    let proof_hash = keccak256(
        proof
            .encode_canonical()
            .map_err(|error| eyre::eyre!("encode candidate key-ready proof: {error}"))?,
    );
    let guard = UpgradeJournalGuardV1::acquire(node_data_dir)?;
    let current = guard
        .load()?
        .ok_or_else(|| eyre::eyre!("upgrade candidate is not prepared"))?;
    let UpgradeJournalStateV1::RootCopied {
        context,
        sealed_root_hash,
    } = current.lifecycle
    else {
        eyre::bail!("candidate key readiness requires the root-copied checkpoint");
    };
    if proof.candidate_manifest_hash != context.candidate_manifest_hash {
        eyre::bail!("candidate key-ready proof does not match the journaled manifest");
    }
    guard.store(UpgradeJournalSnapshotV1::new(
        UpgradeJournalStateV1::CandidateKeyReady {
            context,
            sealed_root_hash,
            resident_offer_public: B256::from(expected_offer_public),
            proof_hash,
        },
    ))?;
    guard
        .load()?
        .ok_or_else(|| eyre::eyre!("candidate-key-ready checkpoint disappeared"))
}

pub fn record_upgrade_submission_prepared_v1(
    node_data_dir: &Path,
    submission: PreparedUpgradeSubmissionV1,
) -> Result<UpgradeJournalSnapshotV1> {
    submission.validate()?;
    let guard = UpgradeJournalGuardV1::acquire(node_data_dir)?;
    let current = guard
        .load()?
        .ok_or_else(|| eyre::eyre!("upgrade candidate is not prepared"))?;
    let UpgradeJournalStateV1::CandidateKeyReady {
        context,
        sealed_root_hash,
        resident_offer_public,
        proof_hash,
    } = current.lifecycle
    else {
        eyre::bail!("upgrade submission requires candidate-key-ready checkpoint");
    };
    guard.store(UpgradeJournalSnapshotV1::new(
        UpgradeJournalStateV1::SubmissionPrepared {
            context,
            sealed_root_hash,
            resident_offer_public,
            proof_hash,
            submission,
        },
    ))?;
    guard
        .load()?
        .ok_or_else(|| eyre::eyre!("submission-prepared checkpoint disappeared"))
}

pub fn record_upgrade_submitted_v1(
    node_data_dir: &Path,
    finalized_height: u64,
) -> Result<UpgradeJournalSnapshotV1> {
    let guard = UpgradeJournalGuardV1::acquire(node_data_dir)?;
    let current = guard
        .load()?
        .ok_or_else(|| eyre::eyre!("upgrade candidate is not prepared"))?;
    let UpgradeJournalStateV1::SubmissionPrepared {
        context,
        sealed_root_hash,
        resident_offer_public,
        proof_hash,
        submission,
    } = current.lifecycle
    else {
        eyre::bail!("upgrade relay requires submission-prepared checkpoint");
    };
    let transaction_hashes = submission
        .relay_variants
        .iter()
        .map(|variant| variant.transaction_hash)
        .collect();
    guard.store(UpgradeJournalSnapshotV1::new(
        UpgradeJournalStateV1::Submitted {
            context,
            sealed_root_hash,
            resident_offer_public,
            proof_hash,
            submission,
            submitted_at_finalized_height: finalized_height,
            transaction_hashes,
        },
    ))?;
    guard
        .load()?
        .ok_or_else(|| eyre::eyre!("submitted upgrade checkpoint disappeared"))
}

pub fn record_upgrade_finalized_v1(
    node_data_dir: &Path,
    finalized_height: u64,
    finalized_hash: B256,
) -> Result<UpgradeJournalSnapshotV1> {
    if finalized_height == 0 || finalized_hash.is_zero() {
        eyre::bail!("finalized upgrade authority is incomplete");
    }
    let guard = UpgradeJournalGuardV1::acquire(node_data_dir)?;
    let current = guard
        .load()?
        .ok_or_else(|| eyre::eyre!("upgrade candidate is not prepared"))?;
    let UpgradeJournalStateV1::Submitted {
        context,
        sealed_root_hash,
        resident_offer_public,
        proof_hash,
        submission,
        ..
    } = current.lifecycle
    else {
        eyre::bail!("upgrade finalization requires a submitted checkpoint");
    };
    guard.store(UpgradeJournalSnapshotV1::new(
        UpgradeJournalStateV1::Finalized {
            context,
            sealed_root_hash,
            resident_offer_public,
            proof_hash,
            submission,
            finalized_height,
            finalized_hash,
        },
    ))?;
    guard
        .load()?
        .ok_or_else(|| eyre::eyre!("finalized upgrade checkpoint disappeared"))
}

pub fn record_upgrade_promoted_v1(node_data_dir: &Path) -> Result<UpgradeJournalSnapshotV1> {
    let guard = UpgradeJournalGuardV1::acquire(node_data_dir)?;
    let current = guard
        .load()?
        .ok_or_else(|| eyre::eyre!("upgrade candidate is not prepared"))?;
    let UpgradeJournalStateV1::Finalized {
        context,
        sealed_root_hash,
        resident_offer_public,
        proof_hash,
        submission,
        finalized_height,
        finalized_hash,
    } = current.lifecycle
    else {
        eyre::bail!("upgrade promotion requires a finalized checkpoint");
    };
    guard.store(UpgradeJournalSnapshotV1::new(
        UpgradeJournalStateV1::Promoted {
            context,
            sealed_root_hash,
            resident_offer_public,
            proof_hash,
            submission,
            finalized_height,
            finalized_hash,
        },
    ))?;
    guard
        .load()?
        .ok_or_else(|| eyre::eyre!("promoted upgrade checkpoint disappeared"))
}

pub fn record_upgrade_missed_cutoff_v1(
    node_data_dir: &Path,
    finalized_height: u64,
    activation_height: u64,
) -> Result<UpgradeJournalSnapshotV1> {
    if activation_height == 0 || finalized_height < activation_height {
        eyre::bail!("successor activation cutoff has not been reached");
    }
    let guard = UpgradeJournalGuardV1::acquire(node_data_dir)?;
    let current = guard
        .load()?
        .ok_or_else(|| eyre::eyre!("upgrade candidate is not prepared"))?;
    if matches!(
        current.lifecycle,
        UpgradeJournalStateV1::Finalized { .. } | UpgradeJournalStateV1::Promoted { .. }
    ) {
        eyre::bail!("a finalized upgrade cannot become a missed-cutoff terminal");
    }
    let context = current.lifecycle.context().clone();
    guard.store(UpgradeJournalSnapshotV1::new(
        UpgradeJournalStateV1::TerminalMissedCutoff {
            context,
            finalized_height,
            activation_height,
        },
    ))?;
    guard
        .load()?
        .ok_or_else(|| eyre::eyre!("missed-cutoff checkpoint disappeared"))
}

/// Resume one same-platform measurement transition from its durable
/// checkpoints. The deployment manager must have already copied the root and
/// restarted candidate B before calling this reducer.
#[allow(clippy::too_many_arguments)]
pub async fn run_upgrade_submission_v1(
    rpc: &(impl RenewalRpc + Sync),
    relay: &RelaySignerV1,
    candidate: &mut ReplacementCandidateEnclaveV1,
    node_signer: &impl UpgradeNodeSignerV1,
    node_data_dir: &Path,
    selector: &NodeBindingSelectorV1,
    binding_id: B256,
    requested_valid_until: u64,
) -> Result<UpgradeSubmissionOutcomeV1> {
    let replayed = inspect_upgrade_journal_v1(node_data_dir)?.is_some();
    loop {
        let snapshot = inspect_upgrade_journal_v1(node_data_dir)?
            .ok_or_else(|| eyre::eyre!("upgrade candidate is not prepared"))?;
        match snapshot.lifecycle {
            UpgradeJournalStateV1::CandidatePrepared { .. } => {
                eyre::bail!(
                    "candidate root is not copied; run the explicit copy checkpoint and restart B"
                );
            }
            UpgradeJournalStateV1::RootCopied { .. } => {
                prepare_candidate_key_ready_v1(
                    rpc,
                    candidate,
                    node_signer,
                    node_data_dir,
                    selector,
                    binding_id,
                    requested_valid_until,
                )
                .await?;
            }
            UpgradeJournalStateV1::CandidateKeyReady { .. } => {
                prepare_upgrade_relay_v1(rpc, relay, node_data_dir, selector).await?;
            }
            UpgradeJournalStateV1::SubmissionPrepared { ref submission, .. } => {
                let transaction_hash = last_transaction_hash(submission)?;
                if finalized_transition_matches_v1(rpc, selector, node_data_dir, submission).await?
                {
                    let finalized = read_finalized_renewal_view_v1(rpc, selector).await?;
                    record_upgrade_submitted_v1(
                        node_data_dir,
                        finalized.schedule.finalized_height,
                    )?;
                    return Ok(UpgradeSubmissionOutcomeV1::AlreadySubmitted { transaction_hash });
                }
                let raw = submission
                    .relay_variants
                    .last()
                    .ok_or_else(|| eyre::eyre!("upgrade submission has no relay bytes"))?;
                let returned_hash = match rpc.send_raw_transaction(&raw.raw_transaction).await {
                    Ok(returned) => returned
                        .parse::<B256>()
                        .wrap_err("parse transition transaction hash")?,
                    Err(error) if transaction_is_already_known(&error) => raw.transaction_hash,
                    Err(error) => {
                        return Err(error)
                            .wrap_err("submit exact measurement-transition transaction")
                    }
                };
                if returned_hash != raw.transaction_hash {
                    eyre::bail!(
                        "RPC returned a transaction hash different from the signed transition bytes"
                    );
                }
                let finalized = read_finalized_renewal_view_v1(rpc, selector).await?;
                record_upgrade_submitted_v1(node_data_dir, finalized.schedule.finalized_height)?;
                return Ok(UpgradeSubmissionOutcomeV1::Submitted {
                    transaction_hash: returned_hash,
                    replayed,
                });
            }
            UpgradeJournalStateV1::Submitted { ref submission, .. } => {
                return Ok(UpgradeSubmissionOutcomeV1::AlreadySubmitted {
                    transaction_hash: last_transaction_hash(submission)?,
                });
            }
            UpgradeJournalStateV1::Finalized {
                ref submission,
                finalized_height,
                ..
            } => {
                return Ok(UpgradeSubmissionOutcomeV1::Finalized {
                    transaction_hash: last_transaction_hash(submission)?,
                    finalized_height,
                });
            }
            UpgradeJournalStateV1::Promoted {
                ref submission,
                finalized_height,
                ..
            } => {
                return Ok(UpgradeSubmissionOutcomeV1::Promoted {
                    transaction_hash: last_transaction_hash(submission)?,
                    finalized_height,
                });
            }
            UpgradeJournalStateV1::TerminalMissedCutoff {
                finalized_height,
                activation_height,
                ..
            } => {
                eyre::bail!(
                    "upgrade missed successor activation cutoff {activation_height} at finalized height {finalized_height}"
                );
            }
        }
    }
}

fn last_transaction_hash(submission: &PreparedUpgradeSubmissionV1) -> Result<B256> {
    submission
        .relay_variants
        .last()
        .map(|raw| raw.transaction_hash)
        .ok_or_else(|| eyre::eyre!("upgrade submission has no relay transaction"))
}

fn transaction_is_already_known(error: &eyre::Report) -> bool {
    let message = format!("{error:#}").to_ascii_lowercase();
    message.contains("already known") || message.contains("known transaction")
}

#[allow(clippy::too_many_arguments)]
async fn prepare_candidate_key_ready_v1(
    rpc: &(impl RenewalRpc + Sync),
    candidate: &mut ReplacementCandidateEnclaveV1,
    node_signer: &impl UpgradeNodeSignerV1,
    node_data_dir: &Path,
    selector: &NodeBindingSelectorV1,
    binding_id: B256,
    requested_valid_until: u64,
) -> Result<()> {
    let checkpoint = inspect_upgrade_journal_v1(node_data_dir)?
        .ok_or_else(|| eyre::eyre!("upgrade candidate is not prepared"))?;
    let UpgradeJournalStateV1::RootCopied { ref context, .. } = checkpoint.lifecycle else {
        eyre::bail!("candidate key readiness requires the root-copied checkpoint");
    };
    let candidate_manifest_hash = candidate
        .manifest()
        .authorization_hash()
        .map_err(|error| eyre::eyre!("hash candidate manifest: {error}"))?;
    if candidate_manifest_hash != context.candidate_manifest_hash {
        eyre::bail!("connected candidate differs from the journaled candidate manifest");
    }
    let active = read_finalized_renewal_view_v1(rpc, selector).await?;
    let successor = read_finalized_staged_successor_policy_v1(rpc)
        .await?
        .ok_or_else(|| eyre::eyre!("no successor TEE policy is staged at finalized state"))?;
    if active.schedule.finalized_height != successor.finalized_height
        || active.schedule.finalized_hash != successor.finalized_hash
    {
        eyre::bail!("finalized active binding and staged policy were read at different heads");
    }
    if successor.policy.attestation_mode != AttestationMode::DcapRequired {
        eyre::bail!("measurement transition requires a DcapRequired successor policy");
    }
    let active_policy_hash = active
        .policy
        .policy_hash()
        .map_err(|error| eyre::eyre!("hash active finalized policy: {error}"))?;
    if successor.policy.chain_id != active.policy.chain_id
        || successor.policy.genesis_hash != active.policy.genesis_hash
        || successor.policy.predecessor_policy_hash != active_policy_hash
        || successor
            .policy
            .policy_hash()
            .map_err(|error| eyre::eyre!("hash staged successor policy: {error}"))?
            != context.successor_policy_hash
        || successor.policy.activation_height != context.activation_height
    {
        eyre::bail!("staged successor is not the direct successor of the finalized active policy");
    }
    if successor.finalized_height >= successor.policy.activation_height {
        record_upgrade_missed_cutoff_v1(
            node_data_dir,
            successor.finalized_height,
            successor.policy.activation_height,
        )?;
        eyre::bail!("successor policy activation cutoff is already finalized");
    }
    validate_candidate_identity_v1(candidate, selector, &active)?;

    if let Some(durable) = load_replacement_candidate_submission(node_data_dir)
        .map_err(|error| eyre::eyre!("reload durable candidate submission: {error}"))?
    {
        recover_candidate_key_ready_v1(
            node_data_dir,
            &durable,
            &successor.policy,
            active.tribute_offer_public,
        )?;
        return Ok(());
    }

    let desired = transition_intent_v1(
        candidate,
        &active,
        &successor.policy,
        binding_id,
        requested_valid_until,
    )?;
    let mut prepared = generate_transition_evidence_v1(candidate, desired, &successor.policy)?;
    let ceiling = prepared
        .collateral_expiration
        .checked_sub(successor.policy.collateral_margin)
        .ok_or_else(|| eyre::eyre!("transition collateral margin underflows"))?;
    if prepared.intent.requested_valid_until > ceiling {
        let minimum = active
            .schedule
            .finalized_timestamp
            .checked_add(successor.policy.minimum_lease)
            .ok_or_else(|| eyre::eyre!("minimum transition lease overflows"))?;
        if ceiling < minimum {
            eyre::bail!("fresh Intel collateral cannot satisfy the successor minimum lease");
        }
        prepared.intent.requested_valid_until = ceiling;
        prepared = generate_transition_evidence_v1(candidate, prepared.intent, &successor.policy)?;
    }
    validate_transition_time_window_v1(
        &prepared,
        &successor.policy,
        active.schedule.finalized_timestamp,
    )?;
    let intent_hash = prepared
        .intent
        .intent_hash()
        .map_err(|error| eyre::eyre!("hash transition intent: {error}"))?;
    let node_signature = node_signer
        .sign_node_hash(intent_hash)
        .wrap_err("sign transition intent with node authority")?;
    let evidence = AttestationEvidenceV1::Dcap(prepared.evidence);
    persist_replacement_candidate_submission(
        node_data_dir,
        &evidence,
        &node_signature,
        &prepared.enclave_signature,
    )
    .map_err(|error| eyre::eyre!("persist exact candidate submission: {error}"))?;
    let AttestationEvidenceV1::Dcap(dcap) = &evidence else {
        unreachable!();
    };
    let proof = dcap
        .transition_key_ready_proof
        .as_ref()
        .ok_or_else(|| eyre::eyre!("candidate transition evidence has no key-ready proof"))?;
    record_candidate_key_ready_v1(
        node_data_dir,
        &dcap.intent,
        proof,
        active.tribute_offer_public.into(),
    )?;
    Ok(())
}

struct PreparedTransitionEvidenceV1 {
    intent: RegistrationIntentV1,
    evidence: DcapEvidenceV1,
    enclave_signature: [u8; 64],
    collateral_issue_floor: u64,
    collateral_expiration: u64,
}

fn generate_transition_evidence_v1(
    candidate: &mut ReplacementCandidateEnclaveV1,
    intent: RegistrationIntentV1,
    policy: &outbe_primitives::tee_attestation_v1::TeePolicyV1,
) -> Result<PreparedTransitionEvidenceV1> {
    let generated = candidate
        .generate_dcap_quote(&intent)
        .map_err(|error| eyre::eyre!("generate candidate transition quote: {error}"))?;
    let components = acquire_dcap_collateral_v1(&generated.quote_body)
        .map_err(|error| eyre::eyre!("acquire candidate transition collateral: {error}"))?;
    let evidence = DcapEvidenceV1 {
        intent: intent.clone(),
        quote: generated.quote_body,
        components,
        transition_key_ready_proof: generated.transition_key_ready_proof,
    };
    let window = dcap_collateral_validity_window_v1(&evidence, policy)
        .map_err(|error| eyre::eyre!("validate transition collateral: {error:?}"))?;
    Ok(PreparedTransitionEvidenceV1 {
        intent,
        evidence,
        enclave_signature: generated.enclave_signature,
        collateral_issue_floor: window.issue_floor,
        collateral_expiration: window.expiration_ceiling,
    })
}

fn validate_candidate_identity_v1(
    candidate: &ReplacementCandidateEnclaveV1,
    selector: &NodeBindingSelectorV1,
    active: &super::registry::FinalizedRenewalChainViewV1,
) -> Result<()> {
    let manifest = candidate.manifest();
    let node_id_hash = manifest
        .node_id
        .node_id_hash()
        .map_err(|error| eyre::eyre!("hash candidate node identity: {error}"))?;
    let enclave_id = manifest
        .enclave_id()
        .map_err(|error| eyre::eyre!("derive candidate enclave identity: {error}"))?;
    let node_host_authorization_hash = manifest
        .node_host_authorization_hash()
        .map_err(|error| eyre::eyre!("derive candidate NodeHost authorization: {error}"))?;
    if manifest.chain_id != active.policy.chain_id
        || manifest.genesis_hash != active.policy.genesis_hash
        || node_id_hash != active.binding.node_id_hash
        || enclave_id == active.binding.enclave_id
        || node_host_authorization_hash != active.binding.node_host_authorization_hash
    {
        eyre::bail!("candidate manifest is not a same-NodeHost successor of finalized A");
    }
    match selector {
        NodeBindingSelectorV1::NodeHost(public) if public == &manifest.node_id.reth_p2p_public => {}
        _ => {
            eyre::bail!("upgrade selector does not match the candidate node identity");
        }
    }
    Ok(())
}

fn transition_intent_v1(
    candidate: &ReplacementCandidateEnclaveV1,
    active: &super::registry::FinalizedRenewalChainViewV1,
    successor: &outbe_primitives::tee_attestation_v1::TeePolicyV1,
    binding_id: B256,
    requested_valid_until: u64,
) -> Result<RegistrationIntentV1> {
    if binding_id.is_zero() || binding_id == active.binding.binding_id {
        eyre::bail!("measurement transition requires a fresh nonzero binding id");
    }
    let manifest = candidate.manifest();
    let intent = RegistrationIntentV1 {
        chain_id: successor.chain_id,
        genesis_hash: successor.genesis_hash,
        operation: AttestationOperationV1::TransitionEnclaveMeasurement,
        attestation_mode: successor.attestation_mode,
        policy_hash: successor
            .policy_hash()
            .map_err(|error| eyre::eyre!("hash staged successor policy: {error}"))?,
        node_id: manifest.node_id.clone(),
        enclave_id: manifest
            .enclave_id()
            .map_err(|error| eyre::eyre!("derive candidate enclave id: {error}"))?,
        binding_id,
        binding_version: active
            .binding
            .binding_version
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("binding version exhausted"))?,
        registration_version: active
            .binding
            .registration_version
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("registration version exhausted"))?,
        renewal_nonce: active.binding.renewal_nonce,
        transition_nonce: active
            .binding
            .transition_nonce
            .checked_add(1)
            .ok_or_else(|| eyre::eyre!("transition nonce exhausted"))?,
        requested_valid_until,
        recipient_x25519: manifest.recipient_x25519,
        attestation_ed25519: manifest.attestation_ed25519,
        noise_responder_x25519: manifest.noise_responder_x25519,
        node_host_authorization_hash: active.binding.node_host_authorization_hash,
    };
    manifest.validate_intent_binding(&intent).map_err(|error| {
        eyre::eyre!("candidate manifest does not bind transition intent: {error}")
    })?;
    Ok(intent)
}

fn validate_transition_time_window_v1(
    prepared: &PreparedTransitionEvidenceV1,
    policy: &outbe_primitives::tee_attestation_v1::TeePolicyV1,
    finalized_timestamp: u64,
) -> Result<()> {
    let lease = prepared
        .intent
        .requested_valid_until
        .checked_sub(finalized_timestamp)
        .ok_or_else(|| eyre::eyre!("transition lease is already expired at finalized time"))?;
    let ceiling = prepared
        .collateral_expiration
        .checked_sub(policy.collateral_margin)
        .ok_or_else(|| eyre::eyre!("transition collateral margin underflows"))?;
    if prepared.collateral_issue_floor > finalized_timestamp
        || lease < policy.minimum_lease
        || lease > policy.maximum_lease
        || prepared.intent.requested_valid_until > ceiling
    {
        eyre::bail!("candidate evidence cannot satisfy the staged successor lease window");
    }
    Ok(())
}

fn recover_candidate_key_ready_v1(
    node_data_dir: &Path,
    durable: &ReplacementCandidateSubmissionV1,
    successor: &outbe_primitives::tee_attestation_v1::TeePolicyV1,
    expected_offer_public: B256,
) -> Result<()> {
    let AttestationEvidenceV1::Dcap(dcap) =
        AttestationEvidenceV1::decode_canonical(durable.evidence())
            .map_err(|error| eyre::eyre!("decode durable transition evidence: {error}"))?
    else {
        eyre::bail!("durable candidate submission is not DCAP evidence");
    };
    if dcap.intent.operation != AttestationOperationV1::TransitionEnclaveMeasurement
        || dcap.intent.policy_hash
            != successor
                .policy_hash()
                .map_err(|error| eyre::eyre!("hash staged successor policy: {error}"))?
    {
        eyre::bail!("durable candidate submission targets another transition policy");
    }
    let proof = dcap
        .transition_key_ready_proof
        .as_ref()
        .ok_or_else(|| eyre::eyre!("durable transition evidence has no key-ready proof"))?;
    record_candidate_key_ready_v1(
        node_data_dir,
        &dcap.intent,
        proof,
        expected_offer_public.into(),
    )?;
    Ok(())
}

async fn prepare_upgrade_relay_v1(
    rpc: &(impl RenewalRpc + Sync),
    relay: &RelaySignerV1,
    node_data_dir: &Path,
    selector: &NodeBindingSelectorV1,
) -> Result<()> {
    let snapshot = inspect_upgrade_journal_v1(node_data_dir)?
        .ok_or_else(|| eyre::eyre!("upgrade candidate is not prepared"))?;
    let UpgradeJournalStateV1::CandidateKeyReady {
        ref context,
        resident_offer_public,
        proof_hash,
        ..
    } = snapshot.lifecycle
    else {
        eyre::bail!("upgrade relay requires candidate-key-ready checkpoint");
    };
    let durable = load_replacement_candidate_submission(node_data_dir)
        .map_err(|error| eyre::eyre!("reload exact candidate submission: {error}"))?
        .ok_or_else(|| eyre::eyre!("candidate-key-ready checkpoint has no durable submission"))?;
    let evidence = AttestationEvidenceV1::decode_canonical(durable.evidence())
        .map_err(|error| eyre::eyre!("decode durable transition evidence: {error}"))?;
    let AttestationEvidenceV1::Dcap(dcap) = &evidence else {
        eyre::bail!("durable upgrade submission is not DCAP evidence");
    };
    let proof = dcap
        .transition_key_ready_proof
        .as_ref()
        .ok_or_else(|| eyre::eyre!("durable transition evidence has no key-ready proof"))?;
    let encoded_proof = proof
        .encode_canonical()
        .map_err(|error| eyre::eyre!("encode durable key-ready proof: {error}"))?;
    if keccak256(encoded_proof) != proof_hash
        || B256::from(proof.resident_offer_public) != resident_offer_public
    {
        eyre::bail!("durable transition proof differs from the journaled key-ready checkpoint");
    }

    let active = read_finalized_renewal_view_v1(rpc, selector).await?;
    let successor = read_finalized_staged_successor_policy_v1(rpc)
        .await?
        .ok_or_else(|| eyre::eyre!("no successor TEE policy is staged at finalized state"))?;
    if active.schedule.finalized_height != successor.finalized_height
        || active.schedule.finalized_hash != successor.finalized_hash
    {
        eyre::bail!("finalized active binding and staged policy were read at different heads");
    }
    if successor.finalized_height >= successor.policy.activation_height {
        record_upgrade_missed_cutoff_v1(
            node_data_dir,
            successor.finalized_height,
            successor.policy.activation_height,
        )?;
        eyre::bail!("successor policy activation cutoff is already finalized");
    }
    let policy_hash = successor
        .policy
        .policy_hash()
        .map_err(|error| eyre::eyre!("hash staged successor policy: {error}"))?;
    if policy_hash != context.successor_policy_hash
        || successor.policy.activation_height != context.activation_height
        || dcap.intent.policy_hash != policy_hash
        || dcap.intent.operation != AttestationOperationV1::TransitionEnclaveMeasurement
    {
        eyre::bail!("durable candidate submission targets another transition policy");
    }
    proof
        .verify_for_transition(&dcap.intent, active.tribute_offer_public.into())
        .map_err(|error| eyre::eyre!("durable key-ready proof is invalid: {error}"))?;
    ensure_transition_source_or_target_v1(&active.binding, &dcap.intent)?;

    let calldata = ITeeRegistryV1::transitionEnclaveMeasurementCall {
        evidence: durable.evidence().to_vec().into(),
        nodeSignature: durable.node_signature().to_vec().into(),
        enclaveSignature: durable.enclave_signature().to_vec().into(),
    }
    .abi_encode();
    let gas_limit = TeeRegistryGasScheduleV1::normative()
        .maximum_transaction_gas(
            RegistryMutatorV1::TransitionEnclaveMeasurement,
            calldata.len(),
            durable.evidence().len(),
            successor.policy.measurement_rules.len(),
            successor.policy.attestation_mode,
        )
        .map_err(|error| eyre::eyre!("calculate normative transition gas: {error}"))?;
    let chain_id = rpc.chain_id().await?;
    let account_nonce = rpc.transaction_count(relay.address()).await?;
    let gas_price = buffered_gas_price(rpc.gas_price().await?);
    let required_balance = gas_price.saturating_mul(U256::from(gas_limit));
    let balance = rpc.balance(relay.address()).await?;
    if balance < required_balance {
        eyre::bail!(
            "upgrade relay {} has {balance} but needs at least {required_balance}",
            relay.address()
        );
    }
    let raw = relay.sign_renewal(
        chain_id,
        account_nonce,
        gas_price,
        gas_limit,
        TEE_REGISTRY_ADDRESS,
        &calldata,
    )?;
    let intent_hash = dcap
        .intent
        .intent_hash()
        .map_err(|error| eyre::eyre!("hash durable transition intent: {error}"))?;
    let evidence_hash = dcap_evidence_hash_v1(durable.evidence())
        .map_err(|code| eyre::eyre!("hash durable transition evidence: {code:?}"))?;
    record_upgrade_submission_prepared_v1(
        node_data_dir,
        PreparedUpgradeSubmissionV1 {
            intent_hash,
            evidence_hash,
            calldata_hash: keccak256(&calldata),
            relay: relay.address(),
            relay_variants: vec![raw],
        },
    )?;
    Ok(())
}

fn ensure_transition_source_or_target_v1(
    current: &super::registry::RenewalBindingV1,
    intent: &RegistrationIntentV1,
) -> Result<()> {
    if transition_target_matches_v1(current, intent) {
        return Ok(());
    }
    let source_matches = current.node_id_hash
        == intent
            .node_id
            .node_id_hash()
            .map_err(|error| eyre::eyre!("hash transition node identity: {error}"))?
        && current.binding_version.checked_add(1) == Some(intent.binding_version)
        && current.registration_version.checked_add(1) == Some(intent.registration_version)
        && current.renewal_nonce == intent.renewal_nonce
        && current.transition_nonce.checked_add(1) == Some(intent.transition_nonce)
        && current.node_host_authorization_hash == intent.node_host_authorization_hash
        && current.enclave_id != intent.enclave_id
        && current.binding_id != intent.binding_id;
    if !source_matches {
        eyre::bail!("finalized Registry binding matches neither transition source nor target");
    }
    Ok(())
}

fn transition_target_matches_v1(
    current: &super::registry::RenewalBindingV1,
    intent: &RegistrationIntentV1,
) -> bool {
    current.node_id_hash == intent.node_id.node_id_hash().unwrap_or(B256::ZERO)
        && current.enclave_id == intent.enclave_id
        && current.binding_id == intent.binding_id
        && current.intent_hash == intent.intent_hash().unwrap_or(B256::ZERO)
        && current.policy_hash == intent.policy_hash
        && current.binding_version == intent.binding_version
        && current.registration_version == intent.registration_version
        && current.renewal_nonce == intent.renewal_nonce
        && current.transition_nonce == intent.transition_nonce
        && current.valid_until == intent.requested_valid_until
        && current.recipient_x25519 == B256::from(intent.recipient_x25519)
        && current.attestation_ed25519 == B256::from(intent.attestation_ed25519)
        && current.noise_responder_x25519 == B256::from(intent.noise_responder_x25519)
        && current.node_host_authorization_hash == intent.node_host_authorization_hash
}

async fn finalized_transition_matches_v1(
    rpc: &(impl RenewalRpc + Sync),
    selector: &NodeBindingSelectorV1,
    node_data_dir: &Path,
    submission: &PreparedUpgradeSubmissionV1,
) -> Result<bool> {
    let durable = load_replacement_candidate_submission(node_data_dir)
        .map_err(|error| eyre::eyre!("reload exact candidate submission: {error}"))?
        .ok_or_else(|| eyre::eyre!("submission checkpoint has no durable NodeHost material"))?;
    let AttestationEvidenceV1::Dcap(durable_evidence) =
        AttestationEvidenceV1::decode_canonical(durable.evidence())
            .map_err(|error| eyre::eyre!("decode durable transition evidence: {error}"))?
    else {
        eyre::bail!("durable upgrade submission is not DCAP evidence");
    };
    let intent_hash = durable_evidence
        .intent
        .intent_hash()
        .map_err(|error| eyre::eyre!("hash durable transition intent: {error}"))?;
    let evidence_hash = dcap_evidence_hash_v1(durable.evidence())
        .map_err(|code| eyre::eyre!("hash durable transition evidence: {code:?}"))?;
    let calldata = ITeeRegistryV1::transitionEnclaveMeasurementCall {
        evidence: durable.evidence().to_vec().into(),
        nodeSignature: durable.node_signature().to_vec().into(),
        enclaveSignature: durable.enclave_signature().to_vec().into(),
    }
    .abi_encode();
    if intent_hash != submission.intent_hash
        || evidence_hash != submission.evidence_hash
        || keccak256(calldata) != submission.calldata_hash
    {
        eyre::bail!("NodeHost transition material differs from the relay checkpoint");
    }
    let view = read_finalized_renewal_view_v1(rpc, selector).await?;
    ensure_transition_source_or_target_v1(&view.binding, &durable_evidence.intent)?;
    Ok(transition_target_matches_v1(
        &view.binding,
        &durable_evidence.intent,
    ))
}

/// Copy exactly `sealed_root.bin` from active A to prepared candidate B.
/// A byte-identical destination is an idempotent crash retry; any other
/// pre-existing destination fails closed.
pub fn copy_same_platform_sealed_root_v1(context: &UpgradeContextV1) -> Result<B256> {
    context.validate()?;
    validate_directory(&context.active_tee_dir)
        .wrap_err("validate active enclave tee directory")?;
    validate_directory(&context.candidate_tee_dir)
        .wrap_err("validate candidate enclave tee directory")?;
    let source = context.active_tee_dir.join(SEALED_ROOT);
    let destination = context.candidate_tee_dir.join(SEALED_ROOT);
    let bytes = read_private_bounded_file(&source, MAX_SEALED_ROOT_BYTES)
        .wrap_err("read active sealed root")?;
    if bytes.is_empty() {
        eyre::bail!("active sealed root is empty");
    }
    let hash = keccak256(&bytes);
    if destination.exists() {
        let existing = read_private_bounded_file(&destination, MAX_SEALED_ROOT_BYTES)
            .wrap_err("read existing candidate sealed root")?;
        if existing != bytes {
            eyre::bail!("candidate sealed root already exists with different bytes");
        }
        return Ok(hash);
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&destination)
        .wrap_err("create candidate sealed root")?;
    output
        .write_all(&bytes)
        .wrap_err("write candidate sealed root")?;
    output.sync_all().wrap_err("fsync candidate sealed root")?;
    sync_directory(&context.candidate_tee_dir)?;
    Ok(hash)
}

#[derive(Clone)]
struct JournalPaths {
    root: PathBuf,
    journal: PathBuf,
    next: PathBuf,
    lock: PathBuf,
}

impl JournalPaths {
    fn new(node_data_dir: &Path) -> Self {
        let root = node_data_dir.join(DIRECTORY);
        Self {
            journal: root.join(JOURNAL),
            next: root.join(NEXT),
            lock: root.join(LOCK),
            root,
        }
    }
}

fn create_or_validate_directory(path: &Path) -> Result<()> {
    let mut builder = DirBuilder::new();
    builder.mode(DIRECTORY_MODE);
    match builder.create(path) {
        Ok(()) => sync_directory(
            path.parent()
                .ok_or_else(|| eyre::eyre!("upgrade directory has no parent"))?,
        ),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => validate_directory(path),
        Err(error) => Err(error).wrap_err("create upgrade journal directory"),
    }
}

fn validate_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .wrap_err_with(|| format!("stat private directory {}", path.display()))?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != DIRECTORY_MODE
    {
        eyre::bail!(
            "private directory {} is not owner-only 0700",
            path.display()
        );
    }
    Ok(())
}

fn open_private_file(path: &Path, create: bool, max_bytes: u64) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .mode(FILE_MODE)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .wrap_err_with(|| format!("open private file {}", path.display()))?;
    validate_private_file(path, max_bytes)?;
    Ok(file)
}

fn validate_private_file(path: &Path, max_bytes: u64) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .wrap_err_with(|| format!("stat private file {}", path.display()))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.permissions().mode() & 0o777 != FILE_MODE
        || metadata.len() > max_bytes
    {
        eyre::bail!(
            "private file {} violates owner or size bounds",
            path.display()
        );
    }
    Ok(())
}

fn read_private_bounded_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    let file = open_private_file(path, false, max_bytes)?;
    let mut bytes = Vec::new();
    file.take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .wrap_err_with(|| format!("read private file {}", path.display()))?;
    if bytes.len() as u64 > max_bytes {
        eyre::bail!("private file {} exceeds its size cap", path.display());
    }
    Ok(bytes)
}

fn reconcile_scratch(paths: &JournalPaths) -> Result<()> {
    if paths.next.exists() {
        validate_private_file(&paths.next, MAX_JOURNAL_BYTES)?;
        fs::remove_file(&paths.next).wrap_err("discard incomplete upgrade journal scratch")?;
        sync_directory(&paths.root)?;
    }
    Ok(())
}

fn read_snapshot(path: &Path) -> Result<Option<UpgradeJournalSnapshotV1>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = read_private_bounded_file(path, MAX_JOURNAL_BYTES)?;
    let snapshot: UpgradeJournalSnapshotV1 =
        serde_json::from_slice(&bytes).wrap_err("decode upgrade journal")?;
    snapshot.validate()?;
    Ok(Some(snapshot))
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .wrap_err_with(|| format!("open directory {} for fsync", path.display()))?
        .sync_all()
        .wrap_err_with(|| format!("fsync directory {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::U256;

    fn private_dir(path: &Path) {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(DIRECTORY_MODE)).unwrap();
    }

    fn context(root: &Path) -> UpgradeContextV1 {
        UpgradeContextV1 {
            predecessor_manifest_hash: B256::repeat_byte(1),
            candidate_manifest_hash: B256::repeat_byte(2),
            successor_policy_hash: B256::repeat_byte(3),
            activation_height: 100,
            active_tee_dir: root.join("active"),
            candidate_tee_dir: root.join("candidate"),
        }
    }

    fn submission() -> PreparedUpgradeSubmissionV1 {
        let calldata = vec![1, 2];
        let raw_transaction = vec![3, 4];
        PreparedUpgradeSubmissionV1 {
            intent_hash: B256::repeat_byte(3),
            evidence_hash: B256::repeat_byte(4),
            calldata_hash: keccak256(&calldata),
            relay: Address::repeat_byte(5),
            relay_variants: vec![RawRelayTransactionV1 {
                relay: Address::repeat_byte(5),
                chain_id: 1,
                account_nonce: 2,
                gas_price: U256::from(3),
                gas_limit: 4,
                calldata_hash: keccak256(&calldata),
                transaction_hash: keccak256(&raw_transaction),
                raw_transaction,
            }],
        }
    }

    #[test]
    fn copies_only_sealed_root_and_exact_retry_is_idempotent() {
        let root = tempfile::tempdir().unwrap();
        let context = context(root.path());
        private_dir(&context.active_tee_dir);
        private_dir(&context.candidate_tee_dir);
        fs::write(context.active_tee_dir.join(SEALED_ROOT), b"sealed-root").unwrap();
        fs::set_permissions(
            context.active_tee_dir.join(SEALED_ROOT),
            fs::Permissions::from_mode(FILE_MODE),
        )
        .unwrap();
        fs::write(context.active_tee_dir.join("must-not-copy"), b"other").unwrap();

        let hash = copy_same_platform_sealed_root_v1(&context).unwrap();
        assert_eq!(hash, keccak256(b"sealed-root"));
        assert_eq!(
            fs::read(context.candidate_tee_dir.join(SEALED_ROOT)).unwrap(),
            b"sealed-root"
        );
        assert!(!context.candidate_tee_dir.join("must-not-copy").exists());
        assert_eq!(copy_same_platform_sealed_root_v1(&context).unwrap(), hash);

        fs::write(context.candidate_tee_dir.join(SEALED_ROOT), b"conflict").unwrap();
        assert!(copy_same_platform_sealed_root_v1(&context).is_err());
    }

    #[test]
    fn journal_roundtrips_all_security_relevant_checkpoints() {
        let root = tempfile::tempdir().unwrap();
        let context = context(root.path());
        let guard = UpgradeJournalGuardV1::acquire(root.path()).unwrap();
        guard
            .store(UpgradeJournalSnapshotV1::new(
                UpgradeJournalStateV1::CandidatePrepared {
                    context: context.clone(),
                },
            ))
            .unwrap();
        guard
            .store(UpgradeJournalSnapshotV1::new(
                UpgradeJournalStateV1::RootCopied {
                    context: context.clone(),
                    sealed_root_hash: B256::repeat_byte(6),
                },
            ))
            .unwrap();
        guard
            .store(UpgradeJournalSnapshotV1::new(
                UpgradeJournalStateV1::CandidateKeyReady {
                    context: context.clone(),
                    sealed_root_hash: B256::repeat_byte(6),
                    resident_offer_public: B256::repeat_byte(7),
                    proof_hash: B256::repeat_byte(8),
                },
            ))
            .unwrap();
        guard
            .store(UpgradeJournalSnapshotV1::new(
                UpgradeJournalStateV1::SubmissionPrepared {
                    context: context.clone(),
                    sealed_root_hash: B256::repeat_byte(6),
                    resident_offer_public: B256::repeat_byte(7),
                    proof_hash: B256::repeat_byte(8),
                    submission: submission(),
                },
            ))
            .unwrap();
        guard
            .store(UpgradeJournalSnapshotV1::new(
                UpgradeJournalStateV1::Submitted {
                    context: context.clone(),
                    sealed_root_hash: B256::repeat_byte(6),
                    resident_offer_public: B256::repeat_byte(7),
                    proof_hash: B256::repeat_byte(8),
                    submission: submission(),
                    submitted_at_finalized_height: 90,
                    transaction_hashes: vec![submission().relay_variants[0].transaction_hash],
                },
            ))
            .unwrap();
        guard
            .store(UpgradeJournalSnapshotV1::new(
                UpgradeJournalStateV1::Finalized {
                    context: context.clone(),
                    sealed_root_hash: B256::repeat_byte(6),
                    resident_offer_public: B256::repeat_byte(7),
                    proof_hash: B256::repeat_byte(8),
                    submission: submission(),
                    finalized_height: 91,
                    finalized_hash: B256::repeat_byte(9),
                },
            ))
            .unwrap();
        guard
            .store(UpgradeJournalSnapshotV1::new(
                UpgradeJournalStateV1::Promoted {
                    context,
                    sealed_root_hash: B256::repeat_byte(6),
                    resident_offer_public: B256::repeat_byte(7),
                    proof_hash: B256::repeat_byte(8),
                    submission: submission(),
                    finalized_height: 91,
                    finalized_hash: B256::repeat_byte(9),
                },
            ))
            .unwrap();
        let snapshot = guard.load().unwrap().unwrap();
        assert_eq!(snapshot.generation, 7);
        assert_eq!(snapshot.lifecycle.label(), "promoted");
        let metadata = fs::metadata(root.path().join(DIRECTORY).join(JOURNAL)).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, FILE_MODE);
    }

    #[test]
    fn journal_rejects_context_change_and_corrupt_committed_state() {
        let root = tempfile::tempdir().unwrap();
        let guard = UpgradeJournalGuardV1::acquire(root.path()).unwrap();
        let context = context(root.path());
        guard
            .store(UpgradeJournalSnapshotV1::new(
                UpgradeJournalStateV1::CandidatePrepared {
                    context: context.clone(),
                },
            ))
            .unwrap();
        let mut different = context;
        different.candidate_manifest_hash = B256::repeat_byte(9);
        assert!(guard
            .store(UpgradeJournalSnapshotV1::new(
                UpgradeJournalStateV1::CandidatePrepared { context: different },
            ))
            .is_err());
        drop(guard);
        fs::write(root.path().join(DIRECTORY).join(JOURNAL), b"corrupt").unwrap();
        assert!(inspect_upgrade_journal_v1(root.path()).is_err());
    }

    #[test]
    fn journal_rejects_skipped_or_changed_security_checkpoints() {
        let root = tempfile::tempdir().unwrap();
        let guard = UpgradeJournalGuardV1::acquire(root.path()).unwrap();
        let context = context(root.path());
        guard
            .store(UpgradeJournalSnapshotV1::new(
                UpgradeJournalStateV1::CandidatePrepared {
                    context: context.clone(),
                },
            ))
            .unwrap();
        assert!(guard
            .store(UpgradeJournalSnapshotV1::new(
                UpgradeJournalStateV1::CandidateKeyReady {
                    context: context.clone(),
                    sealed_root_hash: B256::repeat_byte(6),
                    resident_offer_public: B256::repeat_byte(7),
                    proof_hash: B256::repeat_byte(8),
                },
            ))
            .is_err());
        guard
            .store(UpgradeJournalSnapshotV1::new(
                UpgradeJournalStateV1::RootCopied {
                    context: context.clone(),
                    sealed_root_hash: B256::repeat_byte(6),
                },
            ))
            .unwrap();
        assert!(guard
            .store(UpgradeJournalSnapshotV1::new(
                UpgradeJournalStateV1::CandidateKeyReady {
                    context,
                    sealed_root_hash: B256::repeat_byte(9),
                    resident_offer_public: B256::repeat_byte(7),
                    proof_hash: B256::repeat_byte(8),
                },
            ))
            .is_err());
    }
}
