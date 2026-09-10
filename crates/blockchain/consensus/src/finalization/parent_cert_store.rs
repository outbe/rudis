//! Consensus-owned exact-parent proof handoff store (V2 unified schema).
//!
//! Two proof kinds live in this store, each in its own MDBX slot:
//!
//! 1. **Finalization** - written by the [`crate::finalization::actor::FinalizationActor`]
//!    after Simplex emits `Activity::Finalization`. The proposer-side selector
//!    reads it through [`CertifiedParentProofStore::get_best_parent_proof`] and
//!    builds OAV3 Phase 1 metadata from
//!    [`CertifiedParentProofRecord::to_v2_metadata`].
//! 2. **CertifiedNotarization** - written by [`crate::reporter::OutbeReporter`]
//!    after Simplex emits `Activity::Certification`. Commonware marshal's mailbox
//!    silently drops this activity (`_ => return;`), so Outbe is the only persistent
//!    consumer. The slot is keyed exactly like the finalization slot and is
//!    available to resolver-side local-witness checks.
//!
//! The store is keyed by `(epoch, view, finalized_or_notarized_block_hash)` and
//! only the Simplex context parent is eligible for Phase 1. There is no backlog
//! scan, no oldest-first selection, and no unrelated-parent substitution.
//!
//! Durable backend: MDBX (via `reth_db`) plus an in-memory read cache. Writes
//! commit synchronously before returning, so a crash between `put_*` and the
//! Phase 1 system-tx build cannot lose the proof.
//!
//! This store is **not** an EVM `StorageHandle` consumer - it is node-local
//! proposer-side state, parallel to (not a replacement for) the canonical
//! chain. it is out of scope for the
//! storage-handle survey.
//!
//! Record schema discriminant: every record carries
//! [`CertifiedParentProofRecord::format_version`] == 3. Records with any other
//! version are rejected on read (`Err(UnknownFormatVersion)`).

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, RwLock,
    },
};

use alloy_primitives::{Address, Bytes, B256};
use outbe_primitives::consensus_metadata::{
    CertifiedParentAccountingMetadata, ParentParticipationProof,
};
use reth_db::{
    cursor::DbCursorRO,
    database::Database,
    mdbx::{create_db, DatabaseArguments},
    table::Table,
    transaction::{DbTx, DbTxMut},
    ClientVersion, DatabaseEnv, DatabaseError,
};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

/// On-disk record schema version. Encoded into every persisted
/// [`CertifiedParentProofRecord`]; reads reject any other value
///.
pub const CERTIFIED_PARENT_PROOF_RECORD_FORMAT_VERSION: u8 = 3;

/// Exact lookup key for a certified-parent proof.
///
/// The block hash alone is not enough at epoch/view boundaries: the same hash
/// can be observed through different Simplex contexts during recovery or
/// tests. Phase 1 selection must therefore name the exact consensus parent
/// `(epoch, view, hash)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct CertifiedParentProofKey {
    pub epoch: u64,
    pub view: u64,
    pub block_hash: B256,
}

impl CertifiedParentProofKey {
    pub const fn new(epoch: u64, view: u64, block_hash: B256) -> Self {
        Self {
            epoch,
            view,
            block_hash,
        }
    }

    /// MDBX row key. Keeps the table key compact while preserving the full
    /// exact-key identity in the serialized value.
    pub fn storage_key(self) -> B256 {
        let mut bytes = Vec::with_capacity(37 + 8 + 8 + 32);
        bytes.extend_from_slice(b"OUTBE_CERTIFIED_PARENT_PROOF_KEY_V2");
        bytes.extend_from_slice(&self.epoch.to_be_bytes());
        bytes.extend_from_slice(&self.view.to_be_bytes());
        bytes.extend_from_slice(self.block_hash.as_slice());
        alloy_primitives::keccak256(bytes)
    }
}

mod tables {
    use alloy_primitives::B256;
    use reth_db::{
        table::{Table, TableInfo},
        TableSet,
    };

    /// MDBX table for `ParentParticipationProof::Finalization` records.
    #[derive(Debug)]
    pub struct OutbeCertifiedParentFinalizationRecords;

    impl Table for OutbeCertifiedParentFinalizationRecords {
        const NAME: &'static str = "OutbeCertifiedParentFinalizationRecordsV2";
        const DUPSORT: bool = false;

        type Key = B256;
        type Value = Vec<u8>;
    }

    impl TableInfo for OutbeCertifiedParentFinalizationRecords {
        fn name(&self) -> &'static str {
            <Self as Table>::NAME
        }

        fn is_dupsort(&self) -> bool {
            <Self as Table>::DUPSORT
        }
    }

    /// MDBX table for `ParentParticipationProof::CertifiedNotarization` records.
    #[derive(Debug)]
    pub struct OutbeCertifiedParentNotarizationRecords;

    impl Table for OutbeCertifiedParentNotarizationRecords {
        const NAME: &'static str = "OutbeCertifiedParentNotarizationRecordsV2";
        const DUPSORT: bool = false;

        type Key = B256;
        type Value = Vec<u8>;
    }

    impl TableInfo for OutbeCertifiedParentNotarizationRecords {
        fn name(&self) -> &'static str {
            <Self as Table>::NAME
        }

        fn is_dupsort(&self) -> bool {
            <Self as Table>::DUPSORT
        }
    }

    /// Legacy pre-V2 finalization table. Startup probes this name and fails
    /// fast if it exists; there is intentionally no silent migration path.
    #[derive(Debug)]
    pub struct OutbeCertifiedParentFinalizationRecordsV1;

    impl Table for OutbeCertifiedParentFinalizationRecordsV1 {
        const NAME: &'static str = "OutbeCertifiedParentFinalizationRecords";
        const DUPSORT: bool = false;

        type Key = B256;
        type Value = Vec<u8>;
    }

    impl TableInfo for OutbeCertifiedParentFinalizationRecordsV1 {
        fn name(&self) -> &'static str {
            <Self as Table>::NAME
        }

        fn is_dupsort(&self) -> bool {
            <Self as Table>::DUPSORT
        }
    }

    /// Legacy pre-V2 certified-notarization table.
    #[derive(Debug)]
    pub struct OutbeCertifiedParentNotarizationRecordsV1;

    impl Table for OutbeCertifiedParentNotarizationRecordsV1 {
        const NAME: &'static str = "OutbeCertifiedParentNotarizationRecords";
        const DUPSORT: bool = false;

        type Key = B256;
        type Value = Vec<u8>;
    }

    impl TableInfo for OutbeCertifiedParentNotarizationRecordsV1 {
        fn name(&self) -> &'static str {
            <Self as Table>::NAME
        }

        fn is_dupsort(&self) -> bool {
            <Self as Table>::DUPSORT
        }
    }

    #[cfg(test)]
    #[derive(Debug)]
    pub struct OutbeCertifiedParentProofLegacyTables;

    #[cfg(test)]
    impl TableSet for OutbeCertifiedParentProofLegacyTables {
        fn tables() -> Box<dyn Iterator<Item = Box<dyn TableInfo>>> {
            Box::new(
                [
                    Box::new(OutbeCertifiedParentFinalizationRecordsV1) as Box<dyn TableInfo>,
                    Box::new(OutbeCertifiedParentNotarizationRecordsV1) as Box<dyn TableInfo>,
                ]
                .into_iter(),
            )
        }
    }

    #[derive(Debug)]
    pub struct OutbeCertifiedParentProofTables;

    impl TableSet for OutbeCertifiedParentProofTables {
        fn tables() -> Box<dyn Iterator<Item = Box<dyn TableInfo>>> {
            Box::new(
                [
                    Box::new(OutbeCertifiedParentFinalizationRecords) as Box<dyn TableInfo>,
                    Box::new(OutbeCertifiedParentNotarizationRecords) as Box<dyn TableInfo>,
                ]
                .into_iter(),
            )
        }
    }
}

#[derive(Debug)]
pub enum ParentProofStoreError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Open {
        path: PathBuf,
        message: String,
    },
    Db {
        path: PathBuf,
        source: DatabaseError,
    },
    Serde {
        path: PathBuf,
        source: serde_json::Error,
    },
    Corrupt {
        path: PathBuf,
        message: String,
    },
    UnknownFormatVersion {
        path: PathBuf,
        version: u8,
    },
    LegacyTableFound {
        path: PathBuf,
        table: &'static str,
    },
}

impl std::fmt::Display for ParentProofStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParentProofStoreError::Io { path, source } => write!(f, "{}: {source}", path.display()),
            ParentProofStoreError::Open { path, message } => {
                write!(f, "{}: {message}", path.display())
            }
            ParentProofStoreError::Db { path, source } => write!(f, "{}: {source}", path.display()),
            ParentProofStoreError::Serde { path, source } => {
                write!(f, "{}: {source}", path.display())
            }
            ParentProofStoreError::Corrupt { path, message } => {
                write!(f, "{}: {message}", path.display())
            }
            ParentProofStoreError::UnknownFormatVersion { path, version } => write!(
                f,
                "{}: unknown CertifiedParentProofRecord format_version: {version} (expected {})",
                path.display(),
                CERTIFIED_PARENT_PROOF_RECORD_FORMAT_VERSION
            ),
            ParentProofStoreError::LegacyTableFound { path, table } => write!(
                f,
                "{}: legacy parent proof MDBX table {table} exists; delete/regenerate pre-mainnet state instead of silently starting with empty V2 tables",
                path.display()
            ),
        }
    }
}

impl std::error::Error for ParentProofStoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ParentProofStoreError::Io { source, .. } => Some(source),
            ParentProofStoreError::Db { source, .. } => Some(source),
            ParentProofStoreError::Serde { source, .. } => Some(source),
            ParentProofStoreError::Open { .. }
            | ParentProofStoreError::Corrupt { .. }
            | ParentProofStoreError::UnknownFormatVersion { .. }
            | ParentProofStoreError::LegacyTableFound { .. } => None,
        }
    }
}

/// Which kind of parent proof a record carries, with the variant-specific data
/// that used to be conflated into shared fields (the former `proof_type`,
/// sentinel-`finalized_block_number`, and `local_certification_witness`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofKind {
    /// A finalized block's exact-parent proof - carries its real on-chain height.
    Finalization { finalized_block_number: u64 },
    /// A certified-notarization witness. It carries NO block number (the
    /// notarization has no block context); the proposer-side selector resolves
    /// the height to the known `parent_block_number` at read time. A record in
    /// this variant is, by construction, a local certification witness.
    CertifiedNotarization,
}

/// V2 per-parent proof record. One schema for both proof kinds; the
/// variant-specific data (height for `Finalization`, none for
/// `CertifiedNotarization`) plus the former `proof_type` and
/// `local_certification_witness` discriminants now live in [`ProofKind`]. The
/// canonical `encoded_proof` blob is authoritative; the other V2 fields
/// (`committee_set_hash`, `vrf_material_version`, `vrf_group_public_key_hash`)
/// are materialised by the writer so the proposer builds Phase 1 metadata
/// without a snapshot lookup.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CertifiedParentProofRecord {
    pub format_version: u8,
    /// Proof kind plus its variant-specific data. Replaces the former
    /// `proof_type`, sentinel `finalized_block_number`, and
    /// `local_certification_witness` fields (their invariants are now in the type).
    pub kind: ProofKind,
    pub finalized_epoch: u64,
    pub finalized_view: u64,
    pub parent_view: u64,
    pub finalized_block_hash: B256,
    pub committee_set_hash: B256,
    pub vrf_material_version: u64,
    /// keccak256 of the encoded VRF group public key for the active epoch's DKG
    /// material. Populated by the writer so the proposer-side V2 selector can
    /// build [`outbe_primitives::consensus_metadata::CertifiedParentAccountingMetadata`]
    /// without a separate snapshot lookup. The verifier checks the same hash via
    /// `outbe_consensus::proof::verify_v2_proof` rule 6.
    pub vrf_group_public_key_hash: B256,
    pub ordered_committee: Vec<Address>,
    pub signer_bitmap: Vec<u8>,
    /// Canonical commonware-codec bytes of the source `Notarization` /
    /// `Finalization` (the writer never re-encodes).
    pub encoded_proof: Bytes,
    /// Age-based pruning key: the finalized block height for `Finalization`, the
    /// notarization view as a monotone retention proxy for `CertifiedNotarization`.
    pub stored_at_height: u64,
}

impl Default for CertifiedParentProofRecord {
    fn default() -> Self {
        Self {
            format_version: CERTIFIED_PARENT_PROOF_RECORD_FORMAT_VERSION,
            kind: ProofKind::Finalization {
                finalized_block_number: 0,
            },
            finalized_epoch: 0,
            finalized_view: 0,
            parent_view: 0,
            finalized_block_hash: B256::ZERO,
            committee_set_hash: B256::ZERO,
            vrf_material_version: 0,
            vrf_group_public_key_hash: B256::ZERO,
            ordered_committee: Vec::new(),
            signer_bitmap: Vec::new(),
            encoded_proof: Bytes::new(),
            stored_at_height: 0,
        }
    }
}

impl CertifiedParentProofRecord {
    pub fn proof_key(&self) -> CertifiedParentProofKey {
        CertifiedParentProofKey::new(
            self.finalized_epoch,
            self.finalized_view,
            self.finalized_block_hash,
        )
    }

    /// The block height this proof binds to: real for `Finalization`, `None` for
    /// a `CertifiedNotarization` witness (the selector resolves it to the known
    /// `parent_block_number` at read time).
    pub fn finalized_block_number(&self) -> Option<u64> {
        match self.kind {
            ProofKind::Finalization {
                finalized_block_number,
            } => Some(finalized_block_number),
            ProofKind::CertifiedNotarization => None,
        }
    }

    /// The wire-metadata proof-kind discriminant.
    pub fn proof_kind(&self) -> ParentParticipationProof {
        match self.kind {
            ProofKind::Finalization { .. } => ParentParticipationProof::Finalization,
            ProofKind::CertifiedNotarization => ParentParticipationProof::CertifiedNotarization,
        }
    }

    /// Whether this record is a certified-notarization local witness.
    pub fn is_certification_witness(&self) -> bool {
        matches!(self.kind, ProofKind::CertifiedNotarization)
    }

    /// Build the V2 [`CertifiedParentAccountingMetadata`] from the stored record.
    /// `finalized_block_number` is supplied by the selector (the validated parent
    /// height): it equals the record's own height for `Finalization` and the
    /// resolved `parent_block_number` for a promoted `CertifiedNotarization`
    /// witness. Every other V2 field comes from the record, so no snapshot lookup
    /// is needed at read time.
    pub fn to_v2_metadata(&self, finalized_block_number: u64) -> CertifiedParentAccountingMetadata {
        CertifiedParentAccountingMetadata {
            finalized_block_number,
            finalized_block_hash: self.finalized_block_hash,
            finalized_epoch: self.finalized_epoch,
            finalized_view: self.finalized_view,
            parent_view: self.parent_view,
            ordered_committee: self.ordered_committee.clone(),
            signer_bitmap: self.signer_bitmap.clone(),
            proof: self.encoded_proof.clone(),
            committee_set_hash: self.committee_set_hash,
            vrf_material_version: self.vrf_material_version,
            vrf_group_public_key_hash: self.vrf_group_public_key_hash,
            proof_kind: self.proof_kind(),
            missed_proposers: Vec::new(),
        }
    }
}

/// Public trait surface for the consensus-owned exact-parent proof store
///. Two proof kinds, one record schema; the trait keeps
/// finalization and certified-notarization slots logically distinct so writers
/// cannot confuse the two paths.
///
/// **Invariants:**
/// - `get_certified_notarization` only answers for the exact
///   `(epoch, view, block_hash)` whose hash matches the key.
/// - `get_best_parent_proof` returns the finalization record first and
///   falls back to certified-notarization only when no finalization is present.
/// - Reads reject any record with `format_version != 1`.
/// - `put_certified_notarization` callers must set
///   `local_certification_witness = true` when the writer is the local reporter,
///   and gate remote-fetch fallbacks on the local witness having been seen.
pub trait CertifiedParentProofStore: Clone + Send + Sync + 'static {
    fn put_finalization(
        &self,
        record: CertifiedParentProofRecord,
    ) -> Result<(), ParentProofStoreError>;

    fn put_certified_notarization(
        &self,
        record: CertifiedParentProofRecord,
    ) -> Result<(), ParentProofStoreError>;

    fn get_finalization(&self, key: &CertifiedParentProofKey)
        -> Option<CertifiedParentProofRecord>;

    fn get_certified_notarization(
        &self,
        key: &CertifiedParentProofKey,
    ) -> Option<CertifiedParentProofRecord>;

    /// returns the finalization record if present; otherwise falls back
    /// to the certified-notarization record for the same exact key.
    fn get_best_parent_proof(
        &self,
        key: &CertifiedParentProofKey,
    ) -> Option<CertifiedParentProofRecord> {
        self.get_finalization(key)
            .or_else(|| self.get_certified_notarization(key))
    }

    fn remove(&self, key: &CertifiedParentProofKey) -> Result<bool, ParentProofStoreError>;

    fn prune_below_height(&self, floor: u64) -> Result<usize, ParentProofStoreError>;

    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn oldest_stored_height(&self) -> Option<u64>;
}

/// Atomic snapshot returned by [`FinalizedParentCertStore::get_best_for_parent`].
///
/// The store never mutates a CN witness while selecting. If
/// `requires_promotion` is true, the caller may substitute the known parent
/// block number on its owned clone after the bounded finalization wait expires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParentProofSelection {
    Finalization(CertifiedParentProofRecord),
    /// A certified-notarization witness. It always requires the selector to
    /// resolve its height to the known `parent_block_number` (it carries no block
    /// number of its own), so the former `requires_promotion` flag is implied by
    /// the variant.
    CertifiedNotarization(CertifiedParentProofRecord),
}

/// Hash-keyed parent proof store. Cheap to clone - internally
/// `Arc<RwLock<...>>`. All public methods are non-blocking other than the brief
/// lock acquire; lock window is microseconds.
#[derive(Clone)]
pub struct FinalizedParentCertStore {
    inner: Arc<RwLock<ParentProofStoreState>>,
    backend: Option<Arc<MdbxParentProofBackend>>,
    revision: Arc<AtomicU64>,
    revision_tx: watch::Sender<u64>,
}

#[derive(Default)]
struct ParentProofStoreState {
    finalization: BTreeMap<CertifiedParentProofKey, CertifiedParentProofRecord>,
    certified_notarization: BTreeMap<CertifiedParentProofKey, CertifiedParentProofRecord>,
    seen_certification_keys: BTreeMap<CertifiedParentProofKey, u64>,
}

impl Default for FinalizedParentCertStore {
    fn default() -> Self {
        let (revision_tx, _revision_rx) = watch::channel(0);
        Self {
            inner: Arc::new(RwLock::new(ParentProofStoreState::default())),
            backend: None,
            revision: Arc::new(AtomicU64::new(0)),
            revision_tx,
        }
    }
}

impl FinalizedParentCertStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Open a durable write-ahead store at `dir`. Existing rows in both
    /// finalization and certified-notarization tables are loaded into the
    /// in-memory cache before the handle is returned. A row whose decoded
    /// payload reports an unexpected `format_version` is a startup error
    /// rather than silent data loss.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self, ParentProofStoreError> {
        let backend = Arc::new(MdbxParentProofBackend::open(dir.as_ref())?);
        let mut state = ParentProofStoreState::default();
        for rec in backend.load_all::<tables::OutbeCertifiedParentFinalizationRecords>()? {
            state.finalization.insert(rec.proof_key(), rec);
        }
        for rec in backend.load_all::<tables::OutbeCertifiedParentNotarizationRecords>()? {
            let key = rec.proof_key();
            if rec.is_certification_witness() {
                state
                    .seen_certification_keys
                    .insert(key, rec.stored_at_height);
            }
            state.certified_notarization.insert(key, rec);
        }
        Ok(Self {
            inner: Arc::new(RwLock::new(state)),
            backend: Some(backend),
            revision: Arc::new(AtomicU64::new(0)),
            revision_tx: watch::channel(0).0,
        })
    }

    fn put_inner(
        &self,
        record: CertifiedParentProofRecord,
        slot: ProofSlot,
    ) -> Result<(), ParentProofStoreError> {
        if record.format_version != CERTIFIED_PARENT_PROOF_RECORD_FORMAT_VERSION {
            return Err(ParentProofStoreError::UnknownFormatVersion {
                path: self
                    .backend
                    .as_ref()
                    .map(|b| b.path.clone())
                    .unwrap_or_default(),
                version: record.format_version,
            });
        }
        if let Some(backend) = &self.backend {
            backend.write_record(&record, slot)?;
        }
        let mut state = self.lock_write();
        let key = record.proof_key();
        match slot {
            ProofSlot::Finalization => {
                state.finalization.insert(key, record);
            }
            ProofSlot::CertifiedNotarization => {
                if record.is_certification_witness() {
                    state
                        .seen_certification_keys
                        .insert(key, record.stored_at_height);
                }
                state.certified_notarization.insert(key, record);
            }
        }
        drop(state);
        self.bump_revision();
        Ok(())
    }

    fn bump_revision(&self) {
        let next = self
            .revision
            .fetch_add(1, Ordering::Relaxed)
            .saturating_add(1);
        let _ = self.revision_tx.send(next);
    }

    fn lock_read(&self) -> std::sync::RwLockReadGuard<'_, ParentProofStoreState> {
        match self.inner.read() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    fn lock_write(&self) -> std::sync::RwLockWriteGuard<'_, ParentProofStoreState> {
        match self.inner.write() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        }
    }

    pub fn get_finalization(
        &self,
        key: CertifiedParentProofKey,
    ) -> Option<CertifiedParentProofRecord> {
        self.lock_read().finalization.get(&key).cloned()
    }

    /// Return every persisted finalization record for one exact block identity.
    ///
    /// OCOMP proof construction accepts exactly one record and treats zero or
    /// multiple records as local abstention. Returning the complete,
    /// deterministically ordered set keeps that policy outside the consensus
    /// store and prevents this adapter from silently choosing among proofs.
    pub fn finalizations_for_block(
        &self,
        block_number: u64,
        block_hash: B256,
    ) -> Vec<CertifiedParentProofRecord> {
        self.lock_read()
            .finalization
            .values()
            .filter(|record| {
                record.finalized_block_hash == block_hash
                    && record.finalized_block_number() == Some(block_number)
            })
            .cloned()
            .collect()
    }

    /// Return every persisted finalization record at one block height.
    ///
    /// Retention restart reconciliation uses this complete set to distinguish
    /// an exact finalized candidate from a proven competing canonical block.
    /// The caller must treat an empty or internally ambiguous set as
    /// unavailable; this store never guesses a winner.
    pub fn finalizations_at_height(&self, block_number: u64) -> Vec<CertifiedParentProofRecord> {
        self.lock_read()
            .finalization
            .values()
            .filter(|record| record.finalized_block_number() == Some(block_number))
            .cloned()
            .collect()
    }

    pub fn get_certified_notarization(
        &self,
        key: CertifiedParentProofKey,
    ) -> Option<CertifiedParentProofRecord> {
        self.lock_read().certified_notarization.get(&key).cloned()
    }

    pub fn get_best_parent_proof(
        &self,
        key: CertifiedParentProofKey,
    ) -> Option<CertifiedParentProofRecord> {
        self.get_finalization(key)
            .or_else(|| self.get_certified_notarization(key))
    }

    /// Atomic-read selector snapshot for a known parent block number.
    ///
    /// Acquires the store read lock once, reads both slots, and returns owned
    /// clones. Finalization always wins. No mutation is performed here; CN
    /// witness promotion is a caller-side substitution on the returned clone.
    pub fn get_best_for_parent(
        &self,
        key: CertifiedParentProofKey,
        _parent_block_number: u64,
    ) -> Option<ParentProofSelection> {
        let state = self.lock_read();
        if let Some(record) = state.finalization.get(&key) {
            return Some(ParentProofSelection::Finalization(record.clone()));
        }
        state
            .certified_notarization
            .get(&key)
            .map(|record| ParentProofSelection::CertifiedNotarization(record.clone()))
    }

    /// Subscribe to proof-store writes. The payload is a monotonic revision
    /// counter, so waiters cannot miss an update that happened between their
    /// initial read and `changed().await`.
    pub fn subscribe_revisions(&self) -> watch::Receiver<u64> {
        self.revision_tx.subscribe()
    }

    /// True only if this node locally observed certification for the exact key.
    pub fn has_local_certification_witness(&self, key: CertifiedParentProofKey) -> bool {
        self.lock_read().seen_certification_keys.contains_key(&key)
    }

    pub fn remove(&self, key: CertifiedParentProofKey) -> Result<bool, ParentProofStoreError> {
        <Self as CertifiedParentProofStore>::remove(self, &key)
    }

    /// Drop finalization records persisted for heights strictly above `ceiling`.
    ///
    /// `process_finalization` durably writes the height-N parent record before it
    /// advances the finalization view, so a crash in that window can leave an
    /// ahead-of-recovered-view record on disk. Called once at startup with the
    /// recovered finalized height, this restores the invariant
    /// `stored_at_height <= recovered_last_finalized`. Selection already drains
    /// any height-mismatched record at read time (`validate_parent_record`), so
    /// this is defensive on-disk hygiene, not a divergence fix.
    ///
    /// Only the `Finalization` slot is touched: its `stored_at_height` is the real
    /// block height. `CertifiedNotarization` records key `stored_at_height` to the
    /// notarization view (a retention proxy, not a height), so they are not
    /// comparable to a block-height ceiling and are left untouched.
    pub fn prune_above_height(&self, ceiling: u64) -> Result<usize, ParentProofStoreError> {
        let fin_drop: Vec<CertifiedParentProofKey> = {
            let state = self.lock_read();
            state
                .finalization
                .iter()
                .filter_map(|(key, r)| (r.stored_at_height > ceiling).then_some(*key))
                .collect()
        };
        if fin_drop.is_empty() {
            return Ok(0);
        }
        if let Some(backend) = &self.backend {
            for key in &fin_drop {
                backend.remove_record::<tables::OutbeCertifiedParentFinalizationRecords>(key)?;
            }
        }
        let mut dropped = 0usize;
        {
            let mut state = self.lock_write();
            for key in fin_drop {
                if state.finalization.remove(&key).is_some() {
                    dropped += 1;
                }
            }
        }
        if dropped > 0 {
            self.bump_revision();
        }
        Ok(dropped)
    }
}

/// Narrow, write-only capability to record a local `Activity::Certification`
/// observation. This is the *only* surface the consensus voter side
/// (`OutbeReporter`) is given onto the store, so the reporter structurally
/// cannot reach the durable-write methods (`put_*` / `remove` / `prune`). Durable
/// writes stay the `FinalizationActor`'s responsibility (single durable writer) -
/// the capability narrowing makes that invariant type-enforced instead of
/// convention, preventing a future reporter edit from regressing the off-thread
/// persistence boundary established for the certified-notarization path.
pub trait CertificationWitnessSink: Send + Sync {
    /// Record that this node locally observed certification for `key`
    /// (in-memory; cheap locked insert into `seen_certification_keys`).
    fn mark_local_certification_witness(&self, key: CertifiedParentProofKey);
}

impl CertificationWitnessSink for FinalizedParentCertStore {
    fn mark_local_certification_witness(&self, key: CertifiedParentProofKey) {
        let mut state = self.lock_write();
        state.seen_certification_keys.insert(key, key.view);
    }
}

impl CertifiedParentProofStore for FinalizedParentCertStore {
    fn put_finalization(
        &self,
        record: CertifiedParentProofRecord,
    ) -> Result<(), ParentProofStoreError> {
        debug_assert_eq!(
            record.proof_kind(),
            ParentParticipationProof::Finalization,
            "put_finalization called with non-Finalization record"
        );
        self.put_inner(record, ProofSlot::Finalization)
    }

    fn put_certified_notarization(
        &self,
        record: CertifiedParentProofRecord,
    ) -> Result<(), ParentProofStoreError> {
        debug_assert_eq!(
            record.proof_kind(),
            ParentParticipationProof::CertifiedNotarization,
            "put_certified_notarization called with non-CertifiedNotarization record"
        );
        self.put_inner(record, ProofSlot::CertifiedNotarization)
    }

    fn get_finalization(
        &self,
        key: &CertifiedParentProofKey,
    ) -> Option<CertifiedParentProofRecord> {
        self.lock_read().finalization.get(key).cloned()
    }

    fn get_certified_notarization(
        &self,
        key: &CertifiedParentProofKey,
    ) -> Option<CertifiedParentProofRecord> {
        self.lock_read().certified_notarization.get(key).cloned()
    }

    fn remove(&self, key: &CertifiedParentProofKey) -> Result<bool, ParentProofStoreError> {
        if let Some(backend) = &self.backend {
            backend.remove_record::<tables::OutbeCertifiedParentFinalizationRecords>(key)?;
            backend.remove_record::<tables::OutbeCertifiedParentNotarizationRecords>(key)?;
        }
        let mut state = self.lock_write();
        let removed_fin = state.finalization.remove(key).is_some();
        let removed_cn = state.certified_notarization.remove(key).is_some();
        state.seen_certification_keys.remove(key);
        let removed = removed_fin || removed_cn;
        drop(state);
        if removed {
            self.bump_revision();
        }
        Ok(removed)
    }

    fn prune_below_height(&self, floor: u64) -> Result<usize, ParentProofStoreError> {
        let (fin_drop, cn_drop, witness_drop): (
            Vec<CertifiedParentProofKey>,
            Vec<CertifiedParentProofKey>,
            Vec<CertifiedParentProofKey>,
        ) = {
            let state = self.lock_read();
            (
                state
                    .finalization
                    .iter()
                    .filter_map(|(key, r)| (r.stored_at_height < floor).then_some(*key))
                    .collect(),
                state
                    .certified_notarization
                    .iter()
                    .filter_map(|(key, r)| (r.stored_at_height < floor).then_some(*key))
                    .collect(),
                state
                    .seen_certification_keys
                    .iter()
                    .filter_map(|(key, stored_at_height)| {
                        (*stored_at_height < floor).then_some(*key)
                    })
                    .collect(),
            )
        };
        if let Some(backend) = &self.backend {
            for key in &fin_drop {
                backend.remove_record::<tables::OutbeCertifiedParentFinalizationRecords>(key)?;
            }
            for key in &cn_drop {
                backend.remove_record::<tables::OutbeCertifiedParentNotarizationRecords>(key)?;
            }
        }
        let mut state = self.lock_write();
        let mut dropped = 0usize;
        for key in fin_drop {
            if state.finalization.remove(&key).is_some() {
                dropped += 1;
            }
        }
        for key in cn_drop {
            if state.certified_notarization.remove(&key).is_some() {
                dropped += 1;
            }
        }
        for key in witness_drop {
            state.seen_certification_keys.remove(&key);
        }
        drop(state);
        if dropped > 0 {
            self.bump_revision();
        }
        Ok(dropped)
    }

    fn len(&self) -> usize {
        let state = self.lock_read();
        state.finalization.len() + state.certified_notarization.len()
    }

    fn oldest_stored_height(&self) -> Option<u64> {
        let state = self.lock_read();
        state
            .finalization
            .values()
            .chain(state.certified_notarization.values())
            .map(|r| r.stored_at_height)
            .min()
    }
}

#[derive(Clone, Copy)]
enum ProofSlot {
    Finalization,
    CertifiedNotarization,
}

struct MdbxParentProofBackend {
    path: PathBuf,
    db: Arc<DatabaseEnv>,
}

impl std::fmt::Debug for MdbxParentProofBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MdbxParentProofBackend")
            .field("path", &self.path)
            .finish()
    }
}

fn reject_legacy_parent_proof_tables(
    path: &Path,
    db: &DatabaseEnv,
) -> Result<(), ParentProofStoreError> {
    if legacy_table_exists::<tables::OutbeCertifiedParentFinalizationRecordsV1>(path, db)? {
        return Err(ParentProofStoreError::LegacyTableFound {
            path: path.to_path_buf(),
            table: <tables::OutbeCertifiedParentFinalizationRecordsV1 as Table>::NAME,
        });
    }
    if legacy_table_exists::<tables::OutbeCertifiedParentNotarizationRecordsV1>(path, db)? {
        return Err(ParentProofStoreError::LegacyTableFound {
            path: path.to_path_buf(),
            table: <tables::OutbeCertifiedParentNotarizationRecordsV1 as Table>::NAME,
        });
    }
    Ok(())
}

fn legacy_table_exists<T: Table<Key = B256, Value = Vec<u8>>>(
    path: &Path,
    db: &DatabaseEnv,
) -> Result<bool, ParentProofStoreError> {
    let tx = db.tx().map_err(|source| ParentProofStoreError::Db {
        path: path.to_path_buf(),
        source,
    })?;
    match tx.entries::<T>() {
        Ok(_) => {
            tx.commit().map_err(|source| ParentProofStoreError::Db {
                path: path.to_path_buf(),
                source,
            })?;
            Ok(true)
        }
        Err(source) if is_missing_table_error(&source) => Ok(false),
        Err(source) => Err(ParentProofStoreError::Db {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn is_missing_table_error(error: &DatabaseError) -> bool {
    match error {
        DatabaseError::Open(info) => {
            let message = info.message.to_ascii_lowercase();
            info.code == -30798
                || message.contains("notfound")
                || message.contains("not found")
                || message.contains("mdbx_notfound")
                || message.contains("no matching key/data")
        }
        _ => false,
    }
}

impl MdbxParentProofBackend {
    fn open(dir: &Path) -> Result<Self, ParentProofStoreError> {
        std::fs::create_dir_all(dir).map_err(|source| ParentProofStoreError::Io {
            path: dir.to_path_buf(),
            source,
        })?;
        let args = DatabaseArguments::new(ClientVersion::default());
        let client_version = args.client_version().clone();
        let mut db = create_db(dir, args).map_err(|source| ParentProofStoreError::Open {
            path: dir.to_path_buf(),
            message: source.to_string(),
        })?;
        reject_legacy_parent_proof_tables(dir, &db)?;
        db.create_and_track_tables_for::<tables::OutbeCertifiedParentProofTables>()
            .map_err(|source| ParentProofStoreError::Open {
                path: dir.to_path_buf(),
                message: source.to_string(),
            })?;
        db.record_client_version(client_version)
            .map_err(|source| ParentProofStoreError::Open {
                path: dir.to_path_buf(),
                message: source.to_string(),
            })?;
        Ok(Self {
            path: dir.to_path_buf(),
            db: Arc::new(db),
        })
    }

    fn load_all<T: Table<Key = B256, Value = Vec<u8>>>(
        &self,
    ) -> Result<Vec<CertifiedParentProofRecord>, ParentProofStoreError> {
        let mut records = Vec::new();
        let tx = self.db.tx().map_err(|s| self.db_error(s))?;
        let mut cursor = tx.cursor_read::<T>().map_err(|s| self.db_error(s))?;
        let walker = cursor.walk(None).map_err(|s| self.db_error(s))?;
        for row in walker {
            let (storage_key, bytes) = row.map_err(|s| self.db_error(s))?;
            let rec = self.decode_record(bytes)?;
            let proof_key = rec.proof_key();
            if proof_key.storage_key() != storage_key {
                return Err(ParentProofStoreError::Corrupt {
                    path: self.path.clone(),
                    message: format!(
                        "parent proof record key {storage_key} does not match payload exact key {:?}",
                        proof_key
                    ),
                });
            }
            records.push(rec);
        }
        tx.commit().map_err(|s| self.db_error(s))?;
        Ok(records)
    }

    fn write_record(
        &self,
        rec: &CertifiedParentProofRecord,
        slot: ProofSlot,
    ) -> Result<(), ParentProofStoreError> {
        let bytes = self.encode_record(rec)?;
        let tx = self.db.tx_mut().map_err(|s| self.db_error(s))?;
        let key = rec.proof_key().storage_key();
        match slot {
            ProofSlot::Finalization => tx
                .put::<tables::OutbeCertifiedParentFinalizationRecords>(key, bytes)
                .map_err(|s| self.db_error(s))?,
            ProofSlot::CertifiedNotarization => tx
                .put::<tables::OutbeCertifiedParentNotarizationRecords>(key, bytes)
                .map_err(|s| self.db_error(s))?,
        }
        tx.commit().map_err(|s| self.db_error(s))
    }

    fn remove_record<T: Table<Key = B256, Value = Vec<u8>>>(
        &self,
        key: &CertifiedParentProofKey,
    ) -> Result<(), ParentProofStoreError> {
        let tx = self.db.tx_mut().map_err(|s| self.db_error(s))?;
        // `delete` returns Ok(false) when the key is absent; that is not an
        // error condition here.
        tx.delete::<T>(key.storage_key(), None)
            .map_err(|s| self.db_error(s))?;
        tx.commit().map_err(|s| self.db_error(s))
    }

    fn encode_record(
        &self,
        rec: &CertifiedParentProofRecord,
    ) -> Result<Vec<u8>, ParentProofStoreError> {
        serde_json::to_vec(rec).map_err(|source| ParentProofStoreError::Serde {
            path: self.path.clone(),
            source,
        })
    }

    fn decode_record(
        &self,
        bytes: Vec<u8>,
    ) -> Result<CertifiedParentProofRecord, ParentProofStoreError> {
        let rec: CertifiedParentProofRecord =
            serde_json::from_slice(&bytes).map_err(|source| ParentProofStoreError::Serde {
                path: self.path.clone(),
                source,
            })?;
        if rec.format_version != CERTIFIED_PARENT_PROOF_RECORD_FORMAT_VERSION {
            return Err(ParentProofStoreError::UnknownFormatVersion {
                path: self.path.clone(),
                version: rec.format_version,
            });
        }
        Ok(rec)
    }

    fn db_error(&self, source: DatabaseError) -> ParentProofStoreError {
        ParentProofStoreError::Db {
            path: self.path.clone(),
            source,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    fn finalization_record(hash_byte: u8, height: u64) -> CertifiedParentProofRecord {
        CertifiedParentProofRecord {
            kind: ProofKind::Finalization {
                finalized_block_number: height,
            },
            finalized_block_hash: B256::with_last_byte(hash_byte),
            finalized_epoch: 1,
            finalized_view: 100,
            parent_view: 99,
            ordered_committee: vec![address!("0x1111111111111111111111111111111111111111")],
            signer_bitmap: vec![1],
            encoded_proof: Bytes::from_static(b"cert"),
            stored_at_height: height,
            ..CertifiedParentProofRecord::default()
        }
    }

    fn notarization_record(hash_byte: u8, height: u64) -> CertifiedParentProofRecord {
        CertifiedParentProofRecord {
            kind: ProofKind::CertifiedNotarization,
            finalized_block_hash: B256::with_last_byte(hash_byte),
            finalized_epoch: 1,
            finalized_view: 100,
            parent_view: 99,
            ordered_committee: vec![address!("0x2222222222222222222222222222222222222222")],
            signer_bitmap: vec![3],
            encoded_proof: Bytes::from_static(b"notar"),
            stored_at_height: height,
            ..CertifiedParentProofRecord::default()
        }
    }

    fn key(hash_byte: u8) -> CertifiedParentProofKey {
        CertifiedParentProofKey::new(1, 100, B256::with_last_byte(hash_byte))
    }

    /// Pins the dual-semantic invariants retired by the per-proof-type `kind`
    /// split: a `Finalization` record carries its own height; a
    /// `CertifiedNotarization` witness carries none (the selector resolves it to
    /// the parent height passed to `to_v2_metadata`, replacing the former
    /// sentinel-0-then-mutate promotion). `is_certification_witness` and
    /// `proof_kind` are now derived from the variant, not stored bools/fields.
    #[test]
    fn proof_kind_retires_dual_semantic_fields() {
        let fin = finalization_record(0xAA, 41);
        assert_eq!(fin.finalized_block_number(), Some(41));
        assert_eq!(fin.proof_kind(), ParentParticipationProof::Finalization);
        assert!(!fin.is_certification_witness());
        assert_eq!(fin.to_v2_metadata(41).finalized_block_number, 41);

        let cn = notarization_record(0xBB, 7);
        assert_eq!(
            cn.finalized_block_number(),
            None,
            "a certified-notarization witness carries no block number of its own"
        );
        assert_eq!(
            cn.proof_kind(),
            ParentParticipationProof::CertifiedNotarization
        );
        assert!(cn.is_certification_witness());
        // The selector promotes the witness to the supplied parent height.
        let meta = cn.to_v2_metadata(99);
        assert_eq!(meta.finalized_block_number, 99);
        assert_eq!(
            meta.proof_kind,
            ParentParticipationProof::CertifiedNotarization
        );
    }

    #[test]
    fn prune_above_height_drops_only_ahead_finalization_records() {
        let store = FinalizedParentCertStore::new();
        store
            .put_finalization(finalization_record(0xAA, 50))
            .unwrap();
        store
            .put_finalization(finalization_record(0xBB, 100))
            .unwrap();
        // CN witness: stored_at_height is a notarization-view proxy, not a height.
        store
            .put_certified_notarization(notarization_record(0xCC, 100))
            .unwrap();

        // Recovered finalized height = 60: the height-100 finalization record is
        // ahead of the view and is dropped; the height-50 record stays.
        let dropped = store.prune_above_height(60).unwrap();
        assert_eq!(dropped, 1);
        assert!(store.get_finalization(key(0xAA)).is_some());
        assert!(store.get_finalization(key(0xBB)).is_none());
        // The CertifiedNotarization slot is view-keyed, not height-comparable, so
        // an above-height prune never touches it.
        assert!(store.get_certified_notarization(key(0xCC)).is_some());
    }

    #[test]
    fn put_finalization_get_finalization_roundtrip() {
        let store = FinalizedParentCertStore::new();
        let r = finalization_record(0xAA, 100);
        store.put_finalization(r.clone()).unwrap();
        assert_eq!(store.get_finalization(key(0xAA)), Some(r));
        assert_eq!(store.get_finalization(key(0xBB)), None);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn put_certified_notarization_get_certified_notarization_exact_key_only() {
        let store = FinalizedParentCertStore::new();
        let r = notarization_record(0xAA, 100);
        store.put_certified_notarization(r.clone()).unwrap();
        // exact-key lookup only - no fuzzy match.
        assert_eq!(store.get_certified_notarization(key(0xAA)), Some(r));
        assert_eq!(store.get_certified_notarization(key(0xBB)), None);
    }

    #[test]
    fn put_finalization_get_best_parent_proof_returns_finalization_first() {
        // best-proof finalization-first.
        let store = FinalizedParentCertStore::new();
        store
            .put_certified_notarization(notarization_record(0xAA, 100))
            .unwrap();
        store
            .put_finalization(finalization_record(0xAA, 100))
            .unwrap();
        let best = store.get_best_parent_proof(key(0xAA)).unwrap();
        assert_eq!(best.proof_kind(), ParentParticipationProof::Finalization);
    }

    #[test]
    fn get_best_for_parent_is_single_snapshot_and_reports_cn_promotion_need() {
        let store = FinalizedParentCertStore::new();
        let witness = notarization_record(0xAA, 0);
        store.put_certified_notarization(witness).unwrap();

        let best = store.get_best_for_parent(key(0xAA), 100).unwrap();
        assert!(matches!(
            best,
            ParentProofSelection::CertifiedNotarization(_)
        ));

        store
            .put_finalization(finalization_record(0xAA, 100))
            .unwrap();
        let best = store.get_best_for_parent(key(0xAA), 100).unwrap();
        assert!(matches!(best, ParentProofSelection::Finalization(_)));
    }

    #[test]
    fn get_best_parent_proof_falls_back_to_certified_notarization() {
        let store = FinalizedParentCertStore::new();
        store
            .put_certified_notarization(notarization_record(0xAA, 100))
            .unwrap();
        let best = store.get_best_parent_proof(key(0xAA)).unwrap();
        assert_eq!(
            best.proof_kind(),
            ParentParticipationProof::CertifiedNotarization
        );
    }

    #[test]
    fn local_certification_witness_is_separate_from_persistent_cn_lookup() {
        let store = FinalizedParentCertStore::new();
        assert!(!store.has_local_certification_witness(key(0xAA)));
        store
            .put_certified_notarization(notarization_record(0xAA, 100))
            .unwrap();
        assert!(store.has_local_certification_witness(key(0xAA)));
        assert!(store.remove(key(0xAA)).unwrap());
        assert!(!store.has_local_certification_witness(key(0xAA)));
    }

    #[test]
    fn proof_store_record_format_version_is_two_and_rejects_unknown() {
        // format_version != 2 must be rejected on read.
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("records");
        let mut bad = finalization_record(0xCA, 100);
        bad.format_version = 42;
        {
            // Bypass the put-side guard to simulate a corrupt on-disk row.
            let backend = MdbxParentProofBackend::open(&dir).unwrap();
            let bytes = backend.encode_record(&bad).unwrap();
            let tx = backend.db.tx_mut().unwrap();
            tx.put::<tables::OutbeCertifiedParentFinalizationRecords>(
                B256::with_last_byte(0xCA),
                bytes,
            )
            .unwrap();
            tx.commit().unwrap();
        }
        let err = match FinalizedParentCertStore::open(&dir) {
            Ok(_) => panic!("unknown format_version must be rejected on read"),
            Err(e) => e,
        };
        assert!(
            matches!(
                err,
                ParentProofStoreError::UnknownFormatVersion { version: 42, .. }
            ),
            "expected UnknownFormatVersion(42), got {err}"
        );
    }

    #[test]
    fn put_with_wrong_format_version_returns_unknown_format_version() {
        // Write-side guard rejects records with the wrong version even
        // before they reach disk.
        let store = FinalizedParentCertStore::new();
        let mut bad = finalization_record(0xCC, 1);
        // 2 is the retired pre-V3 version; the write-side guard must reject it.
        bad.format_version = 2;
        let err = store.put_finalization(bad).expect_err("must reject");
        assert!(matches!(
            err,
            ParentProofStoreError::UnknownFormatVersion { version: 2, .. }
        ));
    }

    #[test]
    fn prune_below_height_drops_only_old_in_both_slots() {
        let store = FinalizedParentCertStore::new();
        store
            .put_finalization(finalization_record(0x01, 10))
            .unwrap();
        store
            .put_finalization(finalization_record(0x02, 50))
            .unwrap();
        store
            .put_certified_notarization(notarization_record(0x03, 20))
            .unwrap();
        store
            .put_certified_notarization(notarization_record(0x04, 100))
            .unwrap();
        let dropped = store.prune_below_height(50).unwrap();
        // height=10 fin + height=20 cn drop; 50 fin and 100 cn stay.
        assert_eq!(dropped, 2);
        assert_eq!(store.len(), 2);
        assert!(store.get_finalization(key(0x01)).is_none());
        assert!(store.get_certified_notarization(key(0x03)).is_none());
        assert!(!store.has_local_certification_witness(key(0x03)));
        assert!(store.has_local_certification_witness(key(0x04)));
    }

    #[test]
    fn put_same_hash_same_slot_overwrites() {
        let store = FinalizedParentCertStore::new();
        store
            .put_finalization(finalization_record(0xAA, 100))
            .unwrap();
        let mut updated = finalization_record(0xAA, 100);
        updated.signer_bitmap = vec![0];
        store.put_finalization(updated.clone()).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(store.get_finalization(key(0xAA)), Some(updated));
    }

    #[test]
    fn store_clone_shares_state() {
        let store = FinalizedParentCertStore::new();
        let other = store.clone();
        store
            .put_finalization(finalization_record(0xAB, 7))
            .unwrap();
        assert!(other.get_finalization(key(0xAB)).is_some());
    }

    #[test]
    fn durable_store_recovers_post_put_pre_phase1_record() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("records");
        let f = finalization_record(0xCA, 77);
        let n = notarization_record(0xCB, 78);
        {
            let store = FinalizedParentCertStore::open(&dir).unwrap();
            store.put_finalization(f.clone()).unwrap();
            store.put_certified_notarization(n.clone()).unwrap();
        }
        let reopened = FinalizedParentCertStore::open(&dir).unwrap();
        assert_eq!(reopened.get_finalization(key(0xCA)), Some(f));
        assert_eq!(reopened.get_certified_notarization(key(0xCB)), Some(n));
        assert!(reopened.get_finalization(key(0xCC)).is_none());
    }

    #[test]
    fn durable_store_rejects_corrupt_key_payload_mismatch_on_reopen() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("records");
        let payload = finalization_record(0xAA, 77);
        {
            let backend = MdbxParentProofBackend::open(&dir).unwrap();
            let bytes = backend.encode_record(&payload).unwrap();
            let tx = backend.db.tx_mut().unwrap();
            tx.put::<tables::OutbeCertifiedParentFinalizationRecords>(
                B256::with_last_byte(0xBB),
                bytes,
            )
            .unwrap();
            tx.commit().unwrap();
        }
        let err = match FinalizedParentCertStore::open(&dir) {
            Ok(_) => panic!("mismatched key/payload must fail closed"),
            Err(e) => e,
        };
        assert!(matches!(err, ParentProofStoreError::Corrupt { .. }));
    }

    #[test]
    fn durable_store_rejects_legacy_v1_tables_on_open() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("records");
        let legacy_db = reth_db::mdbx::init_db_for::<
            _,
            tables::OutbeCertifiedParentProofLegacyTables,
        >(&dir, DatabaseArguments::new(ClientVersion::default()))
        .unwrap();
        drop(legacy_db);

        let err = match FinalizedParentCertStore::open(&dir) {
            Ok(_) => panic!("legacy V1 tables must fail startup"),
            Err(e) => e,
        };
        assert!(
            matches!(
                err,
                ParentProofStoreError::LegacyTableFound {
                    table: "OutbeCertifiedParentFinalizationRecords",
                    ..
                }
            ),
            "expected legacy V1 table error, got {err}"
        );
    }

    #[test]
    fn durable_prune_removes_disk_entry() {
        let temp = tempfile::tempdir().unwrap();
        let dir = temp.path().join("records");
        {
            let store = FinalizedParentCertStore::open(&dir).unwrap();
            store
                .put_finalization(finalization_record(0x01, 10))
                .unwrap();
            store
                .put_finalization(finalization_record(0x02, 50))
                .unwrap();
            assert_eq!(store.prune_below_height(50).unwrap(), 1);
        }
        let reopened = FinalizedParentCertStore::open(&dir).unwrap();
        assert!(reopened.get_finalization(key(0x01)).is_none());
        assert!(reopened.get_finalization(key(0x02)).is_some());
    }

    #[test]
    fn remove_drops_both_slots_for_same_hash() {
        let store = FinalizedParentCertStore::new();
        store
            .put_finalization(finalization_record(0xAA, 10))
            .unwrap();
        store
            .put_certified_notarization(notarization_record(0xAA, 10))
            .unwrap();
        assert!(store.remove(key(0xAA)).unwrap());
        assert!(store.get_best_parent_proof(key(0xAA)).is_none());
    }

    #[test]
    fn oldest_stored_height_spans_both_slots() {
        let store = FinalizedParentCertStore::new();
        store
            .put_finalization(finalization_record(0x01, 100))
            .unwrap();
        store
            .put_certified_notarization(notarization_record(0x02, 20))
            .unwrap();
        assert_eq!(store.oldest_stored_height(), Some(20));
    }
}

#[cfg(test)]
mod proptests {
    //! Encoding/decoding safety properties for [`CertifiedParentProofRecord`].
    //!
    //! These tests pin the on-disk shape so a future schema change cannot
    //! silently break the V1 read path:
    //!
    //! 1. Round-trip: any record round-trips through serde_json byte-equal.
    //! 2. Determinism: encoding the same logical record many times yields
    //!    byte-identical output (no per-call randomness, no HashMap/HashSet
    //!    iteration order in the schema).
    //! 3. Cross-version pin: a hand-crafted JSON payload representative of
    //!    the v1 on-disk format decodes to the expected logical record.
    //!    This is the cross-version compatibility check required by the
    //!    skill's "Safety verification" rule for consensus-carrying paths.
    //!
    //! Note: the on-disk encoding is `serde_json` (see `encode_record`),
    //! deliberately chosen for `parent_cert_store.rs:381-385` precedent.
    //! Switching encoding is a schema migration, not a refactor.
    use super::*;
    use proptest::collection::vec;
    use proptest::prelude::*;

    /// Strategy: a `ProofKind`. Either a `Finalization` carrying an arbitrary
    /// block number, or a `CertifiedNotarization` (no block number).
    fn arb_kind() -> impl Strategy<Value = ProofKind> {
        prop_oneof![
            (0u64..(1 << 32)).prop_map(|finalized_block_number| ProofKind::Finalization {
                finalized_block_number
            }),
            Just(ProofKind::CertifiedNotarization),
        ]
    }

    /// Strategy: arbitrary `CertifiedParentProofRecord` with the current
    /// `format_version`. Numeric ranges are kept under realistic protocol
    /// bounds (epoch < 2^24, view < 2^32, etc.) to keep shrinking fast without
    /// sacrificing coverage of the encoded layout.
    fn arb_record() -> impl Strategy<Value = CertifiedParentProofRecord> {
        let head = (
            arb_kind(),
            0u64..(1 << 24),
            0u64..(1 << 32),
            0u64..(1 << 32),
            any::<[u8; 32]>(),
            any::<[u8; 32]>(),
        );
        let tail = (
            0u64..(1 << 40),
            vec(any::<[u8; 20]>(), 0..8),
            vec(any::<u8>(), 0..8),
            vec(any::<u8>(), 0..128),
            0u64..(1 << 40),
        );
        (head, tail).prop_map(
            |(
                (
                    kind,
                    finalized_epoch,
                    finalized_view,
                    parent_view,
                    finalized_block_hash,
                    committee_set_hash,
                ),
                (
                    vrf_material_version,
                    ordered_committee,
                    signer_bitmap,
                    proof_bytes,
                    stored_at_height,
                ),
            )| {
                let encoded_proof = Bytes::from(proof_bytes);
                CertifiedParentProofRecord {
                    format_version: CERTIFIED_PARENT_PROOF_RECORD_FORMAT_VERSION,
                    kind,
                    finalized_epoch,
                    finalized_view,
                    parent_view,
                    finalized_block_hash: B256::from(finalized_block_hash),
                    committee_set_hash: B256::from(committee_set_hash),
                    vrf_material_version,
                    vrf_group_public_key_hash: B256::ZERO,
                    ordered_committee: ordered_committee.into_iter().map(Address::from).collect(),
                    signer_bitmap,
                    encoded_proof,
                    stored_at_height,
                }
            },
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 256,
            ..ProptestConfig::default()
        })]

        /// Property: any record round-trips through serde_json byte-equal.
        #[test]
        fn proptest_record_encode_decode_roundtrip(rec in arb_record()) {
            let bytes = serde_json::to_vec(&rec).expect("encode");
            let decoded: CertifiedParentProofRecord =
                serde_json::from_slice(&bytes).expect("decode");
            prop_assert_eq!(decoded, rec);
        }

        /// Property: encoding the same logical record N times yields
        /// byte-identical output. Determinism guard against any future use
        /// of HashMap/HashSet or per-call randomness in the schema.
        #[test]
        fn proptest_record_encode_is_deterministic(rec in arb_record()) {
            let first = serde_json::to_vec(&rec).expect("encode");
            for _ in 0..16 {
                let again = serde_json::to_vec(&rec).expect("encode again");
                prop_assert_eq!(&again, &first);
            }
        }

        /// Property: non-current format_version is rejected by the backend decoder
        ///, regardless of the rest of the record.
        #[test]
        fn proptest_unknown_format_version_is_rejected(
            mut rec in arb_record(),
            bad_version in prop_oneof![Just(0u8), Just(1u8), Just(2u8), 4u8..=255u8],
        ) {
            rec.format_version = bad_version;
            let bytes = serde_json::to_vec(&rec).expect("encode");

            let temp = tempfile::tempdir().expect("tempdir");
            let backend = MdbxParentProofBackend::open(temp.path()).expect("open backend");
            let decoded = backend.decode_record(bytes);
            // Extract the predicate first - `prop_assert!` treats commas in
            // its arg list as format-string separators, so embedding the
            // `matches! ... if ...` guard inline confuses the macro parser.
            let rejected_with_bad_version = matches!(
                decoded,
                Err(ParentProofStoreError::UnknownFormatVersion { version, .. }) if version == bad_version
            );
            prop_assert!(rejected_with_bad_version);
        }
    }

    /// Current-format (V3) serde-shape pin: a hand-crafted JSON payload that
    /// matches the on-disk shape decodes to the expected logical record, and
    /// the decoded record re-encodes + re-decodes byte-equal. A proptest
    /// round-trip cannot catch a serde field/variant rename (encode and decode
    /// rename symmetrically), so this pin forces an explicit migration decision
    /// if the schema's JSON shape changes. The externally-tagged `ProofKind`
    /// serializes as `{"Finalization":{"finalized_block_number":N}}`, the kind
    /// of detail the pin exists to catch.
    #[test]
    fn current_format_payload_decodes_to_record() {
        let payload = r#"{
            "format_version": 3,
            "kind": { "Finalization": { "finalized_block_number": 42 } },
            "finalized_epoch": 7,
            "finalized_view": 100,
            "parent_view": 99,
            "finalized_block_hash": "0x000000000000000000000000000000000000000000000000000000000000aaaa",
            "committee_set_hash": "0x000000000000000000000000000000000000000000000000000000000000bbbb",
            "vrf_material_version": 3,
            "vrf_group_public_key_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "ordered_committee": ["0x1111111111111111111111111111111111111111"],
            "signer_bitmap": [1, 0, 1],
            "encoded_proof": "0xdeadbeef",
            "stored_at_height": 42
        }"#;
        let rec: CertifiedParentProofRecord =
            serde_json::from_str(payload).expect("current-format payload must decode");
        assert_eq!(
            rec.format_version,
            CERTIFIED_PARENT_PROOF_RECORD_FORMAT_VERSION
        );
        assert_eq!(rec.proof_kind(), ParentParticipationProof::Finalization);
        assert_eq!(rec.finalized_block_number(), Some(42));
        assert_eq!(rec.finalized_epoch, 7);
        assert_eq!(rec.finalized_view, 100);
        assert_eq!(rec.parent_view, 99);
        let mut expected_hash = [0u8; 32];
        expected_hash[30] = 0xaa;
        expected_hash[31] = 0xaa;
        assert_eq!(rec.finalized_block_hash, B256::from(expected_hash));
        assert_eq!(rec.vrf_material_version, 3);
        assert_eq!(rec.ordered_committee.len(), 1);
        assert_eq!(rec.signer_bitmap, vec![1u8, 0, 1]);
        assert_eq!(rec.encoded_proof.as_ref(), &[0xde, 0xad, 0xbe, 0xef]);
        assert_eq!(rec.stored_at_height, 42);

        // Re-encode + re-decode byte-equal: confirms the decoded record's
        // serialized shape is stable under the current schema.
        let encoded = serde_json::to_vec(&rec).expect("re-encode");
        let decoded: CertifiedParentProofRecord =
            serde_json::from_slice(&encoded).expect("re-decode");
        assert_eq!(decoded, rec);

        // A unit-variant `CertifiedNotarization` pins as a bare string tag.
        let cn_payload = r#"{
            "format_version": 3,
            "kind": "CertifiedNotarization",
            "finalized_epoch": 7,
            "finalized_view": 100,
            "parent_view": 99,
            "finalized_block_hash": "0x000000000000000000000000000000000000000000000000000000000000aaaa",
            "committee_set_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "vrf_material_version": 0,
            "vrf_group_public_key_hash": "0x0000000000000000000000000000000000000000000000000000000000000000",
            "ordered_committee": [],
            "signer_bitmap": [],
            "encoded_proof": "0x",
            "stored_at_height": 100
        }"#;
        let cn: CertifiedParentProofRecord =
            serde_json::from_str(cn_payload).expect("CN payload must decode");
        assert_eq!(
            cn.proof_kind(),
            ParentParticipationProof::CertifiedNotarization
        );
        assert_eq!(cn.finalized_block_number(), None);
        assert!(cn.is_certification_witness());
    }
}
