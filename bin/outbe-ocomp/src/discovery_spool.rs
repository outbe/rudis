use std::{
    fs::{self, File, OpenOptions, ReadDir},
    io::{Read as _, Write as _},
    os::{
        fd::AsRawFd as _,
        unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    },
    path::{Path, PathBuf},
};

use alloy_primitives::{keccak256, B256};
use outbe_compressed_entities::LOCAL_STORAGE_SCHEMA_VERSION;
use outbe_ocomp_protocol::{
    control::{FinalizedJobSpecV1, SnapshotExportCommittedV1},
    input::CheckpointIdentityV1,
    intent::JobIntentV1,
    profile::ProtocolBundleV1,
    ProtocolError, SchemaLimits,
};
use outbe_primitives::projection::ProjectionCheckpoint;
use thiserror::Error;

use crate::discovery_control::{
    observation_id, DiscoveryAckRefV1, DiscoveryControlError, DiscoveryOfferRefV1,
};
use crate::export_receipt::VerifiedExportReceipt;

const DIRECTORY_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
const LOCK_FILE: &str = ".lock";
const TEMP_SUFFIX: &str = ".tmp";
const OFFER_SUFFIX: &str = ".offer";
const ACK_SUFFIX: &str = ".ack";
const PENDING_SUFFIX: &str = ".pending";
const QUARANTINE_SUFFIX: &str = ".quarantine";
const RETIREMENT_SUFFIX: &str = ".retirement";
const OFFER_RECORD_MAGIC: [u8; 8] = *b"OUTBDSO1";
const ACK_RECORD_MAGIC: [u8; 8] = *b"OUTBDSA2";
const PENDING_RECORD_MAGIC: [u8; 8] = *b"OUTBDSP1";
const QUARANTINE_MAGIC: [u8; 8] = *b"OUTBDSQ1";
const RETIREMENT_MAGIC: [u8; 8] = *b"OUTBDSR1";
const CHECKPOINT_MAGIC: [u8; 8] = *b"OUTBDCP1";
const RECORD_VERSION: u16 = 1;
const CHECKPOINT_FILE: &str = "checkpoint.v1";
const CHECKPOINT_TEMP: &str = "checkpoint.v1.tmp";
const CHECKPOINT_LOCK: &str = ".lock";
const CHECKPOINT_FIXED_BYTES: usize = 8 + 2 + (8 + 32) * 3 + 32;
const RETIREMENT_FIXED_BYTES: usize = 8 + 2 + 8 + DiscoveryOfferRefV1::FIXED_BYTES + 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PutOutcomeV1 {
    Inserted,
    ExactDuplicate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AckPutOutcomeV1 {
    Committed {
        reference: DiscoveryAckRefV1,
        outcome: PutOutcomeV1,
    },
    Retired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingDiscoveryV1 {
    pub reference: DiscoveryOfferRefV1,
    pub spec: FinalizedJobSpecV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredDiscoveryAckV1 {
    pub reference: DiscoveryAckRefV1,
    pub committed: SnapshotExportCommittedV1,
    pub lease_generation: u64,
    pub manifest_hash: B256,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RetirementReportV1 {
    pub completed: u64,
    pub waiting_for_checkpoint: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RetirementIntentV1 {
    closed_through: u64,
    reference: DiscoveryOfferRefV1,
}

#[derive(Clone)]
pub struct DiscoverySpoolV1 {
    root: PathBuf,
    offers: PathBuf,
    acks: PathBuf,
    pending: PathBuf,
    quarantine: PathBuf,
    retirements: PathBuf,
    chain_id: u64,
    genesis_hash: B256,
    limits: SchemaLimits,
}

impl DiscoverySpoolV1 {
    pub fn open(
        root: impl AsRef<Path>,
        chain_id: u64,
        genesis_hash: B256,
        limits: SchemaLimits,
    ) -> Result<Self, DiscoverySpoolError> {
        if chain_id == 0 || genesis_hash.is_zero() {
            return Err(DiscoverySpoolError::InvalidIdentity);
        }
        let root = root.as_ref().to_path_buf();
        create_private_directory(&root)?;
        let offers = root.join("offers");
        let acks = root.join("acks");
        let pending = root.join("pending");
        let quarantine = root.join("quarantine");
        let retirements = root.join("retirements");
        create_private_directory(&offers)?;
        create_private_directory(&acks)?;
        create_private_directory(&pending)?;
        create_private_directory(&quarantine)?;
        create_private_directory(&retirements)?;
        let spool = Self {
            root,
            offers,
            acks,
            pending,
            quarantine,
            retirements,
            chain_id,
            genesis_hash,
            limits,
        };
        let _lock = FileLock::acquire(&spool.root, LOCK_FILE)?;
        recover_crash_temps(&spool.offers)?;
        recover_crash_temps(&spool.acks)?;
        recover_crash_temps(&spool.pending)?;
        recover_crash_temps(&spool.quarantine)?;
        recover_crash_temps(&spool.retirements)?;
        Ok(spool)
    }

    pub fn put_offer(
        &self,
        generation: u64,
        spec: &FinalizedJobSpecV1,
    ) -> Result<(DiscoveryOfferRefV1, PutOutcomeV1), DiscoverySpoolError> {
        let reference = DiscoveryOfferRefV1::from_spec(
            self.chain_id,
            self.genesis_hash,
            generation,
            spec,
            &self.limits,
        )?;
        let outcome = self.put_offer_exact(&reference, spec)?;
        Ok((reference, outcome))
    }

    pub fn put_offer_exact(
        &self,
        reference: &DiscoveryOfferRefV1,
        spec: &FinalizedJobSpecV1,
    ) -> Result<PutOutcomeV1, DiscoverySpoolError> {
        let _lock = FileLock::acquire(&self.root, LOCK_FILE)?;
        self.require_not_quarantined(reference.observation_id)?;
        let canonical = spec.encode_body(&self.limits)?;
        let expected = DiscoveryOfferRefV1::from_spec(
            self.chain_id,
            self.genesis_hash,
            reference.generation,
            spec,
            &self.limits,
        )?;
        if reference != &expected {
            return self.latch_conflict(reference.observation_id, "offer authority");
        }
        let path = self.offer_path(&reference.observation_id);
        if regular_file_exists(&path)? {
            let stored = self.read_offer_at(&path)?;
            if stored.reference == *reference && stored.spec == *spec {
                if !regular_file_exists(&self.ack_path(&reference.observation_id))? {
                    self.ensure_pending_marker_unlocked(reference.observation_id)?;
                }
                return Ok(PutOutcomeV1::ExactDuplicate);
            }
            return self.latch_conflict(reference.observation_id, "offer replay");
        }
        if regular_file_exists(&self.ack_path(&reference.observation_id))? {
            return self.latch_conflict(reference.observation_id, "ack without offer");
        }
        let encoded = encode_offer_record(reference, &canonical)?;
        persist_immutable_atomic(&self.offers, &path, &encoded)?;
        self.ensure_pending_marker_unlocked(reference.observation_id)?;
        Ok(PutOutcomeV1::Inserted)
    }

    pub fn put_ack(
        &self,
        offer: &DiscoveryOfferRefV1,
        receipt: &VerifiedExportReceipt,
        bundle: &ProtocolBundleV1,
    ) -> Result<AckPutOutcomeV1, DiscoverySpoolError> {
        let committed = receipt.committed();
        let export_receipt_digest = receipt.receipt_ref().transport_digest;
        let _lock = FileLock::acquire(&self.root, LOCK_FILE)?;
        self.require_not_quarantined(offer.observation_id)?;
        let retirement_path = self.retirement_path(&offer.observation_id);
        if regular_file_exists(&retirement_path)? {
            let retirement = self.read_retirement_at(&retirement_path)?;
            if retirement.reference == *offer {
                return Ok(AckPutOutcomeV1::Retired);
            }
            return self.latch_conflict(offer.observation_id, "retired ACK authority");
        }
        let offer_path = self.offer_path(&offer.observation_id);
        if !regular_file_exists(&offer_path)? {
            if !regular_file_exists(&self.ack_path(&offer.observation_id))?
                && !regular_file_exists(&self.pending_path(&offer.observation_id))?
            {
                // `put_ack` is reached only from work previously read from this
                // spool. With every record gone, a completed retirement won the
                // cross-process race; the late completion has no authority.
                return Ok(AckPutOutcomeV1::Retired);
            }
            return Err(DiscoverySpoolError::MissingOffer(offer.observation_id));
        }
        let stored_offer = self.read_offer_at(&offer_path)?;
        let receipt_matches_offer = verified_receipt_matches_offer(
            &stored_offer.spec,
            receipt,
            bundle,
            self.chain_id,
            self.genesis_hash,
            &self.limits,
        )
        .unwrap_or(false);
        if stored_offer.reference != *offer
            || offer.chain_id != self.chain_id
            || offer.genesis_hash != self.genesis_hash
            || committed.job_id != stored_offer.spec.summary.job_id
            || receipt.source_pin_generation() != offer.generation
            || offer
                .generation
                .checked_add(1)
                .is_none_or(|next_generation| committed.pin_generation != next_generation)
            || !receipt_matches_offer
        {
            return self.latch_conflict(offer.observation_id, "ack authority");
        }
        let reference = DiscoveryAckRefV1::from_committed(
            offer,
            &committed,
            export_receipt_digest,
            &self.limits,
        )?;
        let canonical = committed.encode_body(&self.limits)?;
        let path = self.ack_path(&offer.observation_id);
        if regular_file_exists(&path)? {
            let stored = self.read_ack_for_offer(&path, &stored_offer)?;
            if stored.reference == reference && stored.committed == committed {
                self.remove_pending_marker_unlocked(offer.observation_id)?;
                return Ok(AckPutOutcomeV1::Committed {
                    reference,
                    outcome: PutOutcomeV1::ExactDuplicate,
                });
            }
            return self
                .latch_conflict(offer.observation_id, "ack replay")
                .map(|outcome| AckPutOutcomeV1::Committed { reference, outcome });
        }
        let encoded = encode_ack_record(
            &reference,
            receipt.lease_generation(),
            receipt.manifest_hash(),
            &canonical,
        )?;
        persist_immutable_atomic(&self.acks, &path, &encoded)?;
        self.remove_pending_marker_unlocked(offer.observation_id)?;
        Ok(AckPutOutcomeV1::Committed {
            reference,
            outcome: PutOutcomeV1::Inserted,
        })
    }

    pub fn pending(
        &self,
        observation: &B256,
    ) -> Result<Option<PendingDiscoveryV1>, DiscoverySpoolError> {
        let _lock = FileLock::acquire(&self.root, LOCK_FILE)?;
        self.pending_unlocked(observation)
    }

    fn pending_from_index(
        &self,
        observation: &B256,
    ) -> Result<Option<PendingDiscoveryV1>, DiscoverySpoolError> {
        let _lock = FileLock::acquire(&self.root, LOCK_FILE)?;
        let marker = self.pending_path(observation);
        if !regular_file_exists(&marker)? {
            return Ok(None);
        }
        let encoded =
            read_bounded_private_file(&marker, PENDING_RECORD_MAGIC.len() + 2 + B256::len_bytes())?;
        if encoded != encode_pending_marker(*observation) {
            return Err(DiscoverySpoolError::CorruptRecord { path: marker });
        }
        if !regular_file_exists(&self.offer_path(observation))? {
            return Err(DiscoverySpoolError::MissingOffer(*observation));
        }
        self.pending_unlocked(observation)
    }

    pub fn ack(
        &self,
        observation: &B256,
    ) -> Result<Option<StoredDiscoveryAckV1>, DiscoverySpoolError> {
        let _lock = FileLock::acquire(&self.root, LOCK_FILE)?;
        self.require_not_quarantined(*observation)?;
        let path = self.ack_path(observation);
        if !regular_file_exists(&path)? {
            return Ok(None);
        }
        let offer_path = self.offer_path(observation);
        if !regular_file_exists(&offer_path)? {
            return Err(DiscoverySpoolError::MissingOffer(*observation));
        }
        let offer = self.read_offer_at(&offer_path)?;
        self.read_ack_for_offer(&path, &offer).map(Some)
    }

    pub fn pending_count(&self) -> Result<u64, DiscoverySpoolError> {
        let mut count = 0_u64;
        for pending in self.pending_cursor()? {
            pending?;
            count = count.checked_add(1).ok_or(DiscoverySpoolError::Overflow)?;
        }
        Ok(count)
    }

    pub fn pending_cursor(&self) -> Result<DiscoveryPendingCursorV1, DiscoverySpoolError> {
        let entries = fs::read_dir(&self.pending)
            .map_err(|source| io_error("list pending discovery offers", &self.pending, source))?;
        Ok(DiscoveryPendingCursorV1 {
            spool: self.clone(),
            entries,
        })
    }

    pub fn is_quarantined(&self, observation: &B256) -> Result<bool, DiscoverySpoolError> {
        regular_file_exists(&self.quarantine_path(observation))
    }

    /// Durably records that one discovery record may be removed after the
    /// closure checkpoint reaches `closed_through`. The intent is written
    /// before the checkpoint advances, so every crash cut has enough authority
    /// to either retain the record or finish removing it after restart.
    pub fn prepare_retirement(
        &self,
        reference: &DiscoveryOfferRefV1,
        closed_through: u64,
    ) -> Result<PutOutcomeV1, DiscoverySpoolError> {
        if closed_through == 0
            || reference.chain_id != self.chain_id
            || reference.genesis_hash != self.genesis_hash
        {
            return Err(DiscoverySpoolError::InvalidRetirement);
        }
        reference.validate()?;
        let _lock = FileLock::acquire(&self.root, LOCK_FILE)?;
        self.require_not_quarantined(reference.observation_id)?;
        let intent_path = self.retirement_path(&reference.observation_id);
        if regular_file_exists(&intent_path)? {
            let stored = self.read_retirement_at(&intent_path)?;
            if stored.reference == *reference {
                return Ok(PutOutcomeV1::ExactDuplicate);
            }
            return self.latch_conflict(reference.observation_id, "retirement replay");
        }

        let offer_path = self.offer_path(&reference.observation_id);
        if !regular_file_exists(&offer_path)? {
            if regular_file_exists(&self.ack_path(&reference.observation_id))?
                || regular_file_exists(&self.pending_path(&reference.observation_id))?
            {
                return Err(DiscoverySpoolError::MissingOffer(reference.observation_id));
            }
            return Ok(PutOutcomeV1::ExactDuplicate);
        }
        let offer = self.read_offer_at(&offer_path)?;
        if offer.reference != *reference {
            return self.latch_conflict(reference.observation_id, "retirement authority");
        }
        let ack_path = self.ack_path(&reference.observation_id);
        if regular_file_exists(&ack_path)? {
            self.read_ack_for_offer(&ack_path, &offer)?;
        }
        let encoded = encode_retirement_intent(&RetirementIntentV1 {
            closed_through,
            reference: reference.clone(),
        });
        persist_immutable_atomic(&self.retirements, &intent_path, &encoded)?;
        Ok(PutOutcomeV1::Inserted)
    }

    /// Completes every prepared retirement authorized by the durable closure
    /// checkpoint. Records prepared for a later checkpoint remain untouched.
    pub fn complete_retirements_through(
        &self,
        closed_height: u64,
    ) -> Result<RetirementReportV1, DiscoverySpoolError> {
        let _lock = FileLock::acquire(&self.root, LOCK_FILE)?;
        let entries = fs::read_dir(&self.retirements).map_err(|source| {
            io_error(
                "list discovery retirement intents",
                &self.retirements,
                source,
            )
        })?;
        let mut report = RetirementReportV1::default();
        for entry in entries {
            let entry = entry.map_err(|source| {
                io_error(
                    "read discovery retirement intent",
                    &self.retirements,
                    source,
                )
            })?;
            let path = entry.path();
            let Some(observation) = parse_record_name(&path, RETIREMENT_SUFFIX) else {
                return Err(DiscoverySpoolError::UnexpectedEntry(path));
            };
            let intent = self.read_retirement_at(&path)?;
            if intent.reference.observation_id != observation {
                return Err(DiscoverySpoolError::CorruptRecord { path });
            }
            if intent.closed_through > closed_height {
                report.waiting_for_checkpoint = report
                    .waiting_for_checkpoint
                    .checked_add(1)
                    .ok_or(DiscoverySpoolError::Overflow)?;
                continue;
            }
            self.require_not_quarantined(observation)?;
            let offer_path = self.offer_path(&observation);
            let ack_path = self.ack_path(&observation);
            let pending_path = self.pending_path(&observation);
            let offer = if regular_file_exists(&offer_path)? {
                let offer = self.read_offer_at(&offer_path)?;
                if offer.reference != intent.reference {
                    return self.latch_conflict(observation, "retirement completion authority");
                }
                Some(offer)
            } else {
                None
            };

            if regular_file_exists(&ack_path)? {
                let offer = offer
                    .as_ref()
                    .ok_or(DiscoverySpoolError::MissingOffer(observation))?;
                self.read_ack_for_offer(&ack_path, offer)?;
            }
            if regular_file_exists(&pending_path)? {
                let encoded = read_bounded_private_file(
                    &pending_path,
                    PENDING_RECORD_MAGIC.len() + 2 + B256::len_bytes(),
                )?;
                if encoded != encode_pending_marker(observation) {
                    return Err(DiscoverySpoolError::CorruptRecord { path: pending_path });
                }
            }
            if offer.is_none() && regular_file_exists(&pending_path)? {
                return Err(DiscoverySpoolError::MissingOffer(observation));
            }

            remove_private_file_if_present(&self.acks, &ack_path, "remove retired ACK")?;
            remove_private_file_if_present(
                &self.pending,
                &pending_path,
                "remove retired pending marker",
            )?;
            remove_private_file_if_present(&self.offers, &offer_path, "remove retired offer")?;
            remove_private_file_if_present(
                &self.retirements,
                &path,
                "remove completed retirement intent",
            )?;

            report.completed = report
                .completed
                .checked_add(1)
                .ok_or(DiscoverySpoolError::Overflow)?;
        }
        Ok(report)
    }

    #[must_use]
    pub fn offer_path(&self, observation: &B256) -> PathBuf {
        self.offers
            .join(format!("{}{OFFER_SUFFIX}", hex_id(observation)))
    }

    #[must_use]
    pub fn offers_root(&self) -> &Path {
        &self.offers
    }

    fn ack_path(&self, observation: &B256) -> PathBuf {
        self.acks
            .join(format!("{}{ACK_SUFFIX}", hex_id(observation)))
    }

    fn quarantine_path(&self, observation: &B256) -> PathBuf {
        self.quarantine
            .join(format!("{}{QUARANTINE_SUFFIX}", hex_id(observation)))
    }

    fn pending_path(&self, observation: &B256) -> PathBuf {
        self.pending
            .join(format!("{}{PENDING_SUFFIX}", hex_id(observation)))
    }

    fn retirement_path(&self, observation: &B256) -> PathBuf {
        self.retirements
            .join(format!("{}{RETIREMENT_SUFFIX}", hex_id(observation)))
    }

    fn read_retirement_at(&self, path: &Path) -> Result<RetirementIntentV1, DiscoverySpoolError> {
        let intent =
            decode_retirement_intent(&read_bounded_private_file(path, RETIREMENT_FIXED_BYTES)?)?;
        if intent.reference.chain_id != self.chain_id
            || intent.reference.genesis_hash != self.genesis_hash
            || intent.closed_through == 0
        {
            return Err(DiscoverySpoolError::CorruptRecord {
                path: path.to_path_buf(),
            });
        }
        Ok(intent)
    }

    fn pending_unlocked(
        &self,
        observation: &B256,
    ) -> Result<Option<PendingDiscoveryV1>, DiscoverySpoolError> {
        self.require_not_quarantined(*observation)?;
        let retirement_path = self.retirement_path(observation);
        if regular_file_exists(&retirement_path)? {
            let retirement = self.read_retirement_at(&retirement_path)?;
            if retirement.reference.observation_id != *observation {
                return Err(DiscoverySpoolError::CorruptRecord {
                    path: retirement_path,
                });
            }
            return Ok(None);
        }
        let path = self.offer_path(observation);
        if !regular_file_exists(&path)? {
            return Ok(None);
        }
        let offer = self.read_offer_at(&path)?;
        let ack_path = self.ack_path(observation);
        if regular_file_exists(&ack_path)? {
            self.read_ack_for_offer(&ack_path, &offer)?;
            self.remove_pending_marker_unlocked(*observation)?;
            return Ok(None);
        }
        self.ensure_pending_marker_unlocked(*observation)?;
        Ok(Some(offer))
    }

    fn ensure_pending_marker_unlocked(&self, observation: B256) -> Result<(), DiscoverySpoolError> {
        let path = self.pending_path(&observation);
        if regular_file_exists(&path)? {
            let encoded = read_bounded_private_file(
                &path,
                PENDING_RECORD_MAGIC.len() + 2 + B256::len_bytes(),
            )?;
            if encoded != encode_pending_marker(observation) {
                return Err(DiscoverySpoolError::CorruptRecord { path });
            }
            return Ok(());
        }
        persist_immutable_atomic(&self.pending, &path, &encode_pending_marker(observation))
    }

    fn remove_pending_marker_unlocked(&self, observation: B256) -> Result<(), DiscoverySpoolError> {
        let path = self.pending_path(&observation);
        if !regular_file_exists(&path)? {
            return Ok(());
        }
        fs::remove_file(&path)
            .map_err(|source| io_error("remove acknowledged pending marker", &path, source))?;
        sync_directory(&self.pending)
    }

    fn read_offer_at(&self, path: &Path) -> Result<PendingDiscoveryV1, DiscoverySpoolError> {
        let max = OFFER_RECORD_MAGIC
            .len()
            .checked_add(DiscoveryOfferRefV1::FIXED_BYTES)
            .and_then(|value| value.checked_add(8))
            .and_then(|value| value.checked_add(self.limits.max_control_body_bytes))
            .and_then(|value| value.checked_add(32))
            .ok_or(DiscoverySpoolError::Overflow)?;
        let encoded = read_bounded_private_file(path, max)?;
        let (reference, canonical) = decode_offer_record(&encoded)?;
        let spec = FinalizedJobSpecV1::decode_body(canonical, &self.limits)?;
        if spec.encode_body(&self.limits)? != canonical
            || reference.chain_id != self.chain_id
            || reference.genesis_hash != self.genesis_hash
            || reference.observation_id
                != observation_id(self.chain_id, self.genesis_hash, &spec.summary)
            || reference.discovery_record_digest != keccak256(canonical)
        {
            return Err(DiscoverySpoolError::CorruptRecord {
                path: path.to_path_buf(),
            });
        }
        Ok(PendingDiscoveryV1 { reference, spec })
    }

    fn read_ack_at(&self, path: &Path) -> Result<StoredDiscoveryAckV1, DiscoverySpoolError> {
        let max = ACK_RECORD_MAGIC
            .len()
            .checked_add(DiscoveryAckRefV1::FIXED_BYTES)
            .and_then(|value| {
                value.checked_add(8 + 32 + 8 + self.limits.max_control_body_bytes + 32)
            })
            .ok_or(DiscoverySpoolError::Overflow)?;
        let encoded = read_bounded_private_file(path, max)?;
        let (reference, lease_generation, manifest_hash, canonical) = decode_ack_record(&encoded)?;
        let committed = SnapshotExportCommittedV1::decode_body(canonical, &self.limits)?;
        if committed.encode_body(&self.limits)? != canonical
            || reference.chain_id != self.chain_id
            || reference.genesis_hash != self.genesis_hash
            || lease_generation == 0
            || manifest_hash.is_zero()
        {
            return Err(DiscoverySpoolError::CorruptRecord {
                path: path.to_path_buf(),
            });
        }
        Ok(StoredDiscoveryAckV1 {
            reference,
            committed,
            lease_generation,
            manifest_hash,
        })
    }

    fn read_ack_for_offer(
        &self,
        path: &Path,
        offer: &PendingDiscoveryV1,
    ) -> Result<StoredDiscoveryAckV1, DiscoverySpoolError> {
        let ack = self.read_ack_at(path)?;
        if ack.reference.offer_ref() != offer.reference
            || ack.committed.job_id != offer.spec.summary.job_id
            || offer
                .reference
                .generation
                .checked_add(1)
                .is_none_or(|generation| ack.committed.pin_generation != generation)
        {
            return Err(DiscoverySpoolError::CorruptRecord {
                path: path.to_path_buf(),
            });
        }
        Ok(ack)
    }

    fn require_not_quarantined(&self, observation: B256) -> Result<(), DiscoverySpoolError> {
        if regular_file_exists(&self.quarantine_path(&observation))? {
            Err(DiscoverySpoolError::Quarantined { observation })
        } else {
            Ok(())
        }
    }

    fn latch_conflict<T>(
        &self,
        observation: B256,
        reason: &'static str,
    ) -> Result<T, DiscoverySpoolError> {
        let path = self.quarantine_path(&observation);
        if !regular_file_exists(&path)? {
            let mut encoded = Vec::with_capacity(8 + 2 + 32 + 32);
            encoded.extend_from_slice(&QUARANTINE_MAGIC);
            encoded.extend_from_slice(&RECORD_VERSION.to_be_bytes());
            encoded.extend_from_slice(observation.as_slice());
            encoded.extend_from_slice(keccak256(reason.as_bytes()).as_slice());
            persist_immutable_atomic(&self.quarantine, &path, &encoded)?;
        }
        Err(DiscoverySpoolError::ConflictLatched {
            observation,
            reason,
        })
    }
}

fn verified_receipt_matches_offer(
    spec: &FinalizedJobSpecV1,
    receipt: &VerifiedExportReceipt,
    bundle: &ProtocolBundleV1,
    chain_id: u64,
    genesis_hash: B256,
    limits: &SchemaLimits,
) -> Result<bool, ProtocolError> {
    let summary = &spec.summary;
    let intent = JobIntentV1::decode_canonical(&spec.canonical_job_intent.0, limits)?;
    let intent_id = intent.intent_id(limits)?;
    let job_id = intent.job_id(
        summary.finalized_block_hash,
        summary.finalized_state_root,
        limits,
    )?;
    let protocol_bundle_hash = bundle.protocol_bundle_hash(limits)?;
    receipt.manifest().validate_against_bundle(bundle, limits)?;
    let ce_schema_version = u16::try_from(LOCAL_STORAGE_SCHEMA_VERSION).ok();
    let expected_checkpoint = CheckpointIdentityV1 {
        finalized_block_number: summary.cursor,
        finalized_block_hash: summary.finalized_block_hash,
        finalized_state_root: summary.finalized_state_root,
        finalized_ce_root: intent.ce_sealed_root,
        ce_schema_version: ce_schema_version.unwrap_or_default(),
    };
    let manifest = receipt.manifest();
    Ok(ce_schema_version.is_some()
        && intent_id == summary.intent_id
        && job_id == summary.job_id
        && intent.chain_id == chain_id
        && intent.genesis_hash == genesis_hash
        && intent.fork_id == bundle.fork_id
        && intent.protocol_bundle_hash == protocol_bundle_hash
        && summary.protocol_bundle_hash == protocol_bundle_hash
        && receipt.job_id() == summary.job_id
        && receipt.checkpoint() == &expected_checkpoint
        && manifest.protocol_bundle_hash == protocol_bundle_hash
        && manifest.job_id == summary.job_id
        && manifest.attempt == intent.attempt
        && manifest.checkpoint == expected_checkpoint
        && manifest.wwd == intent.wwd
        && manifest.sealed_tribute_collection_key == intent.sealed_tribute_collection_key
        && manifest.sealed_tribute_collection_root == intent.sealed_tribute_collection_root
        && manifest.tribute_count == intent.authenticated_day_count
        && manifest.tribute_nominal_total == intent.authenticated_day_nominal
        && manifest.body_codec_id == bundle.tribute_body_codec_id
        && manifest.opening_codec_registry_hash == bundle.opening_codec_registry_hash()?)
}

fn encode_retirement_intent(intent: &RetirementIntentV1) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(RETIREMENT_FIXED_BYTES);
    encoded.extend_from_slice(&RETIREMENT_MAGIC);
    encoded.extend_from_slice(&RECORD_VERSION.to_be_bytes());
    encoded.extend_from_slice(&intent.closed_through.to_be_bytes());
    encoded.extend_from_slice(&intent.reference.encode_fixed());
    let checksum = keccak256(&encoded);
    encoded.extend_from_slice(checksum.as_slice());
    encoded
}

fn decode_retirement_intent(encoded: &[u8]) -> Result<RetirementIntentV1, DiscoverySpoolError> {
    if encoded.len() != RETIREMENT_FIXED_BYTES || encoded[..8] != RETIREMENT_MAGIC {
        return Err(DiscoverySpoolError::MalformedRecord {
            path: PathBuf::new(),
        });
    }
    if read_u16(encoded, 8)? != RECORD_VERSION {
        return Err(DiscoverySpoolError::MalformedRecord {
            path: PathBuf::new(),
        });
    }
    verify_record_checksum(encoded)?;
    Ok(RetirementIntentV1 {
        closed_through: read_u64(encoded, 10)?,
        reference: DiscoveryOfferRefV1::decode_fixed(
            &encoded[18..18 + DiscoveryOfferRefV1::FIXED_BYTES],
        )?,
    })
}

pub struct DiscoveryPendingCursorV1 {
    spool: DiscoverySpoolV1,
    entries: ReadDir,
}

impl Iterator for DiscoveryPendingCursorV1 {
    type Item = Result<PendingDiscoveryV1, DiscoverySpoolError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let entry = match self.entries.next()? {
                Ok(entry) => entry,
                Err(source) => {
                    return Some(Err(io_error(
                        "read pending discovery directory",
                        &self.spool.pending,
                        source,
                    )))
                }
            };
            let path = entry.path();
            let Some(observation) = parse_record_name(&path, PENDING_SUFFIX) else {
                return Some(Err(DiscoverySpoolError::UnexpectedEntry(path)));
            };
            match self.spool.pending_from_index(&observation) {
                Ok(Some(pending)) => return Some(Ok(pending)),
                Ok(None) => {}
                Err(error) => return Some(Err(error)),
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CheckpointAdvanceOutcomeV1 {
    Advanced,
    ExactReplay,
}

pub struct ContiguousCheckpointStoreV1 {
    root: PathBuf,
    baseline: ProjectionCheckpoint,
}

impl ContiguousCheckpointStoreV1 {
    pub fn open(
        root: impl AsRef<Path>,
        baseline: ProjectionCheckpoint,
    ) -> Result<Self, DiscoverySpoolError> {
        validate_checkpoint(baseline)?;
        let root = root.as_ref().to_path_buf();
        create_private_directory(&root)?;
        let store = Self { root, baseline };
        let _lock = FileLock::acquire(&store.root, CHECKPOINT_LOCK)?;
        recover_named_temp(&store.root, CHECKPOINT_TEMP)?;
        let path = store.root.join(CHECKPOINT_FILE);
        if regular_file_exists(&path)? {
            let state = decode_checkpoint_state(&read_bounded_private_file(
                &path,
                CHECKPOINT_FIXED_BYTES,
            )?)?;
            if state.baseline != baseline {
                return Err(DiscoverySpoolError::CheckpointBaselineMismatch);
            }
        } else {
            persist_replace_atomic(
                &store.root,
                &path,
                &store.root.join(CHECKPOINT_TEMP),
                &encode_checkpoint_state(CheckpointStateV1 {
                    baseline,
                    previous: baseline,
                    current: baseline,
                }),
            )?;
        }
        Ok(store)
    }

    pub fn current(&self) -> Result<ProjectionCheckpoint, DiscoverySpoolError> {
        let _lock = FileLock::acquire(&self.root, CHECKPOINT_LOCK)?;
        Ok(self.load_state()?.current)
    }

    pub fn compare_and_advance(
        &self,
        expected: ProjectionCheckpoint,
        next: ProjectionCheckpoint,
    ) -> Result<CheckpointAdvanceOutcomeV1, DiscoverySpoolError> {
        validate_checkpoint(expected)?;
        validate_checkpoint(next)?;
        if next.block_number
            != expected
                .block_number
                .checked_add(1)
                .ok_or(DiscoverySpoolError::NonContiguousCheckpoint)?
        {
            return Err(DiscoverySpoolError::NonContiguousCheckpoint);
        }
        let _lock = FileLock::acquire(&self.root, CHECKPOINT_LOCK)?;
        let state = self.load_state()?;
        if state.current == next && state.previous == expected {
            return Ok(CheckpointAdvanceOutcomeV1::ExactReplay);
        }
        if state.current != expected {
            return Err(DiscoverySpoolError::CheckpointCompareFailed {
                stored: state.current,
                expected,
            });
        }
        let next_state = CheckpointStateV1 {
            baseline: state.baseline,
            previous: expected,
            current: next,
        };
        persist_replace_atomic(
            &self.root,
            &self.root.join(CHECKPOINT_FILE),
            &self.root.join(CHECKPOINT_TEMP),
            &encode_checkpoint_state(next_state),
        )?;
        Ok(CheckpointAdvanceOutcomeV1::Advanced)
    }

    /// Atomically advances to a later sparse checkpoint while comparing the
    /// exact current authority. Intermediate block identities were already
    /// validated by the unified reader and need not be retained in RAM.
    pub fn compare_and_advance_to(
        &self,
        expected: ProjectionCheckpoint,
        next: ProjectionCheckpoint,
    ) -> Result<CheckpointAdvanceOutcomeV1, DiscoverySpoolError> {
        validate_checkpoint(expected)?;
        validate_checkpoint(next)?;
        if next.block_number <= expected.block_number {
            return Err(DiscoverySpoolError::NonContiguousCheckpoint);
        }
        let _lock = FileLock::acquire(&self.root, CHECKPOINT_LOCK)?;
        let state = self.load_state()?;
        if state.current == next && state.previous == expected {
            return Ok(CheckpointAdvanceOutcomeV1::ExactReplay);
        }
        if state.current != expected {
            return Err(DiscoverySpoolError::CheckpointCompareFailed {
                stored: state.current,
                expected,
            });
        }
        persist_replace_atomic(
            &self.root,
            &self.root.join(CHECKPOINT_FILE),
            &self.root.join(CHECKPOINT_TEMP),
            &encode_checkpoint_state(CheckpointStateV1 {
                baseline: state.baseline,
                previous: expected,
                current: next,
            }),
        )?;
        Ok(CheckpointAdvanceOutcomeV1::Advanced)
    }

    fn load_state(&self) -> Result<CheckpointStateV1, DiscoverySpoolError> {
        let state = decode_checkpoint_state(&read_bounded_private_file(
            &self.root.join(CHECKPOINT_FILE),
            CHECKPOINT_FIXED_BYTES,
        )?)?;
        if state.baseline != self.baseline {
            return Err(DiscoverySpoolError::CheckpointBaselineMismatch);
        }
        Ok(state)
    }
}

#[derive(Clone, Copy)]
struct CheckpointStateV1 {
    baseline: ProjectionCheckpoint,
    previous: ProjectionCheckpoint,
    current: ProjectionCheckpoint,
}

fn encode_offer_record(
    reference: &DiscoveryOfferRefV1,
    canonical: &[u8],
) -> Result<Vec<u8>, DiscoverySpoolError> {
    let length = u64::try_from(canonical.len()).map_err(|_| DiscoverySpoolError::Overflow)?;
    let mut encoded =
        Vec::with_capacity(8 + DiscoveryOfferRefV1::FIXED_BYTES + 8 + canonical.len() + 32);
    encoded.extend_from_slice(&OFFER_RECORD_MAGIC);
    encoded.extend_from_slice(&reference.encode_fixed());
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(canonical);
    let checksum = keccak256(&encoded);
    encoded.extend_from_slice(checksum.as_slice());
    Ok(encoded)
}

fn decode_offer_record(
    encoded: &[u8],
) -> Result<(DiscoveryOfferRefV1, &[u8]), DiscoverySpoolError> {
    let header = 8 + DiscoveryOfferRefV1::FIXED_BYTES + 8;
    if encoded.len() < header + 32 || encoded[..8] != OFFER_RECORD_MAGIC {
        return Err(DiscoverySpoolError::MalformedRecord {
            path: PathBuf::new(),
        });
    }
    verify_record_checksum(encoded)?;
    let reference =
        DiscoveryOfferRefV1::decode_fixed(&encoded[8..8 + DiscoveryOfferRefV1::FIXED_BYTES])?;
    let body_len = read_u64(encoded, 8 + DiscoveryOfferRefV1::FIXED_BYTES)?;
    let body_len = usize::try_from(body_len).map_err(|_| DiscoverySpoolError::Overflow)?;
    let body_end = header
        .checked_add(body_len)
        .ok_or(DiscoverySpoolError::Overflow)?;
    if body_end + 32 != encoded.len() {
        return Err(DiscoverySpoolError::MalformedRecord {
            path: PathBuf::new(),
        });
    }
    Ok((reference, &encoded[header..body_end]))
}

fn encode_ack_record(
    reference: &DiscoveryAckRefV1,
    lease_generation: u64,
    manifest_hash: B256,
    canonical: &[u8],
) -> Result<Vec<u8>, DiscoverySpoolError> {
    if lease_generation == 0 || manifest_hash.is_zero() {
        return Err(DiscoverySpoolError::MalformedRecord {
            path: PathBuf::new(),
        });
    }
    let length = u64::try_from(canonical.len()).map_err(|_| DiscoverySpoolError::Overflow)?;
    let mut encoded =
        Vec::with_capacity(8 + DiscoveryAckRefV1::FIXED_BYTES + 8 + 32 + 8 + canonical.len() + 32);
    encoded.extend_from_slice(&ACK_RECORD_MAGIC);
    encoded.extend_from_slice(&reference.encode_fixed());
    encoded.extend_from_slice(&lease_generation.to_be_bytes());
    encoded.extend_from_slice(manifest_hash.as_slice());
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(canonical);
    let checksum = keccak256(&encoded);
    encoded.extend_from_slice(checksum.as_slice());
    Ok(encoded)
}

fn decode_ack_record(
    encoded: &[u8],
) -> Result<(DiscoveryAckRefV1, u64, B256, &[u8]), DiscoverySpoolError> {
    let lease_offset = 8 + DiscoveryAckRefV1::FIXED_BYTES;
    let manifest_offset = lease_offset + 8;
    let length_offset = manifest_offset + 32;
    let header = length_offset + 8;
    if encoded.len() < header + 32 || encoded[..8] != ACK_RECORD_MAGIC {
        return Err(DiscoverySpoolError::MalformedRecord {
            path: PathBuf::new(),
        });
    }
    verify_record_checksum(encoded)?;
    let reference =
        DiscoveryAckRefV1::decode_fixed(&encoded[8..8 + DiscoveryAckRefV1::FIXED_BYTES])?;
    let lease_generation = read_u64(encoded, lease_offset)?;
    let manifest_hash = read_b256(encoded, manifest_offset)?;
    let body_len = read_u64(encoded, length_offset)?;
    let body_len = usize::try_from(body_len).map_err(|_| DiscoverySpoolError::Overflow)?;
    let body_end = header
        .checked_add(body_len)
        .ok_or(DiscoverySpoolError::Overflow)?;
    if body_end + 32 != encoded.len() {
        return Err(DiscoverySpoolError::MalformedRecord {
            path: PathBuf::new(),
        });
    }
    Ok((
        reference,
        lease_generation,
        manifest_hash,
        &encoded[header..body_end],
    ))
}

fn verify_record_checksum(encoded: &[u8]) -> Result<(), DiscoverySpoolError> {
    let checksum_start =
        encoded
            .len()
            .checked_sub(32)
            .ok_or_else(|| DiscoverySpoolError::MalformedRecord {
                path: PathBuf::new(),
            })?;
    if keccak256(&encoded[..checksum_start]) != B256::from_slice(&encoded[checksum_start..]) {
        return Err(DiscoverySpoolError::CorruptRecord {
            path: PathBuf::new(),
        });
    }
    Ok(())
}

fn encode_checkpoint_state(state: CheckpointStateV1) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(CHECKPOINT_FIXED_BYTES);
    encoded.extend_from_slice(&CHECKPOINT_MAGIC);
    encoded.extend_from_slice(&RECORD_VERSION.to_be_bytes());
    encode_checkpoint(&mut encoded, state.baseline);
    encode_checkpoint(&mut encoded, state.previous);
    encode_checkpoint(&mut encoded, state.current);
    let checksum = keccak256(&encoded);
    encoded.extend_from_slice(checksum.as_slice());
    encoded
}

fn decode_checkpoint_state(encoded: &[u8]) -> Result<CheckpointStateV1, DiscoverySpoolError> {
    if encoded.len() != CHECKPOINT_FIXED_BYTES || encoded[..8] != CHECKPOINT_MAGIC {
        return Err(DiscoverySpoolError::MalformedCheckpoint);
    }
    if read_u16(encoded, 8)? != RECORD_VERSION {
        return Err(DiscoverySpoolError::MalformedCheckpoint);
    }
    if keccak256(&encoded[..encoded.len() - 32]) != B256::from_slice(&encoded[encoded.len() - 32..])
    {
        return Err(DiscoverySpoolError::CorruptCheckpoint);
    }
    let state = CheckpointStateV1 {
        baseline: decode_checkpoint(encoded, 10)?,
        previous: decode_checkpoint(encoded, 50)?,
        current: decode_checkpoint(encoded, 90)?,
    };
    validate_checkpoint(state.baseline)?;
    validate_checkpoint(state.previous)?;
    validate_checkpoint(state.current)?;
    if state.current.block_number < state.baseline.block_number
        || state.previous.block_number > state.current.block_number
    {
        return Err(DiscoverySpoolError::CorruptCheckpoint);
    }
    Ok(state)
}

fn encode_checkpoint(encoded: &mut Vec<u8>, checkpoint: ProjectionCheckpoint) {
    encoded.extend_from_slice(&checkpoint.block_number.to_be_bytes());
    encoded.extend_from_slice(checkpoint.block_hash.as_slice());
}

fn decode_checkpoint(
    encoded: &[u8],
    start: usize,
) -> Result<ProjectionCheckpoint, DiscoverySpoolError> {
    Ok(ProjectionCheckpoint {
        block_number: read_u64(encoded, start)?,
        block_hash: read_b256(encoded, start + 8)?,
    })
}

fn validate_checkpoint(checkpoint: ProjectionCheckpoint) -> Result<(), DiscoverySpoolError> {
    if checkpoint.block_hash.is_zero() {
        Err(DiscoverySpoolError::InvalidCheckpoint)
    } else {
        Ok(())
    }
}

fn create_private_directory(path: &Path) -> Result<(), DiscoverySpoolError> {
    reject_symlink_ancestors(path)?;
    match fs::symlink_metadata(path) {
        Ok(metadata) => inspect_directory_mode(path, &metadata),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path)
                .map_err(|source| io_error("create private directory", path, source))?;
            fs::set_permissions(path, fs::Permissions::from_mode(DIRECTORY_MODE))
                .map_err(|source| io_error("set private directory mode", path, source))?;
            sync_parent(path)?;
            inspect_private_directory(path)
        }
        Err(source) => Err(io_error("inspect private directory", path, source)),
    }
}

fn inspect_private_directory(path: &Path) -> Result<(), DiscoverySpoolError> {
    reject_symlink_ancestors(path)?;
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect private directory", path, source))?;
    inspect_directory_mode(path, &metadata)
}

fn inspect_directory_mode(path: &Path, metadata: &fs::Metadata) -> Result<(), DiscoverySpoolError> {
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(DiscoverySpoolError::UnsafePath(path.to_path_buf()));
    }
    let actual = metadata.permissions().mode() & 0o777;
    if actual != DIRECTORY_MODE {
        return Err(DiscoverySpoolError::PermissiveMode {
            path: path.to_path_buf(),
            actual,
        });
    }
    Ok(())
}

fn reject_symlink_ancestors(path: &Path) -> Result<(), DiscoverySpoolError> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(DiscoverySpoolError::UnsafePath(ancestor.to_path_buf()))
            }
            Ok(_) => {}
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(io_error("inspect path ancestor", ancestor, source)),
        }
    }
    Ok(())
}

fn recover_crash_temps(root: &Path) -> Result<(), DiscoverySpoolError> {
    let mut removed = false;
    for entry in
        fs::read_dir(root).map_err(|source| io_error("list spool directory", root, source))?
    {
        let entry = entry.map_err(|source| io_error("read spool directory", root, source))?;
        let path = entry.path();
        if !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.ends_with(TEMP_SUFFIX))
        {
            continue;
        }
        inspect_private_file(&path)?;
        fs::remove_file(&path)
            .map_err(|source| io_error("remove crash temporary", &path, source))?;
        removed = true;
    }
    if removed {
        sync_directory(root)?;
    }
    Ok(())
}

fn recover_named_temp(root: &Path, name: &str) -> Result<(), DiscoverySpoolError> {
    let path = root.join(name);
    match fs::symlink_metadata(&path) {
        Ok(_) => {
            inspect_private_file(&path)?;
            fs::remove_file(&path)
                .map_err(|source| io_error("remove checkpoint temporary", &path, source))?;
            sync_directory(root)
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(io_error("inspect checkpoint temporary", &path, source)),
    }
}

fn persist_immutable_atomic(
    root: &Path,
    target: &Path,
    encoded: &[u8],
) -> Result<(), DiscoverySpoolError> {
    if regular_file_exists(target)? {
        return Err(DiscoverySpoolError::ImmutableRecordExists(
            target.to_path_buf(),
        ));
    }
    let file_name = target
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| DiscoverySpoolError::UnsafePath(target.to_path_buf()))?;
    let temp = root.join(format!("{file_name}{TEMP_SUFFIX}"));
    persist_replace_atomic(root, target, &temp, encoded)
}

fn persist_replace_atomic(
    root: &Path,
    target: &Path,
    temp: &Path,
    encoded: &[u8],
) -> Result<(), DiscoverySpoolError> {
    if regular_file_exists(temp)? {
        return Err(DiscoverySpoolError::AmbiguousTemporary(temp.to_path_buf()));
    }
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(FILE_MODE)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(temp)
            .map_err(|source| io_error("create atomic temporary", temp, source))?;
        file.write_all(encoded)
            .map_err(|source| io_error("write atomic temporary", temp, source))?;
        file.sync_all()
            .map_err(|source| io_error("fsync atomic temporary", temp, source))?;
        fs::rename(temp, target)
            .map_err(|source| io_error("publish atomic record", target, source))?;
        sync_directory(root)
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

fn regular_file_exists(path: &Path) -> Result<bool, DiscoverySpoolError> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            inspect_private_file(path)?;
            Ok(true)
        }
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(source) => Err(io_error("inspect spool path", path, source)),
    }
}

fn remove_private_file_if_present(
    root: &Path,
    path: &Path,
    operation: &'static str,
) -> Result<(), DiscoverySpoolError> {
    if !regular_file_exists(path)? {
        return Ok(());
    }
    fs::remove_file(path).map_err(|source| io_error(operation, path, source))?;
    sync_directory(root)
}

fn inspect_private_file(path: &Path) -> Result<(), DiscoverySpoolError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|source| io_error("inspect private file", path, source))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(DiscoverySpoolError::UnsafePath(path.to_path_buf()));
    }
    let actual = metadata.permissions().mode() & 0o777;
    if actual != FILE_MODE {
        return Err(DiscoverySpoolError::PermissiveMode {
            path: path.to_path_buf(),
            actual,
        });
    }
    Ok(())
}

fn read_bounded_private_file(
    path: &Path,
    max_bytes: usize,
) -> Result<Vec<u8>, DiscoverySpoolError> {
    inspect_private_file(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| io_error("open private spool file", path, source))?;
    let length = usize::try_from(
        file.metadata()
            .map_err(|source| io_error("stat private spool file", path, source))?
            .len(),
    )
    .map_err(|_| DiscoverySpoolError::RecordTooLarge(path.to_path_buf()))?;
    if length > max_bytes {
        return Err(DiscoverySpoolError::RecordTooLarge(path.to_path_buf()));
    }
    let mut encoded = Vec::with_capacity(length);
    file.read_to_end(&mut encoded)
        .map_err(|source| io_error("read private spool file", path, source))?;
    if encoded.len() != length {
        return Err(DiscoverySpoolError::CorruptRecord {
            path: path.to_path_buf(),
        });
    }
    Ok(encoded)
}

fn sync_directory(path: &Path) -> Result<(), DiscoverySpoolError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| io_error("fsync directory", path, source))
}

fn sync_parent(path: &Path) -> Result<(), DiscoverySpoolError> {
    path.parent().map_or(Ok(()), sync_directory)
}

fn parse_record_name(path: &Path, suffix: &str) -> Option<B256> {
    let name = path.file_name()?.to_str()?;
    let encoded = name.strip_suffix(suffix)?;
    if encoded.len() != 64
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return None;
    }
    let bytes = hex::decode(encoded).ok()?;
    Some(B256::from_slice(&bytes))
}

fn hex_id(value: &B256) -> String {
    hex::encode(value.as_slice())
}

fn encode_pending_marker(observation: B256) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(PENDING_RECORD_MAGIC.len() + 2 + B256::len_bytes());
    encoded.extend_from_slice(&PENDING_RECORD_MAGIC);
    encoded.extend_from_slice(&RECORD_VERSION.to_be_bytes());
    encoded.extend_from_slice(observation.as_slice());
    encoded
}

fn read_u16(encoded: &[u8], start: usize) -> Result<u16, DiscoverySpoolError> {
    encoded
        .get(start..start + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or(DiscoverySpoolError::MalformedCheckpoint)
}

fn read_u64(encoded: &[u8], start: usize) -> Result<u64, DiscoverySpoolError> {
    encoded
        .get(start..start + 8)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u64::from_be_bytes)
        .ok_or(DiscoverySpoolError::MalformedCheckpoint)
}

fn read_b256(encoded: &[u8], start: usize) -> Result<B256, DiscoverySpoolError> {
    encoded
        .get(start..start + 32)
        .map(B256::from_slice)
        .ok_or(DiscoverySpoolError::MalformedCheckpoint)
}

fn io_error(operation: &'static str, path: &Path, source: std::io::Error) -> DiscoverySpoolError {
    DiscoverySpoolError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

struct FileLock {
    file: File,
}

impl FileLock {
    #[allow(unsafe_code)]
    fn acquire(root: &Path, name: &str) -> Result<Self, DiscoverySpoolError> {
        let path = root.join(name);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(FILE_MODE)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|source| io_error("open spool lock", &path, source))?;
        inspect_private_file(&path)?;
        // SAFETY: `file` owns the live descriptor for the duration of the flock call.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io_error(
                "lock spool",
                &path,
                std::io::Error::last_os_error(),
            ));
        }
        Ok(Self { file })
    }
}

impl Drop for FileLock {
    #[allow(unsafe_code)]
    fn drop(&mut self) {
        // SAFETY: `self.file` still owns a live descriptor until this drop completes.
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[derive(Debug, Error)]
pub enum DiscoverySpoolError {
    #[error("invalid discovery spool network identity")]
    InvalidIdentity,
    #[error("unsafe discovery spool path {0}")]
    UnsafePath(PathBuf),
    #[error("discovery spool path {path} has mode {actual:o}")]
    PermissiveMode { path: PathBuf, actual: u32 },
    #[error("unexpected discovery spool entry {0}")]
    UnexpectedEntry(PathBuf),
    #[error("ambiguous discovery spool temporary {0}")]
    AmbiguousTemporary(PathBuf),
    #[error("immutable discovery record already exists at {0}")]
    ImmutableRecordExists(PathBuf),
    #[error("discovery record is too large at {0}")]
    RecordTooLarge(PathBuf),
    #[error("malformed discovery record at {path}")]
    MalformedRecord { path: PathBuf },
    #[error("corrupt discovery record at {path}")]
    CorruptRecord { path: PathBuf },
    #[error("discovery observation {observation} is quarantined")]
    Quarantined { observation: B256 },
    #[error("discovery conflict latched for {observation}: {reason}")]
    ConflictLatched {
        observation: B256,
        reason: &'static str,
    },
    #[error("missing discovery offer {0}")]
    MissingOffer(B256),
    #[error("integer overflow")]
    Overflow,
    #[error("invalid discovery retirement authority")]
    InvalidRetirement,
    #[error("invalid projection checkpoint")]
    InvalidCheckpoint,
    #[error("malformed projection checkpoint")]
    MalformedCheckpoint,
    #[error("corrupt projection checkpoint")]
    CorruptCheckpoint,
    #[error("projection checkpoint baseline mismatch")]
    CheckpointBaselineMismatch,
    #[error("non-contiguous projection checkpoint advance")]
    NonContiguousCheckpoint,
    #[error("projection checkpoint compare failed: stored {stored:?}, expected {expected:?}")]
    CheckpointCompareFailed {
        stored: ProjectionCheckpoint,
        expected: ProjectionCheckpoint,
    },
    #[error("discovery spool I/O during {operation} at {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error(transparent)]
    Control(#[from] DiscoveryControlError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
}
