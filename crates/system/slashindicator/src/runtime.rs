use alloy_primitives::{keccak256, Address, B256, U256};
use commonware_codec::ReadExt as _;
use commonware_cryptography::bls12381;
use commonware_utils::ordered::Set;
use outbe_consensus::proof::{
    invalid_vrf_evidence_hash_v2, verify_seed_partial_against_commitment,
    verify_seed_partial_attest_bytes, verify_v2_proof, V2VerifyError,
};
use outbe_primitives::error::{PrecompileError, Result};
use outbe_primitives::protocol_schedule::OutbeProtocolSchedule;
use outbe_primitives::slashing_journal::{iso8601_now, record as journal_record, JournalRecord};
use outbe_primitives::system_tx::{recover_phase1_proposer, SystemTxInputV2};
use outbe_staking::contract::Staking;
use outbe_validatorset::contract::ValidatorSet;
use outbe_validatorset::state::{
    committee_snapshot_key, read_committee_snapshot, read_committee_snapshot_for_epoch,
};
use outbe_validatorset::ValidatorLifecycle;
use tracing::{info, warn};

use crate::evidence::{EvidenceBlock, EvidenceCommittee};
use crate::seed_partial_evidence::{InvalidSeedPartialEvidence, SeedPartialEquivocationEvidence};
use crate::vrf_evidence::InvalidVrfProofEvidence;

use crate::schema::SlashIndicator;

use crate::precompile::ISlashIndicator;

/// Default config values used when the stored value is zero (uninitialized).
// Felony thresholds are the maximum validator misses TOLERATED within one epoch.
// The per-epoch reset (`reset_epoch_counters`, run at the epoch boundary) zeroes
// the miss counters, so a validator that crosses the threshold inside an epoch is
// force-exited + slashed immediately; otherwise its count resets next epoch. The
// epoch (`config_epoch_length_blocks`) is the ~1-hour window that also drives DKG
// reshare / active-set rotation / counter reset, so a felony threshold MUST stay
// below the epoch length, else the reset wipes the counter before it can trigger
// (prod epoch 1200 ~= 1h at ~3s; dev/localnet seeds a smaller threshold for its
// short epoch via genesis - see `scripts/bootstrap-testnet.sh`). A voter miss
// accrues ~1 per finalized block; a proposer miss only on the validator's own
// leader slots (~1/N). Both are genesis-overridable per network
// (`config_*_felony_threshold` slots).
const DEFAULT_PROPOSER_MISDEMEANOR_THRESHOLD: u64 = 50;
const DEFAULT_PROPOSER_FELONY_THRESHOLD: u64 = 150;
// graduated escalation requires misdemeanor (warn) < felony (slash). The
// two voter defaults were inverted (misdemeanor 500 > felony 150), so the harsh
// penalty fired before the warning could ever emit. Restored to misdemeanor 150
// < felony 500: both sit above the proposer thresholds (voters accrue ~1 miss
// per finalized block vs a proposer's ~1 per own leader slot) and below the
// prod epoch length (1200), so the felony can still trigger before the per-epoch
// reset.
const DEFAULT_VOTER_MISDEMEANOR_THRESHOLD: u64 = 150;
const DEFAULT_VOTER_FELONY_THRESHOLD: u64 = 500;
const DEFAULT_SLASH_AMOUNT_PERCENT: u64 = 5;
const DEFAULT_EVIDENCE_REWARD_PERCENT: u64 = 10;

impl SlashIndicator<'_> {
    // --- Config helpers ---

    pub fn proposer_felony_threshold(&self) -> Result<u64> {
        let v = self.config_proposer_felony_threshold.read()?;
        Ok(if v == 0 {
            DEFAULT_PROPOSER_FELONY_THRESHOLD
        } else {
            v
        })
    }

    pub fn proposer_misdemeanor_threshold(&self) -> Result<u64> {
        let v = self.config_proposer_misdemeanor_threshold.read()?;
        Ok(if v == 0 {
            DEFAULT_PROPOSER_MISDEMEANOR_THRESHOLD
        } else {
            v
        })
    }

    pub fn voter_misdemeanor_threshold(&self) -> Result<u64> {
        let v = self.config_voter_misdemeanor_threshold.read()?;
        Ok(if v == 0 {
            DEFAULT_VOTER_MISDEMEANOR_THRESHOLD
        } else {
            v
        })
    }

    pub fn voter_felony_threshold(&self) -> Result<u64> {
        let v = self.config_voter_felony_threshold.read()?;
        Ok(if v == 0 {
            DEFAULT_VOTER_FELONY_THRESHOLD
        } else {
            v
        })
    }

    pub fn slash_amount_percent(&self) -> Result<u64> {
        let v = self.config_slash_amount_percent.read()?;
        Ok(if v == 0 {
            DEFAULT_SLASH_AMOUNT_PERCENT
        } else {
            v
        })
    }

    pub fn evidence_reward_percent(&self) -> Result<u64> {
        let v = self.config_evidence_reward_percent.read()?;
        Ok(if v == 0 {
            DEFAULT_EVIDENCE_REWARD_PERCENT
        } else {
            v
        })
    }

    // --- Slash actions ---

    /// a validator already JAILED or EXITING is being removed from the
    /// consensus set at the next reshare; while it lingers in the committee
    /// snapshot it must NOT be re-felonied (re-jailed + re-slashed 5% at every
    /// subsequent miss threshold) for the same continuous liveness fault, which
    /// would compound to far more than the intended single-felony penalty.
    fn validator_already_penalized(&self, validator: Address) -> Result<bool> {
        let vs = ValidatorSet::new(self.storage.clone());
        Ok(matches!(
            vs.validator_lifecycle(validator)?,
            ValidatorLifecycle::JailRetained(_)
                | ValidatorLifecycle::Jail(_)
                | ValidatorLifecycle::Exiting(_)
        ))
    }

    /// Records a proposer miss for `validator`.
    ///
    /// - Increments proposer_miss_count[validator].
    /// - At multiples of felony_threshold: forces exit and slashes the validator.
    /// - At multiples of misdemeanor_threshold (non-felony): misdemeanor logged only.
    pub fn slash_proposer(&mut self, validator: Address) -> Result<()> {
        let count = self.proposer_miss_count.read(&validator)? + 1;
        self.proposer_miss_count.write(&validator, count)?;

        let felony_threshold = self.proposer_felony_threshold()?;
        let misdemeanor_threshold = self.proposer_misdemeanor_threshold()?;
        let block_number = self.storage.block_number().unwrap_or(0);

        crate::metrics::record_proposer_miss_count(validator, count);
        crate::metrics::record_proposer_miss_event(validator);

        journal_record(JournalRecord::ProposerMiss {
            wall_clock: iso8601_now(),
            block_number,
            validator: format!("{validator:?}"),
            count,
            felony_threshold,
            misdemeanor_threshold,
        });

        info!(
            target: "outbe::slashing",
            event = "proposer_miss",
            %validator,
            count,
            felony_threshold,
            misdemeanor_threshold,
            block_number,
            "proposer miss recorded",
        );

        // the miss is recorded above, but skip felony/misdemeanor
        // punishment for a validator already JAILED/EXITING for this fault.
        if self.validator_already_penalized(validator)? {
            return Ok(());
        }

        if count > 0 && count % felony_threshold == 0 {
            // Felony: increment cumulative counter, force exit and slash.
            let fc = self.felony_count.read(&validator)? + 1;
            self.felony_count.write(&validator, fc)?;

            // Felony: JAIL (not force-exit) + slash. Jail BEFORE slash_stake -
            // slash_stake demotes ACTIVE/PENDING below min_stake but leaves a
            // JAILED status untouched, so this ordering preserves JAILED.
            let mut vs = ValidatorSet::new(self.storage.clone());
            vs.jail_validator(validator)?;

            let slash_percent = self.slash_amount_percent()?;
            let mut staking = Staking::new(self.storage.clone());
            staking.slash_stake(validator, slash_percent)?;

            crate::metrics::record_felony_count(validator, fc);
            crate::metrics::record_validator_slashed(validator, "proposer_felony");

            journal_record(JournalRecord::ProposerFelony {
                wall_clock: iso8601_now(),
                block_number,
                validator: format!("{validator:?}"),
                miss_count: count,
                felony_threshold,
                felony_count: fc,
                slash_percent,
            });

            warn!(
                target: "outbe::slashing",
                event = "proposer_felony",
                %validator,
                miss_count = count,
                felony_threshold,
                felony_count = fc,
                slash_percent,
                block_number,
                "proposer felony - validator force-exited and slashed",
            );

            self.emit(ISlashIndicator::ProposerFelony {
                validator,
                missCount: count,
                felonyCount: fc,
            })?;
        } else if count > 0 && count % misdemeanor_threshold == 0 {
            journal_record(JournalRecord::ProposerMisdemeanor {
                wall_clock: iso8601_now(),
                block_number,
                validator: format!("{validator:?}"),
                miss_count: count,
                misdemeanor_threshold,
            });
            info!(
                target: "outbe::slashing",
                event = "proposer_misdemeanor",
                %validator,
                miss_count = count,
                misdemeanor_threshold,
                block_number,
                "proposer misdemeanor threshold crossed",
            );
            self.emit(ISlashIndicator::ProposerMisdemeanor {
                validator,
                missCount: count,
            })?;
        }

        Ok(())
    }

    /// Records a voter miss for `validator`.
    ///
    /// - Increments voter_miss_count[validator].
    /// - At multiples of voter_felony_threshold: forces exit and slashes the validator.
    /// - At multiples of voter_misdemeanor_threshold (non-felony): misdemeanor logged only.
    pub fn slash_voter(&mut self, validator: Address) -> Result<()> {
        let count = self.voter_miss_count.read(&validator)? + 1;
        self.voter_miss_count.write(&validator, count)?;

        let felony_threshold = self.voter_felony_threshold()?;
        let misdemeanor_threshold = self.voter_misdemeanor_threshold()?;
        let block_number = self.storage.block_number().unwrap_or(0);

        crate::metrics::record_voter_miss_count(validator, count);
        crate::metrics::record_voter_miss_event(validator);

        journal_record(JournalRecord::VoterMiss {
            wall_clock: iso8601_now(),
            block_number,
            validator: format!("{validator:?}"),
            count,
            misdemeanor_threshold,
        });

        info!(
            target: "outbe::slashing",
            event = "voter_miss",
            %validator,
            count,
            felony_threshold,
            misdemeanor_threshold,
            block_number,
            "voter miss recorded",
        );

        // the miss is recorded above, but skip felony/misdemeanor
        // punishment for a validator already JAILED/EXITING for this fault.
        if self.validator_already_penalized(validator)? {
            return Ok(());
        }

        if count > 0 && count % felony_threshold == 0 {
            // Felony: increment cumulative counter, force exit and slash. Mirrors
            // the proposer-felony path so missed finalize votes are punitive once
            // they cross the configured threshold (vote_ext.md E8 graduated to T1).
            let fc = self.felony_count.read(&validator)? + 1;
            self.felony_count.write(&validator, fc)?;

            // Felony: JAIL (not force-exit) + slash. Jail BEFORE slash_stake -
            // slash_stake demotes ACTIVE/PENDING below min_stake but leaves a
            // JAILED status untouched, so this ordering preserves JAILED.
            let mut vs = ValidatorSet::new(self.storage.clone());
            vs.jail_validator(validator)?;

            let slash_percent = self.slash_amount_percent()?;
            let mut staking = Staking::new(self.storage.clone());
            staking.slash_stake(validator, slash_percent)?;

            crate::metrics::record_felony_count(validator, fc);
            crate::metrics::record_validator_slashed(validator, "voter_felony");

            journal_record(JournalRecord::VoterFelony {
                wall_clock: iso8601_now(),
                block_number,
                validator: format!("{validator:?}"),
                miss_count: count,
                felony_threshold,
                felony_count: fc,
                slash_percent,
            });

            warn!(
                target: "outbe::slashing",
                event = "voter_felony",
                %validator,
                miss_count = count,
                felony_threshold,
                felony_count = fc,
                slash_percent,
                block_number,
                "voter felony - validator force-exited and slashed",
            );

            self.emit(ISlashIndicator::VoterFelony {
                validator,
                missCount: count,
                felonyCount: fc,
            })?;
        } else if count > 0 && count % misdemeanor_threshold == 0 {
            journal_record(JournalRecord::VoterMisdemeanor {
                wall_clock: iso8601_now(),
                block_number,
                validator: format!("{validator:?}"),
                miss_count: count,
                misdemeanor_threshold,
            });
            info!(
                target: "outbe::slashing",
                event = "voter_misdemeanor",
                %validator,
                miss_count = count,
                misdemeanor_threshold,
                block_number,
                "voter misdemeanor threshold crossed",
            );
            self.emit(ISlashIndicator::VoterMisdemeanor {
                validator,
                missCount: count,
            })?;
        }

        Ok(())
    }

    /// Submits double-proposal evidence.
    ///
    /// Each evidence block is encoded as:
    ///   `pubkey[48] || signature[96] || proposal_encoded[variable]`
    ///
    /// Verification:
    /// 1. Both blocks must have the same BLS MinPk signer public key.
    /// 2. Both proposals must be for the same round (epoch + view).
    /// 3. The proposal bytes must differ (two different proposals for the same round).
    /// 4. Both BLS signatures must be valid (signed over the Simplex notarize payload).
    /// 5. The signer must be a registered validator.
    ///
    /// On success: the validator is forced out and slashed (felony), and the
    /// evidence submitter receives a reward (evidence_reward_percent of slashed amount).
    /// Submitter ACL for the BLS-evidence precompile entry points: only
    /// currently-ACTIVE validators may submit. The verifiers run heavy
    /// cryptography (BLS pairings + ecrecover + storage reads); gating to the
    /// staked set makes DoS self-destructive (a griefer pays gas AND has
    /// slashable stake at risk) instead of free on the ZeroFee chain.
    fn require_active_submitter(&self, caller: Address) -> Result<()> {
        let vs = ValidatorSet::new(self.storage.clone());
        let lifecycle = vs.validator_lifecycle(caller)?;
        if !lifecycle.is_active_status() {
            return Err(PrecompileError::Revert(format!(
                "submitter {caller} is not an ACTIVE validator (status: {})",
                lifecycle.stored_status().unwrap_or_default()
            )));
        }
        Ok(())
    }

    /// Build the ordered committee `Set` for `epoch` from the on-chain
    /// `CommitteeSnapshot`. Equivocation vote signatures are committee-bound
    /// (notarize/nullify/finalize namespaces fold `participant_set_commitment`), so
    /// verification must use the SAME committee the Simplex signer used. The
    /// snapshot committee order matches the signer's participant `Set` (both are
    /// the canonical sorted/deduped pubkey set), so the commitment bytes agree.
    fn committee_set_for_epoch(&self, epoch: u64) -> Result<EvidenceCommittee> {
        let snapshot =
            read_committee_snapshot_for_epoch(self.storage.clone(), epoch)?.ok_or_else(|| {
                PrecompileError::Revert(format!(
                    "no committee snapshot for evidence epoch {epoch}; cannot verify the \
                     committee-bound vote signature"
                ))
            })?;
        let mut keys = Vec::with_capacity(snapshot.committee.len());
        for entry in &snapshot.committee {
            let pk = bls12381::PublicKey::read(&mut entry.consensus_pubkey.as_slice()).map_err(
                |_| PrecompileError::Revert("invalid committee pubkey in snapshot".into()),
            )?;
            keys.push(pk);
        }
        Ok(Set::from_iter_dedup(keys))
    }

    pub fn submit_double_proposal_evidence(
        &mut self,
        caller: Address,
        block1: &[u8],
        block2: &[u8],
    ) -> Result<()> {
        self.require_active_submitter(caller)?;
        let ev1 = EvidenceBlock::parse(block1)?;
        let ev2 = EvidenceBlock::parse(block2)?;

        // Same signer
        if ev1.pubkey != ev2.pubkey {
            return Err(PrecompileError::Revert(
                "evidence blocks must have the same signer".into(),
            ));
        }

        // Different proposals
        if ev1.proposal_bytes == ev2.proposal_bytes {
            return Err(PrecompileError::Revert(
                "proposals must differ for double-proposal evidence".into(),
            ));
        }

        // Same round (epoch + view)
        let round1 = ev1.round()?;
        let round2 = ev2.round()?;
        if round1 != round2 {
            return Err(PrecompileError::Revert(
                "proposals must be for the same round".into(),
            ));
        }

        // Compute canonical evidence hash and reject duplicates.
        // Normalize order so (block1, block2) and (block2, block1) produce the same hash.
        let evidence_hash = canonical_evidence_hash(block1, block2);
        if self.evidence_processed.read(&evidence_hash)? {
            return Err(PrecompileError::Revert("evidence already processed".into()));
        }

        // Verify both signatures under the committee that ran the evidence's epoch
        // (notarize namespace is committee-bound).
        let committee = self.committee_set_for_epoch(round1.0)?;
        ev1.verify_notarize_signature(&committee)?;
        ev2.verify_notarize_signature(&committee)?;

        // Look up validator by consensus pubkey hash (keccak256 of 48-byte BLS pubkey)
        let vs = ValidatorSet::new(self.storage.clone());
        let validator_addr = vs.lookup_by_pubkey_hash(ev1.pubkey_hash())?;
        if validator_addr.is_zero() {
            return Err(PrecompileError::Revert(
                "signer is not a registered validator".into(),
            ));
        }

        // Mark evidence as processed before applying effects
        self.evidence_processed.write(&evidence_hash, true)?;

        // Felony: forced exit + slash + reward evidence submitter.
        self.apply_evidence_felony(validator_addr, caller)
    }

    /// Submits conflicting vote evidence (notarize + nullify in the same view).
    ///
    /// Each evidence block is encoded as:
    ///   `pubkey[48] || signature[96] || payload_bytes[variable]`
    ///
    /// One vote must be a valid notarize signature and the other a valid nullify
    /// signature for the same round (epoch + view) by the same signer. This proves
    /// the validator voted both to accept and skip the same view.
    ///
    /// On success: the validator is forced out and slashed (felony), and the
    /// evidence submitter receives a reward.
    pub fn submit_conflicting_vote_evidence(
        &mut self,
        caller: Address,
        vote1: &[u8],
        vote2: &[u8],
    ) -> Result<()> {
        self.require_active_submitter(caller)?;
        let ev1 = EvidenceBlock::parse(vote1)?;
        let ev2 = EvidenceBlock::parse(vote2)?;

        // Same signer
        if ev1.pubkey != ev2.pubkey {
            return Err(PrecompileError::Revert(
                "evidence blocks must have the same signer".into(),
            ));
        }

        // Same round (epoch + view)
        let round1 = ev1.round()?;
        let round2 = ev2.round()?;
        if round1 != round2 {
            return Err(PrecompileError::Revert(
                "votes must be for the same round".into(),
            ));
        }

        // Compute canonical evidence hash and reject duplicates.
        let evidence_hash = canonical_evidence_hash(vote1, vote2);
        if self.evidence_processed.read(&evidence_hash)? {
            return Err(PrecompileError::Revert("evidence already processed".into()));
        }

        // Verify conflicting vote types: one must be notarize, the other nullify.
        // Try ev1=notarize + ev2=nullify first, then the reverse. both
        // namespaces are committee-bound, so verify under the epoch's committee.
        let committee = self.committee_set_for_epoch(round1.0)?;
        let valid = (ev1.verify_notarize_signature(&committee).is_ok()
            && ev2.verify_nullify_signature(&committee).is_ok())
            || (ev1.verify_nullify_signature(&committee).is_ok()
                && ev2.verify_notarize_signature(&committee).is_ok());

        if !valid {
            return Err(PrecompileError::Revert(
                "evidence must contain one valid notarize and one valid nullify signature".into(),
            ));
        }

        // Look up validator by consensus pubkey hash
        let vs = ValidatorSet::new(self.storage.clone());
        let validator_addr = vs.lookup_by_pubkey_hash(ev1.pubkey_hash())?;
        if validator_addr.is_zero() {
            return Err(PrecompileError::Revert(
                "signer is not a registered validator".into(),
            ));
        }

        // Mark evidence as processed before applying effects
        self.evidence_processed.write(&evidence_hash, true)?;

        // Felony: forced exit + slash + reward evidence submitter.
        self.apply_evidence_felony(validator_addr, caller)
    }

    /// Shared verifier for the three commonware same-signer equivocation classes
    /// (`ConflictingNotarize`, `ConflictingFinalize`, `NullifyFinalize`). Each is
    /// two `EvidenceBlock`s from the SAME signer for the SAME round; the two
    /// closures verify each block's signature against the appropriate Simplex
    /// sub-namespace. `require_distinct_proposals` is set for same-vote-type
    /// classes (two notarizes / two finalizes must differ); the nullify+finalize
    /// class differs by construction. Dedup reuses the `evidence_processed`
    /// guard (slot 8) keyed by the order-independent `canonical_evidence_hash`.
    fn apply_equivocation_felony(
        &mut self,
        caller: Address,
        block1: &[u8],
        block2: &[u8],
        require_distinct_proposals: bool,
        verify1: impl Fn(&EvidenceBlock, &EvidenceCommittee) -> Result<()>,
        verify2: impl Fn(&EvidenceBlock, &EvidenceCommittee) -> Result<()>,
    ) -> Result<()> {
        self.require_active_submitter(caller)?;
        let ev1 = EvidenceBlock::parse(block1)?;
        let ev2 = EvidenceBlock::parse(block2)?;

        if ev1.pubkey != ev2.pubkey {
            return Err(PrecompileError::Revert(
                "evidence blocks must have the same signer".into(),
            ));
        }
        let round1 = ev1.round()?;
        if round1 != ev2.round()? {
            return Err(PrecompileError::Revert(
                "votes must be for the same round".into(),
            ));
        }
        if require_distinct_proposals && ev1.proposal_bytes == ev2.proposal_bytes {
            return Err(PrecompileError::Revert(
                "conflicting votes must be for different proposals".into(),
            ));
        }

        let evidence_hash = canonical_evidence_hash(block1, block2);
        if self.evidence_processed.read(&evidence_hash)? {
            return Err(PrecompileError::Revert("evidence already processed".into()));
        }

        // vote namespaces are committee-bound; verify under the committee
        // that ran the evidence's epoch.
        let committee = self.committee_set_for_epoch(round1.0)?;
        verify1(&ev1, &committee)?;
        verify2(&ev2, &committee)?;

        let vs = ValidatorSet::new(self.storage.clone());
        let validator_addr = vs.lookup_by_pubkey_hash(ev1.pubkey_hash())?;
        if validator_addr.is_zero() {
            return Err(PrecompileError::Revert(
                "signer is not a registered validator".into(),
            ));
        }

        self.evidence_processed.write(&evidence_hash, true)?;
        self.apply_evidence_felony(validator_addr, caller)
    }

    /// `ConflictingNotarize`: the same signer notarized two DIFFERENT proposals
    /// in one view.
    pub fn submit_conflicting_notarize_evidence(
        &mut self,
        caller: Address,
        block1: &[u8],
        block2: &[u8],
    ) -> Result<()> {
        self.apply_equivocation_felony(
            caller,
            block1,
            block2,
            true,
            |ev, c| ev.verify_notarize_signature(c),
            |ev, c| ev.verify_notarize_signature(c),
        )
    }

    /// `ConflictingFinalize`: the same signer finalized two DIFFERENT proposals
    /// in one view.
    pub fn submit_conflicting_finalize_evidence(
        &mut self,
        caller: Address,
        block1: &[u8],
        block2: &[u8],
    ) -> Result<()> {
        self.apply_equivocation_felony(
            caller,
            block1,
            block2,
            true,
            |ev, c| ev.verify_finalize_signature(c),
            |ev, c| ev.verify_finalize_signature(c),
        )
    }

    /// `NullifyFinalize`: the same signer both nullified (voted to skip) and
    /// finalized the same view. `nullify_block` is the nullify vote,
    /// `finalize_block` the finalize vote.
    pub fn submit_nullify_finalize_evidence(
        &mut self,
        caller: Address,
        nullify_block: &[u8],
        finalize_block: &[u8],
    ) -> Result<()> {
        self.apply_equivocation_felony(
            caller,
            nullify_block,
            finalize_block,
            false,
            |ev, c| ev.verify_nullify_signature(c),
            |ev, c| ev.verify_finalize_signature(c),
        )
    }

    /// Applies a felony penalty from evidence submission: forced exit, slash, reward submitter.
    fn apply_evidence_felony(
        &mut self,
        validator: Address,
        evidence_submitter: Address,
    ) -> Result<()> {
        let block_number = self.storage.block_number().unwrap_or(0);
        // Felony: JAIL (not force-exit) + slash. Jail before slash_stake (which
        // leaves a JAILED status untouched).
        let mut vs = ValidatorSet::new(self.storage.clone());
        vs.jail_validator(validator)?;

        let fc = self.felony_count.read(&validator)? + 1;
        self.felony_count.write(&validator, fc)?;

        let slash_percent = self.slash_amount_percent()?;
        let mut staking = Staking::new(self.storage.clone());
        let slashed_amount = staking.slash_stake(validator, slash_percent)?;

        crate::metrics::record_felony_count(validator, fc);
        crate::metrics::record_validator_slashed(validator, "evidence_felony");

        journal_record(JournalRecord::EvidenceFelony {
            wall_clock: iso8601_now(),
            block_number,
            validator: format!("{validator:?}"),
            evidence_submitter: format!("{evidence_submitter:?}"),
            felony_count: fc,
            slash_percent,
            slashed_amount: slashed_amount.to_string(),
        });

        warn!(
            target: "outbe::slashing",
            event = "evidence_felony",
            %validator,
            %evidence_submitter,
            felony_count = fc,
            slash_percent,
            slashed_amount = %slashed_amount,
            block_number,
            "evidence-based felony applied - validator force-exited, stake slashed, submitter rewarded",
        );

        // Reward evidence submitter: mint evidence_reward_percent of slashed amount.
        // slash_stake now burns slashed tokens from STAKING_ADDRESS, so we
        // mint the reward directly to the submitter. Net effect: (slashed - reward)
        // is burned from supply, reward goes to the submitter.
        let mut reward = U256::ZERO;
        if !slashed_amount.is_zero() {
            let reward_pct = self.evidence_reward_percent()?;
            reward = slashed_amount * U256::from(reward_pct) / U256::from(100u64);
            if !reward.is_zero() {
                self.storage.increase_balance(evidence_submitter, reward)?;
            }
        }

        self.emit(ISlashIndicator::EvidenceFelonyApplied {
            validator,
            submitter: evidence_submitter,
            slashedAmount: slashed_amount,
            submitterReward: reward,
        })?;

        Ok(())
    }

    /// submit evidence that the Phase 1 system transaction in a
    /// child block carried an invalid threshold VRF proof.
    ///
    /// `evidence` is the wire form of [`InvalidVrfProofEvidence`] (see
    /// `vrf_evidence.rs`). The runtime applies, in order:
    ///
    /// 1. **Submitter ACL**: `caller` must be a currently-`ACTIVE` validator
    ///    in `ValidatorSet`. Reading + verifying VRF/BLS proofs is heavy
    ///    cryptographic work; gating the entry-point to active validators
    ///    keeps DoS exposure inside the staked set (a malicious validator
    ///    pays gas AND has slashable stake at risk) instead of permitting
    ///    arbitrary EOAs to spam the chain.
    /// 2. Size cap (`invalid_vrf_evidence_max_bytes`).
    /// 3. Block-age cap (`invalid_vrf_evidence_max_age_blocks`).
    /// 4. Epoch-lag cap (`invalid_vrf_evidence_max_epoch_lag`) - read from
    ///    on-chain state via [`ValidatorSet::epoch_number`]
    ///    BP-0 option C: epoch is consensus state, not a derived value).
    /// 5. Child and parent canonicity: claimed child and parent
    ///    hashes must match the canonical chain.
    /// 6. Dedup via
    ///    [`outbe_consensus::proof::invalid_vrf_evidence_hash_v2`] keyed by
    ///    `(child_block_hash, keccak256(phase1_tx_bytes))`; replay of the same
    ///    evidence reverts with `"evidence already processed"` matching the
    ///    `submitDoubleProposalEvidence` / `submitConflictingVoteEvidence`
    ///    precedent.
    /// 7. Cryptographic proposer attribution (D-2): validate
    ///    `phase1_tx_bytes` as the canonical Phase 1 tx for the child block,
    ///    recover the signer, and decode metadata from its calldata. The
    ///    signed tx is the only source of truth for metadata/proof bytes.
    /// 8. Look up the committee snapshot for `metadata.finalized_epoch +
    ///    committee_set_hash` via the canonical
    ///    [`outbe_validatorset::state::committee_snapshot_key`] +
    ///    [`outbe_validatorset::state::read_committee_snapshot`] path; reject
    ///    if the snapshot is absent OR if the recovered proposer is not in
    ///    the committee.
    /// 9. Re-run [`outbe_consensus::proof::verify_v2_proof`] against the
    ///    same metadata/snapshot/parent_hash the child block used; accept
    ///    only VRF-class failures from `V2VerifyError`. Any `Ok` or
    ///    non-VRF rejection reverts - the precompile is strictly for VRF
    ///    misbehavior, not for re-litigating BLS quorum or accounting
    ///    binding failures.
    /// 10. Mark dedup BEFORE applying effects, then call
    ///     [`Self::apply_evidence_felony`] for forced exit + 5% slash +
    ///     10% submitter reward (reusing the existing felony helper -
    ///     economics shared with the other evidence types).
    pub fn submit_invalid_vrf_evidence(
        &mut self,
        caller: Address,
        evidence_bytes: &[u8],
    ) -> Result<()> {
        self.submit_invalid_vrf_evidence_with_schedule(
            caller,
            evidence_bytes,
            &OutbeProtocolSchedule::default(),
        )
    }

    /// Test seam for [`Self::submit_invalid_vrf_evidence`].
    ///
    /// Production callers go through the no-arg `submit_invalid_vrf_evidence`,
    /// which always passes [`OutbeProtocolSchedule::default`] - that is the
    /// canonical V2 schedule and the only schedule the precompile dispatcher
    /// ever uses. This `_with_schedule` variant exists so integration tests
    /// can relax admissibility caps (max_age, max_epoch_lag, max_bytes) to
    /// stress a single axis without bumping into the others.
    #[doc(hidden)]
    pub fn submit_invalid_vrf_evidence_with_schedule(
        &mut self,
        caller: Address,
        evidence_bytes: &[u8],
        schedule: &OutbeProtocolSchedule,
    ) -> Result<()> {
        // (1) Submitter ACL. Only currently-ACTIVE validators can submit.
        // Rationale: the verifier path is heavy cryptography (BLS + VRF +
        // ecrecover + storage reads); restricting the entry-point to the
        // staked set means any griefer pays gas AND has slashable stake at
        // risk, so DoS becomes self-destructive rather than free.
        self.require_active_submitter(caller)?;

        // (2) Size cap. Bound the work the precompile body does on
        // attacker-controlled input.
        if evidence_bytes.len() > schedule.invalid_vrf_evidence_max_bytes {
            return Err(PrecompileError::Revert(format!(
                "evidence too large: {} > {} bytes",
                evidence_bytes.len(),
                schedule.invalid_vrf_evidence_max_bytes,
            )));
        }

        // (3) Decode the wire form.
        let ev = InvalidVrfProofEvidence::decode(evidence_bytes)?;

        // (4) Block-age admissibility.
        let current_block = self.storage.block_number().unwrap_or(0);
        let max_acceptable_block = ev
            .child_block_number
            .saturating_add(schedule.invalid_vrf_evidence_max_age_blocks);
        if current_block > max_acceptable_block {
            return Err(PrecompileError::Revert(format!(
                "evidence stale: current_block {} > child_block {} + max_age {}",
                current_block, ev.child_block_number, schedule.invalid_vrf_evidence_max_age_blocks,
            )));
        }

        // (5) Epoch-lag admissibility - read the canonical on-chain
        // epoch counter from ValidatorSet (option C: epoch is consensus
        // state, recorded by update_epoch at boundaries; we do NOT
        // re-derive it from block height).
        let vs = ValidatorSet::new(self.storage.clone());
        let current_epoch = vs.current_epoch_u64()?;
        let max_acceptable_epoch = ev
            .child_epoch
            .saturating_add(schedule.invalid_vrf_evidence_max_epoch_lag);
        if current_epoch > max_acceptable_epoch {
            return Err(PrecompileError::Revert(format!(
                "evidence epoch-stale: current_epoch {} > child_epoch {} + max_lag {}",
                current_epoch, ev.child_epoch, schedule.invalid_vrf_evidence_max_epoch_lag,
            )));
        }

        // (6) Child + parent canonicity. The evidence must bind to
        // canonical chain history on both sides: the accused child block and
        // the parent proof target.
        let canonical_child = self
            .storage
            .canonical_block_hash(ev.child_block_number)?
            .ok_or_else(|| {
                PrecompileError::Revert(format!(
                    "evidence child block {} not in canonical-history window",
                    ev.child_block_number,
                ))
            })?;
        if canonical_child != ev.child_block_hash {
            return Err(PrecompileError::Revert(format!(
                "evidence child hash {} is not canonical at block {} (canonical: {})",
                ev.child_block_hash, ev.child_block_number, canonical_child,
            )));
        }

        if ev.parent_block_number.saturating_add(1) != ev.child_block_number {
            return Err(PrecompileError::Revert(format!(
                "evidence parent/child number mismatch: parent={} child={}",
                ev.parent_block_number, ev.child_block_number,
            )));
        }

        let canonical_parent = self
            .storage
            .canonical_block_hash(ev.parent_block_number)?
            .ok_or_else(|| {
                PrecompileError::Revert(format!(
                    "evidence parent block {} not in canonical-history window",
                    ev.parent_block_number,
                ))
            })?;
        if canonical_parent != ev.parent_block_hash {
            return Err(PrecompileError::Revert(format!(
                "evidence parent hash {} is not canonical at block {} (canonical: {})",
                ev.parent_block_hash, ev.parent_block_number, canonical_parent,
            )));
        }

        // (7) Dedup key. A child block has exactly one Phase 1 system
        // transaction, so (child_hash, phase1_tx_hash) uniquely
        // identifies one invalid-VRF event.
        let phase1_tx_hash = keccak256(&ev.phase1_tx_bytes);
        let evidence_hash = invalid_vrf_evidence_hash_v2(ev.child_block_hash, phase1_tx_hash);
        if self.invalid_vrf_evidence_processed.read(&evidence_hash)? {
            return Err(PrecompileError::Revert("evidence already processed".into()));
        }

        // (8) Cryptographic proposer attribution. The Phase 1 tx is signed by
        // the child block's proposer. Its calldata is the single
        // source of truth for metadata and proof bytes.
        let chain_id = self.storage.chain_id()?;
        let (proposer, calldata) =
            recover_phase1_proposer(&ev.phase1_tx_bytes, chain_id, ev.child_block_number)
                .map_err(|err| PrecompileError::Revert(format!("phase1_tx invalid: {err}")))?;
        let metadata = match SystemTxInputV2::decode(calldata.as_ref()).map_err(|err| {
            PrecompileError::Revert(format!("phase1 calldata decode failed: {err}"))
        })? {
            SystemTxInputV2::CertifiedParentAccounting { metadata } => metadata,
            other => {
                return Err(PrecompileError::Revert(format!(
                    "phase1 calldata is not CertifiedParentAccounting: {:?}",
                    other.kind(),
                )));
            }
        };
        if metadata.finalized_block_number != ev.parent_block_number
            || metadata.finalized_block_hash != ev.parent_block_hash
        {
            return Err(PrecompileError::Revert(format!(
                "metadata parent binding mismatch: evidence=({}, {}), metadata=({}, {})",
                ev.parent_block_number,
                ev.parent_block_hash,
                metadata.finalized_block_number,
                metadata.finalized_block_hash,
            )));
        }
        if metadata.finalized_epoch != ev.child_epoch {
            return Err(PrecompileError::Revert(format!(
                "metadata epoch {} does not match evidence child_epoch {}",
                metadata.finalized_epoch, ev.child_epoch,
            )));
        }

        // (9) Load the canonical committee snapshot for the child's epoch.
        let snapshot_key =
            committee_snapshot_key(metadata.finalized_epoch, metadata.committee_set_hash);
        let snapshot =
            read_committee_snapshot(self.storage.clone(), snapshot_key)?.ok_or_else(|| {
                PrecompileError::Revert(format!(
                    "no committee snapshot for finalized_epoch={} committee_set_hash={}",
                    metadata.finalized_epoch, metadata.committee_set_hash,
                ))
            })?;

        // (10) Proposer must be in the snapshot's committee. Defends
        // against a future bug that signs a Phase 1 tx with a key not
        // bound to any active validator - without this check, the
        // felony helper would call jail_validator on a
        // non-existent validator and the slash path would silently
        // no-op.
        if !snapshot
            .committee
            .iter()
            .any(|entry| entry.address == proposer)
        {
            return Err(PrecompileError::Revert(format!(
                "phase1_tx proposer {proposer} not in committee for epoch {}",
                metadata.finalized_epoch,
            )));
        }

        // (11) Re-verify the proof. We expect verify_v2_proof to REJECT
        // with a VRF-class error; anything else is non-slashable here.
        let verify_err = match verify_v2_proof(
            &metadata,
            &snapshot,
            metadata.proof.as_ref(),
            ev.parent_block_hash,
        ) {
            Ok(_) => {
                return Err(PrecompileError::Revert(
                    "evidence shows a VALID proof; nothing to slash".into(),
                ));
            }
            Err(err) => err,
        };
        let failure_class = classify_vrf_failure(&verify_err).ok_or_else(|| {
            PrecompileError::Revert(format!(
                "verify_v2_proof rejected with non-VRF class ({verify_err}); not slashable here",
            ))
        })?;

        // (12) Mark dedup BEFORE applying effects so a panic / abort
        // between this point and the felony cannot enable replay.
        self.invalid_vrf_evidence_processed
            .write(&evidence_hash, true)?;

        // (13) Apply felony - forced exit + 5% slash + 10% submitter
        // reward, using the same helper the other evidence types call.
        self.apply_evidence_felony(proposer, caller)?;

        // (14) Canonical event with re-derived failure class.
        self.emit(ISlashIndicator::InvalidVrfProofEvidenceApplied {
            proposer,
            submitter: caller,
            childBlockHash: ev.child_block_hash,
            failureCode: failure_class,
        })?;

        // (15) Journal + structured warn! for operator visibility.
        let block_number = self.storage.block_number().unwrap_or(0);
        journal_record(JournalRecord::InvalidVrfProofEvidence {
            wall_clock: iso8601_now(),
            block_number,
            proposer: format!("{proposer:?}"),
            evidence_submitter: format!("{caller:?}"),
            child_block_hash: format!("{:?}", ev.child_block_hash),
            child_block_number: ev.child_block_number,
            child_epoch: ev.child_epoch,
            failure_class,
        });
        warn!(
            target: "outbe::slashing",
            event = "invalid_vrf_proof_evidence",
            %proposer,
            %caller,
            child_block_hash = %ev.child_block_hash,
            child_block_number = ev.child_block_number,
            child_epoch = ev.child_epoch,
            failure_class,
            block_number,
            "invalid-VRF evidence accepted - proposer self-incriminated by Phase 1 tx signature",
        );

        Ok(())
    }

    /// Submit evidence that a validator equivocated on its VRF seed partial:
    /// two DIFFERENT identity-signed `bls_seed_partial`s for the same
    /// `(round, vrf_material_version)`. Self-authenticating from the two MinPk
    /// identity signatures - no committee polynomial is needed - and reuses the
    /// shared felony economics. An honest validator produces exactly one partial
    /// per round/version and never identity-signs a second distinct one, so a
    /// valid pair cannot frame an honest node.
    pub fn submit_seed_partial_equivocation_evidence(
        &mut self,
        caller: Address,
        evidence_bytes: &[u8],
    ) -> Result<()> {
        self.submit_seed_partial_equivocation_evidence_with_schedule(
            caller,
            evidence_bytes,
            &OutbeProtocolSchedule::default(),
        )
    }

    /// Test seam for [`Self::submit_seed_partial_equivocation_evidence`] (lets
    /// integration tests relax the epoch-lag cap). Production goes through the
    /// no-arg wrapper with the canonical schedule.
    #[doc(hidden)]
    pub fn submit_seed_partial_equivocation_evidence_with_schedule(
        &mut self,
        caller: Address,
        evidence_bytes: &[u8],
        schedule: &OutbeProtocolSchedule,
    ) -> Result<()> {
        // (1) Submitter ACL: ACTIVE validators only - verification is BLS-heavy,
        // so gating to the staked set makes DoS self-destructive.
        self.require_active_submitter(caller)?;

        // (2) Decode the fixed-length wire form (length-checked inside).
        let ev = SeedPartialEquivocationEvidence::decode(evidence_bytes)?;

        // (3) Equivocation requires two DIFFERENT partials.
        if ev.partial_1 == ev.partial_2 {
            return Err(PrecompileError::Revert(
                "not equivocation: the two partials are identical".into(),
            ));
        }

        // (4) Both partials must carry a valid identity signature from the SAME
        // signer over the same (round, version). This is the soundness anchor:
        // it proves the accused signer itself produced both distinct partials.
        let ok1 = verify_seed_partial_attest_bytes(
            &ev.signer_pubkey,
            ev.round_epoch,
            ev.round_view,
            ev.vrf_version,
            &ev.partial_1,
            &ev.identity_sig_1,
        );
        let ok2 = verify_seed_partial_attest_bytes(
            &ev.signer_pubkey,
            ev.round_epoch,
            ev.round_view,
            ev.vrf_version,
            &ev.partial_2,
            &ev.identity_sig_2,
        );
        if !(ok1 && ok2) {
            return Err(PrecompileError::Revert(
                "both partials must carry a valid identity signature from the accused signer"
                    .into(),
            ));
        }

        // (5) Epoch-lag admissibility: bound how old the offense round can be
        // (reuses the shared evidence epoch-lag cap).
        let vs = ValidatorSet::new(self.storage.clone());
        let current_epoch = vs.current_epoch_u64()?;
        let max_acceptable_epoch = ev
            .round_epoch
            .saturating_add(schedule.invalid_vrf_evidence_max_epoch_lag);
        if current_epoch > max_acceptable_epoch {
            return Err(PrecompileError::Revert(format!(
                "evidence epoch-stale: current_epoch {} > round_epoch {} + max_lag {}",
                current_epoch, ev.round_epoch, schedule.invalid_vrf_evidence_max_epoch_lag,
            )));
        }

        // (6) Attribution: map the identity pubkey to a registered validator.
        let validator_addr = vs.lookup_by_pubkey_hash(ev.pubkey_hash())?;
        if validator_addr.is_zero() {
            return Err(PrecompileError::Revert(
                "signer is not a registered validator".into(),
            ));
        }

        // (7) Dedup BEFORE effects (order-independent in the two partials).
        let dedup = ev.dedup_hash();
        if self.seed_partial_equivocation_processed.read(&dedup)? {
            return Err(PrecompileError::Revert("evidence already processed".into()));
        }
        self.seed_partial_equivocation_processed
            .write(&dedup, true)?;

        // (8) Felony: jail + slash + reward submitter.
        self.apply_evidence_felony(validator_addr, caller)?;
        self.emit(ISlashIndicator::SeedPartialEquivocationApplied {
            validator: validator_addr,
            submitter: caller,
            roundEpoch: ev.round_epoch,
            roundView: ev.round_view,
            vrfVersion: ev.vrf_version,
        })?;
        Ok(())
    }

    /// Submit evidence that a validator emitted a single INVALID VRF seed
    /// partial: an identity-signed partial that fails verification against the
    /// committee's full public polynomial. Unlike equivocation, this needs the
    /// committee polynomial - carried in the evidence and checked against the
    /// `vrf_public_polynomial_hash` committed in the committee snapshot (which
    /// the executor derives from the consensus-validated DKG boundary outcome,
    /// so a proposer cannot forge it to frame an honest validator). Reuses the
    /// shared felony economics.
    pub fn submit_invalid_seed_partial_evidence(
        &mut self,
        caller: Address,
        evidence_bytes: &[u8],
    ) -> Result<()> {
        self.submit_invalid_seed_partial_evidence_with_schedule(
            caller,
            evidence_bytes,
            &OutbeProtocolSchedule::default(),
        )
    }

    /// Test seam for [`Self::submit_invalid_seed_partial_evidence`].
    #[doc(hidden)]
    pub fn submit_invalid_seed_partial_evidence_with_schedule(
        &mut self,
        caller: Address,
        evidence_bytes: &[u8],
        schedule: &OutbeProtocolSchedule,
    ) -> Result<()> {
        // (1) Submitter ACL: ACTIVE validators only (BLS-heavy verification).
        self.require_active_submitter(caller)?;

        // (2) Size cap - the polynomial commitment dominates; reuse the VRF
        // evidence cap (the only other commitment-carrying evidence).
        if evidence_bytes.len() > schedule.invalid_vrf_evidence_max_bytes {
            return Err(PrecompileError::Revert(format!(
                "evidence too large: {} > {} bytes",
                evidence_bytes.len(),
                schedule.invalid_vrf_evidence_max_bytes,
            )));
        }

        // (3) Decode.
        let ev = InvalidSeedPartialEvidence::decode(evidence_bytes)?;

        // (4) Epoch-lag admissibility.
        let vs = ValidatorSet::new(self.storage.clone());
        let current_epoch = vs.current_epoch_u64()?;
        let max_acceptable_epoch = ev
            .round_epoch
            .saturating_add(schedule.invalid_vrf_evidence_max_epoch_lag);
        if current_epoch > max_acceptable_epoch {
            return Err(PrecompileError::Revert(format!(
                "evidence epoch-stale: current_epoch {} > round_epoch {} + max_lag {}",
                current_epoch, ev.round_epoch, schedule.invalid_vrf_evidence_max_epoch_lag,
            )));
        }

        // (5) Attribution.
        let validator_addr = vs.lookup_by_pubkey_hash(ev.pubkey_hash())?;
        if validator_addr.is_zero() {
            return Err(PrecompileError::Revert(
                "signer is not a registered validator".into(),
            ));
        }

        // (6) Load the committee snapshot for this round's epoch + committee.
        let snapshot_key = committee_snapshot_key(ev.round_epoch, ev.committee_set_hash);
        let snapshot =
            read_committee_snapshot(self.storage.clone(), snapshot_key)?.ok_or_else(|| {
                PrecompileError::Revert(
                    "no committee snapshot for (round_epoch, committee_set_hash)".into(),
                )
            })?;

        // (7) Bind the signer index to the committee pubkey (and to the
        // evidence's claimed pubkey), so PK_i is derived at the right index.
        let idx = ev.signer_index as usize;
        let entry = snapshot
            .committee
            .get(idx)
            .ok_or_else(|| PrecompileError::Revert("signer index out of committee range".into()))?;
        if entry.consensus_pubkey != ev.signer_pubkey {
            return Err(PrecompileError::Revert(
                "signer pubkey does not match committee entry at index".into(),
            ));
        }

        // (8) Material version must match the snapshot's (the carried polynomial
        // is the snapshot's polynomial).
        if snapshot.vrf_material_version != ev.vrf_version {
            return Err(PrecompileError::Revert(
                "vrf material version does not match committee snapshot".into(),
            ));
        }

        // (9) Commitment authenticity: the snapshot must carry a polynomial hash
        // and it must match the carried commitment.
        if snapshot.vrf_public_polynomial_hash.is_zero() {
            return Err(PrecompileError::Revert(
                "committee snapshot has no polynomial commitment".into(),
            ));
        }
        if keccak256(&ev.commitment) != snapshot.vrf_public_polynomial_hash {
            return Err(PrecompileError::Revert(
                "commitment does not match committee snapshot polynomial hash".into(),
            ));
        }

        // (10) Identity signature: proves the accused signer emitted THIS partial
        // (a relay cannot forge it).
        if !verify_seed_partial_attest_bytes(
            &ev.signer_pubkey,
            ev.round_epoch,
            ev.round_view,
            ev.vrf_version,
            &ev.partial,
            &ev.identity_sig,
        ) {
            return Err(PrecompileError::Revert(
                "partial is not identity-signed by the accused signer".into(),
            ));
        }

        // (11) The partial must FAIL verification against the committee
        // polynomial. A valid partial is not slashable; malformed input rejects.
        match verify_seed_partial_against_commitment(
            &ev.commitment,
            ev.signer_index,
            ev.round_epoch,
            ev.round_view,
            &ev.partial,
        ) {
            None => {
                return Err(PrecompileError::Revert(
                    "malformed commitment or partial".into(),
                ))
            }
            Some(true) => {
                return Err(PrecompileError::Revert(
                    "seed partial is valid; nothing to slash".into(),
                ))
            }
            Some(false) => {}
        }

        // (12) Dedup before effects.
        let dedup = ev.dedup_hash();
        if self.invalid_seed_partial_processed.read(&dedup)? {
            return Err(PrecompileError::Revert("evidence already processed".into()));
        }
        self.invalid_seed_partial_processed.write(&dedup, true)?;

        // (13) Felony.
        self.apply_evidence_felony(validator_addr, caller)?;
        self.emit(ISlashIndicator::InvalidSeedPartialApplied {
            validator: validator_addr,
            submitter: caller,
            roundEpoch: ev.round_epoch,
            roundView: ev.round_view,
            vrfVersion: ev.vrf_version,
        })?;
        Ok(())
    }

    /// Applies a felony for byzantine behavior detected by the consensus layer.
    ///
    /// Called from post-execution hooks when the consensus layer detects equivocation
    /// (ConflictingNotarize, ConflictingFinalize, NullifyFinalize).
    /// Unlike `apply_evidence_felony`, there is no external evidence submitter,
    /// so no reward is distributed.
    pub fn slash_byzantine(&mut self, validator: Address) -> Result<()> {
        let block_number = self.storage.block_number().unwrap_or(0);
        // Felony: JAIL (not force-exit) + slash. Jail before slash_stake (which
        // leaves a JAILED status untouched).
        let mut vs = ValidatorSet::new(self.storage.clone());
        vs.jail_validator(validator)?;

        let fc = self.felony_count.read(&validator)? + 1;
        self.felony_count.write(&validator, fc)?;

        let slash_percent = self.slash_amount_percent()?;
        let mut staking = Staking::new(self.storage.clone());
        let slashed_amount = staking.slash_stake(validator, slash_percent)?;

        crate::metrics::record_felony_count(validator, fc);
        crate::metrics::record_validator_slashed(validator, "byzantine");

        journal_record(JournalRecord::ByzantineFelony {
            wall_clock: iso8601_now(),
            block_number,
            validator: format!("{validator:?}"),
            felony_count: fc,
            slash_percent,
            slashed_amount: slashed_amount.to_string(),
        });

        warn!(
            target: "outbe::slashing",
            event = "byzantine_felony",
            %validator,
            felony_count = fc,
            slash_percent,
            slashed_amount = %slashed_amount,
            block_number,
            "byzantine felony - equivocation detected, validator force-exited and slashed",
        );

        self.emit(ISlashIndicator::ByzantineFelony {
            validator,
            slashedAmount: slashed_amount,
            felonyCount: fc,
        })?;

        Ok(())
    }

    /// Resets per-epoch miss counters (proposer and voter) to zero for all given validators.
    ///
    /// Called at epoch boundary. Does NOT reset felony_count (that is cumulative).
    pub fn reset_epoch_counters(&mut self, validators: &[Address]) -> Result<()> {
        tracing::debug!(
            target: "outbe::slashing",
            event = "epoch_counters_reset",
            validator_count = validators.len(),
            block_number = self.storage.block_number().unwrap_or(0),
            "resetting per-epoch proposer/voter miss counters",
        );
        crate::metrics::record_epoch_counters_reset(validators.len());
        for v in validators {
            crate::metrics::record_proposer_miss_count(*v, 0);
            crate::metrics::record_voter_miss_count(*v, 0);
        }
        journal_record(JournalRecord::EpochCountersReset {
            wall_clock: iso8601_now(),
            block_number: self.storage.block_number().unwrap_or(0),
            validator_count: validators.len(),
        });
        for &validator in validators {
            self.proposer_miss_count.write(&validator, 0)?;
            self.voter_miss_count.write(&validator, 0)?;
        }
        Ok(())
    }

    // --- Getters ---

    /// Returns the current proposer miss count for `validator`.
    pub fn get_proposer_miss_count(&self, validator: Address) -> Result<u64> {
        self.proposer_miss_count.read(&validator)
    }

    /// Returns the current voter miss count for `validator`.
    pub fn get_voter_miss_count(&self, validator: Address) -> Result<u64> {
        self.voter_miss_count.read(&validator)
    }

    /// Returns the cumulative felony count for `validator`.
    pub fn get_felony_count(&self, validator: Address) -> Result<u64> {
        self.felony_count.read(&validator)
    }

    /// Returns whether an evidence hash has already been processed.
    pub fn is_evidence_processed(&self, evidence_hash: B256) -> Result<bool> {
        self.evidence_processed.read(&evidence_hash)
    }
}

/// Computes a canonical evidence hash that is order-independent.
///
/// Normalizes the order of two evidence payloads before hashing so that
/// `(block1, block2)` and `(block2, block1)` produce the same hash.
fn canonical_evidence_hash(ev1: &[u8], ev2: &[u8]) -> B256 {
    let (first, second) = if ev1 <= ev2 { (ev1, ev2) } else { (ev2, ev1) };
    let mut buf = Vec::with_capacity(first.len() + second.len());
    buf.extend_from_slice(first);
    buf.extend_from_slice(second);
    keccak256(&buf)
}

/// maps a [`V2VerifyError`] to a canonical VRF failure class code
/// emitted in [`InvalidVrfProofEvidenceApplied`] and the slashing journal.
///
/// Returns `None` for any non-VRF failure - those are not slashable through
/// `submitInvalidVrfProofEvidence` and the caller must revert.
///
/// The codes are stable wire constants once the precompile is live; renaming
/// or renumbering them is a hard-fork change.
pub fn classify_vrf_failure(err: &V2VerifyError) -> Option<u16> {
    match err {
        V2VerifyError::MalformedVrfProof => Some(2),
        V2VerifyError::WrongVrfMaterialVersion { .. } => Some(3),
        V2VerifyError::WrongVrfGroupKeyHash { .. } => Some(4),
        V2VerifyError::WrongVrfNamespace => Some(5),
        V2VerifyError::WrongVrfSeedRound { .. } => Some(6),
        V2VerifyError::InvalidVrfSignature => Some(7),
        _ => None,
    }
}
