//! Canonical direct on-chain result votes and bounded accountability state.

use alloy_primitives::{keccak256, B256};

use crate::{
    abi::SUBMIT_LYSIS_RESULT_SELECTOR,
    codec::{decode_envelope, CanonicalReader},
    committee::{verify_low_s_prehash, POC_KEY_EPOCH},
    error::ProtocolError,
    hash::hash_framed,
    intent::JobIntentV1,
    registry::{HashDomain, ObjectKind},
    result::LysisResultV1,
    schema::{impl_top_level_codec, require, wire_struct, SchemaLimits},
};

wire_struct! {
    pub struct ResultVoteV1 {
        pub protocol_bundle_hash: B256,
        pub job_id: B256,
        pub attempt: u32,
        pub result_validator_set_epoch: u64,
        pub result_committee_set_hash: B256,
        pub result_ocomp_binding_hash: B256,
        pub ocomp_key_hash: B256,
        pub key_epoch: u64,
        pub result: LysisResultV1,
        pub signature_rs: [u8; 64],
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultVotePrefixV1 {
    pub protocol_bundle_hash: B256,
    pub job_id: B256,
    pub attempt: u32,
    pub result_validator_set_epoch: u64,
    pub result_committee_set_hash: B256,
    pub result_ocomp_binding_hash: B256,
    pub ocomp_key_hash: B256,
    pub key_epoch: u64,
}

impl ResultVoteV1 {
    #[must_use]
    pub const fn prefix(&self) -> ResultVotePrefixV1 {
        ResultVotePrefixV1 {
            protocol_bundle_hash: self.protocol_bundle_hash,
            job_id: self.job_id,
            attempt: self.attempt,
            result_validator_set_epoch: self.result_validator_set_epoch,
            result_committee_set_hash: self.result_committee_set_hash,
            result_ocomp_binding_hash: self.result_ocomp_binding_hash,
            ocomp_key_hash: self.ocomp_key_hash,
            key_epoch: self.key_epoch,
        }
    }

    pub fn encode_canonical(&self, limits: &SchemaLimits) -> Result<Vec<u8>, ProtocolError> {
        crate::schema::encode_top(self, ObjectKind::ResultVoteV1, limits)
    }

    pub fn decode_canonical(encoded: &[u8], limits: &SchemaLimits) -> Result<Self, ProtocolError> {
        Self::decode_canonical_prefix(encoded, limits)?;
        crate::schema::decode_top(encoded, ObjectKind::ResultVoteV1, limits)
    }

    pub fn decode_canonical_prefix(
        encoded: &[u8],
        limits: &SchemaLimits,
    ) -> Result<ResultVotePrefixV1, ProtocolError> {
        let envelope = decode_envelope(encoded, limits.codec)?;
        if envelope.kind != ObjectKind::ResultVoteV1 {
            return Err(ProtocolError::UnexpectedObjectKind {
                expected: ObjectKind::ResultVoteV1.tag(),
                actual: envelope.kind.tag(),
            });
        }
        let mut body = CanonicalReader::new(envelope.body, limits.codec)?;
        Ok(ResultVotePrefixV1 {
            protocol_bundle_hash: body.read_b256()?,
            job_id: body.read_b256()?,
            attempt: body.read_u32()?,
            result_validator_set_epoch: body.read_u64()?,
            result_committee_set_hash: body.read_b256()?,
            result_ocomp_binding_hash: body.read_b256()?,
            ocomp_key_hash: body.read_b256()?,
            key_epoch: body.read_u64()?,
        })
    }
}

pub fn decode_submit_lysis_result_prefix(
    calldata: &[u8],
    limits: &SchemaLimits,
) -> Result<ResultVotePrefixV1, ProtocolError> {
    let payload = decode_submit_lysis_result_payload(calldata)?;
    ResultVoteV1::decode_canonical_prefix(payload, limits)
}

/// Decode the complete canonical vote carried by `submitLysisResult(bytes)`.
///
/// This shares the exact ABI length, padding and schema bounds used by the
/// hot-path prefix decoder so a finalized-block observer cannot accept a
/// different envelope from txpool or execution.
pub fn decode_submit_lysis_result(
    calldata: &[u8],
    limits: &SchemaLimits,
) -> Result<ResultVoteV1, ProtocolError> {
    let payload = decode_submit_lysis_result_payload(calldata)?;
    ResultVoteV1::decode_canonical(payload, limits)
}

fn decode_submit_lysis_result_payload(calldata: &[u8]) -> Result<&[u8], ProtocolError> {
    const ABI_HEAD_LEN: usize = 68;
    if calldata.len() < ABI_HEAD_LEN {
        return Err(ProtocolError::UnexpectedEof {
            offset: 0,
            needed: ABI_HEAD_LEN,
            remaining: calldata.len(),
        });
    }
    require(
        calldata[..4] == SUBMIT_LYSIS_RESULT_SELECTOR,
        "submitLysisResult selector",
    )?;
    let mut expected_offset = [0_u8; 32];
    expected_offset[31] = 32;
    require(
        calldata[4..36] == expected_offset,
        "submitLysisResult ABI offset",
    )?;
    let payload_len = abi_word_to_usize(&calldata[36..68])?;
    let vote_cap = usize::try_from(
        crate::generated_shape::OCOMP_POC_CANDIDATE_LIMITS_V1.max_result_vote_bytes,
    )
    .map_err(|_| ProtocolError::InvalidInvariant("result vote byte cap"))?;
    if payload_len > vote_cap {
        return Err(ProtocolError::CapacityExceeded {
            what: "result vote bytes",
            limit: vote_cap,
            actual: payload_len,
        });
    }
    let padded_len = payload_len.checked_add(31).map(|value| value & !31).ok_or(
        ProtocolError::IntegerOverflow {
            what: "result vote ABI padding",
        },
    )?;
    let expected_len =
        ABI_HEAD_LEN
            .checked_add(padded_len)
            .ok_or(ProtocolError::IntegerOverflow {
                what: "result vote ABI calldata",
            })?;
    require(
        calldata.len() == expected_len,
        "submitLysisResult ABI length",
    )?;
    let payload_end =
        ABI_HEAD_LEN
            .checked_add(payload_len)
            .ok_or(ProtocolError::IntegerOverflow {
                what: "result vote ABI payload end",
            })?;
    require(
        calldata[payload_end..].iter().all(|byte| *byte == 0),
        "submitLysisResult ABI padding",
    )?;
    Ok(&calldata[ABI_HEAD_LEN..payload_end])
}

fn abi_word_to_usize(word: &[u8]) -> Result<usize, ProtocolError> {
    require(word.len() == 32, "ABI word length")?;
    let significant = core::mem::size_of::<usize>();
    require(
        word[..32 - significant].iter().all(|byte| *byte == 0),
        "ABI usize overflow",
    )?;
    let mut bytes = [0_u8; core::mem::size_of::<usize>()];
    bytes.copy_from_slice(&word[32 - significant..]);
    Ok(usize::from_be_bytes(bytes))
}

wire_struct! {
    pub struct EquivocationEvidenceV1 {
        pub conflicting_result_digest: B256,
        pub conflicting_key_epoch: u64,
        pub conflicting_signature_rs: [u8; 64],
        pub submitted_height: u64,
    }
}
impl_top_level_codec!(EquivocationEvidenceV1, EquivocationEvidenceV1);

wire_struct! {
    pub struct ResultVoteSlotV1 {
        pub validator_index: u16,
        pub first_result_digest: B256,
        pub key_epoch: u64,
        pub first_signature_rs: [u8; 64],
        pub submitted_height: u64,
        pub equivocation: Option<EquivocationEvidenceV1>,
    }
    validate = validate_vote_slot;
}
impl_top_level_codec!(ResultVoteSlotV1, ResultVoteSlotV1);

wire_struct! {
    pub struct OcompQuorumV1 {
        pub member_count: u16,
        pub quorum_threshold: u16,
        pub result_digest: B256,
        pub quorum_height: u64,
        pub signer_bitmap: Vec<u8>,
        pub evidence_hash: B256,
    }
    validate = validate_quorum;
}
impl_top_level_codec!(OcompQuorumV1, OcompQuorumV1);

wire_struct! {
    pub struct OcompAccountabilitySummaryV1 {
        pub closed_height: u64,
        pub result_validator_set_epoch: u64,
        pub result_committee_set_hash: B256,
        pub result_ocomp_binding_hash: B256,
        pub member_count: u16,
        pub quorum_threshold: u16,
        pub winning_result_digest: Option<B256>,
        pub quorum_evidence_hash: Option<B256>,
        pub timely_bitmap: Vec<u8>,
        pub matching_bitmap: Vec<u8>,
        pub divergent_bitmap: Vec<u8>,
        pub missing_bitmap: Vec<u8>,
        pub equivocation_bitmap: Vec<u8>,
    }
    validate = validate_accountability_summary;
}
impl_top_level_codec!(OcompAccountabilitySummaryV1, OcompAccountabilitySummaryV1);

wire_struct! {
    pub struct OcompVoteAccountabilityV1 {
        pub job_id: B256,
        pub result_validator_set_epoch: u64,
        pub result_committee_set_hash: B256,
        pub result_ocomp_binding_hash: B256,
        pub member_count: u16,
        pub quorum_threshold: u16,
        pub slots: Vec<Option<ResultVoteSlotV1>>,
        pub quorum: Option<OcompQuorumV1>,
        pub closed_summary: Option<OcompAccountabilitySummaryV1>,
    }
    validate = validate_vote_accountability;
}
impl_top_level_codec!(OcompVoteAccountabilityV1, OcompVoteAccountabilityV1);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordVoteOutcomeV1 {
    FirstVote,
    ExactRetry,
    SameDigestRetry,
    EquivocationRecorded,
    EquivocationAlreadyRecorded,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultVoteSigningSubjectV1 {
    pub chain_id: u64,
    pub genesis_hash: B256,
    pub fork_id: B256,
    pub protocol_bundle_hash: B256,
    pub job_id: B256,
    pub attempt: u32,
    pub result_validator_set_epoch: u64,
    pub result_committee_set_hash: B256,
    pub result_ocomp_binding_hash: B256,
    pub ocomp_key_hash: B256,
    pub key_epoch: u64,
    pub purpose: u8,
    pub result_digest: B256,
}

impl ResultVoteSigningSubjectV1 {
    pub fn signing_digest(self) -> Result<B256, ProtocolError> {
        let mut payload = Vec::with_capacity(8 * 3 + 32 * 8 + 4 + 1);
        payload.extend_from_slice(&self.chain_id.to_be_bytes());
        payload.extend_from_slice(self.genesis_hash.as_slice());
        payload.extend_from_slice(self.fork_id.as_slice());
        payload.extend_from_slice(self.protocol_bundle_hash.as_slice());
        payload.extend_from_slice(self.job_id.as_slice());
        payload.extend_from_slice(&self.attempt.to_be_bytes());
        payload.extend_from_slice(&self.result_validator_set_epoch.to_be_bytes());
        payload.extend_from_slice(self.result_committee_set_hash.as_slice());
        payload.extend_from_slice(self.result_ocomp_binding_hash.as_slice());
        payload.extend_from_slice(self.ocomp_key_hash.as_slice());
        payload.extend_from_slice(&self.key_epoch.to_be_bytes());
        payload.push(self.purpose);
        payload.extend_from_slice(self.result_digest.as_slice());
        hash_framed(HashDomain::ResultVoteSubject, &payload)
    }
}

impl ResultVoteV1 {
    /// Verifies a vote against one member resolved by a stateful caller from
    /// the exact historical ValidatorSet snapshot pinned by the intent.
    #[allow(clippy::too_many_arguments)]
    pub fn verify_historical_member(
        &self,
        finalized_intent: &JobIntentV1,
        expected_job_id: B256,
        member_count: u16,
        member_key_epoch: u64,
        member_ocomp_public_key_sec1: &[u8; 33],
        inclusion_height: u64,
        open_height: u64,
        deadline_height: u64,
        limits: &SchemaLimits,
    ) -> Result<(), ProtocolError> {
        finalized_intent.validate_semantics()?;
        self.result.validate_semantics(limits)?;
        self.result.validate_finalized_intent(finalized_intent)?;
        require(open_height < deadline_height, "vote window ordering")?;
        require(
            open_height <= inclusion_height && inclusion_height < deadline_height,
            "vote inclusion height",
        )?;
        require(
            self.protocol_bundle_hash == finalized_intent.protocol_bundle_hash
                && self.job_id == expected_job_id
                && self.attempt == finalized_intent.attempt,
            "vote finalized job binding",
        )?;
        require(
            self.result.protocol_bundle_hash == self.protocol_bundle_hash
                && self.result.job_id == self.job_id
                && self.result.attempt == self.attempt,
            "vote full result binding",
        )?;
        require(
            self.result_validator_set_epoch == finalized_intent.result_validator_set_epoch
                && self.result_committee_set_hash == finalized_intent.result_committee_set_hash
                && self.result_ocomp_binding_hash == finalized_intent.result_ocomp_binding_hash
                && finalized_intent.result_member_count == member_count,
            "vote committee binding",
        )?;
        require(
            self.ocomp_key_hash == keccak256(member_ocomp_public_key_sec1),
            "vote OCOMP key hash",
        )?;
        require(
            self.key_epoch == POC_KEY_EPOCH && member_key_epoch == self.key_epoch,
            "vote key epoch",
        )?;
        let signing_digest = self.signing_digest(finalized_intent, limits)?;
        verify_low_s_prehash(
            member_ocomp_public_key_sec1,
            signing_digest,
            &self.signature_rs,
        )
    }

    pub fn result_digest(&self, limits: &SchemaLimits) -> Result<B256, ProtocolError> {
        self.result.result_digest(limits)
    }

    pub fn signing_digest(
        &self,
        finalized_intent: &JobIntentV1,
        limits: &SchemaLimits,
    ) -> Result<B256, ProtocolError> {
        require(
            self.protocol_bundle_hash == finalized_intent.protocol_bundle_hash
                && self.attempt == finalized_intent.attempt
                && self.result_validator_set_epoch == finalized_intent.result_validator_set_epoch
                && self.result_committee_set_hash == finalized_intent.result_committee_set_hash
                && self.result_ocomp_binding_hash == finalized_intent.result_ocomp_binding_hash,
            "vote signing subject intent binding",
        )?;
        ResultVoteSigningSubjectV1 {
            chain_id: finalized_intent.chain_id,
            genesis_hash: finalized_intent.genesis_hash,
            fork_id: finalized_intent.fork_id,
            protocol_bundle_hash: self.protocol_bundle_hash,
            job_id: self.job_id,
            attempt: self.attempt,
            result_validator_set_epoch: self.result_validator_set_epoch,
            result_committee_set_hash: self.result_committee_set_hash,
            result_ocomp_binding_hash: self.result_ocomp_binding_hash,
            ocomp_key_hash: self.ocomp_key_hash,
            key_epoch: self.key_epoch,
            purpose: 1, // SignOncePurpose::ResultSignature
            result_digest: self.result_digest(limits)?,
        }
        .signing_digest()
    }
}

impl ResultVoteSlotV1 {
    pub fn from_vote(
        validator_index: u16,
        vote: &ResultVoteV1,
        submitted_height: u64,
        limits: &SchemaLimits,
    ) -> Result<Self, ProtocolError> {
        Ok(Self {
            validator_index,
            first_result_digest: vote.result_digest(limits)?,
            key_epoch: vote.key_epoch,
            first_signature_rs: vote.signature_rs,
            submitted_height,
            equivocation: None,
        })
    }

    fn exact_vote(&self, vote: &ResultVoteV1, vote_digest: B256, _submitted_height: u64) -> bool {
        self.first_result_digest == vote_digest
            && self.key_epoch == vote.key_epoch
            && self.first_signature_rs == vote.signature_rs
    }
}

impl OcompVoteAccountabilityV1 {
    pub fn empty(
        job_id: B256,
        result_validator_set_epoch: u64,
        result_committee_set_hash: B256,
        result_ocomp_binding_hash: B256,
        member_count: u16,
        quorum_threshold: u16,
    ) -> Result<Self, ProtocolError> {
        validate_n_and_quorum(member_count, quorum_threshold)?;
        let slots = vec![None; usize::from(member_count)];
        Ok(Self {
            job_id,
            result_validator_set_epoch,
            result_committee_set_hash,
            result_ocomp_binding_hash,
            member_count,
            quorum_threshold,
            slots,
            quorum: None,
            closed_summary: None,
        })
    }

    pub fn record_verified_vote(
        &mut self,
        validator_index: u16,
        vote: &ResultVoteV1,
        submitted_height: u64,
        limits: &SchemaLimits,
    ) -> Result<RecordVoteOutcomeV1, ProtocolError> {
        self.validate_semantics(limits)?;
        require(self.closed_summary.is_none(), "vote window already closed")?;
        require(
            vote.job_id == self.job_id
                && vote.result_validator_set_epoch == self.result_validator_set_epoch
                && vote.result_committee_set_hash == self.result_committee_set_hash
                && vote.result_ocomp_binding_hash == self.result_ocomp_binding_hash,
            "vote accountability binding",
        )?;
        let vote_digest = vote.result_digest(limits)?;
        let slot = self
            .slots
            .get_mut(usize::from(validator_index))
            .ok_or(ProtocolError::InvalidInvariant("vote slot index"))?;
        let outcome = match slot {
            None => {
                *slot = Some(ResultVoteSlotV1::from_vote(
                    validator_index,
                    vote,
                    submitted_height,
                    limits,
                )?);
                RecordVoteOutcomeV1::FirstVote
            }
            Some(existing) if existing.exact_vote(vote, vote_digest, submitted_height) => {
                RecordVoteOutcomeV1::ExactRetry
            }
            Some(existing) if existing.first_result_digest == vote_digest => {
                RecordVoteOutcomeV1::SameDigestRetry
            }
            Some(existing) if existing.equivocation.is_none() => {
                existing.equivocation = Some(EquivocationEvidenceV1 {
                    conflicting_result_digest: vote_digest,
                    conflicting_key_epoch: vote.key_epoch,
                    conflicting_signature_rs: vote.signature_rs,
                    submitted_height,
                });
                RecordVoteOutcomeV1::EquivocationRecorded
            }
            Some(_) => RecordVoteOutcomeV1::EquivocationAlreadyRecorded,
        };
        if self.quorum.is_none() && matches!(outcome, RecordVoteOutcomeV1::FirstVote) {
            self.quorum = self.derive_quorum(submitted_height, limits)?;
        }
        self.validate_semantics(limits)?;
        Ok(outcome)
    }

    pub fn close(
        &mut self,
        closed_height: u64,
        limits: &SchemaLimits,
    ) -> Result<OcompAccountabilitySummaryV1, ProtocolError> {
        self.validate_semantics(limits)?;
        if let Some(summary) = &self.closed_summary {
            require(
                summary.closed_height == closed_height,
                "accountability close exact retry",
            )?;
            return Ok(summary.clone());
        }
        let mut timely_bitmap = empty_bitmap(self.member_count)?;
        let mut matching_bitmap = empty_bitmap(self.member_count)?;
        let mut divergent_bitmap = empty_bitmap(self.member_count)?;
        let mut equivocation_bitmap = empty_bitmap(self.member_count)?;
        for (index, slot) in self.slots.iter().enumerate() {
            let Some(slot) = slot else {
                continue;
            };
            set_bitmap_bit(&mut timely_bitmap, index)?;
            if self
                .quorum
                .as_ref()
                .is_some_and(|quorum| quorum.result_digest == slot.first_result_digest)
            {
                set_bitmap_bit(&mut matching_bitmap, index)?;
            } else {
                set_bitmap_bit(&mut divergent_bitmap, index)?;
            }
            if slot.equivocation.is_some() {
                set_bitmap_bit(&mut equivocation_bitmap, index)?;
            }
        }
        let mut missing_bitmap = participant_mask(self.member_count)?;
        for (missing, timely) in missing_bitmap.iter_mut().zip(&timely_bitmap) {
            *missing &= !*timely;
        }
        let summary = OcompAccountabilitySummaryV1 {
            closed_height,
            result_validator_set_epoch: self.result_validator_set_epoch,
            result_committee_set_hash: self.result_committee_set_hash,
            result_ocomp_binding_hash: self.result_ocomp_binding_hash,
            member_count: self.member_count,
            quorum_threshold: self.quorum_threshold,
            winning_result_digest: self.quorum.as_ref().map(|quorum| quorum.result_digest),
            quorum_evidence_hash: self.quorum.as_ref().map(|quorum| quorum.evidence_hash),
            timely_bitmap,
            matching_bitmap,
            divergent_bitmap,
            missing_bitmap,
            equivocation_bitmap,
        };
        summary.validate_semantics()?;
        self.closed_summary = Some(summary.clone());
        self.validate_semantics(limits)?;
        Ok(summary)
    }

    pub fn accountability_hash(&self, limits: &SchemaLimits) -> Result<B256, ProtocolError> {
        self.validate_semantics(limits)?;
        hash_framed(
            HashDomain::VoteAccountability,
            &self.encode_canonical(limits)?,
        )
    }

    fn derive_quorum(
        &self,
        quorum_height: u64,
        limits: &SchemaLimits,
    ) -> Result<Option<OcompQuorumV1>, ProtocolError> {
        for candidate in self.slots.iter().flatten() {
            let mut signer_bitmap = empty_bitmap(self.member_count)?;
            for (index, slot) in self.slots.iter().enumerate() {
                if slot
                    .as_ref()
                    .is_some_and(|slot| slot.first_result_digest == candidate.first_result_digest)
                {
                    set_bitmap_bit(&mut signer_bitmap, index)?;
                }
            }
            if bitmap_population(&signer_bitmap) < u32::from(self.quorum_threshold) {
                continue;
            }
            let evidence_hash = self.quorum_evidence_hash(
                candidate.first_result_digest,
                quorum_height,
                &signer_bitmap,
                limits,
            )?;
            return Ok(Some(OcompQuorumV1 {
                member_count: self.member_count,
                quorum_threshold: self.quorum_threshold,
                result_digest: candidate.first_result_digest,
                quorum_height,
                signer_bitmap,
                evidence_hash,
            }));
        }
        Ok(None)
    }

    fn quorum_evidence_hash(
        &self,
        result_digest: B256,
        quorum_height: u64,
        signer_bitmap: &[u8],
        _limits: &SchemaLimits,
    ) -> Result<B256, ProtocolError> {
        let mut payload = Vec::new();
        payload.extend_from_slice(self.job_id.as_slice());
        payload.extend_from_slice(&self.result_validator_set_epoch.to_be_bytes());
        payload.extend_from_slice(self.result_committee_set_hash.as_slice());
        payload.extend_from_slice(self.result_ocomp_binding_hash.as_slice());
        payload.extend_from_slice(&self.member_count.to_be_bytes());
        payload.extend_from_slice(&self.quorum_threshold.to_be_bytes());
        payload.extend_from_slice(result_digest.as_slice());
        payload.extend_from_slice(&quorum_height.to_be_bytes());
        payload.extend_from_slice(signer_bitmap);
        for (index, slot) in self.slots.iter().enumerate() {
            if !bitmap_bit_is_set(signer_bitmap, index)? {
                continue;
            }
            let slot = slot
                .as_ref()
                .ok_or(ProtocolError::InvalidInvariant("quorum slot present"))?;
            require(
                slot.first_result_digest == result_digest,
                "quorum slot result digest",
            )?;
            payload.extend_from_slice(&slot.validator_index.to_be_bytes());
            payload.extend_from_slice(slot.first_result_digest.as_slice());
            payload.extend_from_slice(&slot.key_epoch.to_be_bytes());
            payload.extend_from_slice(&slot.first_signature_rs);
            payload.extend_from_slice(&slot.submitted_height.to_be_bytes());
        }
        hash_framed(HashDomain::QuorumEvidence, &payload)
    }

    pub fn validate_semantics(&self, limits: &SchemaLimits) -> Result<(), ProtocolError> {
        validate_n_and_quorum(self.member_count, self.quorum_threshold)?;
        require(
            self.slots.len() == usize::from(self.member_count),
            "accountability slot count",
        )?;
        for (index, slot) in self.slots.iter().enumerate() {
            let Some(slot) = slot else {
                continue;
            };
            slot.validate_semantics()?;
            require(
                usize::from(slot.validator_index) == index,
                "accountability slot position",
            )?;
        }
        if let Some(quorum) = &self.quorum {
            quorum.validate_semantics()?;
            require(
                quorum.member_count == self.member_count
                    && quorum.quorum_threshold == self.quorum_threshold,
                "quorum accountability shape",
            )?;
            let matching = self
                .slots
                .iter()
                .enumerate()
                .filter(|(index, slot)| {
                    bitmap_bit_is_set(&quorum.signer_bitmap, *index).unwrap_or(false)
                        && slot
                            .as_ref()
                            .is_some_and(|slot| slot.first_result_digest == quorum.result_digest)
                })
                .count();
            require(
                matching >= usize::from(self.quorum_threshold),
                "quorum matching slots",
            )?;
            require(
                quorum.evidence_hash
                    == self.quorum_evidence_hash(
                        quorum.result_digest,
                        quorum.quorum_height,
                        &quorum.signer_bitmap,
                        limits,
                    )?,
                "quorum evidence hash",
            )?;
        }
        if let Some(summary) = &self.closed_summary {
            summary.validate_semantics()?;
            require(
                summary.result_validator_set_epoch == self.result_validator_set_epoch
                    && summary.result_committee_set_hash == self.result_committee_set_hash
                    && summary.result_ocomp_binding_hash == self.result_ocomp_binding_hash
                    && summary.member_count == self.member_count
                    && summary.quorum_threshold == self.quorum_threshold
                    && summary.winning_result_digest
                        == self.quorum.as_ref().map(|quorum| quorum.result_digest)
                    && summary.quorum_evidence_hash
                        == self.quorum.as_ref().map(|quorum| quorum.evidence_hash),
                "accountability closed summary binding",
            )?;
        }
        Ok(())
    }
}

impl ResultVoteSlotV1 {
    pub fn validate_semantics(&self) -> Result<(), ProtocolError> {
        require(self.key_epoch == POC_KEY_EPOCH, "vote slot key epoch")?;
        if let Some(equivocation) = &self.equivocation {
            require(
                equivocation.conflicting_key_epoch == self.key_epoch
                    && equivocation.conflicting_result_digest != self.first_result_digest,
                "equivocation shape",
            )?;
        }
        Ok(())
    }
}

impl OcompQuorumV1 {
    pub fn validate_semantics(&self) -> Result<(), ProtocolError> {
        validate_n_and_quorum(self.member_count, self.quorum_threshold)?;
        validate_bitmap(&self.signer_bitmap, self.member_count)?;
        require(
            bitmap_population(&self.signer_bitmap) >= u32::from(self.quorum_threshold),
            "quorum signer bitmap",
        )
    }
}

impl OcompAccountabilitySummaryV1 {
    pub fn validate_semantics(&self) -> Result<(), ProtocolError> {
        validate_n_and_quorum(self.member_count, self.quorum_threshold)?;
        require(
            self.winning_result_digest.is_some() == self.quorum_evidence_hash.is_some(),
            "accountability winning evidence shape",
        )?;
        for bitmap in [
            &self.timely_bitmap,
            &self.matching_bitmap,
            &self.divergent_bitmap,
            &self.missing_bitmap,
            &self.equivocation_bitmap,
        ] {
            validate_bitmap(bitmap, self.member_count)?;
        }
        let mask = participant_mask(self.member_count)?;
        for (index, mask_byte) in mask.iter().copied().enumerate() {
            let timely = self.timely_bitmap[index];
            let matching = self.matching_bitmap[index];
            let divergent = self.divergent_bitmap[index];
            let missing = self.missing_bitmap[index];
            let equivocation = self.equivocation_bitmap[index];
            require(
                matching & divergent == 0
                    && matching | divergent == timely
                    && missing == mask_byte & !timely
                    && equivocation & !timely == 0,
                "accountability bitmap partition",
            )?;
        }
        Ok(())
    }
}

fn validate_vote_slot(
    slot: &ResultVoteSlotV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    slot.validate_semantics()
}

fn validate_quorum(quorum: &OcompQuorumV1, _limits: &SchemaLimits) -> Result<(), ProtocolError> {
    quorum.validate_semantics()
}

fn validate_accountability_summary(
    summary: &OcompAccountabilitySummaryV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    summary.validate_semantics()
}

fn validate_vote_accountability(
    accountability: &OcompVoteAccountabilityV1,
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    accountability.validate_semantics(limits)
}

fn validate_n_and_quorum(member_count: u16, quorum_threshold: u16) -> Result<(), ProtocolError> {
    require(member_count > 0, "OCOMP member count")?;
    require(
        quorum_threshold > 0 && quorum_threshold <= member_count,
        "OCOMP quorum threshold",
    )
}

fn bitmap_len(member_count: u16) -> Result<usize, ProtocolError> {
    usize::from(member_count)
        .checked_add(7)
        .map(|bits| bits / 8)
        .ok_or(ProtocolError::IntegerOverflow {
            what: "OCOMP bitmap length",
        })
}

fn empty_bitmap(member_count: u16) -> Result<Vec<u8>, ProtocolError> {
    Ok(vec![0; bitmap_len(member_count)?])
}

fn participant_mask(member_count: u16) -> Result<Vec<u8>, ProtocolError> {
    let mut mask = vec![u8::MAX; bitmap_len(member_count)?];
    let used_last_bits = member_count % 8;
    if used_last_bits != 0 {
        let last = mask
            .last_mut()
            .ok_or(ProtocolError::InvalidInvariant("OCOMP bitmap member count"))?;
        *last = (1_u8 << used_last_bits) - 1;
    }
    Ok(mask)
}

fn validate_bitmap(bitmap: &[u8], member_count: u16) -> Result<(), ProtocolError> {
    let mask = participant_mask(member_count)?;
    require(bitmap.len() == mask.len(), "OCOMP bitmap length")?;
    require(
        bitmap
            .iter()
            .zip(mask)
            .all(|(byte, allowed)| *byte & !allowed == 0),
        "OCOMP bitmap high bits",
    )
}

fn set_bitmap_bit(bitmap: &mut [u8], participant_index: usize) -> Result<(), ProtocolError> {
    let byte = bitmap
        .get_mut(participant_index / 8)
        .ok_or(ProtocolError::InvalidInvariant(
            "OCOMP bitmap participant index",
        ))?;
    *byte |= 1_u8 << (participant_index % 8);
    Ok(())
}

fn bitmap_bit_is_set(bitmap: &[u8], participant_index: usize) -> Result<bool, ProtocolError> {
    let byte = bitmap
        .get(participant_index / 8)
        .ok_or(ProtocolError::InvalidInvariant(
            "OCOMP bitmap participant index",
        ))?;
    Ok(*byte & (1_u8 << (participant_index % 8)) != 0)
}

fn bitmap_population(bitmap: &[u8]) -> u32 {
    bitmap.iter().map(|byte| byte.count_ones()).sum()
}
