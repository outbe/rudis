use alloy_primitives::B256;

use crate::{
    error::ProtocolError,
    hash::hash_framed,
    intent::JobIntentV1,
    receipts::{ActivationOutcome, AggregateActivationReceiptV1},
    registry::HashDomain,
    result::ExactCountsV1,
    schema::{impl_top_level_codec, require, wire_enum_u8, wire_struct, SchemaLimits},
    vote::OcompQuorumV1,
};

pub const RESULT_VOTE_MIN_FINALITY_DEPTH: u64 = 4;

wire_struct! {
    pub struct ActiveGenerationV1 {
        pub job_id: B256,
        pub program_semantics_hash: B256,
        pub nod_root: B256,
        pub bucket_root: B256,
        pub contributor_root: B256,
        pub output_manifest_root: B256,
        pub exact_counts: ExactCountsV1,
        pub result_evidence_hash: B256,
        pub availability_certificate_hash: Option<B256>,
    }
    validate = validate_active_generation;
}
impl_top_level_codec!(ActiveGenerationV1, ActiveGenerationV1);

wire_struct! {
    pub struct OcompCompletedBindingV1 {
        pub job_id: B256,
        pub activation_call_id: B256,
        pub result_digest: B256,
        pub quorum_height: u64,
        pub quorum_signer_bitmap: Vec<u8>,
        pub quorum_evidence_hash: B256,
        pub result_evidence_hash: B256,
        pub terminal_receipt_hash: B256,
        pub terminal_receipt: AggregateActivationReceiptV1,
    }
}

wire_struct! {
    pub struct OcompFinalizedJobV1 {
        pub job_id: B256,
        pub finalized_request_block_hash: B256,
        pub finalized_request_state_root: B256,
        pub finality_recorded_height: u64,
        pub open_height: u64,
        pub deadline_height: u64,
        pub quorum: Option<OcompQuorumV1>,
    }
    validate = validate_finalized_job;
}

wire_enum_u8! {
    pub enum OcompTerminalOutcome {
        Completed = 1,
        Expired = 2,
        Failed = 3,
    }
}

wire_struct! {
    pub struct LysisTerminalV1 {
        pub outcome: OcompTerminalOutcome,
        pub terminal_height: u64,
        pub terminal_time: u64,
        pub completed_binding: Option<OcompCompletedBindingV1>,
    }
    validate = validate_lysis_terminal;
}
impl_top_level_codec!(LysisTerminalV1, LysisTerminalV1);

wire_enum_u8! {
    pub enum OcompJobStatus {
        AwaitingFinality = 1,
        VotingOpen = 2,
        Completed = 4,
        Expired = 5,
        Failed = 6,
    }
}

wire_struct! {
    pub struct OcompJobRecordV1 {
        pub intent: JobIntentV1,
        pub intent_height: u64,
        pub status: OcompJobStatus,
        pub finalized: Option<OcompFinalizedJobV1>,
        pub terminal: Option<LysisTerminalV1>,
    }
    validate = validate_job_record;
}
impl_top_level_codec!(OcompJobRecordV1, OcompJobRecordV1);

impl ActiveGenerationV1 {
    pub fn active_generation_hash(&self, limits: &SchemaLimits) -> Result<B256, ProtocolError> {
        require(
            self.availability_certificate_hash.is_none(),
            "PoC availability certificate absent",
        )?;
        hash_framed(
            HashDomain::ActiveGeneration,
            &self.encode_canonical(limits)?,
        )
    }
}

impl OcompCompletedBindingV1 {
    pub fn validate_semantics(
        &self,
        quorum: &OcompQuorumV1,
        limits: &SchemaLimits,
    ) -> Result<(), ProtocolError> {
        require(
            self.terminal_receipt.outcome == ActivationOutcome::Applied,
            "completed binding receipt outcome",
        )?;
        require(
            self.job_id == self.terminal_receipt.binding.job_id
                && self.activation_call_id == self.terminal_receipt.binding.activation_call_id
                && self.result_digest == self.terminal_receipt.binding.result_digest
                && self.result_digest == quorum.result_digest
                && self.quorum_height == quorum.quorum_height
                && self.quorum_signer_bitmap == quorum.signer_bitmap
                && self.quorum_evidence_hash == quorum.evidence_hash,
            "completed binding receipt binding",
        )?;
        require(
            self.terminal_receipt_hash == self.terminal_receipt.terminal_receipt_hash(limits)?,
            "completed binding terminal receipt hash",
        )
    }
}

impl OcompFinalizedJobV1 {
    pub fn validate_semantics(&self) -> Result<(), ProtocolError> {
        let expected_open = self
            .finality_recorded_height
            .checked_add(RESULT_VOTE_MIN_FINALITY_DEPTH)
            .ok_or(ProtocolError::IntegerOverflow {
                what: "result-vote open height",
            })?;
        require(
            self.open_height == expected_open && self.open_height < self.deadline_height,
            "finalized job response window",
        )?;
        if let Some(quorum) = &self.quorum {
            quorum.validate_semantics()?;
            require(
                self.open_height <= quorum.quorum_height
                    && quorum.quorum_height < self.deadline_height,
                "quorum height inside response window",
            )?;
        }
        Ok(())
    }
}

impl LysisTerminalV1 {
    pub fn terminal_hash(&self, limits: &SchemaLimits) -> Result<B256, ProtocolError> {
        self.validate_shape()?;
        hash_framed(HashDomain::LysisTerminal, &self.encode_canonical(limits)?)
    }

    pub fn validate_shape(&self) -> Result<(), ProtocolError> {
        match (&self.outcome, &self.completed_binding) {
            (OcompTerminalOutcome::Completed, Some(_))
            | (OcompTerminalOutcome::Expired | OcompTerminalOutcome::Failed, None) => Ok(()),
            _ => Err(ProtocolError::InvalidInvariant(
                "Lysis terminal outcome shape",
            )),
        }
    }
}

impl OcompJobRecordV1 {
    pub fn validate_semantics(&self, limits: &SchemaLimits) -> Result<(), ProtocolError> {
        self.intent.validate_semantics()?;
        require(
            self.intent_height >= self.intent.logical_evaluation_height,
            "job intent inclusion height",
        )?;
        if let Some(finalized) = &self.finalized {
            finalized.validate_semantics()?;
            require(
                finalized.job_id
                    == self.intent.job_id(
                        finalized.finalized_request_block_hash,
                        finalized.finalized_request_state_root,
                        limits,
                    )?,
                "finalized job id",
            )?;
        }
        match (&self.status, &self.finalized, &self.terminal) {
            (OcompJobStatus::AwaitingFinality, None, None) => Ok(()),
            (OcompJobStatus::AwaitingFinality, Some(finalized), None) => {
                require(finalized.quorum.is_none(), "awaiting-open quorum absent")
            }
            (OcompJobStatus::VotingOpen, Some(finalized), None) => {
                require(finalized.quorum.is_none(), "voting-open quorum absent")
            }
            (OcompJobStatus::Completed, Some(finalized), Some(terminal)) => {
                require(
                    terminal.outcome == OcompTerminalOutcome::Completed,
                    "completed terminal shape",
                )?;
                let binding = terminal
                    .completed_binding
                    .as_ref()
                    .ok_or(ProtocolError::InvalidInvariant("completed binding present"))?;
                let quorum = finalized
                    .quorum
                    .as_ref()
                    .ok_or(ProtocolError::InvalidInvariant("completed quorum present"))?;
                binding.validate_semantics(quorum, limits)?;
                require(
                    binding.terminal_receipt.outcome == ActivationOutcome::Applied,
                    "completed applied receipt",
                )
            }
            (OcompJobStatus::Expired, finalized, Some(terminal)) => require(
                finalized
                    .as_ref()
                    .is_none_or(|finalized| finalized.quorum.is_none())
                    && terminal.outcome == OcompTerminalOutcome::Expired
                    && terminal.completed_binding.is_none(),
                "expired terminal shape",
            ),
            (OcompJobStatus::Failed, finalized, Some(terminal)) => require(
                finalized
                    .as_ref()
                    .is_none_or(|finalized| finalized.quorum.is_none())
                    && terminal.outcome == OcompTerminalOutcome::Failed
                    && terminal.completed_binding.is_none(),
                "failed terminal shape",
            ),
            _ => Err(ProtocolError::InvalidInvariant("job status terminal shape")),
        }
    }

    pub fn job_record_hash(&self, limits: &SchemaLimits) -> Result<B256, ProtocolError> {
        self.validate_semantics(limits)?;
        hash_framed(HashDomain::JobRecord, &self.encode_canonical(limits)?)
    }
}

fn validate_active_generation(
    generation: &ActiveGenerationV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        generation.availability_certificate_hash.is_none(),
        "PoC availability certificate absent",
    )
}

fn validate_job_record(
    record: &OcompJobRecordV1,
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    record.validate_semantics(limits)
}

fn validate_finalized_job(
    finalized: &OcompFinalizedJobV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    finalized.validate_semantics()
}

fn validate_lysis_terminal(
    terminal: &LysisTerminalV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    terminal.validate_shape()
}
