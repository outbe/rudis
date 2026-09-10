use std::collections::BTreeSet;

use alloy_primitives::B256;

use crate::{
    common::BoundedBytes,
    error::ProtocolError,
    input::CheckpointIdentityV1,
    intent::JobIntentV1,
    opening::{LysisOpeningsProofV1, OpeningSubjectsV1},
    schema::{require, wire_enum_u8, wire_struct, NestedCodec, SchemaLimits},
    CanonicalReader, CanonicalWriter,
};

pub const MAX_FINALIZED_JOBS_PER_RESPONSE: u16 = 64;
pub const MAX_SNAPSHOT_HANDOFFS_PER_RESPONSE: u16 = 64;
pub const SNAPSHOT_LEASE_WIRE_BYTES: usize = 120;

wire_enum_u8! {
    pub enum UnitFinishedStatus {
        Success = 1,
        Failed = 2,
    }
}

wire_struct! {
    pub struct CasObjectRefV1 {
        pub transport_digest: B256,
        pub encoded_bytes: u64,
        pub expected_ocb1_kind: Option<u16>,
    }
}

wire_struct! {
    pub struct ListFinalizedJobsV1 {
        pub after_cursor: u64,
        pub limit: u16,
    }
    validate = validate_list_finalized_jobs;
}

wire_struct! {
    pub struct FinalizedJobSummaryV1 {
        pub cursor: u64,
        pub job_id: B256,
        pub intent_id: B256,
        pub finalized_block_hash: B256,
        pub finalized_state_root: B256,
        pub protocol_bundle_hash: B256,
        pub open_height: u64,
        pub deadline_height: u64,
    }
    validate = validate_finalized_job_summary;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListFinalizedJobsResponseV1 {
    pub next_cursor: u64,
    pub jobs: Vec<FinalizedJobSummaryV1>,
}

impl NestedCodec for ListFinalizedJobsResponseV1 {
    fn validate(&self, limits: &SchemaLimits) -> Result<(), ProtocolError> {
        require(
            self.jobs.len() <= usize::from(MAX_FINALIZED_JOBS_PER_RESPONSE),
            "finalized job response cap",
        )?;
        for job in &self.jobs {
            job.validate(limits)?;
        }
        require(
            self.jobs
                .windows(2)
                .all(|pair| pair[0].cursor < pair[1].cursor),
            "finalized job response order",
        )?;
        if let Some(job) = self.jobs.last() {
            require(
                self.next_cursor == job.cursor,
                "finalized job response cursor",
            )?;
        }
        Ok(())
    }

    fn encode_nested(
        &self,
        output: &mut CanonicalWriter,
        limits: &SchemaLimits,
    ) -> Result<(), ProtocolError> {
        self.validate(limits)?;
        output.write_u64(self.next_cursor)?;
        output.write_vec(
            &self.jobs,
            usize::from(MAX_FINALIZED_JOBS_PER_RESPONSE),
            |writer, job| job.encode_nested(writer, limits),
        )
    }

    fn decode_nested(
        input: &mut CanonicalReader<'_>,
        limits: &SchemaLimits,
    ) -> Result<Self, ProtocolError> {
        let next_cursor = input.read_u64()?;
        let jobs = input.read_vec(usize::from(MAX_FINALIZED_JOBS_PER_RESPONSE), 0, |reader| {
            FinalizedJobSummaryV1::decode_nested(reader, limits)
        })?;
        Ok(Self { next_cursor, jobs })
    }
}

wire_struct! {
    pub struct GetJobSpecV1 {
        pub job_id: B256,
    }
    validate = validate_get_job_spec;
}

wire_struct! {
    pub struct FinalizedJobSpecV1 {
        pub summary: FinalizedJobSummaryV1,
        pub canonical_job_intent: BoundedBytes,
    }
    validate = validate_finalized_job_spec;
}

wire_struct! {
    pub struct OpenSnapshotLeaseV1 {
        pub job_id: B256,
    }
    validate = validate_job_id_request;
}

wire_struct! {
    pub struct ListSnapshotHandoffsV1 {
        pub after_lease_generation: u64,
        pub limit: u16,
    }
    validate = validate_list_snapshot_handoffs;
}

wire_struct! {
    pub struct SnapshotHandoffV1 {
        pub job_id: B256,
        pub input_lease_id: B256,
        pub pin_generation: u64,
        pub lease_generation: u64,
        pub checkpoint: CheckpointIdentityV1,
        pub canonical_lease_offer: BoundedBytes,
    }
    validate = validate_snapshot_handoff;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListSnapshotHandoffsResponseV1 {
    pub next_lease_generation: u64,
    pub handoffs: Vec<SnapshotHandoffV1>,
}

impl NestedCodec for ListSnapshotHandoffsResponseV1 {
    fn validate(&self, limits: &SchemaLimits) -> Result<(), ProtocolError> {
        require(
            self.handoffs.len() <= usize::from(MAX_SNAPSHOT_HANDOFFS_PER_RESPONSE),
            "snapshot handoff response cap",
        )?;
        for handoff in &self.handoffs {
            handoff.validate(limits)?;
        }
        require(
            self.handoffs.windows(2).all(|pair| {
                pair[0].lease_generation < pair[1].lease_generation
                    && pair[0].job_id != pair[1].job_id
            }),
            "snapshot handoff response order",
        )?;
        if let Some(handoff) = self.handoffs.last() {
            require(
                self.next_lease_generation == handoff.lease_generation,
                "snapshot handoff response cursor",
            )?;
        }
        Ok(())
    }

    fn encode_nested(
        &self,
        output: &mut CanonicalWriter,
        limits: &SchemaLimits,
    ) -> Result<(), ProtocolError> {
        self.validate(limits)?;
        output.write_u64(self.next_lease_generation)?;
        output.write_vec(
            &self.handoffs,
            usize::from(MAX_SNAPSHOT_HANDOFFS_PER_RESPONSE),
            |writer, handoff| handoff.encode_nested(writer, limits),
        )
    }

    fn decode_nested(
        input: &mut CanonicalReader<'_>,
        limits: &SchemaLimits,
    ) -> Result<Self, ProtocolError> {
        let next_lease_generation = input.read_u64()?;
        let handoffs = input.read_vec(
            usize::from(MAX_SNAPSHOT_HANDOFFS_PER_RESPONSE),
            0,
            |reader| SnapshotHandoffV1::decode_nested(reader, limits),
        )?;
        Ok(Self {
            next_lease_generation,
            handoffs,
        })
    }
}

wire_struct! {
    pub struct GetSnapshotHandoffV1 {
        pub job_id: B256,
        pub lease_generation: u64,
    }
    validate = validate_get_snapshot_handoff;
}

wire_struct! {
    pub struct RenewSnapshotLeaseV1 {
        pub job_id: B256,
        pub lease_generation: u64,
        pub canonical_open_ack: BoundedBytes,
    }
    validate = validate_renew_snapshot_lease;
}

wire_struct! {
    pub struct SnapshotLeaseOpenedV1 {
        pub job_id: B256,
        pub lease_generation: u64,
    }
    validate = validate_snapshot_lease_opened;
}

wire_struct! {
    pub struct BuildFinalizedIntentProofV1 {
        pub job_id: B256,
    }
    validate = validate_job_id_request;
}

wire_struct! {
    pub struct FinalizedIntentProofResponseV1 {
        pub job_id: B256,
        pub canonical_proof: BoundedBytes,
    }
    validate = validate_finalized_intent_proof_response;
}

wire_struct! {
    pub struct BuildLysisOpeningsV1 {
        pub job_id: B256,
        pub subjects: OpeningSubjectsV1,
    }
    validate = validate_build_lysis_openings;
}

wire_struct! {
    pub struct ProjectionCheckpointV1 {
        pub block_number: u64,
        pub block_hash: B256,
    }
    validate = validate_projection_checkpoint;
}

wire_struct! {
    pub struct CheckProjectionContainmentV1 {
        pub job_id: B256,
        pub lease_generation: u64,
        pub projection_checkpoint: ProjectionCheckpointV1,
    }
    validate = validate_check_projection_containment;
}

wire_struct! {
    pub struct ProjectionContainedV1 {
        pub job_id: B256,
        pub lease_generation: u64,
        pub projection_checkpoint: ProjectionCheckpointV1,
        pub required_checkpoint: ProjectionCheckpointV1,
    }
    validate = validate_projection_contained;
}

wire_struct! {
    pub struct CommitSnapshotExportV1 {
        pub job_id: B256,
        pub pin_generation: u64,
        pub lease_generation: u64,
        pub manifest_hash: B256,
    }
    validate = validate_commit_snapshot_export;
}

wire_struct! {
    pub struct SnapshotExportCommittedV1 {
        pub job_id: B256,
        pub pin_generation: u64,
        pub record_hash: B256,
    }
    validate = validate_snapshot_export_committed;
}

wire_struct! {
    /// Deterministic EIP-1559 transaction produced by the local OCOMP signer.
    pub struct PreparedVoteTransactionV1 {
        pub canonical_vote: BoundedBytes,
        pub raw_transaction: BoundedBytes,
        pub transaction_hash: B256,
    }
    validate = validate_prepared_vote_transaction;
}

wire_struct! {
    pub struct RunUnitV1 {
        pub protocol_bundle_hash: B256,
        pub job_id: B256,
        pub attempt: u32,
        pub plan_hash: B256,
        pub unit_index: u32,
        pub canonical_unit_spec: BoundedBytes,
        pub unit_membership_siblings: Vec<B256>,
        pub plan_ref: CasObjectRefV1,
        pub input_manifest_ref: CasObjectRefV1,
        pub ordered_input_refs: Vec<CasObjectRefV1>,
    }
    validate = validate_run_unit;
}

wire_struct! {
    pub struct UnitFinishedV1 {
        pub unit_id: B256,
        pub status: UnitFinishedStatus,
        pub exact_staged_bytes: u64,
        pub transport_digest: B256,
    }
}

macro_rules! impl_control_body_codec {
    ($type:ty) => {
        impl $type {
            pub fn encode_body(&self, limits: &SchemaLimits) -> Result<Vec<u8>, ProtocolError> {
                self.validate(limits)?;
                let mut output = CanonicalWriter::new(limits.codec);
                self.encode_nested(&mut output, limits)?;
                Ok(output.into_bytes())
            }

            pub fn decode_body(
                encoded: &[u8],
                limits: &SchemaLimits,
            ) -> Result<Self, ProtocolError> {
                let mut input = CanonicalReader::new(encoded, limits.codec)?;
                let value = Self::decode_nested(&mut input, limits)?;
                input.finish()?;
                value.validate(limits)?;
                Ok(value)
            }
        }
    };
}

impl_control_body_codec!(UnitFinishedV1);
impl_control_body_codec!(ListFinalizedJobsV1);
impl_control_body_codec!(ListFinalizedJobsResponseV1);
impl_control_body_codec!(GetJobSpecV1);
impl_control_body_codec!(FinalizedJobSpecV1);
impl_control_body_codec!(OpenSnapshotLeaseV1);
impl_control_body_codec!(ListSnapshotHandoffsV1);
impl_control_body_codec!(SnapshotHandoffV1);
impl_control_body_codec!(ListSnapshotHandoffsResponseV1);
impl_control_body_codec!(GetSnapshotHandoffV1);
impl_control_body_codec!(RenewSnapshotLeaseV1);
impl_control_body_codec!(SnapshotLeaseOpenedV1);
impl_control_body_codec!(BuildFinalizedIntentProofV1);
impl_control_body_codec!(FinalizedIntentProofResponseV1);
impl_control_body_codec!(BuildLysisOpeningsV1);
impl_control_body_codec!(LysisOpeningsProofV1);
impl_control_body_codec!(CheckProjectionContainmentV1);
impl_control_body_codec!(ProjectionContainedV1);
impl_control_body_codec!(CommitSnapshotExportV1);
impl_control_body_codec!(SnapshotExportCommittedV1);
impl_control_body_codec!(PreparedVoteTransactionV1);

impl RunUnitV1 {
    pub fn validate_semantics(&self, limits: &SchemaLimits) -> Result<(), ProtocolError> {
        require(
            self.ordered_input_refs.len() <= limits.max_unit_inputs,
            "worker input reference cap",
        )?;
        require(
            self.unit_membership_siblings.len() <= u32::BITS as usize
                && self
                    .unit_membership_siblings
                    .iter()
                    .all(|sibling| !sibling.is_zero()),
            "worker unit membership proof",
        )?;
        let mut digests = BTreeSet::new();
        require(
            digests.insert(self.plan_ref.transport_digest)
                && digests.insert(self.input_manifest_ref.transport_digest),
            "worker authority references distinct",
        )?;
        for reference in &self.ordered_input_refs {
            require(
                digests.insert(reference.transport_digest),
                "worker input references distinct",
            )?;
        }
        Ok(())
    }

    pub fn encode_body(&self, limits: &SchemaLimits) -> Result<Vec<u8>, ProtocolError> {
        self.validate_semantics(limits)?;
        let mut output = CanonicalWriter::new(limits.codec);
        self.encode_nested(&mut output, limits)?;
        Ok(output.into_bytes())
    }

    pub fn decode_body(encoded: &[u8], limits: &SchemaLimits) -> Result<Self, ProtocolError> {
        let mut input = CanonicalReader::new(encoded, limits.codec)?;
        let value = Self::decode_nested(&mut input, limits)?;
        input.finish()?;
        value.validate_semantics(limits)?;
        Ok(value)
    }
}

fn validate_run_unit(request: &RunUnitV1, limits: &SchemaLimits) -> Result<(), ProtocolError> {
    request.validate_semantics(limits)
}

fn validate_list_finalized_jobs(
    request: &ListFinalizedJobsV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        request.limit == MAX_FINALIZED_JOBS_PER_RESPONSE,
        "finalized job request limit",
    )
}

fn validate_finalized_job_summary(
    summary: &FinalizedJobSummaryV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(summary.cursor != 0, "finalized job cursor")?;
    require(!summary.job_id.is_zero(), "finalized job id")?;
    require(!summary.intent_id.is_zero(), "finalized intent id")?;
    require(
        !summary.finalized_block_hash.is_zero(),
        "finalized job block hash",
    )?;
    require(
        !summary.finalized_state_root.is_zero(),
        "finalized job state root",
    )?;
    require(
        !summary.protocol_bundle_hash.is_zero(),
        "finalized job protocol bundle",
    )?;
    require(
        summary.open_height < summary.deadline_height,
        "finalized job voting window",
    )
}

fn validate_get_job_spec(
    request: &GetJobSpecV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(!request.job_id.is_zero(), "get job spec id")
}

fn validate_finalized_job_spec(
    spec: &FinalizedJobSpecV1,
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    let intent = JobIntentV1::decode_canonical(&spec.canonical_job_intent.0, limits)?;
    let intent_id = intent.intent_id(limits)?;
    let job_id = intent.job_id(
        spec.summary.finalized_block_hash,
        spec.summary.finalized_state_root,
        limits,
    )?;
    require(intent_id == spec.summary.intent_id, "job spec IntentId")?;
    require(job_id == spec.summary.job_id, "job spec JobId")?;
    require(
        intent.protocol_bundle_hash == spec.summary.protocol_bundle_hash,
        "job spec protocol bundle",
    )
}

fn validate_job_id_request<T>(request: &T, _limits: &SchemaLimits) -> Result<(), ProtocolError>
where
    T: JobIdRequest,
{
    require(!request.job_id().is_zero(), "snapshot job id")
}

trait JobIdRequest {
    fn job_id(&self) -> B256;
}

impl JobIdRequest for OpenSnapshotLeaseV1 {
    fn job_id(&self) -> B256 {
        self.job_id
    }
}

impl JobIdRequest for BuildFinalizedIntentProofV1 {
    fn job_id(&self) -> B256 {
        self.job_id
    }
}

fn validate_list_snapshot_handoffs(
    request: &ListSnapshotHandoffsV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        request.limit == MAX_SNAPSHOT_HANDOFFS_PER_RESPONSE,
        "snapshot handoff request limit",
    )
}

fn validate_snapshot_handoff(
    handoff: &SnapshotHandoffV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        !handoff.job_id.is_zero() && !handoff.input_lease_id.is_zero(),
        "snapshot handoff job/input lease id",
    )?;
    require(
        handoff.pin_generation != 0 && handoff.lease_generation != 0,
        "snapshot handoff generations",
    )?;
    require(
        handoff.canonical_lease_offer.0.len() == SNAPSHOT_LEASE_WIRE_BYTES,
        "snapshot lease offer bytes",
    )?;
    require(
        handoff.checkpoint.finalized_block_number != 0
            && !handoff.checkpoint.finalized_block_hash.is_zero()
            && !handoff.checkpoint.finalized_state_root.is_zero()
            && !handoff.checkpoint.finalized_ce_root.is_zero()
            && handoff.checkpoint.ce_schema_version != 0,
        "snapshot checkpoint identity",
    )
}

fn validate_get_snapshot_handoff(
    request: &GetSnapshotHandoffV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        !request.job_id.is_zero() && request.lease_generation != 0,
        "get snapshot handoff identity",
    )
}

fn validate_renew_snapshot_lease(
    request: &RenewSnapshotLeaseV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        !request.job_id.is_zero() && request.lease_generation != 0,
        "renew snapshot lease identity",
    )?;
    require(
        request.canonical_open_ack.0.len() == SNAPSHOT_LEASE_WIRE_BYTES,
        "snapshot lease acknowledgement bytes",
    )
}

fn validate_snapshot_lease_opened(
    opened: &SnapshotLeaseOpenedV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        !opened.job_id.is_zero() && opened.lease_generation != 0,
        "opened snapshot lease identity",
    )
}

fn validate_finalized_intent_proof_response(
    response: &FinalizedIntentProofResponseV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        !response.job_id.is_zero() && !response.canonical_proof.0.is_empty(),
        "finalized intent proof response",
    )
}

fn validate_build_lysis_openings(
    request: &BuildLysisOpeningsV1,
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(!request.job_id.is_zero(), "Lysis openings job id")?;
    request.subjects.validate(limits)
}

fn validate_projection_checkpoint(
    checkpoint: &ProjectionCheckpointV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        checkpoint.block_number != 0 && !checkpoint.block_hash.is_zero(),
        "projection checkpoint identity",
    )
}

fn validate_check_projection_containment(
    request: &CheckProjectionContainmentV1,
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        !request.job_id.is_zero() && request.lease_generation != 0,
        "projection containment lease identity",
    )?;
    request.projection_checkpoint.validate(limits)
}

fn validate_projection_contained(
    response: &ProjectionContainedV1,
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        !response.job_id.is_zero() && response.lease_generation != 0,
        "contained projection lease identity",
    )?;
    response.projection_checkpoint.validate(limits)?;
    response.required_checkpoint.validate(limits)?;
    require(
        response.projection_checkpoint.block_number >= response.required_checkpoint.block_number,
        "projection contains required checkpoint",
    )
}

fn validate_commit_snapshot_export(
    request: &CommitSnapshotExportV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        !request.job_id.is_zero()
            && request.pin_generation != 0
            && request.lease_generation != 0
            && !request.manifest_hash.is_zero(),
        "snapshot export commit identity",
    )
}

fn validate_snapshot_export_committed(
    response: &SnapshotExportCommittedV1,
    _limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    require(
        !response.job_id.is_zero()
            && response.pin_generation != 0
            && !response.record_hash.is_zero(),
        "snapshot export committed identity",
    )
}

fn validate_prepared_vote_transaction(
    response: &PreparedVoteTransactionV1,
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    response.canonical_vote.validate(limits)?;
    response.raw_transaction.validate(limits)?;
    require(
        !response.canonical_vote.0.is_empty()
            && response.canonical_vote.0.len() <= limits.max_control_body_bytes
            && !response.raw_transaction.0.is_empty()
            && response.raw_transaction.0.len() <= limits.max_control_body_bytes
            && !response.transaction_hash.is_zero(),
        "prepared vote transaction response",
    )
}
