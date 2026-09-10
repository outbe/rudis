//! Incremental cold-restart audit for one plan-bound Lysis V1 artifact set.
//!
//! Every cursor step processes at most one bounded catalog entry, input chunk,
//! unit artifact or directory entry. This layer does not bind finalized job
//! authority and does not validate phase payload semantics, so neither an
//! individual item nor `Complete` is a signing/finalization capability.

use std::collections::BTreeSet;

use alloy_primitives::{Address, B256, U256};
use outbe_compressed_entities::{decode_tribute_v1, derive_poseidon_entity_id};
use outbe_lysis::program_v1::planner::{
    LysisPlanTopologyV1, LysisPlannerBindingsV1, LysisPlannerV1, PlannedProducerV1,
    PlannedUnitPositionV1, PlannerErrorV1,
};
use outbe_ocomp_protocol::{
    common::BoundedBytes,
    control::RunUnitV1,
    input::{
        AuthenticatedOpeningV1, InputChunkKind, InputChunkRefV1, InputManifestV1, OpeningSourceKind,
    },
    list::try_streaming_ordered_list_membership_proof,
    unit::{PlanCommitmentV1, UnitArtifactV1, UnitPhase, UnitSpecV1},
    CasObjectRefV1, ListKind, ObjectKind, ProtocolError, SchemaLimits, StreamingOrderedListRoot,
};
use outbe_primitives::time::WorldwideDay;
use thiserror::Error;

use crate::{
    admission_catalog::{
        AdmissionCatalogError, AdmissionDirectoryCursorV1, AdmissionDirectoryStepV1,
        VerifiedAdmissionCatalog, VerifiedAdmissionRecordV1,
    },
    bundle::PinnedProtocolBundle,
    cas::{CasError, FilesystemCasReader},
    input_artifacts::{decode_fidelity_subject_key, decode_oracle_subject_key, InputArtifactError},
    input_ref_catalog::{
        InputRefCatalogClosureCursorV1, InputRefCatalogClosureStepV1, InputRefCatalogError,
        VerifiedInputChunkRefCatalog, VerifiedInputChunkRefV1,
    },
};

const MAX_SETTLEMENT_ISOS: usize = 256;

pub struct LocalLysisPlanAuditV1<'a> {
    admissions: &'a VerifiedAdmissionCatalog,
    input_refs: &'a VerifiedInputChunkRefCatalog,
    reader: &'a FilesystemCasReader,
    bundle: &'a PinnedProtocolBundle,
    limits: &'a SchemaLimits,
    plan_ref: CasObjectRefV1,
    manifest_ref: CasObjectRefV1,
    manifest: InputManifestV1,
    plan: PlanCommitmentV1,
    planner: LysisPlannerV1,
    topology: LysisPlanTopologyV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanBoundLysisArtifactV1 {
    plan_ordinal: u32,
    position: PlannedUnitPositionV1,
    spec: UnitSpecV1,
    artifact: UnitArtifactV1,
    admission: VerifiedAdmissionRecordV1,
}

impl PlanBoundLysisArtifactV1 {
    #[must_use]
    pub const fn plan_ordinal(&self) -> u32 {
        self.plan_ordinal
    }

    #[must_use]
    pub const fn position(&self) -> PlannedUnitPositionV1 {
        self.position
    }

    #[must_use]
    pub const fn spec(&self) -> &UnitSpecV1 {
        &self.spec
    }

    #[must_use]
    pub const fn artifact(&self) -> &UnitArtifactV1 {
        &self.artifact
    }

    #[must_use]
    pub const fn admission(&self) -> &VerifiedAdmissionRecordV1 {
        &self.admission
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LysisPlanAuditStepV1 {
    InputChecked { ordinal: u32, kind: InputChunkKind },
    FidelityOwnerMembershipProbe { owner: Address },
    FidelityOwnerMembershipChecked { owner: Address },
    InputReferenceListClosed,
    InputCatalogEntryChecked,
    InputsClosed,
    Artifact(Box<PlanBoundLysisArtifactV1>),
    ArtifactsClosed,
    AdmissionCatalogEntryChecked,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LysisPlanAuditStageV1 {
    InputCatalog,
    Artifacts,
    AdmissionCatalog,
    Complete,
}

struct OwnerTributeSearchV1 {
    owner: Address,
    tribute_id: Vec<u8>,
    low: u32,
    high: u32,
}

pub struct LysisPlanAuditCursorV1<'a> {
    audit: &'a LocalLysisPlanAuditV1<'a>,
    stage: LysisPlanAuditStageV1,
    input_catalog: Option<InputRefCatalogClosureCursorV1<'a>>,
    admission_catalog: Option<AdmissionDirectoryCursorV1<'a>>,
    primary_root: Option<StreamingOrderedListRoot>,
    pending_tribute_ref: Option<InputChunkRefV1>,
    primary_spec_count: u32,
    fidelity_opening_count: u32,
    oracle_opening_count: u32,
    fidelity_root: Option<StreamingOrderedListRoot>,
    oracle_root: Option<StreamingOrderedListRoot>,
    tribute_count: u32,
    tribute_nominal_total: U256,
    tribute_isos: BTreeSet<u16>,
    previous_tribute_last_key: Option<Vec<u8>>,
    previous_fidelity_owner: Option<Address>,
    pending_fidelity_owners: Vec<Address>,
    next_fidelity_owner: usize,
    owner_tribute_search: Option<OwnerTributeSearchV1>,
    fidelity_owner_count: u32,
    oracle_subject_isos: Option<Vec<u16>>,
    next_artifact_ordinal: u32,
    failed: bool,
}

impl<'a> LocalLysisPlanAuditV1<'a> {
    pub fn open(
        admissions: &'a VerifiedAdmissionCatalog,
        input_refs: &'a VerifiedInputChunkRefCatalog,
        reader: &'a FilesystemCasReader,
        bundle: &'a PinnedProtocolBundle,
        limits: &'a SchemaLimits,
    ) -> Result<Self, ExactLysisPlanError> {
        let pinned = admissions.reload_pinned_plan(reader)?;
        input_refs
            .require_manifest_authority(&pinned.input_manifest_ref, &pinned.input_manifest)?;
        if bundle.hash() != pinned.plan.protocol_bundle_hash
            || pinned.input_manifest.protocol_bundle_hash != bundle.hash()
        {
            return Err(ExactLysisPlanError::AuthorityMismatch(
                "protocol bundle hash",
            ));
        }
        pinned
            .input_manifest
            .validate_against_bundle(bundle.bundle(), limits)?;
        if pinned.plan.planner_spec_version != bundle.bundle().planner_spec_version
            || pinned.plan.reducer_spec_version != bundle.bundle().reducer_spec_version
        {
            return Err(ExactLysisPlanError::AuthorityMismatch(
                "planner and reducer versions",
            ));
        }

        let planner = LysisPlannerV1::new(LysisPlannerBindingsV1 {
            protocol_bundle_hash: pinned.plan.protocol_bundle_hash,
            job_id: pinned.plan.job_id,
            attempt: pinned.plan.attempt,
            input_manifest_hash: pinned.plan.input_manifest_hash,
            input_manifest_encoded_bytes: pinned.input_manifest_ref.encoded_bytes,
            fidelity_opening_root: pinned.input_manifest.fidelity_opening_root,
            oracle_opening_root: pinned.input_manifest.oracle_opening_root,
            wwd: pinned.plan.wwd,
            lysis_budget: pinned.plan.lysis_budget,
            logical_evaluation_time: pinned.plan.logical_evaluation_time,
            tribute_count: pinned.plan.tribute_count,
            lysis_program_semantics_hash: bundle.bundle().lysis_program_semantics_hash,
            planner_spec_version: bundle.bundle().planner_spec_version,
            reducer_spec_version: bundle.bundle().reducer_spec_version,
        })?;
        let topology = LysisPlanTopologyV1::new(pinned.plan.primary_work_unit_count)?;

        Ok(Self {
            admissions,
            input_refs,
            reader,
            bundle,
            limits,
            plan_ref: pinned.plan_ref,
            manifest_ref: pinned.input_manifest_ref,
            manifest: pinned.input_manifest,
            plan: pinned.plan,
            planner,
            topology,
        })
    }

    /// Produces a scheduler candidate. It is not a finalization input.
    pub fn candidate_spec_at(&self, plan_ordinal: u32) -> Result<UnitSpecV1, ExactLysisPlanError> {
        self.derive_spec_at(plan_ordinal)
    }

    /// Prepares the exact bounded worker request for one ready plan member.
    ///
    /// Producer references come only from durable verified admissions. Input
    /// references come only from the closed manifest-bound input catalog.
    /// Enumerate membership is generated with a bounded streaming frontier.
    pub fn worker_request_at(&self, plan_ordinal: u32) -> Result<RunUnitV1, ExactLysisPlanError> {
        let position = self.topology.plan_position_at(plan_ordinal)?;
        let spec = self.derive_spec_at(plan_ordinal)?;
        let mut ordered_input_refs = Vec::new();
        for producer in self.topology.required_producers(position)? {
            if let PlannedProducerV1::Unit(producer) = producer {
                let producer_ordinal = self.topology.plan_ordinal_of(producer)?;
                if producer_ordinal >= plan_ordinal {
                    return Err(ExactLysisPlanError::AuthorityMismatch(
                        "worker producer topological order",
                    ));
                }
                ordered_input_refs
                    .push(self.plan_bound_admission_at(producer_ordinal)?.artifact_ref);
            }
        }

        let primary_ordinal = match position {
            PlannedUnitPositionV1::Primary { ordinal, .. } => Some(ordinal),
            _ => None,
        };
        match spec.phase {
            UnitPhase::Enumerate => {
                self.push_primary_input_ref(
                    primary_ordinal.ok_or(ExactLysisPlanError::AuthorityMismatch(
                        "Enumerate primary position",
                    ))?,
                    &mut ordered_input_refs,
                )?;
            }
            UnitPhase::FidelityMap => {
                self.push_primary_input_authority_refs(
                    primary_ordinal.ok_or(ExactLysisPlanError::AuthorityMismatch(
                        "FidelityMap primary position",
                    ))?,
                    &mut ordered_input_refs,
                )?;
                self.push_input_kind_refs(InputChunkKind::Fidelity, &mut ordered_input_refs)?;
            }
            UnitPhase::AmountMap => {
                self.push_primary_input_authority_refs(
                    primary_ordinal.ok_or(ExactLysisPlanError::AuthorityMismatch(
                        "AmountMap primary position",
                    ))?,
                    &mut ordered_input_refs,
                )?;
                self.push_input_kind_refs(InputChunkKind::Oracle, &mut ordered_input_refs)?;
            }
            UnitPhase::FixedReduce
            | UnitPhase::GratisPrefix
            | UnitPhase::GratisPrefixDown
            | UnitPhase::OutputFinalize
            | UnitPhase::OwnerShuffle
            | UnitPhase::BucketShuffle
            | UnitPhase::RootReduce => {}
        }

        let canonical_spec = spec.encode_canonical(self.limits)?;
        let unit_membership_siblings = if spec.phase == UnitPhase::Enumerate {
            try_streaming_ordered_list_membership_proof(
                ListKind::UnitSpecificationsArtifacts,
                self.plan.primary_work_unit_count,
                plan_ordinal,
                (0..self.plan.primary_work_unit_count).map(|ordinal| {
                    self.primary_spec_from_catalog(ordinal)?
                        .encode_canonical(self.limits)
                        .map_err(ExactLysisPlanError::from)
                }),
                self.limits.codec.max_body_bytes,
            )?
        } else {
            Vec::new()
        };
        Ok(RunUnitV1 {
            protocol_bundle_hash: self.plan.protocol_bundle_hash,
            job_id: self.plan.job_id,
            attempt: self.plan.attempt,
            plan_hash: self.plan.plan_hash(self.limits)?,
            unit_index: plan_ordinal,
            canonical_unit_spec: BoundedBytes(canonical_spec),
            unit_membership_siblings,
            plan_ref: self.plan_ref.clone(),
            input_manifest_ref: self.manifest_ref.clone(),
            ordered_input_refs,
        })
    }

    pub fn audit_cursor(&'a self) -> Result<LysisPlanAuditCursorV1<'a>, ExactLysisPlanError> {
        let fidelity_opening_count = self
            .manifest
            .exact_record_count
            .checked_sub(self.manifest.tribute_count)
            .and_then(|count| count.checked_sub(1))
            .ok_or(ExactLysisPlanError::AuthorityMismatch(
                "manifest opening record counts",
            ))?;
        if fidelity_opening_count == 0 {
            return Err(ExactLysisPlanError::AuthorityMismatch(
                "manifest Fidelity opening count",
            ));
        }
        Ok(LysisPlanAuditCursorV1 {
            audit: self,
            stage: LysisPlanAuditStageV1::InputCatalog,
            input_catalog: Some(self.input_refs.bounded_closure_cursor()?),
            admission_catalog: None,
            primary_root: Some(StreamingOrderedListRoot::new(
                ListKind::UnitSpecificationsArtifacts,
                self.plan.primary_work_unit_count,
            )?),
            pending_tribute_ref: None,
            primary_spec_count: 0,
            fidelity_opening_count: 0,
            oracle_opening_count: 0,
            fidelity_root: Some(StreamingOrderedListRoot::new(
                ListKind::FidelityOpenings,
                fidelity_opening_count,
            )?),
            oracle_root: Some(StreamingOrderedListRoot::new(ListKind::OracleOpenings, 1)?),
            tribute_count: 0,
            tribute_nominal_total: U256::ZERO,
            tribute_isos: BTreeSet::from([840]),
            previous_tribute_last_key: None,
            previous_fidelity_owner: None,
            pending_fidelity_owners: Vec::new(),
            next_fidelity_owner: 0,
            owner_tribute_search: None,
            fidelity_owner_count: 0,
            oracle_subject_isos: None,
            next_artifact_ordinal: 0,
            failed: false,
        })
    }

    #[must_use]
    pub const fn plan(&self) -> &PlanCommitmentV1 {
        &self.plan
    }

    #[must_use]
    pub const fn manifest(&self) -> &InputManifestV1 {
        &self.manifest
    }

    #[must_use]
    pub(crate) const fn bundle(&self) -> &PinnedProtocolBundle {
        self.bundle
    }

    pub(crate) fn verified_artifact_at(
        &self,
        plan_ordinal: u32,
    ) -> Result<PlanBoundLysisArtifactV1, ExactLysisPlanError> {
        let admission = self.plan_bound_admission_at(plan_ordinal)?;
        let position = self.topology.plan_position_at(plan_ordinal)?;
        let spec = self.derive_spec_at(plan_ordinal)?;
        if admission.unit_id != spec.unit_id(self.limits)? {
            return Err(ExactLysisPlanError::UnexpectedUnitId { plan_ordinal });
        }
        let object = self.reader.read_verified(&admission.artifact_ref)?;
        let artifact = UnitArtifactV1::decode_canonical(object.bytes(), self.limits)?;
        artifact.validate_against(&spec, self.limits)?;
        Ok(PlanBoundLysisArtifactV1 {
            plan_ordinal,
            position,
            spec,
            artifact,
            admission,
        })
    }

    pub(crate) fn plan_bound_admission_at(
        &self,
        plan_ordinal: u32,
    ) -> Result<VerifiedAdmissionRecordV1, ExactLysisPlanError> {
        let admission = self.admissions.read(plan_ordinal)?;
        self.require_admission_authority(&admission)?;
        Ok(admission)
    }

    pub(crate) const fn reader(&self) -> &FilesystemCasReader {
        self.reader
    }

    pub(crate) const fn admissions(&self) -> &VerifiedAdmissionCatalog {
        self.admissions
    }

    pub(crate) const fn limits(&self) -> &SchemaLimits {
        self.limits
    }

    pub(crate) fn bounded_admission_directory_cursor(
        &self,
    ) -> Result<AdmissionDirectoryCursorV1<'_>, ExactLysisPlanError> {
        self.admissions
            .bounded_directory_cursor()
            .map_err(Into::into)
    }

    fn derive_spec_at(&self, plan_ordinal: u32) -> Result<UnitSpecV1, ExactLysisPlanError> {
        let position = self.topology.plan_position_at(plan_ordinal)?;
        let phase = position.phase();
        let phase_ordinal = plan_ordinal
            .checked_sub(self.topology.phase_offset(phase)?)
            .ok_or(PlannerErrorV1::IntegerOverflow)?;
        let producer_ids = self.producer_unit_ids(position, plan_ordinal)?;

        match phase {
            UnitPhase::Enumerate => self.primary_spec_from_catalog(phase_ordinal),
            UnitPhase::FidelityMap => self
                .planner
                .fidelity_map_unit_at(
                    phase_ordinal,
                    required_unit_id(&producer_ids, 0)?,
                    self.limits,
                )
                .map_err(Into::into),
            UnitPhase::FixedReduce => self
                .planner
                .fixed_reduce_unit_at(phase_ordinal, exact_pair(&producer_ids)?, self.limits)
                .map_err(Into::into),
            UnitPhase::AmountMap => {
                let enumerate_spec = self.primary_spec_from_catalog(phase_ordinal)?;
                self.planner
                    .amount_map_unit_at(
                        phase_ordinal,
                        &enumerate_spec,
                        required_unit_id(&producer_ids, 1)?,
                        required_unit_id(&producer_ids, 2)?,
                        self.limits,
                    )
                    .map_err(Into::into)
            }
            UnitPhase::GratisPrefix => self
                .planner
                .gratis_prefix_unit_at(phase_ordinal, &producer_ids, self.limits)
                .map_err(Into::into),
            UnitPhase::GratisPrefixDown => self
                .planner
                .gratis_prefix_down_unit_at(phase_ordinal, &producer_ids, self.limits)
                .map_err(Into::into),
            UnitPhase::OutputFinalize => {
                let amount_position = PlannedUnitPositionV1::Primary {
                    phase: UnitPhase::AmountMap,
                    ordinal: phase_ordinal,
                };
                let amount_spec =
                    self.derive_spec_at(self.topology.plan_ordinal_of(amount_position)?)?;
                self.planner
                    .output_finalize_unit_at(
                        phase_ordinal,
                        &amount_spec,
                        required_unit_id(&producer_ids, 1)?,
                        self.limits,
                    )
                    .map_err(Into::into)
            }
            UnitPhase::OwnerShuffle | UnitPhase::BucketShuffle => {
                let exact = producer_ids
                    .iter()
                    .copied()
                    .map(|unit_id| {
                        unit_id.ok_or(ExactLysisPlanError::AuthorityMismatch("shuffle producer"))
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                self.planner
                    .shuffle_unit_at(phase, phase_ordinal, &exact, self.limits)
                    .map_err(Into::into)
            }
            UnitPhase::RootReduce => self
                .planner
                .root_reduce_unit_at(phase_ordinal, &producer_ids, self.limits)
                .map_err(Into::into),
        }
    }

    fn primary_spec_from_catalog(
        &self,
        shard_ordinal: u32,
    ) -> Result<UnitSpecV1, ExactLysisPlanError> {
        let current = self.input_refs.verified_reference_at(
            shard_ordinal,
            self.reader,
            self.bundle.bundle(),
        )?;
        let next = if shard_ordinal + 1 < self.plan.primary_work_unit_count {
            Some(self.input_refs.verified_reference_at(
                shard_ordinal + 1,
                self.reader,
                self.bundle.bundle(),
            )?)
        } else {
            None
        };
        self.primary_spec_from_refs(
            shard_ordinal,
            &current.reference,
            next.as_ref().map(|verified| &verified.reference),
        )
    }

    fn primary_spec_from_refs(
        &self,
        shard_ordinal: u32,
        current: &InputChunkRefV1,
        next: Option<&InputChunkRefV1>,
    ) -> Result<UnitSpecV1, ExactLysisPlanError> {
        self.planner
            .primary_unit_at(
                shard_ordinal,
                |ordinal| {
                    if ordinal == shard_ordinal {
                        Some(current.clone())
                    } else if ordinal == shard_ordinal + 1 {
                        next.cloned()
                    } else {
                        None
                    }
                },
                self.limits,
            )
            .map_err(Into::into)
    }

    fn push_primary_input_ref(
        &self,
        shard_ordinal: u32,
        output: &mut Vec<CasObjectRefV1>,
    ) -> Result<(), ExactLysisPlanError> {
        let verified = self.input_refs.verified_reference_at(
            shard_ordinal,
            self.reader,
            self.bundle.bundle(),
        )?;
        if verified.reference.kind != InputChunkKind::Tribute {
            return Err(ExactLysisPlanError::AuthorityMismatch(
                "primary Tribute input kind",
            ));
        }
        output.push(input_object_ref(&verified.reference));
        Ok(())
    }

    /// Adds the shard plus the bounded one-shard lookahead needed to rederive
    /// the exact half-open primary interval. The lookahead is authenticated
    /// authority only; phase semantics continue to consume the admitted
    /// Enumerate producer for the current shard.
    fn push_primary_input_authority_refs(
        &self,
        shard_ordinal: u32,
        output: &mut Vec<CasObjectRefV1>,
    ) -> Result<(), ExactLysisPlanError> {
        self.push_primary_input_ref(shard_ordinal, output)?;
        let next = shard_ordinal
            .checked_add(1)
            .ok_or(ExactLysisPlanError::AuthorityMismatch(
                "primary Tribute lookahead ordinal",
            ))?;
        if next < self.plan.primary_work_unit_count {
            self.push_primary_input_ref(next, output)?;
        }
        Ok(())
    }

    fn push_input_kind_refs(
        &self,
        kind: InputChunkKind,
        output: &mut Vec<CasObjectRefV1>,
    ) -> Result<(), ExactLysisPlanError> {
        let mut matched = 0_u32;
        for verified in self
            .input_refs
            .exact_verified_cursor(self.reader, self.bundle.bundle())?
        {
            let verified = verified?;
            if verified.reference.kind == kind {
                output.push(input_object_ref(&verified.reference));
                matched = matched
                    .checked_add(1)
                    .ok_or(PlannerErrorV1::IntegerOverflow)?;
            }
        }
        if matched == 0 {
            return Err(ExactLysisPlanError::AuthorityMismatch(
                "required authenticated input kind",
            ));
        }
        Ok(())
    }

    fn producer_unit_ids(
        &self,
        position: PlannedUnitPositionV1,
        consumer_ordinal: u32,
    ) -> Result<Vec<Option<B256>>, ExactLysisPlanError> {
        self.topology
            .required_producers(position)?
            .into_iter()
            .map(|producer| match producer {
                PlannedProducerV1::CanonicalEmpty { .. } => Ok(None),
                PlannedProducerV1::Unit(producer) => {
                    let producer_ordinal = self.topology.plan_ordinal_of(producer)?;
                    if producer_ordinal >= consumer_ordinal {
                        return Err(ExactLysisPlanError::AuthorityMismatch(
                            "producer topological order",
                        ));
                    }
                    let record = self.admissions.read(producer_ordinal)?;
                    self.require_admission_authority(&record)?;
                    Ok(Some(record.unit_id))
                }
            })
            .collect()
    }

    fn require_admission_authority(
        &self,
        record: &VerifiedAdmissionRecordV1,
    ) -> Result<(), ExactLysisPlanError> {
        let authority = self.admissions.plan_authority();
        if record.protocol_bundle_hash != authority.protocol_bundle_hash
            || record.job_id != authority.job_id
            || record.attempt != authority.attempt
            || record.plan_hash != authority.plan_hash
            || record.unit_id.is_zero()
        {
            return Err(ExactLysisPlanError::AuthorityMismatch("producer admission"));
        }
        Ok(())
    }
}

fn input_object_ref(reference: &InputChunkRefV1) -> CasObjectRefV1 {
    CasObjectRefV1 {
        transport_digest: reference.transport_digest,
        encoded_bytes: reference.encoded_bytes,
        expected_ocb1_kind: Some(ObjectKind::AuthenticatedInputChunkV1.tag()),
    }
}

impl Iterator for LysisPlanAuditCursorV1<'_> {
    type Item = Result<LysisPlanAuditStepV1, ExactLysisPlanError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.stage == LysisPlanAuditStageV1::Complete {
            return None;
        }
        let result = match self.stage {
            LysisPlanAuditStageV1::InputCatalog => self.advance_input_catalog(),
            LysisPlanAuditStageV1::Artifacts => self.advance_artifacts(),
            LysisPlanAuditStageV1::AdmissionCatalog => self.advance_admission_catalog(),
            LysisPlanAuditStageV1::Complete => return None,
        };
        if result.is_err() {
            self.failed = true;
        }
        Some(result)
    }
}

impl LysisPlanAuditCursorV1<'_> {
    fn advance_input_catalog(&mut self) -> Result<LysisPlanAuditStepV1, ExactLysisPlanError> {
        if self.owner_tribute_search.is_some()
            || self.next_fidelity_owner < self.pending_fidelity_owners.len()
        {
            return self.advance_fidelity_owner_membership();
        }
        if !self.pending_fidelity_owners.is_empty() {
            self.pending_fidelity_owners.clear();
            self.next_fidelity_owner = 0;
        }
        let step = self
            .input_catalog
            .as_mut()
            .and_then(Iterator::next)
            .ok_or(ExactLysisPlanError::AuthorityMismatch(
                "input catalog closure",
            ))??;
        match step {
            InputRefCatalogClosureStepV1::Reference(reference) => {
                self.observe_input_reference(&reference)?;
                let verified = self.audit.input_refs.verify_reference(
                    reference.clone(),
                    self.audit.reader,
                    self.audit.bundle.bundle(),
                )?;
                self.observe_verified_input_chunk(&verified)?;
                Ok(LysisPlanAuditStepV1::InputChecked {
                    ordinal: reference.ordinal,
                    kind: reference.kind,
                })
            }
            InputRefCatalogClosureStepV1::ReferencesClosed => {
                Ok(LysisPlanAuditStepV1::InputReferenceListClosed)
            }
            InputRefCatalogClosureStepV1::DirectoryEntryChecked => {
                Ok(LysisPlanAuditStepV1::InputCatalogEntryChecked)
            }
            InputRefCatalogClosureStepV1::Complete => {
                self.close_plan_and_prepare_input_roots()?;
                self.close_input_artifacts()?;
                self.stage = LysisPlanAuditStageV1::Artifacts;
                Ok(LysisPlanAuditStepV1::InputsClosed)
            }
        }
    }

    fn advance_fidelity_owner_membership(
        &mut self,
    ) -> Result<LysisPlanAuditStepV1, ExactLysisPlanError> {
        if self.owner_tribute_search.is_none() {
            let owner = *self
                .pending_fidelity_owners
                .get(self.next_fidelity_owner)
                .ok_or(ExactLysisPlanError::AuthorityMismatch(
                    "pending Fidelity owner",
                ))?;
            let tribute_id =
                derive_poseidon_entity_id(owner, WorldwideDay::new(self.audit.manifest.wwd))
                    .map_err(|_| {
                        ExactLysisPlanError::AuthorityMismatch("Tribute owner identity")
                    })?;
            self.owner_tribute_search = Some(OwnerTributeSearchV1 {
                owner,
                tribute_id: tribute_id.to_vec(),
                low: 0,
                high: self.audit.plan.primary_work_unit_count,
            });
        }

        let search =
            self.owner_tribute_search
                .as_mut()
                .ok_or(ExactLysisPlanError::AuthorityMismatch(
                    "Fidelity owner search state",
                ))?;
        if search.low >= search.high {
            return Err(ExactLysisPlanError::AuthorityMismatch(
                "Fidelity owner Tribute membership",
            ));
        }
        let middle = search.low + (search.high - search.low) / 2;
        let verified = self.audit.input_refs.verified_reference_at(
            middle,
            self.audit.reader,
            self.audit.bundle.bundle(),
        )?;
        if verified.reference.kind != InputChunkKind::Tribute {
            return Err(ExactLysisPlanError::AuthorityMismatch(
                "Fidelity owner Tribute search range",
            ));
        }
        let target = search.tribute_id.as_slice();
        if target < verified.reference.first_key.0.as_slice() {
            search.high = middle;
            return Ok(LysisPlanAuditStepV1::FidelityOwnerMembershipProbe {
                owner: search.owner,
            });
        }
        if target > verified.reference.last_key_inclusive.0.as_slice() {
            search.low = middle
                .checked_add(1)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "Fidelity owner search lower bound",
                })?;
            return Ok(LysisPlanAuditStepV1::FidelityOwnerMembershipProbe {
                owner: search.owner,
            });
        }

        let owner = search.owner;
        let found = verified
            .chunk
            .canonical_records_or_openings
            .iter()
            .map(|record| decode_tribute_v1(&record.0))
            .find_map(|result| match result {
                Ok(tribute) if tribute.tribute_id.as_slice() == target => Some(Ok(tribute)),
                Ok(_) => None,
                Err(error) => Some(Err(error)),
            })
            .transpose()?
            .ok_or(ExactLysisPlanError::AuthorityMismatch(
                "Fidelity owner Tribute membership",
            ))?;
        if found.owner != owner || found.worldwide_day.value() != self.audit.manifest.wwd {
            return Err(ExactLysisPlanError::AuthorityMismatch(
                "Fidelity owner Tribute binding",
            ));
        }
        self.owner_tribute_search = None;
        self.next_fidelity_owner =
            self.next_fidelity_owner
                .checked_add(1)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "Fidelity owner cursor",
                })?;
        self.fidelity_owner_count =
            self.fidelity_owner_count
                .checked_add(1)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "Fidelity owner count",
                })?;
        Ok(LysisPlanAuditStepV1::FidelityOwnerMembershipChecked { owner })
    }

    fn observe_input_reference(
        &mut self,
        reference: &InputChunkRefV1,
    ) -> Result<(), ExactLysisPlanError> {
        match reference.kind {
            InputChunkKind::Tribute => {
                if let Some(previous) = self.pending_tribute_ref.replace(reference.clone()) {
                    self.push_primary_spec(previous, Some(reference))?;
                }
            }
            InputChunkKind::Fidelity => {
                self.flush_last_primary_spec()?;
                self.fidelity_opening_count = self
                    .fidelity_opening_count
                    .checked_add(reference.record_count)
                    .ok_or(ProtocolError::IntegerOverflow {
                        what: "Fidelity opening count",
                    })?;
            }
            InputChunkKind::Oracle => {
                self.flush_last_primary_spec()?;
                self.oracle_opening_count = self
                    .oracle_opening_count
                    .checked_add(reference.record_count)
                    .ok_or(ProtocolError::IntegerOverflow {
                        what: "Oracle opening count",
                    })?;
            }
        }
        Ok(())
    }

    fn push_primary_spec(
        &mut self,
        current: InputChunkRefV1,
        next: Option<&InputChunkRefV1>,
    ) -> Result<(), ExactLysisPlanError> {
        let spec = self
            .audit
            .primary_spec_from_refs(self.primary_spec_count, &current, next)?;
        self.primary_root
            .as_mut()
            .ok_or(ExactLysisPlanError::AuthorityMismatch(
                "primary plan root state",
            ))?
            .push(
                &spec.encode_canonical(self.audit.limits)?,
                self.audit.limits.codec.max_body_bytes,
            )?;
        self.primary_spec_count =
            self.primary_spec_count
                .checked_add(1)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "primary spec count",
                })?;
        Ok(())
    }

    fn flush_last_primary_spec(&mut self) -> Result<(), ExactLysisPlanError> {
        if let Some(previous) = self.pending_tribute_ref.take() {
            self.push_primary_spec(previous, None)?;
        }
        Ok(())
    }

    fn close_plan_and_prepare_input_roots(&mut self) -> Result<(), ExactLysisPlanError> {
        self.flush_last_primary_spec()?;
        let root = self
            .primary_root
            .take()
            .ok_or(ExactLysisPlanError::AuthorityMismatch(
                "primary plan root state",
            ))?
            .finish()?;
        if self.primary_spec_count != self.audit.plan.primary_work_unit_count
            || root != self.audit.plan.primary_work_unit_root
            || self.fidelity_opening_count == 0
            || self.oracle_opening_count != 1
        {
            return Err(ExactLysisPlanError::AuthorityMismatch(
                "rederived plan and opening counts",
            ));
        }
        Ok(())
    }

    fn observe_verified_input_chunk(
        &mut self,
        verified: &VerifiedInputChunkRefV1,
    ) -> Result<(), ExactLysisPlanError> {
        let reference = &verified.reference;
        if reference.kind == InputChunkKind::Tribute
            && self
                .previous_tribute_last_key
                .as_ref()
                .is_some_and(|last| last.as_slice() >= reference.first_key.0.as_slice())
        {
            return Err(ExactLysisPlanError::AuthorityMismatch(
                "Tribute cross-chunk key order",
            ));
        }
        if reference.kind == InputChunkKind::Tribute {
            self.previous_tribute_last_key = Some(reference.last_key_inclusive.0.clone());
        } else if verified.chunk.canonical_records_or_openings.len() != 1 {
            return Err(ExactLysisPlanError::AuthorityMismatch(
                "one opening record per input chunk",
            ));
        }

        for record in &verified.chunk.canonical_records_or_openings {
            match reference.kind {
                InputChunkKind::Tribute => self.observe_tribute(&record.0)?,
                InputChunkKind::Fidelity => self.observe_fidelity_opening(&record.0)?,
                InputChunkKind::Oracle => self.observe_oracle_opening(&record.0)?,
            }
        }
        Ok(())
    }

    fn observe_tribute(&mut self, encoded: &[u8]) -> Result<(), ExactLysisPlanError> {
        let tribute = decode_tribute_v1(encoded)?;
        if tribute.worldwide_day.value() != self.audit.manifest.wwd {
            return Err(ExactLysisPlanError::AuthorityMismatch("Tribute WWD"));
        }
        self.tribute_count =
            self.tribute_count
                .checked_add(1)
                .ok_or(ProtocolError::IntegerOverflow {
                    what: "Tribute count",
                })?;
        self.tribute_nominal_total = self
            .tribute_nominal_total
            .checked_add(tribute.nominal_amount_minor)
            .ok_or(ExactLysisPlanError::AuthorityMismatch(
                "Tribute nominal total overflow",
            ))?;
        self.tribute_isos.insert(tribute.reference_currency);
        if self.tribute_isos.len() > MAX_SETTLEMENT_ISOS {
            return Err(ExactLysisPlanError::AuthorityMismatch(
                "settlement ISO bound",
            ));
        }
        Ok(())
    }

    fn observe_fidelity_opening(&mut self, encoded: &[u8]) -> Result<(), ExactLysisPlanError> {
        let opening = AuthenticatedOpeningV1::decode_canonical_record(encoded, self.audit.limits)?;
        if opening.source_kind != OpeningSourceKind::Fidelity {
            return Err(ExactLysisPlanError::AuthorityMismatch(
                "Fidelity opening source",
            ));
        }
        opening.validate_against_bundle(self.audit.bundle.bundle(), self.audit.limits)?;
        let _ = opening.decode_and_validate_raw_opening(
            self.audit.manifest.checkpoint.finalized_state_root,
            self.audit.limits,
        )?;
        self.fidelity_root
            .as_mut()
            .ok_or(ExactLysisPlanError::AuthorityMismatch(
                "Fidelity root state",
            ))?
            .push(encoded, self.audit.limits.max_bounded_bytes)?;
        let owners = decode_fidelity_subject_key(&opening.canonical_subject_key.0)?;
        if owners.is_empty()
            || owners.len()
                > usize::try_from(outbe_lysis::program_v1::planner::PRIMARY_WORK_SHARD_SIZE)
                    .map_err(|_| {
                        ExactLysisPlanError::AuthorityMismatch("Fidelity owner batch bound")
                    })?
            || !self.pending_fidelity_owners.is_empty()
            || self.owner_tribute_search.is_some()
        {
            return Err(ExactLysisPlanError::AuthorityMismatch(
                "Fidelity owner batch state",
            ));
        }
        for owner in &owners {
            if self
                .previous_fidelity_owner
                .is_some_and(|previous| previous >= *owner)
            {
                return Err(ExactLysisPlanError::AuthorityMismatch(
                    "Fidelity owner order",
                ));
            }
            self.previous_fidelity_owner = Some(*owner);
        }
        self.pending_fidelity_owners = owners;
        self.next_fidelity_owner = 0;
        Ok(())
    }

    fn observe_oracle_opening(&mut self, encoded: &[u8]) -> Result<(), ExactLysisPlanError> {
        if self.oracle_subject_isos.is_some() {
            return Err(ExactLysisPlanError::AuthorityMismatch(
                "exactly one Oracle opening",
            ));
        }
        let opening = AuthenticatedOpeningV1::decode_canonical_record(encoded, self.audit.limits)?;
        if opening.source_kind != OpeningSourceKind::Oracle {
            return Err(ExactLysisPlanError::AuthorityMismatch(
                "Oracle opening source",
            ));
        }
        opening.validate_against_bundle(self.audit.bundle.bundle(), self.audit.limits)?;
        let _ = opening.decode_and_validate_raw_opening(
            self.audit.manifest.checkpoint.finalized_state_root,
            self.audit.limits,
        )?;
        let (wwd, isos) = decode_oracle_subject_key(&opening.canonical_subject_key.0)?;
        if wwd != self.audit.manifest.wwd {
            return Err(ExactLysisPlanError::AuthorityMismatch("Oracle opening WWD"));
        }
        self.oracle_root
            .as_mut()
            .ok_or(ExactLysisPlanError::AuthorityMismatch("Oracle root state"))?
            .push(encoded, self.audit.limits.max_bounded_bytes)?;
        self.oracle_subject_isos = Some(isos);
        Ok(())
    }

    fn close_input_artifacts(&mut self) -> Result<(), ExactLysisPlanError> {
        let fidelity_root = self
            .fidelity_root
            .take()
            .ok_or(ExactLysisPlanError::AuthorityMismatch(
                "Fidelity root state",
            ))?
            .finish()?;
        let oracle_root = self
            .oracle_root
            .take()
            .ok_or(ExactLysisPlanError::AuthorityMismatch("Oracle root state"))?
            .finish()?;
        let expected_isos = self.tribute_isos.iter().copied().collect::<Vec<_>>();
        if self.tribute_count != self.audit.manifest.tribute_count
            || self.tribute_nominal_total != self.audit.manifest.tribute_nominal_total
            || self.fidelity_owner_count != self.audit.manifest.tribute_count
            || fidelity_root != self.audit.manifest.fidelity_opening_root
            || oracle_root != self.audit.manifest.oracle_opening_root
            || self.oracle_subject_isos.as_ref() != Some(&expected_isos)
        {
            return Err(ExactLysisPlanError::AuthorityMismatch(
                "complete input artifact semantics",
            ));
        }
        Ok(())
    }

    fn advance_artifacts(&mut self) -> Result<LysisPlanAuditStepV1, ExactLysisPlanError> {
        if self.next_artifact_ordinal < self.audit.topology.total_unit_count() {
            let plan_ordinal = self.next_artifact_ordinal;
            self.next_artifact_ordinal += 1;
            return Ok(LysisPlanAuditStepV1::Artifact(Box::new(
                self.audit.verified_artifact_at(plan_ordinal)?,
            )));
        }
        self.admission_catalog = Some(self.audit.admissions.bounded_directory_cursor()?);
        self.stage = LysisPlanAuditStageV1::AdmissionCatalog;
        Ok(LysisPlanAuditStepV1::ArtifactsClosed)
    }

    fn advance_admission_catalog(&mut self) -> Result<LysisPlanAuditStepV1, ExactLysisPlanError> {
        let step = self
            .admission_catalog
            .as_mut()
            .and_then(Iterator::next)
            .ok_or(ExactLysisPlanError::AuthorityMismatch(
                "admission catalog closure",
            ))??;
        match step {
            AdmissionDirectoryStepV1::EntryChecked => {
                Ok(LysisPlanAuditStepV1::AdmissionCatalogEntryChecked)
            }
            AdmissionDirectoryStepV1::Complete => {
                self.stage = LysisPlanAuditStageV1::Complete;
                Ok(LysisPlanAuditStepV1::Complete)
            }
        }
    }
}

fn required_unit_id(
    producer_ids: &[Option<B256>],
    index: usize,
) -> Result<B256, ExactLysisPlanError> {
    producer_ids
        .get(index)
        .copied()
        .flatten()
        .filter(|unit_id| !unit_id.is_zero())
        .ok_or(ExactLysisPlanError::AuthorityMismatch(
            "required producer UnitId",
        ))
}

fn exact_pair(producer_ids: &[Option<B256>]) -> Result<[Option<B256>; 2], ExactLysisPlanError> {
    match producer_ids {
        [left, right] => Ok([*left, *right]),
        _ => Err(ExactLysisPlanError::AuthorityMismatch(
            "binary producer count",
        )),
    }
}

#[derive(Debug, Error)]
pub enum ExactLysisPlanError {
    #[error(transparent)]
    Admission(#[from] AdmissionCatalogError),
    #[error(transparent)]
    InputRef(#[from] InputRefCatalogError),
    #[error(transparent)]
    InputArtifact(#[from] InputArtifactError),
    #[error(transparent)]
    TributeBody(#[from] outbe_compressed_entities::CanonicalBodyError),
    #[error(transparent)]
    Cas(#[from] CasError),
    #[error(transparent)]
    Planner(#[from] PlannerErrorV1),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("Lysis plan authority mismatch: {0}")]
    AuthorityMismatch(&'static str),
    #[error("plan ordinal {plan_ordinal} admitted an unexpected UnitId")]
    UnexpectedUnitId { plan_ordinal: u32 },
}
