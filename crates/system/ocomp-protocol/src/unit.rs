use alloy_primitives::{B256, U256};

use crate::{
    codec::require_canonical_reencoding,
    common::BoundedBytes,
    error::ProtocolError,
    hash::hash_framed,
    registry::HashDomain,
    schema::{
        encode_nested_value, impl_top_level_codec, require, wire_enum_u8, wire_struct, NestedCodec,
        SchemaLimits,
    },
    CanonicalReader, CanonicalWriter,
};

wire_enum_u8! {
    pub enum InputPurpose {
        InputManifest = 1,
        TributeStream = 2,
        FidelityOpenings = 3,
        OracleOpenings = 4,
        EnumeratedTributes = 10,
        FidelityPartials = 11,
        FiFractionTable = 12,
        AmountRecords = 13,
        GratisPrefixTable = 14,
        FinalizedOutputRecords = 15,
        OwnerOrderedRecords = 16,
        BucketOrderedRecords = 17,
        RootSummary = 18,
    }
}

wire_enum_u8! {
    pub enum InputSourceKind {
        AuthenticatedRoot = 1,
        UnitOutput = 2,
        CanonicalEmpty = 3,
    }
}

wire_enum_u8! {
    pub enum UnitPhase {
        Enumerate = 1,
        FidelityMap = 2,
        FixedReduce = 3,
        AmountMap = 4,
        GratisPrefix = 5,
        OutputFinalize = 6,
        OwnerShuffle = 7,
        BucketShuffle = 8,
        RootReduce = 9,
        // Top-down half of the deterministic parallel Gratis prefix scan.
        // `GratisPrefix` keeps its frozen tag as the bottom-up summary phase.
        GratisPrefixDown = 10,
    }
}

wire_struct! {
    pub struct CanonicalInputRefV1 {
        pub purpose: InputPurpose,
        pub source_kind: InputSourceKind,
        pub source_id: B256,
        pub record_count_limit: u32,
        pub max_encoded_bytes: u64,
        pub max_decoded_bytes: u64,
    }
}

wire_struct! {
    pub struct EntityIdHalfOpenRange {
        pub start: B256,
        pub end: Option<B256>,
    }
}

wire_struct! {
    pub struct FidelityIndexHalfOpenRange {
        pub start: u32,
        pub end: u32,
    }
}

wire_struct! {
    pub struct CanonicalRunSpan {
        pub start_run: u32,
        pub end_run: u32,
    }
}

wire_struct! {
    pub struct BinaryReducerNode {
        pub level: u16,
        pub index: u32,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UnitInterval {
    EntityIdRange(EntityIdHalfOpenRange),
    FidelityIndexRange(FidelityIndexHalfOpenRange),
    CanonicalRunSpan(CanonicalRunSpan),
    BinaryReducerNode(BinaryReducerNode),
}

impl UnitInterval {
    #[must_use]
    pub const fn tag(&self) -> u8 {
        match self {
            Self::EntityIdRange(_) => 1,
            Self::FidelityIndexRange(_) => 2,
            Self::CanonicalRunSpan(_) => 3,
            Self::BinaryReducerNode(_) => 4,
        }
    }
}

impl NestedCodec for UnitInterval {
    fn validate(&self, limits: &SchemaLimits) -> Result<(), ProtocolError> {
        match self {
            Self::EntityIdRange(value) => value.validate(limits),
            Self::FidelityIndexRange(value) => {
                value.validate(limits)?;
                require(value.start < value.end, "non-empty fidelity range")
            }
            Self::CanonicalRunSpan(value) => {
                value.validate(limits)?;
                require(
                    value.start_run < value.end_run,
                    "non-empty canonical run span",
                )
            }
            Self::BinaryReducerNode(value) => value.validate(limits),
        }
    }

    fn encode_nested(
        &self,
        output: &mut CanonicalWriter,
        limits: &SchemaLimits,
    ) -> Result<(), ProtocolError> {
        output.write_u8(self.tag())?;
        match self {
            Self::EntityIdRange(value) => value.encode_nested(output, limits),
            Self::FidelityIndexRange(value) => value.encode_nested(output, limits),
            Self::CanonicalRunSpan(value) => value.encode_nested(output, limits),
            Self::BinaryReducerNode(value) => value.encode_nested(output, limits),
        }
    }

    fn decode_nested(
        input: &mut CanonicalReader<'_>,
        limits: &SchemaLimits,
    ) -> Result<Self, ProtocolError> {
        match input.read_u8()? {
            1 => Ok(Self::EntityIdRange(EntityIdHalfOpenRange::decode_nested(
                input, limits,
            )?)),
            2 => Ok(Self::FidelityIndexRange(
                FidelityIndexHalfOpenRange::decode_nested(input, limits)?,
            )),
            3 => Ok(Self::CanonicalRunSpan(CanonicalRunSpan::decode_nested(
                input, limits,
            )?)),
            4 => Ok(Self::BinaryReducerNode(BinaryReducerNode::decode_nested(
                input, limits,
            )?)),
            value => Err(ProtocolError::UnknownEnum {
                width: 8,
                value: u16::from(value),
            }),
        }
    }
}

wire_struct! {
    pub struct UnitSpecV1 {
        pub protocol_bundle_hash: B256,
        pub job_id: B256,
        pub attempt: u32,
        pub phase: UnitPhase,
        pub interval: UnitInterval,
        pub canonical_ordered_inputs: Vec<CanonicalInputRefV1>,
        pub lysis_program_semantics_hash: B256,
        pub planner_spec_version: u16,
        pub reducer_spec_version: u16,
    }
    validate = validate_unit_spec;
}
impl_top_level_codec!(UnitSpecV1, UnitSpecV1);

wire_struct! {
    /// Constant-size commitment to a lazily materialized deterministic plan.
    ///
    /// The complete Tribute population is never embedded as a vector here.
    /// Primary unit specifications are committed by an ordered root and may be
    /// generated or verified independently by ordinal.
    pub struct PlanCommitmentV1 {
        pub protocol_bundle_hash: B256,
        pub job_id: B256,
        pub attempt: u32,
        pub input_manifest_hash: B256,
        pub wwd: u32,
        pub lysis_budget: U256,
        pub logical_evaluation_time: u64,
        pub tribute_count: u32,
        pub max_tributes_per_work_shard: u32,
        pub primary_work_unit_count: u32,
        pub primary_work_unit_root: B256,
        pub planner_spec_version: u16,
        pub reducer_spec_version: u16,
    }
}

wire_struct! {
    pub struct UnitArtifactV1 {
        pub protocol_bundle_hash: B256,
        pub job_id: B256,
        pub attempt: u32,
        pub unit_id: B256,
        pub phase: UnitPhase,
        pub interval_commitment: B256,
        pub input_root: B256,
        pub output_record_count: u32,
        pub canonical_output_bytes: BoundedBytes,
        pub output_semantic_digest: B256,
        pub coverage_or_permutation_commitment: B256,
    }
    validate = validate_unit_artifact;
}
impl_top_level_codec!(UnitArtifactV1, UnitArtifactV1);

wire_struct! {
    pub struct RawTributeCoverageItemV1 {
        pub raw_ordinal: u32,
        pub tribute_id: B256,
    }
}

wire_struct! {
    pub struct WorkOutputHeaderV1 {
        pub source_coverage_root: B256,
        pub output_coverage_root: B256,
        pub source_coverage_count: u32,
        pub output_coverage_count: u32,
    }
}

impl UnitSpecV1 {
    pub fn validate_semantics(&self, limits: &SchemaLimits) -> Result<(), ProtocolError> {
        require(
            self.canonical_ordered_inputs.len() <= limits.max_unit_inputs,
            "unit input cap",
        )?;
        let interval_matches = matches!(
            (&self.phase, &self.interval),
            (
                UnitPhase::Enumerate | UnitPhase::AmountMap | UnitPhase::OutputFinalize,
                UnitInterval::EntityIdRange(_)
            ) | (UnitPhase::FidelityMap, UnitInterval::FidelityIndexRange(_))
                | (
                    UnitPhase::FixedReduce
                        | UnitPhase::GratisPrefix
                        | UnitPhase::GratisPrefixDown
                        | UnitPhase::RootReduce,
                    UnitInterval::BinaryReducerNode(_)
                )
                | (
                    UnitPhase::OwnerShuffle | UnitPhase::BucketShuffle,
                    UnitInterval::CanonicalRunSpan(_)
                )
        );
        require(interval_matches, "phase interval binding")?;
        for input in &self.canonical_ordered_inputs {
            if input.source_kind == InputSourceKind::CanonicalEmpty {
                require(input.record_count_limit == 0, "canonical empty input count")?;
                require(
                    input.source_id == empty_unit_input_id(input.purpose)?,
                    "canonical empty input id",
                )?;
            }
        }
        Ok(())
    }

    pub fn unit_id(&self, limits: &SchemaLimits) -> Result<B256, ProtocolError> {
        self.validate_semantics(limits)?;
        hash_framed(HashDomain::Unit, &self.encode_canonical(limits)?)
    }

    pub fn interval_commitment(&self, limits: &SchemaLimits) -> Result<B256, ProtocolError> {
        let mut payload = vec![self.phase as u8];
        payload.extend_from_slice(&encode_nested_value(&self.interval, limits)?);
        hash_framed(HashDomain::UnitInterval, &payload)
    }

    pub fn input_root(&self, limits: &SchemaLimits) -> Result<B256, ProtocolError> {
        let count = u32::try_from(self.canonical_ordered_inputs.len()).map_err(|_| {
            ProtocolError::IntegerOverflow {
                what: "unit input count",
            }
        })?;
        let mut payload = count.to_be_bytes().to_vec();
        for input in &self.canonical_ordered_inputs {
            payload.extend_from_slice(&encode_nested_value(input, limits)?);
        }
        hash_framed(HashDomain::UnitInputs, &payload)
    }
}

fn validate_unit_spec(spec: &UnitSpecV1, limits: &SchemaLimits) -> Result<(), ProtocolError> {
    spec.validate_semantics(limits)
}

impl UnitArtifactV1 {
    pub fn from_canonical_output(
        spec: &UnitSpecV1,
        header: WorkOutputHeaderV1,
        phase_payload: BoundedBytes,
        limits: &SchemaLimits,
    ) -> Result<Self, ProtocolError> {
        <WorkOutputHeaderV1 as NestedCodec>::validate(&header, limits)?;
        require_output_header_semantics(&header)?;
        phase_payload.validate(limits)?;
        let mut writer = CanonicalWriter::new(limits.codec);
        header.encode_nested(&mut writer, limits)?;
        let mut canonical_output = writer.into_bytes();
        let total_bytes = canonical_output
            .len()
            .checked_add(phase_payload.0.len())
            .ok_or(ProtocolError::IntegerOverflow {
                what: "unit canonical output bytes",
            })?;
        require(
            total_bytes <= limits.max_bounded_bytes,
            "unit canonical output byte cap",
        )?;
        canonical_output.extend_from_slice(&phase_payload.0);
        let mut artifact = Self {
            protocol_bundle_hash: spec.protocol_bundle_hash,
            job_id: spec.job_id,
            attempt: spec.attempt,
            unit_id: spec.unit_id(limits)?,
            phase: spec.phase,
            interval_commitment: spec.interval_commitment(limits)?,
            input_root: spec.input_root(limits)?,
            output_record_count: header.output_coverage_count,
            canonical_output_bytes: BoundedBytes(canonical_output),
            output_semantic_digest: B256::ZERO,
            coverage_or_permutation_commitment: header.output_coverage_root,
        };
        artifact.output_semantic_digest = unit_output_semantic_digest(&artifact, limits)?;
        artifact.validate_against(spec, limits)?;
        Ok(artifact)
    }

    pub fn output_header(
        &self,
        limits: &SchemaLimits,
    ) -> Result<WorkOutputHeaderV1, ProtocolError> {
        let mut reader = CanonicalReader::new(&self.canonical_output_bytes.0, limits.codec)?;
        let header = WorkOutputHeaderV1::decode_nested(&mut reader, limits)?;
        <WorkOutputHeaderV1 as NestedCodec>::validate(&header, limits)?;
        require_output_header_semantics(&header)?;
        let encoded_header = encode_nested_value(&header, limits)?;
        require_canonical_reencoding(
            &self.canonical_output_bytes.0[..reader.offset()],
            &encoded_header,
        )?;
        Ok(header)
    }

    pub fn phase_payload<'a>(&'a self, limits: &SchemaLimits) -> Result<&'a [u8], ProtocolError> {
        let mut reader = CanonicalReader::new(&self.canonical_output_bytes.0, limits.codec)?;
        let header = WorkOutputHeaderV1::decode_nested(&mut reader, limits)?;
        <WorkOutputHeaderV1 as NestedCodec>::validate(&header, limits)?;
        require_output_header_semantics(&header)?;
        let payload_offset = reader.offset();
        require(
            payload_offset < self.canonical_output_bytes.0.len(),
            "unit phase payload is non-empty",
        )?;
        Ok(&self.canonical_output_bytes.0[payload_offset..])
    }

    pub fn validate_semantics(&self, limits: &SchemaLimits) -> Result<(), ProtocolError> {
        require(
            !self.protocol_bundle_hash.is_zero()
                && !self.job_id.is_zero()
                && !self.unit_id.is_zero()
                && !self.interval_commitment.is_zero()
                && !self.input_root.is_zero()
                && !self.canonical_output_bytes.0.is_empty()
                && !self.output_semantic_digest.is_zero()
                && !self.coverage_or_permutation_commitment.is_zero(),
            "unit artifact committed fields",
        )?;
        let header = self.output_header(limits)?;
        let _ = self.phase_payload(limits)?;
        require(
            self.output_record_count == header.output_coverage_count
                && self.coverage_or_permutation_commitment == header.output_coverage_root,
            "unit artifact output header binding",
        )?;
        require(
            self.output_semantic_digest == unit_output_semantic_digest(self, limits)?,
            "unit output semantic digest",
        )
    }

    pub fn validate_against(
        &self,
        spec: &UnitSpecV1,
        limits: &SchemaLimits,
    ) -> Result<(), ProtocolError> {
        self.validate_semantics(limits)?;
        require(
            self.protocol_bundle_hash == spec.protocol_bundle_hash
                && self.job_id == spec.job_id
                && self.attempt == spec.attempt
                && self.phase == spec.phase,
            "unit artifact spec binding",
        )?;
        require(self.unit_id == spec.unit_id(limits)?, "unit artifact id")?;
        require(
            self.interval_commitment == spec.interval_commitment(limits)?,
            "unit artifact interval commitment",
        )?;
        require(
            self.input_root == spec.input_root(limits)?,
            "unit artifact input root",
        )?;
        let expected = unit_output_semantic_digest(self, limits)?;
        require(
            self.output_semantic_digest == expected,
            "unit output semantic digest",
        )
    }

    pub fn artifact_digest(&self, limits: &SchemaLimits) -> Result<B256, ProtocolError> {
        hash_framed(HashDomain::UnitArtifact, &self.encode_canonical(limits)?)
    }
}

fn require_output_header_semantics(header: &WorkOutputHeaderV1) -> Result<(), ProtocolError> {
    require(
        !header.source_coverage_root.is_zero()
            && !header.output_coverage_root.is_zero()
            && (header.source_coverage_count > 0 || header.output_coverage_count == 0),
        "work output coverage header",
    )
}

fn validate_unit_artifact(
    artifact: &UnitArtifactV1,
    limits: &SchemaLimits,
) -> Result<(), ProtocolError> {
    artifact.validate_semantics(limits)
}

impl PlanCommitmentV1 {
    pub fn encode_canonical_record(&self, limits: &SchemaLimits) -> Result<Vec<u8>, ProtocolError> {
        <Self as NestedCodec>::validate(self, limits)?;
        let mut writer = CanonicalWriter::new(limits.codec);
        self.encode_nested(&mut writer, limits)?;
        Ok(writer.into_bytes())
    }

    pub fn decode_canonical_record(
        encoded: &[u8],
        limits: &SchemaLimits,
    ) -> Result<Self, ProtocolError> {
        let mut reader = CanonicalReader::new(encoded, limits.codec)?;
        let plan = Self::decode_nested(&mut reader, limits)?;
        reader.finish()?;
        <Self as NestedCodec>::validate(&plan, limits)?;
        require_canonical_reencoding(encoded, &plan.encode_canonical_record(limits)?)?;
        Ok(plan)
    }

    pub fn validate_semantics(&self) -> Result<(), ProtocolError> {
        require(
            self.tribute_count > 0
                && self.wwd > 0
                && !self.lysis_budget.is_zero()
                && self.logical_evaluation_time > 0
                && self.max_tributes_per_work_shard > 0
                && !self.primary_work_unit_root.is_zero(),
            "plan committed population",
        )?;
        let rounded = self
            .tribute_count
            .checked_add(self.max_tributes_per_work_shard - 1)
            .ok_or(ProtocolError::IntegerOverflow {
                what: "primary work unit count",
            })?;
        require(
            self.primary_work_unit_count == rounded / self.max_tributes_per_work_shard,
            "plan exact primary work unit count",
        )
    }

    pub fn plan_hash(&self, limits: &SchemaLimits) -> Result<B256, ProtocolError> {
        self.validate_semantics()?;
        hash_framed(HashDomain::Plan, &self.encode_canonical_record(limits)?)
    }
}

pub fn empty_unit_input_id(purpose: InputPurpose) -> Result<B256, ProtocolError> {
    hash_framed(HashDomain::UnitEmpty, &[purpose as u8])
}

pub fn unit_output_semantic_digest(
    artifact: &UnitArtifactV1,
    _limits: &SchemaLimits,
) -> Result<B256, ProtocolError> {
    let output_len = u32::try_from(artifact.canonical_output_bytes.0.len()).map_err(|_| {
        ProtocolError::IntegerOverflow {
            what: "unit output byte length",
        }
    })?;
    let mut payload = Vec::new();
    payload.extend_from_slice(artifact.protocol_bundle_hash.as_slice());
    payload.extend_from_slice(artifact.job_id.as_slice());
    payload.extend_from_slice(&artifact.attempt.to_be_bytes());
    payload.extend_from_slice(artifact.unit_id.as_slice());
    payload.push(artifact.phase as u8);
    payload.extend_from_slice(artifact.interval_commitment.as_slice());
    payload.extend_from_slice(&output_len.to_be_bytes());
    payload.extend_from_slice(&artifact.canonical_output_bytes.0);
    hash_framed(HashDomain::UnitOutput, &payload)
}
