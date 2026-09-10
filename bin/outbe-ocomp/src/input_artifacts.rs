use std::{collections::BTreeSet, path::Path};

use alloy_primitives::{Address, B256, U256};
use outbe_compressed_entities::{decode_tribute_v1, CanonicalBodyError};
use outbe_lysis::program_v1::planner::PRIMARY_WORK_SHARD_SIZE;
use outbe_ocomp_protocol::{
    control::CasObjectRefV1,
    input::{
        authenticated_opening_root, AuthenticatedInputChunkV1, AuthenticatedOpeningV1,
        CheckpointIdentityV1, Compression, InputChunkKind, InputChunkRefV1, InputManifestV1,
        OpeningSourceKind,
    },
    ordered_list_root,
    profile::ProtocolBundleV1,
    ListKind, ObjectKind, OrderedListLimits, ProtocolError, SchemaLimits, StreamingOrderedListRoot,
};
use thiserror::Error;

use crate::{
    cas::{CasError, FilesystemCas, FilesystemCasReader, VerifiedCasObject},
    input_ref_catalog::{
        InputRefCatalogError, InputRefCatalogPublisher, InputRefCatalogSubjectV1,
        VerifiedInputChunkRefCatalog,
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedInputChunk {
    pub reference: InputChunkRefV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedInputArtifacts {
    pub manifest_hash: B256,
    pub tribute_count: u32,
    pub tribute_nominal_total: U256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputArtifactIdentity {
    pub job_id: B256,
    pub attempt: u32,
    pub checkpoint: CheckpointIdentityV1,
    pub wwd: u32,
    pub sealed_tribute_collection_key: B256,
    pub sealed_tribute_collection_root: B256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InputArtifactContents {
    pub identity: InputArtifactIdentity,
    pub canonical_tributes: Vec<Vec<u8>>,
    pub fidelity_openings: Vec<AuthenticatedOpeningV1>,
    pub oracle_opening: AuthenticatedOpeningV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedInputArtifacts {
    pub manifest_ref: CasObjectRefV1,
    pub ordered_chunk_refs: Vec<CasObjectRefV1>,
    pub manifest_hash: B256,
    pub tribute_count: u32,
    pub tribute_nominal_total: U256,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedStreamingInputArtifacts {
    pub manifest_ref: CasObjectRefV1,
    pub manifest_hash: B256,
    pub tribute_count: u32,
    pub tribute_nominal_total: U256,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputArtifactRetentionStatsV1 {
    pub current_tribute_records: usize,
    pub peak_tribute_records: usize,
    pub configured_tribute_record_bound: usize,
}

pub struct DurableInputArtifactPublisher<'a> {
    cas: &'a FilesystemCas,
    reader: &'a FilesystemCasReader,
    bundle: &'a ProtocolBundleV1,
    identity: InputArtifactIdentity,
    limits: SchemaLimits,
    protocol_bundle_hash: B256,
    refs: Option<InputRefCatalogPublisher>,
    ordinal: u32,
    tribute_chunk: Vec<outbe_ocomp_protocol::common::BoundedBytes>,
    peak_tribute_chunk_len: usize,
    tribute_count: u32,
    tribute_nominal_total: U256,
    tributes_finished: bool,
    fidelity_count: u32,
    previous_fidelity_subject: Option<Vec<u8>>,
    oracle_root: Option<StreamingOrderedListRoot>,
    oracle_published: bool,
}

#[derive(Debug, Error)]
pub enum InputArtifactError {
    #[error(transparent)]
    Cas(#[from] CasError),
    #[error("canonical OCOMP protocol object rejected: {0}")]
    Protocol(#[from] ProtocolError),
    #[error("canonical Tribute body rejected: {0}")]
    Tribute(#[from] CanonicalBodyError),
    #[error("input artifact invariant failed: {0}")]
    Invariant(&'static str),
    #[error("input artifact count does not fit the protocol")]
    CountOverflow,
    #[error("input artifact byte count overflow")]
    ByteCountOverflow,
    #[error("Tribute nominal total overflow")]
    NominalTotalOverflow,
    #[error("streamed Tribute count mismatch: expected {expected}, got {actual}")]
    TributeCountMismatch { expected: u32, actual: u32 },
    #[error("streamed Tribute source failed: {0}")]
    TributeSource(String),
    #[error("streamed opening source failed: {0}")]
    OpeningSource(String),
    #[error(transparent)]
    InputRefCatalog(#[from] InputRefCatalogError),
}

struct DerivedChunk {
    public: DerivedInputChunk,
    protocol_bundle_hash: B256,
    job_id: B256,
    kind: InputChunkKind,
    ordinal: u32,
    record_count: usize,
    tribute_count: usize,
    tribute_nominal_total: U256,
    tribute_owners: Vec<Address>,
    tribute_isos: Vec<u16>,
    fidelity_openings: Vec<AuthenticatedOpeningV1>,
    oracle_openings: Vec<AuthenticatedOpeningV1>,
}

#[must_use]
pub fn poc_input_list_limits() -> OrderedListLimits {
    let candidate = outbe_ocomp_protocol::generated_shape::OCOMP_POC_CANDIDATE_LIMITS_V1;
    OrderedListLimits::new(
        usize::try_from(candidate.max_protocol_collection_items)
            .expect("generated list item cap fits usize"),
        usize::try_from(candidate.max_activation_ocb1_bytes)
            .expect("generated list item byte cap fits usize"),
        usize::try_from(candidate.max_input_manifest_bytes)
            .expect("generated list allocation cap fits usize"),
    )
}

pub fn derive_input_chunk_ref(
    object: &VerifiedCasObject,
    bundle: &ProtocolBundleV1,
    limits: &SchemaLimits,
) -> Result<DerivedInputChunk, InputArtifactError> {
    Ok(derive_input_chunk(object, bundle, limits)?.public)
}

pub fn decode_verified_input_chunk(
    object: &VerifiedCasObject,
    bundle: &ProtocolBundleV1,
    limits: &SchemaLimits,
) -> Result<AuthenticatedInputChunkV1, InputArtifactError> {
    let _ = derive_input_chunk(object, bundle, limits)?;
    Ok(AuthenticatedInputChunkV1::decode_canonical(
        object.bytes(),
        limits,
    )?)
}

pub fn streaming_input_chunk_reference_root(
    expected_count: u32,
    references: impl IntoIterator<Item = Result<InputChunkRefV1, InputArtifactError>>,
    limits: &SchemaLimits,
) -> Result<B256, InputArtifactError> {
    let mut root = StreamingOrderedListRoot::new(ListKind::InputChunkReferences, expected_count)?;
    let mut actual_count = 0_u32;
    for reference in references {
        let reference = reference?;
        require(
            reference.ordinal == actual_count,
            "input chunk reference ordinal",
        )?;
        root.push(
            &reference.encode_canonical_record(limits)?,
            limits.max_bounded_bytes,
        )?;
        actual_count = actual_count
            .checked_add(1)
            .ok_or(InputArtifactError::CountOverflow)?;
    }
    require(
        actual_count == expected_count,
        "input chunk reference count",
    )?;
    Ok(root.finish()?)
}

pub fn validate_verified_input_manifest_semantics(
    catalog: &VerifiedInputChunkRefCatalog,
    reader: &FilesystemCasReader,
    bundle: &ProtocolBundleV1,
    manifest: &InputManifestV1,
    limits: &SchemaLimits,
) -> Result<(), InputArtifactError> {
    validate_verified_input_manifest_semantics_observing(
        catalog,
        reader,
        bundle,
        manifest,
        limits,
        || {},
    )
}

pub fn validate_verified_input_manifest_semantics_observing(
    catalog: &VerifiedInputChunkRefCatalog,
    reader: &FilesystemCasReader,
    bundle: &ProtocolBundleV1,
    manifest: &InputManifestV1,
    limits: &SchemaLimits,
    on_progress: impl Fn(),
) -> Result<(), InputArtifactError> {
    manifest.validate_against_bundle(bundle, limits)?;
    let mut tribute_count = 0_u32;
    let mut tribute_nominal_total = U256::ZERO;
    let mut fidelity_count = 0_u32;
    let mut oracle_count = 0_u32;
    for verified in catalog.exact_verified_cursor_observing(reader, bundle, &on_progress)? {
        let verified = verified?;
        if verified.reference.kind != InputChunkKind::Tribute
            && verified.chunk.canonical_records_or_openings.len() != 1
        {
            return Err(InputArtifactError::Invariant(
                "one opening record per input chunk",
            ));
        }
        for record in &verified.chunk.canonical_records_or_openings {
            match verified.reference.kind {
                InputChunkKind::Tribute => {
                    let tribute = decode_tribute_v1(&record.0)?;
                    require(
                        tribute.worldwide_day.value() == manifest.wwd,
                        "Tribute WWD matches manifest",
                    )?;
                    tribute_count = tribute_count
                        .checked_add(1)
                        .ok_or(InputArtifactError::CountOverflow)?;
                    tribute_nominal_total = tribute_nominal_total
                        .checked_add(tribute.nominal_amount_minor)
                        .ok_or(InputArtifactError::NominalTotalOverflow)?;
                }
                InputChunkKind::Fidelity | InputChunkKind::Oracle => {
                    let opening =
                        AuthenticatedOpeningV1::decode_canonical_record(&record.0, limits)?;
                    opening.validate_against_bundle(bundle, limits)?;
                    let _ = opening.decode_and_validate_raw_opening(
                        manifest.checkpoint.finalized_state_root,
                        limits,
                    )?;
                    match verified.reference.kind {
                        InputChunkKind::Fidelity => {
                            require(
                                opening.source_kind == OpeningSourceKind::Fidelity,
                                "Fidelity opening source",
                            )?;
                            fidelity_count = fidelity_count
                                .checked_add(1)
                                .ok_or(InputArtifactError::CountOverflow)?;
                        }
                        InputChunkKind::Oracle => {
                            require(
                                opening.source_kind == OpeningSourceKind::Oracle,
                                "Oracle opening source",
                            )?;
                            oracle_count = oracle_count
                                .checked_add(1)
                                .ok_or(InputArtifactError::CountOverflow)?;
                        }
                        InputChunkKind::Tribute => {
                            return Err(InputArtifactError::Invariant("opening chunk kind"));
                        }
                    }
                }
            }
            on_progress();
        }
    }
    require(
        tribute_count == manifest.tribute_count,
        "manifest Tribute count",
    )?;
    require(
        tribute_nominal_total == manifest.tribute_nominal_total,
        "manifest Tribute nominal total",
    )?;
    require(fidelity_count > 0, "manifest Fidelity opening set")?;
    require(oracle_count == 1, "manifest Oracle opening count")?;

    let mut fidelity_root =
        StreamingOrderedListRoot::new(ListKind::FidelityOpenings, fidelity_count)?;
    let mut oracle_root = StreamingOrderedListRoot::new(ListKind::OracleOpenings, oracle_count)?;
    for verified in catalog.exact_verified_cursor_observing(reader, bundle, &on_progress)? {
        let verified = verified?;
        let root = match verified.reference.kind {
            InputChunkKind::Tribute => continue,
            InputChunkKind::Fidelity => &mut fidelity_root,
            InputChunkKind::Oracle => &mut oracle_root,
        };
        for record in &verified.chunk.canonical_records_or_openings {
            root.push(&record.0, limits.max_bounded_bytes)?;
            on_progress();
        }
    }
    require(
        fidelity_root.finish()? == manifest.fidelity_opening_root,
        "manifest Fidelity opening root",
    )?;
    require(
        oracle_root.finish()? == manifest.oracle_opening_root,
        "manifest Oracle opening root",
    )
}

impl<'a> DurableInputArtifactPublisher<'a> {
    #[allow(clippy::too_many_arguments)]
    pub fn open(
        cas: &'a FilesystemCas,
        reader: &'a FilesystemCasReader,
        input_ref_catalog_root: impl AsRef<Path>,
        bundle: &'a ProtocolBundleV1,
        identity: InputArtifactIdentity,
        limits: SchemaLimits,
        list_limits: OrderedListLimits,
    ) -> Result<Self, InputArtifactError> {
        let protocol_bundle_hash = bundle.protocol_bundle_hash(&limits)?;
        let refs = InputRefCatalogPublisher::open_or_resume(
            input_ref_catalog_root,
            InputRefCatalogSubjectV1 {
                protocol_bundle_hash,
                job_id: identity.job_id,
                attempt: identity.attempt,
            },
            limits,
            list_limits,
        )?;
        let tribute_chunk_items = usize::try_from(PRIMARY_WORK_SHARD_SIZE)
            .map_err(|_| InputArtifactError::CountOverflow)?;
        Ok(Self {
            cas,
            reader,
            bundle,
            identity,
            limits,
            protocol_bundle_hash,
            refs: Some(refs),
            ordinal: 0,
            tribute_chunk: Vec::with_capacity(tribute_chunk_items),
            peak_tribute_chunk_len: 0,
            tribute_count: 0,
            tribute_nominal_total: U256::ZERO,
            tributes_finished: false,
            fidelity_count: 0,
            previous_fidelity_subject: None,
            oracle_root: Some(StreamingOrderedListRoot::new(ListKind::OracleOpenings, 1)?),
            oracle_published: false,
        })
    }

    pub fn publish_tribute(&mut self, canonical: Vec<u8>) -> Result<(), InputArtifactError> {
        require(!self.tributes_finished, "Tribute publication remains open")?;
        let tribute = decode_tribute_v1(&canonical)?;
        require(
            tribute.worldwide_day.value() == self.identity.wwd,
            "Tribute WWD matches input identity",
        )?;
        self.tribute_count = self
            .tribute_count
            .checked_add(1)
            .ok_or(InputArtifactError::CountOverflow)?;
        self.tribute_nominal_total = self
            .tribute_nominal_total
            .checked_add(tribute.nominal_amount_minor)
            .ok_or(InputArtifactError::NominalTotalOverflow)?;
        self.tribute_chunk
            .push(outbe_ocomp_protocol::common::BoundedBytes(canonical));
        self.peak_tribute_chunk_len = self.peak_tribute_chunk_len.max(self.tribute_chunk.len());
        if self.tribute_chunk.len()
            == usize::try_from(PRIMARY_WORK_SHARD_SIZE)
                .map_err(|_| InputArtifactError::CountOverflow)?
        {
            self.flush_tribute_chunk()?;
        }
        Ok(())
    }

    pub fn retention_stats(&self) -> Result<InputArtifactRetentionStatsV1, InputArtifactError> {
        Ok(InputArtifactRetentionStatsV1 {
            current_tribute_records: self.tribute_chunk.len(),
            peak_tribute_records: self.peak_tribute_chunk_len,
            configured_tribute_record_bound: usize::try_from(PRIMARY_WORK_SHARD_SIZE)
                .map_err(|_| InputArtifactError::CountOverflow)?,
        })
    }

    pub fn finish_tributes(&mut self) -> Result<(), InputArtifactError> {
        require(!self.tributes_finished, "Tribute publication remains open")?;
        require(self.tribute_count > 0, "Tribute input set")?;
        self.flush_tribute_chunk()?;
        self.tributes_finished = true;
        Ok(())
    }

    pub fn publish_fidelity_opening(
        &mut self,
        opening: AuthenticatedOpeningV1,
    ) -> Result<(), InputArtifactError> {
        require(self.tributes_finished, "Tributes precede Fidelity openings")?;
        require(!self.oracle_published, "Fidelity openings precede Oracle")?;
        require(
            opening.source_kind == OpeningSourceKind::Fidelity,
            "Fidelity opening source",
        )?;
        opening.validate_against_bundle(self.bundle, &self.limits)?;
        if self
            .previous_fidelity_subject
            .as_ref()
            .is_some_and(|previous| previous == &opening.canonical_subject_key.0)
        {
            return Err(InputArtifactError::Invariant(
                "adjacent Fidelity opening subject duplicate",
            ));
        }
        let canonical = opening.encode_canonical_record(&self.limits)?;
        self.fidelity_count = self
            .fidelity_count
            .checked_add(1)
            .ok_or(InputArtifactError::CountOverflow)?;
        self.previous_fidelity_subject = Some(opening.canonical_subject_key.0.clone());
        self.publish_one_record_chunk(InputChunkKind::Fidelity, canonical)
    }

    pub fn publish_oracle_opening(
        &mut self,
        opening: AuthenticatedOpeningV1,
    ) -> Result<(), InputArtifactError> {
        require(self.tributes_finished, "Tributes precede Oracle opening")?;
        require(!self.oracle_published, "exactly one Oracle opening")?;
        require(
            opening.source_kind == OpeningSourceKind::Oracle,
            "Oracle opening source",
        )?;
        opening.validate_against_bundle(self.bundle, &self.limits)?;
        let canonical = opening.encode_canonical_record(&self.limits)?;
        self.oracle_root
            .as_mut()
            .expect("Oracle root exists until finish")
            .push(&canonical, self.limits.max_bounded_bytes)?;
        self.publish_one_record_chunk(InputChunkKind::Oracle, canonical)?;
        self.oracle_published = true;
        Ok(())
    }

    pub fn finish(
        self,
        expected_tribute_count: u32,
        expected_tribute_nominal_total: U256,
        expected_fidelity_openings: u32,
        next_fidelity_opening: impl FnMut()
            -> Result<Option<AuthenticatedOpeningV1>, InputArtifactError>,
    ) -> Result<PublishedStreamingInputArtifacts, InputArtifactError> {
        self.finish_observing(
            expected_tribute_count,
            expected_tribute_nominal_total,
            expected_fidelity_openings,
            next_fidelity_opening,
            || {},
        )
    }

    pub fn finish_observing(
        mut self,
        expected_tribute_count: u32,
        expected_tribute_nominal_total: U256,
        expected_fidelity_openings: u32,
        mut next_fidelity_opening: impl FnMut() -> Result<
            Option<AuthenticatedOpeningV1>,
            InputArtifactError,
        >,
        on_progress: impl Fn(),
    ) -> Result<PublishedStreamingInputArtifacts, InputArtifactError> {
        require(self.tributes_finished, "Tribute publication closed")?;
        require(self.oracle_published, "Oracle opening published")?;
        if self.tribute_count != expected_tribute_count {
            return Err(InputArtifactError::TributeCountMismatch {
                expected: expected_tribute_count,
                actual: self.tribute_count,
            });
        }
        require(
            self.tribute_nominal_total == expected_tribute_nominal_total,
            "Tribute nominal conservation",
        )?;
        require(
            expected_fidelity_openings > 0 && expected_fidelity_openings == self.fidelity_count,
            "Fidelity opening count",
        )?;
        let mut fidelity_root =
            StreamingOrderedListRoot::new(ListKind::FidelityOpenings, expected_fidelity_openings)?;
        let mut rooted_fidelity_count = 0_u32;
        while let Some(opening) = next_fidelity_opening()? {
            require(
                opening.source_kind == OpeningSourceKind::Fidelity,
                "rooted Fidelity opening source",
            )?;
            opening.validate_against_bundle(self.bundle, &self.limits)?;
            fidelity_root.push(
                &opening.encode_canonical_record(&self.limits)?,
                self.limits.max_bounded_bytes,
            )?;
            rooted_fidelity_count = rooted_fidelity_count
                .checked_add(1)
                .ok_or(InputArtifactError::CountOverflow)?;
            on_progress();
        }
        require(
            rooted_fidelity_count == expected_fidelity_openings,
            "rooted Fidelity opening count",
        )?;
        let fidelity_opening_root = fidelity_root.finish()?;
        let oracle_opening_root = self
            .oracle_root
            .take()
            .expect("Oracle root exists until finish")
            .finish()?;
        let prepared = self
            .refs
            .take()
            .expect("input-ref publisher exists until finish")
            .prepare_observing(self.reader, self.bundle, &on_progress)?;
        on_progress();
        let summary = prepared.summary();
        if summary.tribute_count != self.tribute_count {
            return Err(InputArtifactError::TributeCountMismatch {
                expected: self.tribute_count,
                actual: summary.tribute_count,
            });
        }
        let manifest = InputManifestV1 {
            protocol_bundle_hash: self.protocol_bundle_hash,
            job_id: self.identity.job_id,
            attempt: self.identity.attempt,
            checkpoint: self.identity.checkpoint,
            wwd: self.identity.wwd,
            sealed_tribute_collection_key: self.identity.sealed_tribute_collection_key,
            sealed_tribute_collection_root: self.identity.sealed_tribute_collection_root,
            tribute_count: self.tribute_count,
            tribute_nominal_total: self.tribute_nominal_total,
            input_chunk_count: summary.input_chunk_count,
            input_chunk_list_root: summary.input_chunk_list_root,
            fidelity_opening_root,
            oracle_opening_root,
            exact_encoded_bytes: summary.exact_encoded_bytes,
            exact_record_count: summary.exact_record_count,
            body_codec_id: self.bundle.tribute_body_codec_id,
            opening_codec_registry_hash: self.bundle.opening_codec_registry_hash()?,
            compression: Compression::None,
        };
        let manifest_hash = manifest.manifest_hash(&self.limits)?;
        let mut manifest_ref = self
            .cas
            .publish_bytes(&manifest.encode_canonical(&self.limits)?)?;
        manifest_ref.expected_ocb1_kind = Some(ObjectKind::InputManifestV1.tag());
        drop(prepared.seal(self.cas, &manifest_ref, self.bundle)?);
        on_progress();
        Ok(PublishedStreamingInputArtifacts {
            manifest_ref,
            manifest_hash,
            tribute_count: self.tribute_count,
            tribute_nominal_total: self.tribute_nominal_total,
        })
    }

    fn flush_tribute_chunk(&mut self) -> Result<(), InputArtifactError> {
        if self.tribute_chunk.is_empty() {
            return Ok(());
        }
        let records = core::mem::take(&mut self.tribute_chunk);
        self.publish_chunk(InputChunkKind::Tribute, records)
    }

    fn publish_one_record_chunk(
        &mut self,
        kind: InputChunkKind,
        canonical: Vec<u8>,
    ) -> Result<(), InputArtifactError> {
        self.publish_chunk(
            kind,
            vec![outbe_ocomp_protocol::common::BoundedBytes(canonical)],
        )
    }

    fn publish_chunk(
        &mut self,
        kind: InputChunkKind,
        records: Vec<outbe_ocomp_protocol::common::BoundedBytes>,
    ) -> Result<(), InputArtifactError> {
        let next_ordinal = self
            .ordinal
            .checked_add(1)
            .ok_or(InputArtifactError::CountOverflow)?;
        let encoded = AuthenticatedInputChunkV1 {
            protocol_bundle_hash: self.protocol_bundle_hash,
            job_id: self.identity.job_id,
            kind,
            ordinal: self.ordinal,
            canonical_records_or_openings: records,
        }
        .encode_canonical(&self.limits)?;
        let mut object_ref = self.cas.publish_bytes(&encoded)?;
        object_ref.expected_ocb1_kind = Some(ObjectKind::AuthenticatedInputChunkV1.tag());
        let object = self.cas.read_verified(&object_ref)?;
        let reference = derive_input_chunk_ref(&object, self.bundle, &self.limits)?.reference;
        self.refs
            .as_mut()
            .expect("input-ref publisher exists until finish")
            .append(&reference)?;
        self.ordinal = next_ordinal;
        Ok(())
    }
}

pub fn publish_input_artifact_set(
    cas: &FilesystemCas,
    input_ref_catalog_root: impl AsRef<Path>,
    bundle: &ProtocolBundleV1,
    contents: InputArtifactContents,
    limits: &SchemaLimits,
    list_limits: OrderedListLimits,
) -> Result<PublishedInputArtifacts, InputArtifactError> {
    let InputArtifactContents {
        identity,
        canonical_tributes,
        fidelity_openings,
        oracle_opening,
    } = contents;
    let expected_tribute_count =
        u32::try_from(canonical_tributes.len()).map_err(|_| InputArtifactError::CountOverflow)?;
    let mut canonical_tributes = canonical_tributes.into_iter();
    publish_streaming_input_artifact_set(
        cas,
        input_ref_catalog_root,
        bundle,
        identity,
        expected_tribute_count,
        || Ok(canonical_tributes.next()),
        fidelity_openings,
        oracle_opening,
        limits,
        list_limits,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn publish_streaming_input_artifact_set(
    cas: &FilesystemCas,
    input_ref_catalog_root: impl AsRef<Path>,
    bundle: &ProtocolBundleV1,
    identity: InputArtifactIdentity,
    expected_tribute_count: u32,
    mut next_tribute: impl FnMut() -> Result<Option<Vec<u8>>, InputArtifactError>,
    fidelity_openings: Vec<AuthenticatedOpeningV1>,
    oracle_opening: AuthenticatedOpeningV1,
    limits: &SchemaLimits,
    list_limits: OrderedListLimits,
) -> Result<PublishedInputArtifacts, InputArtifactError> {
    require(expected_tribute_count > 0, "Tribute input set")?;
    require(!fidelity_openings.is_empty(), "Fidelity opening set")?;
    require(
        oracle_opening.source_kind == OpeningSourceKind::Oracle,
        "Oracle opening source",
    )?;
    let protocol_bundle_hash = bundle.protocol_bundle_hash(limits)?;
    let mut chunk_objects = Vec::new();
    let mut chunk_references = Vec::new();
    let mut ordinal = 0_u32;
    let tribute_chunk_items =
        usize::try_from(PRIMARY_WORK_SHARD_SIZE).map_err(|_| InputArtifactError::CountOverflow)?;

    let mut tribute_count = 0_u32;
    let mut tribute_nominal_total = U256::ZERO;
    let mut tribute_chunk = Vec::with_capacity(tribute_chunk_items);
    while let Some(canonical) = next_tribute()? {
        let tribute = decode_tribute_v1(&canonical)?;
        require(
            tribute.worldwide_day.value() == identity.wwd,
            "Tribute WWD matches input identity",
        )?;
        tribute_count = tribute_count
            .checked_add(1)
            .ok_or(InputArtifactError::CountOverflow)?;
        if tribute_count > expected_tribute_count {
            return Err(InputArtifactError::TributeCountMismatch {
                expected: expected_tribute_count,
                actual: tribute_count,
            });
        }
        tribute_nominal_total = tribute_nominal_total
            .checked_add(tribute.nominal_amount_minor)
            .ok_or(InputArtifactError::NominalTotalOverflow)?;
        tribute_chunk.push(outbe_ocomp_protocol::common::BoundedBytes(canonical));
        if tribute_chunk.len() == tribute_chunk_items {
            publish_chunk(
                cas,
                bundle,
                limits,
                AuthenticatedInputChunkV1 {
                    protocol_bundle_hash,
                    job_id: identity.job_id,
                    kind: InputChunkKind::Tribute,
                    ordinal,
                    canonical_records_or_openings: core::mem::take(&mut tribute_chunk),
                },
                &mut chunk_objects,
                &mut chunk_references,
            )?;
            ordinal = ordinal
                .checked_add(1)
                .ok_or(InputArtifactError::CountOverflow)?;
        }
    }
    if tribute_count != expected_tribute_count {
        return Err(InputArtifactError::TributeCountMismatch {
            expected: expected_tribute_count,
            actual: tribute_count,
        });
    }
    if !tribute_chunk.is_empty() {
        publish_chunk(
            cas,
            bundle,
            limits,
            AuthenticatedInputChunkV1 {
                protocol_bundle_hash,
                job_id: identity.job_id,
                kind: InputChunkKind::Tribute,
                ordinal,
                canonical_records_or_openings: tribute_chunk,
            },
            &mut chunk_objects,
            &mut chunk_references,
        )?;
        ordinal = ordinal
            .checked_add(1)
            .ok_or(InputArtifactError::CountOverflow)?;
    }
    for opening in &fidelity_openings {
        require(
            opening.source_kind == OpeningSourceKind::Fidelity,
            "Fidelity opening source",
        )?;
        publish_chunk(
            cas,
            bundle,
            limits,
            AuthenticatedInputChunkV1 {
                protocol_bundle_hash,
                job_id: identity.job_id,
                kind: InputChunkKind::Fidelity,
                ordinal,
                canonical_records_or_openings: vec![outbe_ocomp_protocol::common::BoundedBytes(
                    opening.encode_canonical_record(limits)?,
                )],
            },
            &mut chunk_objects,
            &mut chunk_references,
        )?;
        ordinal = ordinal
            .checked_add(1)
            .ok_or(InputArtifactError::CountOverflow)?;
    }
    publish_chunk(
        cas,
        bundle,
        limits,
        AuthenticatedInputChunkV1 {
            protocol_bundle_hash,
            job_id: identity.job_id,
            kind: InputChunkKind::Oracle,
            ordinal,
            canonical_records_or_openings: vec![outbe_ocomp_protocol::common::BoundedBytes(
                oracle_opening.encode_canonical_record(limits)?,
            )],
        },
        &mut chunk_objects,
        &mut chunk_references,
    )?;

    let input_chunk_count =
        u32::try_from(chunk_references.len()).map_err(|_| InputArtifactError::CountOverflow)?;
    let input_chunk_list_root = streaming_input_chunk_reference_root(
        input_chunk_count,
        chunk_references.iter().cloned().map(Ok),
        limits,
    )?;
    let fidelity_opening_root = authenticated_opening_root(
        OpeningSourceKind::Fidelity,
        &fidelity_openings,
        bundle,
        limits,
        list_limits,
    )?;
    let oracle_opening_root = authenticated_opening_root(
        OpeningSourceKind::Oracle,
        std::slice::from_ref(&oracle_opening),
        bundle,
        limits,
        list_limits,
    )?;

    let exact_encoded_bytes = chunk_references
        .iter()
        .try_fold(0_u64, |total, reference| {
            total
                .checked_add(reference.encoded_bytes)
                .ok_or(InputArtifactError::ByteCountOverflow)
        })?;
    let exact_record_count = chunk_references
        .iter()
        .try_fold(0_u32, |total, reference| {
            total
                .checked_add(reference.record_count)
                .ok_or(InputArtifactError::CountOverflow)
        })?;
    let manifest = InputManifestV1 {
        protocol_bundle_hash,
        job_id: identity.job_id,
        attempt: identity.attempt,
        checkpoint: identity.checkpoint,
        wwd: identity.wwd,
        sealed_tribute_collection_key: identity.sealed_tribute_collection_key,
        sealed_tribute_collection_root: identity.sealed_tribute_collection_root,
        tribute_count,
        tribute_nominal_total,
        input_chunk_count,
        input_chunk_list_root,
        fidelity_opening_root,
        oracle_opening_root,
        exact_encoded_bytes,
        exact_record_count,
        body_codec_id: bundle.tribute_body_codec_id,
        opening_codec_registry_hash: bundle.opening_codec_registry_hash()?,
        compression: Compression::None,
    };
    let manifest_bytes = manifest.encode_canonical(limits)?;
    let mut manifest_ref = cas.publish_bytes(&manifest_bytes)?;
    manifest_ref.expected_ocb1_kind = Some(ObjectKind::InputManifestV1.tag());
    let manifest_object = cas.read_verified(&manifest_ref)?;
    let verified = verify_input_artifact_set(
        &manifest_object,
        &chunk_objects,
        bundle,
        limits,
        list_limits,
    )?;
    let mut input_ref_catalog = VerifiedInputChunkRefCatalog::open(
        input_ref_catalog_root,
        cas,
        &manifest_ref,
        *limits,
        list_limits,
    )?;
    for reference in &chunk_references {
        let _ = input_ref_catalog.admit(reference)?;
    }
    let _ = input_ref_catalog.exact_cursor()?;

    Ok(PublishedInputArtifacts {
        manifest_ref,
        ordered_chunk_refs: chunk_objects
            .iter()
            .map(VerifiedCasObject::reference)
            .collect(),
        manifest_hash: verified.manifest_hash,
        tribute_count: verified.tribute_count,
        tribute_nominal_total: verified.tribute_nominal_total,
    })
}

pub fn verify_input_artifact_set(
    manifest_object: &VerifiedCasObject,
    chunk_objects: &[VerifiedCasObject],
    bundle: &ProtocolBundleV1,
    limits: &SchemaLimits,
    list_limits: OrderedListLimits,
) -> Result<VerifiedInputArtifacts, InputArtifactError> {
    require_expected_kind(manifest_object, ObjectKind::InputManifestV1)?;
    let manifest = InputManifestV1::decode_canonical(manifest_object.bytes(), limits)?;
    manifest.validate_against_bundle(bundle, limits)?;

    let expected_chunk_count = usize::try_from(manifest.input_chunk_count)
        .map_err(|_| InputArtifactError::CountOverflow)?;
    require(
        chunk_objects.len() == expected_chunk_count,
        "manifest input chunk count",
    )?;

    let mut references = Vec::new();
    references
        .try_reserve_exact(chunk_objects.len())
        .map_err(|_| InputArtifactError::Invariant("input chunk reference allocation"))?;
    let mut exact_encoded_bytes = 0_u64;
    let mut exact_record_count = 0_usize;
    let mut tribute_count = 0_usize;
    let mut tribute_nominal_total = U256::ZERO;
    let mut tribute_owners = BTreeSet::new();
    let mut tribute_isos = BTreeSet::from([840_u16]);
    let mut fidelity_openings = Vec::new();
    let mut oracle_openings = Vec::new();
    let mut previous_kind = None;

    for (index, object) in chunk_objects.iter().enumerate() {
        let derived = derive_input_chunk(object, bundle, limits)?;
        let expected_ordinal =
            u32::try_from(index).map_err(|_| InputArtifactError::CountOverflow)?;
        require(
            derived.ordinal == expected_ordinal,
            "input chunk ordinal sequence",
        )?;
        require(
            derived.protocol_bundle_hash == manifest.protocol_bundle_hash,
            "input chunk protocol bundle hash",
        )?;
        require(derived.job_id == manifest.job_id, "input chunk job id")?;
        if let Some(kind) = previous_kind {
            require(kind <= derived.kind, "input chunk kind order")?;
        }
        previous_kind = Some(derived.kind);

        exact_encoded_bytes = exact_encoded_bytes
            .checked_add(derived.public.reference.encoded_bytes)
            .ok_or(InputArtifactError::ByteCountOverflow)?;
        exact_record_count = exact_record_count
            .checked_add(derived.record_count)
            .ok_or(InputArtifactError::CountOverflow)?;
        tribute_count = tribute_count
            .checked_add(derived.tribute_count)
            .ok_or(InputArtifactError::CountOverflow)?;
        tribute_nominal_total = tribute_nominal_total
            .checked_add(derived.tribute_nominal_total)
            .ok_or(InputArtifactError::NominalTotalOverflow)?;
        tribute_owners.extend(derived.tribute_owners);
        tribute_isos.extend(derived.tribute_isos);
        fidelity_openings.extend(derived.fidelity_openings);
        oracle_openings.extend(derived.oracle_openings);
        references.push(derived.public.reference);
    }

    let reference_bytes = references
        .iter()
        .map(|reference| reference.encode_canonical_record(limits))
        .collect::<Result<Vec<_>, _>>()?;
    require(
        ordered_list_root(
            ListKind::InputChunkReferences,
            &reference_bytes,
            list_limits,
        )? == manifest.input_chunk_list_root,
        "input chunk reference list root",
    )?;
    require(
        exact_encoded_bytes == manifest.exact_encoded_bytes,
        "manifest exact encoded bytes",
    )?;
    require(
        u32::try_from(exact_record_count).map_err(|_| InputArtifactError::CountOverflow)?
            == manifest.exact_record_count,
        "manifest exact record count",
    )?;
    require(
        u32::try_from(tribute_count).map_err(|_| InputArtifactError::CountOverflow)?
            == manifest.tribute_count,
        "manifest Tribute count",
    )?;
    require(
        tribute_nominal_total == manifest.tribute_nominal_total,
        "manifest Tribute nominal total",
    )?;

    require(!fidelity_openings.is_empty(), "Fidelity opening set")?;
    let mut opened_owners = Vec::new();
    for opening in &fidelity_openings {
        opening.validate_against_bundle(bundle, limits)?;
        let _ = opening
            .decode_and_validate_raw_opening(manifest.checkpoint.finalized_state_root, limits)?;
        opened_owners.extend(decode_fidelity_subject_key(
            &opening.canonical_subject_key.0,
        )?);
    }
    require(
        opened_owners == tribute_owners.into_iter().collect::<Vec<_>>(),
        "Fidelity subjects cover the exact Tribute owner set",
    )?;
    require(
        authenticated_opening_root(
            OpeningSourceKind::Fidelity,
            &fidelity_openings,
            bundle,
            limits,
            list_limits,
        )? == manifest.fidelity_opening_root,
        "Fidelity opening root",
    )?;

    require(oracle_openings.len() == 1, "exactly one Oracle opening")?;
    let oracle = &oracle_openings[0];
    oracle.validate_against_bundle(bundle, limits)?;
    let _ =
        oracle.decode_and_validate_raw_opening(manifest.checkpoint.finalized_state_root, limits)?;
    let (oracle_wwd, oracle_isos) = decode_oracle_subject_key(&oracle.canonical_subject_key.0)?;
    require(oracle_wwd == manifest.wwd, "Oracle subject WWD")?;
    require(
        oracle_isos == tribute_isos.into_iter().collect::<Vec<_>>(),
        "Oracle subject covers the exact Tribute currency set",
    )?;
    require(
        authenticated_opening_root(
            OpeningSourceKind::Oracle,
            &oracle_openings,
            bundle,
            limits,
            list_limits,
        )? == manifest.oracle_opening_root,
        "Oracle opening root",
    )?;

    Ok(VerifiedInputArtifacts {
        manifest_hash: manifest.manifest_hash(limits)?,
        tribute_count: manifest.tribute_count,
        tribute_nominal_total: manifest.tribute_nominal_total,
    })
}

fn publish_chunk(
    cas: &FilesystemCas,
    bundle: &ProtocolBundleV1,
    limits: &SchemaLimits,
    chunk: AuthenticatedInputChunkV1,
    objects: &mut Vec<VerifiedCasObject>,
    references: &mut Vec<InputChunkRefV1>,
) -> Result<(), InputArtifactError> {
    let encoded = chunk.encode_canonical(limits)?;
    let mut object_ref = cas.publish_bytes(&encoded)?;
    object_ref.expected_ocb1_kind = Some(ObjectKind::AuthenticatedInputChunkV1.tag());
    let object = cas.read_verified(&object_ref)?;
    references.push(derive_input_chunk_ref(&object, bundle, limits)?.reference);
    objects.push(object);
    Ok(())
}

fn derive_input_chunk(
    object: &VerifiedCasObject,
    bundle: &ProtocolBundleV1,
    limits: &SchemaLimits,
) -> Result<DerivedChunk, InputArtifactError> {
    require_expected_kind(object, ObjectKind::AuthenticatedInputChunkV1)?;
    let chunk = AuthenticatedInputChunkV1::decode_canonical(object.bytes(), limits)?;
    require(
        chunk.protocol_bundle_hash == bundle.protocol_bundle_hash(limits)?,
        "input chunk protocol bundle binding",
    )?;
    require(
        !chunk.canonical_records_or_openings.is_empty(),
        "input chunk is non-empty",
    )?;

    let mut keys = Vec::new();
    keys.try_reserve_exact(chunk.canonical_records_or_openings.len())
        .map_err(|_| InputArtifactError::Invariant("input chunk key allocation"))?;
    let mut tribute_count = 0_usize;
    let mut tribute_nominal_total = U256::ZERO;
    let mut tribute_owners = Vec::new();
    let mut tribute_isos = Vec::new();
    let mut fidelity_openings = Vec::new();
    let mut oracle_openings = Vec::new();

    for record in &chunk.canonical_records_or_openings {
        match chunk.kind {
            InputChunkKind::Tribute => {
                let tribute = decode_tribute_v1(&record.0)?;
                keys.push(tribute.tribute_id.to_vec());
                tribute_count = tribute_count
                    .checked_add(1)
                    .ok_or(InputArtifactError::CountOverflow)?;
                tribute_nominal_total = tribute_nominal_total
                    .checked_add(tribute.nominal_amount_minor)
                    .ok_or(InputArtifactError::NominalTotalOverflow)?;
                tribute_owners.push(tribute.owner);
                tribute_isos.push(tribute.reference_currency);
            }
            InputChunkKind::Fidelity => {
                let opening = AuthenticatedOpeningV1::decode_canonical_record(&record.0, limits)?;
                require(
                    opening.source_kind == OpeningSourceKind::Fidelity,
                    "Fidelity chunk opening source",
                )?;
                opening.validate_against_bundle(bundle, limits)?;
                keys.push(opening.canonical_subject_key.0.clone());
                fidelity_openings.push(opening);
            }
            InputChunkKind::Oracle => {
                let opening = AuthenticatedOpeningV1::decode_canonical_record(&record.0, limits)?;
                require(
                    opening.source_kind == OpeningSourceKind::Oracle,
                    "Oracle chunk opening source",
                )?;
                opening.validate_against_bundle(bundle, limits)?;
                keys.push(opening.canonical_subject_key.0.clone());
                oracle_openings.push(opening);
            }
        }
    }
    require(
        keys.windows(2).all(|pair| pair[0] < pair[1]),
        "input chunk record keys strictly ordered and unique",
    )?;

    let record_count = chunk.canonical_records_or_openings.len();
    let first_key = keys
        .first()
        .cloned()
        .ok_or(InputArtifactError::Invariant("input chunk first key"))?;
    let last_key = keys
        .last()
        .cloned()
        .ok_or(InputArtifactError::Invariant("input chunk last key"))?;
    let object_reference = object.reference();
    let reference = InputChunkRefV1 {
        kind: chunk.kind,
        ordinal: chunk.ordinal,
        record_count: u32::try_from(record_count).map_err(|_| InputArtifactError::CountOverflow)?,
        first_key: outbe_ocomp_protocol::common::BoundedBytes(first_key),
        last_key_inclusive: outbe_ocomp_protocol::common::BoundedBytes(last_key),
        encoded_bytes: object_reference.encoded_bytes,
        semantic_digest: chunk.semantic_digest(limits)?,
        transport_digest: object_reference.transport_digest,
    };
    let _ = reference.encode_canonical_record(limits)?;

    Ok(DerivedChunk {
        public: DerivedInputChunk { reference },
        protocol_bundle_hash: chunk.protocol_bundle_hash,
        job_id: chunk.job_id,
        kind: chunk.kind,
        ordinal: chunk.ordinal,
        record_count,
        tribute_count,
        tribute_nominal_total,
        tribute_owners,
        tribute_isos,
        fidelity_openings,
        oracle_openings,
    })
}

fn require_expected_kind(
    object: &VerifiedCasObject,
    expected: ObjectKind,
) -> Result<(), InputArtifactError> {
    require(
        object.reference().expected_ocb1_kind == Some(expected.tag()),
        "CAS descriptor expected OCB1 kind",
    )
}

pub fn decode_fidelity_subject_key(encoded: &[u8]) -> Result<Vec<Address>, InputArtifactError> {
    let count_bytes: [u8; 4] = encoded
        .get(..4)
        .ok_or(InputArtifactError::Invariant("Fidelity subject count"))?
        .try_into()
        .map_err(|_| InputArtifactError::Invariant("Fidelity subject count"))?;
    let count = usize::try_from(u32::from_be_bytes(count_bytes))
        .map_err(|_| InputArtifactError::CountOverflow)?;
    require(
        (1..=outbe_ocomp_protocol::opening::MAX_FIDELITY_OWNERS_PER_OPENING).contains(&count),
        "Fidelity subject owner batch bound",
    )?;
    let expected_len = 4_usize
        .checked_add(
            count
                .checked_mul(20)
                .ok_or(InputArtifactError::ByteCountOverflow)?,
        )
        .ok_or(InputArtifactError::ByteCountOverflow)?;
    require(
        encoded.len() == expected_len,
        "Fidelity subject exact bytes",
    )?;

    let owners = encoded[4..]
        .chunks_exact(20)
        .map(Address::from_slice)
        .collect::<Vec<_>>();
    require(
        owners.windows(2).all(|pair| pair[0] < pair[1]),
        "Fidelity subject owners strictly ordered and unique",
    )?;
    Ok(owners)
}

pub fn decode_oracle_subject_key(encoded: &[u8]) -> Result<(u32, Vec<u16>), InputArtifactError> {
    let wwd = u32::from_be_bytes(
        encoded
            .get(..4)
            .ok_or(InputArtifactError::Invariant("Oracle subject WWD"))?
            .try_into()
            .map_err(|_| InputArtifactError::Invariant("Oracle subject WWD"))?,
    );
    let count = usize::from(u16::from_be_bytes(
        encoded
            .get(4..6)
            .ok_or(InputArtifactError::Invariant("Oracle subject ISO count"))?
            .try_into()
            .map_err(|_| InputArtifactError::Invariant("Oracle subject ISO count"))?,
    ));
    require((1..=256).contains(&count), "Oracle subject ISO bound")?;
    let expected_len = 6_usize
        .checked_add(
            count
                .checked_mul(2)
                .ok_or(InputArtifactError::ByteCountOverflow)?,
        )
        .ok_or(InputArtifactError::ByteCountOverflow)?;
    require(encoded.len() == expected_len, "Oracle subject exact bytes")?;
    let isos = encoded[6..]
        .chunks_exact(2)
        .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
        .collect::<Vec<_>>();
    require(
        isos.windows(2).all(|pair| pair[0] < pair[1]) && isos.contains(&840),
        "Oracle subject ISOs strictly ordered, unique, and include 840",
    )?;
    Ok((wwd, isos))
}

fn require(condition: bool, invariant: &'static str) -> Result<(), InputArtifactError> {
    if condition {
        Ok(())
    } else {
        Err(InputArtifactError::Invariant(invariant))
    }
}
