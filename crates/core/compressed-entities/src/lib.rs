//! Canonical compressed-body identities, encodings, and commitments.

// Persistence errors intentionally retain both exact markers/identities so a
// startup or finality conflict can be diagnosed without a second database read.
#![allow(clippy::result_large_err)]

mod api;
mod collection;
mod collection_reconstruction;
mod commitment;
mod errors;
mod export_view;
mod lifecycle;
mod persistence;
mod proof;
mod protobuf;
mod replay;
mod runtime;
mod schema;
mod sharding;
mod smt;
mod staging;
mod state;
mod tree_manager;
mod tree_service;

#[doc(hidden)]
pub mod bench_support;

pub use api::{
    begin_block, delete, end_block, list, mint, preview_end_block, read, retire_partition, update,
    AuthenticatedParentTree, AuthenticatedParentTreeFactory, BodyInput, CeWorkCheckpoint,
    CeWorkConfig, EntityRef, ExecutionScope, ExplicitGasCheckpoint, ExplicitGasWindow,
    FinalLeafMutation, IdPage, IdPageRequest, ParentBodySource, ParentBodySourceRef, PartitionRef,
    QueryRef, RetirementOutcome, SealedCollectionRoot, VerifiedBody, VerifiedBodyPage,
    VerifiedPayload, MAX_ID_PAGE_LIMIT,
};

pub use collection::{
    collection_key, collection_root, partition_collection_key, sealed_root,
    tribute_partition_root_from_leaves, CeDomain, CeTopologyV1, CollectionKey, K_PROVISIONAL,
};
pub use collection_reconstruction::{
    BoundedTributePartitionVerifier, TributePartitionExpectationV1,
    TributePartitionReconstructionError, TributePartitionRetentionStatsV1,
    TributePartitionWorkConfig, VerifiedTributePartition,
};
pub use commitment::{
    body_commitment, derive_poseidon_digest, derive_poseidon_entity_id, identity_field, pbytes,
    Commitment, CommitmentError, ACTIVE_COMMITMENT_SCHEME, CES1_TAG_BASE, TAG_BODY,
    TAG_BYTES_ABSORB, TAG_BYTES_FINAL, TAG_BYTES_INIT, TAG_COLLECTION_KEY, TAG_COLLECTION_ROOT,
    TAG_ID, TAG_KEY, TAG_LEAF, TAG_SEALED_ROOT, TAG_SMT_BASE, TAG_SMT_NORMAL, TAG_SMT_ZERO,
    TAG_TOP_NODE,
};
pub use errors::ParentBodySourceError;
pub use export_view::{AuthenticatedExportView, AuthenticatedTributePartition, ExportViewError};
pub use lifecycle::{
    preview_end_block as preview_lifecycle_end_block, CompressedEntitiesLifecycle,
    CompressedEntitiesLifecycleContext, SealOutput,
};
pub use outbe_primitives::wwd_entity_id::WwdEntityId;
pub use persistence::{
    classify_restart, ApplyOutcome, CeMdbx, CeMdbxReadOnly, CeRetentionCursor,
    DurableFinalizedCheckpoint, EnvironmentIdentity, ExactParentIdentity, FinalizationStage,
    FinalizedMarker, PersistenceError, RestartClassification, TreeNamespace, CE_SMT_RELATIVE_PATH,
    LOCAL_STORAGE_SCHEMA_VERSION,
};
pub use proof::{
    verify_point_read_v1, AbsentEvidenceV1, CkbCompiledProofV1, PointProofCommonV1,
    PointReadRequestError, PointReadRequestV1, PointReadResultV1, PointReadServiceError,
    PresentEvidenceV1, SelectedHeaderV1, VerifiedPointReadV1, PROOF_ENCODING_VERSION_V1,
};
pub use protobuf::{
    decode_nod_bucket_v1, decode_nod_item_v1, decode_stored_nod_bucket_v1,
    decode_stored_nod_item_v1, decode_stored_tribute_v1, decode_tribute_v1, encode_nod_bucket_v1,
    encode_nod_item_v1, encode_tribute_v1, CanonicalBodyError, NodBucketBodyV1, NodItemBodyV1,
    StoredBody, TributeBodyV1, BODY_SCHEMA_V1,
};
pub use replay::{
    decode_canonical_body_event, decode_partition_retirement,
    reconstruct_effective_final_mutations, CanonicalBodyEvent, ReplayEventError,
};
pub use sharding::{empty_shard_top_root, ShardingError, K_CANDIDATES};
pub use staging::{
    AuthenticatedCatalogView, CandidateCache, CandidateCacheLimits, CollectionBatch,
    CollectionOperation, ProvisionalCatalogBatch, ProvisionalShardBatch, ProvisionalShardSetBatch,
    ProvisionalTreeBatch, PublicationOutcome, RetirementBatch, StagedTreeBatch, StagingError,
    TreeChange,
};
pub use tree_manager::{
    CompressedTreeService, ExportLeaseOffer, ExportLeaseOpenAck, ExportLeaseStatus,
    FinalizedCandidateOutcome, TreeServiceError, DEFAULT_EXPORT_LEASE_OPEN_TIMEOUT,
};
pub use tree_service::MdbxAuthenticatedTree;

#[cfg(test)]
mod tests;
