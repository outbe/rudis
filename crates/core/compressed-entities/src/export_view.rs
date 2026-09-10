//! Exact-snapshot CE authority used by the OCOMP snapshot exporter.
//!
//! This module deliberately exposes no database path, writer, generic domain
//! registry or body-store adapter. It closes one PoC Tribute partition against
//! the same immutable MDBX transaction used for every leaf authentication.

use alloy_primitives::B256;
use outbe_primitives::time::WorldwideDay;
use thiserror::Error;

use crate::{
    partition_collection_key, AuthenticatedCatalogView, AuthenticatedParentTree, Commitment,
    EntityRef, MdbxAuthenticatedTree, PartitionRef, WwdEntityId,
};

#[derive(Debug)]
pub struct AuthenticatedExportView {
    catalog: AuthenticatedCatalogView,
    tree: MdbxAuthenticatedTree,
}

impl AuthenticatedExportView {
    pub fn new(catalog: AuthenticatedCatalogView) -> Result<Self, ExportViewError> {
        let tree = MdbxAuthenticatedTree::from_view(catalog.clone())
            .map_err(|error| ExportViewError::Tree(error.to_string()))?;
        Ok(Self { catalog, tree })
    }

    /// Closes the one LYSIS_V1 source partition before any body is accepted.
    ///
    /// `exact_leaf_count` comes from a full CE leaf-table traversal inside the
    /// exact snapshot. It is intentionally independent of Mongo pagination.
    pub fn close_tribute_partition(
        &self,
        day: WorldwideDay,
        expected_collection_key: B256,
        expected_collection_root: B256,
        expected_leaf_count: u32,
    ) -> Result<AuthenticatedTributePartition<'_>, ExportViewError> {
        let partition = PartitionRef::TributeWwd(day);
        let identity = self.catalog.identity();
        let (_, collection_key) = partition_collection_key(partition)
            .map_err(|error| ExportViewError::Tree(error.to_string()))?;
        let actual_collection_key = B256::from(*collection_key.as_bytes());
        if actual_collection_key != expected_collection_key {
            return Err(ExportViewError::CollectionKeyMismatch {
                expected: expected_collection_key,
                actual: actual_collection_key,
            });
        }
        let actual_root = self
            .tree
            .partition_root_verified(partition, identity.root)
            .map_err(|error| ExportViewError::Tree(error.to_string()))?
            .ok_or(ExportViewError::MissingPartition)?;
        if actual_root != expected_collection_root {
            return Err(ExportViewError::CollectionRootMismatch {
                expected: expected_collection_root,
                actual: actual_root,
            });
        }
        let actual_count = self
            .catalog
            .collection_leaf_count(collection_key)
            .map_err(|error| ExportViewError::Tree(error.to_string()))?;
        let actual_count =
            u32::try_from(actual_count).map_err(|_| ExportViewError::LeafCountOverflow)?;
        if actual_count != expected_leaf_count {
            return Err(ExportViewError::LeafCountMismatch {
                expected: expected_leaf_count,
                actual: actual_count,
            });
        }
        Ok(AuthenticatedTributePartition {
            export: self,
            day,
            collection_root: actual_root,
            exact_leaf_count: actual_count,
        })
    }
}

#[derive(Debug)]
pub struct AuthenticatedTributePartition<'a> {
    export: &'a AuthenticatedExportView,
    day: WorldwideDay,
    pub collection_root: B256,
    pub exact_leaf_count: u32,
}

impl AuthenticatedTributePartition<'_> {
    pub fn tribute_commitment(
        &self,
        tribute_id: WwdEntityId,
    ) -> Result<Option<Commitment>, ExportViewError> {
        if tribute_id.worldwide_day() != self.day {
            return Err(ExportViewError::TributeDayMismatch {
                expected: self.day.value(),
                actual: tribute_id.worldwide_day().value(),
            });
        }
        let identity = self.export.catalog.identity();
        self.export
            .tree
            .read_leaf_verified(EntityRef::Tribute(tribute_id), identity.root)
            .map_err(|error| ExportViewError::Tree(error.to_string()))
    }
}

#[derive(Debug, Error)]
pub enum ExportViewError {
    #[error("authenticated CE export tree failed: {0}")]
    Tree(String),
    #[error("finalized Tribute partition is missing")]
    MissingPartition,
    #[error("finalized Tribute collection key mismatch: expected {expected}, got {actual}")]
    CollectionKeyMismatch { expected: B256, actual: B256 },
    #[error("finalized Tribute collection root mismatch: expected {expected}, got {actual}")]
    CollectionRootMismatch { expected: B256, actual: B256 },
    #[error("finalized Tribute leaf count does not fit u32")]
    LeafCountOverflow,
    #[error("finalized Tribute leaf count mismatch: expected {expected}, got {actual}")]
    LeafCountMismatch { expected: u32, actual: u32 },
    #[error("Tribute belongs to WWD {actual}, expected {expected}")]
    TributeDayMismatch { expected: u32, actual: u32 },
}
