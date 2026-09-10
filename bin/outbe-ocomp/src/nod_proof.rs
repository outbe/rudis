//! Proof-backed reads of certified Lysis V1 Nod output.
//!
//! The builder accepts its root authority separately from validator-local
//! artifacts. It cold-reloads the exact closed result catalog, streams every
//! canonical Nod action with bounded memory, and returns a proof only when the
//! resulting path verifies against that authority.

use outbe_ocomp_protocol::{
    list::try_streaming_ordered_list_membership_proof,
    result::{ActiveNodSetV1, NodActionV1, NodMembershipProofV1},
    ListKind, ProtocolError,
};
use thiserror::Error;

use crate::{
    lysis_plan_audit::LocalLysisPlanAuditV1,
    lysis_result_catalog::{
        ExactLysisResultCatalogCursorV1, LysisResultCatalogError, LysisResultCatalogStepV1,
    },
};

#[derive(Debug, Error)]
pub enum NodProofBuildError {
    #[error(transparent)]
    Catalog(#[from] LysisResultCatalogError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("active Nod authority does not describe the audited Lysis result")]
    AuthorityMismatch,
    #[error("the exact result catalog did not yield the requested Nod")]
    MissingTarget,
}

/// Builds one proof from cold-reloaded, content-addressed result chunks.
///
/// Memory is bounded by one result chunk plus the Merkle frontier. This PoC
/// implementation scans the exact action population once per requested proof;
/// an indexed proof cache is intentionally outside the PoC scope.
pub fn build_certified_nod_proof<'audit>(
    audit: &'audit LocalLysisPlanAuditV1<'audit>,
    authority: &ActiveNodSetV1,
    target_ordinal: u32,
) -> Result<NodMembershipProofV1, NodProofBuildError> {
    let plan = audit.plan();
    if authority.job_id != plan.job_id
        || authority.program_semantics_hash != audit.bundle().bundle().lysis_program_semantics_hash
        || authority.worldwide_day != plan.wwd
        || authority.nod_count != plan.tribute_count
    {
        return Err(NodProofBuildError::AuthorityMismatch);
    }

    let mut records = ExactNodRecordCursorV1::open(audit, target_ordinal)?;
    let membership_siblings = try_streaming_ordered_list_membership_proof(
        ListKind::NodActions,
        authority.nod_count,
        target_ordinal,
        &mut records,
        audit.limits().max_bounded_bytes,
    )?;
    let action = records
        .target_action
        .take()
        .ok_or(NodProofBuildError::MissingTarget)?;
    let proof = NodMembershipProofV1 {
        job_id: authority.job_id,
        program_semantics_hash: authority.program_semantics_hash,
        worldwide_day: authority.worldwide_day,
        generation: authority.generation,
        nod_ordinal: target_ordinal,
        action,
        membership_siblings,
    };
    proof.verify_against(authority, audit.limits())?;
    Ok(proof)
}

struct CanonicalNodRecordV1(Vec<u8>);

impl AsRef<[u8]> for CanonicalNodRecordV1 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

struct ExactNodRecordCursorV1<'audit> {
    catalog: ExactLysisResultCatalogCursorV1<'audit>,
    limits: &'audit outbe_ocomp_protocol::SchemaLimits,
    current: std::vec::IntoIter<NodActionV1>,
    target_ordinal: u32,
    target_action: Option<NodActionV1>,
    complete: bool,
}

impl<'audit> ExactNodRecordCursorV1<'audit> {
    fn open(
        audit: &'audit LocalLysisPlanAuditV1<'audit>,
        target_ordinal: u32,
    ) -> Result<Self, NodProofBuildError> {
        Ok(Self {
            catalog: ExactLysisResultCatalogCursorV1::open(audit)?,
            limits: audit.limits(),
            current: Vec::new().into_iter(),
            target_ordinal,
            target_action: None,
            complete: false,
        })
    }
}

impl Iterator for ExactNodRecordCursorV1<'_> {
    type Item = Result<CanonicalNodRecordV1, NodProofBuildError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(action) = self.current.next() {
                if action.raw_ordinal == self.target_ordinal {
                    self.target_action = Some(action.clone());
                }
                return Some(
                    action
                        .encode_canonical_record(self.limits)
                        .map(CanonicalNodRecordV1)
                        .map_err(Into::into),
                );
            }
            match self.catalog.next() {
                Some(Ok(LysisResultCatalogStepV1::Chunk(chunk))) => {
                    self.current = chunk.chunk().ordered_nod_actions.clone().into_iter();
                }
                Some(Ok(LysisResultCatalogStepV1::Complete)) => {
                    self.complete = true;
                    return None;
                }
                Some(Ok(_)) => {}
                Some(Err(error)) => return Some(Err(error.into())),
                None if self.complete => return None,
                None => {
                    self.complete = true;
                    return Some(Err(ProtocolError::InvalidInvariant(
                        "exact result catalog completion marker",
                    )
                    .into()));
                }
            }
        }
    }
}
