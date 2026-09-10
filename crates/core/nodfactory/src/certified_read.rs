//! Finalized authority projection for proof-backed certified Nod reads.
//!
//! Callers must load both inputs at the same finalized block. Neither Mongo,
//! CAS, nor a proof response may provide the trusted root.

use outbe_nod::NodCertifiedGenerationProjection;
use outbe_ocomp_protocol::{result::ActiveNodSetV1, state::ActiveGenerationV1};
use thiserror::Error;

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum CertifiedNodReadError {
    #[error("Metadosis and Nod finalized generation projections do not match")]
    ProjectionMismatch,
}

/// Joins the two independently stored owner projections into the only root
/// authority accepted by a public certified Nod read.
pub fn active_nod_set(
    active: &ActiveGenerationV1,
    nod: &NodCertifiedGenerationProjection,
) -> Result<ActiveNodSetV1, CertifiedNodReadError> {
    if active.job_id.is_zero()
        || active.program_semantics_hash.is_zero()
        || active.availability_certificate_hash.is_some()
        || nod.worldwide_day.value() == 0
        || nod.generation == 0
        || nod.issued_at == 0
        || active.job_id != nod.job_id
        || active.program_semantics_hash != nod.program_semantics_hash
        || active.nod_root != nod.nod_root
        || active.bucket_root != nod.bucket_root
        || active.output_manifest_root != nod.output_manifest_root
        || active.exact_counts.tribute_count == 0
        || active.exact_counts.tribute_count != active.exact_counts.nod_count
        || active.exact_counts.tribute_count != nod.tribute_count
        || active.exact_counts.nod_count != nod.nod_count
        || active.exact_counts.bucket_count != nod.bucket_count
        || nod.bucket_count > nod.nod_count
    {
        return Err(CertifiedNodReadError::ProjectionMismatch);
    }
    Ok(ActiveNodSetV1 {
        job_id: active.job_id,
        program_semantics_hash: active.program_semantics_hash,
        worldwide_day: nod.worldwide_day.value(),
        generation: nod.generation,
        nod_root: nod.nod_root,
        nod_count: nod.nod_count,
    })
}
