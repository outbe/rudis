use alloy_primitives::{B256, U256};
use outbe_nod::NodCertifiedGenerationProjection;
use outbe_nodfactory::certified_read::active_nod_set;
use outbe_ocomp_protocol::{result::ExactCountsV1, state::ActiveGenerationV1};
use outbe_primitives::time::WorldwideDay;

const WWD: u32 = 20_260_726;

fn active_generation() -> ActiveGenerationV1 {
    ActiveGenerationV1 {
        job_id: B256::with_last_byte(1),
        program_semantics_hash: B256::with_last_byte(2),
        nod_root: B256::with_last_byte(3),
        bucket_root: B256::with_last_byte(4),
        contributor_root: B256::with_last_byte(5),
        output_manifest_root: B256::with_last_byte(6),
        exact_counts: ExactCountsV1 {
            tribute_count: 257,
            nod_count: 257,
            bucket_count: 10,
            contributor_count: 250,
            semantic_event_count: 0,
        },
        result_evidence_hash: B256::with_last_byte(7),
        availability_certificate_hash: None,
    }
}

fn nod_projection() -> NodCertifiedGenerationProjection {
    NodCertifiedGenerationProjection {
        worldwide_day: WorldwideDay::new(WWD),
        generation: 9,
        job_id: B256::with_last_byte(1),
        program_semantics_hash: B256::with_last_byte(2),
        protocol_bundle_hash: B256::repeat_byte(0x5b),
        nod_root: B256::with_last_byte(3),
        bucket_root: B256::with_last_byte(4),
        output_manifest_root: B256::with_last_byte(6),
        tribute_count: 257,
        nod_count: 257,
        bucket_count: 10,
        nod_amount_total: U256::from(1_000),
        nod_gratis_consumed: U256::from(500),
        issued_at: 1_785_024_000,
        next_nod_ordinal: 0,
        last_progress_height: 1,
    }
}

#[test]
fn matching_finalized_owner_projections_form_one_nod_root_authority() {
    let active = active_generation();
    let projection = nod_projection();

    let authority = active_nod_set(&active, &projection).unwrap();

    assert_eq!(authority.job_id, active.job_id);
    assert_eq!(
        authority.program_semantics_hash,
        active.program_semantics_hash
    );
    assert_eq!(authority.worldwide_day, WWD);
    assert_eq!(authority.generation, projection.generation);
    assert_eq!(authority.nod_root, active.nod_root);
    assert_eq!(authority.nod_count, 257);
}

#[test]
fn inconsistent_finalized_owner_projections_never_form_an_authority() {
    let active = active_generation();

    let mut wrong_root = nod_projection();
    wrong_root.nod_root = B256::with_last_byte(30);
    assert!(active_nod_set(&active, &wrong_root).is_err());

    let mut wrong_count = nod_projection();
    wrong_count.nod_count -= 1;
    assert!(active_nod_set(&active, &wrong_count).is_err());

    let mut wrong_bucket = nod_projection();
    wrong_bucket.bucket_root = B256::with_last_byte(40);
    assert!(active_nod_set(&active, &wrong_bucket).is_err());

    let mut wrong_manifest = nod_projection();
    wrong_manifest.output_manifest_root = B256::with_last_byte(60);
    assert!(active_nod_set(&active, &wrong_manifest).is_err());
}
