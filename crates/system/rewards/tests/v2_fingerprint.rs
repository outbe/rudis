//! V3 Rewards fingerprint sensitivity tests.
//!
//! Each test pins one field of the V3 fingerprint contract: changing a
//! single bound field must change the computed fingerprint, so two
//! metadata-txes that differ in that field for the same `fb_hash` are
//! treated as contradictory by the dedup guard in
//! `check_and_record_metadata_fingerprint`.
//!

use alloy_primitives::{address, b256, Bytes, B256, U256};
use outbe_primitives::{
    block::{BlockContext, BlockRuntimeContext},
    consensus_metadata::{CertifiedParentAccountingMetadata, ParentParticipationProof},
    storage::hashmap::HashMapStorageProvider,
};
use outbe_rewards::runtime::{
    check_and_record_metadata_fingerprint, compute_metadata_fingerprint, MetadataFingerprintOutcome,
};

const CHAIN_ID: u64 = 1;
const GENESIS_TS: u64 = 1_704_067_200;

fn block_ctx(block_number: u64) -> BlockContext {
    BlockContext::new(
        block_number,
        GENESIS_TS + 60,
        CHAIN_ID,
        alloy_primitives::Address::ZERO,
        Vec::new(),
    )
}

fn base_metadata() -> CertifiedParentAccountingMetadata {
    CertifiedParentAccountingMetadata {
        finalized_block_number: 42,
        finalized_block_hash: b256!(
            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        ),
        finalized_epoch: 8,
        finalized_view: 1010,
        parent_view: 1009,
        ordered_committee: vec![
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            address!("0x3333333333333333333333333333333333333333"),
            address!("0x4444444444444444444444444444444444444444"),
        ],
        signer_bitmap: vec![1, 1, 1, 0],
        proof: Bytes::new(),
        committee_set_hash: b256!(
            "0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"
        ),
        vrf_material_version: 7,
        vrf_group_public_key_hash: b256!(
            "0xdadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadada"
        ),
        proof_kind: ParentParticipationProof::Finalization,
        missed_proposers: vec![],
    }
}

const VRF_PROOF_HASH_A: B256 =
    b256!("0x1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa");

// ---------------------------------------------------------------------------
// flipping a single bit in `signer_bitmap` changes the
// fingerprint; consequently a second metadata-tx with the perturbed
// bitmap for the same `fb_hash` is contradictory (no double-credit).
// ---------------------------------------------------------------------------

#[test]
fn v2_rewards_fingerprint_changes_on_signer_bitmap_change() {
    let m1 = base_metadata();
    let mut m2 = m1.clone();
    m2.signer_bitmap = vec![1, 1, 1, 1];

    let fp1 = compute_metadata_fingerprint(&m1, U256::from(100u64), VRF_PROOF_HASH_A);
    let fp2 = compute_metadata_fingerprint(&m2, U256::from(100u64), VRF_PROOF_HASH_A);
    assert_ne!(
        fp1, fp2,
        "V3 fingerprint must change when signer_bitmap changes"
    );

    // End-to-end through the guard: second call with perturbed bitmap
    // for the same fb_hash is contradictory.
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.enter(|handle| {
        let ctx = BlockRuntimeContext::new(block_ctx(2), handle);
        let outcome =
            check_and_record_metadata_fingerprint(&ctx, &m1, U256::from(100u64), VRF_PROOF_HASH_A)
                .unwrap();
        assert_eq!(outcome, MetadataFingerprintOutcome::Fresh);

        let err =
            check_and_record_metadata_fingerprint(&ctx, &m2, U256::from(100u64), VRF_PROOF_HASH_A)
                .unwrap_err();
        assert!(
            format!("{err}").contains("contradictory consensus metadata"),
            "perturbed bitmap must trigger contradictory-fatal; got: {err}"
        );
    });
}

// ---------------------------------------------------------------------------
// switching `proof_kind` (Finalization <->
// CertifiedNotarization) changes the fingerprint.
// ---------------------------------------------------------------------------

#[test]
fn v2_rewards_fingerprint_changes_on_proof_type_change() {
    let mut m_fin = base_metadata();
    m_fin.proof_kind = ParentParticipationProof::Finalization;
    let mut m_notar = base_metadata();
    m_notar.proof_kind = ParentParticipationProof::CertifiedNotarization;

    let fp_fin = compute_metadata_fingerprint(&m_fin, U256::from(100u64), VRF_PROOF_HASH_A);
    let fp_notar = compute_metadata_fingerprint(&m_notar, U256::from(100u64), VRF_PROOF_HASH_A);
    assert_ne!(
        fp_fin, fp_notar,
        "V3 fingerprint must change when proof_kind changes"
    );
}

// ---------------------------------------------------------------------------
// changing `vrf_material_version` OR
// `vrf_group_public_key_hash` (the "seed hash") changes the fingerprint.
// ---------------------------------------------------------------------------

#[test]
fn v2_rewards_fingerprint_changes_on_vrf_material_or_seed_hash_change() {
    let m_base = base_metadata();
    let fp_base = compute_metadata_fingerprint(&m_base, U256::from(100u64), VRF_PROOF_HASH_A);

    // Bump vrf_material_version.
    let mut m_bump_material = m_base.clone();
    m_bump_material.vrf_material_version += 1;
    let fp_bump_material =
        compute_metadata_fingerprint(&m_bump_material, U256::from(100u64), VRF_PROOF_HASH_A);
    assert_ne!(
        fp_base, fp_bump_material,
        "V3 fingerprint must change when vrf_material_version changes"
    );

    // Change vrf_group_public_key_hash (seed hash).
    let mut m_swap_seed = m_base.clone();
    m_swap_seed.vrf_group_public_key_hash =
        b256!("0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
    let fp_swap_seed =
        compute_metadata_fingerprint(&m_swap_seed, U256::from(100u64), VRF_PROOF_HASH_A);
    assert_ne!(
        fp_base, fp_swap_seed,
        "V3 fingerprint must change when vrf_group_public_key_hash (seed hash) changes"
    );
}

// ---------------------------------------------------------------------------
// the fingerprint includes the canonical VRF proof hash
// (`outbe_consensus::proof::canonical_vrf_proof_hash_v2(VrfProof)`).
// Changing the proof hash argument while keeping the metadata identical
// must change the fingerprint - proves the proof hash is bound.
// ---------------------------------------------------------------------------

#[test]
fn v2_certificate_fingerprint_includes_valid_vrf_material_and_proof_hash() {
    let m = base_metadata();
    let vrf_hash_a = VRF_PROOF_HASH_A;
    let vrf_hash_b = b256!("0x2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb");
    assert_ne!(vrf_hash_a, vrf_hash_b);

    let fp_a = compute_metadata_fingerprint(&m, U256::from(100u64), vrf_hash_a);
    let fp_b = compute_metadata_fingerprint(&m, U256::from(100u64), vrf_hash_b);
    assert_ne!(
        fp_a, fp_b,
        "V3 fingerprint must include canonical_vrf_proof_hash"
    );

    // Cross-check: with the same proof hash AND the same metadata, the
    // fingerprint is deterministic (re-computing returns the same B256).
    let fp_a_again = compute_metadata_fingerprint(&m, U256::from(100u64), vrf_hash_a);
    assert_eq!(fp_a, fp_a_again, "fingerprint must be deterministic");
}
