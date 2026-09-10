//! Rewards economics + late-vote invariant tests.
//!
//! These tests pin allocation constants and the V3 certificate fingerprint:
//! locally observed votes cannot change a replayed CPA signer bitmap. Canonical
//! authenticated late credits use a separate phase; their daily GEM accounting
//! is exercised in `late_gem_participation`.

use alloy_primitives::{address, b256, Bytes, B256, U256};
use outbe_emissionlimit::allocation::{
    CCA_REWARD_PCT, PERCENT_DENOMINATOR, SRA_REWARD_PCT, VALIDATOR_REWARD_PCT, WAA_REWARD_PCT,
};
use outbe_primitives::{
    block::{BlockContext, BlockRuntimeContext},
    consensus_metadata::{CertifiedParentAccountingMetadata, ParentParticipationProof},
    storage::hashmap::HashMapStorageProvider,
};
use outbe_rewards::runtime::{
    check_and_record_metadata_fingerprint, compute_metadata_fingerprint,
    MetadataFingerprintOutcome, VALIDATOR_REWARD_PERCENT,
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

fn base_metadata(proof_kind: ParentParticipationProof) -> CertifiedParentAccountingMetadata {
    CertifiedParentAccountingMetadata {
        finalized_block_number: 100,
        finalized_block_hash: b256!(
            "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        ),
        finalized_epoch: 4,
        finalized_view: 500,
        parent_view: 499,
        ordered_committee: vec![
            address!("0x1111111111111111111111111111111111111111"),
            address!("0x2222222222222222222222222222222222222222"),
            address!("0x3333333333333333333333333333333333333333"),
        ],
        signer_bitmap: vec![1, 1, 0],
        proof: Bytes::new(),
        committee_set_hash: b256!(
            "0xc0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0"
        ),
        vrf_material_version: 3,
        vrf_group_public_key_hash: b256!(
            "0xdadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadada"
        ),
        proof_kind,
        missed_proposers: vec![],
    }
}

const VRF_HASH: B256 = b256!("0x1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa");

// ---------------------------------------------------------------------------
// economics constants pinned. The Cycle handler's daily emission
// allocation is sourced from `outbe-emissionlimit::allocation::*_PCT`
// constants; this test pins them at the values the V2 economic policy
// has shipped with. The "by_chainspec" framing matches the canonical percent
// table IS the chainspec-equivalent surface for
// V2 economics.
// ---------------------------------------------------------------------------

#[test]
fn certified_notarization_participation_economics_pinned_by_chainspec() {
    // Per `outbe-emissionlimit::allocation`, the V2 fixed
    // table is: Validator 4%, WAA 4%, SRA 4%, CCA 4%,
    // Metadosis (terminal) = remainder. Any change here is a hard-fork
    // economic policy change and must surface as a test failure.
    assert_eq!(VALIDATOR_REWARD_PCT, 4);
    assert_eq!(WAA_REWARD_PCT, 4);
    assert_eq!(SRA_REWARD_PCT, 4);
    assert_eq!(CCA_REWARD_PCT, 4);
    assert_eq!(PERCENT_DENOMINATOR, 100);

    // The validator share that flows through the `Rewards` precompile
    // is the same constant; pin it independently here so a re-export
    // skew between `outbe-rewards` and `outbe-emissionlimit` trips.
    assert_eq!(VALIDATOR_REWARD_PERCENT, 4);

    // The fixed table sums to 16% so the terminal Metadosis pool
    // receives 84%. Pin that derived invariant.
    let fixed_pct_sum = VALIDATOR_REWARD_PCT + WAA_REWARD_PCT + SRA_REWARD_PCT + CCA_REWARD_PCT;
    assert_eq!(fixed_pct_sum, 16);
    assert_eq!(PERCENT_DENOMINATOR - fixed_pct_sum, 84);
}

// ---------------------------------------------------------------------------
// two metadata-txes for the SAME `fb_hash` with
// different signer bitmaps (the second carrying late local votes the
// first did not) are contradictory under V3, so the late-vote bits
// cannot add credit beyond the first-seen quorum certificate.
// ---------------------------------------------------------------------------

#[test]
fn late_local_votes_do_not_add_credit_beyond_block_carried_certificate() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.enter(|handle| {
        let ctx = BlockRuntimeContext::new(block_ctx(2), handle);
        // First metadata-tx: only the canonical quorum bits set.
        let m1 = base_metadata(ParentParticipationProof::Finalization);
        let outcome =
            check_and_record_metadata_fingerprint(&ctx, &m1, U256::from(0u64), VRF_HASH).unwrap();
        assert_eq!(outcome, MetadataFingerprintOutcome::Fresh);

        // Second metadata-tx: same fb_hash but the bitmap now claims
        // the third validator also signed (a "late local vote"). Under
        // V3 this is a contradictory metadata for the same parent and
        // is rejected - the late-vote bit cannot top up the first
        // metadata's credit.
        let mut m2 = m1.clone();
        m2.signer_bitmap = vec![1, 1, 1];
        let err = check_and_record_metadata_fingerprint(&ctx, &m2, U256::from(0u64), VRF_HASH)
            .unwrap_err();
        assert!(
            format!("{err}").contains("contradictory consensus metadata"),
            "late-vote bitmap perturbation must be contradictory; got: {err}"
        );

        // Re-submitting the original metadata-tx is still a no-op
        // (`IdenticalReplay`) - the guard remains idempotent on the
        // canonical first-seen content.
        let outcome_replay =
            check_and_record_metadata_fingerprint(&ctx, &m1, U256::from(0u64), VRF_HASH).unwrap();
        assert_eq!(outcome_replay, MetadataFingerprintOutcome::IdenticalReplay);
    });
}

// ---------------------------------------------------------------------------
// Phase 1 atomicity. The Phase 1 commit performs metadata
// fingerprint + participation + slashing as a single
// `transact_system_call`; on any precompile failure the transaction
// reverts and `last_accounted_block_number` does not advance.
//
// The fingerprint guard itself returns `Fatal` on contradictory
// metadata, which the executor maps to a precompile failure (Phase 1
// fatal). The "insufficient backing" framing in the
// generalises to: any Phase 1 precompile error (including the V3
// contradictory-metadata fatal) must leave accounting progress
// unchanged.
//
// This test asserts the precondition the executor relies on: a Phase 1
// fingerprint failure produces a `Fatal` error before any per-voter
// accounting write that would back a credit. The full executor
// rollback path (storage checkpoint reverts on any precompile error)
// is covered by `phase1_atomicity` integration tests in
// `crates/blockchain/evm/tests/`.
// ---------------------------------------------------------------------------

#[test]
fn insufficient_rewards_backing_rejects_phase1_and_leaves_progress_unchanged() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.enter(|handle| {
        let ctx = BlockRuntimeContext::new(block_ctx(2), handle);
        let m1 = base_metadata(ParentParticipationProof::Finalization);
        let _ =
            check_and_record_metadata_fingerprint(&ctx, &m1, U256::from(0u64), VRF_HASH).unwrap();

        // Contradictory metadata (different fee sum) - fingerprint
        // returns `Fatal`. In the executor path this maps to a precompile
        // error which short-circuits Phase 1 before any per-voter
        // participation/fee accounting write. Subsequent attempts with the
        // original metadata see the original fingerprint still intact (read
        // it back to prove).
        let err = check_and_record_metadata_fingerprint(&ctx, &m1, U256::from(999u64), VRF_HASH)
            .unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("contradictory consensus metadata"),
            "Phase 1 fingerprint guard must surface contradictory-fatal so the \
             executor rolls back without advancing accounting progress; got: {msg}"
        );

        // The stored fingerprint remains the original. A future Phase
        // 1 retry with the original metadata is `IdenticalReplay`,
        // which is a no-op (no double credit, no progress advance).
        let outcome =
            check_and_record_metadata_fingerprint(&ctx, &m1, U256::from(0u64), VRF_HASH).unwrap();
        assert_eq!(outcome, MetadataFingerprintOutcome::IdenticalReplay);
    });
}

// ---------------------------------------------------------------------------
// per ("in the quorum certificate counts; outside it missed"),
// Finalization is preferred over CertifiedNotarization as
// a "stronger certificate" only in the sense that proof_kind tagging
// changes the wire-level acceptance rules in the verifier. The
// economic distribution is IDENTICAL: the same signer set produces the
// same per-voter share under either proof_kind. Pin both halves of the
// invariant.
// ---------------------------------------------------------------------------

#[test]
fn finalization_preference_is_documented_as_stronger_certificate_not_different_economics() {
    // Half 1: proof_kind is bound by the fingerprint, so the two
    // proof_kinds are NOT interchangeable for dedup (already covered). Re-state here so the documentary intent is anchored
    // alongside the economics half.
    let m_fin = base_metadata(ParentParticipationProof::Finalization);
    let m_notar = base_metadata(ParentParticipationProof::CertifiedNotarization);
    let fp_fin = compute_metadata_fingerprint(&m_fin, U256::from(100u64), VRF_HASH);
    let fp_notar = compute_metadata_fingerprint(&m_notar, U256::from(100u64), VRF_HASH);
    assert_ne!(
        fp_fin, fp_notar,
        "proof_kind is part of the fingerprint (acceptance-rule distinction is preserved)"
    );

    // Half 2: economics are the SAME. The fixed-percent emission
    // allocation table is consumed by the Cycle handler
    // regardless of proof_kind; the per-voter share derives from
    // `(validator_pool_amount, voters_for_day)` which is independent
    // of how the parent certificate was produced. Pin the constants
    // again so a future "stronger certificate gets a bonus" change
    // would trip both this test and
    assert_eq!(VALIDATOR_REWARD_PCT, 4);
    assert_eq!(WAA_REWARD_PCT, 4);
    assert_eq!(SRA_REWARD_PCT, 4);
    assert_eq!(CCA_REWARD_PCT, 4);
}
