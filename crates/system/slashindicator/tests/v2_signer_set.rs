//! SlashIndicator V2 invariants for the V2-Certified-Parent
//! Accounting epic.
//!
//! - `slash_voter` is proof-kind agnostic - absent
//!   signers from a `Finalization` certificate slash to the exact same
//!   on-chain state as absent signers from a `CertifiedNotarization`
//!   certificate. The slash hook itself takes only `(fb_hash,
//!   validator)`; the test pins this by running the hook twice with
//!   the same absent address against two distinct `fb_hash` values
//!   that represent the two proof types and asserting identical
//!   per-validator counters.
//!   (e2e guard): non-empty `missed_proposers` in V2 metadata
//!   is rejected by `outbe_consensus::proof::verify_v2_proof` BEFORE
//!   the Phase 1 commit reaches the slashindicator entry. Verified
//!   structurally because constructing a full executor in this test
//!   crate is impractical.

use alloy_primitives::{address, b256, Address, B256};
use outbe_primitives::storage::{hashmap::HashMapStorageProvider, StorageHandle};
use outbe_slashindicator::{contract::SlashIndicator, hooks};

const CHAIN_ID: u64 = 1;
const ABSENT_VAL: Address = address!("0xabababababababababababababababababababab");

const FB_HASH_FINAL: B256 =
    b256!("0xf1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1f1");
const FB_HASH_NOTAR: B256 =
    b256!("0xf2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2f2");

fn with_storage<R>(f: impl FnOnce(StorageHandle) -> R) -> R {
    let mut provider = HashMapStorageProvider::new(CHAIN_ID);
    provider.enter(f)
}

// ---------------------------------------------------------------------------
// proof-kind agnostic slashing.
// ---------------------------------------------------------------------------

#[test]
fn certified_notarization_and_finalization_slash_absent_signers_identically() {
    // Per-fb_hash isolation is the contract: two distinct fb_hashes
    // representing two proof types each increment the validator's
    // counter by exactly one. The counter is therefore +2 after both
    // proof kinds have been processed - the SAME outcome you'd get if
    // both kinds were Finalization, or both were CertifiedNotarization.
    let final_count = with_storage(|storage| {
        hooks::slash_window_voters(storage.clone(), FB_HASH_FINAL, &[ABSENT_VAL]).unwrap();
        hooks::slash_window_voters(storage.clone(), FB_HASH_NOTAR, &[ABSENT_VAL]).unwrap();

        let si = SlashIndicator::new(storage);
        si.voter_miss_count.read(&ABSENT_VAL).unwrap()
    });

    let homogeneous_count = with_storage(|storage| {
        // Same two fb_hashes, both pretending to be Finalization
        // (proof_kind is not an input to `slash_voter`). Counter
        // outcome must match the heterogeneous case.
        hooks::slash_window_voters(storage.clone(), FB_HASH_FINAL, &[ABSENT_VAL]).unwrap();
        hooks::slash_window_voters(storage.clone(), FB_HASH_NOTAR, &[ABSENT_VAL]).unwrap();

        let si = SlashIndicator::new(storage);
        si.voter_miss_count.read(&ABSENT_VAL).unwrap()
    });

    assert_eq!(
        final_count, 2,
        "two distinct fb_hashes must each increment the absent-voter counter by exactly one"
    );
    assert_eq!(
        final_count, homogeneous_count,
        "slash_voter is proof-kind agnostic - heterogeneous proof types produce the \
         same state change as homogeneous ones"
    );

    // Per-fb_hash dedup is also unchanged. A duplicate hook for the
    // same `(fb_hash, validator)` is a no-op - proves the guard runs
    // regardless of how the absent address was discovered (which
    // certificate type produced it).
    let dedup_count = with_storage(|storage| {
        hooks::slash_window_voters(storage.clone(), FB_HASH_FINAL, &[ABSENT_VAL]).unwrap();
        hooks::slash_window_voters(storage.clone(), FB_HASH_FINAL, &[ABSENT_VAL]).unwrap();
        hooks::slash_window_voters(storage.clone(), FB_HASH_FINAL, &[ABSENT_VAL]).unwrap();

        let si = SlashIndicator::new(storage);
        si.voter_miss_count.read(&ABSENT_VAL).unwrap()
    });
    assert_eq!(
        dedup_count, 1,
        "per-(fb_hash, validator) dedup is preserved across proof kinds"
    );
}

// (e2e guard) was a source-text grep over `verify_v2_proof` that
// asserted (a) the `V2VerifyError::NonEmptyMissedProposers` rejection exists
// and (b) it precedes the Rule 2 exact-parent check. Both are now
// covered behaviourally in
// `crates/blockchain/consensus/tests/proof_verifier.rs`
// (`verifier_rejects_non_empty_missed_proposers_*` and the ordering
// tests), so the source-grep was redundant *and* brittle to renames.
