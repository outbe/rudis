//! - handler / selector behaviour tests
//!
//! The full ApplicationHandler is wired across the whole consensus stack and
//! is exercised end-to-end by `stack_tests.rs`; the tests here pin the V1
//! selector removal at the API surface and exercise the non-blocking
//! `ParentProofSelector` against the same proof-store substrate the proposer
//! reads in production.
//!
//! - `missing_direct_parent_proof_does_not_wait_for_future_finalization` -
//!   (the V1 polling waiter is gone; selector returns synchronously).

use alloy_primitives::B256;
use outbe_consensus::finalization::{
    parent_cert_store::{
        CertifiedParentProofRecord, CertifiedParentProofStore, FinalizedParentCertStore, ProofKind,
    },
    selection::ParentProofSelector,
};
use outbe_primitives::consensus_metadata::ParentParticipationProof;
use std::time::Instant;

fn record(
    block_number: u64,
    hash: B256,
    proof_type: ParentParticipationProof,
) -> CertifiedParentProofRecord {
    let kind = match proof_type {
        ParentParticipationProof::Finalization => ProofKind::Finalization {
            finalized_block_number: block_number,
        },
        ParentParticipationProof::CertifiedNotarization => ProofKind::CertifiedNotarization,
    };
    CertifiedParentProofRecord {
        kind,
        finalized_block_hash: hash,
        stored_at_height: block_number,
        ..CertifiedParentProofRecord::default()
    }
}

/// `rg -n "await_parent_cert" crates/blockchain/consensus/src/`
/// must return 0 hits in non-test code. Performed in-process so the
/// assertion runs on every `cargo nextest` invocation.
#[test]
fn await_parent_cert_is_removed_from_non_test_consensus_src() {
    use std::io::Read;
    let mut total_non_test_hits = 0usize;
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    fn walk(dir: &std::path::Path, hits: &mut usize) {
        let read = match std::fs::read_dir(dir) {
            Ok(r) => r,
            Err(_) => return,
        };
        for entry in read.flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, hits);
                continue;
            }
            if path.extension().and_then(|s| s.to_str()) != Some("rs") {
                continue;
            }
            let file_name = path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or_default();
            // Treat *_tests.rs files and test_harness.rs as test code.
            if file_name.contains("_tests") || file_name.starts_with("test_") {
                continue;
            }
            let mut content = String::new();
            if std::fs::File::open(&path)
                .and_then(|mut f| f.read_to_string(&mut content))
                .is_err()
            {
                continue;
            }
            for line in content.lines() {
                if line.contains("await_parent_cert") {
                    // Allow docstring mentions that reference the historical
                    // method name (these survive as comments). The
                    // contract is "non-test executable code"; mentions inside
                    // `//!` / `///` / `//` lines are documentation only.
                    let trimmed = line.trim_start();
                    if trimmed.starts_with("//") {
                        continue;
                    }
                    *hits += 1;
                    eprintln!("await_parent_cert hit in {}: {}", path.display(), line);
                }
            }
        }
    }
    walk(&root, &mut total_non_test_hits);
    assert_eq!(
        total_non_test_hits, 0,
        "await_parent_cert must not exist in non-test consensus src code"
    );
}

#[test]
fn certified_notarized_parent_does_not_block_proposal() {
    // with a CertifiedNotarization record for the requested parent,
    // the selector returns synchronously - no polling, no future-finalization
    // wait. The V1 path could deadlock here (view 61 reproduction).
    let store = FinalizedParentCertStore::new();
    let hash = B256::with_last_byte(0xAA);
    store
        .put_certified_notarization(record(
            42,
            hash,
            ParentParticipationProof::CertifiedNotarization,
        ))
        .unwrap();
    let selector = ParentProofSelector::new(store);

    let start = Instant::now();
    // The non-wait selector treats a certified-notarization record as
    // witness-only: it returns `None` synchronously (no polling, no
    // future-finalization wait), so a CN parent cannot deadlock the proposer.
    let result = selector.select_direct_parent_proof(0, 0, 42, hash);
    let elapsed = start.elapsed();

    assert!(
        result.is_none(),
        "certified-notarization is witness-only on the non-wait path"
    );
    // The CN witness remains in the store and, once promoted by the selector,
    // projects to V2 metadata at the known parent block number.
    let key =
        outbe_consensus::finalization::parent_cert_store::CertifiedParentProofKey::new(0, 0, hash);
    let witness = selector
        .parent_cert_store()
        .get_certified_notarization(key)
        .expect("CN witness must remain in the store");
    assert_eq!(
        witness.proof_kind(),
        ParentParticipationProof::CertifiedNotarization
    );
    let metadata = witness.to_v2_metadata(42);
    assert_eq!(metadata.finalized_block_number, 42);
    assert_eq!(metadata.finalized_block_hash, hash);
    // budget: synchronous lookup completes in microseconds, not the
    // legacy 25 ms poll interval.
    assert!(
        elapsed.as_millis() < 10,
        "selector must be non-blocking; took {elapsed:?}"
    );
}

#[test]
fn finalized_parent_uses_finalization_proof_when_available() {
    // across two slots: both finalization AND certified-notarization
    // present for the same parent -> finalization wins.
    let store = FinalizedParentCertStore::new();
    let hash = B256::with_last_byte(0xBB);
    store
        .put_certified_notarization(record(
            7,
            hash,
            ParentParticipationProof::CertifiedNotarization,
        ))
        .unwrap();
    store
        .put_finalization(record(7, hash, ParentParticipationProof::Finalization))
        .unwrap();
    let selector = ParentProofSelector::new(store);

    let result = selector.select_direct_parent_proof(0, 0, 7, hash).unwrap();
    assert_eq!(result.proof_kind(), ParentParticipationProof::Finalization);
}

#[test]
fn missing_direct_parent_proof_does_not_wait_for_future_finalization() {
    // empty store -> selector returns None immediately. The V1
    // `await_parent_cert` polled until timeout (terminal-view halt root
    // cause); the new selector is synchronous.
    let store = FinalizedParentCertStore::new();
    let selector = ParentProofSelector::new(store);

    let start = Instant::now();
    let result = selector.select_direct_parent_proof(0, 0, 42, B256::with_last_byte(0xCC));
    let elapsed = start.elapsed();

    assert!(result.is_none());
    assert!(
        elapsed.as_millis() < 10,
        "selector must not poll; took {elapsed:?}"
    );
}
