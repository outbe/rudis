//! Process-local store of individual finalize signatures for the late
//! credits (Phase 5).
//!
//! After a block finalizes on the eager 2f+1 quorum, additional (slow-but-honest)
//! validators keep gossiping their finalize votes. A node observes those
//! individual votes [`OutbeReporter`](crate::reporter) and buffers them here,
//! keyed by view. When the matching block finalizes and its number is known, the
//! buffer is rekeyed to `(fb_number, fb_hash)` (`FinalizationActor` has the
//! height - the reporter sets `finalized_block_number: 0`). When this node is the
//! proposer of `N+1..N+K` it aggregates the votes it locally holds for each
//! in-window target into a [`LateFinalizeCreditsArtifact`].
//!
//! This is **best-effort, process-local** state - *not* consensus state. It
//! never affects the block hash: validators re-verify (via
//! [`crate::proof::verify_late_finalize_proof`]) whatever a proposer chooses to
//! include, and an empty store simply credits nobody (degrading to today's
//! behavior). Durable rebroadcast / hard anti-censorship.

use alloy_primitives::B256;
use commonware_codec::Encode;
use commonware_cryptography::bls12381::{
    self,
    primitives::{
        ops::aggregate,
        variant::{MinPk, Variant},
    },
};
use outbe_primitives::reshare_artifact::{LateFinalizeCreditsArtifact, PerBlockCredit};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

type MinPkSig = <MinPk as Variant>::Signature;

/// Process-local late-finalize signature store shared (read-modify-write under a
/// `Mutex`) by the reporter (records observed votes), the `FinalizationActor`
/// (resolves views to block numbers), and the application handler (packs the
/// proposer artifact). It is **not** consensus state - see the module docs.
pub type SharedLateFinalizeStore = Arc<Mutex<LateFinalizeSigStore>>;

/// Construct an empty [`SharedLateFinalizeStore`] for inclusion window `window_k`.
pub fn shared(window_k: u64) -> SharedLateFinalizeStore {
    Arc::new(Mutex::new(LateFinalizeSigStore::new(window_k)))
}

/// Cap on per-target buffers awaiting block-number resolution. Bounds memory if
/// finalizations stall (targets never resolve); the lowest-`fb_hash` targets are
/// dropped first - arbitrary order, NOT by age (no insertion-order/view is
/// tracked). Eviction only fires under a stalled-finalization flood, where any
/// bounded drop suffices; if true age-based eviction is ever needed, add a
/// per-target view/height field and evict on that instead.
const MAX_PENDING_TARGETS: usize = 512;

/// One buffered finalize vote with the proposal binding it was actually signed
/// over. A finalize signature is valid only over `Proposal{Round(epoch, view),
/// parent_view, payload = fb_hash}.encode()`, so a vote signed at a non-canonical
/// `(epoch, view, parent_view)` for the same `fb_hash` (equivocation / a buggy or
/// Byzantine validator gossiping across views) MUST NOT be merged into the
/// canonical aggregate - it would fail `verify_same_message` and poison the whole
/// per-block credit. We keep the per-vote binding so `resolve_finalized` can drop
/// any vote whose binding != the finalized certificate's.
#[derive(Clone)]
struct BoundVote {
    epoch: u64,
    view: u64,
    parent_view: u64,
    sig: MinPkSig,
}

/// Individual finalize votes for one finalized proposal (keyed by its `fb_hash`),
/// awaiting block-number resolution. Keying by `fb_hash` - not `view` - keeps
/// votes for distinct proposals at the same view (equivocations / forks) in
/// separate buffers so they are never aggregated together.
struct PendingTarget {
    /// signer committee index -> that signer's bound individual MinPk finalize
    /// vote. The binding travels with each vote so cross-view votes for the same
    /// `fb_hash` are filtered out against the canonical certificate at
    /// `resolve_finalized` time.
    votes: BTreeMap<u32, BoundVote>,
}

/// Finalize votes for a target block, resolved to its number (window-scoped).
struct ResolvedTarget {
    fb_hash: B256,
    epoch: u64,
    view: u64,
    parent_view: u64,
    committee_set_hash: B256,
    committee_size: usize,
    votes: BTreeMap<u32, MinPkSig>,
}

/// See module docs.
pub struct LateFinalizeSigStore {
    window_k: u64,
    /// Votes observed before the proposal finalized, keyed by `fb_hash`.
    pending_by_fb_hash: BTreeMap<B256, PendingTarget>,
    /// Votes for finalized proposals, keyed by block number (window-scoped).
    resolved_by_number: BTreeMap<u64, ResolvedTarget>,
    /// `fb_hash -> block number` for every resolved target still in the window, so
    /// a vote that arrives **after** finalization (the slow-validator case) is
    /// routed straight into the resolved target instead of being stranded in
    /// `pending_by_fb_hash`.
    resolved_fb_hash_to_number: BTreeMap<B256, u64>,
}

impl LateFinalizeSigStore {
    pub fn new(window_k: u64) -> Self {
        Self {
            window_k,
            pending_by_fb_hash: BTreeMap::new(),
            resolved_by_number: BTreeMap::new(),
            resolved_fb_hash_to_number: BTreeMap::new(),
        }
    }

    /// Buffer one observed (already signature-verified) individual finalize vote,
    /// keyed by the proposal's `fb_hash`. First writer wins per `(fb_hash, signer)`.
    /// `(epoch, view, parent_view)` is the binding the vote was signed over.
    ///
    /// If the proposal already finalized (its `fb_hash` is in
    /// `resolved_fb_hash_to_number`), the vote is appended **directly** to the
    /// resolved target - this is the slow-validator path, where the vote arrives
    /// after the eager quorum finalized the block - but ONLY if its binding
    /// matches the canonical certificate's; a cross-view vote for the same
    /// `fb_hash` is dropped so it cannot poison the canonical aggregate.
    #[allow(clippy::too_many_arguments)]
    pub fn record_vote(
        &mut self,
        epoch: u64,
        view: u64,
        parent_view: u64,
        fb_hash: B256,
        signer: u32,
        sig: MinPkSig,
    ) {
        // Late arrival: the target already resolved -> append to it directly, but
        // only if the vote's binding equals the canonical one (else drop).
        if let Some(&fb_number) = self.resolved_fb_hash_to_number.get(&fb_hash) {
            if let Some(target) = self.resolved_by_number.get_mut(&fb_number) {
                if target.epoch == epoch && target.view == view && target.parent_view == parent_view
                {
                    target.votes.entry(signer).or_insert(sig);
                }
                return;
            }
        }

        let entry = self
            .pending_by_fb_hash
            .entry(fb_hash)
            .or_insert_with(|| PendingTarget {
                votes: BTreeMap::new(),
            });
        entry.votes.entry(signer).or_insert(BoundVote {
            epoch,
            view,
            parent_view,
            sig,
        });

        // Bound memory: drop the lowest-`fb_hash` entries beyond the cap
        // (arbitrary order, not by age - see `MAX_PENDING_TARGETS`).
        while self.pending_by_fb_hash.len() > MAX_PENDING_TARGETS {
            let Some((&lowest_fb_hash, _)) = self.pending_by_fb_hash.iter().next() else {
                break;
            };
            self.pending_by_fb_hash.remove(&lowest_fb_hash);
        }
    }

    /// Convenience over [`Self::record_vote`] taking the raw MinPk individual
    /// vote as a `bls12381::Signature` (the `bls_individual_vote` carried in a
    /// consensus `HybridSignature`). Keeps the MinPk-variant conversion in one
    /// place so callers in `reporter.rs` stay free of variant generics. The
    /// caller MUST have verified the finalize vote's signature first.
    #[allow(clippy::too_many_arguments)]
    pub fn record_individual_vote(
        &mut self,
        epoch: u64,
        view: u64,
        parent_view: u64,
        fb_hash: B256,
        signer: u32,
        bls_individual_vote: &bls12381::Signature,
    ) {
        let sig: MinPkSig = *bls_individual_vote.as_ref();
        self.record_vote(epoch, view, parent_view, fb_hash, signer, sig);
    }

    /// Rekey a finalized proposal's buffered votes (keyed by `fb_hash`) to its
    /// block number, register the `fb_hash -> number` index so later-arriving
    /// votes route straight to the resolved target, and prune targets that have
    /// fallen out of the inclusion window.
    // The canonical certificate binding (epoch/view/parent_view/fb_hash/
    // committee_set_hash/committee_size) is irreducible here: every field is bound
    // into the per-block credit so a pure post-finalization vote still verifies.
    #[allow(clippy::too_many_arguments)]
    pub fn resolve_finalized(
        &mut self,
        epoch: u64,
        view: u64,
        parent_view: u64,
        fb_number: u64,
        fb_hash: B256,
        committee_set_hash: B256,
        committee_size: usize,
    ) {
        // The canonical (epoch, view, parent_view) come from the finalized
        // certificate, so the resolved target is correctly bound whether or not
        // any vote was buffered before finalization. (A pure post-finalization
        // vote has no pending entry - it must still carry the real binding, or
        // the rebuilt proposal won't match what the signer signed;)
        let target = self
            .resolved_by_number
            .entry(fb_number)
            .or_insert_with(|| ResolvedTarget {
                fb_hash,
                epoch,
                view,
                parent_view,
                committee_set_hash,
                committee_size,
                votes: BTreeMap::new(),
            });
        if let Some(pending) = self.pending_by_fb_hash.remove(&fb_hash) {
            // Merge (first writer wins per signer) in case votes arrive split -
            // but ONLY votes whose binding matches the canonical certificate. A
            // cross-view vote for the same `fb_hash` signed a different message and
            // would make the aggregate fail `verify_same_message`, so it is dropped.
            for (signer, bound) in pending.votes {
                if bound.epoch == epoch && bound.view == view && bound.parent_view == parent_view {
                    target.votes.entry(signer).or_insert(bound.sig);
                }
            }
        }
        self.resolved_fb_hash_to_number.insert(fb_hash, fb_number);

        // Window close: in-memory buffer pruned at N+K+1 - keep only block
        // numbers within `[resolved - K, resolved]`; older targets can no longer
        // be credited. (This prunes the process-local gathering buffer; the EVM
        // settlement state is separately freed at settle, N+K.)
        let min_keep = fb_number.saturating_sub(self.window_k);
        self.resolved_by_number.retain(|&n, _| n >= min_keep);
        self.resolved_fb_hash_to_number
            .retain(|_, &mut n| n >= min_keep);
    }

    /// Assemble the late-finalize-credits artifact for a block proposed at
    /// `proposer_block_number`: every resolved target whose window is still open,
    /// i.e. `fb_number in [proposer_block_number - K, proposer_block_number - 1]`,
    /// aggregating the locally-held individual votes into a per-block credit.
    pub fn build_artifact(&self, proposer_block_number: u64) -> LateFinalizeCreditsArtifact {
        let lo = proposer_block_number.saturating_sub(self.window_k);
        let hi = proposer_block_number.saturating_sub(1);
        let mut batches = Vec::new();
        if lo > hi {
            return LateFinalizeCreditsArtifact { batches };
        }
        // BTreeMap::range yields ascending fb_number, so batches are already in
        // the canonical strictly-ascending order the codec requires.
        for (&fb_number, target) in self.resolved_by_number.range(lo..=hi) {
            if target.votes.is_empty() {
                continue;
            }
            let sigs: Vec<&MinPkSig> = target.votes.values().collect();
            let agg = aggregate::combine_signatures::<MinPk, _>(sigs);
            let mut aggregate_signature = [0u8; 96];
            aggregate_signature.copy_from_slice(&agg.encode());

            let mut signer_bitmap = vec![0u8; target.committee_size.div_ceil(8)];
            for &signer in target.votes.keys() {
                let idx = signer as usize;
                if idx < target.committee_size {
                    signer_bitmap[idx / 8] |= 1u8 << (idx % 8);
                }
            }

            batches.push(PerBlockCredit {
                fb_number,
                fb_hash: target.fb_hash,
                epoch: target.epoch,
                view: target.view,
                parent_view: target.parent_view,
                committee_set_hash: target.committee_set_hash,
                signer_bitmap,
                aggregate_signature,
            });
        }
        LateFinalizeCreditsArtifact { batches }
    }

    #[cfg(test)]
    pub(crate) fn resolved_len(&self) -> usize {
        self.resolved_by_number.len()
    }

    /// Number of buffered (not-yet-resolved) votes for `fb_hash`. Test-only:
    /// used by the reporter wiring test to assert an observed `Finalize`
    /// activity was recorded.
    #[cfg(test)]
    pub(crate) fn pending_vote_count(&self, fb_hash: B256) -> usize {
        self.pending_by_fb_hash
            .get(&fb_hash)
            .map(|p| p.votes.len())
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::committee::{committee_set_hash_v2, CommitteeEntry, CommitteeSnapshot};
    use crate::proof::constants::finalize_namespace;
    use crate::proof::verify_late_finalize_proof;
    use commonware_consensus::simplex::types::Proposal;
    use commonware_consensus::types::{Epoch, Round, View};
    use commonware_cryptography::{bls12381, Signer as _};
    use commonware_math::algebra::Random;

    fn keys(n: usize) -> Vec<bls12381::PrivateKey> {
        (0..n)
            .map(|_| bls12381::PrivateKey::random(rand_core::OsRng))
            .collect()
    }

    fn snapshot_for(keys: &[bls12381::PrivateKey]) -> CommitteeSnapshot {
        let committee = keys
            .iter()
            .enumerate()
            .map(|(i, sk)| {
                let mut consensus_pubkey = [0u8; 48];
                consensus_pubkey.copy_from_slice(&sk.public_key().encode());
                CommitteeEntry {
                    address: alloy_primitives::Address::with_last_byte(i as u8 + 1),
                    consensus_pubkey,
                }
            })
            .collect();
        CommitteeSnapshot {
            committee,
            vrf_material_version: 1,
            vrf_group_public_key_bytes: vec![0x11; 96],
            vrf_public_polynomial_hash: alloy_primitives::B256::ZERO,
        }
    }

    /// Sign the canonical finalize message for `(epoch, view, parent_view, fb_hash)`
    /// with `key` and return the raw MinPk signature the store stores. the
    /// finalize namespace binds the full `committee`, so the signature only
    /// verifies under that committee.
    fn finalize_sig(
        committee: &[bls12381::PrivateKey],
        key: &bls12381::PrivateKey,
        epoch: u64,
        view: u64,
        parent_view: u64,
        fb_hash: B256,
    ) -> MinPkSig {
        let committee_set: commonware_utils::ordered::Set<bls12381::PublicKey> =
            commonware_utils::ordered::Set::from_iter_dedup(
                committee
                    .iter()
                    .map(|k| bls12381::PublicKey::from(k.clone())),
            );
        let proposal = Proposal::new(
            Round::new(Epoch::new(epoch), View::new(view)),
            View::new(parent_view),
            crate::digest::Digest(fb_hash),
        );
        let message = proposal.encode().to_vec();
        let signature = key.sign(&finalize_namespace(&committee_set), &message);
        let inner: &MinPkSig = signature.as_ref();
        *inner
    }

    /// End-to-end: record votes -> resolve to a number -> build artifact ->
    /// the resulting credit verifies through the Phase-4 verifier.
    #[test]
    fn record_resolve_build_round_trips_through_verifier() {
        let keys = keys(4);
        let snapshot = snapshot_for(&keys);
        let csh = committee_set_hash_v2(3, &snapshot);
        let fb = B256::repeat_byte(0xAB);
        let (epoch, view, parent_view, fb_number) = (3u64, 9u64, 8u64, 10u64);

        let mut store = LateFinalizeSigStore::new(3);
        for i in [0u32, 1, 2] {
            store.record_vote(
                epoch,
                view,
                parent_view,
                fb,
                i,
                finalize_sig(&keys, &keys[i as usize], epoch, view, parent_view, fb),
            );
        }
        store.resolve_finalized(
            epoch,
            view,
            parent_view,
            fb_number,
            fb,
            csh,
            snapshot.committee.len(),
        );

        // Proposer of block 11: target 10 is in [11-3, 10] = [8, 10].
        let artifact = store.build_artifact(11);
        assert_eq!(artifact.batches.len(), 1);
        let credit = &artifact.batches[0];
        assert_eq!(credit.fb_number, fb_number);
        assert_eq!(
            verify_late_finalize_proof(&snapshot, credit).expect("late credit verifies"),
            vec![0, 1, 2]
        );
    }

    #[test]
    fn build_artifact_excludes_out_of_window_targets() {
        let keys = keys(4);
        let snapshot = snapshot_for(&keys);
        let csh = committee_set_hash_v2(1, &snapshot);
        let fb = B256::repeat_byte(0x01);
        let mut store = LateFinalizeSigStore::new(3);
        store.record_vote(1, 9, 8, fb, 0, finalize_sig(&keys, &keys[0], 1, 9, 8, fb));
        store.resolve_finalized(1, 9, 8, 10, fb, csh, 4);

        // Proposer at block 14: window [11, 13] - target 10 is too old.
        assert!(store.build_artifact(14).batches.is_empty());
        // Proposer at block 13: window [10, 12] - target 10 is the lower edge.
        assert_eq!(store.build_artifact(13).batches.len(), 1);
    }

    #[test]
    fn resolve_prunes_targets_below_window() {
        let keys = keys(4);
        let snapshot = snapshot_for(&keys);
        // Distinct fb hashes for the two finalized blocks (fb_hash is unique).
        let fb = B256::repeat_byte(0x02);
        let fb2 = B256::repeat_byte(0x22);
        let mut store = LateFinalizeSigStore::new(3);
        store.record_vote(1, 9, 8, fb, 0, finalize_sig(&keys, &keys[0], 1, 9, 8, fb));
        store.resolve_finalized(1, 9, 8, 10, fb, committee_set_hash_v2(1, &snapshot), 4);
        assert_eq!(store.resolved_len(), 1);
        // A much later finalization prunes the old target (10 < 100 - 3).
        store.record_vote(
            1,
            99,
            98,
            fb2,
            0,
            finalize_sig(&keys, &keys[0], 1, 99, 98, fb2),
        );
        store.resolve_finalized(1, 99, 98, 100, fb2, committee_set_hash_v2(1, &snapshot), 4);
        assert_eq!(store.resolved_len(), 1);
    }

    #[test]
    fn duplicate_signer_vote_is_ignored() {
        let keys = keys(4);
        let fb = B256::repeat_byte(0x03);
        let mut store = LateFinalizeSigStore::new(3);
        store.record_vote(1, 9, 8, fb, 0, finalize_sig(&keys, &keys[0], 1, 9, 8, fb));
        // Second vote from the same signer/fb_hash must not overwrite or duplicate.
        store.record_vote(1, 9, 8, fb, 0, finalize_sig(&keys, &keys[0], 1, 9, 8, fb));
        store.resolve_finalized(1, 9, 8, 10, fb, B256::ZERO, 4);
        let artifact = store.build_artifact(11);
        assert_eq!(artifact.batches.len(), 1);
        // One signer bit set.
        assert_eq!(
            artifact.batches[0]
                .signer_bitmap
                .iter()
                .map(|b| b.count_ones())
                .sum::<u32>(),
            1
        );
    }

    /// a vote that arrives AFTER the block
    /// finalized (the slow-validator case) is routed into the already-resolved
    /// target and appears in the built artifact - not stranded in the pending
    /// buffer.
    #[test]
    fn vote_arrives_after_resolution_is_included() {
        let keys = keys(4);
        let snapshot = snapshot_for(&keys);
        let csh = committee_set_hash_v2(3, &snapshot);
        let fb = B256::repeat_byte(0xCD);
        let (epoch, view, parent_view, fb_number) = (3u64, 9u64, 8u64, 10u64);

        let mut store = LateFinalizeSigStore::new(3);
        // Eager voter 0 before finalization.
        store.record_vote(
            epoch,
            view,
            parent_view,
            fb,
            0,
            finalize_sig(&keys, &keys[0], epoch, view, parent_view, fb),
        );
        store.resolve_finalized(
            epoch,
            view,
            parent_view,
            fb_number,
            fb,
            csh,
            snapshot.committee.len(),
        );

        // Slow voter 1 arrives AFTER finalization for the same fb_hash.
        store.record_vote(
            epoch,
            view,
            parent_view,
            fb,
            1,
            finalize_sig(&keys, &keys[1], epoch, view, parent_view, fb),
        );
        // Nothing left pending; both votes are in the resolved target.
        assert_eq!(store.pending_vote_count(fb), 0);

        let artifact = store.build_artifact(11);
        assert_eq!(artifact.batches.len(), 1);
        assert_eq!(
            verify_late_finalize_proof(&snapshot, &artifact.batches[0]).expect("verifies"),
            vec![0, 1],
            "both the eager and the late-arriving vote must be credited"
        );
    }

    /// two proposals at the same view but with
    /// different fb_hash (equivocation / fork) are buffered separately and never
    /// aggregated together - each resolves to its own target.
    #[test]
    fn equivocation_distinct_fb_hash_not_merged() {
        let keys = keys(4);
        let fb1 = B256::repeat_byte(0x11);
        let fb2 = B256::repeat_byte(0x22);
        let (epoch, view, parent_view) = (1u64, 9u64, 8u64);

        let mut store = LateFinalizeSigStore::new(3);
        // Same signer signs two different proposals at the same view.
        store.record_vote(
            epoch,
            view,
            parent_view,
            fb1,
            0,
            finalize_sig(&keys, &keys[0], epoch, view, parent_view, fb1),
        );
        store.record_vote(
            epoch,
            view,
            parent_view,
            fb2,
            0,
            finalize_sig(&keys, &keys[0], epoch, view, parent_view, fb2),
        );
        // Separate buffers - neither aggregate is poisoned by the other proposal.
        assert_eq!(store.pending_vote_count(fb1), 1);
        assert_eq!(store.pending_vote_count(fb2), 1);
    }

    /// a *pure* post-finalization vote - one
    /// where NOTHING was buffered before the block finalized - must still build a
    /// credit that the verifier accepts. `resolve_finalized` creates the target
    /// with the canonical `(epoch, parent_view)` from the finalized certificate,
    /// not `0`/`0`; the round-2 regression filled those with zero, so the rebuilt
    /// proposal mismatched what the signer signed and the aggregate failed.
    #[test]
    fn pure_post_finalization_vote_verifies() {
        let keys = keys(4);
        let snapshot = snapshot_for(&keys);
        let csh = committee_set_hash_v2(3, &snapshot);
        let fb = B256::repeat_byte(0xEF);
        // Non-zero epoch and parent_view - the zero-fill bug only shows up here.
        let (epoch, view, parent_view, fb_number) = (3u64, 9u64, 8u64, 10u64);

        let mut store = LateFinalizeSigStore::new(3);
        // Finalization happens with NO vote buffered for this fb_hash.
        store.resolve_finalized(
            epoch,
            view,
            parent_view,
            fb_number,
            fb,
            csh,
            snapshot.committee.len(),
        );
        assert_eq!(store.pending_vote_count(fb), 0);

        // The validator's own finalize vote arrives strictly after finalization.
        store.record_vote(
            epoch,
            view,
            parent_view,
            fb,
            2,
            finalize_sig(&keys, &keys[2], epoch, view, parent_view, fb),
        );

        let artifact = store.build_artifact(11);
        assert_eq!(artifact.batches.len(), 1);
        let credit = &artifact.batches[0];
        // The credit must carry the canonical binding, not 0/0.
        assert_eq!(credit.epoch, epoch);
        assert_eq!(credit.parent_view, parent_view);
        assert_eq!(
            verify_late_finalize_proof(&snapshot, credit)
                .expect("pure post-finalization credit must verify"),
            vec![2],
            "the post-finalization vote must be credited and verify"
        );
    }

    /// a finalize vote that is individually
    /// valid but signed over a DIFFERENT `(epoch, view, parent_view)` for the same
    /// `fb_hash` (equivocation / a Byzantine validator gossiping across views)
    /// must NOT be merged into the canonical aggregate - otherwise it would make
    /// `verify_same_message` fail and poison the whole per-block credit (a
    /// chain-wide late-tail griefing vector). It is dropped on BOTH the
    /// pending-merge path and the post-resolution late-arrival path; the artifact
    /// still verifies over the honest, canonical-binding signers only.
    #[test]
    fn cross_view_same_fb_hash_vote_not_aggregated() {
        let keys = keys(4);
        let snapshot = snapshot_for(&keys);
        let csh = committee_set_hash_v2(3, &snapshot);
        let fb = B256::repeat_byte(0xC5);
        let (epoch, view, parent_view, fb_number) = (3u64, 9u64, 8u64, 10u64);
        let bad_view = 99u64; // a non-canonical view for the SAME fb_hash

        let mut store = LateFinalizeSigStore::new(3);
        // Pending-merge path: honest signer 0 at the canonical binding, plus a
        // cross-view signer 1 (valid over view=99) - both buffered before resolve.
        store.record_vote(
            epoch,
            view,
            parent_view,
            fb,
            0,
            finalize_sig(&keys, &keys[0], epoch, view, parent_view, fb),
        );
        store.record_vote(
            epoch,
            bad_view,
            parent_view,
            fb,
            1,
            finalize_sig(&keys, &keys[1], epoch, bad_view, parent_view, fb),
        );
        store.resolve_finalized(
            epoch,
            view,
            parent_view,
            fb_number,
            fb,
            csh,
            snapshot.committee.len(),
        );

        // Post-resolution late-arrival path: another cross-view signer 2.
        store.record_vote(
            epoch,
            bad_view,
            parent_view,
            fb,
            2,
            finalize_sig(&keys, &keys[2], epoch, bad_view, parent_view, fb),
        );

        let artifact = store.build_artifact(11);
        assert_eq!(artifact.batches.len(), 1);
        let credit = &artifact.batches[0];
        // Only the canonical-binding signer 0 survived; the aggregate verifies.
        assert_eq!(
            verify_late_finalize_proof(&snapshot, credit)
                .expect("canonical-only aggregate must still verify"),
            vec![0],
            "cross-view votes for the same fb_hash must be dropped, not aggregated"
        );
    }
}
