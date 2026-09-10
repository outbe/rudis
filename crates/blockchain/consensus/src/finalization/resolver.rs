//! Bounded-budget remote fetch for certified-parent notarization proofs.
//!
//! `fetch_parent_proof(key, targets, schedule)` uses
//! [`OutbeProtocolSchedule`] budgets for timeout/attempts/byte cap and only
//! ingests bytes via the `Request::Notarized` byte-recovery channel
//! (monorepo `consensus/src/marshal/core/actor.rs:847`, returns
//! `(notarization, block).encode()`).
//!
//! Marshal-wire integration is 's responsibility. ships:
//!
//! 1. The [`ParentProofTransport`] trait the resolver depends on (concrete
//!    marshal transport plugs in by implementing it).
//! 2. The [`ParentProofResolver`] policy layer: enforces per-attempt timeout,
//!    max attempts, max bytes; rejects hash-mismatch responses
//!    ([`ProofFetchOutcome::NoProofForExactParent`]); gates persistence
//!    on a local certification witness already being present
//!    ([`ProofFetchOutcome::NoLocalCertificationWitness`]).
//! 3. The structured outcome enum [`ProofFetchOutcome`] consumed by
//!    's V2 proposer selector.
//!
//! binding: a remote `Request::Notarized` response NEVER produces a
//! `CertifiedParentProofRecord` write unless this node has already locally
//! observed `Activity::Certification` for the same `(epoch, view, block_hash)`
//! (verified by [`CertifiedParentProofStore::get_certified_notarization`]
//! being non-empty for the requested parent hash).

use std::{future::Future, time::Duration};

use crate::finalization::committee_prelude::build_committee_prelude;
use crate::proof::SnapshotBuildError;
use alloy_primitives::{Address, Bytes, B256};
use commonware_codec::Encode;
use commonware_consensus::{
    simplex::types::Notarization, types::Round, Epochable as _, Viewable as _,
};
use commonware_cryptography::bls12381::primitives::variant::MinSig;
use commonware_parallel::Sequential;
use outbe_primitives::protocol_schedule::OutbeProtocolSchedule;

use crate::{
    digest::Digest,
    finalization::parent_cert_store::{
        CertifiedParentProofKey, CertifiedParentProofRecord, CertifiedParentProofStore,
        FinalizedParentCertStore, ParentProofStoreError, ProofKind,
        CERTIFIED_PARENT_PROOF_RECORD_FORMAT_VERSION,
    },
    finalization::util::build_signer_bitmap_guarded,
    hybrid::{bls_batch_verification_rng, HybridCertificate, HybridScheme},
};

/// Lookup key for a bounded parent-proof fetch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofFetchKey {
    pub round: Round,
    pub parent_hash: B256,
}

/// Outcome of a [`ParentProofResolver::fetch_parent_proof`] call.
///
/// Not `PartialEq` because [`ParentProofStoreError`] does not implement it.
/// Tests should use `matches!` against the desired variant.
#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
pub enum ProofFetchOutcome {
    /// Remote response decoded, signature verified, hash matched, and local
    /// certification witness exists. The record has been persisted to the
    /// certified-notarization slot.
    Hit(CertifiedParentProofRecord),
    /// The remote response payload hash did not match the requested
    /// `parent_hash`. exact-key only; the resolver
    /// fails the request without ever writing under the mismatched key.
    NoProofForExactParent,
    /// No local witness for the requested `(epoch, view, parent_hash)` -
    /// forbids producing a record from remote bytes alone.
    NoLocalCertificationWitness,
    /// All budget exhausted (no successful response within
    /// `max_attempts` x per-attempt `timeout_ms`).
    BudgetExhausted,
    /// Notarization signature verification failed on the decoded remote
    /// response.
    VerifyFailed,
    /// Persistence to the certified-parent proof store failed; the underlying
    /// error is reported for caller diagnostics.
    StoreError(ParentProofStoreError),
    /// The canonical committee snapshot could not be built (an encode-invariant
    /// violation); no record is produced and none is written.
    SnapshotBuildFailed(SnapshotBuildError),
}

/// Errors that a [`ParentProofTransport`] implementation may surface.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportError {
    /// Remote peer returned no notarization for the requested round.
    #[error("remote peer returned no notarization for the requested round")]
    NotFound,
    /// Remote response exceeded the byte cap before being fully decoded.
    #[error("remote response exceeded byte cap: {actual} > {cap}")]
    ResponseTooLarge { actual: usize, cap: usize },
    /// Generic transport failure (network, decode, peer-blocked).
    #[error("transport error: {0}")]
    Other(String),
}

/// Transport contract for the bounded fetch path.
///
/// The marshal-backed impl wraps marshal's `Request::Notarized`
/// resolver subscription and decodes the leading `Notarization<S, D>` from the
/// `(notarization, block).encode` wire payload. ships the trait
/// surface and the mock-driven test suite.
///
/// Implementors MUST enforce `byte_cap` on the wire (refuse oversize bytes
/// without buffering); the resolver passes the protocol schedule's
/// `parent_proof_fetch_max_bytes` so a hostile peer cannot consume node
/// resources before the cap is enforced.
pub trait ParentProofTransport: Send + Sync + 'static {
    /// Opaque target identifier (peer id, address, etc.). Resolver does not
    /// interpret it; it only forwards it to `request_notarized`.
    type Target: Clone + Send + Sync + 'static;

    /// Request the canonical notarization for `round` from `target`,
    /// returning the decoded `Notarization` or a [`TransportError`].
    fn request_notarized(
        &self,
        round: Round,
        target: Self::Target,
        byte_cap: usize,
        attempt_timeout: Duration,
    ) -> impl Future<Output = Result<Notarization<HybridScheme<MinSig>, Digest>, TransportError>> + Send;
}

/// Policy layer over a [`ParentProofTransport`] enforcing 's
/// schedule budgets, hash-exact-only contract, and local-witness gate.
pub struct ParentProofResolver<T: ParentProofTransport> {
    transport: T,
    schedule: OutbeProtocolSchedule,
    proof_store: FinalizedParentCertStore,
    verifier_scheme: HybridScheme<MinSig>,
    validator_addresses: Vec<Address>,
}

impl<T: ParentProofTransport> ParentProofResolver<T> {
    pub fn new(
        transport: T,
        schedule: OutbeProtocolSchedule,
        proof_store: FinalizedParentCertStore,
        verifier_scheme: HybridScheme<MinSig>,
        validator_addresses: Vec<Address>,
    ) -> Self {
        Self {
            transport,
            schedule,
            proof_store,
            verifier_scheme,
            validator_addresses,
        }
    }

    /// Try up to `schedule.parent_proof_fetch_max_attempts` targets, applying
    /// the schedule's per-attempt timeout and byte cap. Returns the first
    /// successful, hash-matching, locally-witnessed response - or one of the
    /// structured failure variants on [`ProofFetchOutcome`].
    ///
    /// The resolver is hash-strict: any decoded notarization whose
    /// payload hash differs from `key.parent_hash` aborts the request with
    /// [`ProofFetchOutcome::NoProofForExactParent`] rather than continuing to
    /// the next target, because a peer that supplied wrong bytes for this
    /// round is not going to redeem itself on retry.
    pub async fn fetch_parent_proof(
        &self,
        clock: &impl commonware_runtime::Clock,
        key: ProofFetchKey,
        targets: &[T::Target],
    ) -> ProofFetchOutcome {
        let max_attempts = self.schedule.parent_proof_fetch_max_attempts as usize;
        let attempt_timeout = Duration::from_millis(self.schedule.parent_proof_fetch_timeout_ms);
        let byte_cap = self.schedule.parent_proof_fetch_max_bytes;
        let attempt_budget = max_attempts.min(targets.len());

        for target in targets.iter().take(attempt_budget).cloned() {
            // The transport future borrows `self`/`target`, so it is not `'static`
            // and cannot use `Clock::timeout` (which requires `Send + 'static`).
            // Inline the same race `Clock::timeout`'s default impl uses: a biased
            // select between the request and a runtime-agnostic sleep, preferring
            // the response.
            let request =
                self.transport
                    .request_notarized(key.round, target, byte_cap, attempt_timeout);
            let sleep = clock.sleep(attempt_timeout);
            let mut request = std::pin::pin!(request);
            let mut sleep = std::pin::pin!(sleep);
            let attempt: Result<_, ()> = commonware_macros::select! {
                result = &mut request => Ok(result),
                _ = &mut sleep => Err(()),
            };

            let notarization = match attempt {
                Ok(Ok(n)) => n,
                Ok(Err(_transport_err)) => continue,
                Err(()) => continue,
            };

            // Strict hash check. A peer that returned a
            // different parent for this round has nothing useful to offer on
            // retry; fail immediately so the caller can fall back to
            // proposer-forfeit.
            if notarization.proposal.payload.0 != key.parent_hash {
                return ProofFetchOutcome::NoProofForExactParent;
            }
            // The notarization must be for the requested round. Defence in
            // depth - a transport implementation that did not enforce this is
            // a bug, but we still fail fast rather than persist mismatched
            // round bookkeeping.
            if notarization.proposal.round != key.round {
                return ProofFetchOutcome::NoProofForExactParent;
            }

            // Signature verification - same trust boundary the reporter uses
            // for Activity::Certification (see `reporter.rs::handle_certification`).
            let mut rng = bls_batch_verification_rng();
            if !notarization.verify(&mut rng, &self.verifier_scheme, &Sequential) {
                return ProofFetchOutcome::VerifyFailed;
            }

            // - local witness gate. A record produced from purely
            // remote bytes is never written; the local node must have already
            // observed `Activity::Certification` for the same key. The gate is
            // the in-memory witness index, not the persistent CN record slot:
            // CN rows may be pruned or withheld from proposer selection, while
            // the witness fact remains a separate local observation.
            let proof_key = CertifiedParentProofKey::new(
                key.round.epoch().get(),
                key.round.view().get(),
                key.parent_hash,
            );
            if !self.proof_store.has_local_certification_witness(proof_key) {
                return ProofFetchOutcome::NoLocalCertificationWitness;
            }

            // Build the record and persist. Witness flag is true by the gate
            // above. `committee_set_hash_v2` matches the reporter's canonical
            // fingerprint so 's V2 selector sees a consistent value.
            //
            // PLAN A4 requires the full canonical snapshot (address +
            // 48-byte MinPk pubkey per validator + raw encoded VRF group pk
            // bytes), so the resolver assembles the same snapshot shape the
            // boundary writer (`apply_boundary_outcome`) and Phase 1 verifier
            // recompute.
            // Defence-in-depth recovery path: a build failure is an
            // encode-invariant violation; surface it as a deterministic non-Hit
            // outcome rather than writing a record whose committee_set_hash would
            // diverge from the writer's. The shared prelude also populates
            // `vrf_group_public_key_hash`, so a promoted witness record passes the
            // Phase 1 verifier Rule 6 - this remote-fetch path previously left it
            // `B256::ZERO` (via `..default()`), which `to_v2_metadata` then carried
            // into Phase 1 metadata that Rule 6 rejected.
            let prelude = match build_committee_prelude(
                &self.verifier_scheme,
                &self.validator_addresses,
                notarization.epoch().get(),
            ) {
                Ok(prelude) => prelude,
                Err(error) => return ProofFetchOutcome::SnapshotBuildFailed(error),
            };
            let encoded_proof: Bytes = notarization.encode().into();
            let view = notarization.view().get();
            // The notarization carries no block-number context. Store `0` so
            // this record can serve as the exact-key local witness, but the
            // Phase 1 selector will not promote it without a real block number.
            let record = CertifiedParentProofRecord {
                format_version: CERTIFIED_PARENT_PROOF_RECORD_FORMAT_VERSION,
                kind: ProofKind::CertifiedNotarization,
                finalized_epoch: notarization.epoch().get(),
                finalized_view: view,
                parent_view: notarization.proposal.parent.get(),
                finalized_block_hash: notarization.proposal.payload.0,
                committee_set_hash: prelude.committee_set_hash,
                vrf_material_version: prelude.vrf_material_version,
                vrf_group_public_key_hash: prelude.vrf_group_public_key_hash,
                ordered_committee: self.validator_addresses.clone(),
                signer_bitmap: build_signer_bitmap_guarded(
                    &notarization.certificate,
                    self.validator_addresses.len(),
                ),
                encoded_proof,
                stored_at_height: view,
            };

            if let Err(error) = self.proof_store.put_certified_notarization(record.clone()) {
                return ProofFetchOutcome::StoreError(error);
            }
            return ProofFetchOutcome::Hit(record);
        }

        ProofFetchOutcome::BudgetExhausted
    }
}

/// Build the canonical V2 **Finalization** parent-proof record from a
/// marshal-recovered finalization.
///
/// After a restart (or under brief finalization lag) the in-process
/// `FinalizedParentCertStore` that the proposer selects from can be empty even
/// though marshal's durable finalization archive still holds the direct parent's
/// finalization. This rebuilds the SAME record the live
/// [`FinalizationActor`](crate::finalization::actor) writes for that
/// finalization - byte-identical, so the proposer's Phase 1 metadata stays
/// canonical and every validator accepts it (the `record_builder_parity` test
/// pins this equality). The inputs are all derived from the recovered
/// finalization plus the finalized epoch's committee scheme + ordered addresses;
/// `missed_proposers` and `finalize_votes` are empty under the V2 contract.
#[allow(clippy::too_many_arguments)]
pub fn build_finalization_record_from_recovered(
    finalized_epoch: u64,
    finalized_view: u64,
    parent_view: u64,
    finalized_block_number: u64,
    finalized_block_hash: B256,
    ordered_committee: &[Address],
    certificate: &HybridCertificate<MinSig>,
    encoded_certificate: Bytes,
    scheme: &HybridScheme<MinSig>,
) -> Result<CertifiedParentProofRecord, SnapshotBuildError> {
    let prelude = build_committee_prelude(scheme, ordered_committee, finalized_epoch)?;
    Ok(CertifiedParentProofRecord {
        format_version: CERTIFIED_PARENT_PROOF_RECORD_FORMAT_VERSION,
        kind: ProofKind::Finalization {
            finalized_block_number,
        },
        finalized_block_hash,
        finalized_epoch,
        finalized_view,
        parent_view,
        ordered_committee: ordered_committee.to_vec(),
        signer_bitmap: build_signer_bitmap_guarded(certificate, ordered_committee.len()),
        encoded_proof: encoded_certificate,
        committee_set_hash: prelude.committee_set_hash,
        vrf_material_version: prelude.vrf_material_version,
        vrf_group_public_key_hash: prelude.vrf_group_public_key_hash,
        stored_at_height: finalized_block_number,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::bootstrap_dkg;
    use crate::digest::Digest as OutbeDigest;
    use crate::proof::{committee_set_hash_v2, CommitteeEntry, CommitteeSnapshot};
    use alloy_primitives::address;
    use commonware_consensus::{
        simplex::types::{Finalization, Proposal, Subject},
        types::{Epoch, View},
    };
    use commonware_cryptography::bls12381;
    use commonware_cryptography::certificate::Scheme as _;
    use commonware_cryptography::{Hasher as _, Sha256, Signer as _};
    use commonware_utils::{
        ordered::{Quorum as _, Set as OrderedSet},
        N3f1, TryCollect as _,
    };
    use outbe_primitives::consensus_metadata::ParentParticipationProof;

    fn participants(n: u8) -> (Vec<bls12381::PrivateKey>, OrderedSet<bls12381::PublicKey>) {
        let keys: Vec<bls12381::PrivateKey> = (0..n)
            .map(|i| bls12381::PrivateKey::from_seed((i + 1) as u64))
            .collect();
        let set = keys
            .iter()
            .map(|sk| bls12381::PublicKey::from(sk.clone()))
            .try_collect()
            .unwrap();
        (keys, set)
    }

    /// A finalization signed by all 3 committee members for `payload`, plus the
    /// matching verifier scheme - all from ONE DKG so the certificate verifies.
    fn finalization_and_verifier(
        round: Round,
        parent_view: View,
        payload: &[u8],
    ) -> (
        Finalization<HybridScheme<MinSig>, OutbeDigest>,
        HybridScheme<MinSig>,
    ) {
        let (keys, set) = participants(3);
        let dkg = bootstrap_dkg(3).unwrap();
        let schemes: Vec<HybridScheme<MinSig>> = keys
            .iter()
            .map(|key| {
                let pk = bls12381::PublicKey::from(key.clone());
                let idx = set.index(&pk).unwrap();
                HybridScheme::signer(
                    b"resolver-test",
                    set.clone(),
                    key.clone(),
                    dkg.polynomial.clone(),
                    dkg.shares[idx.get() as usize].clone(),
                )
                .unwrap()
            })
            .collect();
        let verifier =
            HybridScheme::<MinSig>::verifier(b"resolver-test", set, dkg.polynomial).unwrap();
        let digest = OutbeDigest::from(B256::from_slice(Sha256::hash(payload).as_ref()));
        let proposal = Proposal::new(round, parent_view, digest);
        let subject = Subject::Finalize {
            proposal: &proposal,
        };
        let attestations: Vec<_> = schemes
            .iter()
            .map(|s| s.sign::<OutbeDigest>(subject).unwrap())
            .collect();
        let certificate = verifier
            .assemble::<_, N3f1>(attestations, &Sequential)
            .unwrap();
        (
            Finalization {
                proposal,
                certificate,
            },
            verifier,
        )
    }

    /// the marshal-recovery record builder reproduces the SAME canonical
    /// V2 fields the live `FinalizationActor` writes. The committee-set-hash
    /// derivation is rebuilt inline exactly as `actor.rs` does so a future
    /// divergence in the helper trips this assertion.
    #[test]
    fn record_builder_parity() {
        let epoch = Epoch::new(4);
        let view = View::new(9);
        let parent_view = View::new(8);
        let round = Round::new(epoch, view);
        let (finalization, verifier) = finalization_and_verifier(round, parent_view, b"parent");

        let addresses = vec![
            address!("0x0000000000000000000000000000000000000011"),
            address!("0x0000000000000000000000000000000000000022"),
            address!("0x0000000000000000000000000000000000000033"),
        ];
        let block_number = 42u64;
        let encoded: Bytes = finalization.encode().into();

        let record = build_finalization_record_from_recovered(
            finalization.proposal.round.epoch().get(),
            finalization.proposal.round.view().get(),
            finalization.proposal.parent.get(),
            block_number,
            finalization.proposal.payload.0,
            &addresses,
            &finalization.certificate,
            encoded.clone(),
            &verifier,
        )
        .expect("recovered record builds from valid 48-byte MinPk pubkeys");

        // Field mapping mirrors the finalization + the V2 contract.
        assert_eq!(record.proof_kind(), ParentParticipationProof::Finalization);
        assert_eq!(record.finalized_block_number(), Some(block_number));
        assert_eq!(record.finalized_block_hash, finalization.proposal.payload.0);
        assert_eq!(record.finalized_epoch, epoch.get());
        assert_eq!(record.finalized_view, view.get());
        assert_eq!(record.parent_view, parent_view.get());
        assert_eq!(record.ordered_committee, addresses);
        assert_eq!(record.signer_bitmap, vec![1u8, 1, 1], "all 3 signed");
        assert_eq!(record.stored_at_height, block_number);
        assert_eq!(record.encoded_proof, encoded);

        // Committee-set-hash parity: rebuild the snapshot exactly as
        // `FinalizationActor::handle_finalized` (actor.rs:458-490) and assert the
        // helper produced the identical canonical hash.
        let parts = verifier.participants();
        let committee: Vec<CommitteeEntry> = addresses
            .iter()
            .zip(parts.iter())
            .map(|(a, pk)| {
                let bytes = pk.encode();
                let mut cpk = [0u8; 48];
                let len = bytes.as_ref().len().min(48);
                cpk[..len].copy_from_slice(&bytes.as_ref()[..len]);
                CommitteeEntry {
                    address: *a,
                    consensus_pubkey: cpk,
                }
            })
            .collect();
        let vrf_bytes: Vec<u8> = verifier
            .identity()
            .map(|pk| pk.encode().as_ref().to_vec())
            .unwrap_or_default();
        let expected_snapshot = CommitteeSnapshot {
            committee,
            vrf_material_version: verifier.expected_vrf_material_version(),
            vrf_group_public_key_bytes: vrf_bytes,
            vrf_public_polynomial_hash: B256::ZERO,
        };
        let expected_hash = committee_set_hash_v2(epoch.get(), &expected_snapshot);
        assert_eq!(
            record.committee_set_hash, expected_hash,
            "recovered record committee_set_hash must match the FinalizationActor derivation"
        );
        assert_ne!(record.committee_set_hash, B256::ZERO);
        assert_eq!(
            record.vrf_material_version,
            verifier.expected_vrf_material_version()
        );

        // The record projects to canonical V2 metadata Phase 1 consumes.
        let metadata = record.to_v2_metadata(block_number);
        assert_eq!(metadata.finalized_block_number, block_number);
        assert_eq!(
            metadata.finalized_block_hash,
            finalization.proposal.payload.0
        );
        assert_eq!(metadata.committee_set_hash, expected_hash);
    }
}
