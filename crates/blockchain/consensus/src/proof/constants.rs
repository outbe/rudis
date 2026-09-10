//! V2 protocol constants used by the Hybrid proof verifier.
//!
//! Single source of truth for the application namespace + its derived Simplex
//! sub-namespaces (`_NOTARIZE`, `_FINALIZE`, `_SEED`, `_SEEDATTEST`).
//!
//! **Chain binding.** The application namespace is
//! `b"outbe" || chain_id_be`, so every signed consensus message and every
//! verification (vote/nullify/finalize/seed/seed-attest, the P2P handshake, and
//! SlashIndicator evidence) is bound to this chain. A validator that reuses its
//! BLS key on another Outbe deployment produces signatures under a different
//! namespace, so they no longer cross-verify or replay as fabricated
//! equivocation evidence. The chain id is genesis-fixed and constant for the
//! process; it is injected once at startup via [`init_consensus_chain_id`] and
//! every namespace accessor reads it, so the signer (`HybridScheme`) and the
//! deterministic verifier (this crate, run in the EVM executor - same process,
//! same chain) can never drift.

use commonware_codec::Encode;
use commonware_consensus::simplex::scheme::Namespace;
use commonware_consensus::types::{Epoch, Round, View};
use commonware_cryptography::bls12381;
use commonware_utils::ordered::Set;
use std::sync::OnceLock;

/// Unbound base of the Outbe application namespace. The full namespace appends
/// the consensus chain id (see [`outbe_app_namespace`]).
const OUTBE_APP_NAMESPACE_BASE: &[u8] = b"outbe";

/// Domain tag for the ordered validator-set commitment. Versioned so the
/// commitment scheme can evolve under a coordinated fork without colliding with
/// the previous one.
const COMMITTEE_COMMITMENT_DOMAIN: &[u8] = b"OUTBE_COMMITTEE_V1";

/// Process-wide consensus chain id, folded into every consensus namespace.
static CONSENSUS_DOMAIN: OnceLock<ConsensusDomain> = OnceLock::new();

/// Chain id used before [`init_consensus_chain_id`] runs (unit tests that do not
/// install one). Production always installs the real chain id at startup before
/// any signing or verification.
const DEFAULT_CONSENSUS_CHAIN_ID: u64 = 0;

struct ConsensusDomain {
    chain_id: u64,
    app_namespace: Vec<u8>,
    simplex_namespace: Namespace,
}

impl ConsensusDomain {
    fn new(chain_id: u64) -> Self {
        let mut app_namespace = Vec::with_capacity(OUTBE_APP_NAMESPACE_BASE.len() + 8);
        app_namespace.extend_from_slice(OUTBE_APP_NAMESPACE_BASE);
        app_namespace.extend_from_slice(&chain_id.to_be_bytes());
        let simplex_namespace = Namespace::new(&app_namespace);
        Self {
            chain_id,
            app_namespace,
            simplex_namespace,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConsensusChainIdError {
    #[error(
        "process consensus domain is already bound to chain {installed}, requested {requested}"
    )]
    AlreadyBound { installed: u64, requested: u64 },
}

fn install_consensus_domain(
    cell: &OnceLock<ConsensusDomain>,
    chain_id: u64,
) -> Result<(), ConsensusChainIdError> {
    if let Some(installed) = cell.get() {
        return matching_consensus_chain_id(installed.chain_id, chain_id);
    }
    if cell.set(ConsensusDomain::new(chain_id)).is_ok() {
        return Ok(());
    }
    let installed = cell
        .get()
        .expect("a failed OnceLock set must leave the winning value installed");
    matching_consensus_chain_id(installed.chain_id, chain_id)
}

fn matching_consensus_chain_id(
    installed: u64,
    requested: u64,
) -> Result<(), ConsensusChainIdError> {
    if installed == requested {
        Ok(())
    } else {
        Err(ConsensusChainIdError::AlreadyBound {
            installed,
            requested,
        })
    }
}

fn consensus_domain(cell: &OnceLock<ConsensusDomain>) -> &ConsensusDomain {
    cell.get_or_init(|| ConsensusDomain::new(DEFAULT_CONSENSUS_CHAIN_ID))
}

/// Install the consensus chain id, once, at node startup - before any consensus
/// signing or block verification runs. Reinstalling the same id is idempotent;
/// a conflicting id, including a namespace previously cached under the test
/// default `0`, is rejected without changing the installed domain.
pub fn init_consensus_chain_id(chain_id: u64) -> Result<(), ConsensusChainIdError> {
    install_consensus_domain(&CONSENSUS_DOMAIN, chain_id)
}

/// The installed consensus chain id (or the default in unit tests).
pub fn consensus_chain_id() -> u64 {
    consensus_domain(&CONSENSUS_DOMAIN).chain_id
}

/// Chain-bound application namespace bytes: `b"outbe" || chain_id_be`.
pub fn outbe_app_namespace() -> Vec<u8> {
    consensus_domain(&CONSENSUS_DOMAIN).app_namespace.clone()
}

/// Ordered validator-set commitment: a 32-byte keccak over the committee's
/// BLS MinPk public keys in **canonical commonware `Set` order** (sorted,
/// deduplicated), domain-tagged and length-prefixed.
///
/// This is the "ordered validator-set commitment" the consensus-signature
/// invariant requires. It is folded into the INDIVIDUAL vote sub-namespaces
/// (notarize/nullify/finalize), so a vote signature produced under committee A
/// cannot verify under committee B even within the same chain and epoch -
/// closing the residual that committee-scoped verification covered only
/// operationally. The threshold seed / seed-attest namespaces stay chain-only:
/// the seed is a threshold signature already bound to the committee by its group
/// key, so a participant-set commitment there would be redundant.
///
/// **Parity contract.** This is the single source of truth for the commitment.
/// Every party (the `HybridScheme` signer/verifier, the V2 proof verifier in the
/// executor, the late-finalize verifier, and the SlashIndicator evidence
/// verifier) computes it from the SAME ordered committee via THIS function. The
/// input is a `Set`, whose `Ord`-sorted, deduplicated order matches the scheme's
/// participant indexing exactly, so the bytes are identical across nodes,
/// components, and crates by construction. Any divergence is caught pre-merge by
/// the fingerprint test and the 4-node localnet lockstep.
pub fn participant_set_commitment(committee: &Set<bls12381::PublicKey>) -> [u8; 32] {
    let mut buf = Vec::with_capacity(
        COMMITTEE_COMMITMENT_DOMAIN.len() + 4 + committee.len().saturating_mul(48),
    );
    buf.extend_from_slice(COMMITTEE_COMMITMENT_DOMAIN);
    // Length prefix binds the cardinality so a prefix/superset of one committee
    // cannot collide with another.
    buf.extend_from_slice(&(committee.len() as u32).to_be_bytes());
    for pk in committee.iter() {
        buf.extend_from_slice(commonware_codec::Encode::encode(pk).as_ref());
    }
    alloy_primitives::keccak256(&buf).0
}

/// Chain-only sub-namespace (`outbe_app_namespace() || suffix`), matching
/// commonware's `union(base, suffix)`. Used by the seed paths, which are already
/// committee-bound by the threshold polynomial.
fn sub_namespace(suffix: &[u8]) -> Vec<u8> {
    let mut v = outbe_app_namespace();
    v.extend_from_slice(suffix);
    v
}

/// Committee-bound vote sub-namespace:
/// `outbe_app_namespace() || suffix || participant_set_commitment(committee)`.
///
/// THE single derivation for the individual vote namespaces, used on both the
/// signing side (the `HybridScheme` `Namespace` vote fields are overridden with
/// these fns) and every verifying side (V2 proof verifier, late-finalize,
/// SlashIndicator evidence), so they agree by construction.
fn vote_sub_namespace(suffix: &[u8], committee: &Set<bls12381::PublicKey>) -> Vec<u8> {
    let mut v = outbe_app_namespace();
    v.extend_from_slice(suffix);
    v.extend_from_slice(&participant_set_commitment(committee));
    v
}

/// Simplex notarize sub-namespace, committee-bound.
pub fn notarize_namespace(committee: &Set<bls12381::PublicKey>) -> Vec<u8> {
    vote_sub_namespace(b"_NOTARIZE", committee)
}

/// Simplex nullify sub-namespace, committee-bound.
pub fn nullify_namespace(committee: &Set<bls12381::PublicKey>) -> Vec<u8> {
    vote_sub_namespace(b"_NULLIFY", committee)
}

/// Simplex finalize sub-namespace, committee-bound.
pub fn finalize_namespace(committee: &Set<bls12381::PublicKey>) -> Vec<u8> {
    vote_sub_namespace(b"_FINALIZE", committee)
}

/// Simplex VRF-seed sub-namespace: `outbe_app_namespace() || b"_SEED"`. Equals
/// `simplex_namespace().seed.as_slice()` byte-for-byte. Chain-only: the seed is a
/// threshold signature already bound to the committee via its group key.
pub fn hybrid_seed_namespace() -> Vec<u8> {
    sub_namespace(b"_SEED")
}

/// The canonical `(namespace, message)` pair for verifying a threshold-VRF seed
/// signature at `(round_epoch, round_view)`: the chain-bound seed namespace
/// ([`hybrid_seed_namespace`]) and the `Round::encode()` seed message.
///
/// This is the single derivation shared by the consensus verify paths
/// (`HybridScheme::verified_vrf_seed_for_round` / `verify_vrf_partial`) and the
/// proof-side plain verifiers (`seed_partial`, `verifier`), so they cannot
/// derive different bytes for the same seed round. `hybrid_seed_namespace()` is
/// asserted byte-equal to commonware's `Namespace::new(..).seed` by
/// [`tests::hybrid_seed_namespace_equals_commonware_seed_namespace`]; the seed
/// round's offset (e.g. the elector's `view().previous()`) is the caller's
/// responsibility - this helper is offset-agnostic.
pub fn seed_namespace_and_message(round_epoch: u64, round_view: u64) -> (Vec<u8>, Vec<u8>) {
    let message = Round::new(Epoch::new(round_epoch), View::new(round_view))
        .encode()
        .to_vec();
    (hybrid_seed_namespace(), message)
}

/// Seed-partial identity-attestation sub-namespace:
/// `outbe_app_namespace() || b"_SEEDATTEST"`. Chain-only (the VRF partial it
/// attributes is already committee-bound via the threshold polynomial).
///
/// Distinct from the four Simplex sub-namespaces so a seed-partial identity
/// signature can never be confused with a vote, nullify, finalize, or the
/// threshold-seed signature itself. Used by [`crate::proof::seed_partial`] - the
/// signer (`HybridScheme::sign`) and the SlashIndicator evidence verifier both
/// bind a validator's `bls_seed_partial` to its MinPk identity key under this
/// namespace so the partial becomes non-repudiably attributable.
pub fn seed_attest_namespace() -> Vec<u8> {
    sub_namespace(b"_SEEDATTEST")
}

/// Process-wide singleton of `Namespace::new(outbe_app_namespace())`.
///
/// Both signer (`outbe_consensus::config::simplex_namespace` re-exports this)
/// and the V2 verifier (this crate) read from the same `OnceLock`, so the four
/// `Vec<u8>` sub-namespaces are heap-allocated exactly once and signer/verifier
/// can never drift. [`init_consensus_chain_id`] MUST run before the first call
/// so the cached namespace binds the real chain.
pub fn simplex_namespace() -> &'static Namespace {
    &consensus_domain(&CONSENSUS_DOMAIN).simplex_namespace
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consensus_domain_install_is_idempotent_and_rejects_conflicts() {
        let cell = OnceLock::new();
        install_consensus_domain(&cell, 676).unwrap();
        install_consensus_domain(&cell, 676).unwrap();

        assert_eq!(
            install_consensus_domain(&cell, 70_860_602),
            Err(ConsensusChainIdError::AlreadyBound {
                installed: 676,
                requested: 70_860_602,
            })
        );
        assert_eq!(consensus_domain(&cell).chain_id, 676);
    }

    #[test]
    fn namespace_access_before_installation_is_a_detectable_zero_binding() {
        let cell = OnceLock::new();
        assert_eq!(consensus_domain(&cell).chain_id, 0);
        assert_eq!(
            install_consensus_domain(&cell, 676),
            Err(ConsensusChainIdError::AlreadyBound {
                installed: 0,
                requested: 676,
            })
        );
    }

    /// The proof-side seed verifiers use [`hybrid_seed_namespace`] (our explicit
    /// `b"_SEED"` suffix), while the consensus signer/verifier derive the seed
    /// namespace from commonware's `Namespace::new(..).seed` (`base ||
    /// SEED_SUFFIX`). These MUST be byte-identical or seed verification on the
    /// slashing and next-height-gate paths rejects valid signatures. This is the
    /// cross-path equality that was previously asserted only in a doc comment;
    /// pinning it as a test catches a commonware `SEED_SUFFIX` change (a reviewed
    /// dependency bump) at CI rather than silently at runtime.
    #[test]
    fn hybrid_seed_namespace_equals_commonware_seed_namespace() {
        assert_eq!(
            hybrid_seed_namespace().as_slice(),
            simplex_namespace().seed.as_slice(),
            "proof-side hybrid_seed_namespace() must equal commonware Namespace seed"
        );
    }

    /// The seed message is `Round::encode()`, and the recipe helper must produce
    /// exactly the bytes a directly-encoded `Round` does, for any round.
    #[test]
    fn seed_namespace_and_message_matches_direct_round_encode() {
        for (epoch, view) in [(0u64, 1u64), (12, 61), (7, 0), (u64::MAX, u64::MAX)] {
            let (namespace, message) = seed_namespace_and_message(epoch, view);
            assert_eq!(namespace, hybrid_seed_namespace());
            let expected = Round::new(Epoch::new(epoch), View::new(view))
                .encode()
                .to_vec();
            assert_eq!(message, expected, "seed message must equal Round::encode()");
        }
    }
}
