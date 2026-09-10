//! Canonical committee-snapshot prelude.
//!
//! Four consensus paths build a [`CommitteeSnapshot`] and its
//! `committee_set_hash_v2` fingerprint from an epoch's signer set before writing
//! a `CertifiedParentProofRecord`:
//! - the reporter's `Activity::Certification` witness,
//! - the finalization actor's finalization-slot record,
//! - the resolver's remote-fetch witness (`fetch_parent_proof`), and
//! - the resolver's recovered-record builder.
//!
//! They MUST agree byte-for-byte: `committee_set_hash` is consensus-visible, and
//! `vrf_group_public_key_hash` is bound by the Phase 1 verifier (Rule 6,
//! `proof::verifier`). Hand-replicating the prelude at four sites risked drift;
//! it also let one site (`fetch_parent_proof`) skip the
//! `vrf_group_public_key_hash` computation, leaving `B256::ZERO` on records that
//! `to_v2_metadata` promotes into Phase 1 - which Rule 6 then rejects. Sharing
//! one builder removes the drift risk and guarantees the hash is populated on
//! every write.
//!
//! The DKG boundary writer (`dkg_manager`) is intentionally NOT a caller: it
//! passes a real `vrf_public_polynomial_hash` (not `B256::ZERO`) derived from the
//! full DKG polynomial, a distinct computation.

use alloy_primitives::{keccak256, Address, B256};
use commonware_codec::Encode as _;
use commonware_cryptography::{bls12381::primitives::variant::MinSig, certificate::Scheme as _};

use crate::hybrid::HybridScheme;
use crate::proof::{
    build_committee_snapshot, committee_set_hash_v2, CommitteeSnapshot, SnapshotBuildError,
};

/// The committee-snapshot inputs every V2 certified-parent proof record needs,
/// derived once from the active scheme so all writers agree byte-for-byte.
pub struct CommitteePrelude {
    /// Canonical committee snapshot (committee entries + raw VRF group key bytes).
    pub snapshot: CommitteeSnapshot,
    /// Consensus-visible fingerprint `committee_set_hash_v2(epoch, &snapshot)`.
    pub committee_set_hash: B256,
    /// Active VRF material version for the epoch.
    pub vrf_material_version: u64,
    /// `keccak256` of the encoded VRF group public key (`B256::ZERO` when the
    /// scheme has no identity yet). Bound by Phase 1 verifier Rule 6, so every
    /// certified-parent record MUST carry it.
    pub vrf_group_public_key_hash: B256,
}

/// Build the canonical [`CommitteePrelude`] for `epoch` from `scheme` and the
/// ordered `addresses`.
///
/// The fifth `build_committee_snapshot` argument (`vrf_public_polynomial_hash`)
/// is `B256::ZERO` for every non-DKG path and is excluded from
/// `committee_set_hash_v2`, so the snapshot fingerprint depends only on the
/// committee, `vrf_material_version`, and the raw VRF group-key bytes.
pub fn build_committee_prelude(
    scheme: &HybridScheme<MinSig>,
    addresses: &[Address],
    epoch: u64,
) -> Result<CommitteePrelude, SnapshotBuildError> {
    let vrf_material_version = scheme.expected_vrf_material_version();
    let vrf_group_public_key_bytes: Vec<u8> = scheme
        .identity()
        .map(|pk| pk.encode().as_ref().to_vec())
        .unwrap_or_default();
    let vrf_group_public_key_hash = if vrf_group_public_key_bytes.is_empty() {
        B256::ZERO
    } else {
        keccak256(&vrf_group_public_key_bytes)
    };
    let encoded_pubkeys: Vec<Vec<u8>> = scheme
        .participants()
        .iter()
        .map(|pubkey| pubkey.encode().as_ref().to_vec())
        .collect();
    let snapshot = build_committee_snapshot(
        addresses,
        &encoded_pubkeys,
        vrf_material_version,
        vrf_group_public_key_bytes,
        B256::ZERO,
    )?;
    let committee_set_hash = committee_set_hash_v2(epoch, &snapshot);
    Ok(CommitteePrelude {
        snapshot,
        committee_set_hash,
        vrf_material_version,
        vrf_group_public_key_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bls::bootstrap_dkg;
    use commonware_cryptography::{bls12381, Signer as _};
    use commonware_utils::{ordered::Set, TryCollect as _};

    fn verifier_scheme(n: u8) -> HybridScheme<MinSig> {
        let keys: Vec<bls12381::PrivateKey> = (0..n)
            .map(|i| bls12381::PrivateKey::from_seed((i + 1) as u64))
            .collect();
        let participants: Set<bls12381::PublicKey> = keys
            .iter()
            .map(|sk| bls12381::PublicKey::from(sk.clone()))
            .try_collect()
            .unwrap();
        let dkg = bootstrap_dkg(u32::from(n)).unwrap();
        HybridScheme::<MinSig>::verifier(b"prelude-test", participants, dkg.polynomial).unwrap()
    }

    fn addresses(n: u8) -> Vec<Address> {
        (0..n).map(|i| Address::with_last_byte(i + 1)).collect()
    }

    /// Regression for the `fetch_parent_proof` `vrf_group_public_key_hash = ZERO`
    /// bug: the prelude's hash MUST equal the value the Phase 1 verifier (Rule 6,
    /// `proof::verifier`) recomputes as `keccak256(snapshot.vrf_group_public_key_bytes)`,
    /// so any certified-parent record built from the prelude passes Rule 6. Before
    /// the unification, `fetch_parent_proof` left this `B256::ZERO`, and a promoted
    /// witness record would fail Rule 6.
    #[test]
    fn prelude_hash_matches_phase1_rule6_recomputation() {
        let scheme = verifier_scheme(4);
        let prelude = build_committee_prelude(&scheme, &addresses(4), 0).unwrap();

        assert!(
            !prelude.snapshot.vrf_group_public_key_bytes.is_empty(),
            "verifier scheme must expose a non-empty VRF group key"
        );
        assert_ne!(prelude.vrf_group_public_key_hash, B256::ZERO);
        assert_eq!(
            prelude.vrf_group_public_key_hash,
            keccak256(&prelude.snapshot.vrf_group_public_key_bytes),
            "prelude hash must equal the Phase 1 Rule 6 recomputation"
        );
    }

    /// The prelude's `committee_set_hash` and `vrf_material_version` match
    /// recomputation directly off the produced snapshot (single source of truth).
    #[test]
    fn prelude_committee_set_hash_matches_snapshot() {
        let scheme = verifier_scheme(4);
        let epoch = 7u64;
        let prelude = build_committee_prelude(&scheme, &addresses(4), epoch).unwrap();

        assert_eq!(
            prelude.committee_set_hash,
            committee_set_hash_v2(epoch, &prelude.snapshot)
        );
        assert_eq!(
            prelude.vrf_material_version,
            scheme.expected_vrf_material_version()
        );
    }

    /// A committee/pubkey count mismatch surfaces as a structured
    /// `SnapshotBuildError`, not a panic (the address list is shorter than the
    /// scheme's participant set).
    #[test]
    fn prelude_propagates_snapshot_build_error() {
        let scheme = verifier_scheme(4);
        let result = build_committee_prelude(&scheme, &addresses(3), 0);
        assert!(matches!(
            result,
            Err(SnapshotBuildError::CountMismatch { .. })
        ));
    }
}
