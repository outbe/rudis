//! Canonical V2 committee snapshot types and pure-function hashers.
//!
//! This module is the **single source of truth** for the wire-visible committee
//! snapshot shape used by every V2 consensus-proof path (Phase 1 verifier,
//! certified-parent proof store, Rewards/Slash fingerprints, slashing evidence
//! dedup, and the `apply_boundary_outcome` writer that seeds
//! `CommitteeSnapshotStore`). Everything in this file is pure data and pure
//! arithmetic - no storage, no async, and only a pure allocation-free build error - so it can be reused by full
//! nodes that have no validator runtime, and by the EVM executor that has no
//! consensus stack.
//!

use alloy_primitives::{Address, B256};
use thiserror::Error;

/// Initial VRF material version at genesis.
pub const VRF_MATERIAL_VERSION_GENESIS: u64 = 0;

/// Domain separation tag for the V2 committee set hash.
///
/// Must remain byte-for-byte stable: it is part of the V2 consensus binding
/// and any change forks the chain.
pub const OUTBE_COMMITTEE_SET_HASH_V2_DOMAIN: &[u8] = b"OUTBE_COMMITTEE_SNAPSHOT_V2";

/// Domain separation tag for the V2 committee snapshot storage key.
///
/// Distinct from [`OUTBE_COMMITTEE_SET_HASH_V2_DOMAIN`] so the snapshot key
/// and the committee hash are statistically and semantically unrelated.
pub const OUTBE_COMMITTEE_SNAPSHOT_KEY_V2_DOMAIN: &[u8] = b"OUTBE_COMMITTEE_SNAPSHOT_KEY_V2";

/// One ordered entry of a committee snapshot.
///
/// The pubkey is the 48-byte BLS12-381 MinPk consensus public key, matching
/// the `val_consensus_pubkey_lo/hi` schema layout in
/// `outbe-validatorset::schema`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitteeEntry {
    pub address: Address,
    pub consensus_pubkey: [u8; 48],
}

/// Canonical, ordered V2 committee snapshot.
///
/// `committee` is in Commonware `ordered::Set<bls12381::PublicKey>` order
/// (the same order used by the certificate signer bitmap). It is not
/// registration order and not sorted-by-address order. Re-ordering the
/// vector changes [`committee_set_hash_v2`].
///
/// `vrf_group_public_key_bytes` is the raw output of
/// `commonware_codec::Encode::encode(polynomial.public())` for the active
/// DKG output. Storing the raw bytes (instead of just a hash) lets full
/// nodes reconstruct the VRF verifier from state alone, without rerunning
/// the DKG.
///
/// The epoch is intentionally *not* part of the snapshot struct because the
/// snapshot store is keyed by `(epoch, committee_set_hash)`; callers pass
/// `epoch` to the hashing/keying helpers explicitly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitteeSnapshot {
    pub committee: Vec<CommitteeEntry>,
    pub vrf_material_version: u64,
    pub vrf_group_public_key_bytes: Vec<u8>,
    /// `keccak256(commonware_codec::Encode(polynomial))` of the active DKG
    /// output's FULL public polynomial (the Sharing commitment vector), or
    /// `B256::ZERO` when no full polynomial is available (e.g. a group-key-only
    /// bootstrap outcome).
    ///
    /// Unlike [`Self::vrf_group_public_key_bytes`] (only the constant term /
    /// group key), this commits to ALL coefficients, which is what lets a
    /// verifier derive any signer's threshold public key `PK_i` and check an
    /// individual seed partial. Stored so SlashIndicator can verify an
    /// "invalid seed partial" slash offense; the executor derives it from the
    /// already-consensus-validated boundary `outcome`, so a proposer cannot
    /// forge it (which would otherwise let an attacker frame an honest
    /// validator). Intentionally NOT folded into [`committee_set_hash_v2`] -
    /// its authenticity comes from the validated boundary artifact, not the
    /// committee fingerprint, so adding it changes no V2 binding.
    pub vrf_public_polynomial_hash: B256,
}

impl CommitteeSnapshot {
    /// Returns the canonical V2 committee hash for this snapshot at `epoch`.
    pub fn committee_set_hash_v2(&self, epoch: u64) -> B256 {
        committee_set_hash_v2(epoch, self)
    }

    /// Returns the canonical V2 storage key for this snapshot at `epoch`.
    pub fn snapshot_key(&self, epoch: u64) -> B256 {
        committee_snapshot_key(epoch, self.committee_set_hash_v2(epoch))
    }
}

/// Canonical V2 committee set hash.
///
/// Layout:
///
/// ```text
/// keccak256(
///     "OUTBE_COMMITTEE_SNAPSHOT_V2"
///  || epoch.to_be_bytes()                       // 8  bytes, big-endian
///  || (committee.len() as u64).to_be_bytes()    // 8  bytes, big-endian
///  || ( address_20_bytes || min_pk_pubkey_48_bytes ) * committee.len()
///  || vrf_material_version.to_be_bytes()        // 8  bytes, big-endian
///  || (vrf_group_pk.len() as u64).to_be_bytes() // 8  bytes, big-endian
///  || vrf_group_public_key_bytes                // variable
/// )
/// ```
///
/// The domain prefix and the per-entry pubkey both differ from the legacy
/// address-only `hash_active_set`; equality between the two hashes for any
/// committee is a fingerprint mismatch (tested explicitly).
pub fn committee_set_hash_v2(epoch: u64, snapshot: &CommitteeSnapshot) -> B256 {
    let committee_len_bytes = (snapshot.committee.len() as u64).to_be_bytes();
    let vrf_pk_len_bytes = (snapshot.vrf_group_public_key_bytes.len() as u64).to_be_bytes();

    let capacity = OUTBE_COMMITTEE_SET_HASH_V2_DOMAIN.len()
        + 8
        + 8
        + snapshot.committee.len() * (20 + 48)
        + 8
        + 8
        + snapshot.vrf_group_public_key_bytes.len();
    let mut buf = Vec::with_capacity(capacity);
    buf.extend_from_slice(OUTBE_COMMITTEE_SET_HASH_V2_DOMAIN);
    buf.extend_from_slice(&epoch.to_be_bytes());
    buf.extend_from_slice(&committee_len_bytes);
    for entry in &snapshot.committee {
        buf.extend_from_slice(entry.address.as_slice());
        buf.extend_from_slice(&entry.consensus_pubkey);
    }
    buf.extend_from_slice(&snapshot.vrf_material_version.to_be_bytes());
    buf.extend_from_slice(&vrf_pk_len_bytes);
    buf.extend_from_slice(&snapshot.vrf_group_public_key_bytes);
    alloy_primitives::keccak256(&buf)
}

/// Canonical V2 committee snapshot storage key.
///
/// Layout:
///
/// ```text
/// keccak256(
///     "OUTBE_COMMITTEE_SNAPSHOT_KEY_V2"
///  || epoch.to_be_bytes()        // 8  bytes, big-endian
///  || committee_set_hash         // 32 bytes
/// )
/// ```
pub fn committee_snapshot_key(epoch: u64, committee_set_hash: B256) -> B256 {
    let capacity = OUTBE_COMMITTEE_SNAPSHOT_KEY_V2_DOMAIN.len() + 8 + 32;
    let mut buf = Vec::with_capacity(capacity);
    buf.extend_from_slice(OUTBE_COMMITTEE_SNAPSHOT_KEY_V2_DOMAIN);
    buf.extend_from_slice(&epoch.to_be_bytes());
    buf.extend_from_slice(committee_set_hash.as_slice());
    alloy_primitives::keccak256(&buf)
}

/// Error from [`build_committee_snapshot`].
///
/// Pure and allocation-free, so `committee.rs` stays reusable by full nodes and
/// the EVM executor (no runtime, no storage, no async). Both variants are
/// invariant violations that, under the current Commonware MinPk encoding,
/// cannot occur; the strict checks exist so a future encode-size drift surfaces
/// as a typed error here instead of a silent truncation that would fork the
/// committee fingerprint downstream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum SnapshotBuildError {
    /// `addresses` and `encoded_pubkeys` had different lengths.
    #[error("committee snapshot build: {addresses} addresses but {pubkeys} encoded pubkeys")]
    CountMismatch { addresses: usize, pubkeys: usize },
    /// Entry `index`'s encoded consensus pubkey was not exactly 48 bytes.
    #[error(
        "committee snapshot build: entry {index} consensus pubkey encoded to {got} bytes, expected 48"
    )]
    PubkeyLength { index: usize, got: usize },
}

/// Build the single canonical [`CommitteeSnapshot`] from already-extracted
/// primitives.
///
/// This is the one construction path feeding [`committee_set_hash_v2`]. Runtime
/// callers (the finalization actor/resolver, the reporter, and the DKG manager)
/// extract the ordered committee from their `HybridScheme` / DKG output and pass
/// primitives here, so `committee.rs` never sees a runtime type and stays
/// reusable by the EVM executor and full nodes.
///
/// `addresses[i]` and `encoded_pubkeys[i]` MUST be in the SAME Commonware
/// `ordered::Set` participant order (the certificate signer-bitmap order);
/// `encoded_pubkeys[i]` is the raw `commonware_codec::Encode` of the i-th MinPk
/// public key. Encoding to 48 bytes is **strict**: a pubkey that is not exactly
/// 48 bytes is a [`SnapshotBuildError::PubkeyLength`], never a silent truncation.
///
/// `vrf_public_polynomial_hash` is stored as-is and is intentionally NOT folded
/// into [`committee_set_hash_v2`] (see
/// [`CommitteeSnapshot::vrf_public_polynomial_hash`]), so passing `B256::ZERO`
/// (the metadata-reconstruction paths) versus the real hash (the
/// proposer/executor paths) does not change the committee fingerprint.
pub fn build_committee_snapshot(
    addresses: &[Address],
    encoded_pubkeys: &[impl AsRef<[u8]>],
    vrf_material_version: u64,
    vrf_group_public_key_bytes: Vec<u8>,
    vrf_public_polynomial_hash: B256,
) -> Result<CommitteeSnapshot, SnapshotBuildError> {
    if addresses.len() != encoded_pubkeys.len() {
        return Err(SnapshotBuildError::CountMismatch {
            addresses: addresses.len(),
            pubkeys: encoded_pubkeys.len(),
        });
    }
    let mut committee = Vec::with_capacity(addresses.len());
    for (index, (address, encoded)) in addresses.iter().zip(encoded_pubkeys.iter()).enumerate() {
        let bytes = encoded.as_ref();
        let consensus_pubkey: [u8; 48] =
            bytes
                .try_into()
                .map_err(|_| SnapshotBuildError::PubkeyLength {
                    index,
                    got: bytes.len(),
                })?;
        committee.push(CommitteeEntry {
            address: *address,
            consensus_pubkey,
        });
    }
    Ok(CommitteeSnapshot {
        committee,
        vrf_material_version,
        vrf_group_public_key_bytes,
        vrf_public_polynomial_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(n: u8) -> Address {
        let mut a = [0u8; 20];
        a[19] = n;
        Address::from(a)
    }

    #[test]
    fn build_matches_hand_built_snapshot_and_hash() {
        let addresses = vec![addr(1), addr(2), addr(3)];
        let pubkeys: Vec<[u8; 48]> = vec![[1u8; 48], [2u8; 48], [3u8; 48]];
        let group = vec![9u8; 96];

        let built = build_committee_snapshot(&addresses, &pubkeys, 7, group.clone(), B256::ZERO)
            .expect("valid 48-byte pubkeys build");

        let expected = CommitteeSnapshot {
            committee: vec![
                CommitteeEntry {
                    address: addr(1),
                    consensus_pubkey: [1u8; 48],
                },
                CommitteeEntry {
                    address: addr(2),
                    consensus_pubkey: [2u8; 48],
                },
                CommitteeEntry {
                    address: addr(3),
                    consensus_pubkey: [3u8; 48],
                },
            ],
            vrf_material_version: 7,
            vrf_group_public_key_bytes: group,
            vrf_public_polynomial_hash: B256::ZERO,
        };
        assert_eq!(built, expected);
        assert_eq!(
            committee_set_hash_v2(4, &built),
            committee_set_hash_v2(4, &expected)
        );
    }

    #[test]
    fn rejects_pubkey_that_is_not_48_bytes() {
        let addresses = vec![addr(1), addr(2)];
        // Second pubkey is 47 bytes - a hypothetical Commonware encode-size drift.
        let pubkeys: Vec<Vec<u8>> = vec![vec![1u8; 48], vec![2u8; 47]];
        let err = build_committee_snapshot(&addresses, &pubkeys, 0, Vec::new(), B256::ZERO)
            .expect_err("47-byte pubkey must be rejected, not truncated");
        assert_eq!(err, SnapshotBuildError::PubkeyLength { index: 1, got: 47 });
    }

    #[test]
    fn rejects_address_pubkey_count_mismatch() {
        let addresses = vec![addr(1), addr(2)];
        let pubkeys: Vec<[u8; 48]> = vec![[1u8; 48]];
        let err = build_committee_snapshot(&addresses, &pubkeys, 0, Vec::new(), B256::ZERO)
            .expect_err("count mismatch must be rejected");
        assert_eq!(
            err,
            SnapshotBuildError::CountMismatch {
                addresses: 2,
                pubkeys: 1
            }
        );
    }

    #[test]
    fn committee_order_changes_the_hash() {
        let pubkeys: Vec<[u8; 48]> = vec![[1u8; 48], [2u8; 48]];
        let a = build_committee_snapshot(&[addr(1), addr(2)], &pubkeys, 0, Vec::new(), B256::ZERO)
            .unwrap();
        let b = build_committee_snapshot(&[addr(2), addr(1)], &pubkeys, 0, Vec::new(), B256::ZERO)
            .unwrap();
        assert_ne!(
            committee_set_hash_v2(1, &a),
            committee_set_hash_v2(1, &b),
            "committee order is part of the fingerprint"
        );
    }

    #[test]
    fn poly_hash_is_excluded_from_committee_set_hash() {
        let addresses = vec![addr(1)];
        let pubkeys: Vec<[u8; 48]> = vec![[5u8; 48]];
        let zero =
            build_committee_snapshot(&addresses, &pubkeys, 3, vec![1, 2, 3], B256::ZERO).unwrap();
        let nonzero = build_committee_snapshot(
            &addresses,
            &pubkeys,
            3,
            vec![1, 2, 3],
            B256::repeat_byte(0xab),
        )
        .unwrap();
        assert_ne!(zero, nonzero, "snapshots differ in the stored poly hash");
        assert_eq!(
            committee_set_hash_v2(2, &zero),
            committee_set_hash_v2(2, &nonzero),
            "vrf_public_polynomial_hash must not affect committee_set_hash_v2"
        );
    }
}
