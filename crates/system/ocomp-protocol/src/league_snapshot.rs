//! Shared slot layout and commitment for the Metadosis-owned Fidelity league
//! snapshot.
//!
//! During the OCOMP prepare phase Metadosis writes one league word per
//! participating owner into `MetadosisContract.ocomp_fidelity_league_snapshot`
//! (a `Mapping<B256, u16>`). The OCOMP openings then MPT-prove exactly those
//! slots against the finalized state root instead of reconstructing the raw
//! Fidelity cohort ledger. Both the node opening builder/verifier and the
//! off-chain worker need a pure, storage-handle-free way to derive the same
//! slots and re-check the same commitment, so the derivation lives here - the
//! one crate node, worker and Metadosis all depend on.

use alloy_primitives::{keccak256, Address, B256, U256};

/// Global storage base slot of `MetadosisContract.ocomp_fidelity_league_snapshot`.
///
/// The `#[storage_schema]` macro assigns this as the cumulative slot count of
/// every preceding field, so it is a layout fact of the Metadosis contract that
/// cannot be imported at compile time. It is pinned by
/// `metadosis::ocomp::league_snapshot` tests asserting it equals the live
/// `Mapping::base_slot()`; if the Metadosis layout ever changes, that test
/// fails loudly rather than silently opening the wrong slots.
///
/// Derivation (anchored on the pinned `OCOMP_JOB_RECORDS_BASE_SLOT = 21`,
/// order 8): orders 9-13 are single-slot each (22..=26), order 14
/// `ocomp_day_limit_formations` is a `Map<_, record(2 slots)>` (27..=28),
/// orders 15-19 single-slot each (29..=33), so the appended order-20 snapshot
/// mapping lands at 34.
pub const METADOSIS_LEAGUE_SNAPSHOT_BASE_SLOT: u64 = 34;

/// Domain separator for the composite `(wwd, owner)` mapping key, keeping the
/// league-snapshot key space disjoint from any other B256-keyed mapping.
const LEAGUE_SNAPSHOT_KEY_DOMAIN: u8 = 0x4c; // 'L'

/// Domain prefix for the ordered snapshot commitment bound into the sealed
/// pre-admission envelope (`fidelity_league_snapshot_root`).
const LEAGUE_SNAPSHOT_ROOT_DOMAIN: &[u8] = b"OUTBE_OCOMP_FIDELITY_LEAGUE_SNAPSHOT_ROOT_V1";

/// Canonical `Mapping<B256, u16>` key for one owner's league on `wwd`:
/// `keccak(domain(1) ++ wwd_be(4) ++ owner(20))`. Mirrors Fidelity's
/// `cohort_key` composite-key pattern.
#[must_use]
pub fn league_snapshot_key(wwd: u32, owner: Address) -> B256 {
    let mut buf = [0u8; 1 + 4 + 20];
    buf[0] = LEAGUE_SNAPSHOT_KEY_DOMAIN;
    buf[1..5].copy_from_slice(&wwd.to_be_bytes());
    buf[5..25].copy_from_slice(owner.as_slice());
    keccak256(buf)
}

/// The exact EVM storage slot Metadosis writes owner's league to:
/// `keccak(left_pad(key, 32) ++ base_slot)` - the standard mapping-slot rule
/// applied to [`league_snapshot_key`] at [`METADOSIS_LEAGUE_SNAPSHOT_BASE_SLOT`].
///
/// The rule is inlined (rather than using `outbe_primitives`'s `StorageKey`)
/// because this crate is a non-dev dependency of `outbe-primitives`; the
/// [`league_snapshot_slot_matches_dsl_mapping`] test in `outbe-metadosis` pins
/// this against the live `Mapping::get(..).slot()`.
#[must_use]
pub fn league_snapshot_slot(wwd: u32, owner: Address) -> B256 {
    let key = league_snapshot_key(wwd, owner);
    // The key is already 32 bytes, so no left-padding is needed.
    let mut buf = [0u8; 64];
    buf[..32].copy_from_slice(key.as_slice());
    buf[32..].copy_from_slice(&U256::from(METADOSIS_LEAGUE_SNAPSHOT_BASE_SLOT).to_be_bytes::<32>());
    keccak256(buf)
}

/// League slots for a strictly-ordered owner set, in owner order. The caller is
/// responsible for supplying canonical (ordered, unique) owners; this simply
/// maps each to its slot so the opening's `ordered_slots` follow the owner
/// order both the builder and verifier reconstruct.
#[must_use]
pub fn ordered_league_snapshot_slots(wwd: u32, owners: &[Address]) -> Vec<B256> {
    owners
        .iter()
        .map(|owner| league_snapshot_slot(wwd, *owner))
        .collect()
}

/// Ordered commitment over the snapshotted `(owner, league)` pairs, bound into
/// the sealed `PreAdmissionEnvelopeV1` so the day's participating owner/league
/// set is consensus-committed and re-checkable when verifying an opening.
///
/// `entries` must be in the same strict owner order used to build the opening.
/// Encoding: `domain ++ wwd_be(4) ++ count_be(4) ++ (owner(20) ++ league_be(2))*`.
#[must_use]
pub fn fidelity_league_snapshot_root(wwd: u32, entries: &[(Address, u16)]) -> B256 {
    let mut buf = Vec::with_capacity(LEAGUE_SNAPSHOT_ROOT_DOMAIN.len() + 8 + entries.len() * 22);
    buf.extend_from_slice(LEAGUE_SNAPSHOT_ROOT_DOMAIN);
    buf.extend_from_slice(&wwd.to_be_bytes());
    // Length is bounded by the day's tribute count; saturate rather than cast so
    // the commitment stays total without a narrowing `as`.
    let count = u32::try_from(entries.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&count.to_be_bytes());
    for (owner, league) in entries {
        buf.extend_from_slice(owner.as_slice());
        buf.extend_from_slice(&league.to_be_bytes());
    }
    keccak256(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::address;

    const OWNER_A: Address = address!("0x1111111111111111111111111111111111111111");
    const OWNER_B: Address = address!("0x2222222222222222222222222222222222222222");

    #[test]
    fn slot_is_stable_known_vector() {
        // Guards the exact key + base-slot derivation against accidental drift.
        // The companion `outbe-metadosis` test proves this equals the live DSL
        // `Mapping` slot; this pins the value itself.
        let expected = league_snapshot_key(20_000, OWNER_A);
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(expected.as_slice());
        buf[32..]
            .copy_from_slice(&U256::from(METADOSIS_LEAGUE_SNAPSHOT_BASE_SLOT).to_be_bytes::<32>());
        assert_eq!(league_snapshot_slot(20_000, OWNER_A), keccak256(buf));
        // Base slot must be the appended order-20 mapping slot.
        assert_eq!(METADOSIS_LEAGUE_SNAPSHOT_BASE_SLOT, 34);
    }

    #[test]
    fn distinct_owners_and_days_get_distinct_slots() {
        assert_ne!(
            league_snapshot_slot(1, OWNER_A),
            league_snapshot_slot(1, OWNER_B)
        );
        assert_ne!(
            league_snapshot_slot(1, OWNER_A),
            league_snapshot_slot(2, OWNER_A)
        );
    }

    #[test]
    fn root_is_order_sensitive() {
        let ab = fidelity_league_snapshot_root(7, &[(OWNER_A, 3), (OWNER_B, 9)]);
        let ba = fidelity_league_snapshot_root(7, &[(OWNER_B, 9), (OWNER_A, 3)]);
        assert_ne!(ab, ba);
        // League value participates in the commitment.
        assert_ne!(
            ab,
            fidelity_league_snapshot_root(7, &[(OWNER_A, 4), (OWNER_B, 9)])
        );
    }
}
