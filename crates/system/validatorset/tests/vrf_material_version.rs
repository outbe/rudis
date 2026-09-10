//! Integration tests for the `vrf_material_version` checked-arithmetic
//! activation rule.
//!
//! The rule has two halves:
//!
//! 1. At genesis the version is exactly `0`. Each successful reshare
//!    activation produces exactly `previous + 1` - never `previous` and never
//!    `previous + 2`.
//! 2. At `u64::MAX` the activation **rejects deterministically** with
//!    [`outbe_validatorset::ActivationError::VrfVersionOverflow`]. Saturation
//!    would let two distinct DKG outputs share a version, silently breaking
//!    the V2 metadata binding (`vrf_material_version` + `vrf_group_public_key_hash`
//!    are the identity of the active material in finalized-parent metadata).

use outbe_validatorset::{
    next_vrf_material_version, ActivationError, VRF_MATERIAL_VERSION_GENESIS,
};

// ---------------------------------------------------------------------------
// 10. Zero at genesis; increments by exactly one per reshare.
// ---------------------------------------------------------------------------

#[test]
fn vrf_material_version_zero_at_genesis_and_increments_by_one_per_reshare() {
    // Genesis: pin the genesis value to 0.
    assert_eq!(VRF_MATERIAL_VERSION_GENESIS, 0);

    // Five consecutive successful reshare activations: 0 -> 1 -> 2 -> 3 -> 4 -> 5.
    let mut v = VRF_MATERIAL_VERSION_GENESIS;
    for expected in 1..=5u64 {
        v = next_vrf_material_version(v).expect("non-overflow increment");
        assert_eq!(
            v, expected,
            "vrf_material_version must increment by exactly 1 per reshare"
        );
    }

    // Sanity: spot-check a non-trivial jump in the middle of the u64 range.
    let mid = 1_000_000u64;
    assert_eq!(
        next_vrf_material_version(mid).unwrap(),
        mid + 1,
        "monotonic +1 must hold across the full u64 range until u64::MAX",
    );

    // Sanity: it is strictly monotonic - successive calls must not return the
    // same value (this would be the failure signature of a saturating impl).
    let a = next_vrf_material_version(0).unwrap();
    let b = next_vrf_material_version(a).unwrap();
    assert!(b > a);
}

// ---------------------------------------------------------------------------
// 11. Overflow rejects activation instead of saturating.
// ---------------------------------------------------------------------------

#[test]
fn vrf_material_version_overflow_rejects_activation_not_saturates() {
    // u64::MAX + 1 overflows. The rule says: reject deterministically with
    // ActivationError::VrfVersionOverflow - never return u64::MAX (which would
    // be the saturation outcome and break version uniqueness).
    let result = next_vrf_material_version(u64::MAX);

    match result {
        Err(ActivationError::VrfVersionOverflow) => { /* expected */ }
        Err(other) => panic!("expected ActivationError::VrfVersionOverflow, got {other:?}"),
        Ok(v) => panic!("expected overflow rejection, got Ok({v}) - saturation is not allowed"),
    }

    // u64::MAX - 1 -> u64::MAX is the last successful step; only the *next*
    // call must reject. This pins the boundary.
    assert_eq!(
        next_vrf_material_version(u64::MAX - 1).unwrap(),
        u64::MAX,
        "increment to u64::MAX is still a valid activation; only the step \
         past u64::MAX rejects",
    );
    assert!(
        matches!(
            next_vrf_material_version(u64::MAX),
            Err(ActivationError::VrfVersionOverflow),
        ),
        "step past u64::MAX must reject deterministically",
    );

    // Sanity: the error renders to a stable user-visible message so the
    // operator log line in `stack.rs` doesn't drift silently.
    let err = next_vrf_material_version(u64::MAX).unwrap_err();
    assert_eq!(
        err.to_string(),
        "vrf material version overflow at reshare activation",
    );
}
