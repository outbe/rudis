use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use alloy_primitives::{Address, U256};
use outbe_primitives::consensus_p2p::{encode_v1, P2pAddress, P2P_ADDRESS_VERSION_V1};

use crate::runtime::status::{ACTIVE, EXITING, INACTIVE, JAILED, PENDING, REGISTERED, UNBONDING};

use super::*;

const ADDRESS: Address = Address::repeat_byte(0x11);
const KEY: ConsensusPubkey = [7; 48];

fn history() -> ValidatorHistory {
    ValidatorHistory::new(13, Some(21), 2, 3, 5, 8)
}

fn canonical_history(status: u8, jailed_at: u64) -> ValidatorHistory {
    let deactivated_at = match status {
        ACTIVE => None,
        JAILED => Some(jailed_at),
        EXITING | UNBONDING | INACTIVE => Some(21),
        _ => Some(21),
    };
    ValidatorHistory::new(13, deactivated_at, 2, 3, 5, 8)
}

fn decode(
    status: u8,
    share: bool,
    confirmed: bool,
    jailed_at: u64,
    stake: StakeProjection,
) -> outbe_primitives::error::Result<ValidatorState> {
    ValidatorState::decode_stored(
        ADDRESS,
        3,
        KEY,
        stake,
        status,
        0,
        &[],
        canonical_history(status, jailed_at),
        share,
        confirmed,
        jailed_at,
    )
}

fn canonical(status: u8, share: bool, confirmed: bool, jailed_at: u64) -> ValidatorState {
    let stake = if status == INACTIVE {
        StakeProjection::zero()
    } else {
        StakeProjection::new(U256::from(1_500), Some(34))
    };
    decode(status, share, confirmed, jailed_at, stake).unwrap()
}

#[test]
fn raw_statuses_decode_to_every_canonical_state() {
    let cases = [
        (REGISTERED, false, false, 0, "waiting-for-stake"),
        (PENDING, false, false, 0, "waiting-for-readiness"),
        (PENDING, false, true, 0, "joining"),
        (ACTIVE, true, false, 0, "active"),
        (EXITING, true, false, 0, "exiting"),
        (UNBONDING, false, false, 0, "unbonding"),
        (INACTIVE, false, false, 0, "inactive"),
        (JAILED, true, false, 55, "jail-retained"),
        (JAILED, false, false, 55, "jail"),
    ];

    for (status, share, confirmed, jailed_at, expected) in cases {
        let state = canonical(status, share, confirmed, jailed_at);
        let actual = match state.lifecycle() {
            ValidatorLifecycle::Absent => "absent",
            ValidatorLifecycle::WaitingForStake(_) => "waiting-for-stake",
            ValidatorLifecycle::WaitingForReadiness(_) => "waiting-for-readiness",
            ValidatorLifecycle::Joining(_) => "joining",
            ValidatorLifecycle::Active(_) => "active",
            ValidatorLifecycle::JailRetained(_) => "jail-retained",
            ValidatorLifecycle::Jail(_) => "jail",
            ValidatorLifecycle::Exiting(_) => "exiting",
            ValidatorLifecycle::Unbonding(_) => "unbonding",
            ValidatorLifecycle::Inactive(_) => "inactive",
        };
        assert_eq!(actual, expected);
        assert_eq!(state.stored_status(), Some(status));
        assert_eq!(state.has_bls_share(), share);
        assert_eq!(state.join_confirmed(), confirmed);
        assert_eq!(state.stored_jailed_at(), jailed_at);
    }
}

#[test]
fn unknown_statuses_fail_closed() {
    for status in 7..=u8::MAX {
        assert!(decode(status, false, false, 0, StakeProjection::zero()).is_err());
    }
}

#[test]
fn every_noncanonical_coupled_field_combination_fails_closed() {
    let invalid = [
        (REGISTERED, true, false, 0),
        (REGISTERED, false, true, 0),
        (PENDING, true, false, 0),
        (PENDING, true, true, 0),
        (ACTIVE, false, false, 0),
        (ACTIVE, true, true, 0),
        (EXITING, false, false, 0),
        (EXITING, true, true, 0),
        (UNBONDING, true, false, 0),
        (UNBONDING, false, true, 0),
        (INACTIVE, true, false, 0),
        (INACTIVE, false, true, 0),
        (JAILED, true, true, 10),
        (JAILED, false, true, 10),
        (ACTIVE, true, false, 10),
    ];

    for (status, share, confirmed, jailed_at) in invalid {
        let stake = if status == INACTIVE {
            StakeProjection::zero()
        } else {
            StakeProjection::new(U256::from(1_500), None)
        };
        assert!(decode(status, share, confirmed, jailed_at, stake).is_err());
    }
}

#[test]
fn absence_requires_all_validator_owned_fields_to_be_empty() {
    let absent = ValidatorState::decode_stored(
        ADDRESS,
        0,
        [0; 48],
        StakeProjection::zero(),
        REGISTERED,
        0,
        &[],
        ValidatorHistory::fresh(0),
        false,
        false,
        0,
    )
    .unwrap();
    assert_eq!(absent.lifecycle(), &ValidatorLifecycle::Absent);
    assert!(!absent.is_registered());
    assert_eq!(absent.registry_index(), None);
    assert_eq!(absent.consensus_pubkey(), None);
    assert_eq!(absent.bonded_stake(), U256::ZERO);

    let pre_registration_stake = ValidatorState::decode_stored(
        ADDRESS,
        0,
        [0; 48],
        StakeProjection::new(U256::from(1), None),
        REGISTERED,
        0,
        &[],
        ValidatorHistory::fresh(0),
        false,
        false,
        0,
    );
    assert!(pre_registration_stake.is_err());
}

#[test]
fn registered_identity_requires_a_nonzero_consensus_key() {
    let state = ValidatorState::decode_stored(
        ADDRESS,
        1,
        [0; 48],
        StakeProjection::zero(),
        REGISTERED,
        0,
        &[],
        history(),
        false,
        false,
        0,
    );
    assert!(state.is_err());
}

#[test]
fn p2p_version_and_payload_decode_atomically() {
    let address = P2pAddress::Symmetric(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 30_400));
    let encoded = encode_v1(&address);
    let state = ValidatorState::decode_stored(
        ADDRESS,
        1,
        KEY,
        StakeProjection::zero(),
        REGISTERED,
        P2P_ADDRESS_VERSION_V1,
        &encoded,
        history(),
        false,
        false,
        0,
    )
    .unwrap();
    assert_eq!(state.p2p().and_then(P2pInfo::address), Some(&address));
    assert_eq!(
        state.p2p().unwrap().encode_stored(),
        (P2P_ADDRESS_VERSION_V1, encoded)
    );

    assert!(ValidatorState::decode_stored(
        ADDRESS,
        1,
        KEY,
        StakeProjection::zero(),
        REGISTERED,
        P2P_ADDRESS_VERSION_V1,
        &[],
        history(),
        false,
        false,
        0,
    )
    .is_err());

    let opaque_payload = vec![0xAA, 0xBB];
    let opaque = ValidatorState::decode_stored(
        ADDRESS,
        1,
        KEY,
        StakeProjection::zero(),
        REGISTERED,
        99,
        &opaque_payload,
        history(),
        false,
        false,
        0,
    )
    .unwrap();
    assert_eq!(opaque.p2p().and_then(P2pInfo::address), None);
    assert_eq!(opaque.p2p().unwrap().encode_stored(), (99, opaque_payload));
}

#[test]
fn predicates_follow_effective_states_not_raw_status_groups() {
    let active = canonical(ACTIVE, true, false, 0);
    let exiting = canonical(EXITING, true, false, 0);
    let retained = canonical(JAILED, true, false, 9);
    let jail = canonical(JAILED, false, false, 9);
    let waiting = canonical(PENDING, false, false, 0);
    let joining = canonical(PENDING, false, true, 0);

    assert!(active.lifecycle().is_current_consensus_participant());
    assert!(exiting.lifecycle().is_current_consensus_participant());
    assert!(retained.lifecycle().is_current_consensus_participant());
    assert!(!jail.lifecycle().is_current_consensus_participant());
    assert!(!waiting.lifecycle().is_reshare_target());
    assert!(joining.lifecycle().is_reshare_target());
    assert!(active.lifecycle().is_reshare_target());
    assert!(jail.lifecycle().is_secondary_admission());
}

#[test]
fn join_path_consumes_each_source_state() {
    let absent = ValidatorState::absent(ADDRESS);
    let registered = register(absent, std::num::NonZeroU64::new(1).unwrap(), KEY, 10).unwrap();
    let ValidatorLifecycle::WaitingForStake(registered) = registered.into_lifecycle() else {
        panic!("expected WaitingForStake");
    };
    let pending = reach_minimum(
        registered,
        StakeProjection::new(U256::from(1_000), None),
        U256::from(1_000),
    )
    .unwrap();
    let joining = confirm_ready(pending);
    let active = activate_at_boundary(joining);

    assert_eq!(active.stake.bonded(), U256::from(1_000));
    assert_eq!(active.history.joined_at_height(), 10);
}

#[test]
fn pending_demotion_consumes_readiness() {
    let ValidatorLifecycle::Joining(joining) = canonical(PENDING, false, true, 0).into_lifecycle()
    else {
        panic!("expected Joining");
    };
    let registered = demote_joining(
        joining,
        StakeProjection::new(U256::from(900), Some(40)),
        U256::from(1_000),
    )
    .unwrap();
    let state =
        ValidatorState::from_lifecycle(ADDRESS, ValidatorLifecycle::WaitingForStake(registered))
            .unwrap();
    assert!(!state.join_confirmed());
    assert!(!state.has_bls_share());
}

#[test]
fn jail_has_distinct_retained_and_excluded_states() {
    let ValidatorLifecycle::Active(active) = canonical(ACTIVE, true, false, 0).into_lifecycle()
    else {
        panic!("expected Active");
    };
    let retained = jail(active, 77).unwrap();
    let retained_history = retained.history;
    let excluded = exclude_jailed_at_boundary(retained);

    assert_eq!(excluded.jailed_at, 77);
    assert_eq!(
        excluded.history.joined_at_height(),
        retained_history.joined_at_height()
    );
    assert_eq!(
        excluded.history.slash_count(),
        retained_history.slash_count()
    );
    assert_eq!(
        excluded.history.blocks_proposed(),
        retained_history.blocks_proposed()
    );
    assert_eq!(excluded.history.missed_blocks(), 0);
    assert_eq!(excluded.history.missed_votes(), 0);
    let state =
        ValidatorState::from_lifecycle(ADDRESS, ValidatorLifecycle::Jail(excluded)).unwrap();
    assert!(!state.has_bls_share());
    assert!(!state.lifecycle().is_current_consensus_participant());
}

#[test]
fn unjail_clears_missed_counters_and_checks_cooldown() {
    let ValidatorLifecycle::Jail(jail) = canonical(JAILED, false, false, 50).into_lifecycle()
    else {
        panic!("expected Jail");
    };
    let expected_history = jail.history;
    assert!(unjail(jail.clone(), 59, 10, U256::from(1_000)).is_err());

    let pending = unjail(jail, 60, 10, U256::from(1_000)).unwrap();
    assert_eq!(
        pending.history.joined_at_height(),
        expected_history.joined_at_height()
    );
    assert_eq!(
        pending.history.slash_count(),
        expected_history.slash_count()
    );
    assert_eq!(pending.history.blocks_proposed(), 8);
    assert_eq!(pending.history.missed_blocks(), 0);
    assert_eq!(pending.history.missed_votes(), 0);
}

#[test]
fn excluded_jail_full_exit_goes_directly_to_unbonding() {
    let ValidatorLifecycle::Jail(jail) = canonical(JAILED, false, false, 50).into_lifecycle()
    else {
        panic!("expected Jail");
    };
    assert!(
        full_exit_jailed(jail.clone(), StakeProjection::new(U256::from(1), Some(90)),).is_err()
    );

    let unbonding = full_exit_jailed(jail, StakeProjection::new(U256::ZERO, Some(90))).unwrap();
    assert_eq!(unbonding.stake.bonded(), U256::ZERO);
    assert_eq!(unbonding.stake.unbonding_end_hint(), Some(90));
}

#[test]
fn unbonding_completes_only_after_economic_projection_is_clear() {
    let ValidatorLifecycle::Unbonding(unbonding) =
        canonical(UNBONDING, false, false, 0).into_lifecycle()
    else {
        panic!("expected Unbonding");
    };
    assert!(complete_unbonding(unbonding.clone()).is_err());

    let ValidatorLifecycle::Unbonding(clear) = with_stake(
        ValidatorLifecycle::Unbonding(unbonding),
        StakeProjection::zero(),
    )
    .unwrap() else {
        panic!("expected Unbonding");
    };
    let inactive = complete_unbonding(clear).unwrap();
    let state =
        ValidatorState::from_lifecycle(ADDRESS, ValidatorLifecycle::Inactive(inactive)).unwrap();
    assert_eq!(state.bonded_stake(), U256::ZERO);
    assert_eq!(state.stake(), None);
}

#[test]
fn absent_and_inactive_reject_direct_stake_updates() {
    assert!(with_stake(
        ValidatorLifecycle::Absent,
        StakeProjection::new(U256::from(1), None)
    )
    .is_err());

    let inactive = canonical(INACTIVE, false, false, 0).into_lifecycle();
    assert!(with_stake(inactive, StakeProjection::new(U256::from(1), None)).is_err());
}

#[test]
fn inactive_reregistration_resets_lifecycle_information() {
    let ValidatorLifecycle::Inactive(inactive) =
        canonical(INACTIVE, false, false, 0).into_lifecycle()
    else {
        panic!("expected Inactive");
    };
    let index = inactive.registry_index;
    let registered = reregister(inactive, [9; 48], 100).unwrap();
    assert_eq!(registered.registry_index, index);
    assert_eq!(registered.consensus_pubkey, [9; 48]);
    assert_eq!(registered.p2p, P2pInfo::Unset);
    assert_eq!(registered.stake, StakeProjection::zero());
    assert_eq!(registered.history, ValidatorHistory::fresh(100));
}

#[test]
fn exit_transition_rejects_zero_height_and_excludes_only_at_boundary() {
    let ValidatorLifecycle::Active(active) = canonical(ACTIVE, true, false, 0).into_lifecycle()
    else {
        panic!("expected Active");
    };

    assert!(begin_exit(active.clone(), active.stake, 0).is_err());
    let exiting = begin_exit(active, StakeProjection::new(U256::from(900), Some(80)), 42).unwrap();
    let retained =
        ValidatorState::from_lifecycle(ADDRESS, ValidatorLifecycle::Exiting(exiting.clone()))
            .unwrap();
    assert!(retained.lifecycle().is_current_consensus_participant());
    assert!(retained.has_bls_share());

    let unbonding = exclude_exiting_at_boundary(exiting);
    let excluded =
        ValidatorState::from_lifecycle(ADDRESS, ValidatorLifecycle::Unbonding(unbonding)).unwrap();
    assert!(!excluded.lifecycle().is_current_consensus_participant());
    assert!(!excluded.has_bls_share());
    assert_eq!(excluded.unbonding_end_hint(), Some(80));
}

#[test]
fn jail_and_retained_jail_exit_reject_invalid_transition_inputs() {
    let ValidatorLifecycle::Active(active) = canonical(ACTIVE, true, false, 0).into_lifecycle()
    else {
        panic!("expected Active");
    };

    assert!(jail(active.clone(), 0).is_err());
    let retained = jail(active, 50).unwrap();
    assert!(full_exit_jailed_retained(
        retained.clone(),
        StakeProjection::new(U256::from(1), Some(90)),
    )
    .is_err());

    let exiting =
        full_exit_jailed_retained(retained, StakeProjection::new(U256::ZERO, Some(90))).unwrap();
    assert_eq!(exiting.history.last_deactivated_at_height(), Some(50));
    assert_eq!(exiting.stake.unbonding_end_hint(), Some(90));
}

#[test]
fn waiting_for_readiness_demotion_and_active_retention_are_explicit() {
    let ValidatorLifecycle::WaitingForReadiness(waiting) =
        canonical(PENDING, false, false, 0).into_lifecycle()
    else {
        panic!("expected WaitingForReadiness");
    };
    let registered = demote_waiting_for_readiness(
        waiting,
        StakeProjection::new(U256::from(999), Some(70)),
        U256::from(1_000),
    )
    .unwrap();
    assert_eq!(registered.stake.bonded(), U256::from(999));

    let ValidatorLifecycle::Active(active) = canonical(ACTIVE, true, false, 0).into_lifecycle()
    else {
        panic!("expected Active");
    };
    let expected = active.clone();
    assert_eq!(retain_active_at_boundary(active), expected);
}

#[test]
fn generic_internal_updates_reject_noncanonical_sentinels_and_preserve_metadata() {
    let active = canonical(ACTIVE, true, false, 0).into_lifecycle();
    assert!(with_stake(
        active.clone(),
        StakeProjection::new(U256::from(1_500), Some(0)),
    )
    .is_err());

    let p2p = P2pInfo::V1(P2pAddress::Symmetric(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        30_401,
    )));
    let updated = with_p2p(active, p2p.clone()).unwrap();
    assert_eq!(updated.p2p(), Some(&p2p));

    let invalid_history = ValidatorHistory::new(13, Some(0), 2, 3, 5, 8);
    assert!(with_history(updated, invalid_history).is_err());
}

#[test]
fn inactive_cleanup_consumes_the_terminal_payload() {
    let ValidatorLifecycle::Inactive(inactive) =
        canonical(INACTIVE, false, false, 0).into_lifecycle()
    else {
        panic!("expected Inactive");
    };
    assert_eq!(cleanup(inactive), ValidatorLifecycle::Absent);
}
