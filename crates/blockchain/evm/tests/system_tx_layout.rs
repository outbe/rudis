//! V2 begin-zone system-tx layout invariants.
//!
//! Covers AC1/AC3/AC4 + the block-1 mandatory BoundaryOutcome rule + the
//! block-0 prohibition of begin-zone system txs. Codec-level rejection of V1
//! input bytes is tested at every legacy selector + version combination.

use alloy_consensus::{SignableTransaction as _, TxLegacy};
use alloy_primitives::{address, Bytes, Signature, TxKind, U256};
use outbe_evm::system_tx::{
    build_unsigned_system_tx, expected_begin_block_kinds,
    expected_begin_block_kinds_for_activation, expected_end_block_kinds, split_system_layout,
    validate_active_system_tx_set, validate_system_tx_set_for_activation, BodyZone,
    OcompLifecycleActivation, SystemTxError, SystemTxInputV2, SystemTxKind, SystemTxLayout,
    SystemTxPhase, BOUNDARY_OUTCOME_SELECTOR, CERTIFIED_PARENT_ACCOUNTING_SELECTOR,
    CYCLE_TICK_SELECTOR, OCOMP_LIFECYCLE_BEGIN_SELECTOR, OCOMP_TERMINAL_REQUEST_SELECTOR,
    ORACLE_SLASH_WINDOW_SELECTOR, REWARDS_GEM_DELIVERY_SELECTOR, SYSTEM_TX_INPUT_VERSION,
};
use outbe_primitives::consensus_metadata::CertifiedParentAccountingMetadata;
use reth_ethereum::TransactionSigned;

/// Empty layout - used by the block-1 / block-0 layout tests that only need to
/// drive the membership check, not the structural splitter.
fn empty_layout() -> SystemTxLayout<'static> {
    SystemTxLayout {
        begin: Vec::new(),
        user: Vec::new(),
        end: Vec::new(),
    }
}

const OCOMP_TEST_BLOCK: u64 = 32;
const OCOMP_TEST_CHAIN_ID: u64 = 2026;

fn ocomp_system_input(kind: SystemTxKind) -> SystemTxInputV2 {
    match kind {
        SystemTxKind::CertifiedParentAccounting => SystemTxInputV2::CertifiedParentAccounting {
            metadata: CertifiedParentAccountingMetadata::default(),
        },
        SystemTxKind::LateFinalizeCredits => SystemTxInputV2::LateFinalizeCredits {
            artifact: Default::default(),
        },
        SystemTxKind::OcompLifecycleBegin => SystemTxInputV2::OcompLifecycleBegin,
        SystemTxKind::CycleTick => SystemTxInputV2::CycleTick,
        SystemTxKind::RewardsGemDelivery => SystemTxInputV2::RewardsGemDelivery,
        SystemTxKind::OracleSlashWindow => SystemTxInputV2::OracleSlashWindow,
        SystemTxKind::HookEvents => SystemTxInputV2::HookEvents,
        SystemTxKind::OcompTerminalRequest => SystemTxInputV2::OcompTerminalRequest,
        other => panic!("layout fixture does not use {other:?}"),
    }
}

fn signed_ocomp_system_tx(kind: SystemTxKind, ordinal: u8) -> TransactionSigned {
    build_unsigned_system_tx(
        kind,
        ordinal,
        OCOMP_TEST_BLOCK,
        OCOMP_TEST_CHAIN_ID,
        ocomp_system_input(kind)
            .encode()
            .expect("system input encodes"),
    )
    .expect("system tx builds")
    .into_signed(Signature::test_signature())
    .into()
}

fn user_tx() -> TransactionSigned {
    TxLegacy {
        chain_id: Some(OCOMP_TEST_CHAIN_ID),
        nonce: 0,
        gas_price: 0,
        gas_limit: 21_000,
        to: TxKind::Call(address!("4444444444444444444444444444444444444444")),
        value: U256::ZERO,
        input: Bytes::new(),
    }
    .into_signed(Signature::test_signature())
    .into()
}

/// AC4: active selectors are present and have their fork-specific byte
/// sequences.
#[test]
fn active_selectors_have_expected_byte_sequence() {
    assert_eq!(
        CERTIFIED_PARENT_ACCOUNTING_SELECTOR,
        [0x4f, 0x53, 0x41, 0x33]
    ); // "OSA3"
    assert_eq!(CYCLE_TICK_SELECTOR, [0x4f, 0x53, 0x43, 0x32]); // "OSC2"
    assert_eq!(REWARDS_GEM_DELIVERY_SELECTOR, [0x4f, 0x53, 0x47, 0x32]); // "OSG2"
    assert_eq!(BOUNDARY_OUTCOME_SELECTOR, [0x4f, 0x53, 0x42, 0x32]); // "OSB2"
    assert_eq!(ORACLE_SLASH_WINDOW_SELECTOR, [0x4f, 0x53, 0x4f, 0x32]); // "OSO2"
    assert_eq!(SYSTEM_TX_INPUT_VERSION, 2);
}

/// AC4 + INV1: V2 selectors must differ from V1 byte sequences.
#[test]
fn v2_selectors_differ_from_legacy_v1_selectors() {
    let v1_selectors: [[u8; 4]; 4] = [
        *b"OSF1", // legacy FinalizationAndSlashing
        *b"OSC1", // legacy CycleTick
        *b"OSB1", // legacy BoundaryOutcome
        *b"OSO1", // legacy OracleSlashWindow
    ];
    let v2_selectors: [[u8; 4]; 5] = [
        CERTIFIED_PARENT_ACCOUNTING_SELECTOR,
        CYCLE_TICK_SELECTOR,
        REWARDS_GEM_DELIVERY_SELECTOR,
        BOUNDARY_OUTCOME_SELECTOR,
        ORACLE_SLASH_WINDOW_SELECTOR,
    ];
    for v1 in v1_selectors {
        assert!(
            !v2_selectors.contains(&v1),
            "V2 selector set must not contain any V1 selector bytes: {v1:?}"
        );
    }
}

/// Legacy V1 system-tx input bytes are rejected at every height.
///
/// Two failure modes proven here: (a) the V1 selector bytes (`OSF1` / `OSC1`
/// / `OSB1` / `OSO1`) are unknown to the V2 selector parser; (b) even if a
/// caller padded an unknown body with version byte `1`, the decoder rejects
/// it because `SYSTEM_TX_INPUT_VERSION == 2`.
#[test]
fn legacy_v1_system_tx_rejected_at_all_heights() {
    let v1_selectors_and_bodies: [(&[u8; 4], &[u8]); 4] = [
        (b"OSF1", b""), // FinalizationAndSlashing carried metadata; selector alone suffices for rejection.
        (b"OSC1", b""),
        (b"OSB1", b""),
        (b"OSO1", b""),
    ];
    for (selector, body) in v1_selectors_and_bodies {
        let mut bytes = Vec::with_capacity(5 + body.len());
        bytes.extend_from_slice(selector);
        bytes.push(1); // V1 version
        bytes.extend_from_slice(body);
        let err = SystemTxInputV2::decode(&bytes).expect_err("V1 selector must be rejected");
        match err {
            SystemTxError::UnknownSelector(actual) => {
                assert_eq!(
                    actual, *selector,
                    "decoder must surface the unknown V1 selector"
                );
            }
            other => panic!("expected UnknownSelector, got {other:?}"),
        }
    }

    // Also assert: a V2 selector with the legacy version byte `1` is rejected.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&CYCLE_TICK_SELECTOR);
    bytes.push(1); // wrong (legacy) version
    let err = SystemTxInputV2::decode(&bytes)
        .expect_err("V1 version byte must be rejected even under a V2 selector");
    assert!(
        matches!(err, SystemTxError::UnsupportedVersion(1)),
        "{err:?}"
    );
}

/// Block 1 under V2 must carry a BoundaryOutcome system tx (genesis bootstrap).
#[test]
fn block_1_layout_requires_boundary_outcome_for_v2() {
    let err = validate_active_system_tx_set(&empty_layout(), 1, false, false)
        .expect_err("block 1 without BoundaryOutcome must be rejected under V2");
    assert!(
        matches!(err, SystemTxError::V2Block1MissingBoundaryOutcome),
        "{err:?}",
    );

    // Expected kinds at block 1 with BoundaryOutcome present:
    let expected = expected_begin_block_kinds(1, true, false);
    assert_eq!(
        expected,
        vec![
            SystemTxKind::CycleTick,
            SystemTxKind::RewardsGemDelivery,
            SystemTxKind::BoundaryOutcome,
            SystemTxKind::OracleSlashWindow,
            SystemTxKind::HookEvents,
        ],
        "block 1 V2 layout must include CycleTick, BoundaryOutcome, OracleSlashWindow, HookEvents",
    );
}

/// Block 0 must not carry any begin-zone system tx under V2.
#[test]
fn block_0_has_no_begin_zone_system_txs_under_v2() {
    // Membership check accepts an empty layout at block 0 regardless of
    // `has_boundary_outcome` (genesis cannot be a boundary parent of itself).
    validate_active_system_tx_set(&empty_layout(), 0, false, false)
        .expect("empty layout at block 0 must be accepted under V2");
    validate_active_system_tx_set(&empty_layout(), 0, true, false)
        .expect("empty layout at block 0 must be accepted even if has_boundary_outcome is true");

    let expected = expected_begin_block_kinds(0, false, false);
    assert!(
        expected.is_empty(),
        "block 0 must have no expected begin-zone system tx kinds; got {expected:?}",
    );
    let expected_with_bo = expected_begin_block_kinds(0, true, false);
    assert!(
        expected_with_bo.is_empty(),
        "block 0 must have no expected begin-zone system tx kinds even with has_boundary_outcome=true; got {expected_with_bo:?}",
    );
}

#[test]
fn ocomp_lifecycle_appears_at_activation_height_in_canonical_zones() {
    const ACTIVATION_HEIGHT: u64 = 32;
    let activation = OcompLifecycleActivation::at_block(ACTIVATION_HEIGHT);

    let before = expected_begin_block_kinds_for_activation(31, false, false, activation);
    assert_eq!(
        before,
        vec![
            SystemTxKind::CertifiedParentAccounting,
            SystemTxKind::LateFinalizeCredits,
            SystemTxKind::CycleTick,
            SystemTxKind::RewardsGemDelivery,
            SystemTxKind::OracleSlashWindow,
            SystemTxKind::HookEvents,
        ]
    );
    assert!(expected_end_block_kinds(31, activation).is_empty());

    for height in [ACTIVATION_HEIGHT, ACTIVATION_HEIGHT + 1] {
        let begin = expected_begin_block_kinds_for_activation(height, false, false, activation);
        assert_eq!(
            begin,
            vec![
                SystemTxKind::CertifiedParentAccounting,
                SystemTxKind::LateFinalizeCredits,
                SystemTxKind::OcompLifecycleBegin,
                SystemTxKind::CycleTick,
                SystemTxKind::RewardsGemDelivery,
                SystemTxKind::OracleSlashWindow,
                SystemTxKind::HookEvents,
            ]
        );
        assert_eq!(
            expected_end_block_kinds(height, activation),
            vec![SystemTxKind::OcompTerminalRequest]
        );
    }

    assert_eq!(
        SystemTxInputV2::OcompLifecycleBegin
            .encode()
            .expect("lifecycle begin encodes"),
        [
            &OCOMP_LIFECYCLE_BEGIN_SELECTOR[..],
            &[SYSTEM_TX_INPUT_VERSION]
        ]
        .concat()
    );
    assert_eq!(
        SystemTxInputV2::OcompTerminalRequest
            .encode()
            .expect("terminal request encodes"),
        [
            &OCOMP_TERMINAL_REQUEST_SELECTOR[..],
            &[SYSTEM_TX_INPUT_VERSION],
        ]
        .concat()
    );
    assert_eq!(
        SystemTxKind::OcompLifecycleBegin.body_zone(),
        BodyZone::BeginBlock
    );
    assert_eq!(
        SystemTxKind::OcompTerminalRequest.body_zone(),
        BodyZone::EndBlock
    );
}

#[test]
fn active_ocomp_layout_splits_begin_users_and_terminal_request() {
    let activation = OcompLifecycleActivation::at_block(OCOMP_TEST_BLOCK);
    let txs = vec![
        signed_ocomp_system_tx(SystemTxKind::CertifiedParentAccounting, 0),
        signed_ocomp_system_tx(SystemTxKind::LateFinalizeCredits, 1),
        signed_ocomp_system_tx(SystemTxKind::OcompLifecycleBegin, 2),
        signed_ocomp_system_tx(SystemTxKind::CycleTick, 3),
        signed_ocomp_system_tx(SystemTxKind::RewardsGemDelivery, 4),
        signed_ocomp_system_tx(SystemTxKind::OracleSlashWindow, 5),
        signed_ocomp_system_tx(SystemTxKind::HookEvents, 6),
        user_tx(),
        signed_ocomp_system_tx(SystemTxKind::OcompTerminalRequest, 7),
    ];

    let layout = split_system_layout(&txs).expect("canonical begin/user/end layout splits");
    validate_system_tx_set_for_activation(&layout, OCOMP_TEST_BLOCK, false, false, activation)
        .expect("active lifecycle set validates");

    assert_eq!(
        layout.begin_block_kinds().unwrap(),
        expected_begin_block_kinds_for_activation(OCOMP_TEST_BLOCK, false, false, activation)
    );
    assert_eq!(layout.user.len(), 1);
    assert_eq!(
        layout.end_block_kinds().unwrap(),
        vec![SystemTxKind::OcompTerminalRequest]
    );
}

#[test]
fn active_ocomp_layout_supports_an_empty_user_zone() {
    let activation = OcompLifecycleActivation::at_block(OCOMP_TEST_BLOCK);
    let mut txs = canonical_active_ocomp_transactions();
    txs.remove(7);

    let layout =
        split_system_layout(&txs).expect("terminal suffix remains distinct without user txs");
    validate_system_tx_set_for_activation(&layout, OCOMP_TEST_BLOCK, false, false, activation)
        .expect("empty user zone is a valid active lifecycle layout");

    assert!(layout.user.is_empty());
    assert_eq!(
        layout.end_block_kinds().unwrap(),
        vec![SystemTxKind::OcompTerminalRequest]
    );
}

#[test]
fn active_ocomp_cursor_places_lifecycle_begin_before_cycle_tick() {
    assert_eq!(
        SystemTxPhase::initial_for_block_with_ocomp(1, 1, true),
        SystemTxPhase::OcompLifecycleBegin { body_index: 0 }
    );

    let phase = SystemTxPhase::initial_for_block_with_ocomp(OCOMP_TEST_BLOCK, 1, true);
    let phase = phase.advance_after_commit_with_ocomp(false, false, true);
    assert_eq!(phase, SystemTxPhase::LateFinalizeCredits { body_index: 1 });
    let phase = phase.advance_after_commit_with_ocomp(false, false, true);
    assert_eq!(phase, SystemTxPhase::OcompLifecycleBegin { body_index: 2 });
    let phase = phase.advance_after_commit_with_ocomp(false, false, true);
    assert_eq!(phase, SystemTxPhase::CycleTick { body_index: 3 });
    let phase = phase.advance_after_commit_with_ocomp(false, false, true);
    assert_eq!(phase, SystemTxPhase::RewardsGemDelivery { body_index: 4 });
    let phase = phase.advance_after_commit_with_ocomp(false, false, true);
    assert_eq!(phase, SystemTxPhase::OracleSlashWindow { body_index: 5 });
    let phase = phase.advance_after_commit_with_ocomp(false, false, true);
    assert_eq!(phase, SystemTxPhase::HookEvents { body_index: 6 });
    assert_eq!(
        phase.advance_after_commit_with_ocomp(false, false, true),
        SystemTxPhase::UserTxs
    );
}

fn canonical_active_ocomp_transactions() -> Vec<TransactionSigned> {
    vec![
        signed_ocomp_system_tx(SystemTxKind::CertifiedParentAccounting, 0),
        signed_ocomp_system_tx(SystemTxKind::LateFinalizeCredits, 1),
        signed_ocomp_system_tx(SystemTxKind::OcompLifecycleBegin, 2),
        signed_ocomp_system_tx(SystemTxKind::CycleTick, 3),
        signed_ocomp_system_tx(SystemTxKind::RewardsGemDelivery, 4),
        signed_ocomp_system_tx(SystemTxKind::OracleSlashWindow, 5),
        signed_ocomp_system_tx(SystemTxKind::HookEvents, 6),
        user_tx(),
        signed_ocomp_system_tx(SystemTxKind::OcompTerminalRequest, 7),
    ]
}

#[test]
fn malformed_ocomp_suffixes_and_cross_fork_envelopes_are_rejected() {
    let activation = OcompLifecycleActivation::at_block(OCOMP_TEST_BLOCK);

    let mut missing_terminal = canonical_active_ocomp_transactions();
    missing_terminal.pop();
    let layout = split_system_layout(&missing_terminal).unwrap();
    assert!(matches!(
        validate_system_tx_set_for_activation(&layout, OCOMP_TEST_BLOCK, false, false, activation,),
        Err(SystemTxError::ActiveSystemTxSetMismatch { .. })
    ));

    let mut duplicate_terminal = canonical_active_ocomp_transactions();
    duplicate_terminal.push(signed_ocomp_system_tx(
        SystemTxKind::OcompTerminalRequest,
        7,
    ));
    assert!(matches!(
        split_system_layout(&duplicate_terminal),
        Err(SystemTxError::OutOfOrder {
            zone: BodyZone::EndBlock,
            ..
        })
    ));

    let mut user_after_end = canonical_active_ocomp_transactions();
    user_after_end.push(user_tx());
    assert!(matches!(
        split_system_layout(&user_after_end),
        Err(SystemTxError::MidBlockSystemTx { .. })
    ));

    let mut misordered_begin = canonical_active_ocomp_transactions();
    misordered_begin.swap(2, 3);
    assert!(matches!(
        split_system_layout(&misordered_begin),
        Err(SystemTxError::OutOfOrder {
            zone: BodyZone::BeginBlock,
            ..
        })
    ));

    let canonical = canonical_active_ocomp_transactions();
    let layout = split_system_layout(&canonical).unwrap();
    assert!(matches!(
        validate_system_tx_set_for_activation(
            &layout,
            OCOMP_TEST_BLOCK - 1,
            false,
            false,
            activation,
        ),
        Err(SystemTxError::ActiveSystemTxSetMismatch { .. })
    ));
}

#[test]
fn rewards_gem_delivery_is_mandatory_unique_and_immediately_after_cycle() {
    let activation = OcompLifecycleActivation::at_block(OCOMP_TEST_BLOCK);

    let mut missing = canonical_active_ocomp_transactions();
    missing.remove(4);
    let layout = split_system_layout(&missing).unwrap();
    assert!(matches!(
        validate_system_tx_set_for_activation(&layout, OCOMP_TEST_BLOCK, false, false, activation,),
        Err(SystemTxError::ActiveSystemTxSetMismatch { .. })
    ));

    let mut duplicate = canonical_active_ocomp_transactions();
    duplicate.insert(
        5,
        signed_ocomp_system_tx(SystemTxKind::RewardsGemDelivery, 8),
    );
    assert!(matches!(
        split_system_layout(&duplicate),
        Err(SystemTxError::OutOfOrder {
            zone: BodyZone::BeginBlock,
            ..
        })
    ));

    let mut reordered = canonical_active_ocomp_transactions();
    reordered.swap(3, 4);
    assert!(matches!(
        split_system_layout(&reordered),
        Err(SystemTxError::OutOfOrder {
            zone: BodyZone::BeginBlock,
            ..
        })
    ));
}

/// V2 begin-zone ordering: CertifiedParentAccounting (>=2), CycleTick (>=1),
/// RewardsGemDelivery (>=1), BoundaryOutcome (when present),
/// OracleSlashWindow (>=1).
#[test]
fn v2_begin_zone_ordering_is_canonical() {
    // Block 2+ canonical layout (no BoundaryOutcome on the parent).
    let expected = expected_begin_block_kinds(2, false, false);
    assert_eq!(
        expected,
        vec![
            SystemTxKind::CertifiedParentAccounting,
            SystemTxKind::LateFinalizeCredits,
            SystemTxKind::CycleTick,
            SystemTxKind::RewardsGemDelivery,
            SystemTxKind::OracleSlashWindow,
            SystemTxKind::HookEvents,
        ],
    );

    // Block 2+ with BoundaryOutcome present (e.g. epoch boundary).
    let expected = expected_begin_block_kinds(42, true, false);
    assert_eq!(
        expected,
        vec![
            SystemTxKind::CertifiedParentAccounting,
            SystemTxKind::LateFinalizeCredits,
            SystemTxKind::CycleTick,
            SystemTxKind::RewardsGemDelivery,
            SystemTxKind::BoundaryOutcome,
            SystemTxKind::OracleSlashWindow,
            SystemTxKind::HookEvents,
        ],
    );

    // All begin-zone kinds resolve to BeginBlock body zone.
    for kind in [
        SystemTxKind::CertifiedParentAccounting,
        SystemTxKind::LateFinalizeCredits,
        SystemTxKind::CycleTick,
        SystemTxKind::RewardsGemDelivery,
        SystemTxKind::BoundaryOutcome,
        SystemTxKind::OracleSlashWindow,
        SystemTxKind::HookEvents,
    ] {
        assert_eq!(kind.body_zone(), BodyZone::BeginBlock);
        assert!(kind.begin_order().is_some());
        assert!(kind.end_order().is_none());
    }
}
