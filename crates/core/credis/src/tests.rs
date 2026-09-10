use alloy_primitives::{address, keccak256, Address, U256};
use alloy_sol_types::SolCall;
use outbe_primitives::erc::ERC165_INTERFACE_ID;
use outbe_primitives::storage::hashmap::HashMapStorageProvider;
use outbe_primitives::storage::StorageHandle;
use outbe_primitives::units::SCALE_1E6_U256;

use crate::errors::CredisError;
use crate::precompile::{dispatch, ICredis};
use crate::runtime::{calc_call_price, settlement_deadline, OpenPositionParams};
use crate::schema::{CredisContract, CredisState};

const CHAIN_ID: u64 = 1;
const DAY: u64 = 86_400;
const ORIGINATED_AT: u64 = 1_700_000_000;

// ---------------------------------------------------------------------------
// The product paper's section 5 worked example, in exact on-chain units.
//
// Maria pledges Gratis worth $1,000 at P0 = $0.50/COEN. Stablecoin minor units,
// Gratis collateral and the oracle rate stay six-decimal; native COEN is not
// part of this internal calculation.
// ---------------------------------------------------------------------------

/// P = 1,000 USDC.
const PRINCIPAL: u64 = 1_000_000_000;
/// G = 2,000 COEN units.
fn collateral() -> U256 {
    U256::from(2_000u64) * SCALE_1E6_U256
}
/// P0 = $0.50, scale 1e6.
fn entry_price() -> U256 {
    U256::from(500_000u64)
}
/// r = 4% annual, scale 1e6.
fn policy_rate() -> U256 {
    U256::from(40_000u64)
}

fn alice() -> Address {
    address!("0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
}

fn bob() -> Address {
    address!("0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
}

fn cca() -> Address {
    address!("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC")
}

fn asset() -> Address {
    address!("0x0000000000000000000000000000000000000888")
}

/// Opaque sealed-EOA blob stored verbatim on the position. Credis unit tests
/// treat it as bytes - decryption is exercised in the credisfactory enclave tests.
fn eoa_ct() -> Vec<u8> {
    vec![0xEEu8; 48]
}

fn handle(tag: u8) -> U256 {
    U256::from_be_bytes(keccak256([0x33, tag]).0)
}

fn with_credis<R>(f: impl FnOnce(StorageHandle) -> R) -> R {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.set_timestamp(U256::from(ORIGINATED_AT));
    StorageHandle::enter(&mut storage, f)
}

fn params(handle_id: U256, owner: Address) -> OpenPositionParams {
    OpenPositionParams {
        handle_id,
        smart_account: owner,
        cca: cca(),
        eoa_ct: eoa_ct(),
        asset: asset(),
        issuance_currency: 840,
        reference_currency: 978,
        policy_rate: policy_rate(),
        principal: U256::from(PRINCIPAL),
        entry_price: entry_price(),
        collateral: collateral(),
        originated_at: ORIGINATED_AT,
    }
}

/// Opens the worked-example position. Settleable from this point on.
fn open_pos(credis: &mut CredisContract<'_>, tag: u8) -> U256 {
    credis.open_position(params(handle(tag), alice())).unwrap()
}

fn at(day: u64) -> u64 {
    ORIGINATED_AT + day * DAY
}

// ---------------------------------------------------------------------------
// Key derivation and sealed terms
// ---------------------------------------------------------------------------

#[test]
fn position_id_matches_keccak() {
    let id = CredisContract::position_id(handle(1), alice());
    let mut buf = [0u8; 52];
    buf[0..32].copy_from_slice(&handle(1).to_be_bytes::<32>());
    buf[32..52].copy_from_slice(alice().as_slice());
    assert_eq!(id, U256::from_be_bytes(keccak256(buf).0));
}

#[test]
fn open_position_seals_the_call_price_from_the_reference_entry_price() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let id = credis.open_position(params(handle(1), alice())).unwrap();
        let p = credis.get_position(id).unwrap();

        // $0.50 + 64% = $0.82.
        assert_eq!(p.call_price, U256::from(820_000u64));
        assert_eq!(p.call_price, calc_call_price(entry_price()).unwrap());

        // Both codes are sealed, and they are distinct: the threshold anchor is
        // the reference currency, never the issuance one the position is
        // denominated in.
        assert_eq!(p.issuance_currency, 840);
        assert_eq!(p.reference_currency, 978);

        // Collateral starts fully locked; accrual anchors at origination.
        assert_eq!(p.outstanding, p.principal);
        assert_eq!(p.collateral_locked, p.collateral);
        assert_eq!(p.last_settled_at, p.originated_at);
        assert_eq!(p.called_at, 0);
        assert_eq!(p.lifecycle_state().unwrap(), CredisState::Open);
        assert_eq!(p.cca, cca());
        assert_eq!(p.eoa_ct, eoa_ct());
    });
}

#[test]
fn open_position_rejects_duplicates_and_zero_amounts() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        credis.open_position(params(handle(1), alice())).unwrap();

        let err = credis
            .open_position(params(handle(1), alice()))
            .unwrap_err()
            .to_string();
        assert!(err.contains("already exists"), "got: {err}");

        let mut zero_principal = params(handle(2), alice());
        zero_principal.principal = U256::ZERO;
        assert!(credis.open_position(zero_principal).is_err());

        let mut zero_collateral = params(handle(3), alice());
        zero_collateral.collateral = U256::ZERO;
        assert!(credis.open_position(zero_collateral).is_err());
    });
}

// ---------------------------------------------------------------------------
// The worked example, end to end (section 5)
// ---------------------------------------------------------------------------

#[test]
fn worked_example_ledger_closes_exactly() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let id = open_pos(&mut credis, 1);

        // --- Day 100: partial settlement of $400 while latched. -------------
        let first = credis
            .settle(id, U256::from(400_000_000u64), at(100))
            .unwrap();
        // I = ceil(1_000_000_000 x 0.04 x 100/365) = $10.958905
        assert_eq!(first.interest, U256::from(10_958_905u64));
        assert_eq!(first.principal_paid, U256::from(389_041_095u64));
        assert_eq!(first.total_paid, U256::from(400_000_000u64));
        // deltaG = 2000e18 x 389_041_095 / 1e9 = 778.08219 COEN
        assert_eq!(first.gratis_released, U256::from(778_082_190u64));
        assert!(!first.closed);

        let p = credis.get_position(id).unwrap();
        assert_eq!(p.outstanding, U256::from(610_958_905u64));
        assert_eq!(p.collateral_locked, U256::from(1_221_917_810u64));
        assert_eq!(p.last_settled_at, at(100), "accrual restarts");

        // --- Day 458: the call. ---------------------------------------------
        assert!(credis.mark_called(id, at(458)).unwrap());
        let p = credis.get_position(id).unwrap();
        assert_eq!(p.lifecycle_state().unwrap(), CredisState::Called);
        assert_eq!(settlement_deadline(&p), at(465), "7-days window");

        // --- Day 465: partial settlement of $400 while called. --------------
        let second = credis
            .settle(id, U256::from(400_000_000u64), at(465))
            .unwrap();
        // d = 365 exactly, so I = P_out x 4%.
        assert_eq!(second.interest, U256::from(24_438_357u64));
        assert_eq!(second.principal_paid, U256::from(375_561_643u64));
        assert_eq!(second.gratis_released, U256::from(751_123_286u64));

        let p = credis.get_position(id).unwrap();
        assert_eq!(p.outstanding, U256::from(235_397_262u64));
        assert_eq!(p.collateral_locked, U256::from(470_794_524u64));

        // --- Day 472: the window lapses. ------------------------------------
        let void = credis.void_position(id, at(472)).unwrap();
        assert_eq!(void.gratis_burned, U256::from(470_794_524u64));
        assert_eq!(void.principal_written_off, U256::from(235_397_262u64));
        // 7 days of interest on the remainder - never collected.
        assert_eq!(void.interest_written_off, U256::from(180_579u64));
        // Unpaid fraction 235_397_262 / 1_000_000_000 = 23.5397262%, at scale 1e6.
        assert_eq!(void.unpaid_share, U256::from(235_397u64));
        assert_eq!(void.cca, cca());
        assert_eq!(void.eoa_ct, eoa_ct());

        // --- The paper's ledger check. ---------------------------------------
        let released = first.gratis_released + second.gratis_released + void.gratis_burned;
        assert_eq!(released, collateral(), "collateral closes on G");

        let principal = first.principal_paid + second.principal_paid + void.principal_written_off;
        assert_eq!(principal, U256::from(PRINCIPAL), "principal closes on P");

        // Interest collected across both settlements: $35.397262.
        assert_eq!(first.interest + second.interest, U256::from(35_397_262u64));

        let p = credis.get_position(id).unwrap();
        assert_eq!(p.lifecycle_state().unwrap(), CredisState::Void);
        assert!(p.outstanding.is_zero());
        assert!(p.collateral_locked.is_zero());
    });
}

// ---------------------------------------------------------------------------
// Settlement rules
// ---------------------------------------------------------------------------

#[test]
fn settle_rejects_a_payment_below_the_accrued_interest() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let id = open_pos(&mut credis, 1);

        let position = credis.get_position(id).unwrap();
        let interest = CredisContract::accrued_interest(&position, at(100)).unwrap();
        assert!(!interest.is_zero());

        let err = credis
            .settle(id, interest - U256::from(1u64), at(100))
            .unwrap_err()
            .to_string();
        assert!(err.contains("below the interest"), "got: {err}");

        // Nothing moved.
        let after = credis.get_position(id).unwrap();
        assert_eq!(after.outstanding, position.outstanding);
        assert_eq!(after.last_settled_at, position.last_settled_at);
    });
}

#[test]
fn settle_of_exactly_the_interest_leaves_principal_and_restarts_accrual() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let id = open_pos(&mut credis, 1);

        let interest =
            CredisContract::accrued_interest(&credis.get_position(id).unwrap(), at(100)).unwrap();
        let paid = credis.settle(id, interest, at(100)).unwrap();

        assert_eq!(paid.interest, interest);
        assert!(paid.principal_paid.is_zero());
        assert!(paid.gratis_released.is_zero());

        let p = credis.get_position(id).unwrap();
        assert_eq!(p.outstanding, U256::from(PRINCIPAL));
        assert_eq!(p.collateral_locked, collateral());
        // d resets to 0, so nothing is owed a moment later.
        assert_eq!(
            CredisContract::accrued_interest(&p, at(100)).unwrap(),
            U256::ZERO
        );
    });
}

#[test]
fn settle_takes_only_what_the_position_needs() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let id = open_pos(&mut credis, 1);

        // Wildly over-pay; only interest + outstanding principal is charged.
        let paid = credis
            .settle(id, U256::from(999_999_999_999u64), at(100))
            .unwrap();
        assert_eq!(paid.principal_paid, U256::from(PRINCIPAL));
        assert_eq!(paid.total_paid, paid.interest + U256::from(PRINCIPAL));
        assert!(paid.closed);

        let p = credis.get_position(id).unwrap();
        assert_eq!(p.lifecycle_state().unwrap(), CredisState::Settled);
        assert!(p.outstanding.is_zero());
        assert!(
            p.collateral_locked.is_zero(),
            "the final settlement leaves no dust locked"
        );
    });
}

// ---------------------------------------------------------------------------
// Settlement arithmetic: interest first, principal second
//
// These pin the numbers independently of `accrued_interest`, so a wrong formula
// cannot satisfy them. Day 73 is exactly 1/5 of a 365-day year, so on P = $1,000
// at r = 4% one period of interest is $8.00 with no rounding.
// ---------------------------------------------------------------------------

/// One period of the fixtures below: 73 days = 0.2 x ACT/365.
const FIFTH_YEAR: u64 = 73;

#[test]
fn settle_covers_the_accrued_interest_before_any_principal() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let id = open_pos(&mut credis, 1);

        // I = 1_000_000_000 x 4% x 73/365 = 8_000_000, exactly.
        let expected_interest = U256::from(8_000_000u64);
        let principal_target = U256::from(100_000_000u64);

        let paid = credis
            .settle(id, expected_interest + principal_target, at(FIFTH_YEAR))
            .unwrap();

        // The interest is taken off the top; only the surplus reduces principal.
        assert_eq!(paid.interest, expected_interest);
        assert_eq!(paid.principal_paid, principal_target);
        assert_eq!(paid.total_paid, expected_interest + principal_target);
        assert!(!paid.closed);

        let p = credis.get_position(id).unwrap();
        assert_eq!(p.outstanding, U256::from(PRINCIPAL) - principal_target);
        // Collateral tracks the principal covered, not the gross payment:
        // deltaG = 2e9 x 1e8 / 1e9 = 2e8.
        assert_eq!(paid.gratis_released, U256::from(200_000_000u64));
        assert_eq!(p.collateral_locked, collateral() - paid.gratis_released);
        // Principal, not the payment, is what the position is measured against.
        assert_eq!(p.principal, U256::from(PRINCIPAL), "principal never moves");
    });
}

#[test]
fn one_minor_unit_above_the_interest_pays_exactly_one_of_principal() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let id = open_pos(&mut credis, 1);

        // The boundary: the first unit above the coupon is principal, and only
        // that unit. A payment that mixed the two would show more here.
        let paid = credis
            .settle(id, U256::from(8_000_001u64), at(FIFTH_YEAR))
            .unwrap();

        assert_eq!(paid.interest, U256::from(8_000_000u64));
        assert_eq!(paid.principal_paid, U256::from(1u64));
        assert_eq!(
            credis.get_position(id).unwrap().outstanding,
            U256::from(PRINCIPAL) - U256::from(1u64)
        );
    });
}

#[test]
fn sequential_settlements_recompute_interest_on_the_reduced_principal() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let id = open_pos(&mut credis, 1);

        // Three equal 73-day periods. Interest falls with the outstanding
        // principal, because accrual restarts on what is left rather than
        // carrying anything forward.
        //   day  73: I = 1_000e6 x 4% x 0.2 = 8.00e6, pay 400e6 of principal
        //   day 146: I =   600e6 x 4% x 0.2 = 4.80e6, pay 300e6
        //   day 219: I =   300e6 x 4% x 0.2 = 2.40e6, pay the remaining 300e6
        let plan = [
            (
                1u64,
                8_000_000u64,
                400_000_000u64,
                600_000_000u64,
                800_000_000u64,
            ),
            (2, 4_800_000, 300_000_000, 300_000_000, 600_000_000),
            (3, 2_400_000, 300_000_000, 0, 600_000_000),
        ];

        let mut interest_collected = U256::ZERO;
        let mut principal_settled = U256::ZERO;
        let mut collateral_released = U256::ZERO;

        for (period, interest, principal, outstanding_after, released) in plan {
            let day = at(period * FIFTH_YEAR);
            let paid = credis
                .settle(id, U256::from(interest) + U256::from(principal), day)
                .unwrap();

            assert_eq!(paid.interest, U256::from(interest), "period {period}");
            assert_eq!(
                paid.principal_paid,
                U256::from(principal),
                "period {period}"
            );
            assert_eq!(
                paid.gratis_released,
                U256::from(released),
                "period {period}"
            );

            let p = credis.get_position(id).unwrap();
            assert_eq!(
                p.outstanding,
                U256::from(outstanding_after),
                "period {period}"
            );
            // The anchor advances one whole period, and nothing is owed at the
            // instant of settlement - no interest carries between events.
            assert_eq!(p.last_settled_at, day, "period {period}");
            assert_eq!(
                CredisContract::accrued_interest(&p, day).unwrap(),
                U256::ZERO,
                "period {period}"
            );

            interest_collected += paid.interest;
            principal_settled += paid.principal_paid;
            collateral_released += paid.gratis_released;
        }

        // The three ledgers close exactly.
        assert_eq!(principal_settled, U256::from(PRINCIPAL));
        assert_eq!(collateral_released, collateral());
        assert_eq!(interest_collected, U256::from(15_200_000u64));

        let p = credis.get_position(id).unwrap();
        assert_eq!(p.lifecycle_state().unwrap(), CredisState::Settled);
        assert!(p.outstanding.is_zero());
        assert!(p.collateral_locked.is_zero());
    });
}

#[test]
fn settle_below_the_accrued_interest_reverts_and_changes_nothing() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let id = open_pos(&mut credis, 1);

        // Reject at the first settlement: one unit short of the $8.00 coupon.
        let before = credis.get_position(id).unwrap();
        let err = credis
            .settle(id, U256::from(7_999_999u64), at(FIFTH_YEAR))
            .unwrap_err()
            .to_string();
        assert!(err.contains("below the interest"), "got: {err}");

        let after = credis.get_position(id).unwrap();
        assert_eq!(after.outstanding, before.outstanding);
        assert_eq!(after.collateral_locked, before.collateral_locked);
        assert_eq!(after.last_settled_at, before.last_settled_at);
        assert_eq!(after.state, before.state);

        // Paying the coupon exactly is accepted, so the boundary is `< I`.
        credis
            .settle(id, U256::from(8_000_000u64), at(FIFTH_YEAR))
            .unwrap();

        // The guard still holds once the principal has been drawn down: after
        // settling half, the next period's coupon is 4.00e6 on 500e6, and a
        // payment sized for the *old* balance's coupon is now more than enough
        // while one below the *new* coupon is still rejected.
        credis
            .settle(id, U256::from(500_000_000u64), at(FIFTH_YEAR))
            .unwrap();
        let mid = credis.get_position(id).unwrap();
        assert_eq!(mid.outstanding, U256::from(500_000_000u64));

        let err = credis
            .settle(id, U256::from(3_999_999u64), at(2 * FIFTH_YEAR))
            .unwrap_err()
            .to_string();
        assert!(err.contains("below the interest"), "got: {err}");
        assert_eq!(
            credis.get_position(id).unwrap().outstanding,
            U256::from(500_000_000u64),
            "a rejected settlement leaves the balance untouched"
        );
    });
}

#[test]
fn settle_runs_from_open_and_is_rejected_after_closing() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let id = credis.open_position(params(handle(1), alice())).unwrap();

        credis
            .settle(id, U256::from(999_999_999_999u64), at(100))
            .unwrap();

        let err = credis
            .settle(id, U256::from(1_000u64), at(200))
            .unwrap_err()
            .to_string();
        assert!(err.contains("closed"), "got: {err}");
    });
}

#[test]
fn settlement_stays_open_on_unchanged_terms_while_called() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let id = open_pos(&mut credis, 1);
        credis.mark_called(id, at(10)).unwrap();

        let paid = credis
            .settle(id, U256::from(400_000_000u64), at(100))
            .unwrap();
        // Same arithmetic as the un-called day-100 settlement: being called
        // changes nothing about the terms.
        assert_eq!(paid.interest, U256::from(10_958_905u64));
        assert_eq!(paid.principal_paid, U256::from(389_041_095u64));
        assert_eq!(
            credis.get_position(id).unwrap().lifecycle_state().unwrap(),
            CredisState::Called,
            "a partial settlement does not resolve the call"
        );
    });
}

#[test]
fn full_settlement_while_called_closes_the_position() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let id = open_pos(&mut credis, 1);
        credis.mark_called(id, at(10)).unwrap();

        let paid = credis
            .settle(id, U256::from(999_999_999_999u64), at(100))
            .unwrap();
        assert!(paid.closed);
        assert_eq!(
            credis.get_position(id).unwrap().lifecycle_state().unwrap(),
            CredisState::Settled
        );
        assert!(!credis.has_called_position(alice()).unwrap());
    });
}

/// Repeated partials must compose without stranding or over-releasing
/// collateral, whatever the split.
#[test]
fn repeated_partials_release_exactly_the_collateral() {
    for chunk in [1_000_000u64, 7_777_777, 123_456_789, 333_333_333] {
        with_credis(|storage| {
            let mut credis = CredisContract::new(storage);
            let id = open_pos(&mut credis, 1);

            let mut released = U256::ZERO;
            let mut day = 1u64;
            loop {
                let position = credis.get_position(id).unwrap();
                if position.outstanding.is_zero() {
                    break;
                }
                let interest = CredisContract::accrued_interest(&position, at(day)).unwrap();
                let paid = credis
                    .settle(id, interest + U256::from(chunk), at(day))
                    .unwrap();
                released += paid.gratis_released;
                // Every unit of collateral is either released or still locked -
                // never double-counted, never stranded mid-flight.
                let after = credis.get_position(id).unwrap();
                assert_eq!(released + after.collateral_locked, collateral());
                day += 1;
            }

            assert_eq!(released, collateral(), "chunk={chunk}");
            assert!(credis.get_position(id).unwrap().collateral_locked.is_zero());
        });
    }
}

#[test]
fn interest_rounds_up_and_collateral_release_rounds_down() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let id = open_pos(&mut credis, 1);

        // 1 day of interest on $1,000 at 4% = 109_589.041... minor units.
        let position = credis.get_position(id).unwrap();
        assert_eq!(
            CredisContract::accrued_interest(&position, at(1)).unwrap(),
            U256::from(109_590u64),
            "interest rounds up, favoring the protocol"
        );

        // G/P = 2e9/1e9 = 2, so each minor unit of principal frees exactly 2
        // gratis units and the floored release is exact here.
        let paid = credis
            .settle(id, U256::from(109_590u64) + U256::from(3u64), at(1))
            .unwrap();
        assert_eq!(paid.principal_paid, U256::from(3u64));
        assert_eq!(paid.gratis_released, U256::from(6u64));
    });
}

#[test]
fn accrual_counts_whole_days_only() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let id = open_pos(&mut credis, 1);
        let position = credis.get_position(id).unwrap();

        assert_eq!(
            CredisContract::accrued_interest(&position, at(0) + DAY - 1).unwrap(),
            U256::ZERO
        );
        assert!(!CredisContract::accrued_interest(&position, at(1))
            .unwrap()
            .is_zero());
    });
}

#[test]
fn dust_settlements_cannot_evade_the_coupon() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let id = open_pos(&mut credis, 1);

        // A dust settlement one second short of a whole day charges no
        // interest - and so must not consume accrual time either.
        let dust = credis
            .settle(id, U256::from(1u64), at(0) + DAY - 1)
            .unwrap();
        assert!(dust.interest.is_zero());
        assert_eq!(dust.principal_paid, U256::from(1u64));
        assert_eq!(
            credis.get_position(id).unwrap().last_settled_at,
            ORIGINATED_AT,
            "the accrual anchor must not move when no whole day was charged"
        );

        // Because the anchor stayed put, the clock kept running: repeating the
        // trick just under the next day boundary now owes a full day of
        // interest and is rejected. An anchor that jumped to the payment time
        // would let this repeat forever and never pay a coupon.
        let err = credis
            .settle(id, U256::from(1u64), at(1) + DAY - 1)
            .unwrap_err()
            .to_string();
        assert!(err.contains("below the interest"), "got: {err}");

        // A full year on, the whole coupon is still owed - on the one minor
        // unit of principal the dust settlement retired:
        // ceil(999_999_999 x 4%) = 40_000_000.
        let position = credis.get_position(id).unwrap();
        assert_eq!(position.outstanding, U256::from(PRINCIPAL - 1));
        assert_eq!(
            CredisContract::accrued_interest(&position, at(365)).unwrap(),
            U256::from(40_000_000u64)
        );
    });
}

#[test]
fn the_accrual_anchor_advances_by_whole_days_only() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let id = open_pos(&mut credis, 1);

        // Settling 10.5 days in charges 10 days and leaves the half day on the
        // position, so the anchor lands on day 10 rather than the payment time.
        let interest =
            CredisContract::accrued_interest(&credis.get_position(id).unwrap(), at(10) + DAY / 2)
                .unwrap();
        credis
            .settle(id, interest + U256::from(1u64), at(10) + DAY / 2)
            .unwrap();

        assert_eq!(credis.get_position(id).unwrap().last_settled_at, at(10));
    });
}

// ---------------------------------------------------------------------------
// Call transitions
// ---------------------------------------------------------------------------

#[test]
fn mark_called_does_not_move_the_deadline() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let id = credis.open_position(params(handle(1), alice())).unwrap();

        assert!(credis.mark_called(id, at(10)).unwrap());
        assert!(
            !credis.mark_called(id, at(20)).unwrap(),
            "re-calling must not extend the window"
        );
        assert_eq!(credis.get_position(id).unwrap().called_at, at(10));
    });
}

// ---------------------------------------------------------------------------
// Void
// ---------------------------------------------------------------------------

#[test]
fn void_requires_a_called_position_past_its_window_with_a_remainder() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let id = open_pos(&mut credis, 1);

        let err = credis.void_position(id, at(500)).unwrap_err().to_string();
        assert!(err.contains("not called"), "got: {err}");

        credis.mark_called(id, at(10)).unwrap();
        let deadline = settlement_deadline(&credis.get_position(id).unwrap());
        let err = credis
            .void_position(id, deadline - 1)
            .unwrap_err()
            .to_string();
        assert!(err.contains("window has not lapsed"), "got: {err}");

        // Fully settled inside the window - nothing is left to void.
        credis
            .settle(id, U256::from(999_999_999_999u64), at(11))
            .unwrap();
        let err = credis.void_position(id, deadline).unwrap_err().to_string();
        assert!(
            err.contains("closed") || err.contains("not called"),
            "got: {err}"
        );
    });
}

#[test]
fn a_fully_unpaid_void_burns_all_collateral_and_scores_a_full_unpaid_share() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let id = open_pos(&mut credis, 1);
        credis.mark_called(id, at(10)).unwrap();

        let void = credis.void_position(id, at(24)).unwrap();
        assert_eq!(void.gratis_burned, collateral());
        assert_eq!(void.principal_written_off, U256::from(PRINCIPAL));
        assert_eq!(void.unpaid_share, SCALE_1E6_U256, "100% unpaid");
    });
}

#[test]
fn void_is_terminal() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let id = open_pos(&mut credis, 1);
        credis.mark_called(id, at(10)).unwrap();
        credis.void_position(id, at(24)).unwrap();

        // A second sweep finds nothing: the position is no longer Called.
        assert!(credis.void_position(id, at(25)).is_err());
        assert!(credis.settle(id, U256::from(1u64), at(25)).is_err());
        assert!(!credis.has_called_position(alice()).unwrap());
    });
}

// ---------------------------------------------------------------------------
// Reads and indexes
// ---------------------------------------------------------------------------

#[test]
fn has_called_position_tracks_the_owners_book() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let first = open_pos(&mut credis, 1);
        let _second = open_pos(&mut credis, 2);
        assert!(!credis.has_called_position(alice()).unwrap());

        credis.mark_called(first, at(10)).unwrap();
        assert!(credis.has_called_position(alice()).unwrap());
        assert!(
            !credis.has_called_position(bob()).unwrap(),
            "another owner is unaffected"
        );

        credis
            .settle(first, U256::from(999_999_999_999u64), at(11))
            .unwrap();
        assert!(
            !credis.has_called_position(alice()).unwrap(),
            "settling the call in full clears the owner's block"
        );
    });
}

#[test]
fn the_called_counter_also_clears_on_a_void() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let id = open_pos(&mut credis, 1);
        credis.mark_called(id, at(10)).unwrap();
        assert!(credis.has_called_position(alice()).unwrap());

        credis.void_position(id, at(24)).unwrap();
        assert!(
            !credis.has_called_position(alice()).unwrap(),
            "a void resolves the call as much as a settlement does"
        );
    });
}

/// Reads the active index back as a plain list, so the assertions below are
/// about membership rather than about a particular slot order.
fn active_ids(credis: &CredisContract<'_>) -> Vec<U256> {
    let mut out = Vec::new();
    for i in 0..credis.active_len().unwrap() {
        if let Some(id) = credis.active_at(i).unwrap() {
            out.push(id);
        }
    }
    out
}

#[test]
fn the_active_index_holds_exactly_the_non_terminal_positions() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let id = credis.open_position(params(handle(1), alice())).unwrap();
        assert_eq!(active_ids(&credis), vec![id], "an open position is listed");

        // Calling keeps it listed - a called position is non-terminal.
        credis.mark_called(id, at(10)).unwrap();
        assert_eq!(active_ids(&credis), vec![id]);

        // A partial settlement leaves it listed; the settlement that closes it
        // does not.
        credis
            .settle(id, U256::from(400_000_000u64), at(11))
            .unwrap();
        assert_eq!(active_ids(&credis), vec![id]);
        credis
            .settle(id, U256::from(999_999_999_999u64), at(12))
            .unwrap();
        assert!(active_ids(&credis).is_empty(), "Settled leaves the index");
    });
}

#[test]
fn a_void_leaves_the_active_index() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let id = open_pos(&mut credis, 1);
        credis.mark_called(id, at(10)).unwrap();
        credis.void_position(id, at(24)).unwrap();
        assert!(active_ids(&credis).is_empty());
    });
}

#[test]
fn removing_from_the_middle_keeps_the_active_index_consistent() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let first = open_pos(&mut credis, 1);
        let second = open_pos(&mut credis, 2);
        let third = open_pos(&mut credis, 3);
        assert_eq!(active_ids(&credis), vec![first, second, third]);

        // Close the middle one: the tail swaps into its slot.
        credis
            .settle(second, U256::from(999_999_999_999u64), at(1))
            .unwrap();
        let after = active_ids(&credis);
        assert_eq!(after.len(), 2);
        assert!(after.contains(&first) && after.contains(&third));

        // The swapped entry's stored slot must have followed it, or removing it
        // next would corrupt the list.
        credis
            .settle(third, U256::from(999_999_999_999u64), at(2))
            .unwrap();
        assert_eq!(active_ids(&credis), vec![first]);

        credis
            .settle(first, U256::from(999_999_999_999u64), at(3))
            .unwrap();
        assert!(active_ids(&credis).is_empty());
    });
}

#[test]
fn sums_and_indexes_span_all_of_an_accounts_positions() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        let first = open_pos(&mut credis, 1);
        credis.open_position(params(handle(2), alice())).unwrap();
        credis.open_position(params(handle(3), bob())).unwrap();

        assert_eq!(
            credis.principal_and_outstanding_of(alice()).unwrap(),
            (
                U256::from(PRINCIPAL) * U256::from(2u64),
                U256::from(PRINCIPAL) * U256::from(2u64)
            )
        );

        // Settling one reduces outstanding but never principal.
        credis
            .settle(first, U256::from(999_999_999_999u64), at(1))
            .unwrap();
        assert_eq!(
            credis.principal_and_outstanding_of(alice()).unwrap(),
            (
                U256::from(PRINCIPAL) * U256::from(2u64),
                U256::from(PRINCIPAL)
            )
        );

        assert_eq!(credis.position_count_of(alice()).unwrap(), 2);
        assert_eq!(credis.position_count_of(bob()).unwrap(), 1);
        assert_eq!(credis.total_positions().unwrap(), 3);
        assert_eq!(credis.position_id_at(0).unwrap(), first);

        // Both enumerations address the same positions, from either end.
        assert_eq!(credis.position_at(0).unwrap().position_id, first);
        assert_eq!(
            credis
                .position_of_address_at(alice(), 0)
                .unwrap()
                .position_id,
            first
        );
        assert_eq!(
            credis
                .position_of_address_at(bob(), 0)
                .unwrap()
                .smart_account,
            bob()
        );
    });
}

#[test]
fn enumeration_rejects_an_out_of_range_index() {
    with_credis(|storage| {
        let mut credis = CredisContract::new(storage);
        credis.open_position(params(handle(1), alice())).unwrap();

        // One position exists, so index 1 is past the end of both indexes. An
        // out-of-range read must fail rather than report a zeroed position.
        assert!(matches!(
            credis.position_at(1),
            Err(e) if e.to_string().contains("index out of bounds")
        ));
        assert!(matches!(
            credis.position_of_address_at(alice(), 1),
            Err(e) if e.to_string().contains("index out of bounds")
        ));
        assert!(matches!(
            credis.position_of_address_at(bob(), 0),
            Err(e) if e.to_string().contains("index out of bounds")
        ));
    });
}

#[test]
fn invalid_state_bytes_are_rejected_rather_than_silently_reinterpreted() {
    assert!(matches!(
        CredisState::from_u8(9),
        Err(CredisError::InvalidStateValue(9))
    ));
    for (value, expected) in [
        (0u8, CredisState::Open),
        (1, CredisState::Called),
        (2, CredisState::Settled),
        (3, CredisState::Void),
    ] {
        assert_eq!(CredisState::from_u8(value).unwrap(), expected);
    }
    assert!(CredisState::Settled.is_terminal());
    assert!(CredisState::Void.is_terminal());
    assert!(!CredisState::Called.is_terminal());
}

// ---------------------------------------------------------------------------
// Precompile surface
// ---------------------------------------------------------------------------

#[test]
fn precompile_get_position_returns_the_full_record() {
    with_credis(|storage| {
        let id = {
            let mut credis = CredisContract::new(storage.clone());
            open_pos(&mut credis, 1)
        };

        let data = ICredis::getPositionCall { positionId: id }.abi_encode();
        let out = dispatch(storage, &data, alice(), U256::ZERO).unwrap();
        let decoded = ICredis::getPositionCall::abi_decode_returns(&out).unwrap();

        assert_eq!(decoded.positionId, id);
        assert_eq!(decoded.smartAccount, alice());
        assert_eq!(decoded.cca, cca());
        assert_eq!(decoded.asset, asset());
        assert_eq!(decoded.issuanceCurrency, 840);
        assert_eq!(decoded.referenceCurrency, 978);
        assert_eq!(decoded.principal, U256::from(PRINCIPAL));
        assert_eq!(decoded.collateral, collateral());
        assert_eq!(decoded.entryPrice, entry_price());
        assert_eq!(decoded.callPrice, U256::from(820_000u64));
        assert_eq!(decoded.policyRate, policy_rate());
        assert_eq!(decoded.state, CredisState::Open as u8);
        assert_eq!(decoded.eoaCiphertext.to_vec(), eoa_ct());
    });
}

#[test]
fn precompile_enumerates_positions_globally_and_per_owner() {
    with_credis(|storage| {
        let (first, second) = {
            let mut credis = CredisContract::new(storage.clone());
            let first = credis.open_position(params(handle(1), alice())).unwrap();
            let second = credis.open_position(params(handle(2), bob())).unwrap();
            (first, second)
        };

        let call = |data: Vec<u8>| dispatch(storage.clone(), &data, alice(), U256::ZERO).unwrap();

        let out = call(ICredis::totalSupplyCall {}.abi_encode());
        assert_eq!(
            ICredis::totalSupplyCall::abi_decode_returns(&out).unwrap(),
            U256::from(2u64)
        );

        let out = call(
            ICredis::balanceOfCall {
                smartAccount: alice(),
            }
            .abi_encode(),
        );
        assert_eq!(
            ICredis::balanceOfCall::abi_decode_returns(&out).unwrap(),
            U256::from(1u64)
        );

        // The global index is creation-ordered across owners.
        let out = call(
            ICredis::positionByIndexCall {
                index: U256::from(1u64),
            }
            .abi_encode(),
        );
        assert_eq!(
            ICredis::positionByIndexCall::abi_decode_returns(&out)
                .unwrap()
                .positionId,
            second
        );

        // The per-owner index addresses only that owner's positions.
        let out = call(
            ICredis::positionOfAddressByIndexCall {
                smartAccount: alice(),
                index: U256::ZERO,
            }
            .abi_encode(),
        );
        assert_eq!(
            ICredis::positionOfAddressByIndexCall::abi_decode_returns(&out)
                .unwrap()
                .positionId,
            first
        );

        // `ownerOf` resolves the owner of a single position.
        let out = call(ICredis::ownerOfCall { positionId: first }.abi_encode());
        assert_eq!(
            ICredis::ownerOfCall::abi_decode_returns(&out).unwrap(),
            alice()
        );
        let out = call(ICredis::ownerOfCall { positionId: second }.abi_encode());
        assert_eq!(
            ICredis::ownerOfCall::abi_decode_returns(&out).unwrap(),
            bob()
        );

        // An unknown id is rejected rather than reported as owned by nobody.
        let unknown = ICredis::ownerOfCall {
            positionId: U256::from(0xdeadu64),
        }
        .abi_encode();
        let err = dispatch(storage.clone(), &unknown, alice(), U256::ZERO).unwrap_err();
        assert!(err.to_string().contains("not found"), "got: {err}");
    });
}

#[test]
fn precompile_reports_principal_and_outstanding_together() {
    with_credis(|storage| {
        let id = {
            let mut credis = CredisContract::new(storage.clone());
            let id = open_pos(&mut credis, 1);
            credis.open_position(params(handle(2), alice())).unwrap();
            // Settle one position in full so the two sums diverge.
            credis
                .settle(id, U256::from(999_999_999_999u64), at(1))
                .unwrap();
            id
        };
        let _ = id;

        let data = ICredis::credisPrincipalAndOutstandingOfCall {
            smartAccount: alice(),
        }
        .abi_encode();
        let out = dispatch(storage, &data, alice(), U256::ZERO).unwrap();
        let decoded =
            ICredis::credisPrincipalAndOutstandingOfCall::abi_decode_returns(&out).unwrap();

        assert_eq!(decoded._0, U256::from(PRINCIPAL) * U256::from(2u64));
        assert_eq!(decoded._1, U256::from(PRINCIPAL));
    });
}

#[test]
fn precompile_accrued_interest_uses_the_storage_timestamp() {
    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.set_timestamp(U256::from(ORIGINATED_AT));
    let id = StorageHandle::enter(&mut storage, |handle| {
        let mut credis = CredisContract::new(handle);
        open_pos(&mut credis, 1)
    });

    // At origination nothing has accrued.
    let data = ICredis::accruedInterestCall { positionId: id }.abi_encode();
    let out = StorageHandle::enter(&mut storage, |handle| {
        dispatch(handle, &data, alice(), U256::ZERO).unwrap()
    });
    assert_eq!(
        ICredis::accruedInterestCall::abi_decode_returns(&out).unwrap(),
        U256::ZERO
    );

    // 100 days later it matches the worked example.
    storage.set_timestamp(U256::from(at(100)));
    let out = StorageHandle::enter(&mut storage, |handle| {
        dispatch(handle, &data, alice(), U256::ZERO).unwrap()
    });
    assert_eq!(
        ICredis::accruedInterestCall::abi_decode_returns(&out).unwrap(),
        U256::from(10_958_905u64)
    );
}

#[test]
fn precompile_rejects_msg_value() {
    with_credis(|storage| {
        let data = ICredis::totalSupplyCall {}.abi_encode();
        let err = dispatch(storage, &data, alice(), U256::from(1u64)).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("value"));
    });
}

#[test]
fn precompile_supports_erc165() {
    with_credis(|storage| {
        let data = ICredis::supportsInterfaceCall {
            interfaceId: ERC165_INTERFACE_ID.into(),
        }
        .abi_encode();
        let out = dispatch(storage, &data, alice(), U256::ZERO).unwrap();
        assert!(ICredis::supportsInterfaceCall::abi_decode_returns(&out).unwrap());
    });
}
