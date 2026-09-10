use super::*;

use outbe_desis::{AuctionStage, DesisContract};
use outbe_ocomp_protocol::{
    intent::{AuctionEntryPriceSource, DayType, ReferenceEntryPriceV1},
    receipts::{desis_request_brief_hash, BudgetSplitDestination},
};
use outbe_primitives::error::PrecompileError;

use crate::ocomp_budget::{
    apply_auction_brief, apply_fresh_request_budget_effect, RequestBudgetEffect, RequestBudgetSplit,
};

/// The day's frozen price table: one dollar row, as a single-currency day carries.
fn entry_prices() -> Vec<ReferenceEntryPriceV1> {
    vec![ReferenceEntryPriceV1 {
        reference_currency: outbe_oracle::constants::DAY_TYPE_ISO,
        entry_price_minor: U256::from(2),
        source: AuctionEntryPriceSource::LastClosedDayVwap,
        source_day: 20_251_231,
    }]
}

#[test]
fn request_budget_split_is_exact_at_zero_max_and_rejects_over_budget() {
    assert_eq!(
        RequestBudgetSplit::derive(U256::ZERO, U256::ZERO, U256::ZERO, U256::ZERO, true).unwrap(),
        RequestBudgetSplit {
            day_limit: U256::ZERO,
            lysis_budget: U256::ZERO,
            auction_base: U256::ZERO,
            carry_over_credit: U256::ZERO,
        }
    );
    // Lysis takes the whole emission, so nothing is credited and nothing is drawn.
    assert_eq!(
        RequestBudgetSplit::derive(U256::MAX, U256::MAX, U256::MAX, U256::ZERO, true).unwrap(),
        RequestBudgetSplit {
            day_limit: U256::MAX,
            lysis_budget: U256::MAX,
            auction_base: U256::ZERO,
            carry_over_credit: U256::ZERO,
        }
    );
    // A draw the effective ceiling could not represent is rejected rather than wrapped.
    assert!(matches!(
        RequestBudgetSplit::derive(U256::MAX, U256::ZERO, U256::MAX, U256::ZERO, true),
        Err(PrecompileError::Revert(_))
    ));
    // Lysis above the day's own emission is corruption, not a clamp.
    assert!(matches!(
        RequestBudgetSplit::derive(
            U256::from(9),
            U256::from(10),
            U256::from(9),
            U256::ZERO,
            true
        ),
        Err(PrecompileError::Revert(_))
    ));
}

#[test]
fn request_budget_split_auctions_the_day_nominal_and_leaves_limit_headroom_unbriefed() {
    // A day that earned less than the limit auctions the rest of what it earned; the headroom is
    // not briefed and goes back to the warehouse instead.
    let weak = RequestBudgetSplit::derive(
        U256::from(1_000),
        U256::from(32),
        U256::from(100),
        U256::ZERO,
        true,
    )
    .unwrap();
    assert_eq!(weak.auction_base, U256::from(68));
    assert_eq!(weak.carry_over_credit, U256::from(968));

    // A day that earned past its own emission is bounded by what the accumulator holds.
    let strong = RequestBudgetSplit::derive(
        U256::from(1_000),
        U256::from(320),
        U256::from(5_000),
        U256::ZERO,
        true,
    )
    .unwrap();
    assert_eq!(strong.auction_base, U256::from(680));

    // The same day reaches past its own emission once the accumulator has something to give.
    let funded = RequestBudgetSplit::derive(
        U256::from(1_000),
        U256::from(320),
        U256::from(5_000),
        U256::from(2_000),
        true,
    )
    .unwrap();
    assert_eq!(funded.auction_base, U256::from(2_680));
    assert_eq!(funded.day_limit, U256::from(3_680));

    // Lysis alone can exhaust the day's emission, and then only the accumulator funds the auction.
    let exhausted = RequestBudgetSplit::derive(
        U256::from(1_000),
        U256::from(1_000),
        U256::from(5_000),
        U256::ZERO,
        true,
    )
    .unwrap();
    assert_eq!(exhausted.auction_base, U256::ZERO);

    // A day with no tributes auctions nothing.
    let empty =
        RequestBudgetSplit::derive(U256::from(1_000), U256::ZERO, U256::ZERO, U256::ZERO, true)
            .unwrap();
    assert_eq!(empty.auction_base, U256::ZERO);

    // A red day draws nothing, however much the accumulator holds.
    let red = RequestBudgetSplit::derive(
        U256::from(1_000),
        U256::from(4),
        U256::from(100),
        U256::from(9_000),
        false,
    )
    .unwrap();
    assert_eq!(red.auction_base, U256::ZERO);
    assert_eq!(red.carry_over_credit, U256::from(996));
}

#[test]
fn green_request_commits_exact_auction_base_and_canonical_receipt() {
    with_storage(|storage| {
        let request = RequestBudgetEffect {
            protocol_bundle_hash: B256::repeat_byte(0x41),
            wwd: 20_260_101,
            pending_nonce: 1,
            day_type: DayType::Green,
            day_limit: U256::from(100),
            lysis_budget: U256::from(40),
            nominal_total: U256::from(100),
            auction_entry_prices: entry_prices(),
            logical_anchor: 1_699_920_005,
        };

        let receipt = apply_fresh_request_budget_effect(storage.clone(), request.clone())
            .expect("GREEN request budget effect");
        // The brief waits for the Lysis deadline; drive it here.
        apply_auction_brief(storage.clone(), &receipt).expect("the auction briefs");

        // The effective ceiling is the day's own emission plus what it drew from the accumulator.
        assert_eq!(receipt.day_limit, U256::from(160));
        assert_eq!(receipt.lysis_budget, U256::from(40));
        assert_eq!(receipt.auction_base, U256::from(60));
        assert_eq!(receipt.destination, BudgetSplitDestination::DesisAuction);
        assert_eq!(receipt.carry_over_credit, U256::from(60));
        assert_eq!(
            receipt.desis_brief_hash,
            Some(
                desis_request_brief_hash(
                    request.protocol_bundle_hash,
                    request.wwd,
                    U256::from(60),
                    &request.auction_entry_prices,
                    request.logical_anchor,
                )
                .unwrap()
            )
        );

        let desis = DesisContract::new(storage.clone());
        assert_eq!(
            desis.auction_stage.read(&request.wwd.into()).unwrap(),
            AuctionStage::Briefed as u8
        );
        assert_eq!(
            desis
                .pending_supply_promis
                .read(&request.wwd.into())
                .unwrap(),
            U256::from(60)
        );
        assert_eq!(
            PromisLimitContract::new(storage)
                .get_total_unallocated()
                .unwrap(),
            U256::ZERO
        );
    });
}

#[test]
fn red_request_briefs_desis_without_supply_and_credits_exact_auction_base() {
    with_storage(|storage| {
        let request = RequestBudgetEffect {
            protocol_bundle_hash: B256::repeat_byte(0x41),
            wwd: 20_260_102,
            pending_nonce: 1,
            day_type: DayType::Red,
            day_limit: U256::from(100),
            lysis_budget: U256::from(40),
            nominal_total: U256::from(100),
            auction_entry_prices: entry_prices(),
            logical_anchor: 1_699_920_005,
        };

        let receipt = apply_fresh_request_budget_effect(storage.clone(), request.clone())
            .expect("RED request budget effect");
        // The brief waits for the Lysis deadline; drive it here.
        apply_auction_brief(storage.clone(), &receipt).expect("the auction briefs");

        assert_eq!(receipt.destination, BudgetSplitDestination::CarryOver);
        assert!(receipt.desis_brief_hash.is_some());
        assert_eq!(receipt.carry_over_credit, U256::from(60));
        let desis = DesisContract::new(storage.clone());
        assert_eq!(desis.auction_stage.read(&request.wwd.into()).unwrap(), 1);
        assert_eq!(desis.brief_green.read(&request.wwd.into()).unwrap(), 0);
        assert_eq!(
            PromisLimitContract::new(storage)
                .get_total_unallocated()
                .unwrap(),
            U256::from(60)
        );
    });
}

#[test]
fn strict_desis_refusal_leaves_the_existing_brief_and_carry_over_unchanged() {
    with_storage(|storage| {
        let wwd = outbe_primitives::time::WorldwideDay::new(20_260_105);
        outbe_desis::api::dispatch_auction_brief(
            storage.clone(),
            wwd,
            U256::from(7),
            vec![outbe_desis::ReferenceCurrencyPrice {
                iso_code: 840,
                entry_price_minor: U256::from(3),
            }],
            true,
            1_699_920_005,
            outbe_desis::api::BriefOverflowPolicy::CarryOver,
        )
        .unwrap();
        PromisLimitContract::new(storage.clone())
            .checked_add_carry_over(U256::from(5))
            .unwrap();
        let request = RequestBudgetEffect {
            protocol_bundle_hash: B256::repeat_byte(0x41),
            wwd: wwd.into(),
            pending_nonce: 1,
            day_type: DayType::Green,
            day_limit: U256::from(100),
            lysis_budget: U256::from(40),
            nominal_total: U256::from(100),
            auction_entry_prices: entry_prices(),
            logical_anchor: 1_699_920_005,
        };

        // The request itself only credits; the refusal comes when the auction tries to brief a day
        // Desis already holds.
        let receipt = apply_fresh_request_budget_effect(storage.clone(), request.clone())
            .expect("the request credits without touching Desis");
        let credited = PromisLimitContract::new(storage.clone())
            .get_total_unallocated()
            .unwrap();
        assert!(apply_auction_brief(storage.clone(), &receipt).is_err());

        let desis = DesisContract::new(storage.clone());
        assert_eq!(
            desis.pending_supply_promis.read(&wwd).unwrap(),
            U256::from(7)
        );
        assert_eq!(desis.sched_active_count.read().unwrap(), 1);
        assert_eq!(
            PromisLimitContract::new(storage)
                .get_total_unallocated()
                .unwrap(),
            credited,
            "a refused brief draws nothing"
        );
    });
}

#[test]
fn red_carry_over_overflow_reverts_without_a_partial_request_effect() {
    with_storage(|storage| {
        let before = U256::MAX - U256::from(5);
        PromisLimitContract::new(storage.clone())
            .checked_add_carry_over(before)
            .unwrap();
        let request = RequestBudgetEffect {
            protocol_bundle_hash: B256::repeat_byte(0x41),
            wwd: 20_260_106,
            pending_nonce: 1,
            day_type: DayType::Red,
            day_limit: U256::from(20),
            lysis_budget: U256::from(10),
            nominal_total: U256::from(20),
            auction_entry_prices: entry_prices(),
            logical_anchor: 1_699_920_005,
        };

        assert!(apply_fresh_request_budget_effect(storage.clone(), request.clone()).is_err());
        assert_eq!(
            PromisLimitContract::new(storage.clone())
                .get_total_unallocated()
                .unwrap(),
            before
        );
        assert_eq!(
            DesisContract::new(storage)
                .auction_stage
                .read(&request.wwd.into())
                .unwrap(),
            0
        );
    });
}

#[test]
fn an_unpriced_day_commits_a_canonical_empty_price_table() {
    with_storage(|storage| {
        let request = RequestBudgetEffect {
            protocol_bundle_hash: B256::repeat_byte(0x41),
            wwd: 20_260_109,
            pending_nonce: 1,
            day_type: DayType::Green,
            day_limit: U256::from(100),
            lysis_budget: U256::from(40),
            nominal_total: U256::from(100),
            auction_entry_prices: Vec::new(),
            logical_anchor: 1_699_920_005,
        };

        let receipt = apply_fresh_request_budget_effect(storage.clone(), request.clone())
            .expect("an unpriced day still commits its budget split");
        // The brief waits for the Lysis deadline; drive it here.
        apply_auction_brief(storage.clone(), &receipt).expect("the auction briefs");
        assert!(receipt.auction_entry_prices.is_empty());
        // The brief hash writes the table length first, so an empty table commits as
        // length zero rather than as a special case.
        assert_eq!(
            receipt.desis_brief_hash,
            Some(
                desis_request_brief_hash(
                    request.protocol_bundle_hash,
                    request.wwd,
                    receipt.auction_base,
                    &[],
                    request.logical_anchor,
                )
                .unwrap()
            )
        );
        receipt
            .validate_semantics()
            .expect("the empty table is a canonical request receipt");
    });
}

#[test]
fn a_weak_day_credits_the_headroom_it_never_briefed() {
    with_storage(|storage| {
        let request = RequestBudgetEffect {
            protocol_bundle_hash: B256::repeat_byte(0x41),
            wwd: 20_260_110,
            pending_nonce: 1,
            day_type: DayType::Green,
            day_limit: U256::from(1_000),
            lysis_budget: U256::from(32),
            nominal_total: U256::from(100),
            auction_entry_prices: entry_prices(),
            logical_anchor: 1_699_920_005,
        };

        let receipt = apply_fresh_request_budget_effect(storage.clone(), request.clone())
            .expect("a weak day commits its budget split");
        // The brief waits for the Lysis deadline; drive it here.
        apply_auction_brief(storage.clone(), &receipt).expect("the auction briefs");

        assert_eq!(receipt.auction_base, U256::from(68));
        assert_eq!(receipt.carry_over_credit, U256::from(968));
        assert_eq!(
            receipt.lysis_budget + receipt.auction_base + receipt.carry_over_credit,
            receipt.day_limit,
            "the effective ceiling is exhausted by Lysis, the brief and the accumulator"
        );
        assert_eq!(
            DesisContract::new(storage.clone())
                .pending_supply_promis
                .read(&request.wwd.into())
                .unwrap(),
            U256::from(68)
        );
        assert_eq!(
            PromisLimitContract::new(storage)
                .get_total_unallocated()
                .unwrap(),
            U256::from(900)
        );
    });
}

#[test]
fn a_weak_red_day_credits_its_base_together_with_the_headroom() {
    with_storage(|storage| {
        let request = RequestBudgetEffect {
            protocol_bundle_hash: B256::repeat_byte(0x41),
            wwd: 20_260_111,
            pending_nonce: 1,
            day_type: DayType::Red,
            day_limit: U256::from(1_000),
            lysis_budget: U256::from(4),
            nominal_total: U256::from(100),
            auction_entry_prices: entry_prices(),
            logical_anchor: 1_699_920_005,
        };

        let receipt = apply_fresh_request_budget_effect(storage.clone(), request.clone())
            .expect("a weak RED day commits its budget split");
        // The brief waits for the Lysis deadline; drive it here.
        apply_auction_brief(storage.clone(), &receipt).expect("the auction briefs");

        assert_eq!(receipt.auction_base, U256::ZERO);
        assert_eq!(receipt.carry_over_credit, U256::from(996));
        assert_eq!(
            PromisLimitContract::new(storage)
                .get_total_unallocated()
                .unwrap(),
            U256::from(996),
            "a RED day opens no auction, so its base returns with the headroom"
        );
    });
}

#[test]
fn a_day_reaches_past_its_own_emission_into_the_accumulator() {
    with_storage(|storage| {
        // What earlier days did not issue.
        PromisLimitContract::new(storage.clone())
            .checked_add_carry_over(U256::from(5_000))
            .unwrap();

        let request = RequestBudgetEffect {
            protocol_bundle_hash: B256::repeat_byte(0x41),
            wwd: 20_260_112,
            pending_nonce: 1,
            day_type: DayType::Green,
            day_limit: U256::from(1_000),
            lysis_budget: U256::from(320),
            nominal_total: U256::from(5_000),
            auction_entry_prices: entry_prices(),
            logical_anchor: 1_699_920_005,
        };

        let receipt = apply_fresh_request_budget_effect(storage.clone(), request.clone())
            .expect("a day funded past its own emission");
        // The brief waits for the Lysis deadline; drive it here.
        apply_auction_brief(storage.clone(), &receipt).expect("the auction briefs");

        // Demand is the nominal beyond the symbolic share, and the accumulator covers it.
        assert_eq!(receipt.auction_base, U256::from(4_680));
        assert_eq!(receipt.carry_over_credit, U256::from(680));
        assert_eq!(receipt.day_limit, U256::from(5_680));
        assert_eq!(
            DesisContract::new(storage.clone())
                .pending_supply_promis
                .read(&request.wwd.into())
                .unwrap(),
            U256::from(4_680),
            "the auction is briefed with more than the day's own emission"
        );
        assert_eq!(
            PromisLimitContract::new(storage)
                .get_total_unallocated()
                .unwrap(),
            U256::from(1_000),
            "the accumulator keeps what this day did not draw"
        );
    });
}

#[test]
fn an_auction_takes_what_the_accumulator_holds_when_demand_exceeds_it() {
    with_storage(|storage| {
        PromisLimitContract::new(storage.clone())
            .checked_add_carry_over(U256::from(100))
            .unwrap();

        let request = RequestBudgetEffect {
            protocol_bundle_hash: B256::repeat_byte(0x41),
            wwd: 20_260_114,
            pending_nonce: 1,
            day_type: DayType::Green,
            day_limit: U256::from(1_000),
            lysis_budget: U256::from(320),
            nominal_total: U256::from(5_000),
            auction_entry_prices: entry_prices(),
            logical_anchor: 1_699_920_005,
        };

        let receipt = apply_fresh_request_budget_effect(storage.clone(), request.clone())
            .expect("a day the accumulator cannot fully serve");
        // The brief waits for the Lysis deadline; drive it here.
        apply_auction_brief(storage.clone(), &receipt).expect("the auction briefs");

        // Demand is 4_680, but the accumulator only holds 100 plus this day's own 680.
        assert_eq!(receipt.auction_base, U256::from(780));
        assert_eq!(
            DesisContract::new(storage.clone())
                .pending_supply_promis
                .read(&request.wwd.into())
                .unwrap(),
            U256::from(780)
        );
        assert_eq!(
            PromisLimitContract::new(storage)
                .get_total_unallocated()
                .unwrap(),
            U256::ZERO,
            "the accumulator serves what it has and is left empty"
        );
    });
}
