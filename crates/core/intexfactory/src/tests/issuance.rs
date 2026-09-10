use super::*;

#[test]
fn issue_creates_series_in_registry() {
    with_factory(|s| {
        runtime::issue(&s, sample(7)).unwrap();

        // The series is captured in Intex with the issuance identity.
        let r = outbe_intex::api::read_series(&s, sid(7)).unwrap();
        assert_eq!(r.series_id, sid(7));
        assert_eq!(r.promis_load_minor, U256::from(PROMIS_LOAD_MINOR));
        assert_eq!(r.entry_price_minor, U256::from(ENTRY_PRICE));
        // Floor and trigger are derived from the clearing price at issuance.
        assert_eq!(r.floor_price_minor, U256::from(EXPECTED_FLOOR));
        assert_eq!(r.issued_intex_count, 100);
        assert_eq!(r.call_notice_period, CALL_NOTICE_PERIOD);
        // Window/threshold/call-period are IntexFactory protocol constants now.
        assert_eq!(r.call_price_minor, U256::from(EXPECTED_TRIGGER));
        assert_eq!(
            r.call_trigger(),
            outbe_intex::IntexCallTrigger {
                call_window: 28 * DAY as u32,
                call_threshold: 21 * DAY as u32,
                call_notice_period: CALL_NOTICE_PERIOD,
            }
        );
        // Born Issued; issued_at is the block timestamp.
        assert_eq!(
            r.lifecycle_state().unwrap(),
            outbe_intex::IntexState::Issued
        );
        assert_eq!(r.issued_at, ISSUED_AT);
        assert_eq!(r.called_at, 0);
    });
}

#[test]
fn issue_rejects_duplicate_series() {
    with_factory(|s| {
        runtime::issue(&s, sample(7)).unwrap();
        // The registry record-create rejects a duplicate series id.
        assert!(runtime::issue(&s, sample(7)).is_err());
    });
}

#[test]
fn issue_zero_winners_leaves_the_day_untouched() {
    with_factory(|s| {
        // Lysis recorded contributors for the day, but this group had no winners.
        outbe_intex::api::record_contributors(
            &s,
            WorldwideDay::new(7),
            &[(holder(), U256::from(100u64))],
        )
        .unwrap();
        let mut p = sample(7);
        p.issued_intex_count = 0;
        runtime::issue(&s, p).unwrap();

        // No series is created, and the day's map is left for its caller to
        // decide on: sibling groups of the same day may still distribute.
        assert!(!outbe_intex::api::series_exists(&s, sid(7)).unwrap());
        assert_eq!(
            outbe_intex::api::contributor_count(&s, WorldwideDay::new(7)).unwrap(),
            1
        );
    });
}

#[test]
fn issuance_legs_route_winners_to_their_own_chain() {
    // One winner on chain 10, one on chain 20; chain 30 in the snapshot has none.
    let other = address!("0xCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC");
    let mut p = sample(7);
    p.recipients = vec![holder(), other];
    p.quantities = vec![U256::from(1), U256::from(2)];
    p.recipient_chains = vec![10, 20];
    p.snapshot_chains = vec![10, 20, 30];

    let legs = runtime::issuance_legs(&p);
    assert_eq!(legs.len(), 3);
    assert_eq!(legs[0], (10, vec![holder()], vec![U256::from(1)]));
    assert_eq!(legs[1], (20, vec![other], vec![U256::from(2)]));
    assert_eq!(legs[2], (30, vec![], vec![])); // create-only leg
}

#[test]
fn issue_enrolls_series_in_dense_enumeration() {
    with_factory(|s| {
        runtime::issue(&s, sample(11)).unwrap();
        runtime::issue(&s, sample(22)).unwrap();
        assert_eq!(outbe_intex::api::total_series(&s).unwrap(), 2);
        assert_eq!(outbe_intex::api::series_id_at(&s, 0).unwrap(), sid(11));
        assert_eq!(outbe_intex::api::series_id_at(&s, 1).unwrap(), sid(22));
    });
}

#[test]
fn floor_and_call_derivation() {
    let floor = runtime::marked_up(U256::from(ENTRY_PRICE), FLOOR_RATE).unwrap();
    let call = runtime::marked_up(U256::from(ENTRY_PRICE), CALL_RATE).unwrap();
    assert_eq!(floor, U256::from(EXPECTED_FLOOR));
    assert_eq!(call, U256::from(EXPECTED_TRIGGER));

    let one = U256::from(1_000_000u64);
    assert_eq!(
        runtime::marked_up(one, FLOOR_RATE).unwrap(),
        U256::from(1_080_000u64)
    );
    assert_eq!(
        runtime::marked_up(one, CALL_RATE).unwrap(),
        U256::from(2_280_000u64)
    );
}

#[test]
fn coen_iso_one_maps_to_the_center_price_bin_at_six_decimals() {
    assert_eq!(
        IntexFactoryContract::price_to_bin(U256::from(1_000_000u64)).unwrap(),
        REAL_ID_SHIFT as u32
    );
}

#[test]
fn coen_iso_wire_price_preserves_the_six_decimal_integer() {
    assert_eq!(
        runtime::to_wire_price(U256::from(1_234_567u64)).unwrap(),
        1_234_567
    );
    assert_eq!(
        runtime::to_wire_price(U256::from(u64::MAX)).unwrap(),
        u64::MAX
    );
    assert!(runtime::to_wire_price(U256::from(u64::MAX) + U256::ONE).is_err());
}

fn leg(chain_id: u32, series: u32, recipients: usize) -> runtime::IssuanceLeg {
    let mut payload = crate::sol_ext::IOriginRouter::IssuanceInstructionsParams {
        seriesId: sid(series).into(),
        worldwideDay: series,
        issuedIntexCount: 1,
        promisLoadMinor: PROMIS_LOAD_MINOR,
        entryPriceMinor: 0,
        floorPriceMinor: 0,
        callNoticePeriod: 0,
        issuanceCurrency: 840,
        referenceCurrency: 840,
        callWindow: 0,
        callThreshold: 0,
        callPriceMinor: 0,
        recipients: Vec::new(),
        quantities: Vec::new(),
    };
    for i in 0..recipients {
        payload
            .recipients
            .push(Address::from([(i % 250) as u8 + 1; 20]));
        payload.quantities.push(U256::from(1u64));
    }
    runtime::IssuanceLeg { chain_id, payload }
}

fn shape(
    messages: &[(
        u32,
        Vec<crate::sol_ext::IOriginRouter::IssuanceInstructionsParams>,
    )],
) -> Vec<(u32, usize, usize)> {
    messages
        .iter()
        .map(|(chain, series)| {
            (
                *chain,
                series.len(),
                series.iter().map(|s| s.recipients.len()).sum(),
            )
        })
        .collect()
}

#[test]
fn a_chains_series_travel_together_up_to_the_message_caps() {
    // Nine empty-recipient series on one chain: the series cap alone splits them.
    let legs: Vec<_> = (1..=9u32).map(|s| leg(10, s, 0)).collect();
    assert_eq!(
        shape(&runtime::pack_issuance_messages(legs)),
        vec![(10, MAX_SERIES_PER_MESSAGE, 0), (10, 1, 0)]
    );
}

/// The codec enforces this same number on both encode and decode (`BridgeMsgCodec.sol`), and nothing
/// links the two languages, so the value is pinned here: changing it must be a deliberate act.
#[test]
fn the_recipient_cap_matches_the_wire() {
    assert_eq!(MAX_RECIPIENTS_PER_ISSUANCE, 24);
    assert_eq!(MAX_SERIES_PER_MESSAGE, 8);
}

#[test]
fn a_message_never_carries_more_winners_than_the_wire_allows() {
    // Two series whose winners together exceed the recipient cap: no message may overfill.
    let per_series = MAX_RECIPIENTS_PER_ISSUANCE - 1;
    let legs = vec![leg(10, 1, per_series), leg(10, 2, per_series)];
    let messages = runtime::pack_issuance_messages(legs);

    for (_, _, recipients) in shape(&messages) {
        assert!(
            recipients <= MAX_RECIPIENTS_PER_ISSUANCE,
            "a message carried {recipients} winners, over the wire's cap"
        );
    }
    let total: usize = shape(&messages).iter().map(|(_, _, r)| r).sum();
    assert_eq!(
        total,
        2 * per_series,
        "every winner is carried exactly once"
    );
}

#[test]
fn one_series_with_more_winners_than_a_message_spans_several() {
    // One series far past the cap: it spans full messages plus a remainder, and every piece
    // repeats the series so whichever arrives first can create it.
    let winners = 5 * MAX_RECIPIENTS_PER_ISSUANCE - 10;
    let messages = runtime::pack_issuance_messages(vec![leg(10, 1, winners)]);

    let pieces = shape(&messages);
    assert_eq!(
        pieces.len(),
        winners.div_ceil(MAX_RECIPIENTS_PER_ISSUANCE),
        "one message per full slice plus the remainder"
    );
    assert_eq!(
        pieces.iter().map(|(_, _, r)| r).sum::<usize>(),
        winners,
        "every winner is carried exactly once"
    );
    for (_, series) in &messages {
        assert_eq!(SeriesId::from(series[0].seriesId), sid(1));
    }
}

#[test]
fn a_chains_series_batch_even_when_another_chain_comes_between_them() {
    // A day emits its legs series by series, so one chain's legs are never adjacent.
    // Both of chain 10's series still travel together, or the batching would do
    // nothing precisely when a day has several currency pairs.
    let legs = vec![leg(10, 1, 2), leg(20, 1, 3), leg(10, 2, 1)];
    assert_eq!(
        shape(&runtime::pack_issuance_messages(legs)),
        vec![(10, 2, 3), (20, 1, 3)]
    );
}

fn run_shape(runs: &[runtime::IssuanceRun]) -> Vec<((u32, u32), Vec<usize>)> {
    runs.iter()
        .map(|(key, messages)| {
            (
                *key,
                messages
                    .iter()
                    .map(|m| m.iter().map(|s| s.recipients.len()).sum())
                    .collect(),
            )
        })
        .collect()
}

#[test]
fn a_chains_chunks_form_one_run_even_when_another_chain_interleaves() {
    // One day, one chain, winners spanning two messages, with another chain's message in between.
    let full = MAX_RECIPIENTS_PER_ISSUANCE;
    let packed =
        runtime::pack_issuance_messages(vec![leg(10, 1, full), leg(20, 1, 5), leg(10, 1, full)]);
    let runs = runtime::chunk_issuance_messages(packed);
    assert_eq!(
        run_shape(&runs),
        vec![((10, 1), vec![full, full]), ((20, 1), vec![5])]
    );
}

#[test]
fn a_chains_days_are_numbered_as_separate_runs() {
    // `leg`'s series doubles as its worldwide day: each day carries its own chunk numbering.
    let full = MAX_RECIPIENTS_PER_ISSUANCE;
    let packed = runtime::pack_issuance_messages(vec![leg(10, 1, full), leg(10, 2, full)]);
    let runs = runtime::chunk_issuance_messages(packed);
    assert_eq!(
        run_shape(&runs),
        vec![((10, 1), vec![full]), ((10, 2), vec![full])]
    );
}

#[test]
fn a_single_message_day_is_chunk_zero_of_one() {
    let runs =
        runtime::chunk_issuance_messages(runtime::pack_issuance_messages(vec![leg(7, 1, 3)]));
    assert_eq!(run_shape(&runs), vec![((7, 1), vec![3])]);
}

/// Issue a series whose issuance currency differs from its reference, with a
/// payment token reporting `iso` and 18 decimals and a registered vault.
fn with_dual_currency_series<R>(iso: u64, f: impl FnOnce(StorageHandle) -> R) -> R {
    use crate::sol_ext::{IReferenceCurrency, IERC20};
    use outbe_vaultrouter::api::IVaultRouter;

    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.set_timestamp(U256::from(ISSUED_AT as u64));
    storage.stub_sub_call_at(crate::constants::INTEX_NFT1155_ADDRESS, word(0));
    storage.stub_sub_call_at(crate::constants::ORIGIN_ROUTER_ADDRESS, word(0));
    storage.stub_sub_call_at_selector(
        outbe_primitives::addresses::VAULT_ROUTER_ADDRESS,
        IVaultRouter::assetVaultsCountCall::SELECTOR,
        word(1),
    );
    storage.stub_sub_call_at_selector(
        payment_token(),
        IReferenceCurrency::isoCodeCall::SELECTOR,
        word(iso),
    );
    storage.stub_sub_call_at_selector(payment_token(), IERC20::decimalsCall::SELECTOR, word(18));

    StorageHandle::enter(&mut storage, |s| {
        let params = IssuanceParams {
            issuance_currency: EUR_ISO,
            ..sample(7)
        };
        runtime::issue(&s, params).unwrap();
        f(s)
    })
}

/// Every stablecoin-backed COEN/ISO Oracle rate uses six decimals.
const COEN_ISO_RATE_SCALE: U256 = U256::from_limbs([1_000_000, 0, 0, 0]);

/// Publish a COEN rate for `iso_code`, stamped `age` seconds ago.
fn publish_rate(oracle: &OracleContract, iso_code: u16, pair_id: u32, rate: U256, age: u64) {
    write_rate(oracle, iso_code, pair_id, rate);
    oracle
        .exchange_rate_timestamp
        .write(&pair_id, ISSUED_AT as u64 - age)
        .unwrap();
}

#[test]
fn the_issuance_currency_settles_through_the_coen_pivot() {
    with_dual_currency_series(EUR_ISO as u64, |s| {
        let oracle = OracleContract::new(s.clone());
        // COEN buys twice as many dollars as euros, so the euro price of one
        // Intex is half its dollar price.
        publish_rate(
            &oracle,
            REFERENCE_ISO,
            PAIR_ID,
            U256::from(2u64) * COEN_ISO_RATE_SCALE,
            0,
        );
        publish_rate(&oracle, EUR_ISO, EUR_PAIR_ID, COEN_ISO_RATE_SCALE, 0);

        let (_, cost) = runtime::quote_settlement(&s, sid(7), payment_token()).unwrap();
        assert_eq!(cost, U256::from(500_000_000_000_000_000u64));
    });
}

#[test]
fn issuance_currency_settlement_rounds_a_non_divisible_fx_result_up_once() {
    with_dual_currency_series(EUR_ISO as u64, |s| {
        let oracle = OracleContract::new(s.clone());
        publish_rate(
            &oracle,
            REFERENCE_ISO,
            PAIR_ID,
            U256::from(3u64) * COEN_ISO_RATE_SCALE,
            0,
        );
        publish_rate(&oracle, EUR_ISO, EUR_PAIR_ID, COEN_ISO_RATE_SCALE, 0);

        let (_, cost) = runtime::quote_settlement(&s, sid(7), payment_token()).unwrap();
        assert_eq!(cost, U256::from(333_333_333_333_333_334u64));
    });
}

#[test]
fn an_unpriced_issuance_currency_cannot_be_settled_in() {
    with_dual_currency_series(EUR_ISO as u64, |s| {
        let oracle = OracleContract::new(s.clone());
        publish_rate(
            &oracle,
            REFERENCE_ISO,
            PAIR_ID,
            U256::from(2u64) * COEN_ISO_RATE_SCALE,
            0,
        );
        // No euro pair at all.
        let err = runtime::quote_settlement(&s, sid(7), payment_token()).unwrap_err();
        assert!(err.to_string().contains("not registered"), "{err}");
    });
}

#[test]
fn a_stale_rate_cannot_be_settled_in() {
    with_dual_currency_series(EUR_ISO as u64, |s| {
        let oracle = OracleContract::new(s.clone());
        publish_rate(
            &oracle,
            REFERENCE_ISO,
            PAIR_ID,
            U256::from(2u64) * COEN_ISO_RATE_SCALE,
            0,
        );
        publish_rate(
            &oracle,
            EUR_ISO,
            EUR_PAIR_ID,
            COEN_ISO_RATE_SCALE,
            outbe_oracle::constants::FX_RATE_MAX_AGE_SECONDS + 1,
        );

        let err = runtime::quote_settlement(&s, sid(7), payment_token()).unwrap_err();
        assert!(err.to_string().contains("stale"), "{err}");
    });
}

#[test]
fn issuance_currency_settlement_rejects_fx_overflow() {
    with_dual_currency_series(EUR_ISO as u64, |s| {
        let oracle = OracleContract::new(s.clone());
        publish_rate(&oracle, REFERENCE_ISO, PAIR_ID, COEN_ISO_RATE_SCALE, 0);
        publish_rate(&oracle, EUR_ISO, EUR_PAIR_ID, U256::MAX, 0);

        let err = runtime::quote_settlement(&s, sid(7), payment_token()).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("overflow"), "{err}");
    });
}

#[test]
fn the_reference_currency_settles_without_reading_any_rate() {
    // No rate is published at all, yet the reference currency still settles.
    with_dual_currency_series(REFERENCE_ISO as u64, |s| {
        let (_, cost) = runtime::quote_settlement(&s, sid(7), payment_token()).unwrap();
        assert_eq!(cost, U256::from(1_000_000_000_000_000_000u64));
    });
}
