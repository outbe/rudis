use super::*;

fn contrib(n: u8) -> Address {
    Address::from([n; 20])
}

/// A future fan-in deadline relative to the harness clock (`ISSUED_AT`).
const DEADLINE_FUTURE: u64 = ISSUED_AT as u64 + 1000;

#[test]
fn distribute_pays_contributors_proportionally_with_dust_to_last() {
    with_factory(|s| {
        let owners = [contrib(1), contrib(2), contrib(3)];
        outbe_intex::api::record_contributors(
            &s,
            WorldwideDay::new(7),
            &[
                (owners[0], U256::from(100u64)),
                (owners[1], U256::from(200u64)),
                (owners[2], U256::from(300u64)),
            ],
        )
        .unwrap();
        // A single winning chain: its arrival completes the fan-in immediately.
        outbe_intex::api::arm_proceeds(&s, WorldwideDay::new(7), &[10], DEADLINE_FUTURE).unwrap();
        // Simulate the native value arriving on the precompile via distribute{value}.
        let amount = U256::from(1000u64);
        s.increase_balance(INTEX_FACTORY_ADDRESS, amount).unwrap();

        runtime::distribute(
            &s,
            crate::constants::ORIGIN_ROUTER_ADDRESS,
            7.into(),
            10,
            amount,
        )
        .unwrap();

        // distribute only registers; nothing is paid until the begin-block drain.
        assert_eq!(s.balance(owners[0]).unwrap(), U256::ZERO);
        assert_eq!(outbe_intex::api::active_dist_count(&s).unwrap(), 1);

        runtime::drain_distributions(&s).unwrap();

        // floor shares (amount * nominal / total); the last owner absorbs the
        // rounding remainder, so the sum is exactly `amount`.
        assert_eq!(s.balance(owners[0]).unwrap(), U256::from(166u64)); // 1000*100/600
        assert_eq!(s.balance(owners[1]).unwrap(), U256::from(333u64)); // 1000*200/600
        assert_eq!(s.balance(owners[2]).unwrap(), U256::from(501u64)); // 1000-166-333
                                                                       // precompile fully drained, progress + contributors cleared.
        assert_eq!(s.balance(INTEX_FACTORY_ADDRESS).unwrap(), U256::ZERO);
        assert_eq!(
            outbe_intex::api::get_progress(&s, WorldwideDay::new(7)).unwrap(),
            None
        );
        assert_eq!(outbe_intex::api::active_dist_count(&s).unwrap(), 0);
        assert_eq!(
            outbe_intex::api::contributor_count(&s, WorldwideDay::new(7)).unwrap(),
            0
        );
    });
}

#[test]
fn distribute_waits_for_all_winning_chains_then_pays_the_sum() {
    with_factory(|s| {
        let owners = [contrib(1), contrib(2)];
        outbe_intex::api::record_contributors(
            &s,
            WorldwideDay::new(7),
            &[
                (owners[0], U256::from(100u64)),
                (owners[1], U256::from(100u64)),
            ],
        )
        .unwrap();
        outbe_intex::api::arm_proceeds(&s, WorldwideDay::new(7), &[10, 20], DEADLINE_FUTURE)
            .unwrap();

        // Chain 10 arrives first: pot accumulates, fan-in not complete -> no payout yet.
        s.increase_balance(INTEX_FACTORY_ADDRESS, U256::from(300u64))
            .unwrap();
        runtime::distribute(
            &s,
            crate::constants::ORIGIN_ROUTER_ADDRESS,
            7.into(),
            10,
            U256::from(300u64),
        )
        .unwrap();
        assert_eq!(outbe_intex::api::active_dist_count(&s).unwrap(), 0);
        assert!(!outbe_intex::api::proceeds_ready(&s, WorldwideDay::new(7)).unwrap());

        // Chain 20 completes the fan-in: one distribution over the summed pot.
        s.increase_balance(INTEX_FACTORY_ADDRESS, U256::from(500u64))
            .unwrap();
        runtime::distribute(
            &s,
            crate::constants::ORIGIN_ROUTER_ADDRESS,
            7.into(),
            20,
            U256::from(500u64),
        )
        .unwrap();
        assert_eq!(outbe_intex::api::active_dist_count(&s).unwrap(), 1);

        runtime::drain_distributions(&s).unwrap();
        // 800 split 100:100 -> 400 each; map cleared since every chain is in.
        assert_eq!(s.balance(owners[0]).unwrap(), U256::from(400u64));
        assert_eq!(s.balance(owners[1]).unwrap(), U256::from(400u64));
        assert_eq!(s.balance(INTEX_FACTORY_ADDRESS).unwrap(), U256::ZERO);
        assert_eq!(
            outbe_intex::api::contributor_count(&s, WorldwideDay::new(7)).unwrap(),
            0
        );
    });
}

#[test]
fn distribute_deadline_forces_partial_payout_then_late_chain_supplements() {
    with_factory(|s| {
        let owners = [contrib(1), contrib(2)];
        outbe_intex::api::record_contributors(
            &s,
            WorldwideDay::new(7),
            &[
                (owners[0], U256::from(100u64)),
                (owners[1], U256::from(100u64)),
            ],
        )
        .unwrap();
        outbe_intex::api::arm_proceeds(&s, WorldwideDay::new(7), &[10, 20], DEADLINE_FUTURE)
            .unwrap();

        // Only chain 10 arrives before the deadline.
        s.increase_balance(INTEX_FACTORY_ADDRESS, U256::from(200u64))
            .unwrap();
        runtime::distribute(
            &s,
            crate::constants::ORIGIN_ROUTER_ADDRESS,
            7.into(),
            10,
            U256::from(200u64),
        )
        .unwrap();
        assert_eq!(outbe_intex::api::active_dist_count(&s).unwrap(), 0);

        // Past the deadline the sweep pays out what arrived; the map is retained.
        runtime::try_settle_proceeds(&s, WorldwideDay::new(7), DEADLINE_FUTURE + 1).unwrap();
        assert!(!outbe_intex::api::proceeds_finalize_on_done(&s, WorldwideDay::new(7)).unwrap());
        runtime::drain_distributions(&s).unwrap();
        assert_eq!(s.balance(owners[0]).unwrap(), U256::from(100u64));
        assert_eq!(s.balance(owners[1]).unwrap(), U256::from(100u64));
        assert_eq!(
            outbe_intex::api::contributor_count(&s, WorldwideDay::new(7)).unwrap(),
            2
        ); // retained

        // The straggler arrives: a supplementary payout over the same map, then finalize.
        s.increase_balance(INTEX_FACTORY_ADDRESS, U256::from(400u64))
            .unwrap();
        runtime::distribute(
            &s,
            crate::constants::ORIGIN_ROUTER_ADDRESS,
            7.into(),
            20,
            U256::from(400u64),
        )
        .unwrap();
        assert_eq!(outbe_intex::api::active_dist_count(&s).unwrap(), 1);
        runtime::drain_distributions(&s).unwrap();
        assert_eq!(s.balance(owners[0]).unwrap(), U256::from(300u64)); // +200
        assert_eq!(s.balance(owners[1]).unwrap(), U256::from(300u64));
        assert_eq!(
            outbe_intex::api::contributor_count(&s, WorldwideDay::new(7)).unwrap(),
            0
        ); // finalized
    });
}

#[test]
fn late_top_up_during_final_round_reaches_creators() {
    use outbe_primitives::addresses::VAULT_ROUTER_ADDRESS;
    with_factory(|s| {
        let owners = [contrib(1), contrib(2)];
        outbe_intex::api::record_contributors(
            &s,
            WorldwideDay::new(7),
            &[
                (owners[0], U256::from(100u64)),
                (owners[1], U256::from(100u64)),
            ],
        )
        .unwrap();
        // A single winning chain: the first arrival completes the fan-in, so the
        // round runs finalize-on-done (its end clears the contributor map).
        outbe_intex::api::arm_proceeds(&s, WorldwideDay::new(7), &[10], DEADLINE_FUTURE).unwrap();
        s.increase_balance(INTEX_FACTORY_ADDRESS, U256::from(200u64))
            .unwrap();
        runtime::distribute(
            &s,
            crate::constants::ORIGIN_ROUTER_ADDRESS,
            7.into(),
            10,
            U256::from(200u64),
        )
        .unwrap();
        assert!(outbe_intex::api::proceeds_finalize_on_done(&s, WorldwideDay::new(7)).unwrap());

        // Pay only the first contributor: the round is mid-drain, still active.
        runtime::pay_chunk(&s, WorldwideDay::new(7), 1).unwrap();
        assert_eq!(s.balance(owners[0]).unwrap(), U256::from(100u64));
        assert_eq!(outbe_intex::api::active_dist_count(&s).unwrap(), 1);

        // Chain 10 sends the rest of its proceeds while the round still drains: it
        // only tops the pot up (an in-flight round is never overlapped).
        s.increase_balance(INTEX_FACTORY_ADDRESS, U256::from(400u64))
            .unwrap();
        runtime::distribute(
            &s,
            crate::constants::ORIGIN_ROUTER_ADDRESS,
            7.into(),
            10,
            U256::from(400u64),
        )
        .unwrap();
        assert_eq!(outbe_intex::api::active_dist_count(&s).unwrap(), 1);

        // Finishing the round finds the topped-up pot and opens a supplementary
        // round over the same map instead of finalizing (which would strand it).
        runtime::pay_chunk(&s, WorldwideDay::new(7), 1).unwrap();
        assert_eq!(s.balance(owners[1]).unwrap(), U256::from(100u64));
        assert_eq!(
            outbe_intex::api::contributor_count(&s, WorldwideDay::new(7)).unwrap(),
            2
        ); // retained
        assert_eq!(outbe_intex::api::active_dist_count(&s).unwrap(), 1);

        // The supplementary round pays the top-up to the creators, then finalizes.
        runtime::drain_distributions(&s).unwrap();
        assert_eq!(s.balance(owners[0]).unwrap(), U256::from(300u64)); // +200
        assert_eq!(s.balance(owners[1]).unwrap(), U256::from(300u64)); // +200
        assert_eq!(
            outbe_intex::api::contributor_count(&s, WorldwideDay::new(7)).unwrap(),
            0
        ); // finalized
           // The money reached creators, never the vault or the burn path.
        assert_eq!(s.balance(VAULT_ROUTER_ADDRESS).unwrap(), U256::ZERO);
        assert_eq!(s.balance(INTEX_FACTORY_ADDRESS).unwrap(), U256::ZERO);
    });
}

#[test]
fn distribute_paginates_across_chunks() {
    with_factory(|s| {
        let owners = [contrib(1), contrib(2), contrib(3)];
        outbe_intex::api::record_contributors(
            &s,
            WorldwideDay::new(7),
            &[
                (owners[0], U256::from(100u64)),
                (owners[1], U256::from(200u64)),
                (owners[2], U256::from(300u64)),
            ],
        )
        .unwrap();
        let amount = U256::from(600u64);
        s.increase_balance(INTEX_FACTORY_ADDRESS, amount).unwrap();
        outbe_intex::api::start_distribution(&s, WorldwideDay::new(7), amount, U256::from(600u64))
            .unwrap();

        // Chunk 1 (limit 2): pays the first two, cursor advances, still active.
        runtime::pay_chunk(&s, WorldwideDay::new(7), 2).unwrap();
        assert_eq!(s.balance(owners[0]).unwrap(), U256::from(100u64));
        assert_eq!(s.balance(owners[1]).unwrap(), U256::from(200u64));
        assert_eq!(s.balance(owners[2]).unwrap(), U256::ZERO);
        assert_eq!(
            outbe_intex::api::get_progress(&s, WorldwideDay::new(7))
                .unwrap()
                .unwrap()
                .cursor,
            2
        );
        assert_eq!(outbe_intex::api::active_dist_count(&s).unwrap(), 1);

        // Chunk 2: pays the last and finalizes.
        runtime::pay_chunk(&s, WorldwideDay::new(7), 2).unwrap();
        assert_eq!(s.balance(owners[2]).unwrap(), U256::from(300u64));
        assert_eq!(s.balance(INTEX_FACTORY_ADDRESS).unwrap(), U256::ZERO);
        assert_eq!(
            outbe_intex::api::get_progress(&s, WorldwideDay::new(7)).unwrap(),
            None
        );
        assert_eq!(outbe_intex::api::active_dist_count(&s).unwrap(), 0);
    });
}

#[test]
fn distribute_rejects_non_origin_router() {
    with_factory(|s| {
        outbe_intex::api::record_contributors(
            &s,
            WorldwideDay::new(7),
            &[(contrib(1), U256::from(100u64))],
        )
        .unwrap();
        s.increase_balance(INTEX_FACTORY_ADDRESS, U256::from(100u64))
            .unwrap();
        let err = runtime::distribute(&s, holder(), 7.into(), 10, U256::from(100u64)).unwrap_err();
        assert!(err.to_string().to_lowercase().contains("origin router"));
    });
}

#[test]
fn distribute_no_contributors_burns() {
    use alloy_sol_types::SolEvent;
    use outbe_primitives::addresses::VAULT_ROUTER_ADDRESS;

    let mut storage = HashMapStorageProvider::new(CHAIN_ID);
    storage.set_timestamp(U256::from(ISSUED_AT as u64));
    storage.stub_sub_call_at(
        crate::constants::INTEX_NFT1155_ADDRESS,
        alloy_primitives::Bytes::from(vec![0u8; 32]),
    );
    storage.stub_sub_call_at(
        crate::constants::ORIGIN_ROUTER_ADDRESS,
        alloy_primitives::Bytes::from(vec![0u8; 32]),
    );

    StorageHandle::enter(&mut storage, |s| {
        // Armed but no contributors recorded; the single chain completes the fan-in.
        outbe_intex::api::arm_proceeds(&s, WorldwideDay::new(7), &[10], DEADLINE_FUTURE).unwrap();
        s.increase_balance(INTEX_FACTORY_ADDRESS, U256::from(100u64))
            .unwrap();
        runtime::distribute(
            &s,
            crate::constants::ORIGIN_ROUTER_ADDRESS,
            7.into(),
            10,
            U256::from(100u64),
        )
        .unwrap();

        // A day without contributor authority holds its pot until the window
        // closes, in case a certified root is still landing.
        assert_eq!(
            s.balance(INTEX_FACTORY_ADDRESS).unwrap(),
            U256::from(100u64)
        );
        runtime::sweep_proceeds_deadlines(&s, DEADLINE_FUTURE).unwrap();

        // No distribution opened; the ownerless proceeds were destroyed, not vaulted.
        assert_eq!(outbe_intex::api::active_dist_count(&s).unwrap(), 0);
        assert_eq!(s.balance(VAULT_ROUTER_ADDRESS).unwrap(), U256::ZERO);
        assert_eq!(s.balance(INTEX_FACTORY_ADDRESS).unwrap(), U256::ZERO);
    });

    let sig = IIntexFactory::ProceedsBurned::SIGNATURE_HASH;
    let found = storage.get_events(INTEX_FACTORY_ADDRESS).iter().any(|log| {
        log.topics().first() == Some(&sig)
            && IIntexFactory::ProceedsBurned::decode_log_data(log)
                .map(|ev| ev.worldwideDay == 7 && ev.amount == U256::from(100u64))
                .unwrap_or(false)
    });
    assert!(found, "expected ProceedsBurned event");
}

#[test]
fn begin_block_drain_completes_active_distributions() {
    with_factory(|s| {
        // Two series, each left partially distributed (1 of 3 contributors paid).
        for (sid, owners) in [
            (7u32, [contrib(1), contrib(2), contrib(3)]),
            (9u32, [contrib(4), contrib(5), contrib(6)]),
        ] {
            outbe_intex::api::record_contributors(
                &s,
                WorldwideDay::new(sid),
                &[
                    (owners[0], U256::from(100u64)),
                    (owners[1], U256::from(200u64)),
                    (owners[2], U256::from(300u64)),
                ],
            )
            .unwrap();
            s.increase_balance(INTEX_FACTORY_ADDRESS, U256::from(600u64))
                .unwrap();
            outbe_intex::api::start_distribution(
                &s,
                WorldwideDay::new(sid),
                U256::from(600u64),
                U256::from(600u64),
            )
            .unwrap();
            // Pay only the first contributor, leaving the series active.
            runtime::pay_chunk(&s, WorldwideDay::new(sid), 1).unwrap();
        }
        assert_eq!(outbe_intex::api::active_dist_count(&s).unwrap(), 2);

        // One begin-block drain finishes both (3 <= DIST_CHUNK_LIMIT).
        runtime::drain_distributions(&s).unwrap();

        assert_eq!(outbe_intex::api::active_dist_count(&s).unwrap(), 0);
        assert_eq!(s.balance(INTEX_FACTORY_ADDRESS).unwrap(), U256::ZERO);
        // series 7 fully paid
        assert_eq!(s.balance(contrib(1)).unwrap(), U256::from(100u64));
        assert_eq!(s.balance(contrib(2)).unwrap(), U256::from(200u64));
        assert_eq!(s.balance(contrib(3)).unwrap(), U256::from(300u64));
        // series 9 fully paid
        assert_eq!(s.balance(contrib(4)).unwrap(), U256::from(100u64));
        assert_eq!(s.balance(contrib(5)).unwrap(), U256::from(200u64));
        assert_eq!(s.balance(contrib(6)).unwrap(), U256::from(300u64));
    });
}

#[test]
fn begin_block_drain_isolates_failing_series() {
    with_factory(|s| {
        outbe_intex::api::record_contributors(
            &s,
            WorldwideDay::new(7),
            &[(contrib(1), U256::from(100u64))],
        )
        .unwrap();
        s.increase_balance(INTEX_FACTORY_ADDRESS, U256::from(100u64))
            .unwrap();
        outbe_intex::api::start_distribution(
            &s,
            WorldwideDay::new(7),
            U256::from(100u64),
            U256::from(100u64),
        )
        .unwrap();

        // Series 9 is unfunded: its first transfer fails mid-chunk.
        outbe_intex::api::record_contributors(
            &s,
            WorldwideDay::new(9),
            &[
                (contrib(2), U256::from(100u64)),
                (contrib(3), U256::from(500u64)),
            ],
        )
        .unwrap();
        outbe_intex::api::start_distribution(
            &s,
            WorldwideDay::new(9),
            U256::from(600u64),
            U256::from(600u64),
        )
        .unwrap();

        // The drain must not error: the failing series is skipped and rolled back.
        runtime::drain_distributions(&s).unwrap();

        assert_eq!(s.balance(contrib(1)).unwrap(), U256::from(100u64));
        assert_eq!(outbe_intex::api::active_dist_count(&s).unwrap(), 1);
        let p = outbe_intex::api::get_progress(&s, WorldwideDay::new(9))
            .unwrap()
            .unwrap();
        assert_eq!(p.cursor, 0);
        assert_eq!(p.paid_so_far, U256::ZERO);
        assert_eq!(s.balance(contrib(2)).unwrap(), U256::ZERO);
    });
}

/// IntexFactory is a payable route, so the boundary credits value to its
/// address. Its dispatch must refuse value for every selector outside
/// `PAYABLE_SELECTORS`, or a funded call to a non-payable selector would strand
/// native value at an address with no accounting entry for it.
///
/// Characterization: the per-arm checks this replaced already covered these two
/// selectors with the same message, so the test pins current behavior rather
/// than proving a fix. Its value is catching a future removal of the guard.
#[test]
fn unpublished_selectors_refuse_native_value() {
    use crate::precompile::{dispatch, IIntexFactory};

    let calls = [
        IIntexFactory::settleCall {
            seriesId: Default::default(),
            intexHolder: Address::ZERO,
            amount: U256::ZERO,
            payNoteProof: Default::default(),
        }
        .abi_encode(),
        IIntexFactory::setAuthorizedSettlerCall {
            seriesId: Default::default(),
            settler: Address::ZERO,
        }
        .abi_encode(),
    ];

    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        for data in &calls {
            let funded = dispatch(storage.clone(), data, Address::ZERO, U256::from(1u64));
            assert!(
                matches!(
                    funded,
                    Err(outbe_primitives::error::PrecompileError::Revert(ref message))
                        if message == "non-payable function called with value"
                ),
                "unpublished selector must refuse value, got {funded:?}"
            );
        }
    });
}

/// `distribute` is the one published payable selector here, and it credits
/// auction proceeds straight from `msg.value`. The route table only decides that
/// this *address* may be credited; nothing in it proves the dispatch actually
/// hands the value to the handler. This does: the handler rejects a zero amount,
/// so the two outcomes separate exactly on whether the value arrived.
#[test]
fn distribute_receives_the_call_value() {
    use alloy_sol_types::SolCall;

    use crate::constants::ORIGIN_ROUTER_ADDRESS;
    use crate::precompile::{dispatch, IIntexFactory};

    let data = IIntexFactory::distributeCall {
        worldwideDay: 7u32,
        srcChainId: 10u32,
    }
    .abi_encode();

    let mut provider = HashMapStorageProvider::new(1);
    StorageHandle::enter(&mut provider, |storage| {
        let unfunded = dispatch(storage.clone(), &data, ORIGIN_ROUTER_ADDRESS, U256::ZERO);
        assert!(
            matches!(
                unfunded,
                Err(outbe_primitives::error::PrecompileError::Revert(ref message))
                    if message == "amount must be positive"
            ),
            "a zero-value distribute must reach the handler with nothing, got {unfunded:?}"
        );

        let funded = dispatch(
            storage.clone(),
            &data,
            ORIGIN_ROUTER_ADDRESS,
            U256::from(1_000u64),
        );
        assert!(
            !matches!(
                funded,
                Err(outbe_primitives::error::PrecompileError::Revert(ref message))
                    if message == "amount must be positive"
            ),
            "a funded distribute must reach the handler with the value, got {funded:?}"
        );
    });
}

// --- Certified contributor payout (OCOMP authority) ---

use outbe_intex::payout::test_support::{
    contributor_leaf, contributor_range_proof, contributor_root, metadata_word,
};
use outbe_intex::payout::ContributorLeafData;

use crate::constants::ORIGIN_ROUTER_ADDRESS;

const WWD: u32 = 20_260_725;
const CHAIN: u32 = 10;
fn population(count: u32) -> Vec<ContributorLeafData> {
    (0..count)
        .map(|i| contributor_leaf(i, u64::from(i) + 1))
        .collect()
}

fn nominal_total(leaves: &[ContributorLeafData]) -> U256 {
    leaves
        .iter()
        .fold(U256::ZERO, |acc, leaf| acc + leaf.nominal)
}

/// Writes the constant-size authority that OCOMP activation installs.
fn install_generation(storage: &StorageHandle<'_>, leaves: &[ContributorLeafData]) {
    install_generation_with_total(storage, leaves, nominal_total(leaves));
}

fn install_generation_with_total(
    storage: &StorageHandle<'_>,
    leaves: &[ContributorLeafData],
    eligible_nominal_total: U256,
) {
    let count = u32::try_from(leaves.len()).expect("count fits u32");
    let registry = outbe_intex::IntexContract::new(storage.clone());
    registry
        .ocomp_contributor_root
        .write(
            &outbe_primitives::time::WorldwideDay::new(WWD),
            contributor_root(leaves),
        )
        .unwrap();
    registry
        .ocomp_eligible_nominal_total
        .write(
            &outbe_primitives::time::WorldwideDay::new(WWD),
            eligible_nominal_total,
        )
        .unwrap();
    registry
        .ocomp_contributor_metadata
        .write(
            &outbe_primitives::time::WorldwideDay::new(WWD),
            metadata_word(1, count),
        )
        .unwrap();
}

/// Installs an empty certified generation (a day whose contributors were all
/// excluded), which has a root but no payable leaves.
fn install_empty_generation(storage: &StorageHandle<'_>) {
    let registry = outbe_intex::IntexContract::new(storage.clone());
    registry
        .ocomp_contributor_root
        .write(
            &outbe_primitives::time::WorldwideDay::new(WWD),
            contributor_root(&[]),
        )
        .unwrap();
    registry
        .ocomp_eligible_nominal_total
        .write(&outbe_primitives::time::WorldwideDay::new(WWD), U256::ZERO)
        .unwrap();
    registry
        .ocomp_contributor_metadata
        .write(
            &outbe_primitives::time::WorldwideDay::new(WWD),
            metadata_word(1, 0),
        )
        .unwrap();
}

fn abi_leaves(leaves: &[ContributorLeafData]) -> Vec<IIntexFactory::ContributorLeaf> {
    leaves
        .iter()
        .map(|leaf| IIntexFactory::ContributorLeaf {
            owner: leaf.owner,
            sourceTributeId: leaf.source_tribute_id,
            nominal: leaf.nominal,
        })
        .collect()
}

/// Arms the fan-in and delivers the whole pot from one winning chain.
fn deliver_proceeds(storage: &StorageHandle<'_>, amount: U256) {
    outbe_intex::api::arm_proceeds(
        storage,
        outbe_primitives::time::WorldwideDay::new(WWD),
        &[CHAIN],
        DEADLINE_FUTURE,
    )
    .unwrap();
    storage
        .increase_balance(INTEX_FACTORY_ADDRESS, amount)
        .unwrap();
    runtime::distribute(storage, ORIGIN_ROUTER_ADDRESS, WWD.into(), CHAIN, amount).unwrap();
}

#[test]
fn certified_day_opens_a_payout_round_instead_of_burning_the_pot() {
    with_factory(|s| {
        let leaves = population(300);
        install_generation(&s, &leaves);
        let amount = U256::from(1_000u64);

        deliver_proceeds(&s, amount);

        let round = outbe_intex::api::certified_payout_round(&s, WWD)
            .unwrap()
            .expect("certified day must open a payout round");
        assert_eq!(round.amount, amount);
        // The pot stays on the precompile until batches draw it down; the legacy
        // cursor path must not have claimed the day.
        assert_eq!(s.balance(INTEX_FACTORY_ADDRESS).unwrap(), amount);
        assert_eq!(outbe_intex::api::active_dist_count(&s).unwrap(), 0);
    });
}

#[test]
fn batches_pay_every_certified_contributor() {
    with_factory(|s| {
        let leaves = population(300);
        install_generation(&s, &leaves);
        let amount = U256::from(1_000_000u64);
        deliver_proceeds(&s, amount);

        for (start, len) in [(0_u32, 256_u32), (256, 44)] {
            runtime::pay_contributor_batch(
                &s,
                WWD,
                start,
                &abi_leaves(&leaves[start as usize..(start + len) as usize]),
                &contributor_range_proof(&leaves, start),
            )
            .unwrap_or_else(|e| panic!("batch at {start} must pay: {e:?}"));
        }

        let total = nominal_total(&leaves);
        for leaf in &leaves {
            let expected = amount * leaf.nominal / total;
            assert_eq!(
                s.balance(leaf.owner).unwrap(),
                expected,
                "owner {:?} share",
                leaf.owner
            );
        }

        let round = outbe_intex::api::certified_payout_round(&s, WWD)
            .unwrap()
            .unwrap();
        assert_eq!(round.paid_leaf_count, 300);
        // The last batch closed the round and burned what floor division left,
        // so nothing of this day remains on the precompile.
        assert!(round.paid_so_far < amount, "floor shares must fall short");
        assert_eq!(s.balance(INTEX_FACTORY_ADDRESS).unwrap(), U256::ZERO);
    });
}

#[test]
fn an_unfinished_round_keeps_the_outstanding_shares() {
    with_factory(|s| {
        let leaves = population(300);
        install_generation(&s, &leaves);
        let amount = U256::from(1_000_000u64);
        deliver_proceeds(&s, amount);

        // Only the first chunk is paid: the balance still owes the tail its
        // shares, so nothing may be burned yet.
        runtime::pay_contributor_batch(
            &s,
            WWD,
            0,
            &abi_leaves(&leaves[0..256]),
            &contributor_range_proof(&leaves, 0),
        )
        .unwrap();

        let round = outbe_intex::api::certified_payout_round(&s, WWD)
            .unwrap()
            .unwrap();
        assert_eq!(round.paid_leaf_count, 256);
        assert_eq!(
            s.balance(INTEX_FACTORY_ADDRESS).unwrap(),
            amount - round.paid_so_far
        );
    });
}

#[test]
fn proceeds_arriving_after_the_round_opened_are_burned() {
    with_factory(|s| {
        let leaves = population(300);
        install_generation(&s, &leaves);
        let amount = U256::from(1_000u64);
        deliver_proceeds(&s, amount);

        // A second chain finally delivers, long after the fan-in window closed.
        let late = U256::from(400u64);
        s.increase_balance(INTEX_FACTORY_ADDRESS, late).unwrap();
        runtime::distribute(&s, ORIGIN_ROUTER_ADDRESS, WWD.into(), CHAIN + 1, late).unwrap();

        // The round still distributes only what it froze, and the late delivery
        // is destroyed rather than left on the balance.
        let round = outbe_intex::api::certified_payout_round(&s, WWD)
            .unwrap()
            .unwrap();
        assert_eq!(round.amount, amount);
        assert_eq!(s.balance(INTEX_FACTORY_ADDRESS).unwrap(), amount);
    });
}

#[test]
fn an_understated_nominal_total_cannot_spend_another_days_proceeds() {
    with_factory(|s| {
        let leaves = population(300);
        // The certified total is off-chain input and is never reconciled against
        // the leaves under the root, so a halved one inflates every share.
        install_generation_with_total(&s, &leaves, nominal_total(&leaves) / U256::from(2u64));
        let amount = U256::from(100_000u64);
        deliver_proceeds(&s, amount);

        // Another day's money sits on the same balance and must stay there.
        let other_day = U256::from(1_000_000u64);
        s.increase_balance(INTEX_FACTORY_ADDRESS, other_day)
            .unwrap();

        let err = runtime::pay_contributor_batch(
            &s,
            WWD,
            0,
            &abi_leaves(&leaves[0..256]),
            &contributor_range_proof(&leaves, 0),
        )
        .unwrap_err();

        assert!(
            format!("{err:?}").contains("exceed the round amount"),
            "{err:?}"
        );
        assert_eq!(s.balance(leaves[0].owner).unwrap(), U256::ZERO);
        assert_eq!(
            s.balance(INTEX_FACTORY_ADDRESS).unwrap(),
            amount + other_day
        );
    });
}

#[test]
fn paying_the_same_batch_twice_reverts_before_verification() {
    with_factory(|s| {
        let leaves = population(300);
        install_generation(&s, &leaves);
        deliver_proceeds(&s, U256::from(1_000_000u64));

        let batch = abi_leaves(&leaves[0..256]);
        let proof = contributor_range_proof(&leaves, 0);
        runtime::pay_contributor_batch(&s, WWD, 0, &batch, &proof).unwrap();
        let paid_once = s.balance(leaves[0].owner).unwrap();

        // A garbage proof proves the bitmap gate runs first: the batch is
        // rejected as already paid, never as a bad proof.
        let err = runtime::pay_contributor_batch(&s, WWD, 0, &batch, &[B256::ZERO; 2]).unwrap_err();
        assert!(format!("{err:?}").contains("already paid"), "{err:?}");
        assert_eq!(s.balance(leaves[0].owner).unwrap(), paid_once);
    });
}

#[test]
fn batch_without_an_open_round_is_rejected() {
    with_factory(|s| {
        let leaves = population(300);
        install_generation(&s, &leaves);

        let err = runtime::pay_contributor_batch(
            &s,
            WWD,
            0,
            &abi_leaves(&leaves[0..256]),
            &contributor_range_proof(&leaves, 0),
        )
        .unwrap_err();
        assert!(format!("{err:?}").contains("no open certified"), "{err:?}");
    });
}

#[test]
fn certified_day_without_contributors_burns_the_pot() {
    with_factory(|s| {
        install_empty_generation(&s);
        deliver_proceeds(&s, U256::from(1_000u64));

        assert!(outbe_intex::api::certified_payout_round(&s, WWD)
            .unwrap()
            .is_none());
        assert_eq!(s.balance(INTEX_FACTORY_ADDRESS).unwrap(), U256::ZERO);
    });
}

#[test]
fn day_without_contributor_authority_holds_the_pot_until_the_deadline() {
    with_factory(|s| {
        let amount = U256::from(1_000u64);
        // Fan-in completes immediately, but no root has landed yet.
        deliver_proceeds(&s, amount);

        // Nothing is burned while the window is still open.
        assert_eq!(s.balance(INTEX_FACTORY_ADDRESS).unwrap(), amount);
        assert!(outbe_intex::api::certified_payout_round(&s, WWD)
            .unwrap()
            .is_none());

        // The root arrives late; the preserved pot now funds the round.
        let leaves = population(300);
        install_generation(&s, &leaves);
        runtime::try_settle_proceeds(
            &s,
            outbe_primitives::time::WorldwideDay::new(WWD),
            DEADLINE_FUTURE - 1,
        )
        .unwrap();

        let round = outbe_intex::api::certified_payout_round(&s, WWD)
            .unwrap()
            .expect("late root must still open a round");
        assert_eq!(round.amount, amount);
    });
}

#[test]
fn legacy_day_keeps_using_the_cursor_path() {
    with_factory(|s| {
        let owners = [contrib(1), contrib(2)];
        outbe_intex::api::record_contributors(
            &s,
            outbe_primitives::time::WorldwideDay::new(WWD),
            &[
                (owners[0], U256::from(100u64)),
                (owners[1], U256::from(100u64)),
            ],
        )
        .unwrap();
        deliver_proceeds(&s, U256::from(1_000u64));

        // Legacy authority opens a paginated distribution, not a certified round.
        assert!(outbe_intex::api::certified_payout_round(&s, WWD)
            .unwrap()
            .is_none());
        assert_eq!(outbe_intex::api::active_dist_count(&s).unwrap(), 1);

        runtime::drain_distributions(&s).unwrap();
        assert_eq!(s.balance(owners[0]).unwrap(), U256::from(500u64));
        assert_eq!(s.balance(owners[1]).unwrap(), U256::from(500u64));
    });
}

#[test]
fn a_corrupt_total_reverts_cleanly_before_any_transfer() {
    with_factory(|s| {
        let leaves = population(300);
        install_generation_with_total(&s, &leaves, U256::from(1u64));
        let amount = U256::from(100_000u64);
        deliver_proceeds(&s, amount);

        let err = runtime::pay_contributor_batch(
            &s,
            WWD,
            0,
            &abi_leaves(&leaves[0..256]),
            &contributor_range_proof(&leaves, 0),
        )
        .unwrap_err();

        // The inflated batch dwarfs the whole factory balance: the cap must
        // reject it as a clean revert before the first transfer, never as an
        // insufficient-balance Fatal mid-batch.
        assert!(
            format!("{err:?}").contains("exceed the round amount"),
            "{err:?}"
        );
        assert_eq!(s.balance(leaves[0].owner).unwrap(), U256::ZERO);
        assert_eq!(s.balance(INTEX_FACTORY_ADDRESS).unwrap(), amount);
    });
}

#[test]
fn late_proceeds_after_an_ownerless_certified_day_burn() {
    with_factory(|s| {
        let registry = outbe_intex::IntexContract::new(s.clone());
        registry
            .ocomp_contributor_root
            .write(
                &outbe_primitives::time::WorldwideDay::new(WWD),
                B256::repeat_byte(1),
            )
            .unwrap();
        registry
            .ocomp_contributor_metadata
            .write(
                &outbe_primitives::time::WorldwideDay::new(WWD),
                metadata_word(1, 0),
            )
            .unwrap();
        deliver_proceeds(&s, U256::from(500u64));
        assert_eq!(s.balance(INTEX_FACTORY_ADDRESS).unwrap(), U256::ZERO);

        // A duplicate delivery lands after finalization cleared the deadline;
        // it must burn like any other late arrival, not sit on the balance.
        s.increase_balance(INTEX_FACTORY_ADDRESS, U256::from(70u64))
            .unwrap();
        runtime::distribute(
            &s,
            ORIGIN_ROUTER_ADDRESS,
            WWD.into(),
            CHAIN,
            U256::from(70u64),
        )
        .unwrap();
        assert_eq!(s.balance(INTEX_FACTORY_ADDRESS).unwrap(), U256::ZERO);
    });
}

#[test]
fn a_day_no_chain_ever_paid_into_leaves_the_awaiting_set() {
    with_factory(|s| {
        let wwd = WorldwideDay::new(2026_0301);
        // Two winning chains and not one delivery: the fan-in can never complete.
        outbe_intex::api::arm_proceeds(&s, wwd, &[10, 20], DEADLINE_FUTURE).unwrap();
        assert_eq!(outbe_intex::api::awaiting_proceeds_count(&s).unwrap(), 1);

        // Before the deadline the day is still owed its proceeds.
        runtime::sweep_proceeds_deadlines(&s, DEADLINE_FUTURE - 1).unwrap();
        assert_eq!(outbe_intex::api::awaiting_proceeds_count(&s).unwrap(), 1);

        // Past it there is nothing left to wait for, so the day stops being swept.
        runtime::sweep_proceeds_deadlines(&s, DEADLINE_FUTURE + 1).unwrap();
        assert_eq!(outbe_intex::api::awaiting_proceeds_count(&s).unwrap(), 0);
    });
}
