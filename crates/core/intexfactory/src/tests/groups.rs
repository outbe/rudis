mod group_index {
    //! Two-level index: price bins hold `(reference currency, worldwide day)`
    //! groups, and each group holds its series.

    use alloy_primitives::U256;
    use outbe_intex::SeriesId;
    use outbe_primitives::storage::hashmap::HashMapStorageProvider;
    use outbe_primitives::storage::StorageHandle;
    use outbe_primitives::time::WorldwideDay;

    use crate::schema::IntexFactoryContract;

    const CHAIN_ID: u64 = 1;
    const ISO: u16 = 840;
    const FLOOR: u64 = 2_000;

    fn with_factory<R>(f: impl FnOnce(StorageHandle) -> R) -> R {
        let mut storage = HashMapStorageProvider::new(CHAIN_ID);
        StorageHandle::enter(&mut storage, |handle| {
            crate::tests::select_prod_profile(&handle);
            f(handle)
        })
    }

    /// Same day, differing only in issuance currency - the members of one group.
    fn sid(worldwide_day: u32, issuance: &[u8; 3]) -> SeriesId {
        SeriesId::pack(WorldwideDay::new(worldwide_day), *issuance, b'U').unwrap()
    }

    fn bin_count(f: &IntexFactoryContract<'_>, bin: u32) -> u32 {
        f.unqualified_bin_count
            .read(&IntexFactoryContract::scoped(ISO, bin))
            .unwrap()
    }

    fn floor_bin() -> u32 {
        IntexFactoryContract::price_to_bin(U256::from(FLOOR)).unwrap()
    }

    #[test]
    fn members_of_one_day_share_a_single_bin_entry() {
        with_factory(|s| {
            let mut f = IntexFactoryContract::new(s.clone());
            let floor = U256::from(FLOOR);
            f.insert_unqualified(sid(20260212, b"USD"), ISO, floor)
                .unwrap();
            f.insert_unqualified(sid(20260212, b"EUR"), ISO, floor)
                .unwrap();
            f.insert_unqualified(sid(20260212, b"TRY"), ISO, floor)
                .unwrap();

            // Three series, one group: the bin holds days, not series.
            assert_eq!(bin_count(&f, floor_bin()), 1);
            assert_eq!(
                f.unqualified_group_members(ISO, WorldwideDay::new(20260212))
                    .unwrap(),
                vec![
                    sid(20260212, b"USD"),
                    sid(20260212, b"EUR"),
                    sid(20260212, b"TRY")
                ]
            );
            assert_eq!(
                f.unqualified_groups_in_bin(ISO, floor_bin()).unwrap(),
                vec![WorldwideDay::new(20260212)]
            );
        });
    }

    #[test]
    fn separate_days_are_separate_groups_in_one_bin() {
        with_factory(|s| {
            let mut f = IntexFactoryContract::new(s.clone());
            let floor = U256::from(FLOOR);
            f.insert_unqualified(sid(20260212, b"USD"), ISO, floor)
                .unwrap();
            f.insert_unqualified(sid(20260213, b"USD"), ISO, floor)
                .unwrap();

            assert_eq!(bin_count(&f, floor_bin()), 2);
            assert_eq!(
                f.unqualified_groups_in_bin(ISO, floor_bin()).unwrap(),
                vec![WorldwideDay::new(20260212), WorldwideDay::new(20260213)]
            );
        });
    }

    #[test]
    fn a_member_priced_into_another_bin_is_refused() {
        with_factory(|s| {
            let mut f = IntexFactoryContract::new(s.clone());
            f.insert_unqualified(sid(20260212, b"USD"), ISO, U256::from(FLOOR))
                .unwrap();

            // One decision per group, so a second price for the same day is a split.
            let err = f
                .insert_unqualified(sid(20260212, b"EUR"), ISO, U256::from(FLOOR * 4))
                .unwrap_err();
            assert!(
                err.to_string().contains("indexed in bin"),
                "unexpected error: {err}"
            );
        });
    }

    #[test]
    fn removing_the_group_clears_its_members_and_its_bin() {
        with_factory(|s| {
            let mut f = IntexFactoryContract::new(s.clone());
            let floor = U256::from(FLOOR);
            f.insert_unqualified(sid(20260212, b"USD"), ISO, floor)
                .unwrap();
            f.insert_unqualified(sid(20260212, b"EUR"), ISO, floor)
                .unwrap();
            f.insert_unqualified(sid(20260213, b"USD"), ISO, floor)
                .unwrap();

            f.remove_unqualified_group(ISO, WorldwideDay::new(20260212))
                .unwrap();

            // Swap-and-pop keeps the untouched day reachable.
            assert_eq!(bin_count(&f, floor_bin()), 1);
            assert_eq!(
                f.unqualified_groups_in_bin(ISO, floor_bin()).unwrap(),
                vec![WorldwideDay::new(20260213)]
            );
            assert!(f
                .unqualified_group_members(ISO, WorldwideDay::new(20260212))
                .unwrap()
                .is_empty());

            f.remove_unqualified_group(ISO, WorldwideDay::new(20260213))
                .unwrap();
            assert_eq!(bin_count(&f, floor_bin()), 0);
            assert!(f
                .unqualified_groups_in_bin(ISO, floor_bin())
                .unwrap()
                .is_empty());
        });
    }

    #[test]
    fn removing_an_unindexed_group_is_a_no_op() {
        with_factory(|s| {
            let mut f = IntexFactoryContract::new(s.clone());
            f.insert_unqualified(sid(20260212, b"USD"), ISO, U256::from(FLOOR))
                .unwrap();

            f.remove_unqualified_group(ISO, WorldwideDay::new(20260213))
                .unwrap();

            assert_eq!(bin_count(&f, floor_bin()), 1);
            assert_eq!(
                f.unqualified_group_members(ISO, WorldwideDay::new(20260212))
                    .unwrap(),
                vec![sid(20260212, b"USD")]
            );
        });
    }

    #[test]
    fn indexing_a_group_twice_is_refused() {
        with_factory(|s| {
            let mut f = IntexFactoryContract::new(s.clone());
            let day = WorldwideDay::new(20260212);
            let trigger = U256::from(FLOOR);
            f.insert_qualified_group(ISO, day, trigger, &[sid(20260212, b"USD")])
                .unwrap();

            let err = f
                .insert_qualified_group(ISO, day, trigger, &[sid(20260212, b"EUR")])
                .unwrap_err();
            assert!(
                err.to_string().contains("already indexed"),
                "unexpected error: {err}"
            );
        });
    }

    #[test]
    fn the_two_indexes_and_the_currencies_stay_apart() {
        with_factory(|s| {
            let mut f = IntexFactoryContract::new(s.clone());
            let floor = U256::from(FLOOR);
            let series = sid(20260212, b"USD");
            f.insert_unqualified(series, ISO, floor).unwrap();
            f.insert_qualified_group(ISO, WorldwideDay::new(20260212), floor, &[series])
                .unwrap();
            f.insert_unqualified(series, 978, floor).unwrap();

            f.remove_unqualified_group(ISO, WorldwideDay::new(20260212))
                .unwrap();

            assert_eq!(bin_count(&f, floor_bin()), 0);
            assert_eq!(
                f.qualified_group_members(ISO, WorldwideDay::new(20260212))
                    .unwrap(),
                vec![series]
            );
            assert_eq!(
                f.unqualified_group_members(978, WorldwideDay::new(20260212))
                    .unwrap(),
                vec![series]
            );
        });
    }
}

mod group_scans {
    //! Group transitions: one day in one reference currency decides once and moves
    //! all of its series together.

    use alloy_primitives::U256;
    use outbe_intex::{IntexState, SeriesId};
    use outbe_primitives::storage::hashmap::HashMapStorageProvider;
    use outbe_primitives::storage::StorageHandle;
    use outbe_primitives::time::WorldwideDay;

    use crate::constants::MAX_SERIES_ACTIONS_PER_BLOCK;
    use crate::qualified::{self, ScanBudget};
    use crate::runtime;
    use crate::schema::{IntexFactoryContract, IssuanceParams};
    use crate::state::Group;

    const CHAIN_ID: u64 = 1;
    const REFERENCE_ISO: u16 = 840;
    const ISSUED_AT: u32 = 1_700_000_000;
    const ENTRY_PRICE: u64 = 1_000_000;
    const EXPECTED_FLOOR: u64 = 1_080_000;
    const WWD: u32 = 20260212;

    /// Issuance currencies of one day's series; they share every decision input.
    const ISSUANCES: [u16; 3] = [840, 978, 392];

    fn with_factory<R>(f: impl FnOnce(StorageHandle) -> R) -> R {
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
        StorageHandle::enter(&mut storage, |handle| {
            crate::tests::select_prod_profile(&handle);
            f(handle)
        })
    }

    fn day() -> WorldwideDay {
        WorldwideDay::new(WWD)
    }

    fn params(worldwide_day: u32, issuance_currency: u16) -> IssuanceParams {
        IssuanceParams {
            series_id: SeriesId::for_pair(
                WorldwideDay::new(worldwide_day),
                issuance_currency,
                REFERENCE_ISO,
            )
            .unwrap(),
            worldwide_day: worldwide_day.into(),
            issued_intex_count: 100,
            promis_load_minor: 1_000_000_000_000_000_000,
            entry_price_minor: U256::from(ENTRY_PRICE),
            issuance_currency,
            reference_currency: REFERENCE_ISO,
            recipients: vec![],
            quantities: vec![],
            recipient_chains: vec![],
            snapshot_chains: vec![1],
        }
    }

    /// Issue one day's series, one per issuance currency.
    fn issue_day(s: &StorageHandle<'_>, worldwide_day: u32) {
        for issuance in ISSUANCES {
            runtime::issue(s, params(worldwide_day, issuance)).unwrap();
        }
    }

    fn above_floor() -> U256 {
        U256::from(EXPECTED_FLOOR) + U256::from(1)
    }

    fn qualify(
        s: &StorageHandle<'_>,
        f: &mut IntexFactoryContract,
        rate: U256,
    ) -> outbe_primitives::error::Result<u32> {
        let group = f.unqualified_group(REFERENCE_ISO, day())?;
        qualified::try_qualify_group(s, f, &group, rate)
    }

    #[test]
    fn a_days_series_qualify_together() {
        with_factory(|s| {
            issue_day(&s, WWD);
            let mut f = IntexFactoryContract::new(s.clone());
            let members = f.unqualified_group_members(REFERENCE_ISO, day()).unwrap();
            assert_eq!(members.len(), ISSUANCES.len());

            assert_eq!(qualify(&s, &mut f, above_floor()).unwrap(), 3);

            for series_id in &members {
                assert_eq!(
                    outbe_intex::api::read_series(&s, *series_id)
                        .unwrap()
                        .lifecycle_state()
                        .unwrap(),
                    IntexState::Qualified
                );
            }
            // The whole group left the floor index for the call-trigger one.
            assert!(f
                .unqualified_group_members(REFERENCE_ISO, day())
                .unwrap()
                .is_empty());
            assert_eq!(
                f.qualified_group_members(REFERENCE_ISO, day()).unwrap(),
                members
            );
        });
    }

    #[test]
    fn the_floor_gate_holds_for_the_whole_group() {
        with_factory(|s| {
            issue_day(&s, WWD);
            let mut f = IntexFactoryContract::new(s.clone());
            let floor = U256::from(EXPECTED_FLOOR);

            // The rate only reaches the floor (strict >).
            assert_eq!(qualify(&s, &mut f, floor).unwrap(), 0);
            // Past the floor.
            assert_eq!(qualify(&s, &mut f, above_floor()).unwrap(), 3);
            // Latched: the group is gone from the floor index.
            assert_eq!(qualify(&s, &mut f, above_floor()).unwrap(), 0);
        });
    }

    #[test]
    fn a_member_without_a_record_holds_back_only_its_own_group() {
        with_factory(|s| {
            issue_day(&s, WWD);
            let other = WWD + 1;
            issue_day(&s, other);

            let mut f = IntexFactoryContract::new(s.clone());
            // A member the registry never got: the group's transition cannot complete.
            let ghost = SeriesId::for_pair(day(), 124, REFERENCE_ISO).unwrap();
            f.insert_unqualified(ghost, REFERENCE_ISO, U256::from(EXPECTED_FLOOR))
                .unwrap();

            assert!(qualify(&s, &mut f, above_floor()).is_err());

            // The neighbouring day is untouched by it and still qualifies.
            let group = f
                .unqualified_group(REFERENCE_ISO, WorldwideDay::new(other))
                .unwrap();
            assert_eq!(
                qualified::try_qualify_group(&s, &mut f, &group, above_floor()).unwrap(),
                3
            );
        });
    }

    #[test]
    fn an_empty_group_decides_nothing() {
        with_factory(|s| {
            let mut f = IntexFactoryContract::new(s.clone());
            let empty = Group {
                iso_code: REFERENCE_ISO,
                worldwide_day: day(),
                members: Vec::new(),
            };
            assert_eq!(
                qualified::try_qualify_group(&s, &mut f, &empty, above_floor()).unwrap(),
                0
            );
        });
    }

    #[test]
    fn the_budget_takes_groups_whole() {
        let mut budget = ScanBudget::for_qualify();
        assert!(budget.admits_actions(2));
        budget.spend_decision();
        budget.spend_actions(2);

        // What is left still fits a small group.
        assert!(budget.admits_actions(MAX_SERIES_ACTIONS_PER_BLOCK - 2));
        // One series wider than the remainder waits for the next slice.
        assert!(!budget.admits_actions(MAX_SERIES_ACTIONS_PER_BLOCK - 1));

        // A group wider than the whole allowance would stall forever, so an
        // untouched budget takes it on.
        assert!(ScanBudget::for_qualify().admits_actions(MAX_SERIES_ACTIONS_PER_BLOCK + 1));
    }

    #[test]
    fn the_budget_stops_when_either_half_runs_out() {
        let mut budget = ScanBudget::for_qualify();
        budget.spend_actions(MAX_SERIES_ACTIONS_PER_BLOCK);
        assert!(budget.is_spent());
        assert!(!budget.admits_actions(1));

        let mut budget = ScanBudget::for_qualify();
        for _ in 0..crate::constants::MAX_GROUP_DECISIONS_PER_BLOCK {
            budget.spend_decision();
        }
        assert!(
            budget.is_spent(),
            "spent decisions stop the scan between bins"
        );
        // Deciding costs no actions, so a group still fits: what bounds an
        // undecided bin is the boundary check, not this one.
        assert!(budget.admits_actions(1));
    }
}
