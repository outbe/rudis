//! Daily GEMs include canonical late voters, including across UTC midnight.
use alloy_primitives::{Address, Bytes, B256, U256};
use outbe_primitives::{
    block::{BlockContext, BlockRuntimeContext},
    consensus_metadata::{CertifiedParentAccountingMetadata, ParentParticipationProof},
    storage::hashmap::HashMapStorageProvider,
};
use outbe_rewards::{api, finalized_metadata_hook::on_finalized_metadata, late_settlement};

const DAY: u32 = 20240101;
const MIDNIGHT: u64 = 1_704_153_600;
const HASH: B256 = B256::repeat_byte(0x42);
const VOTERS: [Address; 4] = [
    Address::repeat_byte(1),
    Address::repeat_byte(2),
    Address::repeat_byte(3),
    Address::repeat_byte(4),
];

fn block(height: u64) -> BlockContext {
    BlockContext::new(height, MIDNIGHT + height - 11, 1, Address::ZERO, vec![])
}

fn seed(ctx: &BlockRuntimeContext) {
    let genesis = BlockRuntimeContext::new(
        BlockContext::new(0, MIDNIGHT - 86400, 1, Address::ZERO, vec![]),
        ctx.storage.clone(),
    );
    outbe_rewards::runtime::ensure_genesis_anchor(&genesis).unwrap();
    let metadata = CertifiedParentAccountingMetadata {
        finalized_block_number: 10,
        finalized_block_hash: HASH,
        finalized_epoch: 0,
        finalized_view: 10,
        parent_view: 9,
        ordered_committee: VOTERS.to_vec(),
        signer_bitmap: vec![7],
        proof: Bytes::new(),
        committee_set_hash: B256::ZERO,
        vrf_material_version: 0,
        vrf_group_public_key_hash: B256::ZERO,
        proof_kind: ParentParticipationProof::Finalization,
        missed_proposers: vec![],
    };
    // This seam consumes already-verified CPA; cryptographic checks live in EVM.
    on_finalized_metadata(ctx, &metadata, U256::ZERO, MIDNIGHT - 1, &VOTERS[..3]).unwrap();
    outbe_oracle::api::register_pair(ctx.storage.clone(), outbe_oracle::api::DAY_TYPE_PAIR)
        .unwrap();
    outbe_oracle::api::set_exchange_rate(
        ctx.storage.clone(),
        Address::ZERO,
        outbe_oracle::api::DAY_TYPE_PAIR,
        U256::from(1_000_000),
        11,
        MIDNIGHT,
    )
    .unwrap();
    let oracle = outbe_oracle::schema::OracleContract::new(ctx.storage.clone());
    oracle.reference_currencies.push(840).unwrap();
    oracle.utc_day_vwap_last_finalized.write(DAY).unwrap();
}

#[test]
fn midnight_late_vote_survives_reentry_and_mints_equal_gems_once() {
    let mut storage = HashMapStorageProvider::new(1);
    storage.enter(|handle| {
        let ctx = BlockRuntimeContext::new(block(11), handle);
        seed(&ctx);
        assert!(!api::day_participation_complete(&ctx, DAY).unwrap());
        assert!(api::prepare_daily_validator_gem_batch(
            &ctx,
            DAY,
            U256::from(400),
            &api::read_voters_for_day(&ctx, DAY).unwrap()
        )
        .is_err());
        late_settlement::record_late_credit(&ctx, HASH, VOTERS[3], 1).unwrap();
    });
    // Re-enter the same storage provider with new context handles. Day binding
    // and dedup live in contract storage, not context-local bookkeeping. This
    // is an in-memory provider test, not a disk/process restart test.
    storage.enter(|handle| {
        let ctx = BlockRuntimeContext::new(block(13), handle);
        late_settlement::record_late_credit(&ctx, HASH, VOTERS[3], 3).unwrap();
        late_settlement::record_late_credit(&ctx, HASH, VOTERS[0], 2).unwrap();
        assert_eq!(
            api::read_voters_for_day(&ctx, DAY).unwrap(),
            VOTERS.map(|v| (v, 1)).to_vec()
        );
        assert!(api::read_voters_for_day(&ctx, DAY + 1).unwrap().is_empty());
        assert!(!api::day_participation_complete(&ctx, DAY).unwrap());
        late_settlement::settle_matured(&ctx, 13, 3).unwrap();
        assert_eq!(
            ctx.storage
                .contract::<outbe_rewards::schema::Rewards>()
                .pending_reward_day
                .read(&HASH)
                .unwrap(),
            0
        );
        // The guard was pruned, but the settled-window tombstone rejects replay.
        late_settlement::record_late_credit(&ctx, HASH, VOTERS[3], 1).unwrap();
    });
    storage.enter(|handle| {
        let ctx = BlockRuntimeContext::new(block(14), handle);
        assert!(api::day_participation_complete(&ctx, DAY).unwrap());
        let counts = api::read_voters_for_day(&ctx, DAY).unwrap();
        api::prepare_daily_validator_gem_batch(&ctx, DAY, U256::from(400), &counts).unwrap();
        assert!(matches!(
            api::deliver_oldest_reward_gem_batch(&ctx).unwrap(),
            api::RewardGemDeliveryOutcome::Delivered { .. }
        ));
        api::prepare_daily_validator_gem_batch(&ctx, DAY, U256::from(400), &counts).unwrap();
        api::deliver_oldest_reward_gem_batch(&ctx).unwrap();
        let gems = outbe_gem::GemContract::new(ctx.storage.clone());
        for voter in VOTERS {
            assert_eq!(gems.balance_of(voter).unwrap(), 1);
            let id = gems.token_of_owner_by_index(voter, 0).unwrap();
            let gem = outbe_gem::api::get_gem(&ctx.storage, id).unwrap().unwrap();
            assert_eq!(gem.promis_load_minor, U256::from(100));
        }
    });
}

#[test]
fn last_admissible_slot_counts_for_gem_even_when_fee_weight_is_zero() {
    let mut storage = HashMapStorageProvider::new(1);
    storage.enter(|handle| {
        let ctx = BlockRuntimeContext::new(block(13), handle);
        seed(&ctx);
        late_settlement::record_late_credit(&ctx, HASH, VOTERS[3], 3).unwrap();
        assert_eq!(
            api::read_voters_for_day(&ctx, DAY).unwrap(),
            VOTERS.map(|v| (v, 1)).to_vec()
        );
        assert_eq!(outbe_rewards::constants::decay_weight(3), U256::ZERO);
    });
}

#[test]
fn unknown_or_out_of_window_credit_cannot_add_reward_participation() {
    let mut storage = HashMapStorageProvider::new(1);
    storage.enter(|handle| {
        let ctx = BlockRuntimeContext::new(block(11), handle);
        seed(&ctx);
        let before = api::read_voters_for_day(&ctx, DAY).unwrap();
        assert!(
            late_settlement::record_late_credit(&ctx, B256::repeat_byte(0x99), VOTERS[3], 1)
                .is_err()
        );
        assert!(late_settlement::record_late_credit(&ctx, HASH, VOTERS[3], 4).is_err());
        assert_eq!(api::read_voters_for_day(&ctx, DAY).unwrap(), before);
    });
}
