//! Outbe-owned pool maintenance: two-snapshot pending staleness eviction.
//!
//! Incident background (2026-08-22, `outbe-plan/txpool_stuck_tx_livelock_22-08-2026.md`):
//! pending transactions have no lifetime bound in the upstream pool - only the
//! parked subpools age out. A transaction that keeps landing in proposals that
//! fail to finalize is re-injected by the reorg path and re-selected by every
//! payload build, indefinitely. This task bounds pending residency node-locally.
//!
//! Mechanism: on the canonical-state stream, at most once per configured
//! interval (measured in canonical tip block TIMESTAMPS, not wall clock), take
//! a snapshot of the pending-tx hash set. A hash present in two CONSECUTIVE
//! snapshots has been pending for at least one full interval without being
//! mined - evict it (with descendants). Mined or dropped transactions simply
//! vanish from the next snapshot; a re-added transaction starts a fresh cycle.
//! Effective pending TTL is therefore one to two intervals.
//!
//! Eviction is node-local pool policy and never consensus-visible: payload
//! content is proposer-discretionary, and block validation audits only parent
//! binding, beneficiary and system-transaction layout.

use std::collections::HashSet;

use alloy_consensus::BlockHeader as _;
use alloy_primitives::B256;
use futures::StreamExt as _;
use metrics::{counter, gauge};
use outbe_primitives::OutbePrimitives;
use reth_chain_state::CanonStateSubscriptions;
use reth_transaction_pool::TransactionPool;

/// Configuration for [`maintain_outbe_pool`].
#[derive(Clone, Copy, Debug)]
pub struct OutbePoolMaintainConfig {
    /// Seconds (of canonical block time) between pending-set snapshots. A
    /// pending transaction surviving two consecutive snapshots is evicted, so
    /// the effective pending TTL is one to two intervals. Must be non-zero
    /// (enforced by CLI validation).
    pub staleness_interval_secs: u64,
}

impl Default for OutbePoolMaintainConfig {
    fn default() -> Self {
        Self {
            staleness_interval_secs: 600,
        }
    }
}

/// Two-snapshot pending staleness tracker (pure state machine).
#[derive(Debug, Default)]
pub struct PendingStalenessTracker {
    previous_pending: HashSet<B256>,
    last_snapshot_time: Option<u64>,
    interval_secs: u64,
}

impl PendingStalenessTracker {
    pub fn new(interval_secs: u64) -> Self {
        Self {
            previous_pending: HashSet::new(),
            last_snapshot_time: None,
            interval_secs,
        }
    }

    /// Feed the current pending set at canonical tip time `tip_timestamp`
    /// (unix seconds from the block header - deterministic input, never wall
    /// clock). Returns the hashes to evict: transactions present both in the
    /// previous snapshot and in this one.
    ///
    /// Outside a snapshot boundary (less than one interval since the last
    /// snapshot, including out-of-order timestamps after a head switch) this
    /// returns empty and keeps state unchanged.
    pub fn check_and_update(
        &mut self,
        current_pending: HashSet<B256>,
        tip_timestamp: u64,
    ) -> Vec<B256> {
        match self.last_snapshot_time {
            None => {
                // First observation: seed the snapshot, never evict.
                self.previous_pending = current_pending;
                self.last_snapshot_time = Some(tip_timestamp);
                Vec::new()
            }
            Some(last) => {
                // saturating_sub: a lower timestamp (pre-finalization head
                // rollback) must never evict early or panic.
                if tip_timestamp.saturating_sub(last) < self.interval_secs {
                    return Vec::new();
                }
                let previous = std::mem::take(&mut self.previous_pending);
                let mut stale = Vec::new();
                let mut fresh = HashSet::with_capacity(current_pending.len());
                for hash in current_pending {
                    if previous.contains(&hash) {
                        stale.push(hash);
                    } else {
                        fresh.insert(hash);
                    }
                }
                self.previous_pending = fresh;
                self.last_snapshot_time = Some(tip_timestamp);
                stale
            }
        }
    }
}

/// One maintenance tick against `pool` at canonical tip time `tip_timestamp`.
/// Snapshots the pending set, evicts what the tracker reports stale (with
/// descendants), logs every removal and updates the metrics. Returns the hashes
/// actually removed from the pool.
///
/// Split out of the stream loop so it can be driven directly in tests without a
/// provider subscription.
pub fn run_staleness_tick<Pool>(
    pool: &Pool,
    tracker: &mut PendingStalenessTracker,
    tip_timestamp: u64,
) -> Vec<B256>
where
    Pool: TransactionPool,
{
    let pending: HashSet<B256> = pool
        .pending_transactions()
        .into_iter()
        .map(|tx| *tx.hash())
        .collect();
    gauge!("outbe_txpool_pending_snapshot_size").set(pending.len() as f64);
    let stale = tracker.check_and_update(pending, tip_timestamp);
    if stale.is_empty() {
        return Vec::new();
    }
    let stale_set: HashSet<B256> = stale.iter().copied().collect();
    let removed = pool.remove_transactions_and_descendants(stale);
    for tx in &removed {
        let reason = if stale_set.contains(tx.hash()) {
            "stale_pending"
        } else {
            "descendant_of_stale"
        };
        tracing::warn!(
            target: "outbe::txpool",
            tx_hash = %tx.hash(),
            sender = %tx.sender(),
            nonce = tx.nonce(),
            reason,
            staleness_interval_secs = tracker.interval_secs,
            "evicting stale pending transaction"
        );
    }
    counter!("outbe_txpool_stale_evicted_total").increment(removed.len() as u64);
    removed.iter().map(|tx| *tx.hash()).collect()
}

/// Long-running maintenance loop: subscribes to the canonical-state stream
/// (alongside the upstream maintenance task, which keeps owning nonce/balance
/// pruning and reorg handling) and applies pending staleness eviction. Runs on
/// every node mode - full nodes are the RPC ingress and need it most.
pub async fn maintain_outbe_pool<Provider, Pool>(
    provider: Provider,
    pool: Pool,
    config: OutbePoolMaintainConfig,
) where
    Provider: CanonStateSubscriptions<Primitives = OutbePrimitives>,
    Pool: TransactionPool,
{
    let mut tracker = PendingStalenessTracker::new(config.staleness_interval_secs);
    let mut stream = provider.canonical_state_stream();
    tracing::info!(
        target: "outbe::txpool",
        staleness_interval_secs = config.staleness_interval_secs,
        "pending staleness eviction active"
    );
    while let Some(notification) = stream.next().await {
        // Commit and Reorg are handled identically: only the new tip's
        // timestamp and the pool's CURRENT pending set matter.
        let Some(tip) = notification.tip_checked() else {
            continue;
        };
        let _ = run_staleness_tick(&pool, &mut tracker, tip.header().timestamp());
    }
    tracing::info!(
        target: "outbe::txpool",
        "canonical state stream closed; pending staleness eviction stopped"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        io,
        sync::{Arc, Mutex},
        time::Duration,
    };

    #[derive(Clone, Default)]
    struct CapturedLogWriter {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl CapturedLogWriter {
        fn contents(&self) -> String {
            String::from_utf8(
                self.bytes
                    .lock()
                    .expect("txpool trace capture mutex")
                    .clone(),
            )
            .expect("txpool trace output must be UTF-8")
        }
    }

    struct CapturedLogGuard {
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl io::Write for CapturedLogGuard {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            io::Write::write(
                &mut *self.bytes.lock().expect("txpool trace capture mutex"),
                buf,
            )
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLogWriter {
        type Writer = CapturedLogGuard;

        fn make_writer(&'a self) -> Self::Writer {
            CapturedLogGuard {
                bytes: self.bytes.clone(),
            }
        }
    }

    fn hash(byte: u8) -> B256 {
        B256::repeat_byte(byte)
    }

    fn set(bytes: &[u8]) -> HashSet<B256> {
        bytes.iter().map(|b| hash(*b)).collect()
    }

    #[test]
    fn two_consecutive_snapshots_evict_only_survivors() {
        let mut tracker = PendingStalenessTracker::new(10);
        assert!(
            tracker.check_and_update(set(&[1, 2]), 100).is_empty(),
            "first snapshot only seeds"
        );
        // 1 survived, 2 was mined, 3 is fresh.
        let stale = tracker.check_and_update(set(&[1, 3]), 110);
        assert_eq!(stale, vec![hash(1)]);
        // 3 survives into the next boundary and is evicted then.
        let stale = tracker.check_and_update(set(&[3]), 120);
        assert_eq!(stale, vec![hash(3)]);
    }

    #[test]
    fn mined_transactions_vanish_without_eviction() {
        let mut tracker = PendingStalenessTracker::new(10);
        tracker.check_and_update(set(&[1]), 100);
        // Mined before the boundary: absent from the next snapshot.
        let stale = tracker.check_and_update(set(&[]), 110);
        assert!(stale.is_empty());
        // Re-added later (reorg re-injection): starts a FRESH cycle...
        let stale = tracker.check_and_update(set(&[1]), 120);
        assert!(stale.is_empty(), "re-added tx is fresh again");
        // ...and is evicted one interval later.
        assert_eq!(tracker.check_and_update(set(&[1]), 130), vec![hash(1)]);
    }

    #[test]
    fn interval_gates_snapshots_and_tolerates_time_regression() {
        let mut tracker = PendingStalenessTracker::new(10);
        tracker.check_and_update(set(&[1]), 100);
        // Inside the interval: no snapshot, no eviction.
        assert!(tracker.check_and_update(set(&[1]), 105).is_empty());
        // Head rollback: tip timestamp goes BACKWARDS. Never evicts, never panics.
        assert!(tracker.check_and_update(set(&[1]), 95).is_empty());
        // Boundary reached: 1 was present in the seed snapshot and survived.
        assert_eq!(tracker.check_and_update(set(&[1]), 110), vec![hash(1)]);
    }

    #[test]
    fn empty_pool_and_empty_snapshots_are_no_ops() {
        let mut tracker = PendingStalenessTracker::new(10);
        assert!(tracker.check_and_update(set(&[]), 100).is_empty());
        assert!(tracker.check_and_update(set(&[]), 110).is_empty());
        assert!(tracker.check_and_update(set(&[1]), 120).is_empty());
        assert_eq!(tracker.check_and_update(set(&[1]), 130), vec![hash(1)]);
    }

    /// End-to-end against a real pool: a transaction that survives two
    /// snapshots is removed together with its higher-nonce descendant, while a
    /// transaction admitted after the first snapshot survives this round.
    #[tokio::test]
    async fn tick_evicts_stale_pending_and_descendants_from_a_real_pool() {
        use reth_transaction_pool::{
            test_utils::{testing_pool, MockTransactionFactory},
            TransactionOrigin,
        };

        let pool = testing_pool();
        let mut factory = MockTransactionFactory::default();

        // One sender, two consecutive nonces: the stale head and its descendant.
        let head = factory.create_eip1559();
        let descendant = factory.validated(head.transaction.next());
        let head_hash = *head.transaction.get_hash();
        let descendant_hash = *descendant.transaction.get_hash();
        pool.add_transaction(TransactionOrigin::External, head.transaction.clone())
            .await
            .expect("add head");
        pool.add_transaction(TransactionOrigin::External, descendant.transaction.clone())
            .await
            .expect("add descendant");

        let mut tracker = PendingStalenessTracker::new(10);
        // First snapshot seeds; nothing is evicted.
        assert!(run_staleness_tick(&pool, &mut tracker, 100).is_empty());

        // A newcomer admitted between snapshots must survive this round.
        let newcomer = factory.create_eip1559();
        let newcomer_hash = *newcomer.transaction.get_hash();
        pool.add_transaction(TransactionOrigin::External, newcomer.transaction.clone())
            .await
            .expect("add newcomer");

        let removed = run_staleness_tick(&pool, &mut tracker, 110);
        assert!(removed.contains(&head_hash), "stale head must be evicted");
        assert!(
            removed.contains(&descendant_hash),
            "descendant must be evicted with its stale ancestor"
        );
        assert!(
            !removed.contains(&newcomer_hash),
            "a transaction admitted after the seed snapshot must survive"
        );
        let remaining: HashSet<B256> = pool
            .pending_transactions()
            .into_iter()
            .map(|tx| *tx.hash())
            .collect();
        assert!(!remaining.contains(&head_hash));
        assert!(!remaining.contains(&descendant_hash));
        assert!(remaining.contains(&newcomer_hash));
    }

    /// Regression for ADR-B-TXP-001's no-silent-drop contract. This deliberately
    /// drives Reth's queued-lifetime maintenance task rather than Outbe's
    /// separate two-snapshot pending-staleness task above.
    #[tokio::test]
    async fn queued_lifetime_eviction_emits_structured_identity_and_reason() {
        use alloy_consensus::{SignableTransaction as _, TxEip1559};
        use alloy_primitives::{Signature, TxKind, U256};
        use futures::stream;
        use outbe_primitives::system_tx::OcompLifecycleActivation;
        use reth_ethereum::{evm::EthEvmConfig, EthPrimitives, TransactionSigned};
        use reth_primitives_traits::SignedTransaction as _;
        use reth_provider::test_utils::{ExtendedAccount, MockEthProvider};
        use reth_tasks::Runtime;
        use reth_transaction_pool::{
            blobstore::InMemoryBlobStore, maintain::MaintainPoolConfig,
            validate::EthTransactionValidatorBuilder, EthPooledTransaction, Pool, PoolTransaction,
            TransactionOrigin,
        };
        use tracing::instrument::WithSubscriber as _;

        const NONCE_GAP: u64 = 64;
        let signed: TransactionSigned = TxEip1559 {
            chain_id: 1,
            nonce: NONCE_GAP,
            gas_limit: 21_000,
            max_fee_per_gas: 1_000_000_000,
            max_priority_fee_per_gas: 1,
            to: TxKind::Call(alloy_primitives::Address::repeat_byte(0x44)),
            value: U256::ZERO,
            input: Default::default(),
            access_list: Default::default(),
        }
        .into_signed(Signature::test_signature())
        .into();
        let encoded_length = alloy_eips::eip2718::Encodable2718::encode_2718_len(&signed);
        let recovered = signed
            .try_into_recovered()
            .expect("test transaction signer must recover");
        let transaction = EthPooledTransaction::new(recovered, encoded_length);
        let tx_hash = *transaction.hash();
        let sender = transaction.sender();

        let provider = MockEthProvider::<EthPrimitives>::new().with_genesis_block();
        provider.add_account(sender, ExtendedAccount::new(0, U256::MAX));
        let blob_store = InMemoryBlobStore::default();
        let inner = EthTransactionValidatorBuilder::new(provider.clone(), EthEvmConfig::mainnet())
            .build(blob_store.clone());
        let validator =
            crate::OutbeTransactionValidator::new(inner, OcompLifecycleActivation::at_block(1));
        let pool = Pool::new(
            validator,
            crate::OutbeTransactionOrdering::default(),
            blob_store,
            Default::default(),
        );

        pool.add_transaction(TransactionOrigin::External, transaction)
            .await
            .expect("nonce-gap transaction must enter the real pool");
        let queued = pool.queued_transactions();
        assert_eq!(queued.len(), 1, "the nonce-gap transaction must be queued");
        assert_eq!(*queued[0].hash(), tx_hash);
        assert_eq!(queued[0].sender(), sender);
        assert_eq!(queued[0].nonce(), NONCE_GAP);

        let lifetime = Duration::from_millis(20);
        tokio::time::sleep(lifetime + Duration::from_millis(10)).await;

        let writer = CapturedLogWriter::default();
        let subscriber = tracing_subscriber::fmt()
            .without_time()
            .with_ansi(false)
            .with_max_level(tracing::Level::TRACE)
            .with_writer(writer.clone())
            .finish();
        let runtime = Runtime::test();
        let maintenance = reth_transaction_pool::maintain::maintain_transaction_pool_future::<
            EthPrimitives,
            _,
            _,
            _,
        >(
            provider,
            pool.clone(),
            stream::pending(),
            runtime,
            MaintainPoolConfig {
                max_tx_lifetime: lifetime,
                no_local_exemptions: true,
                ..Default::default()
            },
        )
        .with_subscriber(subscriber);
        let maintenance = tokio::spawn(maintenance);

        tokio::time::timeout(Duration::from_secs(1), async {
            while pool.get(&tx_hash).is_some() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("queued-lifetime maintenance must remove the exact transaction");
        maintenance.abort();

        let logs = writer.contents();
        let expected_hash = format!("tx_hash={tx_hash}");
        let expected_sender = format!("sender={sender}");
        assert!(
            logs.contains("outbe::txpool")
                && logs.contains(&expected_hash)
                && logs.contains(&expected_sender)
                && logs.contains("nonce=64")
                && logs.contains("reason=\"queued_lifetime\""),
            "queued-lifetime eviction must emit exact structured identity and reason; logs:\n{logs}"
        );
    }
}
