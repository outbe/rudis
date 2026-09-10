use std::{collections::BTreeMap, future::Future, pin::Pin};

use commonware_consensus::{marshal::Update, types::Height, Heightable as _};
use commonware_p2p::{AddressableManager, AddressableTrackedPeers, Provider};
use commonware_runtime::{Clock, Handle, Spawner};
use commonware_utils::Acknowledgement as _;
use eyre::WrapErr as _;
use futures::{channel::mpsc, StreamExt as _};
use reth_ethereum::provider::BlockHashReader;
use tracing::{debug, error, instrument, warn, Span};

use crate::validators::{read_admitted_non_consensus_at_block, read_consensus_validators_at_block};
use outbe_consensus::{block::ConsensusBlock, config};
use outbe_node::OutbeFullNode;

use super::{
    admission::PeerAdmission,
    ingress::{Message, MessageWithCause, PublicKey},
};
use crate::validators::ValidatorSet;

pub(crate) struct Config<TOracle> {
    pub(crate) oracle: TOracle,
    pub(crate) node: OutbeFullNode,
    pub(crate) executor: outbe_consensus::executor::Mailbox,
    pub(crate) bootnode_map: BTreeMap<Vec<u8>, std::net::SocketAddr>,
    pub(crate) initial_peers: AddressableTrackedPeers<PublicKey>,
    pub(crate) initial_height: u64,
}

struct FinalizedWaitResult {
    height: u64,
    result: eyre::Result<()>,
}

type FinalizedWait = Pin<Box<dyn Future<Output = FinalizedWaitResult> + Send>>;

pub(crate) struct Actor<TContext, TOracle>
where
    TOracle: AddressableManager<PublicKey = PublicKey>,
{
    context: TContext,
    admission: PeerAdmission<TOracle>,
    node: OutbeFullNode,
    executor: outbe_consensus::executor::Mailbox,
    bootnode_map: BTreeMap<Vec<u8>, std::net::SocketAddr>,
    mailbox: mpsc::UnboundedReceiver<MessageWithCause>,
    pending_refresh: Option<ConsensusBlock>,
    retry_timer: Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
    finalized_wait: FinalizedWait,
}

impl<TContext, TOracle> Actor<TContext, TOracle>
where
    TContext: Clock + Spawner + Send + 'static,
    TOracle: AddressableManager<PublicKey = PublicKey> + Send + 'static,
{
    pub(crate) fn new(context: TContext, config: Config<TOracle>) -> (Self, super::Mailbox) {
        let (tx, rx) = mpsc::unbounded();
        let mailbox = super::Mailbox::new(tx);
        let actor = Self {
            context,
            admission: PeerAdmission::new(
                config.oracle,
                config.initial_height,
                config.initial_peers,
            ),
            node: config.node,
            executor: config.executor,
            bootnode_map: config.bootnode_map,
            mailbox: rx,
            pending_refresh: None,
            retry_timer: Box::pin(std::future::pending()),
            finalized_wait: Box::pin(std::future::pending()),
        };
        (actor, mailbox)
    }

    pub(crate) fn start(self) -> Handle<()> {
        // commonware 2026.5.0: `Context` is no longer `Clone`; derive a scoped
        // child to spawn on (mirrors `outbe_consensus::executor::actor::start`).
        let context = self.context.child("peer_manager");
        context.spawn(move |_| self.run())
    }

    async fn run(mut self) {
        loop {
            tokio::select! {
                biased;

                msg = self.mailbox.next() => {
                    let Some(msg) = msg else {
                        error!("peer_manager mailbox closed");
                        break;
                    };
                    if let Err(error) = self.handle_message(msg.cause, msg.message).await {
                        error!(%error, "peer_manager message failed");
                    }
                }

                wait = &mut self.finalized_wait => {
                    self.finalized_wait = Box::pin(std::future::pending());
                    self.handle_finalized_wait(wait).await;
                }

                _ = &mut self.retry_timer => {
                    self.retry_timer = Box::pin(std::future::pending());
                    if let Some(block) = self.pending_refresh.clone() {
                        self.schedule_executor_finalized_wait(Height::new(block.number()));
                    }
                }
            }
        }
    }

    #[instrument(parent = &cause, skip_all)]
    async fn handle_message(&mut self, cause: Span, message: Message) -> eyre::Result<()> {
        match message {
            Message::Track { id, peers } => {
                self.admission.track(id, peers)?;
            }
            Message::Overwrite { peers } => {
                self.admission.overwrite(peers)?;
            }
            Message::PrepareDkg { peers, response } => {
                let _ = response.send(self.admission.prepare_dkg(peers));
            }
            Message::PeerSet { id, response } => {
                let result = Provider::peer_set(&mut self.admission.oracle, id).await;
                let _ = response.send(result);
            }
            Message::Subscribe { response } => {
                let receiver = Provider::subscribe(&mut self.admission.oracle).await;
                let _ = response.send(receiver);
            }
            Message::Finalized(update) => match *update {
                Update::Tip(..) => {}
                Update::Block(block, ack) => {
                    ack.acknowledge();
                    self.pending_refresh = Some(block.clone());
                    self.schedule_executor_finalized_wait(Height::new(block.number()));
                }
            },
        }
        Ok(())
    }

    fn schedule_executor_finalized_wait(&mut self, height: Height) {
        let executor = self.executor.clone();
        self.finalized_wait = Box::pin(async move {
            let result = executor.subscribe_finalized(height).await;
            FinalizedWaitResult {
                height: height.get(),
                result,
            }
        });
    }

    fn schedule_retry(&mut self) {
        self.retry_timer = Box::pin(self.context.sleep(config::DEFAULT_PEER_RESPONSE_TIMEOUT));
    }

    async fn handle_finalized_wait(&mut self, wait: FinalizedWaitResult) {
        let Some(block) = self.pending_refresh.clone() else {
            debug!(
                height = wait.height,
                "peer_manager finalized wakeup ignored because no refresh is pending"
            );
            return;
        };
        if block.number() != wait.height {
            debug!(
                wait_height = wait.height,
                pending_height = block.number(),
                "peer_manager finalized wakeup ignored for stale pending refresh"
            );
            return;
        }
        if let Err(error) = wait.result {
            warn!(%error, height = wait.height, "peer_manager executor finalized wait failed; will retry");
            self.schedule_retry();
            return;
        }
        if let Err(error) = self.try_refresh_from_block(block).await {
            debug!(%error, height = wait.height, "peer_manager provider not ready after executor finalized wakeup; will retry");
            self.schedule_retry();
        }
    }

    #[instrument(skip_all, fields(height = block.number(), hash = %block.block_hash()))]
    async fn try_refresh_from_block(&mut self, block: ConsensusBlock) -> eyre::Result<()> {
        ensure_provider_ready(&self.node.provider, &block)?;
        // PRIMARY = current consensus participants (ACTIVE|EXITING with share - the
        // voting committee). SECONDARY = non-voting admitted peers (status in
        // {REGISTERED, PENDING}, no share): PENDING joiners (staked, syncing toward
        // their activating reshare) PLUS TEE full-nodes
        // (REGISTERED, P2P-announced, enclave-registered, NOT staked). Both are
        // admitted so they reach head and execute offer blocks BEFORE voting - a
        // joiner must be synced before the reshare (else its DKG output diverges); a
        // full-node just syncs + serves. Voting needs `has_bls_share`, so a secondary
        // peer cannot affect consensus. The tiers are disjoint by status.
        let consensus_set =
            read_consensus_validators_at_block(&self.node.provider, block.block_hash())
                .wrap_err("failed to read consensus validators for peer manager")?;
        let admitted_set =
            read_admitted_non_consensus_at_block(&self.node.provider, block.block_hash())
                .wrap_err("failed to read admitted non-consensus validators for peer manager")?;
        let primary = crate::stack::build_peer_map(&consensus_set, &self.bootnode_map);
        let secondary = crate::stack::build_peer_map(&admitted_set, &self.bootnode_map);
        let count = primary.len() + secondary.len();
        debug!(
            height = block.number(),
            primary = primary.len(),
            secondary = secondary.len(),
            "refreshing canonical P2P admission"
        );
        self.admission.refresh(
            block.number(),
            AddressableTrackedPeers::new(primary, secondary),
        )?;
        outbe_consensus::metrics::record_commonware_p2p_active_peers(count);
        self.pending_refresh = None;
        Ok(())
    }
}

fn ensure_provider_ready(
    provider: &impl BlockHashReader,
    block: &ConsensusBlock,
) -> eyre::Result<()> {
    let height = block.height().get();
    let Some(provider_hash) = provider
        .block_hash(height)
        .map_err(|error| eyre::eyre!("failed to read provider block hash at {height}: {error}"))?
    else {
        return Err(eyre::eyre!(
            "provider has no canonical hash at finalized block height {height}"
        ));
    };
    if provider_hash != block.block_hash() {
        return Err(eyre::eyre!(
            "provider hash mismatch at height {height}: provider={provider_hash}, consensus={}",
            block.block_hash()
        ));
    }
    Ok(())
}

#[allow(dead_code)]
fn _assert_validator_set_send(_: &ValidatorSet) {}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Bytes, B256};
    use outbe_primitives::OutbeHeader;
    use reth_ethereum::{primitives::SealedBlock, Block};
    use reth_provider::ProviderResult;
    use std::collections::BTreeMap;

    #[derive(Default)]
    struct MockBlockHashProvider {
        hashes: BTreeMap<u64, B256>,
    }

    impl BlockHashReader for MockBlockHashProvider {
        fn block_hash(&self, number: u64) -> ProviderResult<Option<B256>> {
            Ok(self.hashes.get(&number).copied())
        }

        fn canonical_hashes_range(&self, start: u64, end: u64) -> ProviderResult<Vec<B256>> {
            Ok((start..end)
                .filter_map(|height| self.hashes.get(&height).copied())
                .collect())
        }
    }

    fn consensus_block(number: u64, seed: u8) -> ConsensusBlock {
        let mut block = Block::default();
        block.header.number = number;
        block.header.extra_data = Bytes::from(vec![seed]);
        let block = block.map_header(OutbeHeader::new);
        ConsensusBlock::from_sealed(SealedBlock::seal_slow(block))
    }

    #[test]
    fn ensure_provider_ready_requires_matching_canonical_hash() {
        let block = consensus_block(11, 0x11);
        let mut provider = MockBlockHashProvider::default();

        assert!(
            ensure_provider_ready(&provider, &block).is_err(),
            "missing provider hash must not be treated as ready"
        );

        provider.hashes.insert(11, B256::repeat_byte(0x22));
        assert!(
            ensure_provider_ready(&provider, &block).is_err(),
            "wrong provider hash must not be treated as ready"
        );

        provider.hashes.insert(11, block.block_hash());
        ensure_provider_ready(&provider, &block)
            .expect("matching provider canonical hash must be ready");
    }
}
