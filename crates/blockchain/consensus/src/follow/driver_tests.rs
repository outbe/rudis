use super::*;
use std::num::{NonZeroU16, NonZeroU64, NonZeroUsize};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use commonware_consensus::{marshal, types::ViewDelta};
use commonware_cryptography::{bls12381::primitives::variant::MinSig, certificate::Scheme as _};
use commonware_parallel::Sequential;
use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner as _, Supervisor as _};
use commonware_storage::archive::immutable;
use futures::FutureExt as _;
use reth_ethereum::{primitives::SealedBlock, Block};

use crate::{
    block::ConsensusBlock,
    hybrid::{HybridScheme, HybridSchemeProvider},
    marshal_types::FollowMarshalActor,
};

/// Real mailbox with an unstarted actor: its progress query stays pending until
/// the actor is dropped. No replacement mailbox or production test override.
async fn pending_marshal(
    context: &deterministic::Context,
) -> (FollowMarshalActor<deterministic::Context>, MarshalMailbox) {
    let cache = CacheRef::from_pooler(
        context,
        NonZeroU16::new(1024).unwrap(),
        NonZeroUsize::new(10).unwrap(),
    );
    let items = NonZeroU64::new(10).unwrap();
    let buffer = NonZeroUsize::new(1024).unwrap();
    let archive_config = |label: &str, codec_config| immutable::Config {
        metadata_partition: format!("{label}-metadata"),
        freezer_table_partition: format!("{label}-table"),
        freezer_table_initial_size: 64,
        freezer_table_resize_frequency: 10,
        freezer_table_resize_chunk_size: 10,
        freezer_key_partition: format!("{label}-key"),
        freezer_key_page_cache: cache.clone(),
        freezer_value_partition: format!("{label}-value"),
        freezer_value_target_size: 1024,
        freezer_value_compression: None,
        ordinal_partition: format!("{label}-ordinal"),
        items_per_section: items,
        codec_config,
        replay_buffer: buffer,
        freezer_key_write_buffer: buffer,
        freezer_value_write_buffer: buffer,
        ordinal_write_buffer: buffer,
    };
    let certificates = immutable::Archive::init(
        context.child("certificates"),
        archive_config(
            "certificates",
            HybridScheme::<MinSig>::certificate_codec_config_unbounded(),
        ),
    )
    .await
    .unwrap();
    // Block and certificate codec configs differ; retain the same storage
    // parameters while supplying the block codec's unit config.
    let base = archive_config(
        "blocks",
        HybridScheme::<MinSig>::certificate_codec_config_unbounded(),
    );
    let blocks = immutable::Archive::init(
        context.child("blocks"),
        immutable::Config {
            metadata_partition: base.metadata_partition,
            freezer_table_partition: base.freezer_table_partition,
            freezer_table_initial_size: base.freezer_table_initial_size,
            freezer_table_resize_frequency: base.freezer_table_resize_frequency,
            freezer_table_resize_chunk_size: base.freezer_table_resize_chunk_size,
            freezer_key_partition: base.freezer_key_partition,
            freezer_key_page_cache: base.freezer_key_page_cache,
            freezer_value_partition: base.freezer_value_partition,
            freezer_value_target_size: base.freezer_value_target_size,
            freezer_value_compression: base.freezer_value_compression,
            ordinal_partition: base.ordinal_partition,
            items_per_section: items,
            codec_config: (),
            replay_buffer: buffer,
            freezer_key_write_buffer: buffer,
            freezer_value_write_buffer: buffer,
            ordinal_write_buffer: buffer,
        },
    )
    .await
    .unwrap();
    let genesis = Block::default().map_header(outbe_primitives::OutbeHeader::new);
    let (actor, mailbox, _) = marshal::core::Actor::init(
        context.child("marshal"),
        certificates,
        blocks,
        marshal::Config {
            provider: HybridSchemeProvider::new(),
            epocher: FollowerEpocher::new(100, 10),
            start: marshal::Start::Genesis(ConsensusBlock::from_sealed(SealedBlock::seal_slow(
                genesis,
            ))),
            partition_prefix: "driver-test".into(),
            mailbox_size: NonZeroUsize::new(32).unwrap(),
            view_retention_timeout: ViewDelta::new(100),
            prunable_items_per_section: items,
            page_cache: cache,
            replay_buffer: buffer,
            key_write_buffer: buffer,
            value_write_buffer: buffer,
            block_codec_config: (),
            max_repair: NonZeroUsize::new(10).unwrap(),
            max_pending_acks: NonZeroUsize::new(1).unwrap(),
            strategy: Sequential,
        },
    )
    .await;
    (actor, mailbox)
}

#[derive(Clone)]
struct Tip {
    pending: bool,
    calls: Arc<AtomicUsize>,
}

impl TipSource for Tip {
    async fn finalized_tip(&self) -> Option<Height> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.pending {
            std::future::pending().await
        } else {
            Some(Height::new(10))
        }
    }
}

#[test]
fn shutdown_cancels_pending_tip_or_marshal_and_polling_sleep() {
    for (pending_tip, closed_marshal) in [(true, false), (false, false), (false, true)] {
        deterministic::Runner::default().start(move |context| async move {
            let (actor, marshal) = pending_marshal(&context).await;
            let _actor = if closed_marshal {
                drop(actor);
                None
            } else {
                Some(actor)
            };
            let calls = Arc::new(AtomicUsize::new(0));
            let driver = Driver::new(
                context.child("driver"),
                Config {
                    marshal,
                    tip: Tip {
                        pending: pending_tip,
                        calls: Arc::clone(&calls),
                    },
                    epocher: FollowerEpocher::new(100, 10),
                },
            );
            let run = driver.run();
            futures::pin_mut!(run);
            assert!(run.as_mut().now_or_never().is_none());
            assert_eq!(calls.load(Ordering::SeqCst), 1);
            let stop = context.stop(0, Some(Duration::from_secs(1)));
            futures::pin_mut!(stop);
            assert!(stop.as_mut().now_or_never().is_none());
            assert!(
                run.as_mut().now_or_never().is_some(),
                "driver must exit without a query response"
            );
            stop.await.unwrap();
            assert_eq!(calls.load(Ordering::SeqCst), 1, "no queries after shutdown");
        });
    }
}

#[test]
fn unavailable_progress_is_not_genesis_and_hints_respect_all_bounds() {
    assert_eq!(
        hint_range(None, Height::new(100), Some(Height::new(100))),
        None
    );
    assert_eq!(
        hint_range(
            Some(Height::new(0)),
            Height::new(100),
            Some(Height::new(100))
        ),
        Some(1..=64)
    );
    assert_eq!(
        hint_range(
            Some(Height::new(60)),
            Height::new(200),
            Some(Height::new(80))
        ),
        Some(61..=80)
    );
    assert_eq!(
        hint_range(
            Some(Height::new(60)),
            Height::new(65),
            Some(Height::new(80))
        ),
        Some(61..=65)
    );
    assert_eq!(
        hint_range(
            Some(Height::new(60)),
            Height::new(60),
            Some(Height::new(80))
        ),
        None
    );
    assert_eq!(
        hint_range(Some(Height::new(60)), Height::new(200), None),
        None
    );
}
