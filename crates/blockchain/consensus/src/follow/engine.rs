//! Follower engine assembly: marshal + resolver + driver + committee chain.
//!
//! The follower reuses the same marshal and executor as the validator path. The
//! marshal actor (with its two immutable archives) and the executor mailbox are
//! built by the caller - they need the reth node handle and the engine-crate
//! storage config, which `outbe-consensus` does not have - and handed in here.
//! This function then:
//!
//! 1. bootstraps the [`CommitteeChain`] at the anchor epoch (fetching the anchor
//!    epoch's first block from the upstream and registering its committee, which
//!    runs the anchor group-key trust check);
//! 2. builds the marshal's resolver handler pair and the [`FollowResolver`] over
//!    the upstream + local block sources;
//! 3. starts the marshal with the executor mailbox as its application reporter,
//!    a null broadcast, and the follow resolver;
//! 4. starts the [`Driver`] which walks the marshal forward to the upstream tip.
//!
//! It returns successfully only after a requested runtime stop and a clean
//! marshal drain. Unexpected completion and bootstrap or marshal errors fail.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use alloy_consensus::BlockHeader as _;
use commonware_codec::Encode as _;
use commonware_consensus::marshal::resolver::handler;
use commonware_consensus::marshal::store::{Blocks, Certificates};
use commonware_consensus::types::{Epoch, Epocher, Height};
use commonware_cryptography::bls12381::primitives::variant::MinSig;
use commonware_runtime::{BufferPooler, Clock, Metrics, Spawner, Storage};
use commonware_storage::archive::Identifier;
use eyre::{ensure, eyre, Result};
use futures::FutureExt as _;
use rand::{CryptoRng, RngCore};
use tracing::info;

use crate::digest::Digest;
use crate::follow::driver::{self, Driver};
use crate::follow::resolver;
use crate::follow::upstream::{FinalizedSource, LocalBlockSource, TipSource};
use crate::follow::FollowerEpocher;
use crate::follow::{stubs, CommitteeChain};
use crate::hybrid::HybridScheme;
use crate::marshal_types::{FollowMarshalActor, MarshalMailbox};

/// Inputs to [`run_follow_engine`].
pub struct FollowEngineConfig<E, F, L, T, R>
where
    E: Spawner
        + Clock
        + Metrics
        + BufferPooler
        + Storage
        + RngCore
        + CryptoRng
        + Send
        + Sync
        + 'static,
{
    /// The marshal actor (already initialized over the committee-chain scheme
    /// provider), ready to `start`.
    pub marshal_actor: FollowMarshalActor<E>,
    /// The marshal mailbox (for the driver's `hint_finalized`).
    pub marshal_mailbox: MarshalMailbox,
    /// Exact durable height recovered by `marshal::Actor::init`.
    ///
    /// This is supplied by the caller because the marshal actor has not been
    /// started yet. Querying its mailbox before `start` would wait forever.
    pub recovered_height: Height,
    /// The executor mailbox, used as the marshal's application reporter. It must
    /// implement `Reporter<Activity = MarshalUpdate>` (the outbe executor does).
    pub executor_reporter: R,
    /// Upstream finalized-block source (the transport seam).
    pub upstream: F,
    /// Local execution-layer block source (for `Request::Block`).
    pub local: L,
    /// Upstream tip discovery.
    pub tip: T,
    /// Height->epoch strategy, shared with the marshal.
    pub epocher: FollowerEpocher,
    /// The shared committee chain. Its `scheme_provider()` MUST be the same
    /// provider the `marshal_actor` was initialized with, so committee
    /// registrations are visible to the marshal's certificate verification.
    /// It is bootstrapped at the anchor epoch by this function.
    pub chain: Arc<Mutex<CommitteeChain>>,
    /// The trust anchor's start epoch (for the bootstrap + driver). Equal to
    /// `chain.anchor_epoch()`.
    pub anchor_epoch: Epoch,
    /// Mailbox capacity for the resolver handler.
    pub mailbox_size: NonZeroUsize,
}

/// Assemble and run the follower engine until requested stop or fatal exit.
pub async fn run_follow_engine<E, F, L, T, R>(
    context: E,
    config: FollowEngineConfig<E, F, L, T, R>,
) -> Result<()>
where
    E: Spawner
        + Clock
        + Metrics
        + BufferPooler
        + Storage
        + RngCore
        + CryptoRng
        + Send
        + Sync
        + 'static,
    F: FinalizedSource,
    L: LocalBlockSource,
    T: TipSource,
    R: commonware_consensus::Reporter<Activity = crate::marshal_types::MarshalUpdate>
        + Send
        + 'static,
{
    let FollowEngineConfig {
        marshal_actor,
        marshal_mailbox,
        recovered_height,
        executor_reporter,
        upstream,
        local,
        tip,
        epocher,
        chain,
        anchor_epoch,
        mailbox_size,
    } = config;

    // -- 1. Rebuild the authenticated committee chain through the durable
    //        marshal floor before any new certificate is admitted. ----------
    prepare_committee_chain(&chain, &upstream, &epocher, anchor_epoch, recovered_height).await?;

    // -- 2. Build the marshal resolver handler pair + follow resolver --------
    let (handler_receiver, handler): (handler::Receiver<Digest>, handler::Handler<Digest>) =
        handler::init(context.child("follow_resolver_handler"), mailbox_size);

    let (resolver_actor, follow_resolver) = resolver::init(
        context.child("follow_resolver"),
        handler,
        upstream.clone(),
        local,
        chain.clone(),
        epocher.clone(),
    );
    let _resolver_handle = resolver_actor.start();

    // -- 3. Null broadcast (the follower never disseminates) -----------------
    let broadcast = stubs::null_broadcast(context.child("follow_broadcast"), mailbox_size);

    // -- 4. Start the marshal: executor as application reporter, follow
    //        resolver for gap repair. ----------------------------------------
    let marshal_handle = marshal_actor.start(
        executor_reporter,
        broadcast,
        (handler_receiver, follow_resolver),
    );

    // -- 5. Start the driver: walk the marshal forward to the upstream tip ---
    let driver = Driver::new(
        context.child("follow_driver"),
        driver::Config {
            marshal: marshal_mailbox,
            tip,
            epocher,
        },
    );
    let _driver_handle = driver.start();

    info!("follower engine started; syncing from upstream");

    await_marshal_exit(context.stopped(), marshal_handle).await
}

async fn await_marshal_exit(
    stopped: commonware_runtime::signal::Signal,
    marshal: impl std::future::Future<Output = std::result::Result<(), commonware_runtime::Error>>,
) -> Result<()> {
    // Await the actual task outcome even during shutdown. A stop request is
    // not permission to discard an already completed error or panic.
    marshal
        .await
        .map_err(|error| eyre!("follower marshal exited: {error:?}"))?;
    match stopped.now_or_never() {
        Some(Ok(_)) => Ok(()),
        Some(Err(error)) => Err(eyre!("follower shutdown signal failed: {error:?}")),
        None => Err(eyre!("follower marshal exited unexpectedly")),
    }
}

/// Rebuild the authenticated follower committee chain from the trusted anchor
/// through the exact epoch of `recovered_height`.
///
/// The recovered certificate's epoch is only a target hint. Every intermediate
/// committee is authenticated by an E-1-finalized pre-announce, every activating
/// height by the corresponding E-finalized boundary, and the recovered
/// certificate is verified again after reconstruction.
pub async fn prepare_committee_chain<F>(
    chain: &Arc<Mutex<CommitteeChain>>,
    source: &F,
    epocher: &FollowerEpocher,
    anchor_epoch: Epoch,
    recovered_height: Height,
) -> Result<Epoch>
where
    F: FinalizedSource,
{
    bootstrap_anchor(chain, source, epocher, anchor_epoch).await?;

    if recovered_height.get() == 0 {
        return Ok(anchor_epoch);
    }
    let recovered = source
        .get_finalization(recovered_height)
        .await
        .ok_or_else(|| {
            eyre!(
                "upstream did not return recovered finalized height {}",
                recovered_height.get()
            )
        })?;
    validate_certified_envelope(&recovered, recovered_height)?;
    let target_epoch = recovered.finalization.proposal.round.epoch();
    ensure!(
        target_epoch >= anchor_epoch,
        "recovered epoch {} precedes follower anchor epoch {}",
        target_epoch.get(),
        anchor_epoch.get(),
    );

    let mut epoch = Epoch::new(anchor_epoch.get().saturating_add(1));
    while epoch <= target_epoch {
        let already_registered = chain
            .lock()
            .expect("committee chain mutex poisoned")
            .highest_registered()
            .is_some_and(|highest| highest >= epoch);
        if already_registered {
            epoch = Epoch::new(epoch.get().saturating_add(1));
            continue;
        }

        rebuild_epoch_boundary(chain, source, epocher, epoch, recovered_height).await?;
        epoch = Epoch::new(epoch.get().saturating_add(1));
    }

    {
        let guard = chain.lock().expect("committee chain mutex poisoned");
        guard.verify_finalization(target_epoch, &recovered.finalization)?;
    }
    ensure!(
        epocher
            .containing(recovered_height)
            .is_some_and(|info| info.epoch() == target_epoch),
        "reconstructed follower epoch does not contain recovered height {}",
        recovered_height.get()
    );
    Ok(target_epoch)
}

/// Authenticate and normalize every durable follower record that Marshal can
/// consume after restart before its actor is initialized or started.
///
/// The range is inclusive. Existing local blocks and finalized proposals must
/// match the authenticated upstream record. A local finalization certificate
/// is verified independently because honest nodes may retain different quorum
/// subsets for the same proposal. A missing certificate or block is repaired
/// from the authenticated record. Committee and boundary state advances
/// through the same transition used by live resolver delivery.
#[allow(clippy::too_many_arguments)]
pub async fn authenticate_and_reconcile_replay_suffix<F, FC, FB>(
    chain: &Arc<Mutex<CommitteeChain>>,
    source: &F,
    epocher: &FollowerEpocher,
    anchor_epoch: Epoch,
    lower: Height,
    upper: Height,
    certificates: &mut FC,
    blocks: &mut FB,
) -> Result<Epoch>
where
    F: FinalizedSource,
    FC: Certificates<BlockDigest = Digest, Commitment = Digest, Scheme = HybridScheme<MinSig>>,
    FB: Blocks<Block = crate::block::ConsensusBlock>,
{
    ensure!(
        lower <= upper,
        "follower replay suffix lower height {} exceeds upper height {}",
        lower.get(),
        upper.get()
    );

    let lower_epoch = prepare_committee_chain(chain, source, epocher, anchor_epoch, lower).await?;
    recover_pending_successor_before_lower(chain, source, epocher, lower_epoch, lower, blocks)
        .await?;

    let mut wrote_certificates = false;
    let mut wrote_blocks = false;
    for raw_height in lower.get()..=upper.get() {
        if raw_height == 0 {
            continue;
        }
        let height = Height::new(raw_height);
        let certified = source.get_finalization(height).await.ok_or_else(|| {
            eyre!(
                "upstream did not return follower replay suffix height {}",
                height.get()
            )
        })?;
        authenticate_live_finalized(chain, epocher, height, &certified)?;

        let digest = certified.block.digest();
        match certificates
            .get(Identifier::Index(height.get()))
            .await
            .map_err(|error| {
                eyre!(
                    "failed to read follower replay finalization at height {}: {error}",
                    height.get()
                )
            })? {
            Some(local) => {
                ensure!(
                    local.proposal == certified.finalization.proposal,
                    "local follower replay finalization proposal differs from authenticated upstream at height {}",
                    height.get()
                );
                let epoch = local.proposal.round.epoch();
                chain
                    .lock()
                    .expect("committee chain mutex poisoned")
                    .verify_finalization(epoch, &local)
                    .map_err(|error| {
                        eyre!(
                            "local follower replay finalization certificate failed verification at height {}: {error}",
                            height.get()
                        )
                    })?;
            }
            None => {
                certificates
                    .put(height, digest, certified.finalization.clone())
                    .await
                    .map_err(|error| {
                        eyre!(
                            "failed to repair follower replay finalization at height {}: {error}",
                            height.get()
                        )
                    })?;
                wrote_certificates = true;
            }
        }

        match blocks
            .get(Identifier::Index(height.get()))
            .await
            .map_err(|error| {
                eyre!(
                    "failed to read follower replay block at height {}: {error}",
                    height.get()
                )
            })? {
            Some(local) => ensure!(
                local.encode() == certified.block.encode(),
                "local follower replay block differs from authenticated upstream at height {}",
                height.get()
            ),
            None => {
                blocks.put(certified.block).await.map_err(|error| {
                    eyre!(
                        "failed to repair follower replay block at height {}: {error}",
                        height.get()
                    )
                })?;
                wrote_blocks = true;
            }
        }
    }

    if wrote_certificates {
        certificates.sync().await.map_err(|error| {
            eyre!("failed to sync repaired follower replay finalizations: {error}")
        })?;
    }
    if wrote_blocks {
        blocks
            .sync()
            .await
            .map_err(|error| eyre!("failed to sync repaired follower replay blocks: {error}"))?;
    }

    Ok(chain
        .lock()
        .expect("committee chain mutex poisoned")
        .highest_registered()
        .unwrap_or(anchor_epoch))
}

async fn recover_pending_successor_before_lower<F, FB>(
    chain: &Arc<Mutex<CommitteeChain>>,
    source: &F,
    epocher: &FollowerEpocher,
    active_epoch: Epoch,
    lower: Height,
    blocks: &FB,
) -> Result<()>
where
    F: FinalizedSource,
    FB: Blocks<Block = crate::block::ConsensusBlock>,
{
    use outbe_primitives::reshare_artifact::ConsensusHeaderArtifact as CHA;

    let Some(activation) = epocher.activation_height(active_epoch) else {
        return Ok(());
    };
    if lower <= activation {
        return Ok(());
    }
    let successor = active_epoch.get().saturating_add(1);
    let mut found_successor = false;

    for raw_height in (activation.get()..lower.get()).rev() {
        let height = Height::new(raw_height);
        let local_block = blocks
            .get(Identifier::Index(raw_height))
            .await
            .map_err(|error| {
                eyre!(
                    "failed to inspect follower replay block at height {}: {error}",
                    height.get()
                )
            })?;
        if local_block.is_none() && found_successor {
            continue;
        }
        let fetched = if local_block.is_none() {
            Some(source.get_finalization(height).await.ok_or_else(|| {
                eyre!(
                    "upstream did not return retained follower history height {}",
                    height.get()
                )
            })?)
        } else {
            None
        };
        let inspected_block = local_block
            .as_ref()
            .or_else(|| fetched.as_ref().map(|certified| &certified.block))
            .expect("retained follower history block source must exist");
        let artifacts = outbe_primitives::reshare_artifact::decode_outbe_block_artifacts(
            inspected_block.header().extra_data().as_ref(),
        )
        .map_err(|error| {
            eyre!(
                "failed to decode retained follower block {} artifacts: {error:?}",
                height.get()
            )
        })?;
        if !matches!(
            artifacts.consensus_header_artifact,
            Some(CHA::CommitteePreAnnounce { epoch, .. }) if epoch == successor
        ) {
            continue;
        }

        let certified = match fetched {
            Some(certified) => certified,
            None => source.get_finalization(height).await.ok_or_else(|| {
                eyre!(
                    "upstream did not return retained follower preannounce height {}",
                    height.get()
                )
            })?,
        };
        if let Some(local_block) = local_block {
            ensure!(
                local_block.encode() == certified.block.encode(),
                "local retained follower preannounce differs from authenticated upstream at height {}",
                height.get()
            );
        }
        authenticate_live_finalized(chain, epocher, height, &certified)?;
        found_successor = true;
    }
    Ok(())
}

fn validate_certified_envelope(
    certified: &crate::follow::upstream::CertifiedFinalizedBlock,
    expected_height: Height,
) -> Result<()> {
    ensure!(
        certified.block.number() == expected_height.get(),
        "certified block reports height {}, expected {}",
        certified.block.number(),
        expected_height.get(),
    );
    ensure!(
        certified.finalization.proposal.payload == certified.block.digest(),
        "finalization payload differs from block at height {}",
        expected_height.get(),
    );
    Ok(())
}

/// Authenticate one live finalized delivery and advance only follower-local
/// committee/boundary state. The marshal verifies the same certificate again;
/// this lead-in exists solely to break the boundary verifier-routing cycle.
pub(super) fn authenticate_live_finalized(
    chain: &Arc<Mutex<CommitteeChain>>,
    epocher: &FollowerEpocher,
    expected_height: Height,
    certified: &crate::follow::upstream::CertifiedFinalizedBlock,
) -> Result<()> {
    use outbe_primitives::reshare_artifact::ConsensusHeaderArtifact as CHA;

    validate_certified_envelope(certified, expected_height)?;
    let certified_epoch = certified.finalization.proposal.round.epoch();
    let routed_epoch = epocher
        .containing(expected_height)
        .ok_or_else(|| {
            eyre!(
                "height {} is outside the observed follower epoch window",
                expected_height.get()
            )
        })?
        .epoch();
    ensure!(
        certified_epoch == routed_epoch
            || certified_epoch.get() == routed_epoch.get().saturating_add(1),
        "certified epoch {} is neither routed epoch {} nor its successor at height {}",
        certified_epoch.get(),
        routed_epoch.get(),
        expected_height.get()
    );
    {
        let guard = chain.lock().expect("committee chain mutex poisoned");
        guard.verify_finalization(certified_epoch, &certified.finalization)?;
    }

    let artifacts = outbe_primitives::reshare_artifact::decode_outbe_block_artifacts(
        certified.block.header().extra_data().as_ref(),
    )
    .map_err(|error| {
        eyre!(
            "failed to decode authenticated block {} artifacts: {error:?}",
            expected_height.get()
        )
    })?;

    if certified_epoch != routed_epoch {
        ensure!(
            matches!(
                artifacts.consensus_header_artifact,
                Some(CHA::BoundaryOutcome(ref boundary))
                    if boundary.epoch == certified_epoch.get()
            ),
            "epoch changes from {} to {} at height {} without its BoundaryOutcome",
            routed_epoch.get(),
            certified_epoch.get(),
            expected_height.get()
        );
    }

    match artifacts.consensus_header_artifact {
        Some(CHA::CommitteePreAnnounce { epoch, outcome }) => {
            ensure!(
                epoch == certified_epoch.get().saturating_add(1),
                "authenticated epoch {} block pre-announces non-successor epoch {}",
                certified_epoch.get(),
                epoch
            );
            chain
                .lock()
                .expect("committee chain mutex poisoned")
                .register_epoch_from_outcome(Epoch::new(epoch), &outcome)?;
        }
        Some(CHA::BoundaryOutcome(boundary)) => {
            ensure!(
                boundary.epoch == certified_epoch.get(),
                "boundary artifact epoch {} differs from certificate epoch {}",
                boundary.epoch,
                certified_epoch.get()
            );
            chain
                .lock()
                .expect("committee chain mutex poisoned")
                .register_epoch_from_outcome(certified_epoch, &boundary.outcome)
                .map_err(|error| {
                    eyre!(
                        "boundary outcome conflicts with authenticated epoch {} outcome: {error}",
                        certified_epoch.get()
                    )
                })?;
            epocher.observe_boundary(certified_epoch, expected_height)?;
        }
        _ => {}
    }
    Ok(())
}

async fn rebuild_epoch_boundary<F>(
    chain: &Arc<Mutex<CommitteeChain>>,
    source: &F,
    epocher: &FollowerEpocher,
    epoch: Epoch,
    recovered_height: Height,
) -> Result<()>
where
    F: FinalizedSource,
{
    use outbe_primitives::reshare_artifact::ConsensusHeaderArtifact as CHA;

    let previous_epoch = Epoch::new(epoch.get().saturating_sub(1));
    let (earliest, latest) = epocher
        .next_boundary_window(previous_epoch)
        .ok_or_else(|| {
            eyre!(
                "missing observed activation for prior epoch {}",
                previous_epoch.get()
            )
        })?;
    let scan_end = latest.get().min(recovered_height.get());
    ensure!(
        scan_end >= earliest.get(),
        "recovered height {} precedes activation window {}..={} for epoch {}",
        recovered_height.get(),
        earliest.get(),
        latest.get(),
        epoch.get()
    );

    let mut boundary = None;
    for height in (earliest.get()..=scan_end).rev() {
        let Some(candidate) = source.get_finalization(Height::new(height)).await else {
            continue;
        };
        validate_certified_envelope(&candidate, Height::new(height))?;
        let artifacts = outbe_primitives::reshare_artifact::decode_outbe_block_artifacts(
            candidate.block.header().extra_data().as_ref(),
        )
        .map_err(|error| eyre!("failed to decode boundary candidate at {height}: {error:?}"))?;
        if matches!(
            artifacts.consensus_header_artifact,
            Some(CHA::BoundaryOutcome(ref value)) if value.epoch == epoch.get()
        ) {
            ensure!(
                candidate.finalization.proposal.round.epoch() == epoch,
                "epoch {} boundary candidate at height {} is finalized by epoch {}",
                epoch.get(),
                height,
                candidate.finalization.proposal.round.epoch().get()
            );
            boundary = Some((Height::new(height), candidate));
            break;
        }
    }
    let (boundary_height, boundary) = boundary.ok_or_else(|| {
        eyre!(
            "no BoundaryOutcome for epoch {} in authenticated search window {}..={}",
            epoch.get(),
            earliest.get(),
            scan_end
        )
    })?;

    let previous_activation = epocher
        .activation_height(previous_epoch)
        .ok_or_else(|| eyre!("missing prior activation height"))?
        .get();
    let mut carrier_height = None;
    for height in (previous_activation..boundary_height.get()).rev() {
        let Some(candidate) = source.get_finalization(Height::new(height)).await else {
            continue;
        };
        validate_certified_envelope(&candidate, Height::new(height))?;
        if candidate.finalization.proposal.round.epoch() != previous_epoch {
            continue;
        }
        {
            let guard = chain.lock().expect("committee chain mutex poisoned");
            guard.verify_finalization(previous_epoch, &candidate.finalization)?;
        }
        let artifacts = outbe_primitives::reshare_artifact::decode_outbe_block_artifacts(
            candidate.block.header().extra_data().as_ref(),
        )
        .map_err(|error| eyre!("failed to decode pre-announce candidate at {height}: {error:?}"))?;
        let Some(CHA::CommitteePreAnnounce {
            epoch: announced,
            outcome,
        }) = artifacts.consensus_header_artifact
        else {
            continue;
        };
        if announced != epoch.get() {
            continue;
        }
        chain
            .lock()
            .expect("committee chain mutex poisoned")
            .register_epoch_from_outcome(epoch, &outcome)?;
        carrier_height = Some(height);
        break;
    }
    let carrier_height = carrier_height.ok_or_else(|| {
        eyre!(
            "no prior-epoch-authenticated CommitteePreAnnounce for epoch {} before boundary {}",
            epoch.get(),
            boundary_height.get()
        )
    })?;

    {
        let guard = chain.lock().expect("committee chain mutex poisoned");
        guard.verify_finalization(epoch, &boundary.finalization)?;
    }
    epocher.observe_boundary(epoch, boundary_height)?;
    info!(
        epoch = epoch.get(),
        previous_epoch = previous_epoch.get(),
        carrier_height,
        boundary_height = boundary_height.get(),
        "reconstructed authenticated follower epoch boundary"
    );
    Ok(())
}

async fn bootstrap_anchor<F>(
    chain: &Arc<Mutex<CommitteeChain>>,
    upstream: &F,
    epocher: &FollowerEpocher,
    anchor_epoch: Epoch,
) -> Result<()>
where
    F: FinalizedSource,
{
    use alloy_consensus::BlockHeader as _;

    if chain
        .lock()
        .expect("committee chain mutex poisoned")
        .highest_registered()
        .is_some_and(|highest| highest >= anchor_epoch)
    {
        return Ok(());
    }

    let candidate = epocher
        .activation_height(anchor_epoch)
        .ok_or_else(|| eyre!("epocher has no activation carrier for anchor epoch"))?;

    let certified = upstream.get_finalization(candidate).await.ok_or_else(|| {
        eyre!(
            "upstream did not return the anchor epoch's boundary block at height {candidate}; \
                 cannot bootstrap the committee chain"
        )
    })?;

    ensure!(
        certified.block.number() == candidate.get(),
        "anchor boundary block reports height {}, expected {}",
        certified.block.number(),
        candidate.get(),
    );
    ensure!(
        certified.finalization.proposal.payload == certified.block.digest(),
        "anchor finalization payload differs from boundary block at height {}",
        candidate.get(),
    );

    validate_certified_envelope(&certified, candidate)?;
    let extra = certified.block.header().extra_data().clone();
    let registered = {
        let mut guard = chain.lock().expect("committee chain mutex poisoned");
        let registered = guard
            .advance_from_block_extra_data(extra.as_ref())?
            .ok_or_else(|| {
                eyre!(
                    "anchor epoch {anchor_epoch}'s first block at height {candidate} carried no \
                 boundary outcome; cannot establish the trust root"
                )
            })?;
        guard.verify_finalization(anchor_epoch, &certified.finalization)?;
        registered
    };
    ensure!(
        registered == anchor_epoch,
        "anchor carrier registered epoch {}, expected {}",
        registered.get(),
        anchor_epoch.get()
    );
    epocher.observe_boundary(anchor_epoch, candidate)?;

    info!(
        anchor_epoch = anchor_epoch.get(),
        registered = registered.get(),
        height = candidate.get(),
        "committee chain anchored at trusted network identity"
    );
    Ok(())
}

#[cfg(test)]
mod shutdown_tests {
    use super::await_marshal_exit;
    use commonware_runtime::{signal::Signaler, Error};
    use futures::FutureExt as _;

    #[tokio::test]
    async fn requested_stop_waits_for_actual_marshal_completion() {
        let (signaler, signal) = Signaler::new();
        let (done, completed) = tokio::sync::oneshot::channel();
        let drain = await_marshal_exit(signal, async { completed.await.unwrap() });
        tokio::pin!(drain);
        assert!(drain.as_mut().now_or_never().is_none());
        let stopped = signaler.signal(0);
        assert!(drain.as_mut().now_or_never().is_none());
        done.send(Ok(())).unwrap();
        drain.await.unwrap();
        stopped.await.unwrap();
    }

    #[tokio::test]
    async fn clean_marshal_completion_without_stop_is_an_error() {
        let (_signaler, signal) = Signaler::new();
        let error = await_marshal_exit(signal, std::future::ready(Ok(())))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("marshal exited unexpectedly"));
    }

    #[tokio::test]
    async fn requested_stop_never_hides_marshal_panic_or_closed_result() {
        for failure in [Error::Exited, Error::Closed] {
            let (signaler, signal) = Signaler::new();
            let stopped = signaler.signal(0);
            let expected = format!("{failure:?}");
            let error = await_marshal_exit(signal, std::future::ready(Err(failure)))
                .await
                .unwrap_err();
            assert!(error.to_string().contains(&expected));
            stopped.await.unwrap();
        }
    }

    #[tokio::test]
    async fn lost_shutdown_sender_is_not_a_requested_stop() {
        let (signaler, signal) = Signaler::new();
        drop(signaler);
        let error = await_marshal_exit(signal, std::future::ready(Ok(())))
            .await
            .unwrap_err();
        assert!(error.to_string().contains("shutdown signal failed"));
    }
}
