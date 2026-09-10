//! Pre-registration of vote/cert/res sub-channels for a future
//! consensus epoch.
//!
//! The Outbe consensus stack runs a fresh `simplex::Engine` per epoch
//! and registers a per-epoch sub-channel on each of three Muxers
//! (vote, cert, resolver). Without pre-registration, sub-channel
//! registration on the *receiver side* happens only when the new
//! epoch's `'epoch_loop` iteration starts - which can lag a faster
//! peer's broadcast for the same epoch. Because production uses
//! `Muxer::new(...)` (no `.with_backup()`), any vote/cert message
//! arriving on an unregistered sub-channel is **dropped silently**
//! and never replayed.
//!
//! This helper closes the cross-node race: at DKG completion (well
//! before any peer fires its activation handler), every honest node
//! pre-registers vote/cert/res sub-channels for the upcoming epoch.
//! By the time a fast peer broadcasts new-epoch traffic, every
//! receiver's Mux already has a route. The activation handler later
//! consumes the stash and hands the (already-receiving) sub-channels
//! to the new Engine.
//!
//! Both production (`stack.rs`) and the multi-node test harness
//! (`test_harness.rs`) call `register_epoch_subchannels` and
//! `take_or_register_current` from this module. Tests therefore
//! exercise the same registration code path that production runs.
//!
//! Error path: any failure in this module is fail-fast through
//! `eyre::Result`. There is no silent fallback to lazy registration -
//! a Mux that cannot register a sub-channel is in a state we cannot
//! safely paper over from a consensus runtime path.

use commonware_consensus::types::Epoch;
use commonware_p2p::{
    utils::mux::{Error as MuxError, MuxHandle, SubReceiver, SubSender},
    Receiver as P2pReceiver, Sender as P2pSender,
};
use commonware_runtime::Clock;
use eyre::{Result, WrapErr as _};
use std::time::Duration;

/// Pre-registered (or freshly-registered) vote / cert / resolver
/// Mux sub-channels for one consensus epoch. Held in a stash from
/// DKG completion until the activation handler consumes it.
///
/// Each `(SubSender, SubReceiver)` tuple keeps the Mux route alive:
/// dropping the `SubReceiver` triggers a `Control::Deregister`
/// message to the Mux, which removes the route. As long as the
/// stash is held, the new epoch's sub-channel keeps draining the
/// physical channel into its buffered SubReceiver mailbox.
pub struct EpochSubchannels<S, R>
where
    S: P2pSender,
    R: P2pReceiver<PublicKey = S::PublicKey>,
{
    pub epoch: Epoch,
    pub vote: (SubSender<S>, SubReceiver<R>),
    pub cert: (SubSender<S>, SubReceiver<R>),
    pub res: (SubSender<S>, SubReceiver<R>),
}

/// Register vote / cert / res sub-channels for `epoch` on the three
/// provided Mux handles. Used at DKG completion to defeat the
/// cross-node registration race.
///
/// Returns the three `(SubSender, SubReceiver)` tuples bundled into
/// an `EpochSubchannels`. Any underlying Mux error
/// (`AlreadyRegistered`, closed Mux) is wrapped in an `eyre` error
/// and propagated.
pub async fn register_epoch_subchannels<S, R>(
    epoch: Epoch,
    vote_mux: &mut MuxHandle<S, R>,
    cert_mux: &mut MuxHandle<S, R>,
    res_mux: &mut MuxHandle<S, R>,
) -> Result<EpochSubchannels<S, R>>
where
    S: P2pSender,
    R: P2pReceiver<PublicKey = S::PublicKey>,
{
    try_register_epoch_subchannels(epoch, vote_mux, cert_mux, res_mux)
        .await
        .map_err(|(channel, error)| {
            eyre::eyre!("register {channel} subchannel for epoch {epoch}: {error}")
        })
}

/// Reacquire the three routes for an engine replacement in the same epoch.
///
/// Aborting the old Simplex root recursively aborts its actor descendants, but
/// awaiting that root does not join every descendant. Their `SubReceiver`s can
/// therefore deregister a few scheduler turns later. Retrying only
/// `AlreadyRegistered` closes that teardown race without permitting two live
/// receivers: a successful registration can happen only after the Mux has
/// processed the old receiver's `Deregister` control message. Any closed Mux or
/// bounded local timeout is fatal to the caller.
pub async fn reacquire_epoch_subchannels<S, R, C>(
    epoch: Epoch,
    clock: &C,
    timeout: Duration,
    retry_interval: Duration,
    vote_mux: &mut MuxHandle<S, R>,
    cert_mux: &mut MuxHandle<S, R>,
    res_mux: &mut MuxHandle<S, R>,
) -> Result<EpochSubchannels<S, R>>
where
    S: P2pSender,
    R: P2pReceiver<PublicKey = S::PublicKey>,
    C: Clock,
{
    let deadline = clock
        .current()
        .checked_add(timeout)
        .ok_or_else(|| eyre::eyre!("same-epoch subchannel timeout overflows SystemTime"))?;
    loop {
        match try_register_epoch_subchannels(epoch, vote_mux, cert_mux, res_mux).await {
            Ok(channels) => return Ok(channels),
            Err((channel, MuxError::AlreadyRegistered(_))) if clock.current() < deadline => {
                tracing::debug!(
                    %epoch,
                    channel,
                    "waiting for prior same-epoch Mux receiver to deregister"
                );
                clock.sleep(retry_interval).await;
            }
            Err((channel, MuxError::AlreadyRegistered(_))) => {
                return Err(eyre::eyre!(
                    "timed out after {timeout:?} reacquiring {channel} subchannel for epoch {epoch}"
                ));
            }
            Err((channel, error)) => {
                return Err(eyre::eyre!(
                    "reacquire {channel} subchannel for epoch {epoch}: {error}"
                ));
            }
        }
    }
}

async fn try_register_epoch_subchannels<S, R>(
    epoch: Epoch,
    vote_mux: &mut MuxHandle<S, R>,
    cert_mux: &mut MuxHandle<S, R>,
    res_mux: &mut MuxHandle<S, R>,
) -> std::result::Result<EpochSubchannels<S, R>, (&'static str, MuxError)>
where
    S: P2pSender,
    R: P2pReceiver<PublicKey = S::PublicKey>,
{
    let vote = vote_mux
        .register(epoch.get())
        .await
        .map_err(|error| ("vote", error))?;
    let cert = match cert_mux.register(epoch.get()).await {
        Ok(cert) => cert,
        Err(error) => {
            drop(vote);
            return Err(("cert", error));
        }
    };
    let res = match res_mux.register(epoch.get()).await {
        Ok(res) => res,
        Err(error) => {
            drop(cert);
            drop(vote);
            return Err(("res", error));
        }
    };
    Ok(EpochSubchannels {
        epoch,
        vote,
        cert,
        res,
    })
}

/// Consume the stash if it matches `epoch`, otherwise register
/// fresh.
///
/// This is the entry point at the top of each `'epoch_loop`
/// iteration. Three branches:
///
/// * `Some(stash)` with `stash.epoch == epoch`: the expected case
///   under the production fix - DKG completion pre-registered for
///   this epoch and the activation handler advanced into it.
///   Consume the stash.
/// * `Some(stash)` with `stash.epoch != epoch`: a state-machine
///   bug. Either DKG completion pre-registered for the wrong epoch,
///   or the epoch counter advanced unexpectedly. Silently
///   re-registering would mask the bug. Drop the stash (its
///   `SubReceiver`s' `Drop` deregisters the wrong-epoch routes from
///   the Muxes) and surface the error.
/// * `None`: genesis bootstrap or restart - there was no prior DKG
///   completion to pre-register from. Register fresh.
pub async fn take_or_register_current<S, R>(
    epoch: Epoch,
    stash: &mut Option<EpochSubchannels<S, R>>,
    vote_mux: &mut MuxHandle<S, R>,
    cert_mux: &mut MuxHandle<S, R>,
    res_mux: &mut MuxHandle<S, R>,
) -> Result<EpochSubchannels<S, R>>
where
    S: P2pSender,
    R: P2pReceiver<PublicKey = S::PublicKey>,
{
    match stash.take() {
        Some(s) if s.epoch == epoch => Ok(s),
        Some(s) => {
            let stash_epoch = s.epoch;
            drop(s);
            Err(eyre::eyre!(
                "pre-registered subchannels for epoch {stash_epoch} cannot be \
                 used for current epoch {epoch}"
            ))
        }
        None => register_epoch_subchannels(epoch, vote_mux, cert_mux, res_mux)
            .await
            .wrap_err_with(|| {
                format!(
                    "lazy register of vote/cert/res subchannels for epoch {epoch} \
                     (no pre-registered stash)"
                )
            }),
    }
}
