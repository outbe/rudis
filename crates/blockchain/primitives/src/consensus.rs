//! Consensus-execution bridge types.
//!
//! Shared data structures for passive consensus status and execution-summary
//! cache handoff. Finalized-parent certificate facts travel through Phase 1
//! system transaction input, not through this bridge. Lives in
//! `outbe-primitives` to avoid circular dependencies between `outbe-consensus`
//! and `outbe-evm`.

use alloy_primitives::{Address, Bytes, B256};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
};
use tokio::sync::{mpsc, oneshot};

use crate::reshare_artifact::ExecutionSummaryArtifact;

const EXECUTION_SUMMARY_CACHE_LIMIT: usize = 1024;

/// Maximum supported block `extra_data` size for Outbe payloads.
///
/// Outbe reserves `header.extra_data` for DKG boundary outcomes and dealer
/// logs. Those artifacts can be materially larger than Ethereum's default
/// 32-byte budget, so the node validator and consensus runtime share a larger
/// explicit cap.
pub const OUTBE_MAX_EXTRA_DATA_SIZE: usize = 64 * 1_024;

/// Maximum allowed RLP-encoded size of a block, in bytes.
///
/// The full block rides a single consensus P2P message (`ConsensusBlock`, and
/// the marshal's `(notarization, block)` resolver co-transport), which
/// commonware caps at `MAX_P2P_MESSAGE_SIZE` (2 MiB) and **panics** on overflow.
/// The execution-layer gas limit permits far larger blocks (~7.5 MB of
/// zero-byte calldata at 30M gas), so without this cap an honest proposer could
/// build a valid block that can never be disseminated - verifiers could never
/// pull it and the view would stall. This bound keeps a margin below the 2 MiB
/// transport cap for the message envelope and the attached certificate.
///
/// Enforced at block build (the payload builder skips txs / rejects a sealed
/// block over this size) and re-checked deterministically at verify
/// (`validate_block_pre_execution` measures `sealed_block.rlp_length()`), so a
/// byzantine proposer that ignores the build cap is rejected rather than
/// crashing the transport. Hard-fork-governed protocol constant; both the
/// builder and the validator read it from here. A workspace test in
/// `outbe-consensus` guards `OUTBE_MAX_BLOCK_SIZE < MAX_P2P_MESSAGE_SIZE`.
pub const OUTBE_MAX_BLOCK_SIZE: usize = 2 * 1024 * 1024 - 128 * 1024;

/// Maximum allowed forward drift, in milliseconds, between a block's
/// `timestamp_millis` and its parent's.
///
/// Block timestamps are proposer-supplied and only checked for parent
/// monotonicity by the stock Ethereum rules. Without an upper bound a single
/// byzantine leader can ratchet chain time arbitrarily far forward in one
/// block, which (a) instantly matures every pending unbonding entry and the
/// slashed-withdrawal delay, letting the proposer's own stake escape the
/// unbonding lock and slashing window, and (b) skips the day-indexed emission
/// schedule. This bound is the deterministic, chain-state-only drift band
/// shared by the proposer (which caps its assigned timestamp at
/// `parent + this`) and every validator (which rejects a block whose delta
/// exceeds `this`); see `crates/blockchain/node/src/consensus.rs`
/// (`validate_against_parent_timestamp_millis`) and the proposer build path in
/// `crates/blockchain/consensus/src/application/handler.rs`.
///
/// 1 hour is >400x the certification timeout, so honest operation - including
/// view-nullification bursts and DKG-reshare pauses - never trips it, while a
/// genuinely long outage self-heals: the proposer caps at `parent + this` and
/// chain time ratchets forward in bounded steps until it catches up to real
/// time, so the band never turns a recoverable stall into a permanent halt. It
/// is ~504x smaller than the 21-day default unbonding period, so the
/// single-block unbonding-lock bypass is eliminated and any residual time
/// ratchet by a sustained byzantine leader is slow and on-chain visible.
/// Hard-fork-governed protocol constant; both paths read it from here.
pub const MAX_BLOCK_TIMESTAMP_DRIFT_MILLIS: u64 = 60 * 60 * 1_000;

/// Minimum advance, in milliseconds, that a block's `timestamp_millis` must add
/// over its parent's - the lower bound of the two-sided drift band.
///
/// Stock monotonicity only requires `+1 ms`, so a colluding leader majority can
/// keep `timestamp = parent + 1 ms` while real time advances, freezing every
/// time-driven settlement that keys off block timestamp: the day-indexed
/// emission schedule never crosses a UTC boundary and unbonding maturity
/// (`complete_time`) is never reached, so stake never unlocks and emission
/// stalls. This bound forces each block to advance chain time by at least
/// `this`, so the freeze is neutralized - the only way to slow chain time below
/// `this`-per-block is to withhold blocks, which the view-timeout / leader
/// rotation machinery already bounds.
///
/// Like the maximum bound, the rule is deterministic and chain-state-only
/// (header + parent, no wall clock) so proposer and every validator agree. The
/// proposer clamps its assigned timestamp *up* to `parent + this` when its clock
/// has not advanced that far (see the consensus handler build path), so an
/// honest block is never rejected; the clamp only bites under clock lag and any
/// resulting forward inflation is bounded by
/// [`MAX_BLOCK_TIMESTAMP_DRIFT_MILLIS`] and self-corrects once real time catches
/// up. The genesis child (parent block number `0`) is exempt on both paths: the
/// `finalization_view` is unseeded at genesis, so block 1 is only checked for
/// monotonicity.
///
/// 1 s is half the 2 s default block-time floor
/// (`DEFAULT_MIN_BLOCK_TIME_MS`), so honest pacing - which leaves real intervals
/// `>=` the floor between consecutive block timestamps - never trips the clamp at
/// the default cadence, while a sub-second freeze is impossible. Operators who
/// configure a block-time floor below `this` accept proportionally more bounded
/// forward inflation. Hard-fork-governed protocol constant; both paths read it
/// from here.
pub const MIN_BLOCK_TIMESTAMP_ADVANCE_MILLIS: u64 = 1_000;

/// Inclusion-window depth `K` for the late-finalize-credits mechanism.
///
/// Block `N`'s fees are escrowed and split at `N+K` across everyone whose
/// finalize signature for `N` was gathered within `K` blocks. Inclusion distance
/// is `k = inclusion_block - N`, `k in {0..=K}`; the window closes / settles at
/// `N+K` and per-block state is freed at `N+K+1`. Hard-fork-set protocol
/// constant. Shared by the executor (settle timing) and
/// the rewards module (decay weights).
pub const LATE_FINALIZE_WINDOW_K: u64 = 3;

/// Decoded participation data from a finalized block.
#[derive(Debug, Clone, Default)]
pub struct ParticipationData {
    /// Validators who signed the finalization.
    pub voters: Vec<Address>,
    /// Validators in the committee who did NOT sign.
    pub absent: Vec<Address>,
}

/// Canonical finalized-parent certificate artifact carried in block history.
///
/// This is proposer-chosen but chain-carried data: once included in a block it
/// becomes the canonical execution input for participation and missed-vote
/// accounting for the finalized parent it references.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FinalizedParentCertificateData {
    /// Finalized proposal epoch.
    pub epoch: u64,
    /// Finalized proposal view.
    pub view: u64,
    /// Parent view recorded in the finalized proposal.
    pub parent_view: u64,
    /// Active committee in participant index order for this finalized proposal.
    pub ordered_committee: Vec<Address>,
    /// One byte per participant in `ordered_committee`: `1` if the validator
    /// signed the finalization, `0` otherwise.
    pub signer_bitmap: Vec<u8>,
    /// Encoded `HybridCertificate<MinSig>` bytes for cryptographic verification.
    pub encoded_certificate: Bytes,
}

/// Result of a DKG/reshare ceremony, consumed by the executor's certified
/// ValidatorSet boundary hook in the first block after the ceremony completes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReshareResult {
    /// EVM addresses of validators who participated in the ceremony.
    pub new_active_set: Vec<Address>,
    /// Deterministic hash of the active consensus set snapshot.
    pub active_set_hash: B256,
}

/// Canonical DKG boundary artifact carried in block `header.extra_data`.
///
/// This artifact is the execution-facing chain record of a DKG outcome at an
/// epoch boundary. Consensus verifies the carried `outcome` bytes against the
/// locally expected DKG outcome, while execution uses the nested
/// [`ReshareResult`] to activate the new validator set deterministically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DkgBoundaryArtifact {
    /// Epoch activated by this artifact.
    pub epoch: u64,
    /// Monotonic DKG/VRF rotation cycle.
    pub dkg_cycle: u64,
    /// Block height where the target validator set was frozen.
    pub freeze_height: u64,
    /// Planned activation height for this frozen target.
    pub planned_activation_height: u64,
    /// Hash of the frozen target set and boundary metadata.
    pub target_set_hash: B256,
    /// Version of the VRF material activated by this outcome.
    pub vrf_material_version: u64,
    /// Keccak256 hash of the serialized VRF group BLS public key.
    pub vrf_group_public_key: B256,
    /// Raw `commonware_codec::Encode(polynomial.public())` bytes for the VRF
    /// group public key. Carried in the boundary artifact so that the executor
    /// can build the incoming `CommitteeSnapshotStore` entry (slot 39) at the
    /// activation block without rerunning the DKG. Empty before V2 wiring.
    pub vrf_group_public_key_bytes: Bytes,
    /// Canonical V2 `committee_set_hash`
    /// (`outbe-validatorset::state::committee_set_hash_v2`). Binds addresses,
    /// MinPk pubkeys, `vrf_material_version`, and the encoded VRF group key
    /// for the activated committee. `B256::ZERO` before V2 wiring.
    pub committee_set_hash: B256,
    /// Whether this outcome changes the active consensus set.
    pub is_validator_set_change: bool,
    /// Canonical encoded full DKG output bytes for consensus-side verification.
    pub outcome: Bytes,
    /// Whether the carried outcome comes from a full DKG instead of a reshare.
    pub is_full_dkg: bool,
    /// Execution-facing reshared-set activation payload.
    pub reshare: ReshareResult,
    /// Per-validator TEE recipient X25519 public keys for the activated
    /// committee, carried so the tribute TEE DKG can address share-relay to the
    /// right enclaves. Empty until the tribute DKG slice
    /// populates it; OART wire `v0.07`.
    pub tee_recipient_pubkeys: Vec<(Address, B256)>,
    /// Canonical storage-order list of ValidatorSet target members excluded at
    /// the exact DKG freeze block because their DcapRequired lease was not ready.
    /// This is the only authority for the narrow replayable expiry demotion.
    pub tee_expired_target_exclusions: Vec<Address>,
    /// Domain-separated commitment to [`Self::tee_expired_target_exclusions`].
    /// Honest voters compare the complete locally frozen artifact, including
    /// both this commitment and the ordered list.
    pub tee_expired_target_exclusions_hash: B256,
}

/// A single validator entry for genesis initialization.
#[derive(Debug, Clone)]
pub struct GenesisValidator {
    /// Ethereum address of the validator.
    pub address: Address,
    /// 48-byte BLS12-381 MinPk consensus public key.
    pub consensus_pubkey: [u8; 48],
}

/// Initial validator set expected in genesis.
///
/// The executor does not write these validators. It verifies the canonical
/// genesis state against this local consensus bootstrap config on fresh start.
#[derive(Debug, Clone)]
pub struct GenesisValidators {
    pub validators: Vec<GenesisValidator>,
    pub epoch_length_blocks: u32,
}

/// Data produced by the consensus layer for a finalized block.
#[derive(Debug, Clone, Default)]
pub struct ConsensusData {
    /// Finalized block number corresponding to this metadata, when known.
    pub finalized_block_number: u64,
    /// Finalized block hash corresponding to this metadata.
    pub finalized_block_hash: B256,
    /// Canonical finalized-parent certificate artifact used for exact
    /// participation/slashing derivation.
    pub finalized_certificate: FinalizedParentCertificateData,
    /// VRF seed derived from the BLS threshold signature (if available).
    pub vrf_seed: Option<B256>,
    /// Canonical missed proposer events for skipped views before this
    /// finalization. This is an event list, so a validator may appear multiple
    /// times when it missed multiple views.
    pub missed_proposers: Vec<Address>,
}

/// Execution summary decoded from a locally executed block header.
///
/// This is a bounded live cache for the Reth in-memory-tree vs provider-DB
/// handoff window. The authoritative data remains the canonical block header:
/// callers must only use this cache after checking that the provider cannot
/// read the header yet, not to override a readable canonical header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachedExecutionSummary {
    pub summary: ExecutionSummaryArtifact,
    pub timestamp: u64,
    /// State root committed by the same exact block header as `summary`.
    ///
    /// `None` is retained only for legacy/test cache writers. Consensus paths
    /// that need to bind an OCOMP JobId require `Some` and fail closed
    /// otherwise.
    pub state_root: Option<B256>,
}

/// VRF/DKG safety state visible to operators and RPC clients.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RandomnessStatus {
    #[default]
    Unknown,
    Healthy,
    Preparing,
    PendingActivation,
    Grace,
    Degraded,
    Expired,
}

impl RandomnessStatus {
    /// Whether validator-mode consensus should be reported as active for this
    /// randomness state.
    pub const fn is_consensus_active(self) -> bool {
        !matches!(self, Self::Unknown | Self::Expired)
    }

    /// Whether this network-level VRF state permits use of a locally present
    /// threshold share. This does not prove that the local process owns one.
    pub const fn has_threshold_shares(self) -> bool {
        matches!(
            self,
            Self::Healthy | Self::Preparing | Self::PendingActivation | Self::Grace
        )
    }
}

/// Finalized consensus status snapshot, updated by the reporter on each finalization.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ConsensusStatus {
    /// Current Simplex view number.
    pub current_view: u64,
    /// Number of connected consensus peers.
    pub connected_peers: u32,
    /// Last finalized block number.
    pub last_finalized_block: u64,
    /// Last VRF seed (from the most recent finalized certificate).
    pub last_vrf_seed: Option<B256>,
    /// Current VRF/DKG safety state.
    pub randomness_status: RandomnessStatus,
    /// Active VRF material version used by consensus votes.
    pub vrf_material_version: u64,
    /// Block height at which the active VRF material was activated.
    pub last_dkg_activation_height: u64,
    /// Planned height for the next VRF/DKG activation.
    pub next_planned_activation_height: u64,
    /// Last block height at which old VRF material may still be used.
    pub vrf_expiry_height: u64,
}

impl ConsensusStatus {
    /// Whether the node is synced and participating in consensus. Derived from
    /// `randomness_status` (single source of truth) rather than stored, so it can
    /// never drift from the VRF/DKG safety state it is computed from.
    pub fn is_active(&self) -> bool {
        self.randomness_status.is_consensus_active()
    }

    /// Whether the network-level randomness state permits threshold-share use.
    ///
    /// This compatibility helper does not prove that the local process owns a
    /// private share. RPC callers must use
    /// [`ConsensusExecutionBridge::consensus_status_with_threshold_shares`].
    pub fn has_threshold_shares(&self) -> bool {
        self.randomness_status.has_threshold_shares()
    }
}

/// Thread-safe bridge for passive consensus/execution status and caches.
///
/// Finalized-parent attestations are no longer transported through this bridge
/// or through `header.extra_data`; consensus writes exact-parent records into
/// the consensus-owned parent certificate store and carries the selected record
/// in the successor block's Phase 1 system transaction. The bridge keeps only
/// bootstrap/status data and the short-lived execution-summary cache used while
/// Reth's generic provider catches up to recently executed headers.
#[derive(Clone)]
pub struct ConsensusExecutionBridge {
    inner: Arc<Mutex<BridgeState>>,
}

#[derive(Default)]
struct BridgeState {
    genesis_validators: Option<GenesisValidators>,
    consensus_status: ConsensusStatus,
    /// Process-local authority fact derived from the active in-memory DKG
    /// material. It is deliberately not persisted or consensus-visible.
    local_threshold_share_present: bool,
    execution_summary_cache: VecDeque<ExecutionSummaryCacheEntry>,
    /// One-time TEE bootstrap payload produced by the consensus-thread TEE DKG
    /// coordination, handed to the payload builder so every block-1 proposal
    /// attempt injects the same bytes (slice 5.1). It must remain available
    /// across rejected or abandoned proposal candidates; the block-number guard
    /// in the payload builder makes it unreachable after block 1.
    pending_tee_bootstrap: Option<crate::tee_bootstrap_v2::TeeBootstrapV2>,
    /// Channel to the consensus-side drainer that answers `rudis_getFinalization`
    /// RPC requests from the marshal. Set once at marshal-start; `None` on a
    /// node that does not serve finalizations (e.g. before consensus is up).
    finalization_fetcher: Option<FinalizationFetcherTx>,
}

/// The marshal-backed answer to an `rudis_getFinalization` request: the
/// commonware-codec-encoded finalization certificate and the encoded
/// `ConsensusBlock`, ready to hex and ship. A follower's resolver reconstructs
/// `finalization.encode() || block.encode()` from exactly these two fields.
#[derive(Clone, Debug)]
pub struct FinalizedBlockBytes {
    /// `commonware_codec::Encode` bytes of the `Finalization` certificate.
    pub finalization: Bytes,
    /// `commonware_codec::Encode` bytes of the finalized `ConsensusBlock`.
    pub block: Bytes,
}

/// Sender half of the finalization fetch channel: a height plus a one-shot
/// reply. Lives in the bridge so the `outbe-rpc` handler (which cannot see the
/// marshal or `ConsensusBlock`) can request finalized bytes from the consensus
/// thread.
type FinalizationFetcherTx =
    mpsc::UnboundedSender<(u64, oneshot::Sender<Option<FinalizedBlockBytes>>)>;

/// Receiver half handed to the consensus-side drainer.
pub type FinalizationFetcherRx =
    mpsc::UnboundedReceiver<(u64, oneshot::Sender<Option<FinalizedBlockBytes>>)>;

#[derive(Clone, Copy)]
struct ExecutionSummaryCacheEntry {
    block_number: u64,
    block_hash: B256,
    summary: ExecutionSummaryArtifact,
    timestamp: u64,
    state_root: Option<B256>,
}

impl ConsensusExecutionBridge {
    /// Creates a new bridge with no pending data.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(BridgeState::default())),
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, BridgeState> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Stores the one-time TEE bootstrap payload for the payload builder to inject.
    /// Set by the consensus thread once the TEE DKG bootstrap coordination completes.
    pub fn set_pending_tee_bootstrap(&self, payload: crate::tee_bootstrap_v2::TeeBootstrapV2) {
        self.lock_state().pending_tee_bootstrap = Some(payload);
    }

    /// Returns a clone of the pending TEE bootstrap payload for a block-1 proposal.
    ///
    /// Proposal construction is retryable: consuming this value while building a
    /// candidate would make a rejected first candidate permanently prevent every
    /// later block-1 proposal. The payload is bounded and immutable after startup,
    /// so cloning it preserves identical bytes across retries.
    pub fn pending_tee_bootstrap(&self) -> Option<crate::tee_bootstrap_v2::TeeBootstrapV2> {
        self.lock_state().pending_tee_bootstrap.clone()
    }

    /// Records a summary from a successfully executed block header.
    ///
    /// This does not make process-local memory authoritative for accounting.
    /// It only allows immediate descendants to settle recently finalized
    /// ancestors while Reth has accepted the block in its tree but the generic
    /// provider has not exposed the canonical header yet.
    pub fn record_execution_summary(
        &self,
        block_number: u64,
        block_hash: B256,
        summary: ExecutionSummaryArtifact,
        timestamp: u64,
    ) {
        self.record_execution_summary_inner(block_number, block_hash, summary, timestamp, None);
    }

    /// Records a summary together with the state root committed by the same
    /// exact block header.
    pub fn record_execution_summary_with_state_root(
        &self,
        block_number: u64,
        block_hash: B256,
        summary: ExecutionSummaryArtifact,
        timestamp: u64,
        state_root: B256,
    ) {
        self.record_execution_summary_inner(
            block_number,
            block_hash,
            summary,
            timestamp,
            Some(state_root),
        );
    }

    fn record_execution_summary_inner(
        &self,
        block_number: u64,
        block_hash: B256,
        summary: ExecutionSummaryArtifact,
        timestamp: u64,
        state_root: Option<B256>,
    ) {
        let mut state = self.lock_state();
        if let Some(entry) = state
            .execution_summary_cache
            .iter_mut()
            .find(|entry| entry.block_number == block_number && entry.block_hash == block_hash)
        {
            entry.summary = summary;
            entry.timestamp = timestamp;
            if state_root.is_some() {
                entry.state_root = state_root;
            }
            return;
        }

        while state.execution_summary_cache.len() >= EXECUTION_SUMMARY_CACHE_LIMIT {
            let _ = state.execution_summary_cache.pop_front();
        }
        state
            .execution_summary_cache
            .push_back(ExecutionSummaryCacheEntry {
                block_number,
                block_hash,
                summary,
                timestamp,
                state_root,
            });
    }

    /// Returns a cached summary for an already executed `(number, hash)` pair.
    pub fn cached_execution_summary(
        &self,
        block_number: u64,
        block_hash: B256,
    ) -> Option<CachedExecutionSummary> {
        let state = self.lock_state();
        state
            .execution_summary_cache
            .iter()
            .rev()
            .find(|entry| entry.block_number == block_number && entry.block_hash == block_hash)
            .map(|entry| CachedExecutionSummary {
                summary: entry.summary,
                timestamp: entry.timestamp,
                state_root: entry.state_root,
            })
    }

    /// Sets the initial validator set expected in genesis.
    ///
    /// Used by the executor during fresh bootstrap to verify that the
    /// on-chain genesis state matches the local consensus bootstrap config.
    pub fn set_genesis_validators(&self, validators: GenesisValidators) {
        let mut state = self.lock_state();
        state.genesis_validators = Some(validators);
    }

    /// Returns and clears the expected genesis validator set.
    pub fn take_genesis_validators(&self) -> Option<GenesisValidators> {
        let mut state = self.lock_state();
        state.genesis_validators.take()
    }

    /// Peeks at expected genesis validators without consuming them.
    pub fn peek_genesis_validators(&self) -> Option<GenesisValidators> {
        let state = self.lock_state();
        state.genesis_validators.clone()
    }

    /// Updates the last finalized block number in the consensus status.
    ///
    /// Called by the application handler after processing a finalization,
    /// since the reporter only knows the Simplex view number (not the
    /// actual block height, which can differ when proposals are missed).
    pub fn set_last_finalized_block_number(&self, number: u64) {
        let mut state = self.lock_state();
        state.consensus_status.last_finalized_block = number;
    }

    /// Updates the finalized consensus status snapshot.
    pub fn set_consensus_status(&self, status: ConsensusStatus) {
        let mut state = self.lock_state();
        state.consensus_status = status;
    }

    /// Returns a snapshot of the current consensus status.
    pub fn consensus_status(&self) -> ConsensusStatus {
        let state = self.lock_state();
        state.consensus_status.clone()
    }

    /// Publishes whether the active in-memory DKG material contains this
    /// process's private threshold share.
    pub fn set_local_threshold_share_present(&self, present: bool) {
        self.lock_state().local_threshold_share_present = present;
    }

    /// Whether the local process currently has a usable active threshold share.
    ///
    /// Local share possession and network-level VRF safety are independent
    /// facts: a shareless verifier can observe healthy public material, while a
    /// signer can retain a private share that is unusable after expiry.
    pub fn has_threshold_shares(&self) -> bool {
        let state = self.lock_state();
        local_threshold_share_is_usable(&state)
    }

    /// Returns the consensus snapshot and its derived local-share report under
    /// one lock so RPC cannot combine values from different transitions.
    pub fn consensus_status_with_threshold_shares(&self) -> (ConsensusStatus, bool) {
        let state = self.lock_state();
        (
            state.consensus_status.clone(),
            local_threshold_share_is_usable(&state),
        )
    }

    /// Installs the finalization fetcher channel. Called once at marshal-start
    /// (validator and follower paths both register one) with the sender; the
    /// consensus thread drains the matching [`FinalizationFetcherRx`] and answers
    /// from the marshal. Returns the receiver to hand to the drainer.
    pub fn set_finalization_fetcher(&self) -> FinalizationFetcherRx {
        let (tx, rx) = mpsc::unbounded_channel();
        self.lock_state().finalization_fetcher = Some(tx);
        rx
    }

    /// Requests the finalized certificate + block bytes for `height` from the
    /// consensus thread (used by the `rudis_getFinalization` RPC handler).
    ///
    /// Returns `None` if no fetcher is installed (consensus not serving), the
    /// drainer dropped the reply (height not available), or the channel is
    /// closed. The reply travels back over a one-shot so concurrent requests do
    /// not interfere.
    pub async fn request_finalization(&self, height: u64) -> Option<FinalizedBlockBytes> {
        let sender = {
            let state = self.lock_state();
            state.finalization_fetcher.clone()?
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        sender.send((height, reply_tx)).ok()?;
        reply_rx.await.ok().flatten()
    }
}

fn local_threshold_share_is_usable(state: &BridgeState) -> bool {
    state.local_threshold_share_present
        && state
            .consensus_status
            .randomness_status
            .has_threshold_shares()
}

impl Default for ConsensusExecutionBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for ConsensusExecutionBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsensusExecutionBridge").finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn randomness_status_maps_operator_flags() {
        for (status, expected_active, expected_shares) in [
            (RandomnessStatus::Unknown, false, false),
            (RandomnessStatus::Healthy, true, true),
            (RandomnessStatus::Preparing, true, true),
            (RandomnessStatus::PendingActivation, true, true),
            (RandomnessStatus::Grace, true, true),
            (RandomnessStatus::Degraded, true, false),
            (RandomnessStatus::Expired, false, false),
        ] {
            assert_eq!(status.is_consensus_active(), expected_active, "{status:?}");
            assert_eq!(status.has_threshold_shares(), expected_shares, "{status:?}");
        }
    }

    #[test]
    fn test_bridge_recovers_poisoned_lock_without_panicking() {
        let bridge = ConsensusExecutionBridge::new();
        let poisoned = bridge.clone();

        let _ = std::panic::catch_unwind(move || {
            let _guard = poisoned.inner.lock().unwrap();
            panic!("poison bridge lock");
        });

        bridge.set_genesis_validators(GenesisValidators {
            validators: vec![GenesisValidator {
                address: Address::with_last_byte(0x11),
                consensus_pubkey: [1u8; 48],
            }],
            epoch_length_blocks: 100,
        });

        let validators = bridge.peek_genesis_validators().unwrap();
        assert_eq!(validators.validators.len(), 1);
        assert_eq!(validators.epoch_length_blocks, 100);
    }

    #[test]
    fn test_bridge_last_finalized_block_number() {
        let bridge = ConsensusExecutionBridge::new();
        assert_eq!(bridge.consensus_status().last_finalized_block, 0);

        bridge.set_last_finalized_block_number(42);
        assert_eq!(bridge.consensus_status().last_finalized_block, 42);

        // Reporter sets status (with view as block number placeholder).
        bridge.set_consensus_status(ConsensusStatus {
            current_view: 100,
            last_finalized_block: 0, // placeholder
            ..Default::default()
        });
        // Handler updates the real block number after.
        bridge.set_last_finalized_block_number(99);
        assert_eq!(bridge.consensus_status().last_finalized_block, 99);
    }

    #[test]
    fn bridge_reports_only_usable_active_local_threshold_share() {
        let bridge = ConsensusExecutionBridge::new();
        bridge.set_consensus_status(ConsensusStatus {
            randomness_status: RandomnessStatus::Healthy,
            ..Default::default()
        });
        assert!(
            !bridge.has_threshold_shares(),
            "global Healthy status must not imply a local private share"
        );

        bridge.set_local_threshold_share_present(true);
        assert!(bridge.has_threshold_shares());

        for (status, expected) in [
            (RandomnessStatus::Preparing, true),
            (RandomnessStatus::PendingActivation, true),
            (RandomnessStatus::Grace, true),
            (RandomnessStatus::Degraded, false),
            (RandomnessStatus::Expired, false),
            (RandomnessStatus::Unknown, false),
            (RandomnessStatus::Healthy, true),
        ] {
            bridge.set_consensus_status(ConsensusStatus {
                randomness_status: status,
                ..Default::default()
            });
            assert_eq!(bridge.has_threshold_shares(), expected, "{status:?}");
            let (snapshot, snapshot_has_share) = bridge.consensus_status_with_threshold_shares();
            assert_eq!(snapshot.randomness_status, status);
            assert_eq!(
                snapshot_has_share, expected,
                "atomic snapshot for {status:?}"
            );
        }

        bridge.set_local_threshold_share_present(false);
        assert!(!bridge.has_threshold_shares());
    }
}
