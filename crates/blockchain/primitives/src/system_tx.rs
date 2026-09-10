//! Deterministic begin/end-block system-transaction primitives.
//!
//! Outbe represents runtime system transactions as ordinary signed Ethereum
//! legacy transaction artifacts so standard `eth_*` RPC methods can expose their
//! receipts and logs. The artifacts are consensus inputs only: execution uses
//! `transact_system_call` with `SYSTEM_ADDRESS` as the EVM caller, while the
//! signed transaction authenticates the proposer and fixes receipt/tx ordering.
//!
//! Begin-zone system transactions run before user transactions in this order:
//!
//! 1. [`SystemTxKind::CertifiedParentAccounting`] for block `>= 2`.
//! 2. [`SystemTxKind::LateFinalizeCredits`] for block `>= 2` (mandatory
//!    inclusion-window phase: records late finalize credits and settles the
//!    matured `N+K` fee escrow).
//! 3. [`SystemTxKind::OcompLifecycleBegin`] once the OCOMP lifecycle is active.
//! 4. [`SystemTxKind::CycleTick`] for block `>= 1`.
//! 5. [`SystemTxKind::RewardsGemDelivery`] for block `>= 1`.
//! 6. [`SystemTxKind::BoundaryOutcome`] iff the header carries a BoundaryOutcome
//!    (mandatory at block `1` under V2 for the genesis bootstrap).
//! 7. [`SystemTxKind::TeeBootstrap`] in the one-time bootstrap block.
//! 8. [`SystemTxKind::OracleSlashWindow`] for block `>= 1`.
//! 9. [`SystemTxKind::HookEvents`] for block `>= 1` (receipt container for
//!    whitelisted pre-exec hook logs; no lifecycle re-execution).
//!
//! Once active, [`SystemTxKind::OcompTerminalRequest`] is the sole end-zone
//! transaction. It follows every user transaction and the compressed-entity
//! seal.
//!
//! ## V2 codec
//!
//! This module ships the V2 wire codec exclusively. V1 system-tx input bytes
//! (selectors `OSF1`/`OSC1`/`OSB1`/`OSO1` with version byte `1`) are rejected
//! at every height. Rewards adds `OSG2`; OCOMP adds `OSE2` and `OSR2`, all
//! without changing the V2 version byte. Greenfield rollout.
//!
//! The split helper below is structural-only: it rejects reserved-address
//! transactions outside the contiguous system zones and rejects wrong-zone or
//! out-of-order system tx kinds. [`validate_active_system_tx_set`] performs the
//! separate membership check for a concrete block number and BoundaryOutcome
//! presence.

use alloy_consensus::{SignableTransaction, Transaction as AlloyTransaction, TxLegacy};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{Bytes, TxKind, B256, U256};
use reth_ethereum::TransactionSigned;
use reth_primitives_traits::SignedTransaction;

use crate::{
    consensus::DkgBoundaryArtifact,
    consensus_metadata::CertifiedParentAccountingMetadata,
    error::PrecompileError,
    reshare_artifact::{
        decode_boundary_artifact, decode_late_finalize_credits_artifact, encode_boundary_artifact,
        encode_late_finalize_credits_artifact, LateFinalizeCreditsArtifact,
    },
};

pub use crate::addresses::OUTBE_SYSTEM_TX_ADDRESS;
pub use outbe_ocomp_protocol::abi::{
    OCOMP_LIFECYCLE_BEGIN_SELECTOR, OCOMP_TERMINAL_REQUEST_SELECTOR,
};

/// Version byte immediately after the 4-byte kind selector in system-tx input.
///
/// Bumped to `2` for V2 Certified-Parent Accounting. Decoder
/// rejects any other value, so V1 bodies with `1` are rejected at every height.
pub const SYSTEM_TX_INPUT_VERSION: u8 = 2;

/// Selector for [`SystemTxKind::CertifiedParentAccounting`] (V2 OSA3).
pub const CERTIFIED_PARENT_ACCOUNTING_SELECTOR: [u8; 4] = [b'O', b'S', b'A', b'3'];
/// Selector for [`SystemTxKind::CycleTick`] (V2 OSC2).
pub const CYCLE_TICK_SELECTOR: [u8; 4] = [b'O', b'S', b'C', b'2'];
/// Selector for [`SystemTxKind::RewardsGemDelivery`] (V2 OSG2).
pub const REWARDS_GEM_DELIVERY_SELECTOR: [u8; 4] = [b'O', b'S', b'G', b'2'];
/// Selector for [`SystemTxKind::BoundaryOutcome`] (V2 OSB2).
pub const BOUNDARY_OUTCOME_SELECTOR: [u8; 4] = [b'O', b'S', b'B', b'2'];
/// Selector for [`SystemTxKind::OracleSlashWindow`] (V2 OSO2).
pub const ORACLE_SLASH_WINDOW_SELECTOR: [u8; 4] = [b'O', b'S', b'O', b'2'];
/// Selector for the evidence-carrying V1 TEE bootstrap payload.
///
/// `OST2` was never a valid selector for this greenfield chain. Only `OST3`
/// is produced or accepted, in both `DcapRequired` and `GramineDirectDev`
/// networks.
pub const TEE_BOOTSTRAP_SELECTOR: [u8; 4] = [b'O', b'S', b'T', b'3'];
/// Selector for [`SystemTxKind::LateFinalizeCredits`].
pub const LATE_FINALIZE_CREDITS_SELECTOR: [u8; 4] = [b'O', b'S', b'L', b'2'];
/// Selector for [`SystemTxKind::HookEvents`] (V2 OSH2).
pub const HOOK_EVENTS_SELECTOR: [u8; 4] = [b'O', b'S', b'H', b'2'];

/// Hard cap on system transactions emitted in a block.
pub const MAX_SYSTEM_TXS_PER_BLOCK: u8 = 16;

/// Highest block number that bootstraps the chain without Phase 1
/// (`CertifiedParentAccounting`). Block `n` runs Phase 1 in pre-execution iff
/// `n >= GENESIS_BOOTSTRAP_BLOCK_NUMBER + 1`. sets this to `1` so
/// Phase 1 begins at block `2` while block `1` still carries the genesis
/// `BoundaryOutcome` as its first begin-zone system transaction.
pub const GENESIS_BOOTSTRAP_BLOCK_NUMBER: u64 = 1;

/// Consensus gas limit for the evidence-heavy one-time block-1 bootstrap.
pub const BOOTSTRAP_BLOCK_GAS_LIMIT: u64 = 500_000_000;
/// Consensus gas limit before bootstrap and from block 2 onward.
pub const STEADY_BLOCK_GAS_LIMIT: u64 = 30_000_000;

/// Height-selected block gas schedule committed by `ResourceScheduleV1`.
pub const fn protocol_block_gas_limit(block_number: u64) -> u64 {
    if block_number == GENESIS_BOOTSTRAP_BLOCK_NUMBER {
        BOOTSTRAP_BLOCK_GAS_LIMIT
    } else {
        STEADY_BLOCK_GAS_LIMIT
    }
}

/// Internal execution gas limit used by the Outbe-aware system-call path.
/// This value is never used as the visible `gas_limit` of the signed
/// transaction envelope; visible envelopes use their Ethereum intrinsic gas so
/// generic block replay/import tools do not reject them as exceeding the
/// block gas limit.
pub const SYSTEM_TX_ARTIFACT_GAS_LIMIT: u64 = 10_000_000_000;

/// Visible compressed-entity gas reserved for the OCOMP lifecycle phase.
///
/// Terminal expiry can request the first Tribute-partition retirement in the
/// block. Its current cleanup precharge is 15,000 gas; the additional 5,000
/// keeps the mandatory phase from sitting exactly on that boundary.
pub const OCOMP_LIFECYCLE_CE_GAS_RESERVE: u64 = 20_000;

/// Minimum visible gas charged by a system transaction envelope.
pub const SYSTEM_TX_VISIBLE_GAS_FLOOR: u64 = 21_000;

const SYSTEM_TX_ZERO_BYTE_GAS: u64 = 4;
pub const SYSTEM_TX_NON_ZERO_BYTE_GAS: u64 = 16;

/// Body-zone position of a system tx.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyZone {
    BeginBlock,
    EndBlock,
}

/// Consensus activation of the PoC OCOMP system-transaction lifecycle.
///
/// The production default is disabled. OCM-26 is the only task that may arm
/// the canonical devnet schedule; earlier tasks can exercise the exact fork
/// boundary by passing an explicit activation to layout validation.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum OcompLifecycleActivation {
    #[default]
    Disabled,
    AtBlock(u64),
}

impl OcompLifecycleActivation {
    #[must_use]
    pub const fn at_block(height: u64) -> Self {
        Self::AtBlock(height)
    }

    #[must_use]
    pub const fn is_active_at(self, block_number: u64) -> bool {
        match self {
            Self::Disabled => false,
            Self::AtBlock(height) => block_number >= height,
        }
    }
}

/// begin_block system transaction kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SystemTxKind {
    CertifiedParentAccounting,
    /// mandatory begin-zone phase (blocks `>= 2`) that records verified
    /// late-finalize credits within the `K`-block inclusion window and settles
    /// matured per-block fee escrows. Ordered immediately after Phase 1 (CPA).
    LateFinalizeCredits,
    /// OCOMP begin-zone lifecycle slot. In the PoC this expires due jobs after
    /// the reserved no-op barrier and before ordinary user transactions.
    OcompLifecycleBegin,
    CycleTick,
    /// Mandatory Rewards-owned retryable delivery of one prepared UTC-day Gem batch.
    RewardsGemDelivery,
    BoundaryOutcome,
    /// Phase 3b: one-time TEE registry bootstrap (present only in the bootstrap
    /// block; reads the same-block `CommitteeSnapshotStore` written by Phase 3a).
    TeeBootstrap,
    OracleSlashWindow,
    /// Receipt container for whitelisted pre-exec hook events (`Vote`, `Update`, ...).
    HookEvents,
    /// Sole end-zone system transaction. The executor seals compressed
    /// entities before dispatching this terminal request slot.
    OcompTerminalRequest,
}

impl SystemTxKind {
    pub const fn selector(self) -> [u8; 4] {
        match self {
            Self::CertifiedParentAccounting => CERTIFIED_PARENT_ACCOUNTING_SELECTOR,
            Self::LateFinalizeCredits => LATE_FINALIZE_CREDITS_SELECTOR,
            Self::OcompLifecycleBegin => OCOMP_LIFECYCLE_BEGIN_SELECTOR,
            Self::CycleTick => CYCLE_TICK_SELECTOR,
            Self::RewardsGemDelivery => REWARDS_GEM_DELIVERY_SELECTOR,
            Self::BoundaryOutcome => BOUNDARY_OUTCOME_SELECTOR,
            Self::TeeBootstrap => TEE_BOOTSTRAP_SELECTOR,
            Self::OracleSlashWindow => ORACLE_SLASH_WINDOW_SELECTOR,
            Self::HookEvents => HOOK_EVENTS_SELECTOR,
            Self::OcompTerminalRequest => OCOMP_TERMINAL_REQUEST_SELECTOR,
        }
    }

    pub const fn body_zone(self) -> BodyZone {
        match self {
            Self::OcompTerminalRequest => BodyZone::EndBlock,
            Self::CertifiedParentAccounting
            | Self::LateFinalizeCredits
            | Self::OcompLifecycleBegin
            | Self::CycleTick
            | Self::RewardsGemDelivery
            | Self::BoundaryOutcome
            | Self::TeeBootstrap
            | Self::OracleSlashWindow
            | Self::HookEvents => BodyZone::BeginBlock,
        }
    }

    /// Whether a non-success EVM result (`Revert` / `Halt`) executing this
    /// begin-zone phase must fail the whole block instead of being recorded as a
    /// soft `status = 0` receipt and skipped. This classification applies only
    /// while the result fits the aggregate internal-work budget. An OOG consumes
    /// the full system-call gas limit; aggregate budget exhaustion always fails
    /// atomically before a receipt, including for a phase classified as soft.
    ///
    /// Consensus- and economic-critical phases are one-shot: their work cannot
    /// be retried by a later block, so a swallowed revert permanently loses it -
    /// stranded validator-fee escrow (`LateFinalizeCredits`), a dropped day of
    /// emission / terminal Metadosis (`CycleTick`), a skipped reshare / validator
    /// set activation (`BoundaryOutcome`), or unrecorded finalized-parent
    /// accounting (`CertifiedParentAccounting`). For these, a revert is a hard
    /// `BlockExecutionError`: the block is rejected on every validator
    /// deterministically (the revert is a function of committed chain state, the
    /// same for all proposers), honoring the "never silent stall / terminal
    /// failure is fatal" invariant rather than silently forfeiting real money or
    /// a protocol-state transition.
    ///
    /// `TeeBootstrap` is mandatory at block 1: a revert would commit a genesis
    /// committee that cannot execute confidential transactions, so it fails the
    /// block. `RewardsGemDelivery` is deliberately soft so its durable FIFO
    /// head retries in a later block; `OracleSlashWindow` and `HookEvents` also
    /// remain soft.
    pub const fn revert_fails_block(self) -> bool {
        match self {
            Self::CertifiedParentAccounting
            | Self::LateFinalizeCredits
            | Self::OcompLifecycleBegin
            | Self::CycleTick
            | Self::BoundaryOutcome
            | Self::TeeBootstrap
            | Self::OcompTerminalRequest => true,
            Self::RewardsGemDelivery | Self::OracleSlashWindow | Self::HookEvents => false,
        }
    }

    pub const fn begin_order(self) -> Option<u8> {
        match self {
            Self::CertifiedParentAccounting => Some(0),
            Self::LateFinalizeCredits => Some(1),
            Self::OcompLifecycleBegin => Some(2),
            Self::CycleTick => Some(3),
            Self::RewardsGemDelivery => Some(4),
            Self::BoundaryOutcome => Some(5),
            Self::TeeBootstrap => Some(6),
            Self::OracleSlashWindow => Some(7),
            Self::HookEvents => Some(8),
            Self::OcompTerminalRequest => None,
        }
    }

    pub const fn end_order(self) -> Option<u8> {
        match self {
            Self::OcompTerminalRequest => Some(0),
            Self::CertifiedParentAccounting
            | Self::LateFinalizeCredits
            | Self::OcompLifecycleBegin
            | Self::CycleTick
            | Self::RewardsGemDelivery
            | Self::BoundaryOutcome
            | Self::TeeBootstrap
            | Self::OracleSlashWindow
            | Self::HookEvents => None,
        }
    }

    fn order_in(self, zone: BodyZone) -> Option<u8> {
        match zone {
            BodyZone::BeginBlock => self.begin_order(),
            BodyZone::EndBlock => self.end_order(),
        }
    }
}

/// Versioned calldata body system transactions.
///
/// completed the wire-format swap: Phase 1 system-tx input now
/// carries the V2 slim
/// [`crate::consensus_metadata::CertifiedParentAccountingMetadata`]
/// instead of the V1 `ConsensusMetadataEnvelope`. The V2 payload omits the
/// dead `encoded_finalize_votes` field (V2 signer bitmap is authoritative)
/// and carries the V2 `committee_set_hash`, `vrf_material_version`,
/// `vrf_group_public_key_hash`, and `proof_kind` fields the verifier needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemTxInputV2 {
    CertifiedParentAccounting {
        metadata: CertifiedParentAccountingMetadata,
    },
    LateFinalizeCredits {
        artifact: LateFinalizeCreditsArtifact,
    },
    OcompLifecycleBegin,
    CycleTick,
    RewardsGemDelivery,
    BoundaryOutcome {
        artifact: DkgBoundaryArtifact,
    },
    TeeBootstrap {
        payload: crate::tee_bootstrap_v2::TeeBootstrapV2,
    },
    OracleSlashWindow,
    HookEvents,
    OcompTerminalRequest,
}

impl SystemTxInputV2 {
    pub const fn kind(&self) -> SystemTxKind {
        match self {
            Self::CertifiedParentAccounting { .. } => SystemTxKind::CertifiedParentAccounting,
            Self::LateFinalizeCredits { .. } => SystemTxKind::LateFinalizeCredits,
            Self::OcompLifecycleBegin => SystemTxKind::OcompLifecycleBegin,
            Self::CycleTick => SystemTxKind::CycleTick,
            Self::RewardsGemDelivery => SystemTxKind::RewardsGemDelivery,
            Self::BoundaryOutcome { .. } => SystemTxKind::BoundaryOutcome,
            Self::TeeBootstrap { .. } => SystemTxKind::TeeBootstrap,
            Self::OracleSlashWindow => SystemTxKind::OracleSlashWindow,
            Self::HookEvents => SystemTxKind::HookEvents,
            Self::OcompTerminalRequest => SystemTxKind::OcompTerminalRequest,
        }
    }

    /// Encode as `selector(4) || version(1) || canonical_body`.
    pub fn encode(&self) -> Result<Bytes, SystemTxError> {
        let mut out = Vec::new();
        let selector = self.kind().selector();
        out.extend_from_slice(&selector);
        out.push(SYSTEM_TX_INPUT_VERSION);
        match self {
            Self::CertifiedParentAccounting { metadata } => {
                out.extend_from_slice(
                    metadata
                        .encode()
                        .map_err(SystemTxError::from_precompile)?
                        .as_ref(),
                );
            }
            Self::OcompLifecycleBegin
            | Self::CycleTick
            | Self::RewardsGemDelivery
            | Self::OracleSlashWindow
            | Self::HookEvents
            | Self::OcompTerminalRequest => {}
            Self::LateFinalizeCredits { artifact } => {
                // Empty batches encode to empty bytes - the mandatory tx then
                // carries an empty body and still drives the window-close settle.
                out.extend_from_slice(
                    encode_late_finalize_credits_artifact(artifact)
                        .map_err(SystemTxError::from_precompile)?
                        .as_ref(),
                );
            }
            Self::BoundaryOutcome { artifact } => {
                out.extend_from_slice(
                    encode_boundary_artifact(artifact)
                        .map_err(SystemTxError::from_precompile)?
                        .as_ref(),
                );
            }
            Self::TeeBootstrap { payload } => out.extend_from_slice(
                payload
                    .encode_canonical()
                    .map_err(|error| SystemTxError::Codec(error.to_string()))?
                    .as_ref(),
            ),
        }
        Ok(Bytes::from(out))
    }

    pub fn decode(data: &[u8]) -> Result<Self, SystemTxError> {
        if data.len() < 5 {
            return Err(SystemTxError::InputTooShort { len: data.len() });
        }
        let selector = selector_from_input(data)?;
        let kind = system_tx_kind_from_selector(selector)?;
        let version = data[4];
        if version != SYSTEM_TX_INPUT_VERSION {
            return Err(SystemTxError::UnsupportedVersion(version));
        }
        let body = &data[5..];
        match kind {
            SystemTxKind::CertifiedParentAccounting => Ok(Self::CertifiedParentAccounting {
                metadata: CertifiedParentAccountingMetadata::decode(body)
                    .map_err(SystemTxError::from_precompile)?,
            }),
            SystemTxKind::LateFinalizeCredits => Ok(Self::LateFinalizeCredits {
                // Empty body => empty (no-op) artifact; the matured-window close
                // still runs on execution.
                artifact: decode_late_finalize_credits_artifact(body)
                    .map_err(SystemTxError::from_precompile)?
                    .unwrap_or_default(),
            }),
            SystemTxKind::OcompLifecycleBegin => {
                if !body.is_empty() {
                    return Err(SystemTxError::UnexpectedBody {
                        kind,
                        len: body.len(),
                    });
                }
                Ok(Self::OcompLifecycleBegin)
            }
            SystemTxKind::CycleTick => {
                if !body.is_empty() {
                    return Err(SystemTxError::UnexpectedBody {
                        kind,
                        len: body.len(),
                    });
                }
                Ok(Self::CycleTick)
            }
            SystemTxKind::RewardsGemDelivery => {
                if !body.is_empty() {
                    return Err(SystemTxError::UnexpectedBody {
                        kind,
                        len: body.len(),
                    });
                }
                Ok(Self::RewardsGemDelivery)
            }
            SystemTxKind::OracleSlashWindow => {
                if !body.is_empty() {
                    return Err(SystemTxError::UnexpectedBody {
                        kind,
                        len: body.len(),
                    });
                }
                Ok(Self::OracleSlashWindow)
            }
            SystemTxKind::HookEvents => {
                if !body.is_empty() {
                    return Err(SystemTxError::UnexpectedBody {
                        kind,
                        len: body.len(),
                    });
                }
                Ok(Self::HookEvents)
            }
            SystemTxKind::OcompTerminalRequest => {
                if !body.is_empty() {
                    return Err(SystemTxError::UnexpectedBody {
                        kind,
                        len: body.len(),
                    });
                }
                Ok(Self::OcompTerminalRequest)
            }
            SystemTxKind::BoundaryOutcome => {
                let Some(artifact) =
                    decode_boundary_artifact(body).map_err(SystemTxError::from_precompile)?
                else {
                    return Err(SystemTxError::MissingBoundaryOutcomeBody);
                };
                Ok(Self::BoundaryOutcome { artifact })
            }
            SystemTxKind::TeeBootstrap => Ok(Self::TeeBootstrap {
                payload: crate::tee_bootstrap_v2::TeeBootstrapV2::decode_canonical(body)
                    .map_err(|error| SystemTxError::Codec(error.to_string()))?,
            }),
        }
    }
}

/// Executor cursor that names the next system-tx phase the block executor
/// expects to consume. introduces this enum so phase routing no
/// longer derives from `self.inner.receipts.len()` once Phase 1 is committed
/// in `apply_pre_execution_changes` (pre-execution) rather than the main tx
/// loop.
///
/// Invariants:
/// - On block `1` (genesis bootstrap), cursor starts at `CycleTick { body_index: 0 }`.
/// - On block `n >= GENESIS_BOOTSTRAP_BLOCK_NUMBER + 1`, cursor starts at
///   `Phase1Preexecuted { body_index: 0, tx_hash, receipt_index: 0 }` after
///   the executor has pre-built and committed the Phase 1 system tx.
/// - The cursor advances exactly once per consumed begin-zone system tx; on
///   reaching the first non-system tx (or block end) it is `UserTxs`.
/// - Encoded purely in-memory: never serialised, hashed, or part of any
///   wire format or `header.extra_data`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemTxPhase {
    /// Phase 1 (`CertifiedParentAccounting`) has been built, verified, and
    /// committed in pre-execution. The proposer-supplied body[`body_index`]
    /// must match `tx_hash` byte-for-byte and is validated without
    /// re-execution.
    Phase1Preexecuted {
        body_index: u8,
        tx_hash: B256,
        receipt_index: u8,
    },
    /// Next expected begin-zone tx is the mandatory (blocks `>= 2`)
    /// `LateFinalizeCredits` phase, ordered immediately after Phase 1.
    LateFinalizeCredits { body_index: u8 },
    /// OCOMP expiry/reset phase, present only once the PoC lifecycle fork is
    /// active and ordered before `CycleTick`.
    OcompLifecycleBegin { body_index: u8 },
    /// Next expected begin-zone tx is Phase 2 (`CycleTick`).
    CycleTick { body_index: u8 },
    /// Mandatory Rewards-owned delivery phase immediately after `CycleTick`.
    RewardsGemDelivery { body_index: u8 },
    /// Next expected begin-zone tx is the optional Phase 3
    /// (`BoundaryOutcome`); only emitted when the header carries a boundary
    /// outcome artifact.
    BoundaryOutcomeOptional { body_index: u8 },
    /// Next expected begin-zone tx is the optional Phase 3b
    /// (`TeeBootstrap`); present only in the one-time bootstrap block.
    TeeBootstrapOptional { body_index: u8 },
    /// Next expected begin-zone tx is Phase 4 (`OracleSlashWindow`).
    OracleSlashWindow { body_index: u8 },
    /// Next expected begin-zone tx is the mandatory `HookEvents` receipt carrier.
    HookEvents { body_index: u8 },
    /// All begin-zone system txs consumed. User transactions may execute until
    /// the optional end-zone transaction is consumed.
    UserTxs,
}

impl SystemTxPhase {
    /// Initial cursor for `block_number` given the configured genesis
    /// bootstrap threshold. Block `1` has no Phase 1 (genesis bootstrap),
    /// so its cursor starts at `CycleTick { body_index: 0 }`. Block `n` with
    /// `n >= genesis_bootstrap_block_number + 1` starts at
    /// `Phase1Preexecuted { body_index: 0, .. }` with a zero placeholder
    /// `tx_hash`; the executor overwrites the placeholder after the Phase 1
    /// preflight commits.
    pub const fn initial_for_block(block_number: u64, genesis_bootstrap_block_number: u64) -> Self {
        Self::initial_for_block_with_ocomp(block_number, genesis_bootstrap_block_number, false)
    }

    pub const fn initial_for_block_with_ocomp(
        block_number: u64,
        genesis_bootstrap_block_number: u64,
        ocomp_lifecycle_active: bool,
    ) -> Self {
        if block_number > genesis_bootstrap_block_number
            && block_number > GENESIS_BOOTSTRAP_BLOCK_NUMBER
        {
            Self::Phase1Preexecuted {
                body_index: 0,
                tx_hash: B256::ZERO,
                receipt_index: 0,
            }
        } else if block_number > 0 && ocomp_lifecycle_active {
            Self::OcompLifecycleBegin { body_index: 0 }
        } else {
            Self::CycleTick { body_index: 0 }
        }
    }

    /// The begin-zone system-tx kind the cursor expects to consume next, or
    /// `None` if the cursor is `UserTxs`.
    pub const fn expected_kind(&self) -> Option<SystemTxKind> {
        match self {
            Self::Phase1Preexecuted { .. } => Some(SystemTxKind::CertifiedParentAccounting),
            Self::LateFinalizeCredits { .. } => Some(SystemTxKind::LateFinalizeCredits),
            Self::OcompLifecycleBegin { .. } => Some(SystemTxKind::OcompLifecycleBegin),
            Self::CycleTick { .. } => Some(SystemTxKind::CycleTick),
            Self::RewardsGemDelivery { .. } => Some(SystemTxKind::RewardsGemDelivery),
            Self::BoundaryOutcomeOptional { .. } => Some(SystemTxKind::BoundaryOutcome),
            Self::TeeBootstrapOptional { .. } => Some(SystemTxKind::TeeBootstrap),
            Self::OracleSlashWindow { .. } => Some(SystemTxKind::OracleSlashWindow),
            Self::HookEvents { .. } => Some(SystemTxKind::HookEvents),
            Self::UserTxs => None,
        }
    }

    /// Body index of the next expected begin-zone system tx, or `None` if
    /// the cursor is `UserTxs`.
    pub const fn body_index(&self) -> Option<u8> {
        match self {
            Self::Phase1Preexecuted { body_index, .. }
            | Self::LateFinalizeCredits { body_index }
            | Self::OcompLifecycleBegin { body_index }
            | Self::CycleTick { body_index }
            | Self::RewardsGemDelivery { body_index }
            | Self::BoundaryOutcomeOptional { body_index }
            | Self::TeeBootstrapOptional { body_index }
            | Self::OracleSlashWindow { body_index }
            | Self::HookEvents { body_index } => Some(*body_index),
            Self::UserTxs => None,
        }
    }

    /// Advance the cursor after a successful begin-zone system-tx commit.
    /// Given the cursor's current variant and whether the current block
    /// carries a boundary-outcome artifact, returns the next cursor
    /// position. Once HookEvents is consumed, the cursor transitions to
    /// `UserTxs`.
    ///
    /// `has_boundary_outcome` controls whether Phase 3
    /// (`BoundaryOutcomeOptional`) is interleaved between
    /// `RewardsGemDelivery` and `OracleSlashWindow`. The flag mirrors the
    /// block-1 invariant:
    /// at block 1, V2 always carries a boundary outcome (genesis bootstrap),
    /// so `has_boundary_outcome = true` is the canonical path there.
    ///
    /// `has_tee_bootstrap` interleaves the optional Phase 3b
    /// (`TeeBootstrapOptional`) after `BoundaryOutcome` (or after
    /// `RewardsGemDelivery` if no boundary outcome) and before
    /// `OracleSlashWindow`. It is true only in the one-time bootstrap block.
    pub const fn advance_after_commit(
        self,
        has_boundary_outcome: bool,
        has_tee_bootstrap: bool,
    ) -> Self {
        self.advance_after_commit_with_ocomp(has_boundary_outcome, has_tee_bootstrap, false)
    }

    pub const fn advance_after_commit_with_ocomp(
        self,
        has_boundary_outcome: bool,
        has_tee_bootstrap: bool,
        ocomp_lifecycle_active: bool,
    ) -> Self {
        match self {
            Self::Phase1Preexecuted { body_index, .. } => Self::LateFinalizeCredits {
                body_index: body_index + 1,
            },
            Self::LateFinalizeCredits { body_index } => {
                if ocomp_lifecycle_active {
                    Self::OcompLifecycleBegin {
                        body_index: body_index + 1,
                    }
                } else {
                    Self::CycleTick {
                        body_index: body_index + 1,
                    }
                }
            }
            Self::OcompLifecycleBegin { body_index } => Self::CycleTick {
                body_index: body_index + 1,
            },
            Self::CycleTick { body_index } => Self::RewardsGemDelivery {
                body_index: body_index + 1,
            },
            Self::RewardsGemDelivery { body_index } => {
                if has_boundary_outcome {
                    Self::BoundaryOutcomeOptional {
                        body_index: body_index + 1,
                    }
                } else if has_tee_bootstrap {
                    Self::TeeBootstrapOptional {
                        body_index: body_index + 1,
                    }
                } else {
                    Self::OracleSlashWindow {
                        body_index: body_index + 1,
                    }
                }
            }
            Self::BoundaryOutcomeOptional { body_index } => {
                if has_tee_bootstrap {
                    Self::TeeBootstrapOptional {
                        body_index: body_index + 1,
                    }
                } else {
                    Self::OracleSlashWindow {
                        body_index: body_index + 1,
                    }
                }
            }
            Self::TeeBootstrapOptional { body_index } => Self::OracleSlashWindow {
                body_index: body_index + 1,
            },
            Self::OracleSlashWindow { body_index } => Self::HookEvents {
                body_index: body_index + 1,
            },
            Self::HookEvents { .. } | Self::UserTxs => Self::UserTxs,
        }
    }
}

/// Structural split of block transactions into system begin-prefix, user middle,
/// and system end-suffix.
#[derive(Debug, Clone)]
pub struct SystemTxLayout<'a> {
    pub begin: Vec<&'a TransactionSigned>,
    pub user: Vec<&'a TransactionSigned>,
    pub end: Vec<&'a TransactionSigned>,
}

impl<'a> SystemTxLayout<'a> {
    pub fn is_empty(&self) -> bool {
        self.begin.is_empty() && self.user.is_empty() && self.end.is_empty()
    }

    pub fn system_tx_count(&self) -> usize {
        self.begin.len() + self.end.len()
    }

    pub fn begin_block_kinds(&self) -> Result<Vec<SystemTxKind>, SystemTxError> {
        self.begin
            .iter()
            .map(|tx| decode_system_tx_kind(tx))
            .collect()
    }

    pub fn end_block_kinds(&self) -> Result<Vec<SystemTxKind>, SystemTxError> {
        self.end
            .iter()
            .map(|tx| decode_system_tx_kind(tx))
            .collect()
    }

    /// True if the begin zone contains a system tx of `kind`. Used to derive the
    /// layout-signaled optional-phase flags (e.g. the one-time
    /// [`SystemTxKind::TeeBootstrap`]). A decode failure - which a
    /// successful [`split_system_layout`] precludes - is treated as absent.
    pub fn has_begin_kind(&self, kind: SystemTxKind) -> bool {
        self.begin_block_kinds()
            .map(|kinds| kinds.contains(&kind))
            .unwrap_or(false)
    }
}

/// Errors returned by deterministic system-tx helpers.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SystemTxError {
    #[error("system tx input too short: {len} bytes")]
    InputTooShort { len: usize },
    #[error("unknown system tx selector: 0x{0:02x?}")]
    UnknownSelector([u8; 4]),
    #[error("unsupported system tx input version: {0}")]
    UnsupportedVersion(u8),
    #[error("unexpected body for {kind:?}: {len} bytes")]
    UnexpectedBody { kind: SystemTxKind, len: usize },
    #[error("missing boundary outcome body")]
    MissingBoundaryOutcomeBody,
    #[error("system tx codec error: {0}")]
    Codec(String),
    #[error("calldata kind mismatch: expected {expected:?}, actual {actual:?}")]
    CalldataKindMismatch {
        expected: SystemTxKind,
        actual: SystemTxKind,
    },
    #[error("system tx ordinal {ordinal} exceeds max {max}")]
    OrdinalTooLarge { ordinal: u8, max: u8 },
    #[error("system tx nonce overflow for block {block_number}, ordinal {ordinal}")]
    NonceOverflow { block_number: u64, ordinal: u8 },
    #[error("system tx visible gas overflow for calldata length {len}")]
    VisibleGasOverflow { len: usize },
    #[error(
        "system tx gas limit below intrinsic gas: gas_limit={gas_limit}, intrinsic={intrinsic_gas}"
    )]
    GasLimitBelowIntrinsic { gas_limit: u64, intrinsic_gas: u64 },
    #[error(
        "system tx required gas exceeds block gas limit: required={required_gas}, block_limit={block_gas_limit}"
    )]
    VisibleGasPlanExceedsBlock {
        required_gas: u64,
        block_gas_limit: u64,
    },
    #[error("system tx visible gas plan contains more than one CycleTick")]
    DuplicateCycleTickGasBudget,
    #[error("system tx kind {kind:?} is in {actual:?} zone, expected {expected:?}")]
    SystemTxInWrongZone {
        kind: SystemTxKind,
        expected: BodyZone,
        actual: BodyZone,
    },
    #[error(
        "system tx kind order violation in {zone:?}: previous {previous:?}, current {current:?}"
    )]
    OutOfOrder {
        zone: BodyZone,
        previous: SystemTxKind,
        current: SystemTxKind,
    },
    #[error("reserved system tx found in user zone at transaction index {index}")]
    MidBlockSystemTx { index: usize },
    #[error("too many system txs in block: {actual} > {max}")]
    TooManySystemTxs { actual: usize, max: u8 },
    #[error(
        "active system tx set mismatch: expected begin {expected_begin:?}, expected end {expected_end:?}, actual begin {actual_begin:?}, actual end {actual_end:?}"
    )]
    ActiveSystemTxSetMismatch {
        expected_begin: Vec<SystemTxKind>,
        expected_end: Vec<SystemTxKind>,
        actual_begin: Vec<SystemTxKind>,
        actual_end: Vec<SystemTxKind>,
    },
    #[error(
        "V2 genesis bootstrap: block 1 must carry a BoundaryOutcome system tx (got has_boundary_outcome = false)"
    )]
    V2Block1MissingBoundaryOutcome,
    #[error("V2 genesis bootstrap: block 1 must carry TeeBootstrap")]
    V2Block1MissingTeeBootstrap,
    #[error("TeeBootstrap is only valid at block 1, got block {block_number}")]
    TeeBootstrapWrongHeight { block_number: u64 },
    #[error("V2 genesis bootstrap: block 1 must not carry user transactions (got {actual})")]
    V2Block1ContainsUserTransactions { actual: usize },
    #[error("phase1 tx decode failed: {0}")]
    Phase1TxDecode(String),
    #[error("phase1 tx signature recovery failed: {0}")]
    Phase1SignatureRecovery(String),
    #[error("phase1 tx must call OUTBE_SYSTEM_TX_ADDRESS")]
    Phase1WrongRecipient,
    #[error("phase1 tx must not transfer native value")]
    Phase1NonZeroValue,
    #[error("phase1 tx chain_id mismatch: expected {expected}, actual {actual:?}")]
    Phase1ChainIdMismatch { expected: u64, actual: Option<u64> },
    #[error("phase1 tx nonce mismatch: expected {expected}, actual {actual}")]
    Phase1NonceMismatch { expected: u64, actual: u64 },
    #[error("phase1 tx gas_limit mismatch: expected {expected}, actual {actual}")]
    Phase1GasLimitMismatch { expected: u64, actual: u64 },
    #[error("phase1 tx calldata mismatch")]
    Phase1CalldataMismatch,
    #[error("phase1 tx signature_hash mismatch")]
    Phase1SignatureHashMismatch,
    #[error("phase1 tx signer mismatch: expected {expected}, actual {actual}")]
    Phase1SignerMismatch {
        expected: alloy_primitives::Address,
        actual: alloy_primitives::Address,
    },
}

impl SystemTxError {
    fn from_precompile(error: PrecompileError) -> Self {
        Self::Codec(error.to_string())
    }
}

pub fn system_tx_kind_from_selector(selector: [u8; 4]) -> Result<SystemTxKind, SystemTxError> {
    match selector {
        CERTIFIED_PARENT_ACCOUNTING_SELECTOR => Ok(SystemTxKind::CertifiedParentAccounting),
        LATE_FINALIZE_CREDITS_SELECTOR => Ok(SystemTxKind::LateFinalizeCredits),
        OCOMP_LIFECYCLE_BEGIN_SELECTOR => Ok(SystemTxKind::OcompLifecycleBegin),
        CYCLE_TICK_SELECTOR => Ok(SystemTxKind::CycleTick),
        REWARDS_GEM_DELIVERY_SELECTOR => Ok(SystemTxKind::RewardsGemDelivery),
        BOUNDARY_OUTCOME_SELECTOR => Ok(SystemTxKind::BoundaryOutcome),
        TEE_BOOTSTRAP_SELECTOR => Ok(SystemTxKind::TeeBootstrap),
        ORACLE_SLASH_WINDOW_SELECTOR => Ok(SystemTxKind::OracleSlashWindow),
        HOOK_EVENTS_SELECTOR => Ok(SystemTxKind::HookEvents),
        OCOMP_TERMINAL_REQUEST_SELECTOR => Ok(SystemTxKind::OcompTerminalRequest),
        other => Err(SystemTxError::UnknownSelector(other)),
    }
}

pub fn selector_from_input(input: &[u8]) -> Result<[u8; 4], SystemTxError> {
    let Some(bytes) = input.get(..4) else {
        return Err(SystemTxError::InputTooShort { len: input.len() });
    };
    bytes
        .try_into()
        .map_err(|_| SystemTxError::InputTooShort { len: input.len() })
}

pub fn is_reserved_system_tx<T>(tx: &T) -> bool
where
    T: AlloyTransaction + ?Sized,
{
    tx.to() == Some(OUTBE_SYSTEM_TX_ADDRESS)
}

pub fn decode_system_tx_kind(tx: &TransactionSigned) -> Result<SystemTxKind, SystemTxError> {
    let input = SystemTxInputV2::decode(tx.input().as_ref())?;
    Ok(input.kind())
}

pub fn system_tx_nonce(block_number: u64, ordinal: u8) -> Result<u64, SystemTxError> {
    if ordinal >= MAX_SYSTEM_TXS_PER_BLOCK {
        return Err(SystemTxError::OrdinalTooLarge {
            ordinal,
            max: MAX_SYSTEM_TXS_PER_BLOCK,
        });
    }
    block_number
        .checked_mul(u64::from(MAX_SYSTEM_TXS_PER_BLOCK))
        .and_then(|base| base.checked_add(u64::from(ordinal)))
        .ok_or(SystemTxError::NonceOverflow {
            block_number,
            ordinal,
        })
}

/// Ethereum-compatible visible gas limit for a system tx envelope.
///
/// Outbe executes the system precompile with
/// [`SYSTEM_TX_ARTIFACT_GAS_LIMIT`] internally, but the signed transaction
/// stored in the block body only needs to be valid as an Ethereum legacy
/// envelope. Charging intrinsic calldata gas keeps system txs visible to
/// generic replay/import tooling without exposing the 100M internal lane.
pub fn system_tx_intrinsic_gas(calldata: &[u8]) -> Result<u64, SystemTxError> {
    calldata
        .iter()
        .try_fold(SYSTEM_TX_VISIBLE_GAS_FLOOR, |gas, byte| {
            let byte_gas = if *byte == 0 {
                SYSTEM_TX_ZERO_BYTE_GAS
            } else {
                SYSTEM_TX_NON_ZERO_BYTE_GAS
            };
            gas.checked_add(byte_gas)
        })
        .ok_or(SystemTxError::VisibleGasOverflow {
            len: calldata.len(),
        })
}

/// Backwards-compatible name for the intrinsic gas of a system envelope.
pub fn system_tx_visible_gas_limit(calldata: &[u8]) -> Result<u64, SystemTxError> {
    system_tx_intrinsic_gas(calldata)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SystemTxVisibleGasEntry {
    intrinsic_gas: u64,
    protocol_precharge: u64,
    gas_limit: u64,
}

/// Deterministic visible-gas allocation for the complete begin-system zone.
///
/// System envelopes reserve intrinsic gas plus any schedule-hashed protocol
/// precharge and phase-specific compressed-entity budget. `CycleTick` receives
/// the remaining block gas while preserving every mandatory phase reserve.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemTxVisibleGasPlan {
    entries: Vec<SystemTxVisibleGasEntry>,
    total_envelope_gas: u64,
}

impl SystemTxVisibleGasPlan {
    pub fn new(
        block_gas_limit: u64,
        system_txs: &[(SystemTxKind, Bytes)],
    ) -> Result<Self, SystemTxError> {
        let mut entries = Vec::with_capacity(system_txs.len());
        let mut required_total = 0u64;
        let mut cycle_ordinal = None;

        for (ordinal, (kind, calldata)) in system_txs.iter().enumerate() {
            let decoded = SystemTxInputV2::decode(calldata)?;
            let actual = decoded.kind();
            if actual != *kind {
                return Err(SystemTxError::CalldataKindMismatch {
                    expected: *kind,
                    actual,
                });
            }
            if *kind == SystemTxKind::CycleTick && cycle_ordinal.replace(ordinal).is_some() {
                return Err(SystemTxError::DuplicateCycleTickGasBudget);
            }
            let intrinsic_gas = system_tx_intrinsic_gas(calldata)?;
            let protocol_precharge = system_tx_protocol_precharge(&decoded)?;
            let ce_gas_reserve = system_tx_ce_gas_reserve(*kind);
            let gas_limit = intrinsic_gas
                .checked_add(protocol_precharge)
                .and_then(|gas| gas.checked_add(ce_gas_reserve))
                .ok_or(SystemTxError::VisibleGasPlanExceedsBlock {
                    required_gas: u64::MAX,
                    block_gas_limit,
                })?;
            required_total = required_total.checked_add(gas_limit).ok_or(
                SystemTxError::VisibleGasPlanExceedsBlock {
                    required_gas: u64::MAX,
                    block_gas_limit,
                },
            )?;
            entries.push(SystemTxVisibleGasEntry {
                intrinsic_gas,
                protocol_precharge,
                gas_limit,
            });
        }

        let remainder = block_gas_limit.checked_sub(required_total).ok_or(
            SystemTxError::VisibleGasPlanExceedsBlock {
                required_gas: required_total,
                block_gas_limit,
            },
        )?;
        let total_envelope_gas = if let Some(ordinal) = cycle_ordinal {
            let entry = entries
                .get_mut(ordinal)
                .ok_or(SystemTxError::DuplicateCycleTickGasBudget)?;
            entry.gas_limit = entry.gas_limit.checked_add(remainder).ok_or(
                SystemTxError::VisibleGasPlanExceedsBlock {
                    required_gas: required_total,
                    block_gas_limit,
                },
            )?;
            block_gas_limit
        } else {
            required_total
        };

        Ok(Self {
            entries,
            total_envelope_gas,
        })
    }

    #[must_use]
    pub fn intrinsic_gas(&self, ordinal: usize) -> Option<u64> {
        self.entries.get(ordinal).map(|entry| entry.intrinsic_gas)
    }

    #[must_use]
    pub fn gas_limit(&self, ordinal: usize) -> Option<u64> {
        self.entries.get(ordinal).map(|entry| entry.gas_limit)
    }

    #[must_use]
    pub fn protocol_precharge(&self, ordinal: usize) -> Option<u64> {
        self.entries
            .get(ordinal)
            .map(|entry| entry.protocol_precharge)
    }

    #[must_use]
    pub fn ce_gas_limit(&self, ordinal: usize) -> Option<u64> {
        self.entries
            .get(ordinal)
            .map(|entry| entry.gas_limit - entry.intrinsic_gas - entry.protocol_precharge)
    }

    #[must_use]
    pub const fn total_envelope_gas(&self) -> u64 {
        self.total_envelope_gas
    }
}

const fn system_tx_ce_gas_reserve(kind: SystemTxKind) -> u64 {
    match kind {
        SystemTxKind::OcompLifecycleBegin => OCOMP_LIFECYCLE_CE_GAS_RESERVE,
        _ => 0,
    }
}

fn system_tx_protocol_precharge(input: &SystemTxInputV2) -> Result<u64, SystemTxError> {
    let SystemTxInputV2::TeeBootstrap { payload } = input else {
        return Ok(0);
    };
    payload
        .protocol_precharge(
            &crate::tee_attestation_v1::SystemGasScheduleV1::normative(),
            &crate::tee_attestation_v1::TeeRegistryGasScheduleV1::normative(),
        )
        .map_err(|error| SystemTxError::Codec(error.to_string()))
}

pub fn build_unsigned_system_tx(
    kind: SystemTxKind,
    ordinal: u8,
    block_number: u64,
    chain_id: u64,
    calldata: Bytes,
) -> Result<TxLegacy, SystemTxError> {
    let gas_limit = system_tx_intrinsic_gas(calldata.as_ref())?;
    build_unsigned_system_tx_with_gas_limit(
        kind,
        ordinal,
        block_number,
        chain_id,
        calldata,
        gas_limit,
    )
}

pub fn build_unsigned_system_tx_with_gas_limit(
    kind: SystemTxKind,
    ordinal: u8,
    block_number: u64,
    chain_id: u64,
    calldata: Bytes,
    gas_limit: u64,
) -> Result<TxLegacy, SystemTxError> {
    let actual = SystemTxInputV2::decode(calldata.as_ref())?.kind();
    if actual != kind {
        return Err(SystemTxError::CalldataKindMismatch {
            expected: kind,
            actual,
        });
    }
    let intrinsic_gas = system_tx_intrinsic_gas(calldata.as_ref())?;
    if gas_limit < intrinsic_gas {
        return Err(SystemTxError::GasLimitBelowIntrinsic {
            gas_limit,
            intrinsic_gas,
        });
    }

    Ok(TxLegacy {
        chain_id: Some(chain_id),
        nonce: system_tx_nonce(block_number, ordinal)?,
        gas_price: 0,
        gas_limit,
        to: TxKind::Call(OUTBE_SYSTEM_TX_ADDRESS),
        value: U256::ZERO,
        input: calldata,
    })
}

/// Validate that a signed Phase 1 system transaction is the canonical
/// `CertifiedParentAccounting` witness for `expected_calldata`.
pub fn validate_phase1_witness_against(
    tx: &TransactionSigned,
    expected_calldata: &[u8],
    expected_proposer: alloy_primitives::Address,
    chain_id: u64,
    block_number: u64,
) -> Result<B256, SystemTxError> {
    let tx_hash = validate_phase1_envelope_shape(tx, expected_calldata, chain_id, block_number)?;
    let signer = tx
        .try_recover()
        .map_err(|error| SystemTxError::Phase1SignatureRecovery(error.to_string()))?;
    if signer != expected_proposer {
        return Err(SystemTxError::Phase1SignerMismatch {
            expected: expected_proposer,
            actual: signer,
        });
    }
    Ok(tx_hash)
}

/// Decode and validate a signed Phase 1 transaction from evidence bytes,
/// returning the recovered proposer and canonical calldata.
pub fn recover_phase1_proposer(
    tx_bytes: &[u8],
    chain_id: u64,
    block_number: u64,
) -> Result<(alloy_primitives::Address, Bytes), SystemTxError> {
    let mut tx_slice = tx_bytes;
    let tx = TransactionSigned::decode_2718(&mut tx_slice)
        .map_err(|error| SystemTxError::Phase1TxDecode(error.to_string()))?;
    if !tx_slice.is_empty() {
        return Err(SystemTxError::Phase1TxDecode(format!(
            "phase1 tx has {} trailing bytes after EIP-2718 envelope",
            tx_slice.len()
        )));
    }
    let calldata = tx.input().clone();
    validate_phase1_envelope_shape(&tx, calldata.as_ref(), chain_id, block_number)?;
    let proposer = tx
        .try_recover()
        .map_err(|error| SystemTxError::Phase1SignatureRecovery(error.to_string()))?;
    Ok((proposer, calldata))
}

fn validate_phase1_envelope_shape(
    tx: &TransactionSigned,
    calldata: &[u8],
    chain_id: u64,
    block_number: u64,
) -> Result<B256, SystemTxError> {
    if tx.to() != Some(OUTBE_SYSTEM_TX_ADDRESS) {
        return Err(SystemTxError::Phase1WrongRecipient);
    }
    if tx.value() != U256::ZERO {
        return Err(SystemTxError::Phase1NonZeroValue);
    }
    if tx.chain_id() != Some(chain_id) {
        return Err(SystemTxError::Phase1ChainIdMismatch {
            expected: chain_id,
            actual: tx.chain_id(),
        });
    }
    let expected_nonce = system_tx_nonce(block_number, 0)?;
    if tx.nonce() != expected_nonce {
        return Err(SystemTxError::Phase1NonceMismatch {
            expected: expected_nonce,
            actual: tx.nonce(),
        });
    }
    let expected_gas_limit = system_tx_visible_gas_limit(calldata)?;
    if tx.gas_limit() != expected_gas_limit {
        return Err(SystemTxError::Phase1GasLimitMismatch {
            expected: expected_gas_limit,
            actual: tx.gas_limit(),
        });
    }
    if tx.input().as_ref() != calldata {
        return Err(SystemTxError::Phase1CalldataMismatch);
    }
    let actual = SystemTxInputV2::decode(calldata)?.kind();
    if actual != SystemTxKind::CertifiedParentAccounting {
        return Err(SystemTxError::CalldataKindMismatch {
            expected: SystemTxKind::CertifiedParentAccounting,
            actual,
        });
    }
    let expected_unsigned = build_unsigned_system_tx(
        SystemTxKind::CertifiedParentAccounting,
        0,
        block_number,
        chain_id,
        Bytes::copy_from_slice(calldata),
    )?;
    if tx.signature_hash() != expected_unsigned.signature_hash() {
        return Err(SystemTxError::Phase1SignatureHashMismatch);
    }
    Ok(tx.signature_hash())
}

pub fn split_system_layout<'a>(
    txs: &'a [TransactionSigned],
) -> Result<SystemTxLayout<'a>, SystemTxError> {
    let mut begin = Vec::new();
    let mut prefix_end = 0usize;
    let mut previous_begin = None;

    while prefix_end < txs.len() && is_reserved_system_tx(&txs[prefix_end]) {
        let kind = decode_system_tx_kind(&txs[prefix_end])?;
        if kind.body_zone() == BodyZone::EndBlock {
            break;
        }
        ensure_system_tx_in_zone(kind, BodyZone::BeginBlock)?;
        ensure_monotonic(BodyZone::BeginBlock, previous_begin, kind)?;
        previous_begin = Some(kind);
        begin.push(&txs[prefix_end]);
        prefix_end += 1;
    }

    let mut suffix_entries: Vec<(usize, SystemTxKind)> = Vec::new();
    let mut suffix_start = txs.len();
    while suffix_start > prefix_end && is_reserved_system_tx(&txs[suffix_start - 1]) {
        suffix_start -= 1;
        let kind = decode_system_tx_kind(&txs[suffix_start])?;
        ensure_system_tx_in_zone(kind, BodyZone::EndBlock)?;
        suffix_entries.push((suffix_start, kind));
    }
    suffix_entries.reverse();

    let mut previous_end = None;
    let mut end = Vec::with_capacity(suffix_entries.len());
    for (index, kind) in suffix_entries {
        ensure_monotonic(BodyZone::EndBlock, previous_end, kind)?;
        previous_end = Some(kind);
        end.push(&txs[index]);
    }

    for (offset, tx) in txs[prefix_end..suffix_start].iter().enumerate() {
        if is_reserved_system_tx(tx) {
            return Err(SystemTxError::MidBlockSystemTx {
                index: prefix_end + offset,
            });
        }
    }

    Ok(SystemTxLayout {
        begin,
        user: txs[prefix_end..suffix_start].iter().collect(),
        end,
    })
}

pub fn expected_begin_block_kinds(
    block_number: u64,
    has_boundary_outcome: bool,
    has_tee_bootstrap: bool,
) -> Vec<SystemTxKind> {
    expected_begin_block_kinds_for_activation(
        block_number,
        has_boundary_outcome,
        has_tee_bootstrap,
        OcompLifecycleActivation::Disabled,
    )
}

pub fn expected_begin_block_kinds_for_activation(
    block_number: u64,
    has_boundary_outcome: bool,
    has_tee_bootstrap: bool,
    ocomp_activation: OcompLifecycleActivation,
) -> Vec<SystemTxKind> {
    let mut expected = match block_number {
        0 => Vec::new(),
        1 => Vec::new(),
        _ => {
            vec![
                SystemTxKind::CertifiedParentAccounting,
                // mandatory inclusion-window phase, ordered after Phase 1
                // and before CycleTick for every block >= 2 (empty when nothing to
                // credit; its body still drives the matured-window settlement).
                SystemTxKind::LateFinalizeCredits,
            ]
        }
    };
    if block_number > 0 && ocomp_activation.is_active_at(block_number) {
        expected.push(SystemTxKind::OcompLifecycleBegin);
    }
    if block_number > 0 {
        expected.push(SystemTxKind::CycleTick);
        expected.push(SystemTxKind::RewardsGemDelivery);
    }
    if block_number > 0 && has_boundary_outcome {
        expected.push(SystemTxKind::BoundaryOutcome);
    }
    if block_number > 0 && has_tee_bootstrap {
        expected.push(SystemTxKind::TeeBootstrap);
    }
    if block_number > 0 {
        expected.push(SystemTxKind::OracleSlashWindow);
        expected.push(SystemTxKind::HookEvents);
    }
    expected
}

pub fn expected_end_block_kinds(
    block_number: u64,
    ocomp_activation: OcompLifecycleActivation,
) -> Vec<SystemTxKind> {
    if block_number > 0 && ocomp_activation.is_active_at(block_number) {
        vec![SystemTxKind::OcompTerminalRequest]
    } else {
        Vec::new()
    }
}

pub fn validate_active_system_tx_set(
    layout: &SystemTxLayout<'_>,
    block_number: u64,
    has_boundary_outcome: bool,
    has_tee_bootstrap: bool,
) -> Result<(), SystemTxError> {
    validate_system_tx_set_for_activation(
        layout,
        block_number,
        has_boundary_outcome,
        has_tee_bootstrap,
        OcompLifecycleActivation::Disabled,
    )
}

pub fn validate_system_tx_set_for_activation(
    layout: &SystemTxLayout<'_>,
    block_number: u64,
    has_boundary_outcome: bool,
    has_tee_bootstrap: bool,
    ocomp_activation: OcompLifecycleActivation,
) -> Result<(), SystemTxError> {
    let actual = layout.system_tx_count();
    if actual > usize::from(MAX_SYSTEM_TXS_PER_BLOCK) {
        return Err(SystemTxError::TooManySystemTxs {
            actual,
            max: MAX_SYSTEM_TXS_PER_BLOCK,
        });
    }

    // / V2: block 1 mandatorily carries the genesis bootstrap
    // BoundaryOutcome. Reject the layout if the proposer omitted it; the
    // expected-kinds list rejection below is structural, this rejection is
    // protocol-level for V2 greenfield.
    if block_number == 1 && !has_boundary_outcome {
        return Err(SystemTxError::V2Block1MissingBoundaryOutcome);
    }
    if block_number == 1 && !has_tee_bootstrap {
        return Err(SystemTxError::V2Block1MissingTeeBootstrap);
    }
    if block_number != 1 && has_tee_bootstrap {
        return Err(SystemTxError::TeeBootstrapWrongHeight { block_number });
    }
    if block_number == 1 && !layout.user.is_empty() {
        return Err(SystemTxError::V2Block1ContainsUserTransactions {
            actual: layout.user.len(),
        });
    }

    let expected_begin = expected_begin_block_kinds_for_activation(
        block_number,
        has_boundary_outcome,
        has_tee_bootstrap,
        ocomp_activation,
    );
    let expected_end = expected_end_block_kinds(block_number, ocomp_activation);
    let actual_begin = layout.begin_block_kinds()?;
    let actual_end = layout.end_block_kinds()?;
    if actual_begin != expected_begin || actual_end != expected_end {
        return Err(SystemTxError::ActiveSystemTxSetMismatch {
            expected_begin,
            expected_end,
            actual_begin,
            actual_end,
        });
    }
    Ok(())
}

fn ensure_system_tx_in_zone(kind: SystemTxKind, actual: BodyZone) -> Result<(), SystemTxError> {
    let expected = kind.body_zone();
    if expected != actual {
        return Err(SystemTxError::SystemTxInWrongZone {
            kind,
            expected,
            actual,
        });
    }
    Ok(())
}

fn ensure_monotonic(
    zone: BodyZone,
    previous: Option<SystemTxKind>,
    current: SystemTxKind,
) -> Result<(), SystemTxError> {
    let Some(previous) = previous else {
        return Ok(());
    };
    let previous_order = previous
        .order_in(zone)
        .ok_or(SystemTxError::SystemTxInWrongZone {
            kind: previous,
            expected: previous.body_zone(),
            actual: zone,
        })?;
    let current_order = current
        .order_in(zone)
        .ok_or(SystemTxError::SystemTxInWrongZone {
            kind: current,
            expected: current.body_zone(),
            actual: zone,
        })?;
    if current_order <= previous_order {
        return Err(SystemTxError::OutOfOrder {
            zone,
            previous,
            current,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::ReshareResult;
    use crate::signer::OutbeEvmSigner;
    use alloy_eips::eip2718::Encodable2718;
    use alloy_primitives::{address, Signature, B256};

    const CHAIN_ID: u64 = 2026;

    fn sample_metadata() -> CertifiedParentAccountingMetadata {
        CertifiedParentAccountingMetadata {
            finalized_block_number: 41,
            finalized_block_hash: B256::repeat_byte(0x41),
            finalized_epoch: 7,
            finalized_view: 42,
            parent_view: 41,
            ordered_committee: vec![address!("0x1111111111111111111111111111111111111111")],
            signer_bitmap: vec![1],
            proof: Bytes::from_static(b"cert"),
            committee_set_hash: B256::repeat_byte(0x77),
            vrf_material_version: 3,
            vrf_group_public_key_hash: B256::repeat_byte(0x88),
            proof_kind: crate::consensus_metadata::ParentParticipationProof::Finalization,
            // V2 contract requires `missed_proposers` to be empty;
            // this test fixture keeps it empty to stay consistent with the
            // verifier rule.
            missed_proposers: Vec::new(),
        }
    }

    fn sample_boundary() -> DkgBoundaryArtifact {
        DkgBoundaryArtifact {
            epoch: 8,
            dkg_cycle: 2,
            freeze_height: 40,
            planned_activation_height: 42,
            target_set_hash: B256::repeat_byte(0x33),
            vrf_material_version: 3,
            vrf_group_public_key: B256::repeat_byte(0x44),
            vrf_group_public_key_bytes: Bytes::from_static(&[0x44u8; 96]),
            committee_set_hash: B256::repeat_byte(0x66),
            is_validator_set_change: true,
            outcome: Bytes::from_static(b"boundary"),
            is_full_dkg: false,
            tee_recipient_pubkeys: Vec::new(),
            tee_expired_target_exclusions: Vec::new(),
            tee_expired_target_exclusions_hash: B256::ZERO,
            reshare: ReshareResult {
                new_active_set: vec![address!("0x3333333333333333333333333333333333333333")],
                active_set_hash: B256::repeat_byte(0x55),
            },
        }
    }

    fn sample_tee_bootstrap() -> crate::tee_bootstrap_v2::TeeBootstrapV2 {
        use crate::{
            tee_attestation_v1::{
                AttestationMode, AttestationOperationV1, DcapCollateralComponentV1,
                DcapCollateralKind, NodeIdV1, PlatformTcbStatusSetV1, QvlTcbStatusV1,
                RegistrationIntentV1, ResourceScheduleV1, TeeMeasurementRuleV1, TeePolicyV1,
                ValidatorNodeBindingV1,
            },
            tee_bootstrap_v2::{
                TeeBootstrapCommitteeSignatureV2, TeeBootstrapParticipantEvidenceV2,
                TeeBootstrapParticipantV2, TeeBootstrapV2,
            },
        };

        use k256::ecdsa::signature::hazmat::PrehashSigner as _;
        let validator_signer =
            crate::signer::OutbeEvmSigner::from_secret_bytes(crate::test_keys::secret(0x22))
                .expect("validator signer");
        let validator = validator_signer.address();
        let node_signer =
            k256::ecdsa::SigningKey::from_bytes((&crate::test_keys::secret(0x23)).into())
                .expect("NodeHost signer");
        let reth_p2p_public = node_signer
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .expect("SEC1-33 NodeHost public key");
        let policy = TeePolicyV1 {
            policy_version: 1,
            chain_id: [0x10; 32],
            genesis_hash: B256::repeat_byte(0x11),
            activation_height: 1,
            predecessor_policy_hash: B256::ZERO,
            attestation_mode: AttestationMode::DcapRequired,
            intel_root_der_hash: B256::repeat_byte(0x72),
            quote_version: 3,
            tee_type: 0,
            attestation_key_type: 2,
            qe_vendor_id: [
                0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9, 0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f,
                0x06, 0x07,
            ],
            certification_data_type: 5,
            tcb_info_schema_version: 3,
            qe_identity_schema_version: 2,
            minimum_tcb_evaluation_data_number: 1,
            accepted_platform_tcb_statuses: PlatformTcbStatusSetV1::UpToDateOrHardeningNeeded,
            accepted_qe_tcb_status: QvlTcbStatusV1::UpToDate,
            minimum_lease: 3_600,
            maximum_lease: 604_800,
            collateral_margin: 3_600,
            resource_schedule_hash: ResourceScheduleV1::normative()
                .expect("normative resource schedule")
                .schedule_hash()
                .expect("resource schedule hashes"),
            measurement_rules: vec![TeeMeasurementRuleV1 {
                mrenclave: B256::repeat_byte(0x81),
                mrsigner: B256::repeat_byte(0x82),
                isv_prod_id: 1,
                minimum_isv_svn: 2,
                admit_from_height: 1,
                admit_until_height_exclusive: 1_000,
            }],
        };
        let policy_hash = policy.policy_hash().expect("policy hashes");
        let intent = RegistrationIntentV1 {
            chain_id: policy.chain_id,
            genesis_hash: B256::repeat_byte(0x11),
            operation: AttestationOperationV1::RegisterEnclave,
            attestation_mode: AttestationMode::DcapRequired,
            policy_hash,
            node_id: NodeIdV1 { reth_p2p_public },
            enclave_id: B256::repeat_byte(0x32),
            binding_id: B256::repeat_byte(0x33),
            binding_version: 1,
            registration_version: 0,
            renewal_nonce: 0,
            transition_nonce: 0,
            requested_valid_until: 7_200,
            recipient_x25519: [0x34; 32],
            attestation_ed25519: [0x35; 32],
            noise_responder_x25519: [0x36; 32],
            node_host_authorization_hash: B256::repeat_byte(0x37),
        };

        let validator_binding = ValidatorNodeBindingV1 {
            chain_id: intent.chain_id,
            genesis_hash: intent.genesis_hash,
            validator: validator.into_array(),
            node_id_hash: intent.node_id.node_id_hash().expect("NodeHost hash"),
        };
        let binding_hash = validator_binding.binding_hash().expect("binding hash");
        let validator_signature = validator_signer
            .sign_hash(&binding_hash)
            .expect("validator binding signature");
        let (node_signature_body, node_recovery) = node_signer
            .sign_prehash(binding_hash.as_slice())
            .expect("NodeHost binding signature");
        let mut node_binding_signature = [0_u8; 65];
        node_binding_signature[..64].copy_from_slice(node_signature_body.to_bytes().as_slice());
        node_binding_signature[64] = node_recovery.to_byte();

        TeeBootstrapV2 {
            policy,
            committee_snapshot_hash: B256::repeat_byte(0xB2),
            committee_snapshot_block: 1,
            key_epoch: 1,
            tribute_offer_epoch: 1,
            dkg_transcript_hash: B256::repeat_byte(0xB3),
            tribute_offer_public_key: B256::repeat_byte(0xB4),
            tribute_offer_group_public_key: Bytes::from(vec![0xB5; 96]),
            collateral_pool: (1_u8..=8)
                .map(|kind| DcapCollateralComponentV1 {
                    kind: DcapCollateralKind::try_from(kind).expect("known collateral kind"),
                    bytes: vec![kind],
                })
                .collect(),
            participants: vec![TeeBootstrapParticipantV2 {
                intent,
                validator_binding,
                validator_signature,
                node_binding_signature,
                evidence: TeeBootstrapParticipantEvidenceV2::Dcap {
                    quote: vec![0x41; 64],
                    collateral_component_indices: [0, 1, 2, 3, 4, 5, 6, 7],
                },
                node_signature: [0x42; 65],
                enclave_signature: [0x43; 64],
            }],
            committee_signatures: vec![TeeBootstrapCommitteeSignatureV2 {
                validator,
                signature: [0x44; 65],
            }],
        }
    }

    fn input_for(kind: SystemTxKind) -> SystemTxInputV2 {
        match kind {
            SystemTxKind::CertifiedParentAccounting => SystemTxInputV2::CertifiedParentAccounting {
                metadata: sample_metadata(),
            },
            SystemTxKind::LateFinalizeCredits => SystemTxInputV2::LateFinalizeCredits {
                artifact: LateFinalizeCreditsArtifact::default(),
            },
            SystemTxKind::OcompLifecycleBegin => SystemTxInputV2::OcompLifecycleBegin,
            SystemTxKind::CycleTick => SystemTxInputV2::CycleTick,
            SystemTxKind::RewardsGemDelivery => SystemTxInputV2::RewardsGemDelivery,
            SystemTxKind::BoundaryOutcome => SystemTxInputV2::BoundaryOutcome {
                artifact: sample_boundary(),
            },
            SystemTxKind::TeeBootstrap => SystemTxInputV2::TeeBootstrap {
                payload: sample_tee_bootstrap(),
            },
            SystemTxKind::OracleSlashWindow => SystemTxInputV2::OracleSlashWindow,
            SystemTxKind::HookEvents => SystemTxInputV2::HookEvents,
            SystemTxKind::OcompTerminalRequest => SystemTxInputV2::OcompTerminalRequest,
        }
    }

    fn system_tx(kind: SystemTxKind, ordinal: u8, block_number: u64) -> TransactionSigned {
        let input = input_for(kind).encode().expect("system input encodes");
        build_unsigned_system_tx(kind, ordinal, block_number, CHAIN_ID, input)
            .expect("system tx builds")
            .into_signed(Signature::test_signature())
            .into()
    }

    fn user_tx() -> TransactionSigned {
        TxLegacy {
            chain_id: Some(CHAIN_ID),
            nonce: 0,
            gas_price: 0,
            gas_limit: 21_000,
            to: TxKind::Call(address!("0x4444444444444444444444444444444444444444")),
            value: U256::ZERO,
            input: Bytes::new(),
        }
        .into_signed(Signature::test_signature())
        .into()
    }

    fn test_signer(seed: u8) -> OutbeEvmSigner {
        OutbeEvmSigner::from_secret_bytes(crate::test_keys::secret((seed) as u64))
            .expect("valid test signer")
    }

    fn phase1_calldata() -> Bytes {
        input_for(SystemTxKind::CertifiedParentAccounting)
            .encode()
            .expect("phase1 input encodes")
    }

    fn signed_phase1(
        signer: &OutbeEvmSigner,
        block_number: u64,
        chain_id: u64,
        calldata: Bytes,
    ) -> TransactionSigned {
        let unsigned = build_unsigned_system_tx(
            SystemTxKind::CertifiedParentAccounting,
            0,
            block_number,
            chain_id,
            calldata,
        )
        .expect("phase1 tx builds");
        signer.sign_unsigned(unsigned).expect("phase1 signs")
    }

    #[test]
    fn input_roundtrips_every_system_tx_kind() {
        for kind in [
            SystemTxKind::CertifiedParentAccounting,
            SystemTxKind::LateFinalizeCredits,
            SystemTxKind::CycleTick,
            SystemTxKind::RewardsGemDelivery,
            SystemTxKind::BoundaryOutcome,
            SystemTxKind::TeeBootstrap,
            SystemTxKind::OracleSlashWindow,
            SystemTxKind::HookEvents,
        ] {
            let input = input_for(kind);
            let encoded = input.encode().expect("input encodes");
            let decoded = SystemTxInputV2::decode(&encoded).expect("input decodes");
            assert_eq!(decoded, input);
            assert_eq!(decoded.kind(), kind);
        }
    }

    #[test]
    fn build_unsigned_system_tx_sets_deterministic_fields() {
        let input = input_for(SystemTxKind::CycleTick)
            .encode()
            .expect("input encodes");
        let tx = build_unsigned_system_tx(SystemTxKind::CycleTick, 0, 1, CHAIN_ID, input.clone())
            .expect("tx builds");
        assert_eq!(tx.chain_id, Some(CHAIN_ID));
        assert_eq!(tx.nonce, u64::from(MAX_SYSTEM_TXS_PER_BLOCK));
        assert_eq!(tx.gas_price, 0);
        assert_eq!(
            tx.gas_limit,
            system_tx_visible_gas_limit(input.as_ref()).expect("visible gas computes")
        );
        assert!(tx.gas_limit >= SYSTEM_TX_VISIBLE_GAS_FLOOR);
        assert!(tx.gas_limit < SYSTEM_TX_ARTIFACT_GAS_LIMIT);
        assert_eq!(tx.to, TxKind::Call(OUTBE_SYSTEM_TX_ADDRESS));
        assert_eq!(tx.value, U256::ZERO);
        assert_eq!(tx.input, input);
    }

    #[test]
    fn visible_gas_plan_assigns_only_cycle_the_block_remainder() {
        let inputs = [
            input_for(SystemTxKind::CertifiedParentAccounting)
                .encode()
                .expect("CPA input encodes"),
            input_for(SystemTxKind::CycleTick)
                .encode()
                .expect("CycleTick input encodes"),
            input_for(SystemTxKind::HookEvents)
                .encode()
                .expect("HookEvents input encodes"),
        ];
        let entries = [
            (SystemTxKind::CertifiedParentAccounting, inputs[0].clone()),
            (SystemTxKind::CycleTick, inputs[1].clone()),
            (SystemTxKind::HookEvents, inputs[2].clone()),
        ];
        let intrinsic_total = inputs
            .iter()
            .map(|input| system_tx_intrinsic_gas(input).expect("intrinsic gas computes"))
            .sum::<u64>();
        let block_gas_limit = intrinsic_total + 50_000;

        let plan = SystemTxVisibleGasPlan::new(block_gas_limit, &entries)
            .expect("system gas plan fits the block");

        assert_eq!(plan.gas_limit(0), Some(plan.intrinsic_gas(0).unwrap()));
        assert_eq!(plan.ce_gas_limit(0), Some(0));
        assert_eq!(plan.ce_gas_limit(1), Some(50_000));
        assert_eq!(
            plan.gas_limit(1),
            Some(plan.intrinsic_gas(1).unwrap() + 50_000)
        );
        assert_eq!(plan.gas_limit(2), Some(plan.intrinsic_gas(2).unwrap()));
        assert_eq!(plan.total_envelope_gas(), block_gas_limit);
    }

    #[test]
    fn visible_gas_plan_reserves_ocomp_terminal_ce_before_cycle_remainder() {
        let ocomp = input_for(SystemTxKind::OcompLifecycleBegin)
            .encode()
            .expect("OCOMP lifecycle input encodes");
        let cycle = input_for(SystemTxKind::CycleTick)
            .encode()
            .expect("CycleTick input encodes");
        let entries = [
            (SystemTxKind::OcompLifecycleBegin, ocomp.clone()),
            (SystemTxKind::CycleTick, cycle.clone()),
        ];
        let intrinsic_total = system_tx_intrinsic_gas(&ocomp)
            .expect("OCOMP intrinsic gas computes")
            + system_tx_intrinsic_gas(&cycle).expect("Cycle intrinsic gas computes");
        let cycle_remainder = 50_000;
        let block_gas_limit = intrinsic_total + OCOMP_LIFECYCLE_CE_GAS_RESERVE + cycle_remainder;

        let plan = SystemTxVisibleGasPlan::new(block_gas_limit, &entries)
            .expect("system gas plan fits the block");

        assert_eq!(plan.protocol_precharge(0), Some(0));
        assert_eq!(plan.ce_gas_limit(0), Some(OCOMP_LIFECYCLE_CE_GAS_RESERVE));
        assert_eq!(
            plan.gas_limit(0),
            Some(plan.intrinsic_gas(0).unwrap() + OCOMP_LIFECYCLE_CE_GAS_RESERVE)
        );
        assert_eq!(plan.ce_gas_limit(1), Some(cycle_remainder));
        assert_eq!(plan.total_envelope_gas(), block_gas_limit);
    }

    #[test]
    fn visible_gas_plan_rejects_system_intrinsic_gas_above_the_block_limit() {
        let cycle = input_for(SystemTxKind::CycleTick)
            .encode()
            .expect("CycleTick input encodes");
        let intrinsic = system_tx_intrinsic_gas(&cycle).expect("intrinsic gas computes");

        let error = SystemTxVisibleGasPlan::new(intrinsic - 1, &[(SystemTxKind::CycleTick, cycle)])
            .expect_err("system envelope cannot exceed the block gas limit");

        assert_eq!(
            error,
            SystemTxError::VisibleGasPlanExceedsBlock {
                required_gas: intrinsic,
                block_gas_limit: intrinsic - 1,
            }
        );
    }

    #[test]
    fn signature_hash_is_deterministic_for_identical_inputs() {
        let input = input_for(SystemTxKind::CycleTick)
            .encode()
            .expect("input encodes");
        let a = build_unsigned_system_tx(SystemTxKind::CycleTick, 0, 42, CHAIN_ID, input.clone())
            .expect("tx builds");
        let b = build_unsigned_system_tx(SystemTxKind::CycleTick, 0, 42, CHAIN_ID, input)
            .expect("tx builds");
        assert_eq!(a.signature_hash(), b.signature_hash());

        let different_block = build_unsigned_system_tx(
            SystemTxKind::CycleTick,
            0,
            43,
            CHAIN_ID,
            input_for(SystemTxKind::CycleTick)
                .encode()
                .expect("input encodes"),
        )
        .expect("tx builds");
        assert_ne!(a.signature_hash(), different_block.signature_hash());
    }

    #[test]
    fn phase1_witness_validation_accepts_canonical_signed_tx() {
        let signer = test_signer(1);
        let calldata = phase1_calldata();
        let signed = signed_phase1(&signer, 42, CHAIN_ID, calldata.clone());

        let validated = validate_phase1_witness_against(
            &signed,
            calldata.as_ref(),
            signer.address(),
            CHAIN_ID,
            42,
        )
        .expect("canonical phase1 witness validates");

        assert_eq!(validated, signed.signature_hash());
    }

    #[test]
    fn phase1_witness_validation_rejects_wrong_signer() {
        let signer = test_signer(1);
        let other = test_signer(2);
        let calldata = phase1_calldata();
        let signed = signed_phase1(&signer, 42, CHAIN_ID, calldata.clone());

        let err = validate_phase1_witness_against(
            &signed,
            calldata.as_ref(),
            other.address(),
            CHAIN_ID,
            42,
        )
        .expect_err("wrong proposer must be rejected");

        assert!(matches!(
            err,
            SystemTxError::Phase1SignerMismatch { expected, actual }
                if expected == other.address() && actual == signer.address()
        ));
    }

    #[test]
    fn phase1_witness_validation_rejects_wrong_chain_id_and_nonce() {
        let signer = test_signer(1);
        let calldata = phase1_calldata();
        let signed = signed_phase1(&signer, 42, CHAIN_ID, calldata.clone());

        let wrong_chain = validate_phase1_witness_against(
            &signed,
            calldata.as_ref(),
            signer.address(),
            CHAIN_ID + 1,
            42,
        )
        .expect_err("wrong chain id must be rejected");
        assert!(matches!(
            wrong_chain,
            SystemTxError::Phase1ChainIdMismatch { expected, actual }
                if expected == CHAIN_ID + 1 && actual == Some(CHAIN_ID)
        ));

        let wrong_nonce = validate_phase1_witness_against(
            &signed,
            calldata.as_ref(),
            signer.address(),
            CHAIN_ID,
            43,
        )
        .expect_err("wrong block-number nonce must be rejected");
        assert!(matches!(
            wrong_nonce,
            SystemTxError::Phase1NonceMismatch { .. }
        ));
    }

    #[test]
    fn phase1_witness_validation_rejects_noncanonical_envelope_shape() {
        let signer = test_signer(1);
        let calldata = phase1_calldata();
        let base = build_unsigned_system_tx(
            SystemTxKind::CertifiedParentAccounting,
            0,
            42,
            CHAIN_ID,
            calldata.clone(),
        )
        .expect("phase1 tx builds");

        let mut wrong_gas = base.clone();
        wrong_gas.gas_limit = wrong_gas.gas_limit.saturating_add(1);
        let signed_wrong_gas = signer.sign_unsigned(wrong_gas).expect("signs");
        assert!(matches!(
            validate_phase1_witness_against(
                &signed_wrong_gas,
                calldata.as_ref(),
                signer.address(),
                CHAIN_ID,
                42
            ),
            Err(SystemTxError::Phase1GasLimitMismatch { .. })
        ));

        let mut wrong_value = base.clone();
        wrong_value.value = U256::from(1);
        let signed_wrong_value = signer.sign_unsigned(wrong_value).expect("signs");
        assert!(matches!(
            validate_phase1_witness_against(
                &signed_wrong_value,
                calldata.as_ref(),
                signer.address(),
                CHAIN_ID,
                42
            ),
            Err(SystemTxError::Phase1NonZeroValue)
        ));

        let mut wrong_recipient = base;
        wrong_recipient.to = TxKind::Call(address!("0x5555555555555555555555555555555555555555"));
        let signed_wrong_recipient = signer.sign_unsigned(wrong_recipient).expect("signs");
        assert!(matches!(
            validate_phase1_witness_against(
                &signed_wrong_recipient,
                calldata.as_ref(),
                signer.address(),
                CHAIN_ID,
                42
            ),
            Err(SystemTxError::Phase1WrongRecipient)
        ));
    }

    #[test]
    fn phase1_witness_validation_rejects_wrong_calldata_or_kind() {
        let signer = test_signer(1);
        let calldata = phase1_calldata();
        let signed = signed_phase1(&signer, 42, CHAIN_ID, calldata.clone());

        let mut altered = sample_metadata();
        altered.finalized_block_hash = B256::repeat_byte(0x99);
        let altered_calldata = SystemTxInputV2::CertifiedParentAccounting { metadata: altered }
            .encode()
            .expect("altered phase1 input encodes");
        assert!(matches!(
            validate_phase1_witness_against(
                &signed,
                altered_calldata.as_ref(),
                signer.address(),
                CHAIN_ID,
                42
            ),
            Err(SystemTxError::Phase1CalldataMismatch)
        ));

        let cycle_calldata = input_for(SystemTxKind::CycleTick)
            .encode()
            .expect("cycle input encodes");
        let cycle_unsigned = build_unsigned_system_tx(
            SystemTxKind::CycleTick,
            0,
            42,
            CHAIN_ID,
            cycle_calldata.clone(),
        )
        .expect("cycle tx builds");
        let signed_cycle = signer.sign_unsigned(cycle_unsigned).expect("cycle signs");
        assert!(matches!(
            validate_phase1_witness_against(
                &signed_cycle,
                cycle_calldata.as_ref(),
                signer.address(),
                CHAIN_ID,
                42
            ),
            Err(SystemTxError::CalldataKindMismatch {
                expected: SystemTxKind::CertifiedParentAccounting,
                actual: SystemTxKind::CycleTick,
            })
        ));
    }

    #[test]
    fn canonical_phase1_calldata_changes_signature_hash() {
        let mut left_meta = sample_metadata();
        left_meta.finalized_block_hash = B256::repeat_byte(0x11);
        let left = SystemTxInputV2::CertifiedParentAccounting {
            metadata: left_meta,
        }
        .encode()
        .expect("left input encodes");

        let mut right_meta = sample_metadata();
        right_meta.finalized_block_hash = B256::repeat_byte(0x22);
        let right = SystemTxInputV2::CertifiedParentAccounting {
            metadata: right_meta,
        }
        .encode()
        .expect("right input encodes");

        let left_tx = build_unsigned_system_tx(
            SystemTxKind::CertifiedParentAccounting,
            0,
            42,
            CHAIN_ID,
            left,
        )
        .expect("left tx builds");
        let right_tx = build_unsigned_system_tx(
            SystemTxKind::CertifiedParentAccounting,
            0,
            42,
            CHAIN_ID,
            right,
        )
        .expect("right tx builds");

        assert_ne!(left_tx.signature_hash(), right_tx.signature_hash());
    }

    #[test]
    fn recover_phase1_proposer_rejects_trailing_eip2718_bytes() {
        let signer = test_signer(1);
        let calldata = phase1_calldata();
        let signed = signed_phase1(&signer, 42, CHAIN_ID, calldata);
        let mut encoded = Vec::new();
        signed.encode_2718(&mut encoded);
        encoded.push(0);

        let err =
            recover_phase1_proposer(&encoded, CHAIN_ID, 42).expect_err("trailing bytes rejected");

        assert!(
            matches!(err, SystemTxError::Phase1TxDecode(message) if message.contains("trailing bytes"))
        );
    }

    #[test]
    fn nonce_is_block_number_times_max_plus_ordinal() {
        assert_eq!(system_tx_nonce(1, 0).expect("nonce"), 16);
        assert_eq!(system_tx_nonce(200_600, 2).expect("nonce"), 3_209_602);
        assert!(matches!(
            system_tx_nonce(u64::MAX, 15),
            Err(SystemTxError::NonceOverflow { .. })
        ));
    }

    #[test]
    fn split_accepts_empty_and_user_only_layouts() {
        let empty = split_system_layout(&[]).expect("empty splits");
        assert!(empty.is_empty());

        let txs = vec![user_tx(), user_tx()];
        let layout = split_system_layout(&txs).expect("user-only splits");
        assert_eq!(layout.begin.len(), 0);
        assert_eq!(layout.user.len(), 2);
        assert_eq!(layout.end.len(), 0);
    }

    #[test]
    fn split_accepts_block1_cycle_tick_prefix() {
        let txs = vec![
            system_tx(SystemTxKind::CycleTick, 0, 1),
            system_tx(SystemTxKind::RewardsGemDelivery, 1, 1),
            user_tx(),
        ];
        let layout = split_system_layout(&txs).expect("layout splits");
        assert_eq!(
            layout.begin_block_kinds().expect("kinds"),
            vec![SystemTxKind::CycleTick, SystemTxKind::RewardsGemDelivery,]
        );
        assert_eq!(layout.user.len(), 1);
        assert!(layout.end.is_empty());
    }

    #[test]
    fn split_accepts_block_with_optional_boundary_prefix() {
        let txs = vec![
            system_tx(SystemTxKind::CertifiedParentAccounting, 0, 42),
            system_tx(SystemTxKind::CycleTick, 1, 42),
            system_tx(SystemTxKind::RewardsGemDelivery, 2, 42),
            system_tx(SystemTxKind::BoundaryOutcome, 3, 42),
            user_tx(),
        ];
        let layout = split_system_layout(&txs).expect("layout splits");
        assert_eq!(
            layout.begin_block_kinds().expect("kinds"),
            vec![
                SystemTxKind::CertifiedParentAccounting,
                SystemTxKind::CycleTick,
                SystemTxKind::RewardsGemDelivery,
                SystemTxKind::BoundaryOutcome,
            ]
        );
        assert_eq!(layout.user.len(), 1);
    }

    #[test]
    fn split_rejects_out_of_order_prefix() {
        let txs = vec![
            system_tx(SystemTxKind::CycleTick, 0, 42),
            system_tx(SystemTxKind::CertifiedParentAccounting, 1, 42),
        ];
        assert!(matches!(
            split_system_layout(&txs),
            Err(SystemTxError::OutOfOrder { .. })
        ));
    }

    #[test]
    fn split_rejects_reserved_tx_in_wrong_suffix_zone() {
        let txs = vec![user_tx(), system_tx(SystemTxKind::CycleTick, 0, 42)];
        assert!(matches!(
            split_system_layout(&txs),
            Err(SystemTxError::SystemTxInWrongZone {
                actual: BodyZone::EndBlock,
                ..
            })
        ));
    }

    #[test]
    fn split_rejects_reserved_tx_in_middle_zone() {
        let txs = vec![
            system_tx(SystemTxKind::CycleTick, 0, 1),
            system_tx(SystemTxKind::RewardsGemDelivery, 1, 1),
            user_tx(),
            system_tx(SystemTxKind::BoundaryOutcome, 2, 1),
            user_tx(),
        ];
        assert!(matches!(
            split_system_layout(&txs),
            Err(SystemTxError::MidBlockSystemTx { index: 3 })
        ));
    }

    #[test]
    fn validate_active_system_tx_set_accepts_expected_membership() {
        let block0 = split_system_layout(&[]).expect("layout");
        validate_active_system_tx_set(&block0, 0, false, false).expect("genesis ok");

        // / V2: block 1 mandatorily carries a BoundaryOutcome for
        // the genesis bootstrap.
        let block1_txs = vec![
            system_tx(SystemTxKind::CycleTick, 0, 1),
            system_tx(SystemTxKind::RewardsGemDelivery, 1, 1),
            system_tx(SystemTxKind::BoundaryOutcome, 2, 1),
            system_tx(SystemTxKind::TeeBootstrap, 3, 1),
            system_tx(SystemTxKind::OracleSlashWindow, 4, 1),
            system_tx(SystemTxKind::HookEvents, 5, 1),
        ];
        let block1 = split_system_layout(&block1_txs).expect("layout");
        validate_active_system_tx_set(&block1, 1, true, true).expect("block 1 V2 ok");

        let block2_txs = vec![
            system_tx(SystemTxKind::CertifiedParentAccounting, 0, 2),
            system_tx(SystemTxKind::LateFinalizeCredits, 1, 2),
            system_tx(SystemTxKind::CycleTick, 2, 2),
            system_tx(SystemTxKind::RewardsGemDelivery, 3, 2),
            system_tx(SystemTxKind::OracleSlashWindow, 4, 2),
            system_tx(SystemTxKind::HookEvents, 5, 2),
        ];
        let block2 = split_system_layout(&block2_txs).expect("layout");
        validate_active_system_tx_set(&block2, 2, false, false).expect("block 2 ok");

        let block2_with_boundary_txs = vec![
            system_tx(SystemTxKind::CertifiedParentAccounting, 0, 2),
            system_tx(SystemTxKind::LateFinalizeCredits, 1, 2),
            system_tx(SystemTxKind::CycleTick, 2, 2),
            system_tx(SystemTxKind::RewardsGemDelivery, 3, 2),
            system_tx(SystemTxKind::BoundaryOutcome, 4, 2),
            system_tx(SystemTxKind::OracleSlashWindow, 5, 2),
            system_tx(SystemTxKind::HookEvents, 6, 2),
        ];
        let block2_with_boundary = split_system_layout(&block2_with_boundary_txs).expect("layout");
        validate_active_system_tx_set(&block2_with_boundary, 2, true, false)
            .expect("block 2 boundary ok");
    }

    #[test]
    fn validate_active_system_tx_set_requires_mandatory_and_conditional_kinds() {
        let missing_finalization_txs = vec![
            system_tx(SystemTxKind::CycleTick, 0, 2),
            system_tx(SystemTxKind::RewardsGemDelivery, 1, 2),
            system_tx(SystemTxKind::OracleSlashWindow, 2, 2),
        ];
        let missing_finalization = split_system_layout(&missing_finalization_txs).expect("layout");
        assert!(matches!(
            validate_active_system_tx_set(&missing_finalization, 2, false, false),
            Err(SystemTxError::ActiveSystemTxSetMismatch { .. })
        ));

        let missing_cycle_tick_txs = vec![
            system_tx(SystemTxKind::CertifiedParentAccounting, 0, 2),
            system_tx(SystemTxKind::RewardsGemDelivery, 1, 2),
            system_tx(SystemTxKind::OracleSlashWindow, 2, 2),
        ];
        let missing_cycle_tick = split_system_layout(&missing_cycle_tick_txs).expect("layout");
        assert!(matches!(
            validate_active_system_tx_set(&missing_cycle_tick, 2, false, false),
            Err(SystemTxError::ActiveSystemTxSetMismatch { .. })
        ));

        // / V2: block 1 must include CycleTick, BoundaryOutcome and TeeBootstrap.
        // Missing CycleTick (with the other mandatory phases present)
        // still yields ActiveSystemTxSetMismatch.
        let block1_missing_cycle_tick_txs = vec![
            system_tx(SystemTxKind::RewardsGemDelivery, 0, 1),
            system_tx(SystemTxKind::BoundaryOutcome, 1, 1),
            system_tx(SystemTxKind::TeeBootstrap, 2, 1),
            system_tx(SystemTxKind::OracleSlashWindow, 3, 1),
            system_tx(SystemTxKind::HookEvents, 4, 1),
        ];
        let block1_missing_cycle_tick =
            split_system_layout(&block1_missing_cycle_tick_txs).expect("layout");
        assert!(matches!(
            validate_active_system_tx_set(&block1_missing_cycle_tick, 1, true, true),
            Err(SystemTxError::ActiveSystemTxSetMismatch { .. })
        ));

        let block1_missing_tee_txs = vec![
            system_tx(SystemTxKind::CycleTick, 0, 1),
            system_tx(SystemTxKind::RewardsGemDelivery, 1, 1),
            system_tx(SystemTxKind::BoundaryOutcome, 2, 1),
            system_tx(SystemTxKind::OracleSlashWindow, 3, 1),
            system_tx(SystemTxKind::HookEvents, 4, 1),
        ];
        let block1_missing_tee = split_system_layout(&block1_missing_tee_txs).expect("layout");
        assert!(
            validate_active_system_tx_set(&block1_missing_tee, 1, true, false).is_err(),
            "block 1 must not commit without TeeBootstrap"
        );

        let block1_with_user_txs = vec![
            system_tx(SystemTxKind::CycleTick, 0, 1),
            system_tx(SystemTxKind::RewardsGemDelivery, 1, 1),
            system_tx(SystemTxKind::BoundaryOutcome, 2, 1),
            system_tx(SystemTxKind::TeeBootstrap, 3, 1),
            system_tx(SystemTxKind::OracleSlashWindow, 4, 1),
            system_tx(SystemTxKind::HookEvents, 5, 1),
            user_tx(),
        ];
        let block1_with_user = split_system_layout(&block1_with_user_txs).expect("layout");
        assert!(
            validate_active_system_tx_set(&block1_with_user, 1, true, true).is_err(),
            "block 1 must contain exactly the six mandatory system transactions"
        );

        // / V2: block 1 without BoundaryOutcome is rejected with
        // the V2-specific genesis bootstrap error before structural checks.
        let block1_no_boundary_txs = vec![
            system_tx(SystemTxKind::CycleTick, 0, 1),
            system_tx(SystemTxKind::RewardsGemDelivery, 1, 1),
            system_tx(SystemTxKind::OracleSlashWindow, 2, 1),
            system_tx(SystemTxKind::HookEvents, 3, 1),
        ];
        let block1_no_boundary = split_system_layout(&block1_no_boundary_txs).expect("layout");
        assert!(matches!(
            validate_active_system_tx_set(&block1_no_boundary, 1, false, false),
            Err(SystemTxError::V2Block1MissingBoundaryOutcome)
        ));

        let missing_oracle_slash_window_txs = vec![
            system_tx(SystemTxKind::CertifiedParentAccounting, 0, 2),
            system_tx(SystemTxKind::CycleTick, 1, 2),
            system_tx(SystemTxKind::RewardsGemDelivery, 2, 2),
            system_tx(SystemTxKind::HookEvents, 3, 2),
        ];
        let missing_oracle_slash_window =
            split_system_layout(&missing_oracle_slash_window_txs).expect("layout");
        assert!(matches!(
            validate_active_system_tx_set(&missing_oracle_slash_window, 2, false, false),
            Err(SystemTxError::ActiveSystemTxSetMismatch { .. })
        ));

        let missing_boundary_txs = vec![
            system_tx(SystemTxKind::CertifiedParentAccounting, 0, 2),
            system_tx(SystemTxKind::CycleTick, 1, 2),
            system_tx(SystemTxKind::RewardsGemDelivery, 2, 2),
            system_tx(SystemTxKind::OracleSlashWindow, 3, 2),
            system_tx(SystemTxKind::HookEvents, 4, 2),
        ];
        let missing_boundary = split_system_layout(&missing_boundary_txs).expect("layout");
        assert!(matches!(
            validate_active_system_tx_set(&missing_boundary, 2, true, false),
            Err(SystemTxError::ActiveSystemTxSetMismatch { .. })
        ));

        let unexpected_boundary_txs = vec![
            system_tx(SystemTxKind::CertifiedParentAccounting, 0, 2),
            system_tx(SystemTxKind::CycleTick, 1, 2),
            system_tx(SystemTxKind::RewardsGemDelivery, 2, 2),
            system_tx(SystemTxKind::BoundaryOutcome, 3, 2),
            system_tx(SystemTxKind::OracleSlashWindow, 4, 2),
            system_tx(SystemTxKind::HookEvents, 5, 2),
        ];
        let unexpected_boundary = split_system_layout(&unexpected_boundary_txs).expect("layout");
        assert!(matches!(
            validate_active_system_tx_set(&unexpected_boundary, 2, false, false),
            Err(SystemTxError::ActiveSystemTxSetMismatch { .. })
        ));
    }

    #[test]
    fn revert_fails_block_classifies_critical_begin_zone_phases() {
        // consensus- and economic-critical phases fail the block on
        // a revert/halt; non-critical phases keep the soft-receipt skip. Pin the
        // full classification so a new phase is forced to make this choice.
        for kind in [
            SystemTxKind::CertifiedParentAccounting,
            SystemTxKind::LateFinalizeCredits,
            SystemTxKind::CycleTick,
            SystemTxKind::BoundaryOutcome,
            SystemTxKind::TeeBootstrap,
        ] {
            assert!(
                kind.revert_fails_block(),
                "{kind:?} must fail the block on revert"
            );
        }
        for kind in [
            SystemTxKind::RewardsGemDelivery,
            SystemTxKind::OracleSlashWindow,
            SystemTxKind::HookEvents,
        ] {
            assert!(
                !kind.revert_fails_block(),
                "{kind:?} must keep the soft-receipt skip"
            );
        }
    }

    #[test]
    fn validate_active_system_tx_set_rejects_phase3b_outside_block1() {
        // TeeBootstrap is the mandatory block-1 Phase 3b and cannot be replayed
        // at a later height even when the body-derived flag says it is present.
        let txs = vec![
            system_tx(SystemTxKind::CertifiedParentAccounting, 0, 2),
            system_tx(SystemTxKind::LateFinalizeCredits, 1, 2),
            system_tx(SystemTxKind::CycleTick, 2, 2),
            system_tx(SystemTxKind::RewardsGemDelivery, 3, 2),
            system_tx(SystemTxKind::BoundaryOutcome, 4, 2),
            system_tx(SystemTxKind::TeeBootstrap, 5, 2),
            system_tx(SystemTxKind::OracleSlashWindow, 6, 2),
            system_tx(SystemTxKind::HookEvents, 7, 2),
        ];
        let layout = split_system_layout(&txs).expect("layout");
        assert!(validate_active_system_tx_set(&layout, 2, true, true).is_err());

        // Same bytes, but the flag says no bootstrap expected -> mismatch.
        assert!(matches!(
            validate_active_system_tx_set(&layout, 2, true, false),
            Err(SystemTxError::ActiveSystemTxSetMismatch { .. })
        ));

        // A later bootstrap without a boundary outcome is equally invalid.
        let txs_no_bo = vec![
            system_tx(SystemTxKind::CertifiedParentAccounting, 0, 2),
            system_tx(SystemTxKind::LateFinalizeCredits, 1, 2),
            system_tx(SystemTxKind::CycleTick, 2, 2),
            system_tx(SystemTxKind::RewardsGemDelivery, 3, 2),
            system_tx(SystemTxKind::TeeBootstrap, 4, 2),
            system_tx(SystemTxKind::OracleSlashWindow, 5, 2),
            system_tx(SystemTxKind::HookEvents, 6, 2),
        ];
        let layout_no_bo = split_system_layout(&txs_no_bo).expect("layout");
        assert!(validate_active_system_tx_set(&layout_no_bo, 2, false, true).is_err());
    }

    #[test]
    fn advance_after_commit_interleaves_optional_phase3b() {
        // CycleTick -> RewardsGemDelivery -> BoundaryOutcome -> TeeBootstrap -> OracleSlashWindow.
        let cycle = SystemTxPhase::CycleTick { body_index: 1 };
        let rewards = cycle.advance_after_commit(true, true);
        assert_eq!(rewards, SystemTxPhase::RewardsGemDelivery { body_index: 2 });
        let bo = rewards.advance_after_commit(true, true);
        assert_eq!(bo, SystemTxPhase::BoundaryOutcomeOptional { body_index: 3 });
        let tee = bo.advance_after_commit(true, true);
        assert_eq!(tee, SystemTxPhase::TeeBootstrapOptional { body_index: 4 });
        let oracle = tee.advance_after_commit(true, true);
        assert_eq!(oracle, SystemTxPhase::OracleSlashWindow { body_index: 5 });
        let hook_events = oracle.advance_after_commit(true, true);
        assert_eq!(hook_events, SystemTxPhase::HookEvents { body_index: 6 });
        assert_eq!(
            hook_events.advance_after_commit(true, true),
            SystemTxPhase::UserTxs
        );

        // No boundary, bootstrap present: CycleTick -> RewardsGemDelivery -> TeeBootstrap.
        assert_eq!(
            SystemTxPhase::CycleTick { body_index: 1 }.advance_after_commit(false, true),
            SystemTxPhase::RewardsGemDelivery { body_index: 2 }
        );
        assert_eq!(
            SystemTxPhase::RewardsGemDelivery { body_index: 2 }.advance_after_commit(false, true),
            SystemTxPhase::TeeBootstrapOptional { body_index: 3 }
        );

        // Neither: CycleTick -> RewardsGemDelivery -> OracleSlashWindow.
        assert_eq!(
            SystemTxPhase::CycleTick { body_index: 1 }.advance_after_commit(false, false),
            SystemTxPhase::RewardsGemDelivery { body_index: 2 }
        );
        assert_eq!(
            SystemTxPhase::RewardsGemDelivery { body_index: 2 }.advance_after_commit(false, false),
            SystemTxPhase::OracleSlashWindow { body_index: 3 }
        );
        assert_eq!(
            SystemTxPhase::OracleSlashWindow { body_index: 3 }.advance_after_commit(false, false),
            SystemTxPhase::HookEvents { body_index: 4 }
        );
    }

    #[test]
    fn reserved_address_does_not_collide_with_system_precompiles() {
        let addr_bytes = OUTBE_SYSTEM_TX_ADDRESS.0;
        assert_eq!(addr_bytes[0], 0xff);
        assert_ne!(addr_bytes[19], 0x00);
    }

    // ---------- : SystemTxPhase cursor tests ----------

    #[test]
    fn initial_for_block_block_1_is_cycletick() {
        // block 1 (genesis bootstrap) skips Phase 1 and starts at CycleTick.
        let cursor = SystemTxPhase::initial_for_block(1, GENESIS_BOOTSTRAP_BLOCK_NUMBER);
        assert_eq!(cursor, SystemTxPhase::CycleTick { body_index: 0 });
        assert_eq!(cursor.expected_kind(), Some(SystemTxKind::CycleTick));
        assert_eq!(cursor.body_index(), Some(0));
    }

    #[test]
    fn initial_for_block_block_2_is_phase1_preexecuted() {
        // Block 2 (first post-bootstrap block) starts at Phase1Preexecuted with
        // a zero placeholder tx_hash that the executor overwrites after the
        // Phase 1 preflight commits.
        let cursor = SystemTxPhase::initial_for_block(2, GENESIS_BOOTSTRAP_BLOCK_NUMBER);
        assert!(matches!(
            cursor,
            SystemTxPhase::Phase1Preexecuted {
                body_index: 0,
                receipt_index: 0,
                ..
            }
        ));
        if let SystemTxPhase::Phase1Preexecuted { tx_hash, .. } = cursor {
            assert_eq!(tx_hash, B256::ZERO);
        }
        assert_eq!(
            cursor.expected_kind(),
            Some(SystemTxKind::CertifiedParentAccounting)
        );
    }

    #[test]
    fn initial_for_block_block_0_is_cycletick_placeholder() {
        // Block 0 is genesis; it has no begin-zone txs at all, but the cursor
        // initialisation must not panic and must not pick the Phase 1 branch.
        let cursor = SystemTxPhase::initial_for_block(0, GENESIS_BOOTSTRAP_BLOCK_NUMBER);
        assert_eq!(cursor, SystemTxPhase::CycleTick { body_index: 0 });
    }

    #[test]
    fn expected_kind_returns_phase_for_each_variant() {
        let cases = [
            (
                SystemTxPhase::Phase1Preexecuted {
                    body_index: 0,
                    tx_hash: B256::ZERO,
                    receipt_index: 0,
                },
                Some(SystemTxKind::CertifiedParentAccounting),
            ),
            (
                SystemTxPhase::CycleTick { body_index: 1 },
                Some(SystemTxKind::CycleTick),
            ),
            (
                SystemTxPhase::RewardsGemDelivery { body_index: 2 },
                Some(SystemTxKind::RewardsGemDelivery),
            ),
            (
                SystemTxPhase::BoundaryOutcomeOptional { body_index: 3 },
                Some(SystemTxKind::BoundaryOutcome),
            ),
            (
                SystemTxPhase::TeeBootstrapOptional { body_index: 4 },
                Some(SystemTxKind::TeeBootstrap),
            ),
            (
                SystemTxPhase::OracleSlashWindow { body_index: 5 },
                Some(SystemTxKind::OracleSlashWindow),
            ),
            (
                SystemTxPhase::HookEvents { body_index: 6 },
                Some(SystemTxKind::HookEvents),
            ),
            (SystemTxPhase::UserTxs, None),
        ];
        for (phase, expected) in cases {
            assert_eq!(phase.expected_kind(), expected, "phase={phase:?}");
        }
    }

    #[test]
    fn body_index_matches_for_every_begin_zone_variant() {
        for (phase, expected) in [
            (
                SystemTxPhase::Phase1Preexecuted {
                    body_index: 0,
                    tx_hash: B256::ZERO,
                    receipt_index: 0,
                },
                Some(0),
            ),
            (SystemTxPhase::CycleTick { body_index: 1 }, Some(1)),
            (SystemTxPhase::RewardsGemDelivery { body_index: 2 }, Some(2)),
            (
                SystemTxPhase::BoundaryOutcomeOptional { body_index: 3 },
                Some(3),
            ),
            (
                SystemTxPhase::TeeBootstrapOptional { body_index: 4 },
                Some(4),
            ),
            (SystemTxPhase::OracleSlashWindow { body_index: 5 }, Some(5)),
            (SystemTxPhase::HookEvents { body_index: 6 }, Some(6)),
            (SystemTxPhase::UserTxs, None),
        ] {
            assert_eq!(phase.body_index(), expected, "phase={phase:?}");
        }
    }
}
