//! Consensus block-timing defaults and the gas <-> consensus-timeout contract.
//!
//! This module is the single source of *default* values for the three
//! consensus-sync timing knobs. The live values are read from `genesis.json`
//! (`config.minBlockTimeMs` / `config.leaderTimeoutMs` /
//! `config.certificationTimeoutMs`), each falling back to the default here when
//! absent. There is **no CLI flag** for any of the three: the only two sources of
//! truth are these Rust defaults and `genesis.json`. A third (per-node CLI)
//! source would let operators desync their timings and fork the network, so it is
//! deliberately not offered.
//!
//! # The model (execute-then-agree)
//!
//! Every block's transactions run through REVM **twice, serially**: once on the
//! proposer (build) and once on each validator (verify, on the critical path to
//! the vote). The proposal is a fully executed, sealed block - its hash binds the
//! post-execution state root - so a validator cannot start verifying until it has
//! received the proposer's executed block. Simplex arms `leader_deadline` and
//! `certification_deadline` from the same view-entry instant `t0`.
//!
//! There is **no separate REVM execution timeout**. REVM is bounded from two
//! sides that already exist: above by `leader_timeout` (the proposer self-
//! nullifies if it overruns its leader window) and in volume by `block_gas_limit`.
//! A wall-clock kill on REVM is pointless on the proposer (the leader timeout
//! already bounds it) and forbidden on validators (a per-node wall-clock verdict
//! on the same block would split consensus).
//!
//! # Gas <-> consensus-timeout formula
//!
//! The certification window splits into two named sub-windows:
//!
//! - **Max block-*creation* time = `leaderTimeoutMs`** - the proposer's window to
//!   build and deliver the proposal. The leader self-nullifies (forfeits its
//!   slot) if it overruns; nothing else bounds build time.
//! - **Max block-*validation* time = `certificationTimeoutMs - leaderTimeoutMs`**
//!   what remains of the certification window after proposal delivery, for
//!   every validator's `new_payload` re-execution **plus** the 2f+1 vote round.
//!
//! **Calibration rule (the single dial):** size `gasLimit` so a *full*
//! (gas-saturated) block's `new_payload` on the *slowest* validator, plus the
//! vote round, fits strictly inside the validation window:
//!
//! ```text
//! full_block_exec_time(gasLimit, slowest_validator) + vote_round
//!     <  certificationTimeoutMs - leaderTimeoutMs
//! ```
//!
//! With the defaults below (`leader 4000`, `cert 8000`) the validation window is
//! 4000 ms; targeting full-block exec <= ~2 s leaves ~2 s for votes + margin.
//! `gasLimit` is the *only* knob - turn it and re-derive `leader`/`cert` to fit.
//! ZeroFee admission means resizing `gasLimit` has no fee-market side effect.
//!
//! # Why the default floor is 2000 ms (L2 rationale)
//!
//! [`DEFAULT_MIN_BLOCK_TIME_MS`] is set to 2 s **deliberately for L2
//! settlement/sync cadence**, not as an arbitrary number. The floor is
//! proposer-side liveness pacing only: the elected leader holds an already-sealed
//! block until the floor elapses before handing its digest to Simplex. It never
//! enters block bytes and is never a validation rule. Recording the rationale
//! here lets future maintainers and auditors reason about the protocol's pacing
//! intent rather than treating 2 s as a magic constant.
//!
//! # Startup invariants
//!
//! Enforced by the genesis reader at node start (structured error, no panic):
//! `0 < minBlockTimeMs < leaderTimeoutMs <= certificationTimeoutMs`. A
//! `minBlockTimeMs` of `0` is rejected (the floor cannot be disabled).

/// Default minimum block time (proposer-side liveness floor), in milliseconds.
///
/// 2 s is the L2 settlement/sync cadence (see module docs). `0` is rejected at
/// startup; an absent genesis key falls back to this value.
pub const DEFAULT_MIN_BLOCK_TIME_MS: u64 = 2000;

/// Default Simplex leader (proposal) timeout, in milliseconds.
///
/// The proposer must build and deliver its proposal within this window or it
/// self-nullifies. Also the max block-*creation* time in the gas<->timeout formula.
pub const DEFAULT_LEADER_TIMEOUT_MS: u64 = 4000;

/// Default Simplex certification (notarization) timeout, in milliseconds.
///
/// Spans leader delivery + validator re-execution + the 2f+1 vote round. The
/// validation window is
/// `DEFAULT_CERTIFICATION_TIMEOUT_MS - DEFAULT_LEADER_TIMEOUT_MS`.
pub const DEFAULT_CERTIFICATION_TIMEOUT_MS: u64 = 8000;

/// Default payload warm-up before the first `resolve_kind`, in milliseconds.
///
/// Mirrors the existing payload-resolve preparation window; unchanged by the
/// minimum-block-time feature and kept here so all timing defaults live together.
pub const DEFAULT_PAYLOAD_WARMUP_MS: u64 = 200;
