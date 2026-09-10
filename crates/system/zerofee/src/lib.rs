//! System-level zero-fee transaction policy registry.
//!
//! Zero-fee transactions are still normal signed EVM transactions. This crate
//! owns the deterministic policy hooks that decide whether a specific public
//! transaction class may skip native fee debit. Execution and txpool crates only
//! adapt their transaction/state views into this registry.
//!
//! ## Two parallel mechanisms
//!
//! 1. **Trait-registry hooks** (`hooks.rs`, `oracle.rs`): stateless envelope
//!    classification + stateful authorization for protocol-defined
//!    transactions like `Oracle.submitVote`. The signer is authenticated by
//!    cross-module state (e.g. validator status).
//!
//! 2. **EIP-7702 paymaster precompile** (`schema.rs`, `state.rs`,
//!    `runtime.rs`, `precompile.rs`): a stateful precompile at
//!    [`outbe_primitives::addresses::ZEROFEE_ADDRESS`] that grants every EOA
//!    that has delegated to it (via an EIP-7702 set-code authorization) up to
//!    `FREE_TX_DAILY_LIMIT` free transactions per UTC day. The executor's
//!    pre-fee path detects the delegation designator and routes the
//!    transaction through the same `disable_balance_check`,
//!    `disable_base_fee`, and `disable_fee_charge` machinery that already
//!    serves oracle votes.

pub mod constants;
pub mod hooks;
mod intexfactory;
mod oracle;
pub mod precompile;
pub mod runtime;
pub mod schema;
pub mod state;

pub use constants::{
    FREE_TX_BOOTSTRAP_GAS_LIMIT, FREE_TX_DAILY_CALLDATA_BYTES, FREE_TX_DAILY_GAS_LIMIT,
    FREE_TX_DAILY_LIMIT, FREE_TX_TRIBUTE_FACTORY_GAS_LIMIT, MIN_FREE_TX_MAX_FEE_PER_GAS,
};
pub use hooks::{
    registry, ZeroFeeAuthorization, ZeroFeeCandidate, ZeroFeeHook, ZeroFeeHookId,
    ZeroFeePolicyError, ZeroFeeRegistry, ZeroFeeTransaction,
};
pub use intexfactory::{
    MAX_ZERO_FEE_CONTRIBUTOR_BATCH_CALLDATA_BYTES, MAX_ZERO_FEE_CONTRIBUTOR_BATCH_GAS_LIMIT,
    MIN_ZERO_FEE_CONTRIBUTOR_BATCH_MAX_FEE_PER_GAS,
};
pub use outbe_primitives::addresses::ZEROFEE_ADDRESS;
pub use runtime::{
    authorize_bootstrap, authorize_sponsorship, classify_bootstrap, classify_sponsorship,
    precheck_sponsorship, record_sponsorship_use, BootstrapAccountView, BootstrapCandidate,
    BootstrapTransactionView, SponsorshipAuthorization,
};
pub use schema::{pack_counter, unpack_counter, ZeroFeeContract};
