//! Constants for the zero-fee paymaster sponsorship policy.
//!
//! These are part of the protocol contract - changing them is a hard-fork
//! event. Fee shape errors share the generic `FeeCapTooLow` (code 105)
//! with the oracle hook because both paths require `priority_fee == 0`
//! and `max_fee >= MIN_PROTOCOL_BASE_FEE`. All other free-tx-specific
//! reasons occupy dedicated codes 110..=116:
//!
//! - 110 `FreeTxDailyExhausted` - daily quota burned
//! - 111 retired - formerly rejected zero-balance signers; MUST NOT be reused
//! - 112 `FreeTxDailyContractCreationForbidden` - `to == None`
//! - 113 `FreeTxDailyValueNotZero` - `msg.value != 0`
//! - 114 `FreeTxDailyGasLimitExceeded` - `gas_limit > FREE_TX_DAILY_GAS_LIMIT`
//! - 115 `FreeTxDailyCalldataTooLarge` - `calldata > FREE_TX_DAILY_CALLDATA_BYTES`
//! - 116 `FreeTxDailyTargetNotWhitelisted` - `to not in SPONSORED_TARGET_WHITELIST`
//!
//! See `hooks.rs::ZeroFeePolicyError::code` for the authoritative mapping.

use alloy_eips::eip1559::MIN_PROTOCOL_BASE_FEE;

/// Maximum number of sponsored free transactions per signer per UTC day.
pub const FREE_TX_DAILY_LIMIT: u32 = 8;

/// Maximum `gas_limit` accepted for a sponsored free transaction.
///
/// Caps the per-tx compute budget so 8 x N sybil-funded addresses cannot
/// exhaust a block on the sponsored path. 500_000 covers ERC-20 transfer
/// plus a small log, matching the typical onboarding interaction. The
/// TributeFactory has a separate, narrowly scoped limit because a ZK-enabled
/// `offerTribute` performs an UltraHonk verification.
pub const FREE_TX_DAILY_GAS_LIMIT: u64 = 500_000;

/// Maximum gas limit for the one-time self-authorized EIP-7702 bootstrap.
///
/// The bootstrap transaction only installs the canonical ZeroFee delegation
/// and calls the paymaster's read-only authorization view. It is deliberately
/// narrower than the ordinary sponsored-call budget.
pub const FREE_TX_BOOTSTRAP_GAS_LIMIT: u64 = 100_000;

/// Maximum sponsored gas limit for calls to the TributeFactory.
///
/// This matches the explicit transaction limit used by `outbe-cli tribute
/// offer` and leaves headroom above the verifier's 3,000,000 base gas without
/// broadening the limit for every sponsored target.
pub const FREE_TX_TRIBUTE_FACTORY_GAS_LIMIT: u64 = 8_000_000;

/// Maximum calldata size accepted for a sponsored free transaction.
///
/// Mirrors the existing oracle zero-fee envelope cap to prevent calldata
/// DoS through the free path.
pub const FREE_TX_DAILY_CALLDATA_BYTES: usize = 16 * 1024;

/// Minimum EIP-1559 fee cap accepted by Reth's public txpool.
///
/// Mirrors the oracle hook's threshold so both zero-fee paths agree on
/// the same lower bound. A free tx with `max_fee_per_gas` below this is
/// rejected with [`super::hooks::ZeroFeePolicyError::FeeCapTooLow`].
pub const MIN_FREE_TX_MAX_FEE_PER_GAS: u128 = MIN_PROTOCOL_BASE_FEE as u128;
