// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

/// @title IZeroFee
/// @notice ZeroFee paymaster precompile at 0x000000000000000000000000000000000000EE09.
///
/// Acts as the EIP-7702 delegation target for void sponsorship - EOAs
/// that delegate to this address may submit up to 8 free transactions
/// per UTC day, each capped by hard envelope limits enforced in the
/// txpool admission policy and re-enforced by the executor pre-fee
/// hook (`max_value == 0`, `gas_limit <= 500_000`, `calldata <= 16 KiB`,
/// `max_priority_fee_per_gas == 0`, target in
/// `SPONSORED_TARGET_WHITELIST`).
///
/// Authorization rules:
/// - signer must NOT be the paymaster itself (no self-sponsorship).
/// Native balance is not an eligibility signal: a correctly delegated
/// address with zero COEN may consume the same eight daily sponsored slots.
///
/// Counter encoding: a single `uint64` per signer packs
/// `(date_key uint32, count uint32)` where `date_key = yyyymmdd` (UTC).
/// Off-chain decoders recover `(day, count)` via
/// `(packed >> 32, packed & 0xFFFFFFFF)`.
interface IZeroFee {
    /// Emitted when the executor pre-fee hook grants a sponsored
    /// transaction to `signer` on UTC day `day` and bumps the
    /// per-signer counter to `newCount`. `newCount` is the post-write
    /// value (1..=FREE_TX_DAILY_LIMIT); the previous value is
    /// `newCount - 1`.
    event SponsorshipAuthorized(address indexed signer, uint32 indexed day, uint32 newCount);

    /// @notice Returns `true` if `signer` would be admitted to the
    /// sponsored path for this block. Equivalent to the executor
    /// pre-fee gate: rejects self-sponsorship and requires
    /// `count < FREE_TX_DAILY_LIMIT` for today's UTC day
    /// key. Wallets can call this before sending a sponsored
    /// transaction to surface a clean UX warning instead of waiting
    /// for a soft-failure receipt.
    function authorizeSponsorship(address signer) external view returns (bool);

    /// @notice Returns the EFFECTIVE `(day, count)` for `signer` as of
    /// the current block, with the lazy day-reset already applied:
    /// `day` is always today's UTC day key, and `count` is 0 if the
    /// stored slot belongs to an earlier day (or was never written).
    /// Remaining free txs = `FREE_TX_DAILY_LIMIT - count`. The raw
    /// pre-reset slot (`date_key << 32 | count`) is readable via
    /// `eth_getStorageAt` for anyone who needs it.
    function getCounter(address signer) external view returns (uint32 day, uint32 count);
}
