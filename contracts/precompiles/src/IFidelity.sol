// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

interface IFidelity {
    /// Fidelity Index for `account` at the current block timestamp.
    /// The cohort ledger is encrypted, so the caller must present an
    /// owner-signed, expiring authorization (EIP-191 `personal_sign` over
    /// "outbe/fidelity/query-auth/v1" || chainId || account || expiry). The
    /// enclave verifies it (signer == account, chain-scoped, expiry >= block
    /// timestamp) before decrypting. Intended for `eth_call`.
    function getFidelityIndex(address account, uint64 expiry, bytes calldata signature) external view returns (uint256);

    /// Fidelity Index for `account` evaluated at `timestamp` (same
    /// authorization as `getFidelityIndex`; the curve is pure, so any
    /// timestamp is answerable).
    function getFidelityIndexAt(address account, uint64 timestamp, uint64 expiry, bytes calldata signature)
        external
        view
        returns (uint256);

    /// Returns fidelity index decimals precision.
    function decimals() external view returns (uint8);

    /// Synthetic maximum Fidelity Index (saturating RCFI) at `timestamp`.
    /// Derived from the plaintext global anchor - no authorization needed.
    function maxFidelityIndexAt(uint64 timestamp) external view returns (uint256);

    /// Lowest league (inclusive).
    function minLeague() external view returns (uint16);

    /// Highest league (inclusive).
    function maxLeague() external view returns (uint16);
}
