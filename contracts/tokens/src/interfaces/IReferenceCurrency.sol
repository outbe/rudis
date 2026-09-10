// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @title IReferenceCurrency
/// @notice Implemented by asset (ERC20) tokens that denominate a reference
///         currency. The Credis Factory calls `isoCode()` on the disbursed
///         asset at issuance to learn the position's issuance currency and to
///         look up the matching currency rate from the Oracle.
interface IReferenceCurrency {
    /// @notice ISO 4217 numeric currency code for this asset (e.g. 840 = USD).
    function isoCode() external view returns (uint16);
}
