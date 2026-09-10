// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

/// @title ICredisFactory - credis lifecycle orchestrator.
interface ICredisFactory {
    event CredisRequested(address indexed smartAccount, address indexed cca, uint256 amount);

    /// @notice Open a credis position against a confidential Gratis pledge. Called by
    ///         the CCA, which presents `pledgeHandle` (the public id returned by
    ///         `pledgeGratis`) and `spendAuth` = HMAC(pledgeSecret,
    ///         "credis-bind" || smartAccount), where the pledger EOA derived
    ///         `pledgeSecret` from its modify key + the handle off-chain. The
    ///         pledge-lock ticket is consumed once and bound to `smartAccount`.
    ///         The disbursed amount and the asset are NOT calldata: both were sealed
    ///         into the ticket at `pledgeGratis` time, so the loan is issued at the
    ///         price the pledger accepted. `msg.sender` is recorded on the position
    ///         as the originating CCA.
    ///
    /// `msg.sender` must be a CCA in `Active` standing at the registry, and
    /// `smartAccount` must already be deployed - the loan is delivered by a
    /// call into it, which would silently succeed against a codeless account.
    ///
    /// The call is payable and `msg.value` must equal the pledged collateral
    /// exactly, in COEN: the CCA matches the borrower's stake one for one. That
    /// COEN is forwarded to `smartAccount` at origination as ordinary unrestricted
    /// balance and never returns to the CCA - settlement and void leave it alone.
    /// The required amount is not in calldata - it was sealed into the ticket at
    /// pledge time - so read it from the pledge quote before calling.
    /// @param referenceCurrency ISO 4217 numeric code of the threshold-evaluation
    ///        anchor, elected here and fixed for the position's life. Must be a
    ///        registered reference currency; the call price is struck from the
    ///        COEN/<referenceCurrency> quote and the daily breach scan reads that same
    ///        series. Passing the disbursed asset's own currency reuses the rate sealed
    ///        at `pledgeGratis`, so the threshold cannot drift between pledge and
    ///        origination; any other currency is quoted at origination instead. It does
    ///        not denominate the position.
    /// @return positionId Derived from `pledgeHandle` and `smartAccount`.
    /// @return amountStables Stablecoin amount disbursed, as quoted at pledge time.
    function requestCredis(address smartAccount, bytes32 pledgeHandle, bytes32 spendAuth, uint16 referenceCurrency)
        external
        payable
        returns (uint256 positionId, uint256 amountStables);

    /// @notice Settle `amount` against a position and release the matching share of
    ///         collateral from the pledged lock ledger back to its balance.
    ///         A position is settleable from the moment it opens. Payment is applied
    ///         interest first, principal second, so an `amount` below the interest accrued
    ///         since the last settlement is rejected - query
    ///         `ICredis.accruedInterest` for that floor. Collateral is released in
    ///         proportion to the principal covered, and the settlement that clears
    ///         the last of the outstanding principal releases exactly the remainder,
    ///         leaving no dust.
    ///         When `amount` exceeds what the position still needs, only the required
    ///         part is pulled from the caller. Any caller may settle, including on
    ///         behalf of another account: the debt is pulled from the caller's own
    ///         balance while the freed collateral is always released to the original
    ///         pledger, so a payer can never redirect value to themselves.
    /// @return principal Principal covered by this settlement. Drives the collateral
    ///         released and the reduction in the position's outstanding balance.
    /// @return interest Accrued interest collected by this settlement. Taken in full
    ///         before any principal, and never carried between settlements.
    function settle(uint256 positionId, uint256 amount) external returns (uint256 principal, uint256 interest);

    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}
