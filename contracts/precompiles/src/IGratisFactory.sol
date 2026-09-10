// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

/// @title IGratisFactory - Gratis orchestration entry point.
interface IGratisFactory {
    /// @notice Emitted when `sender` converts protocol-6 gratis to native-18 COEN.
    /// @param amount Native COEN atomic units minted to `sender`.
    event RudisMined(address indexed sender, uint256 amount);

    /// @notice Emitted when a user pledges gratis as credis collateral.
    /// `pledgeHandle` is the confidential record id presented later at
    /// `requestCredis`. NOTE: both amounts are public (calldata / event); only
    /// cumulative balances are encrypted (see the gratis amount-privacy TODO).
    event GratisPledged(
        address indexed account,
        uint256 amountStables,
        address indexed asset,
        uint256 gratisAmount,
        bytes32 pledgeHandle
    );

    /// @notice Emitted when an unspent pledge is returned to the caller.
    ///         `gratisAmount` is the collateral credited back.
    event GratisUnpledged(address indexed account, uint256 gratisAmount);

    /// @notice Pledge enough gratis to collateralize `amountStables` of credit in
    ///         `asset`. The gratis cost is derived on-chain from the oracle rate and
    ///         sealed into the pledge ticket together with the asset and the rate, so
    ///         `requestCredis` disburses exactly `amountStables` without re-pricing.
    ///         Authorized by the caller's Gratis modify key:
    ///         `mac = HMAC(modifyKey, op-preimage over amountStables)` where `opNonce`
    ///         MUST equal the caller's current on-chain gratis op-nonce (fetch via
    ///         `rudis_deriveKeys` + `opNonceOf`).
    /// @param amountStables Stablecoin minor units of credit this pledge must cover.
    /// @param asset         Stablecoin the credis will later be disbursed in.
    /// @param maxGratis     Slippage cap: reverts if the oracle-derived gratis cost
    ///                      exceeds it. Authenticated by the transaction signature.
    /// @return pledgeHandle The confidential pledge record id. Hand it (and the
    ///         derived pledge secret) to the CCA to request credis.
    function pledgeGratis(uint256 amountStables, address asset, uint256 maxGratis, bytes32 mac, uint64 opNonce)
        external
        returns (bytes32 pledgeHandle);

    /// @notice Directly unpledge an UNSPENT pledge (e.g. credis rejected),
    ///         releasing the full collateral back to `msg.sender`. Authorized by
    ///         the caller's modify key. `amountStables` is the figure the pledge was
    ///         quoted for and must match the one sealed in the ticket.
    // todo remove amountStables
    function unpledgeGratis(uint256 amountStables, bytes32 pledgeHandle, bytes32 mac, uint64 opNonce) external;

    /// @notice Convert `amount` protocol-6 gratis to the same whole-token amount of
    ///         native-18 COEN (burns gratis). The return value and
    ///         `RudisMined.amount` are native COEN atomic units. Authorized by the
    ///         caller's modify key.
    function mineRudis(uint256 amount, bytes32 mac, uint64 opNonce) external returns (uint256);

    /// @notice ERC-165 conformance check.
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}
