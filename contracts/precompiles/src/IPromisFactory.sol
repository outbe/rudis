// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

/// @title IPromisFactory - Promis mint/burn orchestration entry point (0x2337).
interface IPromisFactory {
    /// @notice Emitted when `sender` converts protocol-6 promis to native-18 COEN.
    /// @param amount Native COEN atomic units minted to `sender`.
    event RudisMined(address indexed sender, uint256 amount);

    /// @notice Convert `amount` protocol-6 promis to the same whole-token amount of
    ///         native-18 COEN (burns the caller's confidential promis). The return
    ///         value and `RudisMined.amount` are native COEN atomic units.
    ///         Authorized by the caller's Promis modify key:
    ///         `mac = HMAC(modifyKey, op-preimage)` where `opNonce` MUST equal the
    ///         caller's current on-chain promis op-nonce (fetch via
    ///         `rudis_deriveKeys` + `IPromis.opNonceOf`).
    function mineRudis(uint256 amount, bytes32 mac, uint64 opNonce) external returns (uint256);

    /// @notice Convert `amount` promis to confidential Gratis at 1:1 (burns the
    ///         caller's confidential promis, mints gratis). Both tokens are
    ///         enclave-confidential and independently keyed, so the caller supplies
    ///         TWO modify authorizations, each binding `amount` to that ledger's own
    ///         current op-nonce. Fetch each via `rudis_deriveKeys(<ledger>, ...)` +
    ///         `opNonceOf`. The gratis mint records a fresh Fidelity acquisition
    ///         cohort, exactly as any other gratis acquisition does.
    function mineGratis(
        uint256 amount,
        bytes32 promisMac,
        uint64 promisOpNonce,
        bytes32 gratisMac,
        uint64 gratisOpNonce
    ) external returns (uint256);

    /// @notice ERC-165 conformance check.
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}
