// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {ICca} from "@precompiles/ICca.sol";

/// @title MockCcaRegistry
/// @notice Stand-in for the CCA registry precompile in tests.
/// @dev Written to be usable through `vm.etch`, which copies runtime code but **not** storage.
///      An etched copy therefore starts with every slot zero, so the mapping stores
///      `uint8(state) + 1` and reads zero as "unset". That makes an untouched, freshly etched
///      registry answer `Active` for every address - matching the `outbe_cca` precompile stub it
///      replaces - while `setState` can still pin any individual agent to another state.
contract MockCcaRegistry is ICca {
    /// @dev 0 = unset (answer `Active`); otherwise `uint8(state) + 1`.
    mapping(address => uint8) private _states;

    function setState(address cca, State state) external {
        _states[cca] = uint8(state) + 1;
    }

    /// @inheritdoc ICca
    function getCcaState(address cca) external view returns (State) {
        uint8 stored = _states[cca];
        return stored == 0 ? State.Active : State(stored - 1);
    }

    /// @inheritdoc ICca
    /// @dev ERC-165 only, matching what the `outbe_cca` precompile answers. A mock that claimed
    ///      more would hide a divergence rather than expose it.
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == 0x01ffc9a7;
    }
}
