// SPDX-License-Identifier: UNLICENSED

pragma solidity ^0.8.30;

import {IERC7786GatewaySource} from "../interfaces/IERC7786.sol";
import {SafeCast} from "@openzeppelin/contracts/utils/math/SafeCast.sol";

/**
 * @dev The single ERC-7786 attribute the gateway adapters understand: a per-message destination
 * execution gas limit.
 *
 * Applications pass it in the `attributes` array of {IERC7786GatewaySource-sendMessage} (and the
 * matching `quote`); each adapter translates the transport-agnostic value into its native mechanism
 * (LayerZero executor options, Hyperlane hook metadata). When the attribute is absent, the adapter
 * falls back to its own `defaultGasLimit`.
 */
library GasLimitAttribute {
    /// @dev `bytes4(keccak256("executionGasLimit(uint256)"))`.
    bytes4 internal constant SELECTOR = bytes4(keccak256("executionGasLimit(uint256)"));

    /// @dev ABI-encodes the attribute carrying `gasLimit`, for use in an ERC-7786 `attributes` array.
    function encode(uint256 gasLimit) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(SELECTOR, gasLimit);
    }

    /**
     * @dev Scans `attributes` for the executionGasLimit attribute, returning whether it was present
     * and the decoded gas limit (the last occurrence wins). Reverts
     * {IERC7786GatewaySource-UnsupportedAttribute} for any other attribute, as ERC-7786 requires.
     */
    function find(bytes[] calldata attributes) internal pure returns (bool found, uint256 gasLimit) {
        for (uint256 i = 0; i < attributes.length; i++) {
            bytes calldata attribute = attributes[i];
            bytes4 selector = attribute.length < 4 ? bytes4(0) : bytes4(attribute[0:4]);
            if (selector != SELECTOR) revert IERC7786GatewaySource.UnsupportedAttribute(selector);
            gasLimit = abi.decode(attribute[4:], (uint256));
            found = true;
        }
    }

    /**
     * @dev Resolves the destination gas for a message: the executionGasLimit attribute bounded to `uint128`, or
     * `defaultGasLimit` when the attribute is absent. Reverts as {find} for any other attribute, or via {SafeCast}
     * if the requested gas exceeds `uint128`.
     */
    function resolve(bytes[] calldata attributes, uint128 defaultGasLimit) internal pure returns (uint128) {
        (bool found, uint256 gasLimit) = find(attributes);
        return found ? SafeCast.toUint128(gasLimit) : defaultGasLimit;
    }
}
