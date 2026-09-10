// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {Vm} from "forge-std/Vm.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";
import {MockERC7786Bridge} from "@test-mocks/MockERC7786Bridge.sol";

/// @dev Base for cross-chain protocol tests. A single loopback {MockERC7786Bridge} stands in for the hub; logical
///      chainIds are explicit and delivery is manual (via {_deliver}), so a send never auto-loops unless a test opts
///      in. Replaces the ERC-7786 `TestHelperOz5` harness.
abstract contract CrossChainTest is Test {
    MockERC7786Bridge internal bridge;

    /// @dev Deploy the loopback bridge with manual delivery. Call from `setUp`.
    function _setUpBridge() internal {
        bridge = new MockERC7786Bridge();
        bridge.setAutoDeliver(false);
    }

    /// @dev ERC-7930 interoperable address for `a` on `chainId`.
    function _interop(uint32 chainId, address a) internal pure returns (bytes memory) {
        return InteroperableAddress.formatEvmV1(chainId, a);
    }

    /// @dev How many recorded logs carry `sig` as topic0. Requires a prior `vm.recordLogs()`.
    function _countTopic(bytes32 sig) internal returns (uint256 n) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].topics[0] == sig) n++;
        }
    }

    /// @dev Deliver `packet` to `recipient` as if sent by `src` on `srcChainId` (the bridge is the caller).
    function _deliver(uint32 srcChainId, address src, address recipient, bytes memory packet) internal {
        bridge.deliverAs(_interop(srcChainId, src), _interop(uint32(block.chainid), recipient), packet);
    }
}
