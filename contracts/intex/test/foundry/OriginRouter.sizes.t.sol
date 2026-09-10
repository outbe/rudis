// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";

/// @dev EIP-170 runtime-size guard for OriginRouter.
///
/// OriginRouter inlines every `BridgeMsgCodec` encoder and is the tightest contract in the system.
/// `forge test` does NOT enforce EIP-170 on deploy, so a size regression passes the whole suite and
/// only surfaces in `forge build --sizes`. This test reads the compiled runtime bytecode from the
/// build artifact and fails the moment a change makes the contract undeployable.
contract OriginRouterSizeTest is Test {
    /// @notice EIP-170 maximum contract runtime bytecode size, in bytes.
    uint256 internal constant EIP170_LIMIT = 24_576;

    function test_OriginRouter_RuntimeSize_WithinEIP170() public {
        uint256 size = vm.getDeployedCode("OriginRouter.sol:OriginRouter").length;
        assertLe(size, EIP170_LIMIT, "OriginRouter runtime bytecode exceeds the EIP-170 limit");
    }
}
