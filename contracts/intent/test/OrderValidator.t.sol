// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test} from "forge-std/Test.sol";

import {OrderValidator} from "../src/libs/OrderValidator.sol";
import {OrderEncoder} from "../src/libs/OrderEncoder.sol";
import {TypeCasts} from "../src/libs/TypeCasts.sol";
import {OrderData} from "../src/interfaces/OrderTypes.sol";
import {IDestinationSettler} from "../src/interfaces/IDestinationSettler.sol";

/// @dev Wraps the internal library in an external function so `originData` is calldata and a
///      branch revert surfaces at a call boundary for vm.expectRevert.
contract OrderValidatorHarness {
    function decodeAndCheck(bytes calldata originData, bytes32 orderId, uint256 outputAmount)
        external
        view
        returns (OrderData memory)
    {
        return OrderValidator.decodeAndCheck(originData, orderId, outputAmount);
    }
}

/// @title OrderValidatorTest
/// @notice Direct unit tests for OrderValidator.decodeAndCheck - one per branch plus a fuzz on the
///         outputAmount floor (OIP-00035 T-01). The library is load-bearing for the OIP-00023
///         amountOut-floor invariant, so each branch is isolated rather than covered transitively.
contract OrderValidatorTest is Test {
    using TypeCasts for address;

    OrderValidatorHarness internal harness;

    function setUp() public {
        harness = new OrderValidatorHarness();
    }

    function _validFixture() internal view returns (OrderData memory) {
        return OrderData({
            sender: address(0xA11CE).addressToBytes32(),
            recipient: address(0xB0B).addressToBytes32(),
            inputToken: address(0x1117).addressToBytes32(),
            outputToken: address(0x2227).addressToBytes32(),
            amountIn: 1000,
            amountOut: 1000,
            senderNonce: 1,
            originDomain: 1,
            destinationDomain: 2,
            destinationSettler: address(0xDE57).addressToBytes32(),
            fillDeadline: uint32(block.timestamp + 1000),
            data: new bytes(0)
        });
    }

    function test_decodeAndCheck_happyPath() public view {
        OrderData memory order = _validFixture();
        bytes memory originData = OrderEncoder.encode(order);
        bytes32 orderId = OrderEncoder.id(order);

        OrderData memory result = harness.decodeAndCheck(originData, orderId, order.amountOut);

        assertEq(result.amountOut, order.amountOut, "amountOut");
        assertEq(result.fillDeadline, order.fillDeadline, "fillDeadline");
        assertEq(result.senderNonce, order.senderNonce, "senderNonce");
    }

    function test_decodeAndCheck_revertsOnOrderIdMismatch() public {
        OrderData memory order = _validFixture();
        bytes memory originData = OrderEncoder.encode(order);
        bytes32 wrongId = bytes32(uint256(1));
        assertTrue(OrderEncoder.id(order) != wrongId, "fixture id collides with wrongId");

        vm.expectRevert(IDestinationSettler.InvalidOrderId.selector);
        harness.decodeAndCheck(originData, wrongId, order.amountOut);
    }

    function test_decodeAndCheck_revertsOnExpiredDeadline() public {
        OrderData memory order = _validFixture();
        bytes memory originData = OrderEncoder.encode(order);
        bytes32 orderId = OrderEncoder.id(order);

        vm.warp(uint256(order.fillDeadline) + 1);

        vm.expectRevert(IDestinationSettler.OrderFillExpired.selector);
        harness.decodeAndCheck(originData, orderId, order.amountOut);
    }

    function test_decodeAndCheck_revertsOnBelowFloor() public {
        OrderData memory order = _validFixture();
        bytes memory originData = OrderEncoder.encode(order);
        bytes32 orderId = OrderEncoder.id(order);

        vm.expectRevert(IDestinationSettler.BelowMinimumOutput.selector);
        harness.decodeAndCheck(originData, orderId, order.amountOut - 1);
    }

    function test_decodeAndCheck_revertsOnMalformedOriginData() public {
        // Too short to abi.decode into OrderData (a tuple with a dynamic `data` member).
        bytes memory originData = hex"abcd";

        vm.expectRevert();
        harness.decodeAndCheck(originData, bytes32(0), 0);
    }

    function testFuzz_decodeAndCheck_outputAmountBounds(uint256 outputAmount) public {
        OrderData memory order = _validFixture();
        bytes memory originData = OrderEncoder.encode(order);
        bytes32 orderId = OrderEncoder.id(order);

        if (outputAmount >= order.amountOut) {
            OrderData memory result = harness.decodeAndCheck(originData, orderId, outputAmount);
            assertEq(result.amountOut, order.amountOut, "amountOut at/above floor");
        } else {
            vm.expectRevert(IDestinationSettler.BelowMinimumOutput.selector);
            harness.decodeAndCheck(originData, orderId, outputAmount);
        }
    }
}
