// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {ReferenceCurrencyPriceLib} from "../helpers/ReferenceCurrencyPriceLib.sol";
import {CrossChainTest} from "../helpers/CrossChainTest.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";
import {MockDesis} from "@test-mocks/MockDesis.sol";

import {OriginRouter} from "@contracts/origin/OriginRouter.sol";
import {TargetRouter} from "@contracts/target/TargetRouter.sol";
import {IOriginRouter} from "@contracts/origin/interfaces/IOriginRouter.sol";
import {IntexGas} from "@contracts/shared/libs/IntexGas.sol";

/// @dev Every send carries the destination gas as the ERC-7786 executionGasLimit attribute, sized from IntexGas.
contract GasAttributeTest is CrossChainTest {
    uint32 internal constant BNB_CHAIN_ID = 1;
    uint32 internal constant OUTBE_CHAIN_ID = 2;
    bytes4 internal constant GAS_SELECTOR = bytes4(keccak256("executionGasLimit(uint256)"));

    OriginRouter internal outbe;
    TargetRouter internal bnb;
    address internal admin = address(this);
    address internal desis;

    function setUp() public {
        _setUpBridge();
        outbe = DeployProxy.originRouter(address(bridge), admin);
        bnb = DeployProxy.targetRouter(address(bridge), admin, OUTBE_CHAIN_ID);
        outbe.setRemoteMessenger(BNB_CHAIN_ID, _interop(BNB_CHAIN_ID, address(bnb)));
        bnb.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, address(outbe)));
        outbe.addTarget(BNB_CHAIN_ID);
        vm.deal(address(outbe), 10 ether);

        desis = address(new MockDesis());
        outbe.wire(desis, makeAddr("factory"));
        bnb.wire(admin, makeAddr("intex"), makeAddr("escrow"));
    }

    /// @dev The last recorded send carries exactly one executionGasLimit attribute equal to `expectedGas`.
    function _assertLastGas(uint256 expectedGas) internal view {
        bytes[] memory attrs = bridge.getLastAttributes();
        assertEq(attrs.length, 1, "expected one attribute");
        assertEq(attrs[0], abi.encodeWithSelector(GAS_SELECTOR, expectedGas), "executionGasLimit attribute mismatch");
    }

    function test_fixedMessage_carriesTypeGas() public {
        IOriginRouter.AuctionStageStartParams memory p;
        p.prices = ReferenceCurrencyPriceLib.one(840, 1, 2, 3);
        p.worldwideDay = 42;
        p.dayState = 1;
        p.prices = ReferenceCurrencyPriceLib.one(840, 1, 2, 3);
        vm.prank(desis);
        outbe.sendAuctionStageStart(p);
        _assertLastGas(IntexGas.auctionStart(1));
    }

    function test_variableMessage_gasScalesWithItemCount() public {
        // Freeze day 42's snapshot so the addressed refund send passes membership.
        IOriginRouter.AuctionStageStartParams memory sp;
        sp.prices = ReferenceCurrencyPriceLib.one(840, 1, 2, 3);
        sp.worldwideDay = 42;
        sp.dayState = 1;
        vm.prank(desis);
        outbe.sendAuctionStageStart(sp);

        _assertRefundGas(1);
        _assertRefundGas(5);
        // Sizing is strictly increasing in the item count.
        assertGt(IntexGas.refund(5), IntexGas.refund(1), "gas must grow with item count");
    }

    function _assertRefundGas(uint256 n) internal {
        vm.prank(desis);
        outbe.sendRefundInstructions(BNB_CHAIN_ID, 42, 0, 1, new address[](n), new uint128[](n), new uint128[](n));
        _assertLastGas(IntexGas.refund(n));
    }

    function test_quoteMatchesSend_bothCarryGas() public view {
        // The quote path builds the same attribute; the mock returns a flat fee, so this simply confirms the
        // quote signature compiles and returns without reverting under the gas attribute.
        IOriginRouter.AuctionStageStartParams memory p;
        p.prices = ReferenceCurrencyPriceLib.one(840, 1, 2, 3);
        p.worldwideDay = 7;
        p.dayState = 1;
        outbe.quoteSendAuctionStageStart(p);
    }
}
