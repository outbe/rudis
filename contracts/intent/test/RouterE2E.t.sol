// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {ResetPeriod} from "the-compact/src/types/ResetPeriod.sol";
import {Scope} from "the-compact/src/types/Scope.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";

import {Router} from "../src/router/Router.sol";
import {BaseRouter} from "../src/router/BaseRouter.sol";
import {Auction} from "../src/Auction.sol";
import {SolverAllocator} from "../src/allocators/SolverAllocator.sol";
import {SolverEscrow} from "../src/SolverEscrow.sol";
import {OnchainCrossChainOrder} from "../src/interfaces/OrderTypes.sol";
import {OrderData, OrderEncoder} from "../src/libs/OrderEncoder.sol";
import {RouterMessage} from "../src/libs/RouterMessage.sol";
import {TypeCasts} from "../src/libs/TypeCasts.sol";

import {BaseTest} from "./BaseTest.sol";
import {MockERC7786Bridge} from "./mocks/MockERC7786Bridge.sol";
import {MockTheCompact} from "./mocks/MockTheCompact.sol";
import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {NotWhitelisted, Whitelist} from "@shared/Whitelist.sol";

event Settle(bytes32[] orderIds, bytes[] ordersFillerData);

event Refund(bytes32[] orderIds);

/// @dev Test wrapper with a fixed local domain (domain == logical chain id for the simulation).
contract RouterWithDomain is Router {
    uint32 private immutable _FIXED_LOCAL_DOMAIN;

    constructor(
        address _bridge,
        address _owner,
        uint32 fixedDomain,
        address _compact,
        bytes12 _lockTag,
        address _escrow,
        address _auction
    ) Router(_bridge, _owner, _compact, _lockTag, _escrow, _auction) {
        _FIXED_LOCAL_DOMAIN = fixedDomain;
    }

    function _localDomain() internal view override returns (uint32) {
        return _FIXED_LOCAL_DOMAIN;
    }
}

/// @title RouterE2E
/// @notice End-to-end tests for the composition {Router} using a loopback ERC-7786 bridge mock.
contract RouterE2E is BaseTest {
    using TypeCasts for address;

    MockERC7786Bridge internal originBridge;
    MockERC7786Bridge internal destBridge;

    MockTheCompact internal mockCompact;
    MockTheCompact internal destCompact;
    SolverEscrow internal destEscrow;

    RouterWithDomain internal originRouter;
    RouterWithDomain internal destinationRouter;

    Auction internal auction;

    address internal owner = address(this);
    bytes32 constant SALT = bytes32(uint256(42));

    function setUp() public virtual override {
        super.setUp();

        // Each bridge represents one chain (localChainId == domain) and routes to the other.
        originBridge = new MockERC7786Bridge(origin);
        destBridge = new MockERC7786Bridge(destination);
        originBridge.setRemoteBridge(destination, destBridge);
        destBridge.setRemoteBridge(origin, originBridge);

        mockCompact = new MockTheCompact();
        destCompact = new MockTheCompact();

        auction = new Auction(owner);

        (destinationRouter, destEscrow) = _deployRouterWithEscrow(destBridge, destination, destCompact, 1000);
        auction.setRouter(address(destinationRouter));

        // Solvers deposit collateral on destination.
        uint256 collateralDeposit = 1000;
        address[3] memory solvers = [vegeta, kakaroto, karpincho];
        for (uint256 i = 0; i < solvers.length; i++) {
            vm.startPrank(solvers[i]);
            destCompact.setOperator(address(destEscrow), true);
            outputToken.approve(address(destEscrow), collateralDeposit);
            destEscrow.deposit(address(outputToken), collateralDeposit);
            destEscrow.deposit{value: collateralDeposit}(address(0), 0);
            vm.stopPrank();
        }

        originRouter = new RouterWithDomain(
            address(originBridge), owner, origin, address(mockCompact), bytes12(uint96(1)), address(0), address(auction)
        );

        // Register the matching Router on each side (ERC-7930 interop addresses; domain == chainId).
        originRouter.setRemoteRouter(destination, _interop(destination, address(destinationRouter)));
        destinationRouter.setRemoteRouter(origin, _interop(origin, address(originRouter)));

        balanceId[address(mockCompact)] = 4;
        balanceId[address(originRouter)] = 4;
        balanceId[address(destinationRouter)] = 5;
        users.push(address(mockCompact));
        users.push(address(destinationRouter));
    }

    receive() external payable {}

    // ========== Helpers ==========

    function _interop(uint256 chainId, address addr) internal pure returns (bytes memory) {
        return InteroperableAddress.formatEvmV1(chainId, addr);
    }

    function _prepareOrderData() internal view returns (OrderData memory) {
        return OrderData({
            sender: TypeCasts.addressToBytes32(kakaroto),
            recipient: TypeCasts.addressToBytes32(karpincho),
            inputToken: TypeCasts.addressToBytes32(address(inputToken)),
            outputToken: TypeCasts.addressToBytes32(address(outputToken)),
            amountIn: amount,
            amountOut: amount,
            senderNonce: 1,
            originDomain: origin,
            destinationDomain: destination,
            destinationSettler: address(destinationRouter).addressToBytes32(),
            fillDeadline: uint32(block.timestamp + 100),
            data: new bytes(0)
        });
    }

    function _doFullAuction(address solver, bytes32 orderId, uint256 outputAmount, bytes memory originData) internal {
        vm.prank(solver);
        auction.commit(orderId, keccak256(abi.encode(orderId, outputAmount, SALT)));
        vm.warp(block.timestamp + auction.commitPeriod());
        vm.prank(solver);
        auction.reveal(orderId, outputAmount, SALT, originData);
        vm.warp(block.timestamp + auction.revealPeriod());
    }

    function _deployRouterWithEscrow(MockERC7786Bridge bridge, uint32 fixedDomain, MockTheCompact compact, uint256 bps)
        internal
        returns (RouterWithDomain router, SolverEscrow esc)
    {
        SolverAllocator alloc = new SolverAllocator(address(compact));
        bytes12 tag = alloc.buildLockTag(Scope.ChainSpecific, ResetPeriod.TenMinutes);

        esc = new SolverEscrow(address(compact), tag, bps);
        alloc.setArbiter(address(esc));

        router = new RouterWithDomain(
            address(bridge), owner, fixedDomain, address(compact), tag, address(esc), address(auction)
        );

        esc.setAuthorizedCaller(address(router));
    }

    function _openOrder() internal returns (bytes32 orderId, OnchainCrossChainOrder memory order) {
        OrderData memory orderData = _prepareOrderData();
        order = OnchainCrossChainOrder({
            fillDeadline: orderData.fillDeadline,
            orderDataType: OrderEncoder.orderDataType(),
            orderData: OrderEncoder.encode(orderData)
        });

        vm.startPrank(kakaroto);
        inputToken.approve(address(originRouter), amount);
        originRouter.open(order);
        vm.stopPrank();

        orderId = OrderEncoder.id(orderData);
    }

    // ========== Tests ==========

    function _ids(bytes32 orderId) internal pure returns (bytes32[] memory ids) {
        ids = new bytes32[](1);
        ids[0] = orderId;
    }

    function test_emergencyWithdraw_releasesInputToOwner() public {
        (bytes32 orderId,) = _openOrder();

        uint256 before = inputToken.balanceOf(owner);
        originRouter.emergencyWithdraw(_ids(orderId));

        assertEq(inputToken.balanceOf(owner), before + amount, "input released");
        assertEq(originRouter.orderStatus(orderId), originRouter.REFUNDED(), "status");
    }

    function test_emergencyWithdraw_onlyOwner() public {
        (bytes32 orderId,) = _openOrder();

        vm.prank(vegeta);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, vegeta));
        originRouter.emergencyWithdraw(_ids(orderId));
    }

    function test_emergencyWithdraw_revertsWhenAlreadyWithdrawn() public {
        (bytes32 orderId,) = _openOrder();

        originRouter.emergencyWithdraw(_ids(orderId));
        vm.expectRevert("order not open");
        originRouter.emergencyWithdraw(_ids(orderId));
    }

    function test_open_ungatedUntilWhitelistIsSet() public {
        assertEq(address(originRouter.whitelist()), address(0));
        _openOrder(); // vegeta is not on any list; open() must still work
    }

    function test_open_gatedOnceWhitelistIsSet() public {
        address[] memory allowed = new address[](1);
        allowed[0] = kakaroto;
        originRouter.setWhitelist(address(new Whitelist(owner, allowed)));

        OrderData memory orderData = _prepareOrderData();
        OnchainCrossChainOrder memory order = OnchainCrossChainOrder({
            fillDeadline: orderData.fillDeadline,
            orderDataType: OrderEncoder.orderDataType(),
            orderData: OrderEncoder.encode(orderData)
        });

        vm.startPrank(vegeta);
        inputToken.approve(address(originRouter), amount);
        vm.expectRevert(abi.encodeWithSelector(NotWhitelisted.selector, vegeta));
        originRouter.open(order);
        vm.stopPrank();

        _openOrder(); // kakaroto is on the list
    }

    function test_setWhitelist_onlyOwner() public {
        vm.prank(vegeta);
        vm.expectRevert(abi.encodeWithSelector(Ownable.OwnableUnauthorizedAccount.selector, vegeta));
        originRouter.setWhitelist(address(1));
    }

    function test_open_fill_settle() public {
        (bytes32 orderId, OnchainCrossChainOrder memory order) = _openOrder();

        _doFullAuction(vegeta, orderId, amount, order.orderData);
        destinationRouter.claimOrder(orderId, order.orderData);

        vm.startPrank(vegeta);
        outputToken.approve(address(destinationRouter), amount);
        bytes memory fillerData = abi.encode(TypeCasts.addressToBytes32(vegeta));
        destinationRouter.fill(orderId, order.orderData, fillerData);
        assertEq(destinationRouter.destinationOrderStatus(orderId), destinationRouter.FILLED());

        bytes32[] memory orderIds = new bytes32[](1);
        orderIds[0] = orderId;
        bytes[] memory ordersFillerData = new bytes[](1);
        ordersFillerData[0] = fillerData;

        uint256[] memory beforeSettle = _balances(inputToken);

        vm.expectEmit(false, false, false, true, address(destinationRouter));
        emit Settle(orderIds, ordersFillerData);
        destinationRouter.settle(orderIds);
        vm.stopPrank();

        uint256[] memory afterSettle = _balances(inputToken);
        assertEq(afterSettle[balanceId[vegeta]], beforeSettle[balanceId[vegeta]] + amount, "solver paid on origin");
        assertEq(
            afterSettle[balanceId[address(originRouter)]],
            beforeSettle[balanceId[address(originRouter)]] - amount,
            "origin lock released"
        );
        assertEq(originRouter.orderStatus(orderId), originRouter.SETTLED(), "order settled on origin");
    }

    /// @dev The claim takes custody of the winner's collateral, so it needs a live operator grant.
    ///      A winner without one must forfeit the auction rather than leave the order unclaimable.
    function test_claimOrder_revokedOperator_restartsAuction() public {
        (bytes32 orderId, OnchainCrossChainOrder memory order) = _openOrder();

        _doFullAuction(vegeta, orderId, amount, order.orderData);

        vm.prank(vegeta);
        destCompact.setOperator(address(destEscrow), false);

        destinationRouter.claimOrder(orderId, order.orderData);

        assertEq(destinationRouter.destinationOrderStatus(orderId), destinationRouter.UNKNOWN(), "order not claimed");
        assertEq(auction.getQuoteCount(orderId), 0, "auction restarted with quotes cleared");

        // The order is still claimable by a solver whose collateral can be taken into custody.
        _doFullAuction(kakaroto, orderId, amount, order.orderData);
        destinationRouter.claimOrder(orderId, order.orderData);
        assertEq(destinationRouter.destinationOrderStatus(orderId), destinationRouter.CLAIMED(), "claimed by other");
    }

    function test_open_refund() public {
        (bytes32 orderId, OnchainCrossChainOrder memory order) = _openOrder();

        vm.warp(order.fillDeadline + 1);

        bytes32[] memory orderIds = new bytes32[](1);
        orderIds[0] = orderId;
        OnchainCrossChainOrder[] memory orders = new OnchainCrossChainOrder[](1);
        orders[0] = order;

        uint256[] memory beforeRefund = _balances(inputToken);

        vm.expectEmit(false, false, false, true, address(destinationRouter));
        emit Refund(orderIds);
        destinationRouter.refund(orders);

        uint256[] memory afterRefund = _balances(inputToken);
        assertEq(originRouter.orderStatus(orderId), originRouter.REFUNDED(), "order refunded on origin");
        assertEq(
            afterRefund[balanceId[address(originRouter)]],
            beforeRefund[balanceId[address(originRouter)]] - amount,
            "origin lock released"
        );
        assertEq(afterRefund[balanceId[kakaroto]], beforeRefund[balanceId[kakaroto]] + amount, "user refunded");
    }

    /// @dev An oversized inbound batch must be rejected up front so it cannot make delivery
    ///      un-executable (gas) rather than being processed.
    function test_receiveMessage_RevertWhen_BatchTooLarge() public {
        uint256 n = destinationRouter.MAX_BATCH() + 1;
        bytes32[] memory orderIds = new bytes32[](n);
        bytes[] memory fillerData = new bytes[](n);
        bytes memory payload = RouterMessage.encodeSettle(orderIds, fillerData);
        bytes memory sender = _interop(origin, address(originRouter));

        vm.prank(address(destBridge));
        vm.expectRevert(abi.encodeWithSelector(Router.BatchTooLarge.selector, n));
        destinationRouter.receiveMessage(bytes32(0), sender, payload);
    }

    /// @dev A same-chain settle forwards no bridge fee, so attached native value would be trapped;
    ///      the dispatch must reject it instead.
    function test_settle_RevertWhen_SameChainCarriesValue() public {
        // originDomain == destination => the same-chain dispatch branch.
        OrderData memory orderData = _prepareOrderData();
        orderData.originDomain = destination;
        orderData.destinationDomain = destination;
        bytes memory originData = OrderEncoder.encode(orderData);
        bytes32 orderId = OrderEncoder.id(orderData);

        _doFullAuction(vegeta, orderId, amount, originData);
        destinationRouter.claimOrder(orderId, originData);

        vm.startPrank(vegeta);
        outputToken.approve(address(destinationRouter), amount);
        destinationRouter.fill(orderId, originData, abi.encode(TypeCasts.addressToBytes32(vegeta)));

        bytes32[] memory orderIds = new bytes32[](1);
        orderIds[0] = orderId;
        vm.expectRevert(BaseRouter.UnexpectedNativeValue.selector);
        destinationRouter.settle{value: 1}(orderIds);
        vm.stopPrank();
    }

    function test_RevertWhen_ReceiveFromNonBridge() public {
        bytes memory sender = _interop(origin, address(originRouter));
        vm.prank(makeAddr("intruder"));
        vm.expectRevert(abi.encodeWithSelector(Router.UnauthorizedBridge.selector, makeAddr("intruder")));
        destinationRouter.receiveMessage(bytes32(0), sender, "");
    }

    function test_Quote_DelegatesToBridge() public {
        destBridge.setFeeQuote(123);
        assertEq(destinationRouter.quote(origin, "payload"), 123, "quote delegated to bridge");
    }
}
