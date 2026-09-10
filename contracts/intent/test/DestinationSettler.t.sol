// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {TypeCasts} from "../src/libs/TypeCasts.sol";

import {BaseTest} from "./BaseTest.sol";
import {DestinationSettler} from "../src/router/destination/DestinationSettler.sol";
import {IDestinationSettler} from "../src/interfaces/IDestinationSettler.sol";
import {IAuction} from "../src/interfaces/IAuction.sol";
import {ISolverEscrow} from "../src/interfaces/ISolverEscrow.sol";
import {Auction} from "../src/Auction.sol";
import {OrderStatusStorage} from "../src/router/common/OrderStatusStorage.sol";
import {ITheCompact} from "the-compact/src/interfaces/ITheCompact.sol";
import {OrderData, OrderEncoder} from "../src/libs/OrderEncoder.sol";
import {OnchainCrossChainOrder} from "../src/interfaces/OrderTypes.sol";

event Filled(bytes32 orderId, bytes originData, bytes fillerData);
event Settle(bytes32[] orderIds, bytes[] ordersFillerData);
event Refund(bytes32[] orderIds);

contract DestinationSettlerForTest is DestinationSettler {
    uint32 private immutable _FIXED_LOCAL_DOMAIN;
    IAuction private _auctionContract;
    ISolverEscrow private _solverEscrowContract;

    uint32 public dispatchedOriginDomain;
    bytes32[] public dispatchedOrderIds;
    bytes[] public dispatchedOrdersFillerData;

    constructor(uint32 fixedDomain, address auction_) {
        _FIXED_LOCAL_DOMAIN = fixedDomain;
        _auctionContract = IAuction(auction_);
    }

    function _localDomain() internal view override returns (uint32) {
        return _FIXED_LOCAL_DOMAIN;
    }

    function _auction() internal view override returns (IAuction) {
        return _auctionContract;
    }

    function _solverEscrow() internal view override returns (ISolverEscrow) {
        return _solverEscrowContract;
    }

    function _compact() internal pure override returns (ITheCompact) {
        return ITheCompact(address(0));
    }

    function _lockTag() internal pure override returns (bytes12) {
        return bytes12(0);
    }

    function _dispatchSettle(uint32 _originDomain, bytes32[] memory _orderIds, bytes[] memory _ordersFillerData)
        internal
        override
    {
        dispatchedOriginDomain = _originDomain;
        dispatchedOrderIds = _orderIds;
        dispatchedOrdersFillerData = _ordersFillerData;
    }

    function _dispatchRefund(uint32 _originDomain, bytes32[] memory _orderIds) internal override {
        dispatchedOriginDomain = _originDomain;
        dispatchedOrderIds = _orderIds;
    }

    // Expose internal functions for testing
    function fillOrder(bytes32 _orderId, bytes calldata _originData, bytes calldata _fillerData) public payable {
        _fillOrder(_orderId, _originData, _fillerData);
    }

    function settleOrders(
        bytes32[] calldata _orderIds,
        bytes[] memory ordersOriginData,
        bytes[] memory ordersFillerData
    ) public {
        _settleOrders(_orderIds, ordersOriginData, ordersFillerData);
    }

    function refundOrders(OnchainCrossChainOrder[] calldata _orders, bytes32[] memory _orderIds) public {
        _refundOrders(_orders, _orderIds);
    }

    function getOrderId(OnchainCrossChainOrder calldata _order) public pure returns (bytes32) {
        return _getOrderId(_order);
    }
}

contract DestinationSettlerTest is BaseTest {
    using TypeCasts for address;

    DestinationSettlerForTest internal destinationSettler;
    Auction internal auction;

    bytes32 constant SALT = bytes32(uint256(42));

    function setUp() public override {
        super.setUp();

        auction = new Auction(address(this));
        destinationSettler = new DestinationSettlerForTest(destination, address(auction));
        auction.setRouter(address(destinationSettler));

        balanceId[address(destinationSettler)] = 4;
        users.push(address(destinationSettler));
    }

    receive() external payable {}

    // ========== Helpers ==========

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
            destinationSettler: address(destinationSettler).addressToBytes32(),
            fillDeadline: uint32(block.timestamp + 100),
            data: new bytes(0)
        });
    }

    function _commit(address solver, bytes32 orderId, uint256 outputAmount) internal {
        vm.prank(solver);
        auction.commit(orderId, keccak256(abi.encode(orderId, outputAmount, SALT)));
    }

    function _reveal(address solver, bytes32 orderId, uint256 outputAmount, bytes memory originData) internal {
        vm.prank(solver);
        auction.reveal(orderId, outputAmount, SALT, originData);
    }

    /// @dev Single-solver full auction: commit -> warp -> reveal -> warp -> ended
    function _doFullAuction(address solver, bytes32 orderId, uint256 outputAmount, bytes memory originData) internal {
        _commit(solver, orderId, outputAmount);
        vm.warp(block.timestamp + auction.commitPeriod());
        _reveal(solver, orderId, outputAmount, originData);
        vm.warp(block.timestamp + auction.revealPeriod());
    }

    /// @dev Two-solver full auction: both commit -> warp -> both reveal -> warp -> ended
    function _doFullAuctionTwo(
        address solver1,
        uint256 amount1,
        address solver2,
        uint256 amount2,
        bytes32 orderId,
        bytes memory originData
    ) internal {
        // Use different salts per solver via separate commit hashes
        vm.prank(solver1);
        auction.commit(orderId, keccak256(abi.encode(orderId, amount1, bytes32(uint256(1)))));
        vm.prank(solver2);
        auction.commit(orderId, keccak256(abi.encode(orderId, amount2, bytes32(uint256(2)))));

        vm.warp(block.timestamp + auction.commitPeriod());

        vm.prank(solver1);
        auction.reveal(orderId, amount1, bytes32(uint256(1)), originData);
        vm.prank(solver2);
        auction.reveal(orderId, amount2, bytes32(uint256(2)), originData);

        vm.warp(block.timestamp + auction.revealPeriod());
    }

    // ========== settleOrders ==========

    function test_settleOrders_works() public {
        OrderData memory orderData1 = _prepareOrderData();
        OrderData memory orderData2 = _prepareOrderData();
        orderData2.senderNonce = 2;

        bytes32[] memory _orderIds = new bytes32[](2);
        _orderIds[0] = bytes32("order1");
        _orderIds[1] = bytes32("order2");
        bytes[] memory ordersOriginData = new bytes[](2);
        ordersOriginData[0] = OrderEncoder.encode(orderData1);
        ordersOriginData[1] = OrderEncoder.encode(orderData2);
        bytes[] memory ordersFillerData = new bytes[](2);
        ordersFillerData[0] = abi.encode("some filler data1");
        ordersFillerData[1] = abi.encode("some filler data2");

        destinationSettler.settleOrders(_orderIds, ordersOriginData, ordersFillerData);

        assertEq(destinationSettler.dispatchedOriginDomain(), origin);
        assertEq(destinationSettler.dispatchedOrderIds(0), _orderIds[0]);
        assertEq(destinationSettler.dispatchedOrderIds(1), _orderIds[1]);
        assertEq(destinationSettler.dispatchedOrdersFillerData(0), abi.encode("some filler data1"));
        assertEq(destinationSettler.dispatchedOrdersFillerData(1), abi.encode("some filler data2"));
    }

    // ========== refundOrders ==========

    function test_refundOrders_onChain_works() public {
        OrderData memory orderData1 = _prepareOrderData();
        OrderData memory orderData2 = _prepareOrderData();
        orderData2.senderNonce = 2;

        OnchainCrossChainOrder memory order1 = _prepareOnchainOrder(
            OrderEncoder.encode(orderData1), orderData1.fillDeadline, OrderEncoder.orderDataType()
        );
        OnchainCrossChainOrder memory order2 = _prepareOnchainOrder(
            OrderEncoder.encode(orderData2), orderData2.fillDeadline, OrderEncoder.orderDataType()
        );

        bytes32[] memory _orderIds = new bytes32[](2);
        _orderIds[0] = bytes32("order1");
        _orderIds[1] = bytes32("order2");

        OnchainCrossChainOrder[] memory orders = new OnchainCrossChainOrder[](2);
        orders[0] = order1;
        orders[1] = order2;

        destinationSettler.refundOrders(orders, _orderIds);

        assertEq(destinationSettler.dispatchedOriginDomain(), origin);
        assertEq(destinationSettler.dispatchedOrderIds(0), _orderIds[0]);
        assertEq(destinationSettler.dispatchedOrderIds(1), _orderIds[1]);
    }

    // ========== mixed origin domain ==========

    /// @dev The whole batch dispatches to order [0]'s domain, so a batch mixing origins would
    ///      silently mis-route the divergent orders - it must revert. settle/refund share the same
    ///      _requireSameOriginDomain check, so the settle path covers both.
    function test_settleOrders_RevertWhen_MixedOriginDomain() public {
        uint32 otherDomain = origin + 1;

        OrderData memory orderData1 = _prepareOrderData();
        OrderData memory orderData2 = _prepareOrderData();
        orderData2.senderNonce = 2;
        orderData2.originDomain = otherDomain;

        bytes32[] memory _orderIds = new bytes32[](2);
        _orderIds[0] = bytes32("order1");
        _orderIds[1] = bytes32("order2");
        bytes[] memory ordersOriginData = new bytes[](2);
        ordersOriginData[0] = OrderEncoder.encode(orderData1);
        ordersOriginData[1] = OrderEncoder.encode(orderData2);
        bytes[] memory ordersFillerData = new bytes[](2);
        ordersFillerData[0] = abi.encode("f1");
        ordersFillerData[1] = abi.encode("f2");

        vm.expectRevert(abi.encodeWithSelector(DestinationSettler.MixedOriginDomain.selector, origin, otherDomain));
        destinationSettler.settleOrders(_orderIds, ordersOriginData, ordersFillerData);
    }

    // ========== fillOrder (with auction) ==========

    function test_fillOrder_ERC20_works() public {
        OrderData memory orderData = _prepareOrderData();
        bytes32 orderId = OrderEncoder.id(orderData);
        bytes memory originData = OrderEncoder.encode(orderData);

        _doFullAuction(vegeta, orderId, amount, originData);

        uint256[] memory balancesBefore = _balances(outputToken);

        vm.startPrank(vegeta);
        outputToken.approve(address(destinationSettler), amount);
        destinationSettler.fillOrder(orderId, originData, abi.encode(vegeta.addressToBytes32()));

        uint256[] memory balancesAfter = _balances(outputToken);
        assertEq(balancesAfter[balanceId[vegeta]], balancesBefore[balanceId[vegeta]] - amount);
        assertEq(balancesAfter[balanceId[karpincho]], balancesBefore[balanceId[karpincho]] + amount);
        vm.stopPrank();
    }

    function test_fillOrder_native_works() public {
        OrderData memory orderData = _prepareOrderData();
        orderData.inputToken = TypeCasts.addressToBytes32(address(0));
        orderData.outputToken = TypeCasts.addressToBytes32(address(0));
        bytes32 orderId = OrderEncoder.id(orderData);
        bytes memory originData = OrderEncoder.encode(orderData);

        _doFullAuction(vegeta, orderId, amount, originData);

        uint256[] memory balancesBefore = _balances();

        vm.startPrank(vegeta);
        destinationSettler.fillOrder{value: amount}(orderId, originData, abi.encode(vegeta.addressToBytes32()));

        uint256[] memory balancesAfter = _balances();
        assertEq(balancesAfter[balanceId[vegeta]], balancesBefore[balanceId[vegeta]] - amount);
        assertEq(balancesAfter[balanceId[karpincho]], balancesBefore[balanceId[karpincho]] + amount);
        vm.stopPrank();
    }

    function test_fillOrder_native_InvalidNativeAmount() public {
        OrderData memory orderData = _prepareOrderData();
        orderData.inputToken = TypeCasts.addressToBytes32(address(0));
        orderData.outputToken = TypeCasts.addressToBytes32(address(0));
        bytes32 orderId = OrderEncoder.id(orderData);
        bytes memory originData = OrderEncoder.encode(orderData);

        _doFullAuction(vegeta, orderId, amount, originData);

        vm.prank(vegeta);
        vm.expectRevert(OrderStatusStorage.InvalidNativeAmount.selector);
        destinationSettler.fillOrder{value: amount - 1}(orderId, originData, new bytes(0));
    }

    function test_fillOrder_InvalidOrderId() public {
        OrderData memory orderData = _prepareOrderData();
        bytes32 correctOrderId = OrderEncoder.id(orderData);
        bytes memory originData = OrderEncoder.encode(orderData);

        _doFullAuction(vegeta, correctOrderId, amount, originData);

        vm.prank(vegeta);
        vm.expectRevert(IDestinationSettler.InvalidOrderId.selector);
        destinationSettler.fillOrder(bytes32("wrongId"), originData, new bytes(0));
    }

    function test_fillOrder_OrderFillExpired() public {
        OrderData memory orderData = _prepareOrderData();
        bytes32 orderId = OrderEncoder.id(orderData);
        bytes memory originData = OrderEncoder.encode(orderData);

        _doFullAuction(vegeta, orderId, amount, originData);

        // Warp past fill deadline
        vm.warp(orderData.fillDeadline + 1);

        vm.prank(vegeta);
        vm.expectRevert(IDestinationSettler.OrderFillExpired.selector);
        destinationSettler.fillOrder(orderId, originData, new bytes(0));
    }

    function test_fillOrder_InvalidOrderDomain() public {
        OrderData memory orderData = _prepareOrderData();
        orderData.destinationDomain = origin; // Wrong domain
        bytes32 orderId = OrderEncoder.id(orderData);
        bytes memory originData = OrderEncoder.encode(orderData);

        _doFullAuction(vegeta, orderId, amount, originData);

        vm.prank(vegeta);
        vm.expectRevert(IDestinationSettler.InvalidOrderDomain.selector);
        destinationSettler.fillOrder(orderId, originData, new bytes(0));
    }

    function test_claimOrder_RevealNotEnded() public {
        OrderData memory orderData = _prepareOrderData();
        bytes32 orderId = OrderEncoder.id(orderData);
        bytes memory originData = OrderEncoder.encode(orderData);

        // Commit and reveal but don't warp past reveal phase
        _commit(vegeta, orderId, amount);
        vm.warp(block.timestamp + auction.commitPeriod());
        _reveal(vegeta, orderId, amount, originData);

        vm.expectRevert(IAuction.RevealNotEnded.selector);
        destinationSettler.claimOrder(orderId, originData);
    }

    function test_fillOrder_NotAWinner() public {
        OrderData memory orderData = _prepareOrderData();
        bytes32 orderId = OrderEncoder.id(orderData);
        bytes memory originData = OrderEncoder.encode(orderData);

        // vegeta bids higher (winner), kakaroto bids lower
        _doFullAuctionTwo(vegeta, amount + 10, kakaroto, amount, orderId, originData);

        vm.startPrank(kakaroto);
        outputToken.approve(address(destinationSettler), amount);
        vm.expectRevert(IDestinationSettler.NotAWinner.selector);
        destinationSettler.fillOrder(orderId, originData, new bytes(0));
        vm.stopPrank();
    }

    // ========== getOrderId ==========

    function test_getOrderId_onchain_works() public view {
        OrderData memory orderData = _prepareOrderData();

        OnchainCrossChainOrder memory order =
            _prepareOnchainOrder(OrderEncoder.encode(orderData), orderData.fillDeadline, OrderEncoder.orderDataType());

        assertEq(destinationSettler.getOrderId(order), OrderEncoder.id(orderData));
    }

    // ========== Auction: commit ==========

    function test_commit_works() public {
        OrderData memory orderData = _prepareOrderData();
        bytes32 orderId = OrderEncoder.id(orderData);

        _commit(vegeta, orderId, amount);

        assertTrue(auction.hasSolverCommitted(orderId, vegeta));
        assertGt(auction.auctionStartedAt(orderId), 0);
    }

    function test_commit_alreadyCommitted() public {
        OrderData memory orderData = _prepareOrderData();
        bytes32 orderId = OrderEncoder.id(orderData);

        _commit(vegeta, orderId, amount);

        vm.prank(vegeta);
        vm.expectRevert(IAuction.AlreadyCommitted.selector);
        auction.commit(orderId, keccak256(abi.encode(orderId, amount + 1, SALT)));
    }

    function test_commit_commitPhaseEnded() public {
        OrderData memory orderData = _prepareOrderData();
        bytes32 orderId = OrderEncoder.id(orderData);

        _commit(vegeta, orderId, amount);

        // Warp past commit phase
        vm.warp(block.timestamp + auction.commitPeriod());

        vm.prank(kakaroto);
        vm.expectRevert(IAuction.CommitPhaseEnded.selector);
        auction.commit(orderId, keccak256(abi.encode(orderId, amount, SALT)));
    }

    // ========== Auction: reveal ==========

    function test_reveal_works() public {
        OrderData memory orderData = _prepareOrderData();
        bytes32 orderId = OrderEncoder.id(orderData);
        bytes memory originData = OrderEncoder.encode(orderData);

        _commit(vegeta, orderId, amount);
        vm.warp(block.timestamp + auction.commitPeriod());
        _reveal(vegeta, orderId, amount, originData);

        assertEq(auction.getQuoteCount(orderId), 1);
        // After reveal, commit is cleared
        assertFalse(auction.hasSolverCommitted(orderId, vegeta));
    }

    function test_reveal_invalidHash() public {
        OrderData memory orderData = _prepareOrderData();
        bytes32 orderId = OrderEncoder.id(orderData);
        bytes memory originData = OrderEncoder.encode(orderData);

        _commit(vegeta, orderId, amount);
        vm.warp(block.timestamp + auction.commitPeriod());

        vm.prank(vegeta);
        vm.expectRevert(IAuction.InvalidReveal.selector);
        auction.reveal(orderId, amount + 1, SALT, originData); // wrong amount
    }

    function test_reveal_notCommitted() public {
        OrderData memory orderData = _prepareOrderData();
        bytes32 orderId = OrderEncoder.id(orderData);
        bytes memory originData = OrderEncoder.encode(orderData);

        // Start auction with kakaroto
        _commit(kakaroto, orderId, amount);
        vm.warp(block.timestamp + auction.commitPeriod());

        // Vegeta tries to reveal without committing
        vm.prank(vegeta);
        vm.expectRevert(IAuction.NotCommitted.selector);
        auction.reveal(orderId, amount, SALT, originData);
    }

    function test_reveal_revealPhaseNotActive() public {
        OrderData memory orderData = _prepareOrderData();
        bytes32 orderId = OrderEncoder.id(orderData);
        bytes memory originData = OrderEncoder.encode(orderData);

        _commit(vegeta, orderId, amount);

        // Try to reveal during commit phase (no warp)
        vm.prank(vegeta);
        vm.expectRevert(IAuction.RevealPhaseNotActive.selector);
        auction.reveal(orderId, amount, SALT, originData);
    }

    // ========== Auction: getWinner (Vickrey) ==========

    function test_getWinner_singleSolver() public {
        OrderData memory orderData = _prepareOrderData();
        bytes32 orderId = OrderEncoder.id(orderData);
        bytes memory originData = OrderEncoder.encode(orderData);

        _doFullAuction(vegeta, orderId, amount, originData);

        (address winner, uint256 winningAmount) = auction.getWinner(orderId);
        assertEq(winner, vegeta);
        assertEq(winningAmount, amount); // single solver pays own amount
    }

    function test_getWinner_vickreySecondPrice() public {
        OrderData memory orderData = _prepareOrderData();
        bytes32 orderId = OrderEncoder.id(orderData);
        bytes memory originData = OrderEncoder.encode(orderData);

        _doFullAuctionTwo(kakaroto, amount + 10, vegeta, amount, orderId, originData);

        (address winner, uint256 winningAmount) = auction.getWinner(orderId);
        assertEq(winner, kakaroto); // highest bidder wins
        assertEq(winningAmount, amount); // pays second-highest price
    }

    function test_getWinner_revealNotEnded() public {
        OrderData memory orderData = _prepareOrderData();
        bytes32 orderId = OrderEncoder.id(orderData);
        bytes memory originData = OrderEncoder.encode(orderData);

        _commit(vegeta, orderId, amount);
        vm.warp(block.timestamp + auction.commitPeriod());
        _reveal(vegeta, orderId, amount, originData);

        // Don't warp past reveal
        vm.expectRevert(IAuction.RevealNotEnded.selector);
        auction.getWinner(orderId);
    }

    function test_getWinner_noQuotes() public {
        OrderData memory orderData = _prepareOrderData();
        bytes32 orderId = OrderEncoder.id(orderData);

        vm.expectRevert(IAuction.NoQuotes.selector);
        auction.getWinner(orderId);
    }

    // ========== Auction: reset ==========

    function test_auction_afterReset_works() public {
        OrderData memory orderData = _prepareOrderData();
        bytes32 orderId = OrderEncoder.id(orderData);
        bytes memory originData = OrderEncoder.encode(orderData);

        _doFullAuction(vegeta, orderId, amount, originData);

        (address winner,) = auction.getWinner(orderId);
        assertEq(winner, vegeta);
        assertEq(auction.getQuoteCount(orderId), 1);
    }
}
