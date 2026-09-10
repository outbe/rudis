// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {TypeCasts} from "../src/libs/TypeCasts.sol";

import {BaseTest} from "./BaseTest.sol";
import {OriginSettler} from "../src/router/origin/OriginSettler.sol";
import {IOriginSettler} from "../src/interfaces/IOriginSettler.sol";
import {OrderData, OrderEncoder} from "../src/libs/OrderEncoder.sol";
import {OnchainCrossChainOrder, ResolvedCrossChainOrder} from "../src/interfaces/OrderTypes.sol";
import {ITheCompact} from "the-compact/src/interfaces/ITheCompact.sol";
import {IAuction} from "../src/interfaces/IAuction.sol";
import {ISolverEscrow} from "../src/interfaces/ISolverEscrow.sol";
import {MockTheCompact} from "./mocks/MockTheCompact.sol";

event Settled(bytes32 orderId, address receiver);
event Refunded(bytes32 orderId, address receiver);

contract OriginSettlerForTest is OriginSettler {
    uint32 private immutable _FIXED_LOCAL_DOMAIN;
    ITheCompact private _compactAddr;

    constructor(uint32 fixedDomain, address compactMock) {
        _FIXED_LOCAL_DOMAIN = fixedDomain;
        _compactAddr = ITheCompact(compactMock);
    }

    function _localDomain() internal view override returns (uint32) {
        return _FIXED_LOCAL_DOMAIN;
    }

    function _compact() internal view override returns (ITheCompact) {
        return _compactAddr;
    }

    // Zero lockTag - lower 160 bits = token address, claimant lower 160 bits = recipient
    function _lockTag() internal pure override returns (bytes12) {
        return bytes12(0);
    }

    function _auction() internal pure override returns (IAuction) {
        return IAuction(address(0));
    }

    function _solverEscrow() internal pure override returns (ISolverEscrow) {
        return ISolverEscrow(address(0));
    }

    // Expose internal functions for testing
    function handleSettleOrder(uint32 _messageOrigin, bytes32 _messageSender, bytes32 _orderId, bytes32 _receiver)
        public
    {
        _handleSettleOrder(_messageOrigin, _messageSender, _orderId, _receiver);
    }

    function handleRefundOrder(uint32 _messageOrigin, bytes32 _messageSender, bytes32 _orderId) public {
        _handleRefundOrder(_messageOrigin, _messageSender, _orderId);
    }

    function resolveOrder(OnchainCrossChainOrder memory _order)
        public
        view
        returns (ResolvedCrossChainOrder memory, bytes32 orderId, uint256 nonce)
    {
        return _resolveOrder(_order);
    }

    function resolvedOrder(bytes32 _orderType, address _sender, uint32 _fillDeadline, bytes memory _orderData)
        public
        view
        returns (ResolvedCrossChainOrder memory rOrder)
    {
        (rOrder,,) = _resolvedOrder(_orderType, _sender, _fillDeadline, _orderData);
    }

    function setOrderOpened(bytes32 _orderId, OrderData memory orderData) public {
        openOrders[_orderId] = abi.encode(OrderEncoder.orderDataType(), OrderEncoder.encode(orderData));
        orderStatus[_orderId] = OPENED;
    }
}

contract OriginSettlerTest is BaseTest {
    using TypeCasts for address;

    MockTheCompact internal mockCompact;
    OriginSettlerForTest internal originSettler;

    uint32 internal wrongMsgOrigin = 678;
    bytes32 internal wrongMsgSender = makeAddr("wrongMsgSender").addressToBytes32();

    function setUp() public override {
        super.setUp();

        mockCompact = new MockTheCompact();
        originSettler = new OriginSettlerForTest(origin, address(mockCompact));

        // Index 4 tracks the compact (token source for settle/refund).
        // Both mockCompact and originSettler map to the same index so existing
        // assertions using balanceId[address(originSettler)] still resolve correctly.
        balanceId[address(mockCompact)] = 4;
        balanceId[address(originSettler)] = 4;
        users.push(address(mockCompact));
    }

    receive() external payable {}

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
            destinationSettler: counterpart.addressToBytes32(),
            fillDeadline: uint32(block.timestamp + 100),
            data: new bytes(0)
        });
    }

    // ========== handleSettleOrder ==========

    function test_handleSettleOrder_works() public {
        OrderData memory orderData = _prepareOrderData();
        bytes32 orderId = bytes32("order1");

        originSettler.setOrderOpened(orderId, orderData);

        deal(address(inputToken), address(mockCompact), 1_000_000, true);
        mockCompact.__setBalance(address(originSettler), uint160(address(inputToken)), amount);

        uint256[] memory balancesBefore = _balances(inputToken);

        vm.expectEmit(false, false, false, true);
        emit Settled(orderId, karpincho);

        originSettler.handleSettleOrder(
            destination, counterpart.addressToBytes32(), orderId, TypeCasts.addressToBytes32(karpincho)
        );

        uint256[] memory balancesAfter = _balances(inputToken);

        assertEq(originSettler.orderStatus(orderId), originSettler.SETTLED());
        assertEq(
            balancesAfter[balanceId[address(originSettler)]], balancesBefore[balanceId[address(originSettler)]] - amount
        );
        assertEq(balancesAfter[balanceId[karpincho]], balancesBefore[balanceId[karpincho]] + amount);
    }

    function test_handleSettleOrder_native_works() public {
        OrderData memory orderData = _prepareOrderData();
        orderData.inputToken = TypeCasts.addressToBytes32(address(0));
        orderData.outputToken = TypeCasts.addressToBytes32(address(0));
        bytes32 orderId = bytes32("order1");

        originSettler.setOrderOpened(orderId, orderData);

        deal(address(mockCompact), 1_000_000);
        mockCompact.__setBalance(address(originSettler), 0, amount);

        uint256[] memory balancesBefore = _balances();

        vm.expectEmit(false, false, false, true);
        emit Settled(orderId, karpincho);

        originSettler.handleSettleOrder(
            destination, counterpart.addressToBytes32(), orderId, TypeCasts.addressToBytes32(karpincho)
        );

        uint256[] memory balancesAfter = _balances();

        assertEq(originSettler.orderStatus(orderId), originSettler.SETTLED());
        assertEq(
            balancesAfter[balanceId[address(originSettler)]], balancesBefore[balanceId[address(originSettler)]] - amount
        );
        assertEq(balancesAfter[balanceId[karpincho]], balancesBefore[balanceId[karpincho]] + amount);
    }

    function test_handleSettleOrder_not_OPENED() public {
        bytes32 orderId = bytes32("order1");
        // don't set the order as opened

        deal(address(inputToken), address(mockCompact), 1_000_000, true);

        uint256[] memory balancesBefore = _balances(inputToken);

        originSettler.handleSettleOrder(
            destination, counterpart.addressToBytes32(), orderId, TypeCasts.addressToBytes32(karpincho)
        );

        uint256[] memory balancesAfter = _balances(inputToken);

        assertEq(originSettler.orderStatus(orderId), originSettler.UNKNOWN());
        assertEq(balancesAfter[balanceId[address(originSettler)]], balancesBefore[balanceId[address(originSettler)]]);
        assertEq(balancesAfter[balanceId[karpincho]], balancesBefore[balanceId[karpincho]]);
    }

    function test_handleSettleOrder_wrong_msgOrigin() public {
        OrderData memory orderData = _prepareOrderData();
        bytes32 orderId = bytes32("order1");

        originSettler.setOrderOpened(orderId, orderData);

        deal(address(inputToken), address(mockCompact), 1_000_000, true);

        uint256[] memory balancesBefore = _balances(inputToken);

        originSettler.handleSettleOrder(
            wrongMsgOrigin, counterpart.addressToBytes32(), orderId, TypeCasts.addressToBytes32(karpincho)
        );

        uint256[] memory balancesAfter = _balances(inputToken);

        // Order stays OPENED because message origin doesn't match
        assertEq(originSettler.orderStatus(orderId), originSettler.OPENED());
        assertEq(balancesAfter[balanceId[address(originSettler)]], balancesBefore[balanceId[address(originSettler)]]);
        assertEq(balancesAfter[balanceId[karpincho]], balancesBefore[balanceId[karpincho]]);
    }

    function test_handleSettleOrder_wrong_msgSender() public {
        OrderData memory orderData = _prepareOrderData();
        bytes32 orderId = bytes32("order1");

        originSettler.setOrderOpened(orderId, orderData);

        deal(address(inputToken), address(mockCompact), 1_000_000, true);

        uint256[] memory balancesBefore = _balances(inputToken);

        originSettler.handleSettleOrder(destination, wrongMsgSender, orderId, TypeCasts.addressToBytes32(karpincho));

        uint256[] memory balancesAfter = _balances(inputToken);

        // Order stays OPENED because message sender doesn't match
        assertEq(originSettler.orderStatus(orderId), originSettler.OPENED());
        assertEq(balancesAfter[balanceId[address(originSettler)]], balancesBefore[balanceId[address(originSettler)]]);
        assertEq(balancesAfter[balanceId[karpincho]], balancesBefore[balanceId[karpincho]]);
    }

    // ========== handleRefundOrder ==========

    function test_handleRefundOrder_works() public {
        OrderData memory orderData = _prepareOrderData();
        bytes32 orderId = bytes32("order1");

        originSettler.setOrderOpened(orderId, orderData);

        deal(address(inputToken), address(mockCompact), 1_000_000, true);
        mockCompact.__setBalance(address(originSettler), uint160(address(inputToken)), amount);

        uint256[] memory balancesBefore = _balances(inputToken);

        vm.expectEmit(false, false, false, true);
        emit Refunded(orderId, kakaroto);

        originSettler.handleRefundOrder(destination, counterpart.addressToBytes32(), orderId);

        uint256[] memory balancesAfter = _balances(inputToken);

        assertEq(originSettler.orderStatus(orderId), originSettler.REFUNDED());
        assertEq(
            balancesAfter[balanceId[address(originSettler)]], balancesBefore[balanceId[address(originSettler)]] - amount
        );
        assertEq(balancesAfter[balanceId[kakaroto]], balancesBefore[balanceId[kakaroto]] + amount);
    }

    function test_handleRefundOrder_native_works() public {
        OrderData memory orderData = _prepareOrderData();
        orderData.inputToken = TypeCasts.addressToBytes32(address(0));
        orderData.outputToken = TypeCasts.addressToBytes32(address(0));
        bytes32 orderId = bytes32("order1");

        originSettler.setOrderOpened(orderId, orderData);

        deal(address(mockCompact), 1_000_000);
        mockCompact.__setBalance(address(originSettler), 0, amount);

        uint256[] memory balancesBefore = _balances();

        vm.expectEmit(false, false, false, true);
        emit Refunded(orderId, kakaroto);

        originSettler.handleRefundOrder(destination, counterpart.addressToBytes32(), orderId);

        uint256[] memory balancesAfter = _balances();

        assertEq(originSettler.orderStatus(orderId), originSettler.REFUNDED());
        assertEq(
            balancesAfter[balanceId[address(originSettler)]], balancesBefore[balanceId[address(originSettler)]] - amount
        );
        assertEq(balancesAfter[balanceId[kakaroto]], balancesBefore[balanceId[kakaroto]] + amount);
    }

    function test_handleRefundOrder_not_OPENED() public {
        bytes32 orderId = bytes32("order1");

        // don't set the order as opened

        deal(address(inputToken), address(mockCompact), 1_000_000, true);

        uint256[] memory balancesBefore = _balances(inputToken);

        originSettler.handleRefundOrder(destination, counterpart.addressToBytes32(), orderId);

        uint256[] memory balancesAfter = _balances(inputToken);

        assertEq(originSettler.orderStatus(orderId), originSettler.UNKNOWN());
        assertEq(balancesAfter[balanceId[address(originSettler)]], balancesBefore[balanceId[address(originSettler)]]);
        assertEq(balancesAfter[balanceId[karpincho]], balancesBefore[balanceId[karpincho]]);
    }

    function test_handleRefundOrder_wrong_msgOrigin() public {
        OrderData memory orderData = _prepareOrderData();
        bytes32 orderId = bytes32("order1");

        originSettler.setOrderOpened(orderId, orderData);

        deal(address(inputToken), address(mockCompact), 1_000_000, true);

        uint256[] memory balancesBefore = _balances(inputToken);

        originSettler.handleRefundOrder(wrongMsgOrigin, counterpart.addressToBytes32(), orderId);

        uint256[] memory balancesAfter = _balances(inputToken);

        // Order stays OPENED
        assertEq(originSettler.orderStatus(orderId), originSettler.OPENED());
        assertEq(balancesAfter[balanceId[address(originSettler)]], balancesBefore[balanceId[address(originSettler)]]);
        assertEq(balancesAfter[balanceId[karpincho]], balancesBefore[balanceId[karpincho]]);
    }

    function test_handleRefundOrder_wrong_msgSender() public {
        OrderData memory orderData = _prepareOrderData();
        bytes32 orderId = bytes32("order1");

        originSettler.setOrderOpened(orderId, orderData);

        deal(address(inputToken), address(mockCompact), 1_000_000, true);

        uint256[] memory balancesBefore = _balances(inputToken);

        originSettler.handleRefundOrder(destination, wrongMsgSender, orderId);

        uint256[] memory balancesAfter = _balances(inputToken);

        // Order stays OPENED
        assertEq(originSettler.orderStatus(orderId), originSettler.OPENED());
        assertEq(balancesAfter[balanceId[address(originSettler)]], balancesBefore[balanceId[address(originSettler)]]);
        assertEq(balancesAfter[balanceId[karpincho]], balancesBefore[balanceId[karpincho]]);
    }

    // ========== resolveOrder ==========

    function test_resolveOrder_onChain_works() public {
        OrderData memory orderData = _prepareOrderData();
        OnchainCrossChainOrder memory order =
            _prepareOnchainOrder(OrderEncoder.encode(orderData), orderData.fillDeadline, OrderEncoder.orderDataType());

        vm.prank(kakaroto);
        (ResolvedCrossChainOrder memory rOrder,,) = originSettler.resolveOrder(order);

        _assertResolvedOrder(
            rOrder,
            OrderEncoder.encode(orderData),
            kakaroto,
            orderData.fillDeadline,
            counterpart.addressToBytes32(),
            counterpart.addressToBytes32(),
            origin,
            address(inputToken),
            address(outputToken)
        );
    }

    function test_resolveOrder_InvalidOrderType() public {
        bytes32 wrongOrderType = bytes32("wrongOrderType");
        OrderData memory orderData = _prepareOrderData();
        OnchainCrossChainOrder memory order =
            _prepareOnchainOrder(OrderEncoder.encode(orderData), orderData.fillDeadline, wrongOrderType);

        vm.expectRevert(abi.encodeWithSelector(IOriginSettler.InvalidOrderType.selector, wrongOrderType));
        originSettler.resolveOrder(order);
    }

    function test_resolveOrder_InvalidOriginDomain() public {
        OrderData memory orderData = _prepareOrderData();
        orderData.originDomain = 0;
        OnchainCrossChainOrder memory order =
            _prepareOnchainOrder(OrderEncoder.encode(orderData), orderData.fillDeadline, OrderEncoder.orderDataType());

        vm.expectRevert(abi.encodeWithSelector(IOriginSettler.InvalidOriginDomain.selector, orderData.originDomain));
        originSettler.resolveOrder(order);
    }
}
