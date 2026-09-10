// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import {Test, Vm} from "forge-std/Test.sol";

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {MockERC20} from "./mocks/MockERC20.sol";
import {TypeCasts} from "../src/libs/TypeCasts.sol";

import {OnchainCrossChainOrder, ResolvedCrossChainOrder} from "../src/interfaces/OrderTypes.sol";

event Open(bytes32 indexed orderId, ResolvedCrossChainOrder resolvedOrder);

contract BaseTest is Test {
    ERC20 internal inputToken;
    ERC20 internal outputToken;

    address internal kakaroto;
    uint256 internal kakarotoPK;
    address internal karpincho;
    uint256 internal karpinchoPK;
    address internal vegeta;
    uint256 internal vegetaPK;
    address internal counterpart = makeAddr("counterpart");

    uint32 internal origin = 1;
    uint32 internal destination = 2;
    uint256 internal amount = 100;

    mapping(address => uint256) internal balanceId;
    address[] internal users;

    function setUp() public virtual {
        (kakaroto, kakarotoPK) = makeAddrAndKey("kakaroto");
        (karpincho, karpinchoPK) = makeAddrAndKey("karpincho");
        (vegeta, vegetaPK) = makeAddrAndKey("vegeta");

        inputToken = new MockERC20("Input Token", "IN");
        outputToken = new MockERC20("Output Token", "OUT");

        deal(address(inputToken), kakaroto, 1_000_000, true);
        deal(address(inputToken), karpincho, 1_000_000, true);
        deal(address(inputToken), vegeta, 1_000_000, true);
        deal(address(outputToken), kakaroto, 1_000_000, true);
        deal(address(outputToken), karpincho, 1_000_000, true);
        deal(address(outputToken), vegeta, 1_000_000, true);

        deal(kakaroto, 1_000_000);
        deal(karpincho, 1_000_000);
        deal(vegeta, 1_000_000);

        balanceId[kakaroto] = 0;
        balanceId[karpincho] = 1;
        balanceId[vegeta] = 2;
        balanceId[counterpart] = 3;

        users.push(kakaroto);
        users.push(karpincho);
        users.push(vegeta);
        users.push(counterpart);
    }

    function _prepareOnchainOrder(bytes memory orderData, uint32 fillDeadline, bytes32 orderDataType)
        internal
        pure
        returns (OnchainCrossChainOrder memory)
    {
        return OnchainCrossChainOrder({fillDeadline: fillDeadline, orderDataType: orderDataType, orderData: orderData});
    }

    function _getOrderIDFromLogs() internal returns (bytes32, ResolvedCrossChainOrder memory) {
        Vm.Log[] memory _logs = vm.getRecordedLogs();

        ResolvedCrossChainOrder memory resolvedOrder;
        bytes32 orderID;

        for (uint256 i = 0; i < _logs.length; i++) {
            Vm.Log memory _log = _logs[i];

            if (_log.topics[0] != Open.selector) {
                continue;
            }
            orderID = _log.topics[1];

            (resolvedOrder) = abi.decode(_log.data, (ResolvedCrossChainOrder));
        }
        return (orderID, resolvedOrder);
    }

    function _balances(ERC20 _token) internal view returns (uint256[] memory) {
        uint256[] memory balances = new uint256[](users.length);
        for (uint256 i = 0; i < users.length; i++) {
            balances[i] = _token.balanceOf(users[i]);
        }

        return balances;
    }

    function _balances() internal view returns (uint256[] memory) {
        uint256[] memory balances = new uint256[](users.length);
        for (uint256 i = 0; i < users.length; i++) {
            balances[i] = users[i].balance;
        }

        return balances;
    }

    function _assertResolvedOrder(
        ResolvedCrossChainOrder memory resolvedOrder,
        bytes memory orderData,
        address _user,
        uint32 _fillDeadline,
        bytes32 _recipient,
        bytes32 _destinationSettler,
        uint64 _originChainId,
        address _inputToken,
        address _outputToken
    ) internal view {
        assertEq(resolvedOrder.maxSpent.length, 1);
        assertEq(resolvedOrder.maxSpent[0].token, TypeCasts.addressToBytes32(address(_outputToken)));
        assertEq(resolvedOrder.maxSpent[0].amount, amount);
        assertEq(resolvedOrder.maxSpent[0].recipient, _recipient);
        assertEq(resolvedOrder.maxSpent[0].chainId, destination);

        assertEq(resolvedOrder.minReceived.length, 1);
        assertEq(resolvedOrder.minReceived[0].token, TypeCasts.addressToBytes32(address(_inputToken)));
        assertEq(resolvedOrder.minReceived[0].amount, amount);
        assertEq(resolvedOrder.minReceived[0].recipient, bytes32(0));
        assertEq(resolvedOrder.minReceived[0].chainId, origin);

        assertEq(resolvedOrder.fillInstructions.length, 1);
        assertEq(resolvedOrder.fillInstructions[0].destinationChainId, destination);
        assertEq(resolvedOrder.fillInstructions[0].destinationSettler, _destinationSettler);

        assertEq(resolvedOrder.fillInstructions[0].originData, orderData);

        assertEq(resolvedOrder.user, _user);
        assertEq(resolvedOrder.originChainId, _originChainId);
        assertEq(resolvedOrder.fillDeadline, _fillDeadline);
    }
}
