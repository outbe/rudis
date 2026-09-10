// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {CrossChainTest} from "../helpers/CrossChainTest.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";
import {TargetRouter} from "@contracts/target/TargetRouter.sol";
import {ITargetRouter} from "@contracts/target/interfaces/ITargetRouter.sol";
import {IEscrowAdapter} from "@contracts/target/interfaces/IEscrowAdapter.sol";
import {BridgeMsgCodec} from "@contracts/shared/libs/BridgeMsgCodec.sol";
import {IntexGas} from "@contracts/shared/libs/IntexGas.sol";
import {MockWCOEN} from "@test-mocks/MockWCOEN.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @dev Minimal EscrowAdapter stand-in: `finalizeAuction` returns a configured totalPaid; exposes `paymentToken`.
contract MockEscrowAdapter {
    IERC20 public paymentToken;
    uint128 public totalPaidToReturn;

    constructor(IERC20 token) {
        paymentToken = token;
    }

    function setTotalPaid(uint128 v) external {
        totalPaidToReturn = v;
    }

    function finalizeAuction(uint32, bytes32, IEscrowAdapter.FinalizationInstruction[] calldata, bool)
        external
        view
        returns (uint128)
    {
        return totalPaidToReturn;
    }

    function getAuctionStatus(uint32) external pure returns (bool, bool, uint128) {
        return (false, false, 0);
    }
}

/// @dev Records the composed-transfer send; can be toggled to revert to exercise the park path.
contract MockTokenBridge {
    bool public shouldRevert;
    uint256 public fee = 0.001 ether;

    uint256 public calls;
    uint32 public lastDomain;
    address public lastTo;
    uint256 public lastAmount;
    bytes public lastExtraData;
    uint256 public lastGas;
    uint256 public valueReceived;

    function setShouldRevert(bool v) external {
        shouldRevert = v;
    }

    function quoteSend(uint32, address, uint256, bytes calldata, uint256) external view returns (uint256) {
        return fee;
    }

    function sendAndCall(uint32 domain, address to, uint256 amount, bytes calldata extraData, uint256 gasLimit)
        external
        payable
        returns (bytes32)
    {
        require(!shouldRevert, "bridge down");
        calls++;
        lastDomain = domain;
        lastTo = to;
        lastAmount = amount;
        lastExtraData = extraData;
        lastGas = gasLimit;
        valueReceived = msg.value;
        return bytes32(uint256(1));
    }
}

contract TargetRouterProceedsTest is CrossChainTest {
    uint32 internal constant BNB_CHAIN_ID = 1;
    uint32 internal constant OUTBE_CHAIN_ID = 2;
    uint32 internal constant SERIES_ID = 20_260_713;
    uint128 internal constant AMOUNT = 100e6;

    TargetRouter internal target;
    MockEscrowAdapter internal escrow;
    MockTokenBridge internal tokenBridge;
    MockWCOEN internal wcoen;

    address internal originSender = makeAddr("originSender"); // inbound message source on Outbe
    address internal originRouter = makeAddr("originRouter"); // proceeds recipient on Outbe
    address internal bidder = makeAddr("bidder");

    function setUp() public {
        _setUpBridge();
        target = DeployProxy.targetRouter(address(bridge), address(this), OUTBE_CHAIN_ID);
        vm.deal(address(target), 10 ether); // relay float for bridge fees

        wcoen = new MockWCOEN();
        escrow = new MockEscrowAdapter(IERC20(address(wcoen)));
        tokenBridge = new MockTokenBridge();

        target.wire(makeAddr("auction"), makeAddr("intex"), address(escrow));
        target.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, originSender));
        target.setProceedsRoute(address(tokenBridge), originRouter);
    }

    function _deliverRefund(uint32 worldwideDay) internal {
        address[] memory bidders = new address[](1);
        uint128[] memory refunded = new uint128[](1);
        uint128[] memory paid = new uint128[](1);
        bidders[0] = bidder;
        refunded[0] = 0;
        paid[0] = AMOUNT;
        bytes memory packet = BridgeMsgCodec.encodeRefundInstructions(worldwideDay, 0, 1, bidders, refunded, paid);
        _deliver(OUTBE_CHAIN_ID, originSender, address(target), packet);
    }

    function test_SetProceedsRoute_Getters() public view {
        assertEq(address(target.tokenBridge()), address(tokenBridge));
        assertEq(target.originRouter(), originRouter);
    }

    function test_RevertWhen_SetProceedsRouteZero() public {
        vm.expectRevert();
        target.setProceedsRoute(address(0), originRouter);
        vm.expectRevert();
        target.setProceedsRoute(address(tokenBridge), address(0));
    }

    function test_RefundInstructions_RoutesProceeds() public {
        escrow.setTotalPaid(AMOUNT);

        _deliverRefund(SERIES_ID);

        assertEq(tokenBridge.calls(), 1);
        assertEq(tokenBridge.lastDomain(), OUTBE_CHAIN_ID);
        assertEq(tokenBridge.lastTo(), originRouter);
        assertEq(tokenBridge.lastAmount(), AMOUNT);
        assertEq(tokenBridge.lastExtraData(), abi.encode(SERIES_ID));
        assertEq(tokenBridge.lastGas(), IntexGas.PROCEEDS_COMPOSE);
        assertEq(tokenBridge.valueReceived(), tokenBridge.fee());
        // Router approved the bridge to pull the proceeds.
        assertEq(wcoen.allowance(address(target), address(tokenBridge)), AMOUNT);
    }

    function test_RefundInstructions_ZeroPaidSkipsRouting() public {
        escrow.setTotalPaid(0);
        _deliverRefund(SERIES_ID);
        assertEq(tokenBridge.calls(), 0);
    }

    function test_RefundInstructions_ParksOnBridgeFailure() public {
        escrow.setTotalPaid(AMOUNT);
        tokenBridge.setShouldRevert(true);

        _deliverRefund(SERIES_ID);

        // Finalization still settled; the send was parked instead of rolling back.
        assertEq(tokenBridge.calls(), 0);
        (uint32 s, uint128 a, bool exists, bool done) = target.pendingProceedsRoutes(0);
        assertEq(s, SERIES_ID);
        assertEq(a, AMOUNT);
        assertTrue(exists);
        assertFalse(done);
    }

    function test_FlushPendingProceedsRoute_Retries() public {
        escrow.setTotalPaid(AMOUNT);
        tokenBridge.setShouldRevert(true);
        _deliverRefund(SERIES_ID);

        tokenBridge.setShouldRevert(false);
        vm.expectEmit(true, true, false, true, address(target));
        emit ITargetRouter.ProceedsRouteFlushed(0, SERIES_ID);
        target.flushPendingProceedsRoute(0);

        assertEq(tokenBridge.calls(), 1);
        assertEq(tokenBridge.lastAmount(), AMOUNT);
        (,,, bool done) = target.pendingProceedsRoutes(0);
        assertTrue(done);
    }

    function test_RevertWhen_FlushAlreadyDone() public {
        escrow.setTotalPaid(AMOUNT);
        tokenBridge.setShouldRevert(true);
        _deliverRefund(SERIES_ID);
        tokenBridge.setShouldRevert(false);
        target.flushPendingProceedsRoute(0);

        vm.expectRevert(abi.encodeWithSelector(ITargetRouter.AlreadyFlushed.selector, uint256(0)));
        target.flushPendingProceedsRoute(0);
    }

    function test_RevertWhen_FlushUnknownIdx() public {
        vm.expectRevert(abi.encodeWithSelector(ITargetRouter.NoSuchPendingProceedsRoute.selector, uint256(99)));
        target.flushPendingProceedsRoute(99);
    }
}
