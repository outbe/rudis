// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {CrossChainTest} from "../helpers/CrossChainTest.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";
import {TargetRouter} from "@contracts/target/TargetRouter.sol";
import {IEscrowAdapter} from "@contracts/target/interfaces/IEscrowAdapter.sol";
import {BridgeMsgCodec} from "@contracts/shared/libs/BridgeMsgCodec.sol";
import {EscrowAdapter} from "@contracts/target/EscrowAdapter.sol";
import {MockTheCompact} from "@test-mocks/MockTheCompact.sol";
import {MockWCOEN} from "@test-mocks/MockWCOEN.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @dev Escrow stand-in that reports back exactly what the chunk it was handed paid.
contract SummingEscrowAdapter {
    IERC20 public paymentToken;

    constructor(IERC20 token) {
        paymentToken = token;
    }

    function finalizeAuction(uint32, bytes32, IEscrowAdapter.FinalizationInstruction[] calldata instructions, bool)
        external
        pure
        returns (uint128 totalPaid)
    {
        for (uint256 i = 0; i < instructions.length; i++) {
            totalPaid += instructions[i].paidAmount;
        }
    }

    function getAuctionStatus(uint32) external pure returns (bool, bool, uint128) {
        return (false, false, 0);
    }
}

/// @dev Counts proceeds transfers and remembers the last amount.
contract CountingTokenBridge {
    uint256 public calls;
    uint256 public lastAmount;

    function quoteSend(uint32, address, uint256, bytes calldata, uint256) external pure returns (uint256) {
        return 0.001 ether;
    }

    function sendAndCall(uint32, address, uint256 amount, bytes calldata, uint256) external payable returns (bytes32) {
        calls++;
        lastAmount = amount;
        return bytes32(uint256(1));
    }
}

/// A chain's refunds arrive as a run of chunks, but the day's proceeds leave as one
/// transfer: the origin counts a chain paid on the first delivery.
contract TargetRouterRefundChunksTest is CrossChainTest {
    uint32 internal constant OUTBE_CHAIN_ID = 2;
    uint32 internal constant DAY = 20_260_713;

    TargetRouter internal target;
    CountingTokenBridge internal tokenBridge;

    address internal originSender = makeAddr("originSender");
    address internal originRouter = makeAddr("originRouter");

    function setUp() public {
        _setUpBridge();
        target = DeployProxy.targetRouter(address(bridge), address(this), OUTBE_CHAIN_ID);
        vm.deal(address(target), 10 ether);

        MockWCOEN wcoen = new MockWCOEN();
        SummingEscrowAdapter escrow = new SummingEscrowAdapter(IERC20(address(wcoen)));
        tokenBridge = new CountingTokenBridge();

        target.wire(makeAddr("auction"), makeAddr("intex"), address(escrow));
        target.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, originSender));
        target.setProceedsRoute(address(tokenBridge), originRouter);
    }

    function _deliverChunk(uint16 chunkIndex, uint16 totalChunks, uint128 paidAmount) internal {
        address[] memory bidders = new address[](1);
        uint128[] memory refunded = new uint128[](1);
        uint128[] memory paid = new uint128[](1);
        bidders[0] = address(uint160(uint256(0xB1D) + chunkIndex));
        refunded[0] = 0;
        paid[0] = paidAmount;
        bytes memory packet =
            BridgeMsgCodec.encodeRefundInstructions(DAY, chunkIndex, totalChunks, bidders, refunded, paid);
        _deliver(OUTBE_CHAIN_ID, originSender, address(target), packet);
    }

    function test_ProceedsLeaveOnceTheLastChunkLands() public {
        _deliverChunk(0, 2, 40e6);
        assertEq(tokenBridge.calls(), 0, "an unfinished day must not route");

        _deliverChunk(1, 2, 60e6);
        assertEq(tokenBridge.calls(), 1, "one transfer for the day");
        assertEq(tokenBridge.lastAmount(), 100e6, "the whole day's proceeds");
    }

    function test_RedeliveredChunkNeitherRoutesNorRecounts() public {
        _deliverChunk(0, 2, 40e6);
        _deliverChunk(0, 2, 40e6); // the bridge may deliver the same chunk twice
        assertEq(tokenBridge.calls(), 0, "a repeat must not complete the day");

        _deliverChunk(1, 2, 60e6);
        assertEq(tokenBridge.calls(), 1);
        assertEq(tokenBridge.lastAmount(), 100e6, "the repeat must not be counted twice");
    }

    function test_ChunksMayArriveInAnyOrder() public {
        _deliverChunk(1, 2, 60e6);
        assertEq(tokenBridge.calls(), 0);

        _deliverChunk(0, 2, 40e6);
        assertEq(tokenBridge.calls(), 1);
        assertEq(tokenBridge.lastAmount(), 100e6);
    }

    function test_SingleChunkDayRoutesImmediately() public {
        _deliverChunk(0, 1, 25e6);
        assertEq(tokenBridge.calls(), 1);
        assertEq(tokenBridge.lastAmount(), 25e6);
    }

    /// Driven through the real adapter: the rule that matters - a finalized day refuses
    /// everything after - is exactly what the mock above cannot express.
    function test_TheRealEscrowSettlesEveryChunkOfADay() public {
        MockWCOEN token = new MockWCOEN();
        MockTheCompact compact = new MockTheCompact();
        EscrowAdapter escrow = DeployProxy.escrowAdapter(address(this), address(this));
        escrow.wire(address(this), address(compact), address(token));
        compact.setResetPeriodSeconds(0);
        escrow.grantRole(escrow.RELAYER_ROLE(), address(target));
        escrow.grantRole(escrow.AUCTION_ROLE(), address(this));
        escrow.setProceedsRecipient(address(target));
        target.wire(makeAddr("auction"), makeAddr("intex"), address(escrow));

        address[2] memory bidders = [makeAddr("early"), makeAddr("late")];
        for (uint256 i = 0; i < bidders.length; i++) {
            token.mint(bidders[i], 1_000_000e6);
            vm.prank(bidders[i]);
            token.approve(address(escrow), type(uint256).max);
            escrow.lockFunds(DAY, bidders[i], 100e6);
        }

        _deliverChunkFor(bidders[0], 0, 2, 100e6);
        _deliverChunkFor(bidders[1], 1, 2, 100e6);

        assertTrue(
            escrow.getBidLock(DAY, bidders[0]).status == IEscrowAdapter.LockStatus.Finalized, "first chunk settled"
        );
        assertTrue(
            escrow.getBidLock(DAY, bidders[1]).status == IEscrowAdapter.LockStatus.Finalized, "second chunk settled too"
        );
    }

    function _deliverChunkFor(address bidder, uint16 chunkIndex, uint16 totalChunks, uint128 paidAmount) internal {
        address[] memory bidders = new address[](1);
        uint128[] memory refunded = new uint128[](1);
        uint128[] memory paid = new uint128[](1);
        bidders[0] = bidder;
        refunded[0] = 0;
        paid[0] = paidAmount;
        _deliver(
            OUTBE_CHAIN_ID,
            originSender,
            address(target),
            BridgeMsgCodec.encodeRefundInstructions(DAY, chunkIndex, totalChunks, bidders, refunded, paid)
        );
    }
}
