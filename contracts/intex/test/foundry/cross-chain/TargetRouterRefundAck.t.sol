// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {CrossChainTest} from "../helpers/CrossChainTest.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";
import {TargetRouter} from "@contracts/target/TargetRouter.sol";
import {IEscrowAdapter} from "@contracts/target/interfaces/IEscrowAdapter.sol";
import {ERC7786MessengerBase} from "@contracts/shared/ERC7786MessengerBase.sol";
import {ITargetRouter} from "@contracts/target/interfaces/ITargetRouter.sol";
import {BridgeMsgCodec} from "@contracts/shared/libs/BridgeMsgCodec.sol";
import {InboundReason} from "@contracts/shared/libs/InboundReason.sol";
import {MockWCOEN} from "@test-mocks/MockWCOEN.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @dev Escrow stand-in that counts finalizations and can be told the day is closed.
contract ClosableEscrowAdapter {
    IERC20 public paymentToken;
    bool public closed;
    uint256 public finalizations;

    constructor(IERC20 token) {
        paymentToken = token;
    }

    function close() external {
        closed = true;
    }

    function finalizeAuction(uint32, bytes32, IEscrowAdapter.FinalizationInstruction[] calldata, bool)
        external
        returns (uint128)
    {
        finalizations++;
        return 0;
    }

    function getAuctionStatus(uint32) external view returns (bool, bool, uint128) {
        return (false, closed, 0);
    }
}

/// A refund chunk that was already applied, or that lands after the escrow closed the day, is
/// acknowledged without effect instead of bouncing back to the transport.
contract TargetRouterRefundAckTest is CrossChainTest {
    uint32 internal constant OUTBE_CHAIN_ID = 2;
    uint32 internal constant DAY = 20_260_713;

    TargetRouter internal target;
    ClosableEscrowAdapter internal escrow;
    address internal originSender = makeAddr("originSender");

    function setUp() public {
        _setUpBridge();
        target = DeployProxy.targetRouter(address(bridge), address(this), OUTBE_CHAIN_ID);
        escrow = new ClosableEscrowAdapter(IERC20(address(new MockWCOEN())));
        target.wire(makeAddr("auction"), makeAddr("intex"), address(escrow));
        target.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, originSender));
    }

    function _deliverChunk(uint16 chunkIndex, uint16 totalChunks) internal {
        address[] memory bidders = new address[](1);
        bidders[0] = makeAddr("bidder");
        bytes memory packet = BridgeMsgCodec.encodeRefundInstructions(
            DAY, chunkIndex, totalChunks, bidders, new uint128[](1), new uint128[](1)
        );
        _deliver(OUTBE_CHAIN_ID, originSender, address(target), packet);
    }

    function _expectIgnored(uint16 chunkIndex, uint8 reason) internal {
        vm.expectEmit(true, true, true, true, address(target));
        emit ITargetRouter.InboundMessageIgnored(
            OUTBE_CHAIN_ID, BridgeMsgCodec.MSG_REFUND_INSTRUCTIONS, bytes32((uint256(DAY) << 16) | chunkIndex), reason
        );
    }

    function test_ARepeatedChunkIsADuplicate() public {
        _deliverChunk(0, 2);
        _expectIgnored(0, InboundReason.DUPLICATE);
        _deliverChunk(0, 2);
        assertEq(escrow.finalizations(), 1, "settled once");
    }

    function test_AChunkClaimingAnotherTotalCannotCloseTheDayEarly() public {
        _deliverChunk(1, 2); // fixes the day's total at 2
        _expectIgnored(0, InboundReason.CONFLICT);
        _deliverChunk(0, 1);
        assertEq(escrow.finalizations(), 1, "the conflicting chunk never reaches the escrow");
        (uint16 seen, uint16 total) = target.refundChunks(DAY);
        assertEq(seen, 1, "not counted");
        assertEq(total, 2, "the first chunk's total stands");

        _deliverChunk(0, 2);
        (seen,) = target.refundChunks(DAY);
        assertEq(seen, 2, "day completed by the corrected chunk");
    }

    function test_AChunkAfterTheEscrowClosedTheDayIsObsolete() public {
        _deliverChunk(0, 2);
        escrow.close();
        _expectIgnored(1, InboundReason.OBSOLETE);
        _deliverChunk(1, 2);
        assertEq(escrow.finalizations(), 1, "the late chunk never reaches the escrow");
    }
}
