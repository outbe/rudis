// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {CrossChainTest} from "../helpers/CrossChainTest.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";
import {TargetRouter} from "@contracts/target/TargetRouter.sol";
import {ITargetRouter} from "@contracts/target/interfaces/ITargetRouter.sol";
import {ERC7786MessengerBase} from "@contracts/shared/ERC7786MessengerBase.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {BridgeMsgCodec} from "@contracts/shared/libs/BridgeMsgCodec.sol";
import {InboundReason} from "@contracts/shared/libs/InboundReason.sol";
import {IssuanceBatchLib} from "../helpers/IssuanceBatch.sol";

/// A day's issuance reaches a chain as numbered chunks. Each winner is issued once per series whatever
/// the chunks say; a repeated chunk, a chunk disagreeing with the day's run and a series named under other
/// terms are acknowledged without effect; the last chunk completes the day.
contract TargetRouterIssuanceChunksTest is CrossChainTest {
    uint32 internal constant OUTBE_CHAIN_ID = 2;
    uint32 internal constant DAY = 20_250_101;
    bytes14 internal constant USD = "20250101-USD-U";
    bytes14 internal constant EUR = "20250101-EUR-E";

    TargetRouter internal router;
    IntexNFT1155 internal intex;
    address internal originSender = makeAddr("originSender");
    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");

    function setUp() public {
        _setUpBridge();
        intex = DeployProxy.intexNFT1155(address(this), address(this));
        router = DeployProxy.targetRouter(address(bridge), address(this), OUTBE_CHAIN_ID);

        router.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, originSender));
        router.wire(makeAddr("auction"), address(intex), makeAddr("escrow"));
        intex.grantRole(intex.RELAYER_ROLE(), address(router));
        intex.grantRole(intex.GEM_ROLE(), address(this));
    }

    // --- helpers ---

    function _series(bytes14 seriesId, address recipient, uint256 quantity)
        internal
        pure
        returns (BridgeMsgCodec.IssuanceInstructionsPayload memory payload)
    {
        payload.seriesId = seriesId;
        payload.worldwideDay = DAY;
        payload.issuedIntexCount = 100;
        payload.promisLoadMinor = 1_000;
        payload.entryPriceMinor = 100e6;
        payload.floorPriceMinor = 40e6;
        payload.issuanceCurrency = 840;
        payload.referenceCurrency = 840;
        payload.callWindow = 30;
        payload.callThreshold = 5;
        payload.callPriceMinor = 200e6;
        if (recipient != address(0)) {
            payload.recipients = new address[](1);
            payload.quantities = new uint256[](1);
            payload.recipients[0] = recipient;
            payload.quantities[0] = quantity;
        }
    }

    function _deliver(uint16 chunkIndex, uint16 totalChunks, BridgeMsgCodec.IssuanceInstructionsPayload[] memory series)
        internal
    {
        _deliver(
            OUTBE_CHAIN_ID,
            originSender,
            address(router),
            BridgeMsgCodec.encodeIssuanceInstructions(DAY, chunkIndex, totalChunks, series)
        );
    }

    function _balance(bytes14 seriesId, address holder) internal view returns (uint256) {
        return intex.balanceOf(holder, intex.issuedTokenId(seriesId));
    }

    // --- repeats ---

    function test_ARepeatedChunkIssuesNothingAndIsAcknowledged() public {
        _deliver(0, 1, IssuanceBatchLib.one(_series(USD, alice, 7)));
        assertEq(_balance(USD, alice), 7, "first delivery mints");

        vm.expectEmit(true, true, true, true, address(router));
        emit ITargetRouter.InboundMessageIgnored(
            OUTBE_CHAIN_ID,
            BridgeMsgCodec.MSG_ISSUANCE_INSTRUCTIONS,
            bytes32(uint256(DAY) << 16),
            InboundReason.DUPLICATE
        );
        _deliver(0, 1, IssuanceBatchLib.one(_series(USD, alice, 7)));
        assertEq(_balance(USD, alice), 7, "repeat mints nothing");
        (uint16 seen, uint16 total) = router.issuanceChunks(DAY);
        assertEq(seen, 1, "repeat is not counted");
        assertEq(total, 1, "total unchanged");
    }

    function test_AWinnerNamedTwiceAcrossChunksIsIssuedOnce() public {
        _deliver(0, 2, IssuanceBatchLib.one(_series(USD, alice, 7)));
        vm.recordLogs();
        _deliver(1, 2, IssuanceBatchLib.one(_series(USD, alice, 3)));
        assertEq(_balance(USD, alice), 7, "alice keeps her one allocation");
        assertEq(_countTopic(ITargetRouter.InboundMessageIgnored.selector), 1, "the repeated winner is reported");
        assertTrue(router.issued(USD, alice), "alice recorded as issued");
        assertFalse(router.issued(USD, bob), "bob never issued");
    }

    function test_ABurnDoesNotReopenAWinnersAllocation() public {
        _deliver(0, 2, IssuanceBatchLib.one(_series(USD, alice, 7)));
        // Parking frees supply-cap room; the per-winner record is what keeps a later chunk from re-minting
        // (a repeat of the same chunk index never gets this far - the chunk guard drops it first).
        intex.parkIntex(alice, USD, 7);
        assertEq(_balance(USD, alice), 0, "parked");

        _deliver(1, 2, IssuanceBatchLib.one(_series(USD, alice, 7)));
        assertEq(_balance(USD, alice), 0, "the freed room is not re-minted into");
        assertTrue(router.issued(USD, alice), "the winner stays recorded as issued");
    }

    // --- conflicts ---

    function test_AChunkDisagreeingOnTheTotalIsSkipped() public {
        _deliver(0, 2, IssuanceBatchLib.one(_series(USD, alice, 7)));

        vm.expectEmit(true, true, true, true, address(router));
        emit ITargetRouter.InboundMessageIgnored(
            OUTBE_CHAIN_ID,
            BridgeMsgCodec.MSG_ISSUANCE_INSTRUCTIONS,
            bytes32((uint256(DAY) << 16) | 1),
            InboundReason.CONFLICT
        );
        _deliver(1, 3, IssuanceBatchLib.one(_series(EUR, bob, 2)));
        assertFalse(intex.seriesExists(EUR), "nothing of the conflicting chunk applied");
        (uint16 seen,) = router.issuanceChunks(DAY);
        assertEq(seen, 1, "conflicting chunk not counted");
    }

    function test_ASeriesNamedUnderOtherTermsSkipsTheWholeChunk() public {
        _deliver(0, 2, IssuanceBatchLib.one(_series(USD, alice, 7)));

        BridgeMsgCodec.IssuanceInstructionsPayload[] memory chunk = new BridgeMsgCodec.IssuanceInstructionsPayload[](2);
        chunk[0] = _series(EUR, bob, 2);
        chunk[1] = _series(USD, bob, 3);
        chunk[1].entryPriceMinor = 101e6; // disagrees with the series this chain already holds

        vm.expectEmit(true, true, true, true, address(router));
        emit ITargetRouter.InboundMessageIgnored(
            OUTBE_CHAIN_ID,
            BridgeMsgCodec.MSG_ISSUANCE_INSTRUCTIONS,
            bytes32((uint256(DAY) << 16) | 1),
            InboundReason.CONFLICT
        );
        _deliver(1, 2, chunk);
        assertFalse(intex.seriesExists(EUR), "the healthy series of the chunk is not created either");
        assertEq(_balance(USD, bob), 0, "no mint from the conflicting chunk");
        assertFalse(router.issuanceChunkApplied(DAY, 1), "chunk stays unapplied so a corrected resend can land");
    }

    function test_ACorrectedResendOfASkippedChunkLands() public {
        _deliver(0, 2, IssuanceBatchLib.one(_series(USD, alice, 7)));
        BridgeMsgCodec.IssuanceInstructionsPayload memory bad = _series(USD, bob, 3);
        bad.entryPriceMinor = 101e6;
        _deliver(1, 2, IssuanceBatchLib.one(bad));
        assertEq(_balance(USD, bob), 0, "conflict skipped");

        _deliver(1, 2, IssuanceBatchLib.one(_series(USD, bob, 3)));
        assertEq(_balance(USD, bob), 3, "corrected chunk applied");
    }

    function test_ASeriesWithNoSupplyIsInvalidNotALoop() public {
        BridgeMsgCodec.IssuanceInstructionsPayload memory p = _series(USD, alice, 7);
        p.issuedIntexCount = 0;
        vm.expectEmit(true, true, true, true, address(router));
        emit ITargetRouter.InboundMessageIgnored(
            OUTBE_CHAIN_ID, BridgeMsgCodec.MSG_ISSUANCE_INSTRUCTIONS, bytes32(uint256(DAY) << 16), InboundReason.INVALID
        );
        _deliver(0, 1, IssuanceBatchLib.one(p));
        assertFalse(intex.seriesExists(USD), "nothing created");
        assertFalse(router.issuanceChunkApplied(DAY, 0), "a corrected resend can still land");
    }

    function test_AnUnissuableQuantityIsAckedAndTheAllocationStaysOpen() public {
        BridgeMsgCodec.IssuanceInstructionsPayload memory p = _series(USD, alice, uint256(type(uint16).max) + 1);
        vm.recordLogs();
        _deliver(0, 2, IssuanceBatchLib.one(p));
        assertEq(_balance(USD, alice), 0, "nothing minted");
        assertFalse(router.issued(USD, alice), "the allocation is not burned");
        assertEq(_countTopic(ITargetRouter.InboundMessageIgnored.selector), 1, "acknowledged as invalid");

        _deliver(1, 2, IssuanceBatchLib.one(_series(USD, alice, 7))); // the corrected allocation in the run's other chunk
        assertEq(_balance(USD, alice), 7, "the corrected allocation lands");
    }

    function test_ADuplicateSeriesWithOtherTermsInsideOneChunkIsAConflict() public {
        BridgeMsgCodec.IssuanceInstructionsPayload[] memory chunk = new BridgeMsgCodec.IssuanceInstructionsPayload[](2);
        chunk[0] = _series(USD, alice, 7);
        chunk[1] = _series(USD, bob, 3);
        chunk[1].entryPriceMinor = 101e6;

        vm.expectEmit(true, true, true, true, address(router));
        emit ITargetRouter.InboundMessageIgnored(
            OUTBE_CHAIN_ID,
            BridgeMsgCodec.MSG_ISSUANCE_INSTRUCTIONS,
            bytes32(uint256(DAY) << 16),
            InboundReason.CONFLICT
        );
        _deliver(0, 1, chunk);
        assertFalse(intex.seriesExists(USD), "nothing of the chunk applied");
    }

    function test_ASeriesSplitInsideOneChunkIssuesBothPieces() public {
        BridgeMsgCodec.IssuanceInstructionsPayload[] memory chunk = new BridgeMsgCodec.IssuanceInstructionsPayload[](2);
        chunk[0] = _series(USD, alice, 7);
        chunk[1] = _series(USD, bob, 3); // same terms, different winners - a legitimate split
        _deliver(0, 1, chunk);
        assertEq(_balance(USD, alice), 7, "first piece minted");
        assertEq(_balance(USD, bob), 3, "second piece minted");
    }

    function test_ARecipientNamedTwiceInOnePayloadIsIssuedOnce() public {
        BridgeMsgCodec.IssuanceInstructionsPayload memory p = _series(USD, address(0), 0);
        p.recipients = new address[](2);
        p.quantities = new uint256[](2);
        p.recipients[0] = alice;
        p.recipients[1] = alice;
        p.quantities[0] = 7;
        p.quantities[1] = 3;
        vm.recordLogs();
        _deliver(0, 1, IssuanceBatchLib.one(p));
        assertEq(_balance(USD, alice), 7, "only the first naming mints");
        assertEq(_countTopic(ITargetRouter.InboundMessageIgnored.selector), 1, "the repeat is reported");
    }

    // --- completeness ---

    function test_TheLastChunkCompletesTheDayWhateverTheOrder() public {
        vm.recordLogs();
        _deliver(2, 3, IssuanceBatchLib.one(_series(EUR, bob, 2)));
        _deliver(0, 3, IssuanceBatchLib.one(_series(USD, alice, 7)));
        assertEq(_countTopic(ITargetRouter.IssuanceCompleted.selector), 0, "not complete yet");

        vm.expectEmit(true, true, true, true, address(router));
        emit ITargetRouter.IssuanceCompleted(DAY, 3);
        _deliver(1, 3, IssuanceBatchLib.one(_series(USD, bob, 1)));
        (uint16 seen, uint16 total) = router.issuanceChunks(DAY);
        assertEq(seen, 3, "every chunk counted");
        assertEq(total, 3, "total as declared");
    }

    function test_ASeriesOnlyChunkCompletesADayWithNoLocalWinners() public {
        vm.expectEmit(true, true, true, true, address(router));
        emit ITargetRouter.IssuanceCompleted(DAY, 1);
        _deliver(0, 1, IssuanceBatchLib.one(_series(USD, address(0), 0)));
        assertTrue(intex.seriesExists(USD), "series created");
    }
}
