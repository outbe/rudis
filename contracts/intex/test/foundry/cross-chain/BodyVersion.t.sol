// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {MarkBatchLib} from "../helpers/MarkBatchLib.sol";
import {BidPackLib} from "../helpers/BidPackLib.sol";
import {ReferenceCurrencyPriceLib} from "../helpers/ReferenceCurrencyPriceLib.sol";
import {Test} from "forge-std/Test.sol";
import {BridgeMsgCodec} from "@contracts/shared/libs/BridgeMsgCodec.sol";
import {IIntexAuction} from "@contracts/target/interfaces/IIntexAuction.sol";
import {IssuanceBatchLib} from "../helpers/IssuanceBatch.sol";

/// @dev Exercises the body-version contract on both codecs:
///      - every encoder emits `bodyVersion == BODY_VERSION_V1` at offset 0;
///      - every decoder reverts `UnsupportedBodyVersion(got)` on any other leading byte;
///      - round-trip preserves the version byte alongside the payload.
contract BodyVersionTest is Test {
    /// @dev Fixed call stamp; these tests exercise the wire, not the clock.
    uint32 internal constant CALLED_AT = 1_777_000_000;

    // --- BridgeMsgCodec: encoder emits version byte ---

    function test_BridgeCodec_AllEncodersEmitVersionV1() public pure {
        bytes memory encoded;

        encoded = BridgeMsgCodec.encodeBidsBatch(1, 30101, 1, 0, 1, new address[](0), new uint256[](0));
        assertEq(uint8(encoded[0]), BridgeMsgCodec.BODY_VERSION_V1, "bidsBatch.version");
        assertEq(uint8(encoded[1]), BridgeMsgCodec.MSG_BIDS_BATCH, "bidsBatch.msgType");

        encoded = BridgeMsgCodec.encodeAuctionStageStart(
            1, 100, 200, 300, 1e6, 1e6, ReferenceCurrencyPriceLib.one(840, 2e6, 3e6, 4e6), 5, 6, 7, 1, 9e6, 1
        );
        assertEq(uint8(encoded[0]), BridgeMsgCodec.BODY_VERSION_V1, "stageStart.version");
        assertEq(uint8(encoded[1]), BridgeMsgCodec.MSG_AUCTION_STAGE_START, "stageStart.msgType");
        assertEq(
            encoded.length,
            BridgeMsgCodec.MIN_LEN_AUCTION_STAGE_START + BridgeMsgCodec.REFERENCE_PRICE_LEN,
            "stageStart.length"
        );

        encoded = BridgeMsgCodec.encodeAuctionStageClearing(1);
        assertEq(uint8(encoded[0]), BridgeMsgCodec.BODY_VERSION_V1, "stageClearing.version");
        assertEq(uint8(encoded[1]), BridgeMsgCodec.MSG_AUCTION_STAGE_CLEARING, "stageClearing.msgType");
        assertEq(encoded.length, 6, "stageClearing.length");

        encoded = BridgeMsgCodec.encodeAuctionResult(1, 7, 5e6, 3);
        assertEq(uint8(encoded[0]), BridgeMsgCodec.BODY_VERSION_V1, "auctionResult.version");
        assertEq(uint8(encoded[1]), BridgeMsgCodec.MSG_AUCTION_RESULT, "auctionResult.msgType");
        assertEq(encoded.length, 22, "auctionResult.length");

        encoded = BridgeMsgCodec.encodeMarkCalled(20260212, CALLED_AT, MarkBatchLib.one("20260212-TRY-U"));
        assertEq(uint8(encoded[0]), BridgeMsgCodec.BODY_VERSION_V1, "markCalled.version");
        assertEq(uint8(encoded[1]), BridgeMsgCodec.MSG_MARK_CALLED, "markCalled.msgType");
        assertEq(encoded.length, BridgeMsgCodec.MIN_LEN_MARK_CALLED, "markCalled.length");

        encoded = BridgeMsgCodec.encodeRefundInstructions(1, 0, 1, new address[](0), new uint128[](0), new uint128[](0));
        assertEq(uint8(encoded[0]), BridgeMsgCodec.BODY_VERSION_V1, "refund.version");
        assertEq(uint8(encoded[1]), BridgeMsgCodec.MSG_REFUND_INSTRUCTIONS, "refund.msgType");

        BridgeMsgCodec.IssuanceInstructionsPayload memory payload;
        payload.seriesId = "20260212-TRY-U";
        encoded = BridgeMsgCodec.encodeIssuanceInstructions(0, 0, 1, IssuanceBatchLib.one(payload));
        assertEq(uint8(encoded[0]), BridgeMsgCodec.BODY_VERSION_V1, "issuance.version");
        assertEq(uint8(encoded[1]), BridgeMsgCodec.MSG_ISSUANCE_INSTRUCTIONS, "issuance.msgType");
    }

    // --- BridgeMsgCodec: round-trip ---

    function test_BridgeCodec_AuctionStageStart_RoundTrip() public view {
        bytes memory packet = BridgeMsgCodec.encodeAuctionStageStart(
            42, 100, 200, 300, 1e6, 5e6, ReferenceCurrencyPriceLib.one(10, 7e6, 11e6, 13e6), 5, 6, 7, 3, 17e6, 1
        );
        (
            uint32 worldwideDay,
            IIntexAuction.WorldwideDayState dayState,
            IIntexAuction.AuctionSchedule memory schedule,
            IIntexAuction.AuctionParams memory params
        ) = BridgeMsgCodec.decodeAuctionParams(packet);

        assertEq(worldwideDay, 42);
        assertEq(uint8(dayState), uint8(IIntexAuction.WorldwideDayState.Green));
        assertEq(schedule.commitEnd, 100);
        assertEq(schedule.revealEnd, 200);
        assertEq(schedule.issuanceEnd, 300);
        assertEq(params.prices[0].isoCode, 10);
        assertEq(params.promisLoadMinor, 1e6);
        assertEq(params.minIntexBidRate, 5e6);
        assertEq(params.prices[0].entryPriceMinor, 7e6);
        assertEq(params.prices[0].floorPriceMinor, 11e6);
        assertEq(params.prices[0].callPriceMinor, 13e6);
        assertEq(params.callTrigger.callNoticePeriod, 5);
        assertEq(params.callTrigger.callWindow, 6);
        assertEq(params.callTrigger.callThreshold, 7);
        assertEq(params.minIntexBidQuantity, 3);
        assertEq(params.commitBondMinor, 17e6);
    }

    function test_BridgeCodec_AuctionResult_RoundTrip() public view {
        bytes memory packet = BridgeMsgCodec.encodeAuctionResult(42, 7, 13e6, 5);
        (uint32 worldwideDay, uint32 issuedCount, uint64 clearingPrice, uint32 wonCount) =
            this.exposedDecodeAuctionResult(packet);
        assertEq(worldwideDay, 42);
        assertEq(issuedCount, 7);
        assertEq(clearingPrice, 13e6);
        assertEq(wonCount, 5);
    }

    function test_BridgeCodec_MarkCalled_RoundTrip() public view {
        bytes memory packet = BridgeMsgCodec.encodeMarkCalled(20260212, CALLED_AT, MarkBatchLib.one("20260212-TRY-U"));
        bytes14 seriesId = this.exposedDecodeMarkCalled(packet);
        assertEq(seriesId, bytes14("20260212-TRY-U"));
    }

    // --- BridgeMsgCodec: unknown version reverts ---

    function test_BridgeCodec_UnknownBodyVersion_AuctionStageStart_Reverts() public {
        bytes memory packet = BridgeMsgCodec.encodeAuctionStageStart(
            1, 100, 200, 300, 1e6, 1e6, ReferenceCurrencyPriceLib.one(840, 2e6, 3e6, 4e6), 5, 6, 7, 1, 9e6, 1
        );
        packet[0] = 0xFF;
        vm.expectRevert(abi.encodeWithSelector(BridgeMsgCodec.UnsupportedBodyVersion.selector, 0xFF));
        BridgeMsgCodec.decodeAuctionParams(packet);
    }

    function test_BridgeCodec_UnknownBodyVersion_AuctionResult_Reverts() public {
        bytes memory packet = BridgeMsgCodec.encodeAuctionResult(1, 1, 1, 1);
        packet[0] = 0x42;
        vm.expectRevert(abi.encodeWithSelector(BridgeMsgCodec.UnsupportedBodyVersion.selector, 0x42));
        this.exposedDecodeAuctionResult(packet);
    }

    function test_BridgeCodec_UnknownBodyVersion_MarkCalled_Reverts() public {
        bytes memory packet = BridgeMsgCodec.encodeMarkCalled(20260212, CALLED_AT, MarkBatchLib.one("20260212-TRY-U"));
        packet[0] = 0xAA;
        vm.expectRevert(abi.encodeWithSelector(BridgeMsgCodec.UnsupportedBodyVersion.selector, 0xAA));
        this.exposedDecodeMarkCalled(packet);
    }

    function test_BridgeCodec_UnknownBodyVersion_BidsBatch_Reverts() public {
        bytes memory packet = BridgeMsgCodec.encodeBidsBatch(1, 30101, 1, 0, 1, new address[](0), new uint256[](0));
        packet[0] = 0x99;
        vm.expectRevert(abi.encodeWithSelector(BridgeMsgCodec.UnsupportedBodyVersion.selector, 0x99));
        this.exposedDecodeBidsBatch(packet);
    }

    function test_BridgeCodec_UnknownBodyVersion_AuctionStageClearing_Reverts() public {
        bytes memory packet = BridgeMsgCodec.encodeAuctionStageClearing(1);
        packet[0] = 0x10;
        vm.expectRevert(abi.encodeWithSelector(BridgeMsgCodec.UnsupportedBodyVersion.selector, 0x10));
        this.exposedDecodeAuctionStageClearing(packet);
    }

    function test_BridgeCodec_UnknownBodyVersion_RefundInstructions_Reverts() public {
        bytes memory packet =
            BridgeMsgCodec.encodeRefundInstructions(1, 0, 1, new address[](0), new uint128[](0), new uint128[](0));
        packet[0] = 0x55;
        vm.expectRevert(abi.encodeWithSelector(BridgeMsgCodec.UnsupportedBodyVersion.selector, 0x55));
        this.exposedDecodeRefundInstructions(packet);
    }

    function test_BridgeCodec_UnknownBodyVersion_IssuanceInstructions_Reverts() public {
        BridgeMsgCodec.IssuanceInstructionsPayload memory payload;
        payload.seriesId = "20260212-TRY-U";
        bytes memory packet = BridgeMsgCodec.encodeIssuanceInstructions(0, 0, 1, IssuanceBatchLib.one(payload));
        packet[0] = 0x77;
        vm.expectRevert(abi.encodeWithSelector(BridgeMsgCodec.UnsupportedBodyVersion.selector, 0x77));
        this.exposedDecodeIssuanceInstructions(packet);
    }

    // --- BridgeMsgCodec: sibling-array parity + cap on the variable-length decoders ---

    function test_BridgeCodec_DecodeBidsBatch_RejectsArrayLengthMismatch() public {
        // Four parallel arrays with mismatched lengths: indexed in lockstep downstream, so an
        // unequal decode would panic out of bounds inside the ordered lane. Must revert typed.
        // The encoder now reverts on parity mismatch, so the wire payload is hand-built directly -
        // matching the way an oversized REFUND would arrive via a peer compromise or a future
        // encoder change.
        address[] memory bidders = new address[](2);
        uint16[] memory quantities = new uint16[](1); // short
        uint32[] memory rates = new uint32[](2);
        uint32[] memory timestamps = new uint32[](2);
        bytes memory packet = abi.encodePacked(
            BridgeMsgCodec.BODY_VERSION_V1,
            BridgeMsgCodec.MSG_BIDS_BATCH,
            abi.encode(
                uint32(42), uint32(30101), uint32(1), uint16(0), uint16(1), bidders, quantities, rates, timestamps
            )
        );

        vm.expectRevert(abi.encodeWithSelector(BridgeMsgCodec.BidsArrayLengthMismatch.selector, uint256(2), uint256(1)));
        this.exposedDecodeBidsBatch(packet);
    }

    function test_BridgeCodec_DecodeIssuance_RejectsArrayLengthMismatch() public {
        BridgeMsgCodec.IssuanceInstructionsPayload memory payload;
        payload.seriesId = "20260212-TRY-U";
        payload.recipients = new address[](3);
        payload.quantities = new uint256[](2); // short
        // Hand-build the body so the encoder's new parity check does not intervene.
        bytes memory packet = abi.encodePacked(
            BridgeMsgCodec.BODY_VERSION_V1,
            BridgeMsgCodec.MSG_ISSUANCE_INSTRUCTIONS,
            abi.encode(uint32(0), uint16(0), uint16(1), IssuanceBatchLib.one(payload))
        );

        vm.expectRevert(
            abi.encodeWithSelector(BridgeMsgCodec.IssuanceArrayLengthMismatch.selector, uint256(3), uint256(2))
        );
        this.exposedDecodeIssuanceInstructions(packet);
    }

    function test_BridgeCodec_DecodeIssuance_RejectsOverCap() public {
        // The outbound encoder caps recipients at MAX_RECIPIENTS_PER_ISSUANCE, so an over-cap packet
        // cannot be built through it; hand-build the wire body to exercise the inbound decode cap
        // (the trusted-peer-bug path), reading the cap from the constant.
        uint256 n = uint256(BridgeMsgCodec.MAX_RECIPIENTS_PER_ISSUANCE) + 1;
        BridgeMsgCodec.IssuanceInstructionsPayload memory payload;
        payload.seriesId = "20260212-TRY-U";
        payload.recipients = new address[](n);
        payload.quantities = new uint256[](n);
        bytes memory packet = abi.encodePacked(
            BridgeMsgCodec.BODY_VERSION_V1,
            BridgeMsgCodec.MSG_ISSUANCE_INSTRUCTIONS,
            abi.encode(uint32(0), uint16(0), uint16(1), IssuanceBatchLib.one(payload))
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.IssuanceBatchTooLarge.selector, n, uint256(BridgeMsgCodec.MAX_RECIPIENTS_PER_ISSUANCE)
            )
        );
        this.exposedDecodeIssuanceInstructions(packet);
    }

    function test_BridgeCodec_BidsBatch_BatchIndexTotal_RoundTrips() public view {
        address[] memory bidders = new address[](1);
        bidders[0] = address(0xB1);
        uint16[] memory quantities = new uint16[](1);
        quantities[0] = 7;
        uint32[] memory rates = new uint32[](1);
        rates[0] = 100;
        uint32[] memory timestamps = new uint32[](1);
        timestamps[0] = 42;

        bytes memory lastPacket =
            BridgeMsgCodec.encodeBidsBatch(1, 30101, 7, 1, 2, bidders, BidPackLib.pack(quantities, rates, timestamps));
        (,, uint32 genLast, uint16 idxLast, uint16 totalLast,,) = this.exposedDecodeBidsBatch(lastPacket);
        assertEq(idxLast, 1, "batchIndex should round-trip");
        assertEq(totalLast, 2, "totalBatches should round-trip");
        assertEq(genLast, 7, "relayGeneration should round-trip");

        bytes memory midPacket =
            BridgeMsgCodec.encodeBidsBatch(1, 30101, 7, 0, 2, bidders, BidPackLib.pack(quantities, rates, timestamps));
        (,,, uint16 idxMid, uint16 totalMid,,) = this.exposedDecodeBidsBatch(midPacket);
        assertEq(idxMid, 0, "batchIndex=0 should round-trip");
        assertEq(totalMid, 2, "totalBatches should round-trip");
    }

    // --- External wrappers so calldata-slice helpers can be invoked via vm.expectRevert ---

    function exposedDecodeBidsBatch(bytes calldata p)
        external
        pure
        returns (uint32, uint32, uint32, uint16, uint16, address[] memory, uint256[] memory)
    {
        return BridgeMsgCodec.decodeBidsBatch(p);
    }

    function exposedDecodeAuctionStageClearing(bytes calldata p) external pure returns (uint32) {
        return BridgeMsgCodec.decodeAuctionStageClearing(p);
    }

    function exposedDecodeAuctionResult(bytes calldata p) external pure returns (uint32, uint32, uint64, uint32) {
        return BridgeMsgCodec.decodeAuctionResult(p);
    }

    function exposedDecodeMarkCalled(bytes calldata p) external pure returns (bytes14) {
        (,, bytes14[] memory seriesIds) = BridgeMsgCodec.decodeMarkCalled(p);
        return seriesIds[0];
    }

    function exposedDecodeRefundInstructions(bytes calldata p)
        external
        pure
        returns (uint32, uint16, uint16, address[] memory, uint128[] memory, uint128[] memory)
    {
        return BridgeMsgCodec.decodeRefundInstructions(p);
    }

    function exposedDecodeIssuanceInstructions(bytes calldata p)
        external
        pure
        returns (BridgeMsgCodec.IssuanceInstructionsPayload[] memory series)
    {
        (,,, series) = BridgeMsgCodec.decodeIssuanceInstructions(p);
    }
}
