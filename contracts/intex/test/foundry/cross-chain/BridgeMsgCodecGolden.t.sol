// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {MarkBatchLib} from "../helpers/MarkBatchLib.sol";
import {BidPackLib} from "../helpers/BidPackLib.sol";
import {ReferenceCurrencyPriceLib} from "../helpers/ReferenceCurrencyPriceLib.sol";
import {Test} from "forge-std/Test.sol";
import {BridgeMsgCodec} from "@contracts/shared/libs/BridgeMsgCodec.sol";
import {IIntexAuction} from "@contracts/target/interfaces/IIntexAuction.sol";
import {IssuanceBatchLib} from "../helpers/IssuanceBatch.sol";

/// @dev Golden-value and per-field round-trip coverage for BridgeMsgCodec encode/decode.
contract BridgeMsgCodecGoldenTest is Test {
    /// @dev Fixed call stamp; these tests exercise the wire, not the clock.
    uint32 internal constant CALLED_AT = 1_777_000_000;

    // Byte-literal goldens for the fixed-width packed messages.

    function test_Golden_AuctionStageStart() public pure {
        bytes memory encoded = BridgeMsgCodec.encodeAuctionStageStart(
            0x11223344,
            0x55667788,
            0x99AABBCC,
            0xDDEEFF00,
            0x0102030405060708090A0B0C0D0E0F10,
            0x1A2B3C4D,
            ReferenceCurrencyPriceLib.one(0xD1D2, 0x1122334455667788, 0x99AABBCCDDEEFF00, 0xA1B2C3D4E5F60718),
            0xCAFEBABE,
            0x5678,
            0x9ABC,
            0xABCD,
            0xF1F2F3F4F5F6F7F8F9FAFBFCFDFEFF01,
            0x01
        );
        assertEq(
            encoded,
            hex"0103112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f101a2b3c4dcafebabe0000567800009abcabcdf1f2f3f4f5f6f7f8f9fafbfcfdfeff010101d1d2112233445566778899aabbccddeeff00a1b2c3d4e5f60718"
        );
        assertEq(encoded.length, BridgeMsgCodec.MIN_LEN_AUCTION_STAGE_START + BridgeMsgCodec.REFERENCE_PRICE_LEN);
    }

    function test_Golden_AuctionStageClearing() public pure {
        assertEq(BridgeMsgCodec.encodeAuctionStageClearing(0x0A0B0C0D), hex"01040a0b0c0d");
    }

    function test_Golden_AuctionResult() public pure {
        bytes memory encoded =
            BridgeMsgCodec.encodeAuctionResult(0x11223344, 0x55667788, 0x99AABBCCDDEEFF00, 0xA1B2C3D4);
        assertEq(encoded, hex"0105112233445566778899aabbccddeeff00a1b2c3d4");
        assertEq(encoded.length, BridgeMsgCodec.MIN_LEN_AUCTION_RESULT);
    }

    function test_Golden_MarkCalled() public pure {
        // [ver=01][type=08] ++ abi.encode(wwd, calledAt, seriesIds)
        assertEq(
            BridgeMsgCodec.encodeMarkCalled(20260212, CALLED_AT, MarkBatchLib.one("20260212-TRY-U")),
            abi.encodePacked(hex"0108", abi.encode(uint32(20260212), CALLED_AT, MarkBatchLib.one("20260212-TRY-U")))
        );
    }

    function test_Golden_MarkQualified() public pure {
        assertEq(
            BridgeMsgCodec.encodeMarkQualified(20260212, MarkBatchLib.one("20260212-TRY-U")),
            abi.encodePacked(hex"0109", abi.encode(uint32(20260212), MarkBatchLib.one("20260212-TRY-U")))
        );
    }

    function test_Golden_BidsDone() public pure {
        // [ver=01][type=02][wwd=11223344][srcChain=00000061][gen=00000002][totalBatches=0003][totalBids=000000c8]
        assertEq(
            BridgeMsgCodec.encodeBidsDone(0x11223344, 0x61, 0x02, 0x0003, 0xC8),
            hex"01021122334400000061000000020003000000c8"
        );
    }

    function test_RoundTrip_BidsDone_AllFields() public view {
        (uint32 wwd, uint32 src, uint32 gen, uint16 batches, uint32 bids) = this.exposedDecodeBidsDone(
            BridgeMsgCodec.encodeBidsDone(0x0A0B0C0D, 0x11121314, 0x21222324, 0x3132, 0x41424344)
        );
        assertEq(wwd, 0x0A0B0C0D, "worldwideDay");
        assertEq(src, 0x11121314, "srcChainId");
        assertEq(gen, 0x21222324, "relayGeneration");
        assertEq(batches, 0x3132, "totalBatches");
        assertEq(bids, 0x41424344, "totalBids");
    }

    // Per-field round-trips: a distinct sentinel per field, so any offset or tuple
    // reorder lands a value in the wrong field and fails an assertion.

    function test_RoundTrip_AuctionStageStart_AllFields() public view {
        (
            uint32 worldwideDay,
            IIntexAuction.WorldwideDayState dayState,
            IIntexAuction.AuctionSchedule memory schedule,
            IIntexAuction.AuctionParams memory params
        ) = BridgeMsgCodec.decodeAuctionParams(
            BridgeMsgCodec.encodeAuctionStageStart(
                0x11223344,
                0x55667788,
                0x99AABBCC,
                0xDDEEFF00,
                0x0102030405060708090A0B0C0D0E0F10,
                0x1A2B3C4D,
                ReferenceCurrencyPriceLib.one(0xD1D2, 0x1122334455667788, 0x99AABBCCDDEEFF00, 0xA1B2C3D4E5F60718),
                0xCAFEBABE,
                0x5678,
                0x9ABC,
                0xABCD,
                0xF1F2F3F4F5F6F7F8F9FAFBFCFDFEFF01,
                0x02
            )
        );
        assertEq(worldwideDay, 0x11223344, "worldwideDay");
        assertEq(uint8(dayState), uint8(IIntexAuction.WorldwideDayState.Red), "dayState");
        assertEq(schedule.commitEnd, 0x55667788, "commitEnd");
        assertEq(schedule.revealEnd, 0x99AABBCC, "revealEnd");
        assertEq(schedule.issuanceEnd, 0xDDEEFF00, "issuanceEnd");
        assertEq(params.prices[0].isoCode, 0xD1D2, "priceIsoCode");
        assertEq(params.promisLoadMinor, 0x0102030405060708090A0B0C0D0E0F10, "promisLoadMinor");
        assertEq(params.minIntexBidRate, 0x1A2B3C4D, "minIntexBidRate");
        assertEq(params.prices[0].entryPriceMinor, 0x1122334455667788, "entryPrice");
        assertEq(params.prices[0].floorPriceMinor, 0x99AABBCCDDEEFF00, "floorPriceMinor");
        assertEq(params.prices[0].callPriceMinor, 0xA1B2C3D4E5F60718, "callPriceMinor");
        assertEq(params.callTrigger.callNoticePeriod, 0xCAFEBABE, "callNoticePeriod");
        assertEq(params.callTrigger.callWindow, 0x5678, "callWindow");
        assertEq(params.callTrigger.callThreshold, 0x9ABC, "callThreshold");
        assertEq(params.minIntexBidQuantity, 0xABCD, "minIntexBidQuantity");
        assertEq(params.commitBondMinor, 0xF1F2F3F4F5F6F7F8F9FAFBFCFDFEFF01, "commitBondMinor");
    }

    function test_RoundTrip_AuctionResult_AllFields() public view {
        (uint32 worldwideDay, uint32 issuedIntexCount, uint64 clearingPrice, uint32 wonBidsCount) = this.exposedDecodeAuctionResult(
            BridgeMsgCodec.encodeAuctionResult(0x11223344, 0x55667788, 0x99AABBCCDDEEFF00, 0xA1B2C3D4)
        );
        assertEq(worldwideDay, 0x11223344, "worldwideDay");
        assertEq(issuedIntexCount, 0x55667788, "issuedIntexCount");
        assertEq(clearingPrice, 0x99AABBCCDDEEFF00, "clearingPrice");
        assertEq(wonBidsCount, 0xA1B2C3D4, "wonBidsCount");
    }

    function test_RoundTrip_BidsBatch_AllFields_InclRelayGeneration() public view {
        address[] memory bidders = new address[](2);
        bidders[0] = address(0xA11CE);
        bidders[1] = address(0xB0B);
        uint16[] memory quantities = new uint16[](2);
        quantities[0] = 0x1111;
        quantities[1] = 0x2222;
        uint32[] memory rates = new uint32[](2);
        rates[0] = 0x33333333;
        rates[1] = 0x44444444;
        uint32[] memory timestamps = new uint32[](2);
        timestamps[0] = 0x55555555;
        timestamps[1] = 0x66666666;

        (
            uint32 worldwideDay,
            uint32 srcChainId,
            uint32 relayGeneration,
            uint16 batchIndex,
            uint16 totalBatches,
            address[] memory dBidders,
            uint256[] memory dPacked
        ) = this.exposedDecodeBidsBatch(
            BridgeMsgCodec.encodeBidsBatch(
                0x11223344,
                0x0000ABCD,
                0x0000002A,
                0x0000,
                0x0001,
                bidders,
                BidPackLib.pack(quantities, rates, timestamps)
            )
        );

        assertEq(worldwideDay, 0x11223344, "worldwideDay");
        assertEq(srcChainId, 0x0000ABCD, "srcChainId");
        assertEq(batchIndex, 0x0000, "batchIndex");
        assertEq(totalBatches, 0x0001, "totalBatches");
        assertEq(relayGeneration, 0x0000002A, "relayGeneration");
        assertEq(dBidders.length, 2, "bidders len");
        assertEq(dBidders[0], address(0xA11CE), "bidders[0]");
        assertEq(dBidders[1], address(0xB0B), "bidders[1]");
        // Every scalar survives the one-word packing, the currency pair included.
        for (uint256 i = 0; i < 2; ++i) {
            (uint16 q, uint32 r, uint32 ts, uint16 iso, uint16 ref) = BridgeMsgCodec.unpackBid(dPacked[i]);
            assertEq(q, quantities[i], "quantity");
            assertEq(r, rates[i], "rate");
            assertEq(ts, timestamps[i], "timestamp");
            assertEq(iso, 840, "issuanceCurrency");
            assertEq(ref, 840, "referenceCurrency");
        }
    }

    function test_RoundTrip_BidsBatch_MidBatch_RelayGenerationOne() public view {
        (,, uint32 relayGeneration, uint16 batchIndex, uint16 totalBatches,,) = this.exposedDecodeBidsBatch(
            BridgeMsgCodec.encodeBidsBatch(7, 30101, 1, 0, 2, new address[](0), new uint256[](0))
        );
        assertEq(batchIndex, 0, "batchIndex");
        assertEq(totalBatches, 2, "totalBatches");
        assertEq(relayGeneration, 1, "relayGeneration");
    }

    function test_RoundTrip_RefundInstructions_AllFields() public view {
        address[] memory bidders = new address[](2);
        bidders[0] = address(0xA11CE);
        bidders[1] = address(0xB0B);
        uint128[] memory refunded = new uint128[](2);
        refunded[0] = 0x1111111111111111;
        refunded[1] = 0x2222222222222222;
        uint128[] memory paid = new uint128[](2);
        paid[0] = 0x3333333333333333;
        paid[1] = 0x4444444444444444;

        (
            uint32 worldwideDay,
            uint16 chunkIndex,
            uint16 totalChunks,
            address[] memory dBidders,
            uint128[] memory dRefunded,
            uint128[] memory dPaid
        ) = this.exposedDecodeRefundInstructions(
            BridgeMsgCodec.encodeRefundInstructions(0x77665544, 0, 1, bidders, refunded, paid)
        );

        assertEq(chunkIndex, 0, "chunkIndex");
        assertEq(totalChunks, 1, "totalChunks");

        assertEq(worldwideDay, 0x77665544, "worldwideDay");
        assertEq(dBidders[0], address(0xA11CE), "bidders[0]");
        assertEq(dBidders[1], address(0xB0B), "bidders[1]");
        assertEq(dRefunded[0], 0x1111111111111111, "refunded[0]");
        assertEq(dRefunded[1], 0x2222222222222222, "refunded[1]");
        assertEq(dPaid[0], 0x3333333333333333, "paid[0]");
        assertEq(dPaid[1], 0x4444444444444444, "paid[1]");
    }

    function test_RoundTrip_IssuanceInstructions_AllFields() public view {
        address[] memory recipients = new address[](2);
        recipients[0] = address(0xA11CE);
        recipients[1] = address(0xB0B);
        uint256[] memory quantities = new uint256[](2);
        quantities[0] = 0xDEAD;
        quantities[1] = 0xBEEF;

        BridgeMsgCodec.IssuanceInstructionsPayload memory p;
        p.seriesId = "20260212-TRY-U";
        p.worldwideDay = 0x55555555; // distinct from seriesId so a field swap can't pass
        p.issuedIntexCount = 0x55667788;
        p.promisLoadMinor = 0x0102030405060708090A0B0C0D0E0F10;
        p.entryPriceMinor = 0x0A0B0C0D0E0F1011;
        p.floorPriceMinor = 0x99AABBCCDDEEFF00;
        p.callNoticePeriod = 0xCAFEBABE;
        p.issuanceCurrency = 840;
        p.referenceCurrency = 978;
        p.callWindow = 0x5678;
        p.callThreshold = 0x9ABC;
        p.callPriceMinor = 0xA1B2C3D4E5F60718;
        p.recipients = recipients;
        p.quantities = quantities;

        BridgeMsgCodec.IssuanceInstructionsPayload memory d = this.exposedDecodeIssuanceInstructions(
            BridgeMsgCodec.encodeIssuanceInstructions(p.worldwideDay, 0, 1, IssuanceBatchLib.one(p))
        )[0];

        assertEq(d.seriesId, bytes14("20260212-TRY-U"), "seriesId");
        assertEq(d.worldwideDay, 0x55555555, "worldwideDay");
        assertEq(d.issuedIntexCount, 0x55667788, "issuedIntexCount");
        assertEq(d.promisLoadMinor, 0x0102030405060708090A0B0C0D0E0F10, "promisLoadMinor");
        assertEq(d.entryPriceMinor, 0x0A0B0C0D0E0F1011, "entryPriceMinor");
        assertEq(d.floorPriceMinor, 0x99AABBCCDDEEFF00, "floorPriceMinor");
        assertEq(d.callNoticePeriod, 0xCAFEBABE, "callNoticePeriod");
        assertEq(d.issuanceCurrency, 840, "issuanceCurrency");
        assertEq(d.referenceCurrency, 978, "referenceCurrency");
        assertEq(d.callWindow, 0x5678, "callWindow");
        assertEq(d.callThreshold, 0x9ABC, "callThreshold");
        assertEq(d.callPriceMinor, 0xA1B2C3D4E5F60718, "callPriceMinor");
        assertEq(d.recipients[0], address(0xA11CE), "recipients[0]");
        assertEq(d.recipients[1], address(0xB0B), "recipients[1]");
        assertEq(d.quantities[0], 0xDEAD, "quantities[0]");
        assertEq(d.quantities[1], 0xBEEF, "quantities[1]");
    }

    function test_RoundTrip_SingleField_SeriesId() public view {
        assertEq(
            this.exposedDecodeAuctionStageClearing(BridgeMsgCodec.encodeAuctionStageClearing(0x0A0B0C0D)), 0x0A0B0C0D
        );
        assertEq(
            this.exposedDecodeMarkCalled(
                BridgeMsgCodec.encodeMarkCalled(20260212, CALLED_AT, MarkBatchLib.one("20260212-TRY-U"))
            ),
            bytes14("20260212-TRY-U")
        );
        assertEq(
            this.exposedDecodeMarkQualified(
                BridgeMsgCodec.encodeMarkQualified(20260212, MarkBatchLib.one("20260212-TRY-U"))
            ),
            bytes14("20260212-TRY-U")
        );
    }

    // External calldata wrappers for the internal decoders.

    function exposedDecodeAuctionResult(bytes calldata p) external pure returns (uint32, uint32, uint64, uint32) {
        return BridgeMsgCodec.decodeAuctionResult(p);
    }

    function exposedDecodeAuctionStageClearing(bytes calldata p) external pure returns (uint32) {
        return BridgeMsgCodec.decodeAuctionStageClearing(p);
    }

    function exposedDecodeMarkCalled(bytes calldata p) external pure returns (bytes14) {
        (,, bytes14[] memory seriesIds) = BridgeMsgCodec.decodeMarkCalled(p);
        return seriesIds[0];
    }

    function exposedDecodeMarkQualified(bytes calldata p) external pure returns (bytes14) {
        (, bytes14[] memory seriesIds) = BridgeMsgCodec.decodeMarkQualified(p);
        return seriesIds[0];
    }

    function exposedDecodeBidsDone(bytes calldata p) external pure returns (uint32, uint32, uint32, uint16, uint32) {
        return BridgeMsgCodec.decodeBidsDone(p);
    }

    function exposedDecodeBidsBatch(bytes calldata p)
        external
        pure
        returns (uint32, uint32, uint32, uint16, uint16, address[] memory, uint256[] memory)
    {
        return BridgeMsgCodec.decodeBidsBatch(p);
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
