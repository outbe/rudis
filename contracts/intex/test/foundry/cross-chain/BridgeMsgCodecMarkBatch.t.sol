// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {BridgeMsgCodec} from "@contracts/shared/libs/BridgeMsgCodec.sol";
import {MarkBatchLib} from "../helpers/MarkBatchLib.sol";

/// @dev MARK_CALLED and MARK_QUALIFIED carry one day's series in one reference currency, so both
///      round-trip a batch and both refuse an empty or over-sized one.
contract BridgeMsgCodecMarkBatchTest is Test {
    /// @dev Fixed call stamp; these tests exercise the wire, not the clock.
    uint32 internal constant CALLED_AT = 1_777_000_000;

    uint32 internal constant WORLDWIDE_DAY = 20260212;
    bytes14 internal constant FIRST = "20260212-USD-U";
    bytes14 internal constant SECOND = "20260212-EUR-U";

    function exposedDecodeMarkCalled(bytes calldata p)
        external
        pure
        returns (uint32 worldwideDay, uint32 calledAt, bytes14[] memory seriesIds)
    {
        return BridgeMsgCodec.decodeMarkCalled(p);
    }

    function exposedDecodeMarkQualified(bytes calldata p)
        external
        pure
        returns (uint32 worldwideDay, bytes14[] memory seriesIds)
    {
        return BridgeMsgCodec.decodeMarkQualified(p);
    }

    function exposedEncodeMarkCalled(uint32 day, bytes14[] calldata ids) external pure returns (bytes memory) {
        return BridgeMsgCodec.encodeMarkCalled(day, CALLED_AT, ids);
    }

    function exposedEncodeMarkQualified(uint32 day, bytes14[] calldata ids) external pure returns (bytes memory) {
        return BridgeMsgCodec.encodeMarkQualified(day, ids);
    }

    function test_markCalledRoundTripsTheWholeBatch() public view {
        bytes memory packet = BridgeMsgCodec.encodeMarkCalled(WORLDWIDE_DAY, CALLED_AT, MarkBatchLib.two(FIRST, SECOND));

        (uint32 day,, bytes14[] memory ids) = this.exposedDecodeMarkCalled(packet);

        assertEq(day, WORLDWIDE_DAY, "worldwideDay survives");
        assertEq(ids.length, 2, "both series survive");
        assertEq(ids[0], FIRST, "first series");
        assertEq(ids[1], SECOND, "second series");
    }

    function test_markQualifiedRoundTripsTheWholeBatch() public view {
        bytes memory packet = BridgeMsgCodec.encodeMarkQualified(WORLDWIDE_DAY, MarkBatchLib.two(FIRST, SECOND));

        (uint32 day, bytes14[] memory ids) = this.exposedDecodeMarkQualified(packet);

        assertEq(day, WORLDWIDE_DAY, "worldwideDay survives");
        assertEq(ids.length, 2, "both series survive");
    }

    function test_aFullBatchRoundTrips() public view {
        uint256 max = BridgeMsgCodec.MAX_SERIES_PER_MARK;
        bytes14[] memory batch = MarkBatchLib.sized(FIRST, max);

        (,, bytes14[] memory ids) =
            this.exposedDecodeMarkCalled(BridgeMsgCodec.encodeMarkCalled(WORLDWIDE_DAY, CALLED_AT, batch));

        assertEq(ids.length, max, "the cap round-trips");
        for (uint256 i = 0; i < max; ++i) {
            // Distinct ids, so this pins the order and not just the count.
            assertEq(ids[i], batch[i], "series survives in place");
            if (i > 0) assertTrue(batch[i] != batch[i - 1], "the fixture ids differ");
        }
    }

    function test_theHeaderNamesTheMessageType() public view {
        bytes memory called = BridgeMsgCodec.encodeMarkCalled(WORLDWIDE_DAY, CALLED_AT, MarkBatchLib.one(FIRST));
        bytes memory qualified = BridgeMsgCodec.encodeMarkQualified(WORLDWIDE_DAY, MarkBatchLib.one(FIRST));

        assertEq(uint8(called[0]), BridgeMsgCodec.BODY_VERSION_V1, "called version");
        assertEq(uint8(called[1]), BridgeMsgCodec.MSG_MARK_CALLED, "called type");
        assertEq(uint8(qualified[0]), BridgeMsgCodec.BODY_VERSION_V1, "qualified version");
        assertEq(uint8(qualified[1]), BridgeMsgCodec.MSG_MARK_QUALIFIED, "qualified type");
    }

    function test_anEmptyBatchIsRefusedOnBothSides() public {
        bytes14[] memory empty = new bytes14[](0);

        vm.expectRevert(BridgeMsgCodec.EmptyMarkBatch.selector);
        this.exposedEncodeMarkCalled(WORLDWIDE_DAY, empty);

        // Inbound too, though the length floor gets there first: an empty batch encodes
        // shorter than the one-series minimum, so it never reaches the batch check.
        bytes memory forged = abi.encodePacked(hex"0108", abi.encode(WORLDWIDE_DAY, empty));
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.InvalidPayloadLength.selector,
                BridgeMsgCodec.MSG_MARK_CALLED,
                forged.length,
                BridgeMsgCodec.MIN_LEN_MARK_CALLED
            )
        );
        this.exposedDecodeMarkCalled(forged);
    }

    function test_anOverSizedBatchIsRefusedOnBothSides() public {
        uint256 tooMany = BridgeMsgCodec.MAX_SERIES_PER_MARK + 1;
        bytes14[] memory batch = MarkBatchLib.sized(FIRST, tooMany);
        bytes memory expected = abi.encodeWithSelector(
            BridgeMsgCodec.MarkBatchTooLarge.selector, tooMany, BridgeMsgCodec.MAX_SERIES_PER_MARK
        );

        vm.expectRevert(expected);
        this.exposedEncodeMarkQualified(WORLDWIDE_DAY, batch);

        bytes memory forged = abi.encodePacked(hex"0109", abi.encode(WORLDWIDE_DAY, batch));
        vm.expectRevert(expected);
        this.exposedDecodeMarkQualified(forged);
    }

    function test_aBodyShorterThanOneSeriesIsRefused() public {
        bytes memory tooShort = abi.encodePacked(hex"0109", new bytes(96));
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.InvalidPayloadLength.selector,
                BridgeMsgCodec.MSG_MARK_QUALIFIED,
                tooShort.length,
                BridgeMsgCodec.MIN_LEN_MARK_QUALIFIED
            )
        );
        this.exposedDecodeMarkQualified(tooShort);
    }
}
