// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {MarkBatchLib} from "../helpers/MarkBatchLib.sol";
import {BidPackLib} from "../helpers/BidPackLib.sol";
import {ReferenceCurrencyPriceLib} from "../helpers/ReferenceCurrencyPriceLib.sol";
import {Test} from "forge-std/Test.sol";
import {BridgeMsgCodec} from "@contracts/shared/libs/BridgeMsgCodec.sol";
import {IIntexAuction} from "@contracts/target/interfaces/IIntexAuction.sol";
import {IssuanceBatchLib} from "../helpers/IssuanceBatch.sol";

/// @dev PR-A Tier-1 input-validation hardening of BridgeMsgCodec:
///      - fixed-width decoders assert exact length (truncation silent-truncation);
///      - the STAGE_START `dayState` byte decodes strictly;
///      - outbound encoders cap payload arrays at `MAX_PAYLOAD_ARRAY_LEN`;
///      - `decode*` deliberately does NOT cap (inbound is A3's drop-don't-block job).
///
///      External wrappers expose the internal calldata-slice decoders so they can be
///      driven through `vm.expectRevert` (mirrors BodyVersion.t.sol).
contract BridgeMsgCodecValidationTest is Test {
    /// @dev Fixed call stamp; these tests exercise the wire, not the clock.
    uint32 internal constant CALLED_AT = 1_777_000_000;

    // --- fixed-width decoders reject over-long payloads ---

    function test_AuctionStageStart_OverLong_Reverts() public {
        bytes memory packet = BridgeMsgCodec.encodeAuctionStageStart(
            1, 100, 200, 300, 1e6, 1e6, ReferenceCurrencyPriceLib.one(840, 2e6, 3e6, 4e6), 5, 6, 7, 1, 9e6, 1
        );
        bytes memory tooLong = abi.encodePacked(packet, hex"00");
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.InvalidPayloadLength.selector,
                BridgeMsgCodec.MSG_AUCTION_STAGE_START,
                tooLong.length,
                BridgeMsgCodec.MIN_LEN_AUCTION_STAGE_START
            )
        );
        BridgeMsgCodec.decodeAuctionParams(tooLong);
    }

    // --- fixed-width decoders reject empty / truncated payloads with a typed error ---

    function test_AuctionStageStart_Empty_RevertsTyped() public {
        bytes memory empty = "";
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.InvalidPayloadLength.selector,
                BridgeMsgCodec.MSG_AUCTION_STAGE_START,
                0,
                BridgeMsgCodec.MIN_LEN_AUCTION_STAGE_START
            )
        );
        BridgeMsgCodec.decodeAuctionParams(empty);
    }

    function test_AuctionStageStart_Truncated_RevertsTyped() public {
        bytes memory packet = BridgeMsgCodec.encodeAuctionStageStart(
            1, 100, 200, 300, 1e6, 1e6, ReferenceCurrencyPriceLib.one(840, 2e6, 3e6, 4e6), 5, 6, 7, 1, 9e6, 1
        );
        bytes memory truncated = new bytes(packet.length - 1);
        for (uint256 i = 0; i < truncated.length; i++) {
            truncated[i] = packet[i];
        }
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.InvalidPayloadLength.selector,
                BridgeMsgCodec.MSG_AUCTION_STAGE_START,
                truncated.length,
                BridgeMsgCodec.MIN_LEN_AUCTION_STAGE_START
            )
        );
        BridgeMsgCodec.decodeAuctionParams(truncated);
    }

    // --- remaining fixed-width decoders reject over-long payloads ---

    function test_AuctionStageClearing_OverLong_Reverts() public {
        bytes memory tooLong = abi.encodePacked(BridgeMsgCodec.encodeAuctionStageClearing(1), hex"00");
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.InvalidPayloadLength.selector,
                BridgeMsgCodec.MSG_AUCTION_STAGE_CLEARING,
                tooLong.length,
                BridgeMsgCodec.MIN_LEN_AUCTION_STAGE_CLEARING
            )
        );
        this.exposedDecodeAuctionStageClearing(tooLong);
    }

    function test_AuctionResult_OverLong_Reverts() public {
        bytes memory tooLong = abi.encodePacked(BridgeMsgCodec.encodeAuctionResult(1, 7, 5e6, 3), hex"00");
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.InvalidPayloadLength.selector,
                BridgeMsgCodec.MSG_AUCTION_RESULT,
                tooLong.length,
                BridgeMsgCodec.MIN_LEN_AUCTION_RESULT
            )
        );
        this.exposedDecodeAuctionResult(tooLong);
    }

    function test_MarkCalled_EmptyBatch_Reverts() public {
        bytes14[] memory empty = new bytes14[](0);
        vm.expectRevert(BridgeMsgCodec.EmptyMarkBatch.selector);
        this.exposedEncodeMarkCalled(20260212, empty);
    }

    function test_MarkQualified_OverSizedBatch_Reverts() public {
        uint256 tooMany = BridgeMsgCodec.MAX_SERIES_PER_MARK + 1;
        bytes14[] memory batch = MarkBatchLib.sized("20260212-TRY-U", tooMany);
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.MarkBatchTooLarge.selector, tooMany, BridgeMsgCodec.MAX_SERIES_PER_MARK
            )
        );
        this.exposedEncodeMarkQualified(20260212, batch);
    }

    function test_MarkCalled_ShortBody_Reverts() public {
        bytes memory tooShort = abi.encodePacked(hex"0108", new bytes(64));
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.InvalidPayloadLength.selector,
                BridgeMsgCodec.MSG_MARK_CALLED,
                tooShort.length,
                BridgeMsgCodec.MIN_LEN_MARK_CALLED
            )
        );
        this.exposedDecodeMarkCalled(tooShort);
    }

    function testFuzz_AuctionStageStart_DayStateByteAboveRed_Reverts(uint8 state) public {
        state = uint8(bound(state, 3, 255));
        bytes memory packet = BridgeMsgCodec.encodeAuctionStageStart(
            1, 100, 200, 300, 1e6, 1e6, ReferenceCurrencyPriceLib.one(840, 2e6, 3e6, 4e6), 5, 6, 7, 1, 9e6, 1
        );
        packet[68] = bytes1(state);
        vm.expectRevert(IIntexAuction.InvalidDayState.selector);
        BridgeMsgCodec.decodeAuctionParams(packet);
    }

    // --- Happy-path round-trips still pass after the exact-length guard ---

    function test_FixedWidth_RoundTrips_StillPass() public view {
        (uint32 s,,,) = BridgeMsgCodec.decodeAuctionParams(
            BridgeMsgCodec.encodeAuctionStageStart(
                42, 1, 2, 3, 1e6, 1, ReferenceCurrencyPriceLib.one(840, 2, 3, 4e6), 5, 6, 7, 1, 9e6, 1
            )
        );
        assertEq(s, 42, "stageStart");
        assertEq(this.exposedDecodeAuctionStageClearing(BridgeMsgCodec.encodeAuctionStageClearing(7)), 7, "clearing");
        (uint32 rs,,,) = this.exposedDecodeAuctionResult(BridgeMsgCodec.encodeAuctionResult(9, 1, 1, 1));
        assertEq(rs, 9, "result");
        assertEq(
            this.exposedDecodeMarkCalled(
                BridgeMsgCodec.encodeMarkCalled(20260212, CALLED_AT, MarkBatchLib.one("20260212-TRY-U"))
            ),
            bytes14("20260212-TRY-U"),
            "markCalled"
        );
        assertEq(
            this.exposedDecodeMarkQualified(
                BridgeMsgCodec.encodeMarkQualified(20260212, MarkBatchLib.one("20260212-TRY-U"))
            ),
            bytes14("20260212-TRY-U"),
            "markQualified"
        );
    }

    // --- outbound encoders cap payload arrays at MAX_PAYLOAD_ARRAY_LEN ---

    function test_EncodeBidsBatch_AtCap_Encodes() public pure {
        uint16 n = BridgeMsgCodec.MAX_PAYLOAD_ARRAY_LEN; // 64
        bytes memory encoded = BridgeMsgCodec.encodeBidsBatch(1, 30101, 1, 0, 1, new address[](n), new uint256[](n));
        assertEq(uint8(encoded[1]), BridgeMsgCodec.MSG_BIDS_BATCH);
    }

    function test_EncodeBidsBatch_OverCap_Reverts() public {
        uint16 n = BridgeMsgCodec.MAX_PAYLOAD_ARRAY_LEN + 1;
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.PayloadArrayTooLong.selector, uint256(n), BridgeMsgCodec.MAX_PAYLOAD_ARRAY_LEN
            )
        );
        this.exposedEncodeBidsBatch(n);
    }

    function test_EncodeRefund_OverCap_Reverts() public {
        uint16 n = BridgeMsgCodec.MAX_PAYLOAD_ARRAY_LEN + 1;
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.PayloadArrayTooLong.selector, uint256(n), BridgeMsgCodec.MAX_PAYLOAD_ARRAY_LEN
            )
        );
        this.exposedEncodeRefund(n);
    }

    function test_EncodeIssuance_OverCap_Reverts() public {
        uint16 n = BridgeMsgCodec.MAX_RECIPIENTS_PER_ISSUANCE + 1;
        // The cap is now on the recipients a whole message carries, however many series they are
        // spread over, so it reports the message's total rather than one array's length.
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.IssuanceBatchTooLarge.selector,
                uint256(n),
                uint256(BridgeMsgCodec.MAX_RECIPIENTS_PER_ISSUANCE)
            )
        );
        this.exposedEncodeIssuance(n);
    }

    /// @dev decodeRefundInstructions enforces a symmetric inbound cap so a peer compromise or a
    ///      future encoder change cannot deliver an oversized REFUND that exhausts the receiver's
    ///      gas in the per-bidder loop. Built by hand to bypass the now-capping encoder.
    function test_DecodeRefund_OverOutboundCap_RevertsRefundBatchTooLarge() public {
        uint256 n = uint256(BridgeMsgCodec.MAX_PAYLOAD_ARRAY_LEN) + 1; // 65, over the outbound cap
        bytes memory overCap = abi.encodePacked(
            BridgeMsgCodec.BODY_VERSION_V1,
            BridgeMsgCodec.MSG_REFUND_INSTRUCTIONS,
            abi.encode(uint32(1), uint16(0), uint16(1), new address[](n), new uint128[](n), new uint128[](n))
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.RefundBatchTooLarge.selector, n, uint256(BridgeMsgCodec.MAX_PAYLOAD_ARRAY_LEN)
            )
        );
        this.exposedDecodeRefundInstructions(overCap);
    }

    // --- Real payload-length ceiling vs the ERC-7786 message-size cap ---

    /// @notice The send-side `maxMessageSize` the bridge configures for these pathways. A send whose
    ///         encoded message exceeds this reverts on the source chain. This is the *byte*
    ///         ceiling only; destination gas (the per-item crosschainMint loop) is a separate and,
    ///         for the heavy paths, tighter limit - not measured here.
    uint256 internal constant MAX_MESSAGE_BYTES = 10_000;

    /// @dev Derives the largest array length whose encoded message still fits under
    ///      `MAX_MESSAGE_BYTES`, by measuring the actual per-item byte cost, and asserts
    ///      `MAX_PAYLOAD_ARRAY_LEN` sits under it. Regression guard: if a payload grows
    ///      (e.g. a new array/field), the real ceiling drops and this fails if the cap loses
    ///      headroom. `len0/len1/len2` are encoded lengths at 0/1/2 items.
    function _deriveCeilingAndAssertHeadroom(string memory label, uint256 len0, uint256 len1, uint256 len2) internal {
        uint256 perItem = len1 - len0;
        assertEq(len2 - len1, perItem, string.concat(label, ": per-item byte cost is not linear"));
        uint256 derivedMaxItems = (MAX_MESSAGE_BYTES - len0) / perItem;
        emit log_named_uint(string.concat(label, " bytes/item"), perItem);
        emit log_named_uint(string.concat(label, " real max items @ 10000B"), derivedMaxItems);
        assertGe(
            derivedMaxItems,
            BridgeMsgCodec.MAX_PAYLOAD_ARRAY_LEN,
            string.concat(label, ": MAX_PAYLOAD_ARRAY_LEN exceeds the real byte ceiling")
        );
    }

    /// @notice Computes the real per-message array ceiling under the bridge byte cap and proves the
    ///         single system-wide `MAX_PAYLOAD_ARRAY_LEN = 64` clears every one of them. Run with
    ///         `-vv` to see the derived numbers (bids is the tightest at ~128 B/item).
    function test_RealPayloadByteCeiling_ClearsTheCap() public {
        _deriveCeilingAndAssertHeadroom(
            "bids",
            this.exposedEncodeBidsBatch(0).length,
            this.exposedEncodeBidsBatch(1).length,
            this.exposedEncodeBidsBatch(2).length
        );
        _deriveCeilingAndAssertHeadroom(
            "refund",
            this.exposedEncodeRefund(0).length,
            this.exposedEncodeRefund(1).length,
            this.exposedEncodeRefund(2).length
        );
        _deriveCeilingAndAssertHeadroom(
            "issuance",
            this.exposedEncodeIssuance(0).length,
            this.exposedEncodeIssuance(1).length,
            this.exposedEncodeIssuance(2).length
        );
    }

    // --- External wrappers ---

    function exposedDecodeAuctionStageClearing(bytes calldata p) external pure returns (uint32) {
        return BridgeMsgCodec.decodeAuctionStageClearing(p);
    }

    function exposedDecodeAuctionResult(bytes calldata p) external pure returns (uint32, uint32, uint64, uint32) {
        return BridgeMsgCodec.decodeAuctionResult(p);
    }

    function exposedEncodeMarkCalled(uint32 day, bytes14[] calldata ids) external pure returns (bytes memory) {
        return BridgeMsgCodec.encodeMarkCalled(day, CALLED_AT, ids);
    }

    function exposedEncodeMarkQualified(uint32 day, bytes14[] calldata ids) external pure returns (bytes memory) {
        return BridgeMsgCodec.encodeMarkQualified(day, ids);
    }

    function exposedDecodeMarkCalled(bytes calldata p) external pure returns (bytes14) {
        (,, bytes14[] memory seriesIds) = BridgeMsgCodec.decodeMarkCalled(p);
        return seriesIds[0];
    }

    function exposedDecodeMarkQualified(bytes calldata p) external pure returns (bytes14) {
        (, bytes14[] memory seriesIds) = BridgeMsgCodec.decodeMarkQualified(p);
        return seriesIds[0];
    }

    function exposedDecodeRefundInstructions(bytes calldata p)
        external
        pure
        returns (uint32, uint16, uint16, address[] memory, uint128[] memory, uint128[] memory)
    {
        return BridgeMsgCodec.decodeRefundInstructions(p);
    }

    function exposedEncodeBidsBatch(uint16 n) external pure returns (bytes memory) {
        return BridgeMsgCodec.encodeBidsBatch(1, 30101, 1, 0, 1, new address[](n), new uint256[](n));
    }

    function exposedEncodeRefund(uint16 n) external pure returns (bytes memory) {
        return BridgeMsgCodec.encodeRefundInstructions(1, 0, 1, new address[](n), new uint128[](n), new uint128[](n));
    }

    function exposedEncodeIssuance(uint16 n) external pure returns (bytes memory) {
        BridgeMsgCodec.IssuanceInstructionsPayload memory payload;
        payload.seriesId = "20260212-TRY-U";
        payload.recipients = new address[](n);
        payload.quantities = new uint256[](n);
        return BridgeMsgCodec.encodeIssuanceInstructions(0, 0, 1, IssuanceBatchLib.one(payload));
    }
}
