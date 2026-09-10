// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.28;

import {BidPackLib} from "../helpers/BidPackLib.sol";
import {Test} from "forge-std/Test.sol";
import {BridgeMsgCodec} from "@contracts/shared/libs/BridgeMsgCodec.sol";
import {IssuanceBatchLib} from "../helpers/IssuanceBatch.sol";

/// @dev Thin external wrapper around the `internal pure` encoders so the per-encoder revert paths
///      can be asserted via `vm.expectRevert` from a test contract.
contract BridgeMsgCodecHardeningHarness {
    function encodeBidsBatch(
        uint32 worldwideDay,
        uint32 srcChainId,
        uint32 relayGeneration,
        uint16 batchIndex,
        uint16 totalBatches,
        address[] calldata bidders,
        uint256[] calldata packedBids
    ) external pure returns (bytes memory) {
        return BridgeMsgCodec.encodeBidsBatch(
            worldwideDay, srcChainId, relayGeneration, batchIndex, totalBatches, bidders, packedBids
        );
    }

    function encodeIssuanceInstructions(BridgeMsgCodec.IssuanceInstructionsPayload[] calldata series)
        external
        pure
        returns (bytes memory)
    {
        return BridgeMsgCodec.encodeIssuanceInstructions(series[0].worldwideDay, 0, 1, series);
    }

    function encodeIssuanceInstructions2(
        uint32 worldwideDay,
        uint16 chunkIndex,
        uint16 totalChunks,
        BridgeMsgCodec.IssuanceInstructionsPayload[] calldata series
    ) external pure returns (bytes memory) {
        return BridgeMsgCodec.encodeIssuanceInstructions(worldwideDay, chunkIndex, totalChunks, series);
    }

    function encodeRefundInstructions(
        uint32 worldwideDay,
        uint16 chunkIndex,
        uint16 totalChunks,
        address[] calldata bidders,
        uint128[] calldata refundedAmounts,
        uint128[] calldata paidAmounts
    ) external pure returns (bytes memory) {
        return BridgeMsgCodec.encodeRefundInstructions(
            worldwideDay, chunkIndex, totalChunks, bidders, refundedAmounts, paidAmounts
        );
    }

    function decodeRefundInstructions(bytes calldata m)
        external
        pure
        returns (uint32, uint16, uint16, address[] memory, uint128[] memory, uint128[] memory)
    {
        return BridgeMsgCodec.decodeRefundInstructions(m);
    }

    function decodeBidsBatch(bytes calldata m)
        external
        pure
        returns (uint32, uint32, uint32, uint16, uint16, address[] memory, uint256[] memory)
    {
        return BridgeMsgCodec.decodeBidsBatch(m);
    }

    function decodeIssuanceInstructions(bytes calldata m)
        external
        pure
        returns (BridgeMsgCodec.IssuanceInstructionsPayload[] memory series)
    {
        (,,, series) = BridgeMsgCodec.decodeIssuanceInstructions(m);
    }
}

/// @dev Defence-in-depth assertions on `BridgeMsgCodec`: encoder-side parallel-array equality
///      checks, inbound `decodeRefundInstructions` cap, and typed `InvalidPayloadLength` on
///      empty-payload entry to the three variable-length decoders.
contract BridgeMsgCodecHardeningTest is Test {
    BridgeMsgCodecHardeningHarness internal harness;

    function setUp() public {
        harness = new BridgeMsgCodecHardeningHarness();
    }

    // --- Encoder parallel-array equality ---

    function test_encodeBidsBatch_arrayLengthMismatch_reverts() public {
        // Decoder rejects parallel-array mismatch; the encoder must surface the same typed error
        // at the source so the bridge send is aborted before paying the fee.
        address[] memory bidders = new address[](2);
        bidders[0] = address(0xB1);
        bidders[1] = address(0xB2);
        uint16[] memory quantities = new uint16[](1); // one short
        quantities[0] = 1;
        uint32[] memory rates = new uint32[](2);
        uint32[] memory timestamps = new uint32[](2);

        vm.expectRevert(abi.encodeWithSelector(BridgeMsgCodec.BidsArrayLengthMismatch.selector, uint256(2), uint256(1)));
        harness.encodeBidsBatch(1, 1, 1, 0, 1, bidders, BidPackLib.pack(quantities, rates, timestamps));
    }

    function test_encodeIssuanceInstructions_arrayLengthMismatch_reverts() public {
        // recipients.length must match quantities.length; encoder reverts before encoding.
        address[] memory recipients = new address[](2);
        recipients[0] = address(0xA1);
        recipients[1] = address(0xA2);
        uint256[] memory quantities = new uint256[](1);
        quantities[0] = 1;

        BridgeMsgCodec.IssuanceInstructionsPayload memory payload = BridgeMsgCodec.IssuanceInstructionsPayload({
            seriesId: "20260212-TRY-U",
            worldwideDay: 2,
            issuedIntexCount: 1,
            promisLoadMinor: 1,
            entryPriceMinor: 1,
            floorPriceMinor: 1,
            callNoticePeriod: 0,
            issuanceCurrency: 840,
            referenceCurrency: 840,
            callWindow: 0,
            callThreshold: 0,
            callPriceMinor: 0,
            recipients: recipients,
            quantities: quantities
        });
        vm.expectRevert(
            abi.encodeWithSelector(BridgeMsgCodec.IssuanceArrayLengthMismatch.selector, uint256(2), uint256(1))
        );
        harness.encodeIssuanceInstructions(IssuanceBatchLib.one(payload));
    }

    function test_encodeIssuanceInstructions_dayMismatch_reverts() public {
        BridgeMsgCodec.IssuanceInstructionsPayload memory payload;
        payload.seriesId = "20260212-TRY-U";
        payload.worldwideDay = 20_260_212;
        payload.recipients = new address[](0);
        payload.quantities = new uint256[](0);
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.IssuanceDayMismatch.selector, payload.seriesId, uint32(20_260_212), uint32(20_260_213)
            )
        );
        harness.encodeIssuanceInstructions2(20_260_213, 0, 1, IssuanceBatchLib.one(payload));
    }

    function test_encodeRefundInstructions_arrayLengthMismatch_reverts() public {
        // bidders / refundedAmounts / paidAmounts must move in lockstep.
        address[] memory bidders = new address[](2);
        bidders[0] = address(0xB1);
        bidders[1] = address(0xB2);
        uint128[] memory refundedAmounts = new uint128[](1); // mismatch
        refundedAmounts[0] = 1;
        uint128[] memory paidAmounts = new uint128[](2);

        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.RefundArrayLengthMismatch.selector, uint256(2), uint256(1), uint256(2)
            )
        );
        harness.encodeRefundInstructions(1, 0, 1, bidders, refundedAmounts, paidAmounts);
    }

    // --- decodeRefundInstructions over-cap symmetric with BIDS / ISSUANCE ---

    function test_decodeRefundInstructions_overCap_revertsRefundBatchTooLarge() public {
        // The outbound encoder caps at MAX_PAYLOAD_ARRAY_LEN; an over-cap inbound payload can only
        // reach the receiver via a peer compromise or a future encoder change. The decoder must
        // reject with the typed RefundBatchTooLarge error so the drop-don't-block handler surfaces
        // a parameterized diagnostic.
        uint256 n = BridgeMsgCodec.MAX_PAYLOAD_ARRAY_LEN + 1;
        address[] memory bidders = new address[](n);
        uint128[] memory refundedAmounts = new uint128[](n);
        uint128[] memory paidAmounts = new uint128[](n);
        for (uint256 i = 0; i < n; ++i) {
            bidders[i] = address(uint160(i + 1));
            refundedAmounts[i] = 1;
            paidAmounts[i] = 0;
        }
        bytes memory packet = abi.encodePacked(
            BridgeMsgCodec.BODY_VERSION_V1,
            BridgeMsgCodec.MSG_REFUND_INSTRUCTIONS,
            abi.encode(uint32(42), uint16(0), uint16(1), bidders, refundedAmounts, paidAmounts)
        );

        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.RefundBatchTooLarge.selector, n, uint256(BridgeMsgCodec.MAX_PAYLOAD_ARRAY_LEN)
            )
        );
        harness.decodeRefundInstructions(packet);
    }

    // --- Empty-payload typed revert on the three variable-length decoders ---

    function test_decodeBidsBatch_emptyMsg_revertsInvalidPayloadLength() public {
        // The fixed-length decoders pre-check via _assertExactLength; the variable-length ones must
        // match the same pattern so an empty `_msg` yields a typed error rather than out-of-bounds
        // Panic(0x32) on `_msg[0]`.
        bytes memory empty = "";
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.InvalidPayloadLength.selector,
                BridgeMsgCodec.MSG_BIDS_BATCH,
                uint256(0),
                uint256(BridgeMsgCodec.HEADER_LEN)
            )
        );
        harness.decodeBidsBatch(empty);
    }

    function test_decodeIssuanceInstructions_emptyMsg_revertsInvalidPayloadLength() public {
        bytes memory empty = "";
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.InvalidPayloadLength.selector,
                BridgeMsgCodec.MSG_ISSUANCE_INSTRUCTIONS,
                uint256(0),
                uint256(BridgeMsgCodec.HEADER_LEN)
            )
        );
        harness.decodeIssuanceInstructions(empty);
    }

    function test_decodeRefundInstructions_emptyMsg_revertsInvalidPayloadLength() public {
        bytes memory empty = "";
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.InvalidPayloadLength.selector,
                BridgeMsgCodec.MSG_REFUND_INSTRUCTIONS,
                uint256(0),
                uint256(BridgeMsgCodec.HEADER_LEN)
            )
        );
        harness.decodeRefundInstructions(empty);
    }
}
