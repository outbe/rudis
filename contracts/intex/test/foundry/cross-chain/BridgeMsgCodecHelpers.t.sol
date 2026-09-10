// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {BridgeMsgCodec} from "@contracts/shared/libs/BridgeMsgCodec.sol";

/// @dev Thin external wrapper around `internal pure` helpers in BridgeMsgCodec so the per-helper
///      revert paths can be exercised with `vm.expectRevert` from a test contract.
contract BridgeMsgCodecHarness {
    function readHeader(bytes calldata m) external pure returns (uint8) {
        return BridgeMsgCodec.readHeader(m);
    }

    function assertMinLength(bytes calldata m, uint8 t) external pure {
        BridgeMsgCodec.assertMinLength(m, t);
    }

    function minLengthFor(uint8 t) external pure returns (uint16) {
        return BridgeMsgCodec.minLengthFor(t);
    }

    function assertAddress(bytes32 v) external pure {
        BridgeMsgCodec.assertAddress(v);
    }

    function decodeBidsBatch(bytes calldata m) external pure {
        BridgeMsgCodec.decodeBidsBatch(m);
    }

    function decodeRefundInstructions(bytes calldata m) external pure {
        BridgeMsgCodec.decodeRefundInstructions(m);
    }
}

/// @dev Library-level negative tests for `BridgeMsgCodec`. The revert paths exercised here used to
///      ride end-to-end via the now-skipped `InboundValidation.t.sol` / `InboundDropDontBlock.t.sol`
///      router tests (drop-don't-block was temporarily removed for the BSC testnet executor
///      workaround). The library still emits these reverts identically; this file pins them at the
///      library boundary so they stay asserted in CI regardless of the router-layer wrapper state.
contract BridgeMsgCodecHelpersTest is Test {
    BridgeMsgCodecHarness internal harness;

    function setUp() public {
        harness = new BridgeMsgCodecHarness();
    }

    // --- readHeader ---
    function test_readHeader_revertsOnShortHeader() public {
        // A single byte cannot carry both bodyVersion and msgType.
        bytes memory packet = hex"01";
        vm.expectRevert(
            abi.encodeWithSelector(BridgeMsgCodec.InvalidPayloadLength.selector, uint8(0), uint256(1), uint256(2))
        );
        harness.readHeader(packet);
    }

    // --- assertMinLength on variable-length payloads ---
    function test_assertMinLength_shortBidsBatch_reverts() public {
        uint16 floor = BridgeMsgCodec.MIN_LEN_BIDS_BATCH;
        bytes memory packet = new bytes(uint256(floor) - 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.InvalidPayloadLength.selector,
                BridgeMsgCodec.MSG_BIDS_BATCH,
                uint256(floor) - 1,
                uint256(floor)
            )
        );
        harness.assertMinLength(packet, BridgeMsgCodec.MSG_BIDS_BATCH);
    }

    function test_assertMinLength_shortRefundInstructions_reverts() public {
        uint16 floor = BridgeMsgCodec.MIN_LEN_REFUND_INSTRUCTIONS;
        bytes memory packet = new bytes(uint256(floor) - 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.InvalidPayloadLength.selector,
                BridgeMsgCodec.MSG_REFUND_INSTRUCTIONS,
                uint256(floor) - 1,
                uint256(floor)
            )
        );
        harness.assertMinLength(packet, BridgeMsgCodec.MSG_REFUND_INSTRUCTIONS);
    }

    function test_assertMinLength_shortIssuanceInstructions_reverts() public {
        uint16 floor = BridgeMsgCodec.MIN_LEN_ISSUANCE_INSTRUCTIONS;
        bytes memory packet = new bytes(uint256(floor) - 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.InvalidPayloadLength.selector,
                BridgeMsgCodec.MSG_ISSUANCE_INSTRUCTIONS,
                uint256(floor) - 1,
                uint256(floor)
            )
        );
        harness.assertMinLength(packet, BridgeMsgCodec.MSG_ISSUANCE_INSTRUCTIONS);
    }

    // --- assertMinLength on the fixed-width-but-variable-floor helpers ---
    function test_assertMinLength_shortMarkCalled_reverts() public {
        uint16 floor = BridgeMsgCodec.MIN_LEN_MARK_CALLED;
        bytes memory packet = new bytes(uint256(floor) - 1);
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.InvalidPayloadLength.selector,
                BridgeMsgCodec.MSG_MARK_CALLED,
                uint256(floor) - 1,
                uint256(floor)
            )
        );
        harness.assertMinLength(packet, BridgeMsgCodec.MSG_MARK_CALLED);
    }

    // --- minLengthFor: unknown msgType returns 0 (caller raises UnknownMsgType) ---
    function test_minLengthFor_unknownMsgType_returnsZero() public view {
        assertEq(harness.minLengthFor(0xFE), 0, "unknown msgType -> 0 (caller decides)");
    }

    // --- assertAddress: dirty high bits revert MalformedAddress ---
    function test_assertAddress_dirtyHighBits_revertsMalformedAddress() public {
        // High bit 161 set: cannot losslessly cast to address.
        bytes32 dirty = bytes32(uint256(1) << 161);
        vm.expectRevert(abi.encodeWithSelector(BridgeMsgCodec.MalformedAddress.selector, dirty));
        harness.assertAddress(dirty);
    }

    function test_assertAddress_cleanAddress_passes() public view {
        // Low 20 bytes only: no revert.
        harness.assertAddress(bytes32(uint256(uint160(address(0xCAFE)))));
    }

    // --- decodeBidsBatch: inbound over-cap rejected with BidsBatchTooLarge ---
    function test_decodeBidsBatch_overCap_revertsBidsBatchTooLarge() public {
        // The outbound encoder caps at MAX_PAYLOAD_ARRAY_LEN; an over-cap inbound packet can only
        // arrive via a trusted-peer bug. The decode-side guard exists to reject it.
        uint256 n = BridgeMsgCodec.MAX_BIDS_BATCH + 1;
        address[] memory bidders = new address[](n);
        uint16[] memory quantities = new uint16[](n);
        uint32[] memory rates = new uint32[](n);
        uint32[] memory timestamps = new uint32[](n);
        for (uint256 i = 0; i < n; i++) {
            bidders[i] = address(uint160(i + 1));
            quantities[i] = 1;
            rates[i] = 1;
            timestamps[i] = 1;
        }
        bytes memory packet = abi.encodePacked(
            BridgeMsgCodec.BODY_VERSION_V1,
            BridgeMsgCodec.MSG_BIDS_BATCH,
            abi.encode(uint32(42), uint32(1), uint32(1), uint16(0), uint16(1), bidders, quantities, rates, timestamps)
        );
        vm.expectRevert(
            abi.encodeWithSelector(BridgeMsgCodec.BidsBatchTooLarge.selector, n, BridgeMsgCodec.MAX_BIDS_BATCH)
        );
        harness.decodeBidsBatch(packet);
    }

    // --- decodeRefundInstructions: parallel-array length mismatch ---
    function test_decodeRefundInstructions_arrayLengthMismatch_reverts() public {
        // The decoder cross-checks that bidders / refundedAmounts / paidAmounts have equal length.
        address[] memory bidders = new address[](2);
        bidders[0] = address(0xB1);
        bidders[1] = address(0xB2);
        uint64[] memory refundedAmounts = new uint64[](1); // mismatch
        refundedAmounts[0] = 1;
        uint64[] memory paidAmounts = new uint64[](2);

        bytes memory packet = abi.encodePacked(
            BridgeMsgCodec.BODY_VERSION_V1,
            BridgeMsgCodec.MSG_REFUND_INSTRUCTIONS,
            abi.encode(uint32(42), uint16(0), uint16(1), bidders, refundedAmounts, paidAmounts)
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.RefundArrayLengthMismatch.selector, uint256(2), uint256(1), uint256(2)
            )
        );
        harness.decodeRefundInstructions(packet);
    }
}
