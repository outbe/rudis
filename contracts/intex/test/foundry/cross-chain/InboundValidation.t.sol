// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {BidPackLib} from "../helpers/BidPackLib.sol";
import {CrossChainTest} from "../helpers/CrossChainTest.sol";

import {TargetRouter} from "@contracts/target/TargetRouter.sol";
import {OriginRouter} from "@contracts/origin/OriginRouter.sol";
import {IntexNFT1155Bridge} from "@contracts/shared/IntexNFT1155Bridge.sol";
import {IOriginRouter} from "@contracts/origin/interfaces/IOriginRouter.sol";
import {BridgeMsgCodec} from "@contracts/shared/libs/BridgeMsgCodec.sol";
import {InboundReason} from "@contracts/shared/libs/InboundReason.sol";
import {ERC7786MessengerBase} from "@contracts/shared/ERC7786MessengerBase.sol";
import {IntexNFT1155BridgeCodec} from "@contracts/shared/libs/IntexNFT1155BridgeCodec.sol";
import {IIntexNFT1155Bridge} from "@contracts/shared/interfaces/IIntexNFT1155Bridge.sol";

import {IntexAuction} from "@contracts/target/IntexAuction.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";
import {MockDesis} from "@test-mocks/MockDesis.sol";

/// @title InboundValidationTest
/// @notice Inbound validation over the ERC-7786 bridge: a malformed/unknown payload no longer advances a lane
///         silently - the router/adapter reverts with a typed error, the bridge rolls back, and the transport
///         redelivers. Each case asserts the exact typed revert propagates out of `bridge.deliverAs`.
/// @dev Delivery goes through the loopback bridge as the authenticated peer, so the peer table + bridge gate are
///      honored and the payload is the only thing under test - exactly what we want for validation coverage.
contract InboundValidationTest is CrossChainTest {
    uint32 internal constant BNB_CHAIN_ID = 1;
    uint32 internal constant OUTBE_CHAIN_ID = 2;

    TargetRouter internal bnbRouter;
    OriginRouter internal outbeRouter;
    IntexNFT1155Bridge internal nftBridgeBnb;
    IntexNFT1155Bridge internal nftBridgeOutbe;

    IntexAuction internal auction;
    IntexNFT1155 internal intex;
    address internal desis;
    address internal intexFactory;
    address internal admin = address(this);

    function setUp() public {
        _setUpBridge();

        desis = address(new MockDesis());
        intexFactory = makeAddr("factory");
        auction = DeployProxy.intexAuction(admin, admin);
        intex = DeployProxy.intexNFT1155(admin, admin);

        bnbRouter = DeployProxy.targetRouter(address(bridge), admin, OUTBE_CHAIN_ID);
        outbeRouter = DeployProxy.originRouter(address(bridge), admin);
        nftBridgeBnb = DeployProxy.intexNFT1155Bridge(address(intex), address(bridge), admin);

        IntexNFT1155 intexOutbe = DeployProxy.intexNFT1155(admin, admin);
        nftBridgeOutbe = DeployProxy.intexNFT1155Bridge(address(intexOutbe), address(bridge), admin);

        // Register remote messengers so inbound peer authentication passes and the payload is what fails.
        bnbRouter.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, address(outbeRouter)));
        outbeRouter.setRemoteMessenger(BNB_CHAIN_ID, _interop(BNB_CHAIN_ID, address(bnbRouter)));
        nftBridgeBnb.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, address(nftBridgeOutbe)));

        bnbRouter.wire(address(auction), address(intex), admin);
        outbeRouter.wire(desis, intexFactory);
    }

    // ---------------------------------------------------------------
    // TargetRouter - BridgeMsgCodec validation
    // ---------------------------------------------------------------

    function test_TM_TooShortPayload_RevertsInvalidPayloadLength() public {
        // Only the bodyVersion byte - header itself is shorter than 2.
        bytes memory packet = hex"01";
        vm.expectRevert(abi.encodeWithSelector(BridgeMsgCodec.InvalidPayloadLength.selector, 0, 1, 2));
        _deliver(OUTBE_CHAIN_ID, address(outbeRouter), address(bnbRouter), packet);
    }

    function test_TM_UnknownMsgType_RevertsUnknownMsgType() public {
        // Header is well-formed (version=1, msgType=0xFE) but msgType is not in TM's accepted set.
        bytes memory packet = hex"01FE";
        vm.expectRevert(abi.encodeWithSelector(BridgeMsgCodec.UnknownMsgType.selector, 0xFE));
        _deliver(OUTBE_CHAIN_ID, address(outbeRouter), address(bnbRouter), packet);
    }

    function test_TM_ShortMarkCalled_RevertsInvalidPayloadLength() public {
        // MARK_CALLED min length = 6 (bodyVersion + msgType + seriesId(4)). Build a 5-byte packet.
        uint24 truncatedSeriesId = 20_250;
        bytes memory packet =
            abi.encodePacked(BridgeMsgCodec.BODY_VERSION_V1, BridgeMsgCodec.MSG_MARK_CALLED, truncatedSeriesId);
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.InvalidPayloadLength.selector,
                BridgeMsgCodec.MSG_MARK_CALLED,
                5,
                BridgeMsgCodec.MIN_LEN_MARK_CALLED
            )
        );
        _deliver(OUTBE_CHAIN_ID, address(outbeRouter), address(bnbRouter), packet);
    }

    function test_TM_ShortRefundInstructions_RevertsInvalidPayloadLength() public {
        // REFUND_INSTRUCTIONS carries three ABI-encoded arrays; its minimum (HEADER_LEN + 224)
        // pins the empty-arrays floor. Send one byte under it to trip the per-type length check.
        uint256 minLen = BridgeMsgCodec.MIN_LEN_REFUND_INSTRUCTIONS;
        bytes memory packet = abi.encodePacked(
            BridgeMsgCodec.BODY_VERSION_V1, BridgeMsgCodec.MSG_REFUND_INSTRUCTIONS, new bytes(minLen - 3)
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.InvalidPayloadLength.selector, BridgeMsgCodec.MSG_REFUND_INSTRUCTIONS, minLen - 1, minLen
            )
        );
        _deliver(OUTBE_CHAIN_ID, address(outbeRouter), address(bnbRouter), packet);
    }

    function test_TM_ShortIssuanceInstructions_RevertsInvalidPayloadLength() public {
        // ISSUANCE_INSTRUCTIONS has the largest minimum (HEADER_LEN + 544): a struct with two
        // arrays. One byte under the floor must trip the per-type length check.
        uint256 minLen = BridgeMsgCodec.MIN_LEN_ISSUANCE_INSTRUCTIONS;
        bytes memory packet = abi.encodePacked(
            BridgeMsgCodec.BODY_VERSION_V1, BridgeMsgCodec.MSG_ISSUANCE_INSTRUCTIONS, new bytes(minLen - 3)
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.InvalidPayloadLength.selector,
                BridgeMsgCodec.MSG_ISSUANCE_INSTRUCTIONS,
                minLen - 1,
                minLen
            )
        );
        _deliver(OUTBE_CHAIN_ID, address(outbeRouter), address(bnbRouter), packet);
    }

    function test_TM_RefundArrayLengthMismatch_Reverts() public {
        // REFUND_INSTRUCTIONS with parallel arrays of unequal length must revert a typed error,
        // not panic out-of-bounds inside the handler.
        address[] memory bidders = new address[](2);
        bidders[0] = address(0xB1);
        bidders[1] = address(0xB2);
        uint64[] memory refundedAmounts = new uint64[](1); // mismatch: 1 vs 2
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
        _deliver(OUTBE_CHAIN_ID, address(outbeRouter), address(bnbRouter), packet);
    }

    // ---------------------------------------------------------------
    // OriginRouter - body-srcChainId cross-check + msgType
    // ---------------------------------------------------------------

    function test_OM_UnknownMsgType_RevertsUnknownMsgType() public {
        // Pick a msgType the codec itself does not know - `minLengthFor` returns 0 so the
        // per-type length assertion is a no-op, and the OM dispatch else-branch raises `UnknownMsgType(0xFE)`.
        bytes memory packet = hex"01FE";
        vm.expectRevert(abi.encodeWithSelector(BridgeMsgCodec.UnknownMsgType.selector, 0xFE));
        _deliver(BNB_CHAIN_ID, address(bnbRouter), address(outbeRouter), packet);
    }

    /// @notice Reverse of the previous test: a msgType that the codec knows but OM does not accept
    ///         (e.g. MARK_CALLED) fails the length assertion first because the codec's
    ///         `minLengthFor(MARK_CALLED)` is a whole batch body, and our 2-byte packet trips `InvalidPayloadLength` before
    ///         the else-branch is reached. This pins the order: length is asserted before the msgType-set check.
    function test_OM_CodecKnownButHandlerUnknown_RevertsInvalidPayloadLength() public {
        bytes memory packet = hex"0108"; // bodyVersion + MARK_CALLED (8): codec-known, OM doesn't accept
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.InvalidPayloadLength.selector,
                BridgeMsgCodec.MSG_MARK_CALLED,
                2,
                BridgeMsgCodec.MIN_LEN_MARK_CALLED
            )
        );
        _deliver(BNB_CHAIN_ID, address(bnbRouter), address(outbeRouter), packet);
    }

    function test_OM_BodySrcChainIdMismatch_IsAcknowledgedAsAConflict() public {
        // Build a well-formed BIDS_BATCH whose body-srcChainId (0xDEAD) disagrees with the
        // authenticated source chainId (BNB_CHAIN_ID = 1): never acceptable, so acknowledged, not retried.
        bytes memory packet = BridgeMsgCodec.encodeBidsBatch(42, 0xDEAD, 1, 0, 1, new address[](0), new uint256[](0));
        vm.expectEmit(true, true, true, true, address(outbeRouter));
        emit IOriginRouter.InboundMessageIgnored(
            BNB_CHAIN_ID,
            BridgeMsgCodec.MSG_BIDS_BATCH,
            bytes32((uint256(42) << 32) | BNB_CHAIN_ID),
            InboundReason.CONFLICT
        );
        _deliver(BNB_CHAIN_ID, address(bnbRouter), address(outbeRouter), packet);
    }

    function test_OM_ShortBidsBatch_RevertsInvalidPayloadLength() public {
        // Empty-arrays BIDS_BATCH. Send a one-byte-short packet (truncate the last byte of the trailing
        // length word) to trip the per-type minimum-length check.
        bytes memory full =
            BridgeMsgCodec.encodeBidsBatch(42, BNB_CHAIN_ID, 1, 0, 1, new address[](0), new uint256[](0));
        bytes memory truncated = new bytes(full.length - 1);
        for (uint256 i = 0; i < truncated.length; i++) {
            truncated[i] = full[i];
        }
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.InvalidPayloadLength.selector,
                BridgeMsgCodec.MSG_BIDS_BATCH,
                full.length - 1,
                full.length
            )
        );
        _deliver(BNB_CHAIN_ID, address(bnbRouter), address(outbeRouter), truncated);
    }

    function test_OM_BidsBatchTooLarge_Reverts() public {
        // A batch above MAX_BIDS_BATCH is rejected on decode before it can be dispatched.
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
        // Hand-build the over-cap payload: the outbound encoder caps at MAX_PAYLOAD_ARRAY_LEN (64),
        // so encodeBidsBatch can no longer produce an over-cap batch. Such a message can therefore only
        // reach the inbound handler via a trusted-peer bug - exactly the case the inbound BidsBatchTooLarge
        // decode guard exists to reject.
        bytes memory packet = abi.encodePacked(
            BridgeMsgCodec.BODY_VERSION_V1,
            BridgeMsgCodec.MSG_BIDS_BATCH,
            abi.encode(
                uint32(42), BNB_CHAIN_ID, uint32(1), uint16(0), uint16(1), bidders, quantities, rates, timestamps
            )
        );
        vm.expectRevert(
            abi.encodeWithSelector(BridgeMsgCodec.BidsBatchTooLarge.selector, n, BridgeMsgCodec.MAX_BIDS_BATCH)
        );
        _deliver(BNB_CHAIN_ID, address(bnbRouter), address(outbeRouter), packet);
    }

    // ---------------------------------------------------------------
    // OriginRouter.wire() - Desis interface probe
    // ---------------------------------------------------------------

    function test_OM_Wire_EOA_RevertsInvalidDesisInterface() public {
        OriginRouter fresh = DeployProxy.originRouter(address(bridge), admin);
        vm.expectRevert(abi.encodeWithSelector(IOriginRouter.InvalidDesisInterface.selector, address(0xBEEF)));
        fresh.wire(address(0xBEEF), intexFactory);
    }

    function test_OM_Wire_NonIDesisContract_RevertsInvalidDesisInterface() public {
        // IntexAuction is a contract but does not advertise IDesis via ERC-165.
        OriginRouter fresh = DeployProxy.originRouter(address(bridge), admin);
        vm.expectRevert(abi.encodeWithSelector(IOriginRouter.InvalidDesisInterface.selector, address(auction)));
        fresh.wire(address(auction), intexFactory);
    }

    function test_OM_Wire_MockContracts_Succeeds() public {
        OriginRouter fresh = DeployProxy.originRouter(address(bridge), admin);
        address newDesis = address(new MockDesis());
        address newFactory = makeAddr("newFactory");
        fresh.wire(newDesis, newFactory);
        assertEq(fresh.desis(), newDesis);
        assertEq(fresh.intexFactory(), newFactory);
        assertTrue(fresh.hasRole(fresh.DESIS_ROLE(), newDesis));
        assertTrue(fresh.hasRole(fresh.INTEX_FACTORY_ROLE(), newFactory));
    }

    // ---------------------------------------------------------------
    // IntexNFT1155Bridge - V2 codec: version + length + size + msgType + address validation
    // ---------------------------------------------------------------

    function test_NFTBatch_UnknownMsgType_RevertsUnknownMsgType() public {
        // Valid V2 version byte, unknown msgType 0x99 - routing rejects it.
        bytes memory packet = hex"0299";
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155Bridge.UnknownMsgType.selector, 0x99));
        _deliverToBatch(packet);
    }

    function test_NFTBatch_StaleV1Version_RevertsUnsupportedBodyVersion() public {
        // A pre-migration V1 packet must fail closed rather than misdecode into a wrong crosschainMint.
        bytes memory packet = _batchV2(address(0xCAFE), 1, 100);
        packet[0] = bytes1(uint8(1)); // downgrade the version byte to stale V1
        vm.expectRevert(abi.encodeWithSelector(IntexNFT1155BridgeCodec.UnsupportedBodyVersion.selector, uint8(1)));
        _deliverToBatch(packet);
    }

    function test_NFTBatch_ShortHeader_RevertsInvalidPayloadLength() public {
        // A packet shorter than the [version][msgType] header cannot even be routed.
        bytes memory packet = hex"02";
        vm.expectRevert(abi.encodeWithSelector(IntexNFT1155BridgeCodec.InvalidPayloadLength.selector, 1, 2));
        _deliverToBatch(packet);
    }

    function test_NFTBatch_TruncatedBody_Reverts() public {
        // Valid header but the abi.encode body is truncated - abi.decode rejects it (no misread).
        bytes memory packet =
            abi.encodePacked(IntexNFT1155BridgeCodec.BODY_VERSION_V2, IntexNFT1155BridgeCodec.SEND, hex"deadbeef");
        vm.expectRevert();
        _deliverToBatch(packet);
    }

    function test_NFTBatch_OverCap_RevertsBatchTooLarge() public {
        // Inbound decoded array length is capped at MAX_BATCH_SIZE.
        uint256 over = IntexNFT1155BridgeCodec.MAX_BATCH_SIZE + 1;
        uint256[] memory tokenIds = new uint256[](over);
        uint256[] memory amounts = new uint256[](over);
        bytes memory packet = IntexNFT1155BridgeCodec.encodeBatch(
            IntexNFT1155BridgeCodec.BatchPayload({
                to: bytes32(uint256(uint160(address(0xCAFE)))), tokenIds: tokenIds, amounts: amounts
            })
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                IntexNFT1155BridgeCodec.BatchTooLarge.selector, over, IntexNFT1155BridgeCodec.MAX_BATCH_SIZE
            )
        );
        _deliverToBatch(packet);
    }

    function test_NFTBatch_ZeroRecipient_RevertsInvalidReceiver() public {
        // An all-zero recipient passes the high-bit check but is explicitly rejected.
        bytes32[] memory recipients = new bytes32[](1);
        recipients[0] = bytes32(0);
        uint256[] memory tokenIds = new uint256[](1);
        tokenIds[0] = 1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100;
        bytes memory packet = IntexNFT1155BridgeCodec.encodeMulti(
            IntexNFT1155BridgeCodec.MultiPayload({recipients: recipients, tokenIds: tokenIds, amounts: amounts})
        );
        vm.expectRevert(IIntexNFT1155Bridge.InvalidReceiver.selector);
        _deliverToBatch(packet);
    }

    function test_NFTBatch_MalformedTo_RevertsMalformedAddress() public {
        // A `to` with non-zero high bits is rejected before any crosschainMint (empty item arrays).
        bytes32 badTo = bytes32(uint256(1) << 200);
        bytes memory packet = abi.encodePacked(
            IntexNFT1155BridgeCodec.BODY_VERSION_V2,
            IntexNFT1155BridgeCodec.SEND,
            abi.encode(
                IntexNFT1155BridgeCodec.BatchPayload({to: badTo, tokenIds: new uint256[](0), amounts: new uint256[](0)})
            )
        );
        vm.expectRevert(abi.encodeWithSelector(IntexNFT1155BridgeCodec.MalformedAddress.selector, badTo));
        _deliverToBatch(packet);
    }

    function test_NFTBatch_MalformedRecipient_RevertsMalformedAddress() public {
        // SEND_MULTI with one malformed recipient (non-zero high bits).
        bytes32 badRecipient = bytes32(uint256(1) << 200);
        bytes32[] memory recipients = new bytes32[](1);
        recipients[0] = badRecipient;
        uint256[] memory tokenIds = new uint256[](1);
        tokenIds[0] = 1;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 100;
        bytes memory packet = IntexNFT1155BridgeCodec.encodeMulti(
            IntexNFT1155BridgeCodec.MultiPayload({recipients: recipients, tokenIds: tokenIds, amounts: amounts})
        );
        vm.expectRevert(abi.encodeWithSelector(IntexNFT1155BridgeCodec.MalformedAddress.selector, badRecipient));
        _deliverToBatch(packet);
    }

    function test_NFTBatch_ZeroTo_RevertsInvalidReceiver() public {
        // SEND branch parity to the SEND_MULTI ZeroRecipient test: assertAddress passes for
        // bytes32(0), so the explicit `if (p.to == bytes32(0))` reject is what stops the crosschainMint.
        bytes memory packet = abi.encodePacked(
            IntexNFT1155BridgeCodec.BODY_VERSION_V2,
            IntexNFT1155BridgeCodec.SEND,
            abi.encode(
                IntexNFT1155BridgeCodec.BatchPayload({
                    to: bytes32(0), tokenIds: new uint256[](0), amounts: new uint256[](0)
                })
            )
        );
        vm.expectRevert(IIntexNFT1155Bridge.InvalidReceiver.selector);
        _deliverToBatch(packet);
    }

    function test_NFTBatch_MultiOverCap_RevertsBatchTooLarge() public {
        // SEND_MULTI cap parity to the SEND OverCap test - decodeMulti rejects oversize arrays
        // before the per-item loop touches any recipient or crosschainMint.
        uint256 over = IntexNFT1155BridgeCodec.MAX_BATCH_SIZE + 1;
        bytes32[] memory recipients = new bytes32[](over);
        uint256[] memory tokenIds = new uint256[](over);
        uint256[] memory amounts = new uint256[](over);
        bytes memory packet = IntexNFT1155BridgeCodec.encodeMulti(
            IntexNFT1155BridgeCodec.MultiPayload({recipients: recipients, tokenIds: tokenIds, amounts: amounts})
        );
        vm.expectRevert(
            abi.encodeWithSelector(
                IntexNFT1155BridgeCodec.BatchTooLarge.selector, over, IntexNFT1155BridgeCodec.MAX_BATCH_SIZE
            )
        );
        _deliverToBatch(packet);
    }

    function test_NFTBatch_MultiArrayMismatch_RevertsArrayLengthMismatch() public {
        // SEND_MULTI array-length mismatch propagates the codec revert through dispatch.
        // recipients.length != tokenIds.length is enough to trip decodeMulti's guard.
        bytes32[] memory recipients = new bytes32[](2);
        recipients[0] = bytes32(uint256(uint160(address(0xCAFE))));
        recipients[1] = bytes32(uint256(uint160(address(0xBEEF))));
        uint256[] memory tokenIds = new uint256[](1);
        tokenIds[0] = 1;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 10;
        amounts[1] = 20;
        bytes memory packet = abi.encodePacked(
            IntexNFT1155BridgeCodec.BODY_VERSION_V2,
            IntexNFT1155BridgeCodec.SEND_MULTI,
            abi.encode(
                IntexNFT1155BridgeCodec.MultiPayload({recipients: recipients, tokenIds: tokenIds, amounts: amounts})
            )
        );
        vm.expectRevert(IntexNFT1155BridgeCodec.ArrayLengthMismatch.selector);
        _deliverToBatch(packet);
    }

    // --- Helpers ---

    /// @dev Deliver a batch packet to `nftBridgeBnb` from its wired peer on OUTBE_CHAIN_ID.
    function _deliverToBatch(bytes memory packet) internal {
        _deliver(OUTBE_CHAIN_ID, address(nftBridgeOutbe), address(nftBridgeBnb), packet);
    }

    /// @dev Build a one-item V2 SEND packet for a single recipient.
    function _batchV2(address to, uint256 tokenId_, uint256 amount_) internal pure returns (bytes memory) {
        uint256[] memory tokenIds = new uint256[](1);
        tokenIds[0] = tokenId_;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = amount_;
        return IntexNFT1155BridgeCodec.encodeBatch(
            IntexNFT1155BridgeCodec.BatchPayload({
                to: bytes32(uint256(uint160(to))), tokenIds: tokenIds, amounts: amounts
            })
        );
    }
}
