// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {CrossChainTest} from "../helpers/CrossChainTest.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";
import {TargetRouter} from "@contracts/target/TargetRouter.sol";
import {OriginRouter} from "@contracts/origin/OriginRouter.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {BridgeMsgCodec} from "@contracts/shared/libs/BridgeMsgCodec.sol";

/// A chain's share of a day is a set of series, carried in as few messages as the caps
/// allow; a series may span several, which create-if-absent makes safe.
contract TargetRouterIssuanceBatchTest is CrossChainTest {
    uint32 internal constant OUTBE_CHAIN_ID = 2;
    uint32 internal constant DAY = 20_250_101;

    TargetRouter internal router;
    IntexNFT1155 internal intex;
    address internal originSender = makeAddr("originSender");

    function setUp() public {
        _setUpBridge();
        intex = DeployProxy.intexNFT1155(address(this), address(this));
        router = DeployProxy.targetRouter(address(bridge), address(this), OUTBE_CHAIN_ID);

        router.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, originSender));
        router.wire(makeAddr("auction"), address(intex), makeAddr("escrow"));
        intex.grantRole(intex.RELAYER_ROLE(), address(router));
    }

    function _series(bytes14 seriesId, address[] memory recipients, uint256[] memory quantities)
        internal
        pure
        returns (BridgeMsgCodec.IssuanceInstructionsPayload memory payload)
    {
        payload.seriesId = seriesId;
        payload.worldwideDay = DAY;
        payload.issuedIntexCount = 1_000;
        payload.promisLoadMinor = 1_000;
        payload.entryPriceMinor = 100e6;
        payload.floorPriceMinor = 40e6;
        payload.issuanceCurrency = 840;
        payload.referenceCurrency = 840;
        payload.callWindow = 30;
        payload.callThreshold = 5;
        payload.callPriceMinor = 200e6;
        payload.recipients = recipients;
        payload.quantities = quantities;
    }

    function _issueTo(address recipient, uint256 quantity)
        internal
        pure
        returns (address[] memory recipients, uint256[] memory quantities)
    {
        recipients = new address[](1);
        quantities = new uint256[](1);
        recipients[0] = recipient;
        quantities[0] = quantity;
    }

    function _deliver(BridgeMsgCodec.IssuanceInstructionsPayload[] memory series) internal {
        _deliver(0, 1, series);
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

    function test_OneMessageCreatesEverySeriesItCarries() public {
        address holder = makeAddr("holder");
        (address[] memory recipients, uint256[] memory quantities) = _issueTo(holder, 7);

        BridgeMsgCodec.IssuanceInstructionsPayload[] memory series = new BridgeMsgCodec.IssuanceInstructionsPayload[](3);
        series[0] = _series("20250101-USD-U", recipients, quantities);
        series[1] = _series("20250101-EUR-E", recipients, quantities);
        series[2] = _series("20250101-TRY-U", new address[](0), new uint256[](0));

        _deliver(series);

        assertTrue(intex.seriesExists("20250101-USD-U"), "dollar series");
        assertTrue(intex.seriesExists("20250101-EUR-E"), "euro series");
        assertTrue(intex.seriesExists("20250101-TRY-U"), "series with no local winners");
        assertEq(intex.balanceOf(holder, intex.issuedTokenId("20250101-USD-U")), 7);
        assertEq(intex.balanceOf(holder, intex.issuedTokenId("20250101-EUR-E")), 7);
    }

    function test_ASeriesSplitAcrossMessagesIsCreatedOnceAndIssuesEveryPiece() public {
        address first = makeAddr("first");
        address second = makeAddr("second");

        BridgeMsgCodec.IssuanceInstructionsPayload[] memory head = new BridgeMsgCodec.IssuanceInstructionsPayload[](1);
        (address[] memory r1, uint256[] memory q1) = _issueTo(first, 4);
        head[0] = _series("20250101-USD-U", r1, q1);
        _deliver(0, 2, head);

        BridgeMsgCodec.IssuanceInstructionsPayload[] memory tail = new BridgeMsgCodec.IssuanceInstructionsPayload[](1);
        (address[] memory r2, uint256[] memory q2) = _issueTo(second, 6);
        tail[0] = _series("20250101-USD-U", r2, q2);
        // The second piece repeats the series; creating it again would revert, so the
        // receiver must recognise that it already exists.
        _deliver(1, 2, tail);

        uint256 tokenId = intex.issuedTokenId("20250101-USD-U");
        assertEq(intex.balanceOf(first, tokenId), 4, "first piece minted");
        assertEq(intex.balanceOf(second, tokenId), 6, "second piece minted");
    }

    function test_AFullMessageStaysUnderTheSendCeiling() public pure {
        // The caps are counts, not bytes, so pin that the worst case they admit - every
        // series slot filled, every recipient slot filled - still fits the wire.
        uint256 seriesCount = BridgeMsgCodec.MAX_SERIES_PER_ISSUANCE;
        uint256 perSeries = BridgeMsgCodec.MAX_RECIPIENTS_PER_ISSUANCE / seriesCount;

        BridgeMsgCodec.IssuanceInstructionsPayload[] memory series =
            new BridgeMsgCodec.IssuanceInstructionsPayload[](seriesCount);
        for (uint256 s = 0; s < seriesCount; s++) {
            address[] memory recipients = new address[](perSeries);
            uint256[] memory quantities = new uint256[](perSeries);
            for (uint256 i = 0; i < perSeries; i++) {
                recipients[i] = address(uint160(1 + s * perSeries + i));
                quantities[i] = 1;
            }
            series[s] = _series(bytes14(uint112(uint256(0x3230323530313031) + s)), recipients, quantities);
        }

        uint256 encoded = BridgeMsgCodec.encodeIssuanceInstructions(DAY, 0, 1, series).length;
        assertLt(encoded, 10_000, "a full message must fit the bridge send ceiling");
    }
}
