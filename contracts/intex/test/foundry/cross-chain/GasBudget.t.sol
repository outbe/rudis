// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {CrossChainTest} from "../helpers/CrossChainTest.sol";

import {TargetRouter} from "@contracts/target/TargetRouter.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {IIntexNFT1155} from "@contracts/shared/interfaces/IIntexNFT1155.sol";
import {BridgeMsgCodec} from "@contracts/shared/libs/BridgeMsgCodec.sol";
import {IntexGas} from "@contracts/shared/libs/IntexGas.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";
import {CreateSeriesLib} from "../helpers/CreateSeriesLib.sol";
import {MarkBatchLib} from "../helpers/MarkBatchLib.sol";
import {IssuanceBatchLib} from "../helpers/IssuanceBatch.sol";
import {IntexNFT1155Bridge} from "@contracts/shared/IntexNFT1155Bridge.sol";
import {MultiRecipientSendParam} from "@contracts/shared/interfaces/IIntexNFT1155Bridge.sol";
import {IntexNFT1155BridgeCodec} from "@contracts/shared/libs/IntexNFT1155BridgeCodec.sol";
import {OriginRouter} from "@contracts/origin/OriginRouter.sol";
import {IOriginRouter} from "@contracts/origin/interfaces/IOriginRouter.sol";
import {IntexAuction} from "@contracts/target/IntexAuction.sol";
import {IIntexAuction} from "@contracts/target/interfaces/IIntexAuction.sol";
import {EscrowAdapter} from "@contracts/target/EscrowAdapter.sol";
import {ReferenceCurrencyPriceLib} from "../helpers/ReferenceCurrencyPriceLib.sol";
import {MockTheCompact} from "@test-mocks/MockTheCompact.sol";
import {MockWCOEN} from "@test-mocks/MockWCOEN.sol";
import {IDesis} from "@contracts/origin/interfaces/IDesis.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {BidPackLib} from "../helpers/BidPackLib.sol";

/// @dev The origin buys destination gas from `IntexGas` before it knows what the target will spend, and
///      the budgets were last sized by estimate rather than measurement. These pin each formula against
///      the real consumption of a realistic message: a budget below actual cost strands the delivery in
///      redelivery, and one far above it just overpays every send.
contract GasBudgetTest is CrossChainTest {
    uint32 internal constant OUTBE_CHAIN_ID = 2;
    uint32 internal constant WORLDWIDE_DAY = 20260501;
    bytes14 internal constant SERIES_PREFIX = "20260501-USD-U";
    bytes14 internal constant POISON = "20260501-EUR-U";

    TargetRouter internal router;
    IntexNFT1155 internal intex;
    address internal admin = address(this);
    address internal originPeer = address(0x0B1);

    function setUp() public {
        _setUpBridge();
        intex = DeployProxy.intexNFT1155(admin, admin);
        router = DeployProxy.targetRouter(address(bridge), admin, OUTBE_CHAIN_ID);
        router.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, originPeer));
        router.wire(makeAddr("auction"), address(intex), makeAddr("escrow"));
        intex.grantRole(intex.RELAYER_ROLE(), address(router));
    }

    function _measure(bytes14[] memory batch) internal returns (uint256 spent) {
        bytes memory packet = BridgeMsgCodec.encodeMarkCalled(WORLDWIDE_DAY, uint32(block.timestamp), batch);
        uint256 before = gasleft();
        _deliver(OUTBE_CHAIN_ID, originPeer, address(router), packet);
        spent = before - gasleft();
    }

    function _seed(bytes14[] memory batch) internal {
        for (uint256 i = 0; i < batch.length; ++i) {
            IIntexNFT1155.CreateSeriesParams memory p = CreateSeriesLib.params(WORLDWIDE_DAY, 10_000, 0);
            p.seriesId = batch[i];
            intex.createSeries(p);
        }
    }

    function test_TheQuoteCoversAFullBatchThatApplies() public {
        bytes14[] memory batch = MarkBatchLib.sized(SERIES_PREFIX, BridgeMsgCodec.MAX_SERIES_PER_MARK);
        _seed(batch);

        uint256 spent = _measure(batch);

        emit log_named_uint("apply_batch8", spent);
        assertLt(spent, IntexGas.markCalled(batch.length), "a full applying batch must fit the quote");
    }

    /// @dev The cap bounds one series, not the batch: it buys the parking write room to run when a single
    ///      series runs away. A batch where most of them do is outside what the quote can carry.
    function test_TheQuoteSurvivesOneRunawaySeriesInAFullBatch() public {
        GasBurningIntex poisoned = new GasBurningIntex(POISON);
        TargetRouter mocked = DeployProxy.targetRouter(address(bridge), admin, OUTBE_CHAIN_ID);
        mocked.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, originPeer));
        mocked.wire(makeAddr("auction"), address(poisoned), makeAddr("escrow"));

        bytes14[] memory batch = MarkBatchLib.sized(SERIES_PREFIX, BridgeMsgCodec.MAX_SERIES_PER_MARK);
        batch[0] = POISON;
        bytes memory packet = BridgeMsgCodec.encodeMarkCalled(WORLDWIDE_DAY, uint32(block.timestamp), batch);
        bytes memory call = abi.encodeCall(
            bridge.deliverAs,
            (_interop(OUTBE_CHAIN_ID, originPeer), _interop(uint32(block.chainid), address(mocked)), packet)
        );

        (bool ok,) = address(bridge).call{gas: IntexGas.markCalled(batch.length)}(call);

        assertTrue(ok, "the message must land inside the gas its quote buys");
        assertEq(mocked.pendingMark(POISON), BridgeMsgCodec.MSG_MARK_CALLED, "the runaway waits in its slot");
    }

    function test_TheQuoteCoversAFullBatchThatParks() public {
        // No series exist, so every mark reverts and parks - the heavier of the two paths.
        bytes14[] memory batch = MarkBatchLib.sized(SERIES_PREFIX, BridgeMsgCodec.MAX_SERIES_PER_MARK);

        uint256 spent = _measure(batch);

        for (uint256 i = 0; i < batch.length; ++i) {
            assertEq(router.pendingMark(batch[i]), BridgeMsgCodec.MSG_MARK_CALLED, "every series waits in its slot");
        }
        emit log_named_uint("park_batch8", spent);
        assertLt(spent, IntexGas.markCalled(batch.length), "a full parking batch must fit the quote");
    }

    function test_TheQuoteCoversASingleSeriesMark() public {
        bytes14[] memory one = MarkBatchLib.one(SERIES_PREFIX);
        _seed(one);
        emit log_named_uint("apply_batch1", _measure(one));

        bytes14[] memory absent = MarkBatchLib.sized("20260501-EUR-U", 1);
        emit log_named_uint("park_batch1", _measure(absent));

        assertLt(_measure(one), IntexGas.markCalled(1), "a single mark must fit the quote");
    }

    /// @dev A qualified batch whose series have not landed: every mark slots instead of applying, which is
    ///      the dearer of the two paths and the one the budget has to cover.
    function test_TheQuoteCoversAQualifiedBatchThatSlots() public {
        bytes14[] memory batch = MarkBatchLib.sized(SERIES_PREFIX, BridgeMsgCodec.MAX_SERIES_PER_MARK);

        bytes memory packet = BridgeMsgCodec.encodeMarkQualified(WORLDWIDE_DAY, batch);
        uint256 before = gasleft();
        _deliver(OUTBE_CHAIN_ID, originPeer, address(router), packet);
        uint256 spent = before - gasleft();

        emit log_named_uint("qualified_slot_8", spent);
        assertLt(spent, IntexGas.markQualified(batch.length), "a full slotting qualified batch must fit");
    }

    function test_TheQuoteCoversASingleQualifiedMark() public {
        bytes14[] memory one = MarkBatchLib.sized(SERIES_PREFIX, 1);

        bytes memory packet = BridgeMsgCodec.encodeMarkQualified(WORLDWIDE_DAY, one);
        uint256 before = gasleft();
        _deliver(OUTBE_CHAIN_ID, originPeer, address(router), packet);
        uint256 spent = before - gasleft();

        emit log_named_uint("qualified_slot_1", spent);
        assertLt(spent, IntexGas.markQualified(1), "a single slotting qualified mark must fit");
    }

    function test_TheQuoteCoversAMarkQualifiedBatch() public {
        bytes14[] memory batch = MarkBatchLib.sized(SERIES_PREFIX, BridgeMsgCodec.MAX_SERIES_PER_MARK);
        _seed(batch);

        bytes memory packet = BridgeMsgCodec.encodeMarkQualified(WORLDWIDE_DAY, batch);
        uint256 before = gasleft();
        _deliver(OUTBE_CHAIN_ID, originPeer, address(router), packet);
        uint256 spent = before - gasleft();

        emit log_named_uint("mark_qualified_8", spent);
        assertLt(spent, IntexGas.markQualified(batch.length), "a full qualified batch must fit the quote");
    }

    function test_TheQuoteCoversIssuanceAtItsWidest() public {
        uint256 recipients = BridgeMsgCodec.MAX_RECIPIENTS_PER_ISSUANCE;
        address[] memory to = new address[](recipients);
        uint256[] memory qty = new uint256[](recipients);
        for (uint256 i = 0; i < recipients; ++i) {
            to[i] = address(uint160(0x2000 + i));
            qty[i] = 1;
        }

        bytes memory packet = BridgeMsgCodec.encodeIssuanceInstructions(
            WORLDWIDE_DAY,
            0,
            1,
            IssuanceBatchLib.one(
                BridgeMsgCodec.IssuanceInstructionsPayload({
                    seriesId: SERIES_PREFIX,
                    worldwideDay: WORLDWIDE_DAY,
                    issuedIntexCount: 10_000,
                    promisLoadMinor: 1e6,
                    entryPriceMinor: 100e6,
                    floorPriceMinor: 40e6,
                    callNoticePeriod: 0,
                    issuanceCurrency: 840,
                    referenceCurrency: 840,
                    callWindow: 0,
                    callThreshold: 0,
                    callPriceMinor: 200e6,
                    recipients: to,
                    quantities: qty
                })
            )
        );

        uint256 before = gasleft();
        _deliver(OUTBE_CHAIN_ID, originPeer, address(router), packet);
        uint256 spent = before - gasleft();

        emit log_named_uint("issuance_one_series_full_recipients", spent);
        assertLt(spent, IntexGas.issuance(1, recipients), "the widest issuance must fit the quote");
    }

    /// @dev The costliest chunk the batcher can emit: every series slot filled and the recipient cap
    ///      spread across them, so both terms of the quote are exercised at once.
    function test_TheQuoteCoversTheWidestIssuanceChunk() public {
        uint256 seriesCount = BridgeMsgCodec.MAX_SERIES_PER_ISSUANCE;
        uint256 recipients = BridgeMsgCodec.MAX_RECIPIENTS_PER_ISSUANCE;
        uint256 perSeries = recipients / seriesCount;

        BridgeMsgCodec.IssuanceInstructionsPayload[] memory batch =
            new BridgeMsgCodec.IssuanceInstructionsPayload[](seriesCount);
        for (uint256 s = 0; s < seriesCount; ++s) {
            address[] memory to = new address[](perSeries);
            uint256[] memory qty = new uint256[](perSeries);
            for (uint256 i = 0; i < perSeries; ++i) {
                to[i] = address(uint160(0x3000 + s * 0x100 + i));
                qty[i] = 1;
            }
            batch[s] = BridgeMsgCodec.IssuanceInstructionsPayload({
                seriesId: bytes14(uint112(uint112(SERIES_PREFIX) + s + 1)),
                worldwideDay: WORLDWIDE_DAY,
                issuedIntexCount: 10_000,
                promisLoadMinor: 1e6,
                entryPriceMinor: 100e6,
                floorPriceMinor: 40e6,
                callNoticePeriod: 0,
                issuanceCurrency: 840,
                referenceCurrency: 840,
                callWindow: 0,
                callThreshold: 0,
                callPriceMinor: 200e6,
                recipients: to,
                quantities: qty
            });
        }

        bytes memory packet = BridgeMsgCodec.encodeIssuanceInstructions(WORLDWIDE_DAY, 0, 1, batch);
        uint256 before = gasleft();
        _deliver(OUTBE_CHAIN_ID, originPeer, address(router), packet);
        uint256 spent = before - gasleft();

        emit log_named_uint("issuance_full_series_full_recipients", spent);
        assertLt(spent, IntexGas.issuance(seriesCount, recipients), "the widest chunk must fit the quote");
        assertLt(IntexGas.issuance(seriesCount, recipients), 10_000_000, "no message may outgrow a block");
    }

    function test_TheQuoteCoversABridgeMintAtItsWidest() public {
        uint256 items = IntexNFT1155BridgeCodec.MAX_BATCH_SIZE;
        IntexNFT1155 dstToken = DeployProxy.intexNFT1155(admin, admin);
        IntexNFT1155Bridge src = DeployProxy.intexNFT1155Bridge(address(intex), address(bridge), admin);
        IntexNFT1155Bridge dst = DeployProxy.intexNFT1155Bridge(address(dstToken), address(bridge), admin);
        src.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, address(dst)));
        dst.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, address(src)));
        intex.grantRole(intex.RELAYER_ROLE(), address(src));
        dstToken.grantRole(dstToken.RELAYER_ROLE(), address(dst));

        bytes14[] memory one = MarkBatchLib.one(SERIES_PREFIX);
        _seed(one);
        dstToken.createSeries(CreateSeriesLib.params(WORLDWIDE_DAY, 10_000, 0));
        intex.markQualified(SERIES_PREFIX);
        dstToken.markQualified(SERIES_PREFIX);

        // `multiSend` burns the whole batch from its caller and fans it out to `recipients`.
        address sender = address(0x3000);
        uint256 tokenId = intex.issuedTokenId(SERIES_PREFIX);
        intex.issue(sender, items, SERIES_PREFIX);

        bytes32[] memory to = new bytes32[](items);
        uint256[] memory ids = new uint256[](items);
        uint256[] memory amounts = new uint256[](items);
        for (uint256 i = 0; i < items; ++i) {
            to[i] = bytes32(uint256(uint160(address(uint160(0x4000 + i)))));
            ids[i] = tokenId;
            amounts[i] = 1;
        }

        vm.prank(sender);
        src.multiSend(
            MultiRecipientSendParam({dstChainId: OUTBE_CHAIN_ID, recipients: to, tokenIds: ids, amounts: amounts})
        );

        bytes memory payload = bridge.lastPayload();
        uint256 before = gasleft();
        _deliver(OUTBE_CHAIN_ID, address(src), address(dst), payload);
        uint256 spent = before - gasleft();

        emit log_named_uint("nft_mint_full_batch", spent);
        assertLt(spent, IntexGas.nftMint(items), "the widest bridge mint must fit the quote");
    }

    /// @dev The costly path is not the mint but its failure: every item that a recipient rejects is
    ///      recorded with its revert bytes so the owner can retry. Tokens are already burned on the
    ///      source, so a budget that only covers the happy path strands them.
    function test_TheQuoteCoversABridgeMintWhereEveryItemIsRejected() public {
        uint256 items = IntexNFT1155BridgeCodec.MAX_BATCH_SIZE;
        IntexNFT1155 dstToken = DeployProxy.intexNFT1155(admin, admin);
        IntexNFT1155Bridge src = DeployProxy.intexNFT1155Bridge(address(intex), address(bridge), admin);
        IntexNFT1155Bridge dst = DeployProxy.intexNFT1155Bridge(address(dstToken), address(bridge), admin);
        src.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, address(dst)));
        dst.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, address(src)));
        intex.grantRole(intex.RELAYER_ROLE(), address(src));
        dstToken.grantRole(dstToken.RELAYER_ROLE(), address(dst));

        _seed(MarkBatchLib.one(SERIES_PREFIX));
        dstToken.createSeries(CreateSeriesLib.params(WORLDWIDE_DAY, 10_000, 0));
        intex.markQualified(SERIES_PREFIX);
        dstToken.markQualified(SERIES_PREFIX);

        address sender = address(0x3000);
        uint256 tokenId = intex.issuedTokenId(SERIES_PREFIX);
        intex.issue(sender, items, SERIES_PREFIX);

        // One receiver that rejects every mint, so every item takes the recording path.
        RevertingReceiver rejecting = new RevertingReceiver();
        bytes32[] memory to = new bytes32[](items);
        uint256[] memory ids = new uint256[](items);
        uint256[] memory amounts = new uint256[](items);
        for (uint256 i = 0; i < items; ++i) {
            to[i] = bytes32(uint256(uint160(address(rejecting))));
            ids[i] = tokenId;
            amounts[i] = 1;
        }

        vm.prank(sender);
        src.multiSend(
            MultiRecipientSendParam({dstChainId: OUTBE_CHAIN_ID, recipients: to, tokenIds: ids, amounts: amounts})
        );

        bytes memory payload = bridge.lastPayload();
        uint256 before = gasleft();
        _deliver(OUTBE_CHAIN_ID, address(src), address(dst), payload);
        uint256 spent = before - gasleft();

        emit log_named_uint("nft_mint_full_batch_all_rejected", spent);
        assertLt(spent, IntexGas.nftMint(items), "the rejecting path must fit the quote too");
    }

    // The delivery runs inside the gas the quote buys: uncapped, one runaway series spends it all before
    // the parking write and the whole message reverts into redelivery.
    function test_ARunawaySeriesIsParkedAndTheBatchContinues() public {
        GasBurningIntex poisoned = new GasBurningIntex(POISON);
        TargetRouter mocked = DeployProxy.targetRouter(address(bridge), admin, OUTBE_CHAIN_ID);
        mocked.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, originPeer));
        mocked.wire(makeAddr("auction"), address(poisoned), makeAddr("escrow"));

        bytes memory packet = BridgeMsgCodec.encodeMarkCalled(
            WORLDWIDE_DAY, uint32(block.timestamp), MarkBatchLib.two(POISON, SERIES_PREFIX)
        );
        bytes memory call = abi.encodeCall(
            bridge.deliverAs,
            (_interop(OUTBE_CHAIN_ID, originPeer), _interop(uint32(block.chainid), address(mocked)), packet)
        );
        (bool ok,) = address(bridge).call{gas: IntexGas.markCalled(2)}(call);

        assertTrue(ok, "the message must land, not bounce back into redelivery");
        assertEq(mocked.pendingMark(POISON), BridgeMsgCodec.MSG_MARK_CALLED, "the runaway waits in its slot");
        assertEq(mocked.pendingMark(SERIES_PREFIX), 0, "its batch mate has no slot");
        assertEq(poisoned.markedCount(), 1, "its batch mate still applied");
    }
}

/// @dev Stands in for IntexNFT1155 so one series can be made to burn everything it is given.
contract GasBurningIntex {
    bytes14 private immutable poison;
    uint256 public markedCount;

    constructor(bytes14 _poison) {
        poison = _poison;
    }

    /// @dev The inbound path asks before it marks; every series here is live.
    function seriesExists(bytes14) external pure returns (bool) {
        return true;
    }

    function markCalled(bytes14 seriesId, uint32) external {
        if (seriesId == poison) {
            // Spin until the frame's gas is gone.
            while (true) {
                markedCount = markedCount;
            }
        }
        markedCount++;
    }
}

/// @dev Rejects every ERC-1155 receive, so each item lands in the bridge's failed-mint record.
contract RevertingReceiver {
    error Rejected();

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        revert Rejected();
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata, uint256[] calldata, bytes calldata)
        external
        pure
        returns (bytes4)
    {
        revert Rejected();
    }
}

/// @dev The auction-side handlers need the real Auction and EscrowAdapter behind the router, so they
///      get their own fixture. CLEARING is the interesting one: its budget has to cover the bids relay
///      that fires from inside the same delivery, not just the stage flip.
contract AuctionGasBudgetTest is CrossChainTest {
    uint32 internal constant BNB_CHAIN_ID = 1;
    uint32 internal constant OUTBE_CHAIN_ID = 2;
    uint32 internal constant WORLDWIDE_DAY = 20250101;
    uint32 internal constant ISSUED_INTEX_COUNT = 10_000;
    uint64 internal constant ENTRY_PRICE = 100e6;

    TargetRouter internal router;
    OriginRouter internal originRouter;
    IntexAuction internal auction;
    IntexNFT1155 internal intex;
    EscrowAdapter internal escrow;
    MockTheCompact internal compact;
    MockWCOEN internal paymentToken;
    address internal admin = address(this);

    function setUp() public {
        _setUpBridge();
        intex = DeployProxy.intexNFT1155(admin, admin);
        auction = DeployProxy.intexAuction(admin, admin);
        router = DeployProxy.targetRouter(address(bridge), admin, OUTBE_CHAIN_ID);
        originRouter = DeployProxy.originRouter(address(bridge), admin);
        escrow = DeployProxy.escrowAdapter(admin, admin);
        compact = new MockTheCompact();
        paymentToken = new MockWCOEN();
        escrow.wire(admin, address(compact), address(paymentToken));
        compact.setResetPeriodSeconds(0);

        router.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, address(originRouter)));
        router.wire(address(auction), address(intex), address(escrow));
        auction.grantRole(auction.RELAYER_ROLE(), address(router));
        intex.grantRole(intex.RELAYER_ROLE(), address(router));
        escrow.grantRole(escrow.RELAYER_ROLE(), address(router));

        // The relay leaves from the router's own float.
        vm.deal(address(router), 100 ether);
    }

    function _deliver(bytes memory packet) internal returns (uint256 spent) {
        uint256 before = gasleft();
        _deliver(OUTBE_CHAIN_ID, address(originRouter), address(router), packet);
        spent = before - gasleft();
    }

    /// @dev The widest start the codec allows: `MAX_REFERENCE_PRICES` rows.
    function _startPacket(uint256 rows) internal view returns (bytes memory) {
        IOriginRouter.ReferenceCurrencyPrice[] memory prices = new IOriginRouter.ReferenceCurrencyPrice[](rows);
        for (uint256 i = 0; i < rows; ++i) {
            prices[i] = IOriginRouter.ReferenceCurrencyPrice({
                isoCode: uint16(840 + i),
                entryPriceMinor: ENTRY_PRICE,
                floorPriceMinor: 40e6,
                callPriceMinor: ENTRY_PRICE
            });
        }
        return BridgeMsgCodec.encodeAuctionStageStart(
            WORLDWIDE_DAY,
            uint32(block.timestamp + 1 days),
            uint32(block.timestamp + 2 days),
            uint32(block.timestamp + 3 days),
            1e6,
            60e6,
            prices,
            0,
            0,
            0,
            1,
            0,
            1
        );
    }

    function test_TheQuoteCoversAuctionStageStartAtItsWidest() public {
        uint256 rows = BridgeMsgCodec.MAX_REFERENCE_PRICES;

        uint256 spent = _deliver(_startPacket(rows));

        emit log_named_uint("auction_start_6prices", spent);
        assertLt(spent, IntexGas.auctionStart(rows), "auction start must fit the quote");
    }

    function test_TheQuoteCoversAuctionStageClearingWithNoBids() public {
        _deliver(_startPacket(1));
        vm.warp(block.timestamp + 1 days);

        uint256 spent = _deliver(BridgeMsgCodec.encodeAuctionStageClearing(WORLDWIDE_DAY));

        emit log_named_uint("clearing_0bids", spent);
        assertLt(spent, IntexGas.AUCTION_STAGE_CLEARING, "clearing must fit the quote");
    }

    function test_TheQuoteCoversRefundsAtTheirWidest() public {
        uint256 bidders = BridgeMsgCodec.MAX_PAYLOAD_ARRAY_LEN;
        escrow.grantRole(escrow.AUCTION_ROLE(), admin);

        address[] memory who = new address[](bidders);
        uint128[] memory refunded = new uint128[](bidders);
        uint128[] memory paid = new uint128[](bidders);
        for (uint256 i = 0; i < bidders; ++i) {
            who[i] = address(uint160(0x5000 + i));
            paymentToken.mint(who[i], 1000e6);
            vm.prank(who[i]);
            paymentToken.approve(address(escrow), type(uint256).max);
            escrow.lockFunds(WORLDWIDE_DAY, who[i], 1000e6);
            refunded[i] = 1000e6;
            paid[i] = 0;
        }

        uint256 spent = _deliver(BridgeMsgCodec.encodeRefundInstructions(WORLDWIDE_DAY, 0, 1, who, refunded, paid));

        emit log_named_uint("refund_full_chunk", spent);
        assertLt(spent, IntexGas.refund(bidders), "the widest refund chunk must fit the quote");
    }

    function test_TheQuoteCoversAuctionResult() public {
        _deliver(_startPacket(1));
        vm.warp(block.timestamp + 1 days);
        vm.prank(address(router));
        auction.startClearingStage(WORLDWIDE_DAY);

        uint256 spent = _deliver(BridgeMsgCodec.encodeAuctionResult(WORLDWIDE_DAY, ISSUED_INTEX_COUNT, ENTRY_PRICE, 0));

        emit log_named_uint("auction_result", spent);
        assertLt(spent, IntexGas.AUCTION_RESULT, "auction result must fit the quote");
    }
}

/// @dev CLEARING's budget is dominated by the bids relay it fires: the day's revealed bids leave as
///      chunks of `MAX_PAYLOAD_ARRAY_LEN`, and every chunk is an outbound send paid from this same
///      delivery. A stub auction supplies the bids so the slope is measurable without the reveal flow.
contract ClearingRelayGasTest is CrossChainTest {
    uint32 internal constant OUTBE_CHAIN_ID = 2;
    uint32 internal constant WORLDWIDE_DAY = 20250101;

    TargetRouter internal router;
    BidStub internal stub;
    address internal admin = address(this);
    address internal originPeer = address(0x0B1);

    function setUp() public {
        _setUpBridge();
        stub = new BidStub();
        router = DeployProxy.targetRouter(address(bridge), admin, OUTBE_CHAIN_ID);
        router.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, originPeer));
        router.wire(address(stub), makeAddr("intex"), makeAddr("escrow"));
        vm.deal(address(router), 100 ether);
    }

    function _clearingCost(uint256 bids) internal returns (uint256 spent) {
        stub.setBidCount(bids);
        uint256 before = gasleft();
        _deliver(OUTBE_CHAIN_ID, originPeer, address(router), BridgeMsgCodec.encodeAuctionStageClearing(WORLDWIDE_DAY));
        spent = before - gasleft();
    }

    function test_TheQuoteCoversClearingWithAFullChunkOfBids() public {
        uint256 spent = _clearingCost(BridgeMsgCodec.MAX_PAYLOAD_ARRAY_LEN);

        emit log_named_uint("clearing_one_chunk", spent);
        assertEq(router.nextPendingBidsRelayIdx(), 0, "the relay went out, it did not park");
        assertLt(spent, IntexGas.AUCTION_STAGE_CLEARING, "one full chunk must fit the quote");
    }

    function test_TheQuoteCoversClearingWithFourChunksOfBids() public {
        uint256 spent = _clearingCost(4 * BridgeMsgCodec.MAX_PAYLOAD_ARRAY_LEN);

        emit log_named_uint("clearing_four_chunks", spent);
        assertEq(router.nextPendingBidsRelayIdx(), 0, "the relay went out, it did not park");
        assertLt(spent, IntexGas.AUCTION_STAGE_CLEARING, "four chunks must fit the quote");
    }

    /// @dev Past the relay's ceiling the stage still transitions and the relay parks, so the day is
    ///      recoverable by a flush rather than stuck in redelivery.
    function test_ADayTooHeavyToRelayParksInsteadOfFailing() public {
        uint256 spent = _clearingCost(16 * BridgeMsgCodec.MAX_PAYLOAD_ARRAY_LEN);

        emit log_named_uint("clearing_1024bids", spent);
        assertEq(router.nextPendingBidsRelayIdx(), 1, "the relay parked");
        assertLt(spent, IntexGas.AUCTION_STAGE_CLEARING, "the capped delivery still fits the quote");
    }
}

/// @dev Supplies a settable number of revealed bids; the stage flip itself is a no-op.
contract BidStub {
    uint256 public bidCount;

    function setBidCount(uint256 n) external {
        bidCount = n;
    }

    function startClearingStage(uint32) external {}

    function getAuctionDetails(uint32)
        external
        view
        returns (IIntexAuction.AuctionData memory data, IIntexAuction.SubmittedBidData[] memory bids)
    {
        bids = new IIntexAuction.SubmittedBidData[](bidCount);
        for (uint256 i = 0; i < bidCount; ++i) {
            bids[i] = IIntexAuction.SubmittedBidData({
                bidderAddress: address(uint160(0xCAFE + i)),
                intexQuantity: 1,
                intexBidRate: 100e6,
                timestamp: uint32(block.timestamp),
                issuanceCurrency: 840,
                referenceCurrency: 840
            });
        }
    }
}

/// @dev The Outbe-side receives: a target relays its bids as BIDS_BATCH chunks and closes the generation
///      with a BIDS_DONE. Both land on OriginRouter and forward to Desis.
contract OriginInboundGasTest is CrossChainTest {
    uint32 internal constant BNB_CHAIN_ID = 1;
    uint32 internal constant WORLDWIDE_DAY = 20250101;
    uint64 internal constant ENTRY_PRICE = 100e6;

    OriginRouter internal originRouter;
    DesisSink internal desis;
    address internal admin = address(this);
    address internal targetPeer = address(0x7A6);

    function setUp() public {
        _setUpBridge();
        desis = new DesisSink();
        originRouter = DeployProxy.originRouter(address(bridge), admin);
        originRouter.setRemoteMessenger(BNB_CHAIN_ID, _interop(BNB_CHAIN_ID, targetPeer));
        originRouter.wire(address(desis), makeAddr("factory"));
        originRouter.addTarget(BNB_CHAIN_ID);

        // Freeze the day's snapshot so the target is allowed to feed bids into it.
        IOriginRouter.AuctionStageStartParams memory p;
        p.worldwideDay = WORLDWIDE_DAY;
        p.dayState = 1;
        p.prices = ReferenceCurrencyPriceLib.one(840, ENTRY_PRICE, 40e6, ENTRY_PRICE);
        vm.prank(address(desis));
        originRouter.sendAuctionStageStart(p);
    }

    function _deliver(bytes memory packet) internal returns (uint256 spent) {
        uint256 before = gasleft();
        _deliver(BNB_CHAIN_ID, targetPeer, address(originRouter), packet);
        spent = before - gasleft();
    }

    function test_TheQuoteCoversABidsBatchAtItsWidest() public {
        uint256 count = BridgeMsgCodec.MAX_PAYLOAD_ARRAY_LEN;
        address[] memory bidders = new address[](count);
        uint16[] memory quantities = new uint16[](count);
        uint32[] memory rates = new uint32[](count);
        uint32[] memory timestamps = new uint32[](count);
        for (uint256 i = 0; i < count; ++i) {
            bidders[i] = address(uint160(0x6000 + i));
            quantities[i] = 1;
            rates[i] = uint32(ENTRY_PRICE);
            timestamps[i] = uint32(block.timestamp);
        }

        uint256 spent = _deliver(
            BridgeMsgCodec.encodeBidsBatch(
                WORLDWIDE_DAY, BNB_CHAIN_ID, 1, 0, 1, bidders, BidPackLib.pack(quantities, rates, timestamps)
            )
        );

        emit log_named_uint("bids_batch_full_chunk", spent);
        assertLt(spent, IntexGas.bidsBatch(count), "the widest bids batch must fit the quote");
    }

    function test_TheQuoteCoversBidsDone() public {
        uint256 spent = _deliver(BridgeMsgCodec.encodeBidsDone(WORLDWIDE_DAY, BNB_CHAIN_ID, 1, 1, 0));

        emit log_named_uint("bids_done", spent);
        assertLt(spent, IntexGas.BIDS_DONE, "bids done must fit the quote");
    }
}

/// @dev On Outbe the real Desis is a precompile, so these measure the router's own share of an inbound
///      bids message. The precompile's work sits outside this harness and outside the numbers below.
contract DesisSink {
    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IDesis).interfaceId || interfaceId == type(IERC165).interfaceId;
    }

    function processBidsBatch(uint32, uint32, uint32, uint16, uint16, address[] calldata, uint256[] calldata)
        external {}

    function processBidsDone(uint32, uint32, uint32, uint16, uint32) external {}

    function getAuctionStage(uint32) external pure returns (uint8) {
        return 0;
    }

    function getBidsCount(uint32) external pure returns (uint256) {
        return 0;
    }
}
