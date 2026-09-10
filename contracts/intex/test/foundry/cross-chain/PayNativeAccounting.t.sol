// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {CrossChainTest} from "../helpers/CrossChainTest.sol";

import {TargetRouter} from "@contracts/target/TargetRouter.sol";
import {ITargetRouter} from "@contracts/target/interfaces/ITargetRouter.sol";
import {IIntexAuction} from "@contracts/target/interfaces/IIntexAuction.sol";
import {OriginRouter} from "@contracts/origin/OriginRouter.sol";
import {IntexNFT1155Bridge} from "@contracts/shared/IntexNFT1155Bridge.sol";
import {SendParam} from "@contracts/shared/interfaces/IIntexNFT1155Bridge.sol";
import {ERC7786MessengerBase} from "@contracts/shared/ERC7786MessengerBase.sol";
import {BridgeMsgCodec} from "@contracts/shared/libs/BridgeMsgCodec.sol";

import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";
import {CreateSeriesLib} from "../helpers/CreateSeriesLib.sol";

/// @title PayNativeAccountingTest
/// @notice Behavioural coverage for the native-fee funding logic that {ERC7786MessengerBase-_send} owns for every
///         intex bridge client. Two calling conventions are distinguished:
///           * entry-funded (`msg.value > 0`): the send must cover the quoted fee and refund the excess to the
///             caller, so an entry caller's buffer never silently seeds (or drains) the contract's relay float;
///           * relay-funded (`msg.value == 0`): a chain-native module that cannot attach value triggered the send, so
///             the fee is drawn from the contract's pre-funded native float and reverts `NotEnoughNative` when short.
///         Conflating the two would let an entry caller's `msg.value` seed future relay sends without refund, or let
///         an entry caller drain the relay float.
/// @dev Entry path is driven through the user-facing `IntexNFT1155Bridge.send` (payable); the relay path by an
///      inbound CLEARING whose handler relays the day's bids from inside `receiveMessage`.
contract PayNativeAccountingTest is CrossChainTest {
    uint32 internal constant BNB_CHAIN_ID = 1;
    uint32 internal constant OUTBE_CHAIN_ID = 2;

    /// @dev Positive fee the loopback bridge charges; every send must fund this from `msg.value` or the float.
    uint256 internal constant BRIDGE_FEE = 0.001 ether;

    TargetRouter internal bnbRouter;
    OriginRouter internal outbeRouter;
    IntexNFT1155Bridge internal nftBridge;

    IntexNFT1155 internal intex;
    address internal admin = address(this);
    address internal auctionRole = address(0xA11C7);

    uint32 internal constant SERIES_ID_DAY = 20260501;
    bytes14 internal constant SERIES_ID = "20260501-USD-U";
    uint256 internal constant TOKEN_ID = uint256(uint112(SERIES_ID));
    address internal holder = address(0xCAFE);

    function setUp() public {
        _setUpBridge();
        // A positive fee is what makes the funding branches observable: entry sends must be covered and refunded,
        // relay sends must draw a non-zero amount from the float.
        bridge.setFee(BRIDGE_FEE);

        intex = DeployProxy.intexNFT1155(admin, admin);

        bnbRouter = DeployProxy.targetRouter(address(bridge), admin, OUTBE_CHAIN_ID);
        outbeRouter = DeployProxy.originRouter(address(bridge), admin);
        nftBridge = DeployProxy.intexNFT1155Bridge(address(intex), address(bridge), admin);

        // Register remote messengers so `_send` has a destination and inbound delivery authenticates.
        bnbRouter.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, address(outbeRouter)));
        outbeRouter.setRemoteMessenger(BNB_CHAIN_ID, _interop(BNB_CHAIN_ID, address(bnbRouter)));
        nftBridge.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, address(nftBridge)));

        // Wire TM with a stub auction and the batch adapter.
        StubAuction stubAuction = new StubAuction();
        bnbRouter.wire(address(stubAuction), address(intex), admin);

        // `crosschainBurn` is `RELAYER_ROLE`-gated, so the adapter needs it on the token.
        intex.grantRole(intex.RELAYER_ROLE(), address(nftBridge));
        intex.grantRole(intex.RELAYER_ROLE(), address(bnbRouter));

        // Series + holder balance so markCalled/holder enumeration and the entry-path bridge sends have tokens.
        intex.createSeries(CreateSeriesLib.params(SERIES_ID_DAY, 10_000, 0));
        intex.markQualified(SERIES_ID);
        intex.issue(holder, 5, SERIES_ID);
    }

    /// @dev A 1-token bridge-out to Outbe; the entry path (payable `send`) burns it from `holder`.
    function _sendParam() internal view returns (SendParam memory) {
        return
            SendParam({dstChainId: OUTBE_CHAIN_ID, to: bytes32(uint256(uint160(holder))), tokenId: TOKEN_ID, amount: 1});
    }

    function _holderArrays() internal view returns (address[] memory holders, uint256[] memory amounts) {
        holders = new address[](1);
        holders[0] = holder;
        amounts = new uint256[](1);
        amounts[0] = 1;
    }

    // ---------------------------------------------------------------
    // Entry path - msg.value handling (IntexNFT1155Bridge.send)
    // ---------------------------------------------------------------

    function test_Entry_ExactFeeLeavesNoFloat() public {
        SendParam memory params = _sendParam();
        uint256 fee = nftBridge.quoteSend(params);
        assertEq(fee, BRIDGE_FEE, "fee mirrors the positive bridge fee");

        vm.deal(holder, fee);
        uint256 floatBefore = address(nftBridge).balance;

        vm.prank(holder);
        nftBridge.send{value: fee}(params);

        // `msg.value` flowed through to the bridge exactly; nothing seeded the relay float.
        assertEq(address(nftBridge).balance, floatBefore, "no leakage on exact-fee entry");
        assertEq(holder.balance, 0, "caller paid the full fee");
    }

    function test_Entry_ExcessIsRefundedToCaller() public {
        SendParam memory params = _sendParam();
        uint256 fee = nftBridge.quoteSend(params);

        uint256 buffer = 0.5 ether;
        vm.deal(holder, fee + buffer);
        uint256 floatBefore = address(nftBridge).balance;

        vm.prank(holder);
        nftBridge.send{value: fee + buffer}(params);

        // Excess refunded out of `_send`, not retained for future relay sends.
        assertEq(address(nftBridge).balance, floatBefore, "excess must not seed the relay float");
        assertEq(holder.balance, buffer, "caller refunded the excess");
    }

    function test_Entry_BelowFeeRevertsMsgValueBelowFee() public {
        SendParam memory params = _sendParam();
        uint256 fee = nftBridge.quoteSend(params);

        uint256 short = fee - 1;
        vm.deal(holder, fee);

        vm.prank(holder);
        vm.expectRevert(abi.encodeWithSelector(ERC7786MessengerBase.MsgValueBelowFee.selector, short, fee));
        nftBridge.send{value: short}(params);
    }

    /// @notice Pin the no-leakage invariant across an entry-followed-by-entry sequence: the second entry must not see
    ///         the first's `msg.value` accumulated as float.
    function test_Entry_DoesNotLeakIntoFloatAcrossSends() public {
        SendParam memory params = _sendParam();
        uint256 fee = nftBridge.quoteSend(params);

        uint256 buffer = 1 ether;
        vm.deal(holder, (fee + buffer) * 2);
        uint256 floatBefore = address(nftBridge).balance;

        vm.prank(holder);
        nftBridge.send{value: fee + buffer}(params);
        assertEq(address(nftBridge).balance, floatBefore, "first entry: no leakage");

        vm.prank(holder);
        nftBridge.send{value: fee + buffer}(params);
        assertEq(address(nftBridge).balance, floatBefore, "second entry: no leakage");
        assertEq(holder.balance, 2 * buffer, "both excess values refunded");
    }

    function test_Entry_RefundFailsRevertsRefundFailed() public {
        // `_send` refunds excess to msg.sender via `.call{value: refund}("")`; a caller whose receive() reverts trips
        // the RefundFailed guard. Without it, a refactor that swallowed the .call return would silently seed the
        // relay float with the entry caller's excess.
        NftRefundRejector rejector = new NftRefundRejector(address(nftBridge));
        intex.issue(address(rejector), 1, SERIES_ID);

        SendParam memory params = _sendParam();
        params.to = bytes32(uint256(uint160(address(rejector))));
        uint256 fee = nftBridge.quoteSend(params);
        uint256 buffer = 0.3 ether;
        vm.deal(address(rejector), fee + buffer);

        vm.expectRevert(ERC7786MessengerBase.RefundFailed.selector);
        rejector.callSend{value: fee + buffer}(params);
    }

    // ---------------------------------------------------------------
    // Relay / float path - fired from inside receiveMessage (CLEARING)
    // ---------------------------------------------------------------

    /// @dev The inbound CLEARING handler relays the day's bids, funding the send from TargetRouter's float. With
    ///      that float empty the send reverts, which the handler catches and parks for later flush.
    function test_Relay_InsideReceiveMessage_EmptyFloatDefers() public {
        assertEq(address(bnbRouter).balance, 0, "router float unfunded");

        _deliverClearing();

        (uint32 storedDay, bool exists, bool done) = bnbRouter.pendingBidsRelays(0);
        assertEq(storedDay, SERIES_ID_DAY, "bids relay deferred on float-starved NotEnoughNative");
        assertTrue(exists);
        assertFalse(done);
    }

    /// @dev With TargetRouter's float funded, the relay fired from inside `receiveMessage` draws the fee and
    ///      sends cleanly - nothing is parked.
    function test_Relay_InsideReceiveMessage_FundedFloatSucceeds() public {
        vm.deal(address(bnbRouter), 1 ether);
        uint256 floatBefore = address(bnbRouter).balance;

        _deliverClearing();

        // One bid relays as a data batch plus the final empty one, so the float pays two fees.
        assertEq(bnbRouter.nextPendingBidsRelayIdx(), 0, "no bids relay deferred");
        assertEq(floatBefore - address(bnbRouter).balance, 2 * BRIDGE_FEE, "every batch drew its fee from the float");
    }

    function _deliverClearing() internal {
        _deliver(
            OUTBE_CHAIN_ID,
            address(outbeRouter),
            address(bnbRouter),
            BridgeMsgCodec.encodeAuctionStageClearing(SERIES_ID_DAY)
        );
    }

    // ---------------------------------------------------------------
    // Admin float recovery (sweepNative)
    // ---------------------------------------------------------------

    function test_SweepNative_AdminRecoversFloat() public {
        vm.deal(address(bnbRouter), 3 ether);
        address payable to = payable(address(0x5EE3));

        bnbRouter.sweepNative(to, 1 ether);

        assertEq(to.balance, 1 ether, "recipient received the swept amount");
        assertEq(address(bnbRouter).balance, 2 ether, "remainder stays as float");
    }

    function test_SweepNative_NonAdminReverts() public {
        vm.deal(address(bnbRouter), 1 ether);
        vm.prank(auctionRole); // an arbitrary non-admin caller
        vm.expectRevert();
        bnbRouter.sweepNative(payable(auctionRole), 1 ether);
    }

    function test_SweepNative_OverBalanceReverts() public {
        vm.deal(address(bnbRouter), 1 ether);
        vm.expectRevert(
            abi.encodeWithSelector(ITargetRouter.NativeBalanceInsufficient.selector, uint256(1 ether), uint256(2 ether))
        );
        bnbRouter.sweepNative(payable(address(0xBEEF)), 2 ether);
    }

    function test_SweepNative_ZeroRecipientReverts() public {
        vm.deal(address(bnbRouter), 1 ether);
        vm.expectRevert(abi.encodeWithSelector(ITargetRouter.ZeroAddress.selector, "to"));
        bnbRouter.sweepNative(payable(address(0)), 1 ether);
    }
}

/// @dev Auction stub with one bid, so an inbound CLEARING produces exactly one relayed batch - one bridge fee.
contract StubAuction {
    function auctionStart(
        uint32,
        IIntexAuction.WorldwideDayState,
        IIntexAuction.AuctionSchedule calldata,
        IIntexAuction.AuctionParams calldata
    ) external {}
    function startClearingStage(uint32) external {}
    function executeAuctionClearing(uint32, uint32, uint64, uint32) external {}

    function getAuctionDetails(uint32)
        external
        view
        returns (IIntexAuction.AuctionData memory data, IIntexAuction.SubmittedBidData[] memory bids)
    {
        bids = new IIntexAuction.SubmittedBidData[](1);
        bids[0] = IIntexAuction.SubmittedBidData({
            bidderAddress: address(0xCAFE),
            intexQuantity: 1,
            intexBidRate: 100e6,
            timestamp: uint32(block.timestamp),
            issuanceCurrency: 840,
            referenceCurrency: 840
        });
    }
}

/// @dev Holds a bridgeable token (accepts the ERC-1155 mint) but whose `receive()` reverts; used to pin `_send`'s
///      RefundFailed guard on the entry path via the NFT bridge.
contract NftRefundRejector {
    IntexNFT1155Bridge private immutable bridge;

    constructor(address _bridge) {
        bridge = IntexNFT1155Bridge(payable(_bridge));
    }

    function callSend(SendParam calldata params) external payable {
        bridge.send{value: msg.value}(params);
    }

    function onERC1155Received(address, address, uint256, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    receive() external payable {
        revert("refund-rejected");
    }
}
