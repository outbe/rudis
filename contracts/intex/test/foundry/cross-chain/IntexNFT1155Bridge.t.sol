// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {CrossChainTest} from "../helpers/CrossChainTest.sol";
import {IntexNFT1155Bridge} from "@contracts/shared/IntexNFT1155Bridge.sol";
import {
    IIntexNFT1155Bridge,
    BatchSendParam,
    MultiRecipientSendParam
} from "@contracts/shared/interfaces/IIntexNFT1155Bridge.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";
import {CreateSeriesLib} from "../helpers/CreateSeriesLib.sol";

/// @title IntexNFT1155BridgeTest
/// @notice direct coverage for the NFT-Batch outbound entry points
///         (`batchSend`, `multiSend`) and their `quote*` views. The inbound
///         `receiveMessage` validation matrix (malformed / duplicate / version / srcChainId) is covered by
///         the sibling cross-chain suites; this file exercises the send-side surface that had no
///         direct test: happy-path delivery, every revert branch, the role gate, and quoting.
contract IntexNFT1155BridgeTest is CrossChainTest {
    uint32 internal constant SRC_CHAIN_ID = 1;
    uint32 internal constant DST_CHAIN_ID = 2;

    uint256 internal constant FEE = 0.001 ether;

    IntexNFT1155Bridge internal srcBatch;
    IntexNFT1155Bridge internal dstBatch;
    IntexNFT1155 internal srcToken;
    IntexNFT1155 internal dstToken;

    address internal admin = address(this);
    address internal sender = address(0xB0B);
    address internal recipientA = address(0xA11CE);
    address internal recipientB = address(0xCAFE);

    uint32 internal constant SERIES_A_DAY = 20260601;
    bytes14 internal constant SERIES_A = "20260601-USD-U";
    uint32 internal constant SERIES_B_DAY = 20260602;
    bytes14 internal constant SERIES_B = "20260602-USD-U";
    uint256 internal constant TID_A = uint256(uint112(SERIES_A));
    uint256 internal constant TID_B = uint256(uint112(SERIES_B));

    function setUp() public {
        _setUpBridge();
        bridge.setFee(FEE);

        srcToken = DeployProxy.intexNFT1155(admin, admin);
        dstToken = DeployProxy.intexNFT1155(admin, admin);
        srcBatch = DeployProxy.intexNFT1155Bridge(address(srcToken), address(bridge), admin);
        dstBatch = DeployProxy.intexNFT1155Bridge(address(dstToken), address(bridge), admin);

        srcBatch.setRemoteMessenger(DST_CHAIN_ID, _interop(DST_CHAIN_ID, address(dstBatch)));
        dstBatch.setRemoteMessenger(SRC_CHAIN_ID, _interop(SRC_CHAIN_ID, address(srcBatch)));

        for (uint32 i = 0; i < 2; i++) {
            uint32 day = i == 0 ? SERIES_A_DAY : SERIES_B_DAY;
            bytes14 series = i == 0 ? SERIES_A : SERIES_B;
            srcToken.createSeries(CreateSeriesLib.params(day, 1_000_000, 0));
            dstToken.createSeries(CreateSeriesLib.params(day, 1_000_000, 0));
            srcToken.markQualified(series);
            dstToken.markQualified(series);
        }

        srcToken.grantRole(srcToken.RELAYER_ROLE(), address(srcBatch));
        dstToken.grantRole(dstToken.RELAYER_ROLE(), address(dstBatch));

        vm.deal(sender, 100 ether); // batchSend/multiSend are caller-funded

        // Stock the sender with units on both series so the per-item `crosschainBurn` succeeds.
        srcToken.issue(sender, 100, SERIES_A);
        srcToken.issue(sender, 100, SERIES_B);
    }

    // --- helpers ---

    function _u256(uint256 a, uint256 b) internal pure returns (uint256[] memory arr) {
        arr = new uint256[](2);
        arr[0] = a;
        arr[1] = b;
    }

    function _u256One(uint256 a) internal pure returns (uint256[] memory arr) {
        arr = new uint256[](1);
        arr[0] = a;
    }

    /// @dev Deliver the packet the src adapter just handed the bridge to the dst adapter.
    function _deliverLast() internal {
        _deliver(SRC_CHAIN_ID, address(srcBatch), address(dstBatch), bridge.lastPayload());
    }

    // ---------------------------------------------------------------
    // constructor - zero-address guards on immutable wiring
    // ---------------------------------------------------------------

    /// @notice `token` is immutable; a zero address permanently bricks every crosschainMint/crosschainBurn path.
    /// @dev Property of the implementation constructor.
    function test_Constructor_RevertsZeroToken() public {
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155Bridge.ZeroAddress.selector, "token"));
        new IntexNFT1155Bridge(address(0), address(bridge));
    }

    /// @notice A zero bridge address is caught by the `ERC7786MessengerBase` constructor guard.
    function test_Constructor_RevertsZeroBridge() public {
        vm.expectRevert(abi.encodeWithSignature("InvalidBridge()"));
        new IntexNFT1155Bridge(address(srcToken), address(0));
    }

    /// @notice The explicit `ZeroAddress("delegate")` guard in `initialize` rejects a zero
    ///         delegate/owner during proxy initialization.
    function test_Initialize_RevertsZeroDelegate() public {
        IntexNFT1155Bridge impl = new IntexNFT1155Bridge(address(srcToken), address(bridge));
        vm.expectRevert(abi.encodeWithSignature("ZeroAddress(string)", "delegate"));
        new ERC1967Proxy(address(impl), abi.encodeCall(IntexNFT1155Bridge.initialize, (address(0))));
    }

    // ---------------------------------------------------------------
    // batchSend / quoteBatchSend - single recipient, many tokenIds
    // ---------------------------------------------------------------

    function test_BatchSend_HappyPath_CrosschainBurnsSenderAndCrosschainMintsRecipient() public {
        BatchSendParam memory p = BatchSendParam({
            dstChainId: DST_CHAIN_ID,
            to: bytes32(uint256(uint160(recipientA))),
            tokenIds: _u256(TID_A, TID_B),
            amounts: _u256(5, 7)
        });

        uint256 fee = srcBatch.quoteBatchSend(p);

        vm.prank(sender);
        srcBatch.batchSend{value: fee}(p);

        // Sender crosschainBurned on the source for both items.
        assertEq(srcToken.balanceOf(sender, TID_A), 95, "src A crosschainBurned");
        assertEq(srcToken.balanceOf(sender, TID_B), 93, "src B crosschainBurned");

        // Deliver the queued packet; recipient crosschainMinted on the destination.
        _deliverLast();
        assertEq(dstToken.balanceOf(recipientA, TID_A), 5, "dst A crosschainMinted");
        assertEq(dstToken.balanceOf(recipientA, TID_B), 7, "dst B crosschainMinted");
    }

    function test_BatchSend_RevertsEmptyBatch() public {
        BatchSendParam memory p = BatchSendParam({
            dstChainId: DST_CHAIN_ID,
            to: bytes32(uint256(uint160(recipientA))),
            tokenIds: new uint256[](0),
            amounts: new uint256[](0)
        });
        vm.expectRevert(IIntexNFT1155Bridge.EmptyBatch.selector);
        vm.prank(sender);
        srcBatch.batchSend{value: FEE}(p);
    }

    function test_BatchSend_RevertsArrayLengthMismatch() public {
        BatchSendParam memory p = BatchSendParam({
            dstChainId: DST_CHAIN_ID,
            to: bytes32(uint256(uint160(recipientA))),
            tokenIds: _u256(TID_A, TID_B),
            amounts: _u256One(5)
        });
        vm.expectRevert(IIntexNFT1155Bridge.ArrayLengthMismatch.selector);
        vm.prank(sender);
        srcBatch.batchSend{value: FEE}(p);
    }

    function test_BatchSend_RevertsInvalidReceiver_ZeroTo() public {
        // Sender holds balance, so the crosschainBurn loop succeeds; the zero `to` then trips InvalidReceiver
        // inside `_buildBatchMsg`. The whole tx reverts, so the crosschainBurn rolls back too.
        BatchSendParam memory p =
            BatchSendParam({dstChainId: DST_CHAIN_ID, to: bytes32(0), tokenIds: _u256One(TID_A), amounts: _u256One(1)});
        vm.expectRevert(IIntexNFT1155Bridge.InvalidReceiver.selector);
        vm.prank(sender);
        srcBatch.batchSend{value: FEE}(p);

        assertEq(srcToken.balanceOf(sender, TID_A), 100, "crosschainBurn rolled back on revert");
    }

    function test_BatchSend_ZeroAmount_IsNoOpAndDelivers() public {
        // No ZeroValue guard on amounts: a zero-amount item is a burn/crosschainMint of 0 (a no-op) and the
        // send still succeeds. Documents the intended permissive behaviour.
        BatchSendParam memory p = BatchSendParam({
            dstChainId: DST_CHAIN_ID,
            to: bytes32(uint256(uint160(recipientA))),
            tokenIds: _u256One(TID_A),
            amounts: _u256One(0)
        });
        uint256 fee = srcBatch.quoteBatchSend(p);

        vm.prank(sender);
        srcBatch.batchSend{value: fee}(p);

        _deliverLast();
        assertEq(srcToken.balanceOf(sender, TID_A), 100, "sender unchanged for zero-amount item");
        assertEq(dstToken.balanceOf(recipientA, TID_A), 0, "recipient crosschainMinted zero");
    }

    function test_QuoteBatchSend_ReturnsNonZeroNativeFee() public view {
        BatchSendParam memory p = BatchSendParam({
            dstChainId: DST_CHAIN_ID,
            to: bytes32(uint256(uint160(recipientA))),
            tokenIds: _u256(TID_A, TID_B),
            amounts: _u256(5, 7)
        });
        uint256 fee = srcBatch.quoteBatchSend(p);
        assertEq(fee, FEE, "native fee quoted");
    }

    // --- Caller-funded fee accounting ---

    function test_BatchSend_RevertsBelowFee() public {
        // batchSend is caller-funded: less than the quoted fee reverts (it must not draw the float).
        BatchSendParam memory p = BatchSendParam({
            dstChainId: DST_CHAIN_ID,
            to: bytes32(uint256(uint160(recipientA))),
            tokenIds: _u256One(TID_A),
            amounts: _u256One(1)
        });
        uint256 fee = srcBatch.quoteBatchSend(p);
        vm.expectRevert(abi.encodeWithSignature("MsgValueBelowFee(uint256,uint256)", fee - 1, fee));
        vm.prank(sender);
        srcBatch.batchSend{value: fee - 1}(p);
    }

    function test_BatchSend_RefundsExcessValue() public {
        // Excess native value above the fee is refunded to the caller, not absorbed into the float.
        BatchSendParam memory p = BatchSendParam({
            dstChainId: DST_CHAIN_ID,
            to: bytes32(uint256(uint160(recipientA))),
            tokenIds: _u256One(TID_A),
            amounts: _u256One(1)
        });
        uint256 fee = srcBatch.quoteBatchSend(p);
        uint256 floatBefore = address(srcBatch).balance;
        uint256 senderBefore = sender.balance;

        vm.prank(sender);
        srcBatch.batchSend{value: fee + 1 ether}(p);

        // Caller paid only the fee; the 1 ether excess came back; the float was untouched.
        assertEq(sender.balance, senderBefore - fee, "only the fee charged");
        assertEq(address(srcBatch).balance, floatBefore, "system float untouched");
    }

    // ---------------------------------------------------------------
    // multiSend / quoteMultiSend - many recipients
    // ---------------------------------------------------------------

    function test_MultiSend_HappyPath_CrosschainMintsEachRecipient() public {
        bytes32[] memory recipients = new bytes32[](2);
        recipients[0] = bytes32(uint256(uint160(recipientA)));
        recipients[1] = bytes32(uint256(uint160(recipientB)));

        MultiRecipientSendParam memory p = MultiRecipientSendParam({
            dstChainId: DST_CHAIN_ID, recipients: recipients, tokenIds: _u256(TID_A, TID_B), amounts: _u256(3, 4)
        });

        uint256 fee = srcBatch.quoteMultiSend(p);

        vm.prank(sender);
        srcBatch.multiSend{value: fee}(p);

        assertEq(srcToken.balanceOf(sender, TID_A), 97, "src A crosschainBurned");
        assertEq(srcToken.balanceOf(sender, TID_B), 96, "src B crosschainBurned");

        _deliverLast();
        assertEq(dstToken.balanceOf(recipientA, TID_A), 3, "recipientA crosschainMinted A");
        assertEq(dstToken.balanceOf(recipientB, TID_B), 4, "recipientB crosschainMinted B");
    }

    function test_MultiSend_RevertsEmptyBatch() public {
        MultiRecipientSendParam memory p = MultiRecipientSendParam({
            dstChainId: DST_CHAIN_ID,
            recipients: new bytes32[](0),
            tokenIds: new uint256[](0),
            amounts: new uint256[](0)
        });
        vm.expectRevert(IIntexNFT1155Bridge.EmptyBatch.selector);
        vm.prank(sender);
        srcBatch.multiSend{value: FEE}(p);
    }

    function test_MultiSend_RevertsArrayLengthMismatch() public {
        bytes32[] memory recipients = new bytes32[](2);
        recipients[0] = bytes32(uint256(uint160(recipientA)));
        recipients[1] = bytes32(uint256(uint160(recipientB)));

        MultiRecipientSendParam memory p = MultiRecipientSendParam({
            dstChainId: DST_CHAIN_ID,
            recipients: recipients,
            tokenIds: _u256One(TID_A), // length 1 vs 2 recipients
            amounts: _u256(3, 4)
        });
        vm.expectRevert(IIntexNFT1155Bridge.ArrayLengthMismatch.selector);
        vm.prank(sender);
        srcBatch.multiSend{value: FEE}(p);
    }

    function test_MultiSend_RevertsInvalidReceiver_ZeroRecipient() public {
        bytes32[] memory recipients = new bytes32[](1);
        recipients[0] = bytes32(0);

        MultiRecipientSendParam memory p = MultiRecipientSendParam({
            dstChainId: DST_CHAIN_ID, recipients: recipients, tokenIds: _u256One(TID_A), amounts: _u256One(1)
        });
        vm.expectRevert(IIntexNFT1155Bridge.InvalidReceiver.selector);
        vm.prank(sender);
        srcBatch.multiSend{value: FEE}(p);
    }

    function test_QuoteMultiSend_ReturnsNonZeroNativeFee() public view {
        bytes32[] memory recipients = new bytes32[](1);
        recipients[0] = bytes32(uint256(uint160(recipientA)));
        MultiRecipientSendParam memory p = MultiRecipientSendParam({
            dstChainId: DST_CHAIN_ID, recipients: recipients, tokenIds: _u256One(TID_A), amounts: _u256One(1)
        });
        uint256 fee = srcBatch.quoteMultiSend(p);
        assertEq(fee, FEE, "native fee quoted");
    }
}
