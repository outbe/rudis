// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {DeployProxy} from "./helpers/DeployProxy.sol";
import {CreateSeriesLib} from "./helpers/CreateSeriesLib.sol";
import {IIntexNFT1155} from "@contracts/shared/interfaces/IIntexNFT1155.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {Test} from "forge-std/Test.sol";

/// @dev ERC1155 receiver that, during the `onERC1155Received` callback, snapshots
///      `totalSupply(tokenId)` against `balanceOf(self, tokenId)`. After the mint
///      returns, the test asserts the two were equal mid-callback - which holds iff
///      the contract writes `totalSupply` before `_mint` (the read-only-reentrancy guarantee).
contract MidCallbackSnapshotReceiver is IERC1155Receiver {
    IntexNFT1155 public immutable nft;
    uint256 public observedTotalSupply;
    uint256 public observedBalance;
    bool public observed;

    constructor(IntexNFT1155 nft_) {
        nft = nft_;
    }

    function onERC1155Received(address, address, uint256 id, uint256, bytes calldata) external returns (bytes4) {
        observedTotalSupply = nft.totalSupply(id);
        observedBalance = nft.balanceOf(address(this), id);
        observed = true;
        return IERC1155Receiver.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] calldata ids, uint256[] calldata, bytes calldata)
        external
        returns (bytes4)
    {
        // Snapshot the last id in the batch - the mid-callback inconsistency exists
        // after the full _mint loop, before the post-loop totalSupply write.
        uint256 last = ids[ids.length - 1];
        observedTotalSupply = nft.totalSupply(last);
        observedBalance = nft.balanceOf(address(this), last);
        observed = true;
        return IERC1155Receiver.onERC1155BatchReceived.selector;
    }

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IERC1155Receiver).interfaceId;
    }
}

contract IntexNFT1155Test is Test {
    IntexNFT1155 nft;
    address admin = address(1);
    address bridger = address(4);
    address user = address(5);
    address user2 = address(6);

    uint32 constant SERIES_ID_1_DAY = 20250101;
    bytes14 constant SERIES_ID_1 = "20250101-USD-U";
    uint32 constant SERIES_ID_2_DAY = 20250102;
    bytes14 constant SERIES_ID_2 = "20250102-USD-U";
    uint32 constant SERIES_ID_3_DAY = 20250103;
    bytes14 constant SERIES_ID_3 = "20250103-USD-U";
    uint256 constant TOKEN_ID_1 = uint256(uint112(SERIES_ID_1));
    uint256 constant TOKEN_ID_2 = uint256(uint112(SERIES_ID_2));
    uint256 constant TOKEN_ID_3 = uint256(uint112(SERIES_ID_3));

    /// @dev Sized well above every per-mint quantity in this suite so existing tests
    ///      exercise lifecycle and bridge behavior independently of the supply cap.
    ///      Dedicated cap coverage lives in `IntexNFT1155.supply.t.sol`.
    uint32 constant ISSUED_INTEX_COUNT = 10_000;

    function setUp() public {
        nft = DeployProxy.intexNFT1155(admin, bridger);
    }

    /// @dev Create a series with the standard parameters and a given call period.
    function _createSeries(uint32 worldwideDay, uint32 callPeriod) internal {
        vm.prank(bridger);
        nft.createSeries(CreateSeriesLib.params(worldwideDay, ISSUED_INTEX_COUNT, callPeriod));
    }

    function test_InitialState() public view {
        assertTrue(nft.hasRole(nft.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(nft.hasRole(nft.RELAYER_ROLE(), bridger));
    }

    function test_CreateSeries() public {
        uint32 callPeriod = uint32(30 days);
        vm.prank(bridger);
        nft.createSeries(CreateSeriesLib.params(SERIES_ID_1_DAY, ISSUED_INTEX_COUNT, callPeriod));

        IIntexNFT1155.SeriesData memory data = nft.readData(SERIES_ID_1);
        assertEq(uint8(data.state), uint8(IIntexNFT1155.IntexState.Issued));
        assertEq(uint8(data.status), uint8(IIntexNFT1155.IntexStatus.Issued));
        assertEq(data.issuedAt, block.timestamp);
        assertEq(data.calledAt, 0);
        assertEq(data.totalSupply, 0);
        assertEq(data.issuedIntexCount, ISSUED_INTEX_COUNT);
        // callPeriod is stored verbatim; defaulting/bounding is the caller's (intexfactory) responsibility.
        assertEq(data.callTrigger.callNoticePeriod, callPeriod);
    }

    function test_OnlyBridgeCanCreateSeries() public {
        vm.prank(user);
        vm.expectRevert();
        nft.createSeries(CreateSeriesLib.params(SERIES_ID_1_DAY, ISSUED_INTEX_COUNT, 0));
    }

    function test_CreateSeriesDuplicate() public {
        _createSeries(SERIES_ID_1_DAY, 0);

        vm.prank(bridger);
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.TokenAlreadyExists.selector, TOKEN_ID_1));
        nft.createSeries(CreateSeriesLib.params(SERIES_ID_1_DAY, ISSUED_INTEX_COUNT, 0));
    }

    function test_CreateSeries_RecordsWorldwideDay() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        _createSeries(SERIES_ID_2_DAY, 0);

        assertEq(nft.worldwideDayOf(SERIES_ID_1), SERIES_ID_1_DAY);
        bytes14[] memory ids = nft.seriesIdsByWorldwideDay(SERIES_ID_1_DAY);
        assertEq(ids.length, 1);
        assertEq(ids[0], SERIES_ID_1);
        assertEq(nft.seriesIdsByWorldwideDay(SERIES_ID_2_DAY)[0], SERIES_ID_2);
    }

    /// @dev The day is stored verbatim, not inferred from `seriesId`: prove it with distinct values so a future
    ///      composite seriesId (many series per day) records the real day. Fails if provenance reads `params.seriesId`.
    function test_CreateSeries_StoresRealDay_DistinctFromSeriesId() public {
        bytes14 seriesId = "20250505-TRY-U";
        uint32 worldwideDay = 20260101;
        IIntexNFT1155.CreateSeriesParams memory p = CreateSeriesLib.params(worldwideDay, ISSUED_INTEX_COUNT, 0);
        p.seriesId = seriesId; // the id's own day differs from the provenance day
        vm.prank(bridger);
        nft.createSeries(p);

        assertEq(nft.worldwideDayOf(seriesId), worldwideDay, "day stored verbatim");
        bytes14[] memory ids = nft.seriesIdsByWorldwideDay(worldwideDay);
        assertEq(ids.length, 1);
        assertEq(ids[0], seriesId, "day indexes the series id");
        assertEq(nft.seriesIdsByWorldwideDay(20250505).length, 0, "the id's own day is not a provenance key");
    }

    function test_Issue() public {
        uint256 quantity = 10;

        _createSeries(SERIES_ID_1_DAY, 0);
        vm.prank(bridger);
        nft.issue(user, quantity, SERIES_ID_1);

        assertEq(nft.balanceOf(user, TOKEN_ID_1), quantity);
        assertEq(nft.readData(SERIES_ID_1).totalSupply, quantity);
    }

    function test_OnlyBridgeCanIssue() public {
        _createSeries(SERIES_ID_1_DAY, 0);

        vm.prank(user);
        vm.expectRevert();
        nft.issue(user, 10, SERIES_ID_1);
    }

    function test_IssueToZeroAddress() public {
        _createSeries(SERIES_ID_1_DAY, 0);

        vm.prank(bridger);
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.ZeroAddress.selector, "to", address(0)));
        nft.issue(address(0), 10, SERIES_ID_1);
    }

    function test_IssueNonexistentSeries() public {
        vm.prank(bridger);
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.NonexistentToken.selector, TOKEN_ID_1));
        nft.issue(user, 10, SERIES_ID_1);
    }

    function test_IssueQuantityTooLarge() public {
        _createSeries(SERIES_ID_1_DAY, 0);

        uint256 tooLarge = uint256(type(uint16).max) + 1;
        vm.prank(bridger);
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.QuantityTooLarge.selector, tooLarge));
        nft.issue(user, tooLarge, SERIES_ID_1);
    }

    function test_AuctionWonCount_SingleIssue() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.prank(bridger);
        nft.issue(user, 10, SERIES_ID_1);

        // Auction won count should be recorded.
        assertEq(nft.getAuctionWonCount(SERIES_ID_1, user), 10);
        // Non-minted address should return 0.
        assertEq(nft.getAuctionWonCount(SERIES_ID_1, user2), 0);
    }

    function test_AuctionWonCount_UnchangedAfterTransfer() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.prank(bridger);
        nft.issue(user, 10, SERIES_ID_1);

        // Transfer some tokens to user2.
        vm.prank(user);
        nft.safeTransferFrom(user, user2, TOKEN_ID_1, 3, "");

        // Auction won count should remain unchanged for user.
        assertEq(nft.getAuctionWonCount(SERIES_ID_1, user), 10);
        // user2 received via transfer, not mint - should be 0.
        assertEq(nft.getAuctionWonCount(SERIES_ID_1, user2), 0);

        // Current balances are different from initial.
        assertEq(nft.balanceOf(user, TOKEN_ID_1), 7);
        assertEq(nft.balanceOf(user2, TOKEN_ID_1), 3);
    }

    function test_MarkCalled() public {
        uint32 customCallPeriod = uint32(14 days);
        uint32 calledAt = uint32(block.timestamp);

        _createSeries(SERIES_ID_1_DAY, customCallPeriod);
        vm.prank(bridger);
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));

        IIntexNFT1155.SeriesData memory data = nft.readData(SERIES_ID_1);
        assertEq(uint8(data.state), uint8(IIntexNFT1155.IntexState.Called));
        assertEq(data.calledAt, calledAt);
        assertEq(data.callTrigger.callNoticePeriod, customCallPeriod);
        assertEq(data.calledAt + data.callTrigger.callNoticePeriod, calledAt + customCallPeriod);
    }

    function test_OnlyBridgeCanMarkCalled() public {
        _createSeries(SERIES_ID_1_DAY, 0);

        vm.prank(user);
        vm.expectRevert();
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
    }

    function test_MarkCalledNonexistentToken() public {
        vm.prank(bridger);
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.NonexistentToken.selector, TOKEN_ID_1));
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
    }

    function test_MarkCalledInvalidState() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.startPrank(bridger);
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
        // Re-calling on an already Called series surfaces the canonical "Qualified expected" hint.
        vm.expectRevert(
            abi.encodeWithSelector(
                IIntexNFT1155.InvalidState.selector,
                uint8(IIntexNFT1155.IntexState.Qualified),
                uint8(IIntexNFT1155.IntexState.Called)
            )
        );
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
        vm.stopPrank();
    }

    function test_MarkQualifiedTransitions() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.prank(bridger);
        nft.markQualified(SERIES_ID_1);

        IIntexNFT1155.SeriesData memory data = nft.readData(SERIES_ID_1);
        assertEq(uint8(data.state), uint8(IIntexNFT1155.IntexState.Qualified));
        assertEq(data.calledAt, 0);
    }

    function test_MarkCalledFromQualified() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.startPrank(bridger);
        nft.markQualified(SERIES_ID_1);
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
        vm.stopPrank();

        IIntexNFT1155.SeriesData memory data = nft.readData(SERIES_ID_1);
        assertEq(uint8(data.state), uint8(IIntexNFT1155.IntexState.Called));
        assertEq(data.calledAt, uint32(block.timestamp));
    }

    function test_MarkQualifiedRevertsFromCalled() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.startPrank(bridger);
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
        vm.expectRevert(
            abi.encodeWithSelector(
                IIntexNFT1155.InvalidState.selector,
                uint8(IIntexNFT1155.IntexState.Issued),
                uint8(IIntexNFT1155.IntexState.Called)
            )
        );
        nft.markQualified(SERIES_ID_1);
        vm.stopPrank();
    }

    function test_CrosschainBurnNonexistentToken() public {
        vm.prank(bridger);
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.NonexistentToken.selector, TOKEN_ID_1));
        nft.crosschainBurn(user, user, TOKEN_ID_1, 5);
    }

    function test_CrosschainBurnAndMint_AllowedInIssuedState() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.startPrank(bridger);
        nft.issue(user, 10, SERIES_ID_1);

        // Voluntary bridging is open while the series is tradable (Issued): burn out...
        nft.crosschainBurn(user, user, TOKEN_ID_1, 4);
        assertEq(nft.balanceOf(user, TOKEN_ID_1), 6);

        // ...and mint in (the destination side of the same hop).
        nft.crosschainMint(user2, TOKEN_ID_1, 4);
        assertEq(nft.balanceOf(user2, TOKEN_ID_1), 4);
        vm.stopPrank();
    }

    function test_CrosschainBurn_AllowedInQualifiedAndCalled_ForSystemRelayer() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.startPrank(bridger);
        nft.issue(user, 10, SERIES_ID_1);

        nft.markQualified(SERIES_ID_1);
        nft.crosschainBurn(user, user, TOKEN_ID_1, 3);
        assertEq(nft.balanceOf(user, TOKEN_ID_1), 7);

        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
        nft.crosschainBurn(user, user, TOKEN_ID_1, 2);
        assertEq(nft.balanceOf(user, TOKEN_ID_1), 5);
        vm.stopPrank();
    }

    /// @dev In Called the gate is the holder, not the caller: any relayer may move a balance, but only
    ///      back to the same holder.
    function test_CrosschainBurn_InCalled_RefusesAChangeOfHolder() public {
        address plainRelayer = address(0x9999);
        vm.startPrank(admin);
        nft.grantRole(nft.RELAYER_ROLE(), plainRelayer);
        vm.stopPrank();

        _createSeries(SERIES_ID_1_DAY, 0);
        vm.startPrank(bridger);
        nft.issue(user, 10, SERIES_ID_1);
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
        vm.stopPrank();

        vm.prank(plainRelayer);
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.TransferOnCalledForbidden.selector, TOKEN_ID_1));
        nft.crosschainBurn(user, user2, TOKEN_ID_1, 1);

        vm.prank(plainRelayer);
        nft.crosschainBurn(user, user, TOKEN_ID_1, 1);
        assertEq(nft.balanceOf(user, TOKEN_ID_1), 9, "the holder may still carry their own balance");
    }

    function test_ReadData() public {
        vm.prank(bridger);
        nft.createSeries(CreateSeriesLib.params(SERIES_ID_1_DAY, ISSUED_INTEX_COUNT, 0));

        IIntexNFT1155.SeriesData memory data = nft.readData(SERIES_ID_1);
        assertEq(uint8(data.state), uint8(IIntexNFT1155.IntexState.Issued));
    }

    function test_ReadDataNonexistentToken() public {
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.NonexistentToken.selector, TOKEN_ID_1));
        nft.readData(SERIES_ID_1);
    }

    function test_TransferRestrictions() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.prank(bridger);
        nft.issue(user, 10, SERIES_ID_1);

        // Token should be transferable in Issued state.
        vm.prank(user);
        nft.safeTransferFrom(user, user2, TOKEN_ID_1, 5, "");
        assertEq(nft.balanceOf(user, TOKEN_ID_1), 5);
        assertEq(nft.balanceOf(user2, TOKEN_ID_1), 5);

        // Transfer back to user for next test.
        vm.prank(user2);
        nft.safeTransferFrom(user2, user, TOKEN_ID_1, 5, "");

        // Still transferable in Qualified state.
        vm.prank(bridger);
        nft.markQualified(SERIES_ID_1);
        vm.prank(user);
        nft.safeTransferFrom(user, user2, TOKEN_ID_1, 2, "");
        assertEq(nft.balanceOf(user2, TOKEN_ID_1), 2);

        // Mark as called.
        vm.prank(bridger);
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));

        // Called freezes holder-to-holder transfers: the settlement obligation
        // stays with the holder and cannot be passed on.
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.TransferOnCalledForbidden.selector, TOKEN_ID_1));
        nft.safeTransferFrom(user, user2, TOKEN_ID_1, 3, "");
    }

    function test_TransferRestrictionsIssued() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.prank(bridger);
        nft.issue(user, 10, SERIES_ID_1);

        // Token should be transferable in Issued state.
        vm.prank(user);
        nft.safeTransferFrom(user, user2, TOKEN_ID_1, 5, "");
        assertEq(nft.balanceOf(user, TOKEN_ID_1), 5);
        assertEq(nft.balanceOf(user2, TOKEN_ID_1), 5);
    }

    function test_Events() public {
        uint256 quantity = 10;
        uint32 customCallPeriod = uint32(14 days);
        uint32 callDeadlineAt = uint32(block.timestamp + 14 days);

        vm.startPrank(bridger);
        vm.expectEmit();
        emit IIntexNFT1155.MetadataUpdate(TOKEN_ID_1);
        nft.createSeries(CreateSeriesLib.params(SERIES_ID_1_DAY, ISSUED_INTEX_COUNT, customCallPeriod));

        vm.expectEmit(true, true, true, true);
        emit IIntexNFT1155.IntexIssued(bridger, TOKEN_ID_1, user, quantity);
        nft.issue(user, quantity, SERIES_ID_1);

        vm.expectEmit(true, true, false, true);
        emit IIntexNFT1155.IntexStatusUpdated(
            bridger,
            TOKEN_ID_1,
            IIntexNFT1155.IntexState.Issued,
            IIntexNFT1155.IntexState.Called,
            uint32(block.timestamp),
            callDeadlineAt
        );
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
        vm.stopPrank();
    }

    function test_TokenIds_PairAndStatus() public {
        _createSeries(SERIES_ID_1_DAY, 0);

        (uint256 issued, uint256 settled) = nft.tokenIds(SERIES_ID_1);
        assertEq(issued, uint256(uint112(SERIES_ID_1)));
        assertEq(issued, nft.issuedTokenId(SERIES_ID_1));
        assertEq(settled, nft.settledTokenId(SERIES_ID_1));
        assertTrue(issued != settled, "issued and settled ids differ");

        assertEq(uint8(nft.statusOf(issued)), uint8(IIntexNFT1155.IntexStatus.Issued));
        assertEq(uint8(nft.statusOf(settled)), uint8(IIntexNFT1155.IntexStatus.Settled));
    }

    function test_BatchTransferRestrictions() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        _createSeries(SERIES_ID_2_DAY, 0);
        vm.startPrank(bridger);
        nft.issue(user, 10, SERIES_ID_1);
        nft.issue(user, 10, SERIES_ID_2);

        // Mark one as called.
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
        vm.stopPrank();

        uint256[] memory ids = new uint256[](2);
        ids[0] = TOKEN_ID_1;
        ids[1] = TOKEN_ID_2;

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 5;
        amounts[1] = 5;

        // A batch containing a Called series id reverts atomically.
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.TransferOnCalledForbidden.selector, TOKEN_ID_1));
        nft.safeBatchTransferFrom(user, user2, ids, amounts, "");

        // The non-Called series still transfers on its own.
        vm.prank(user);
        nft.safeTransferFrom(user, user2, TOKEN_ID_2, 5, "");
        assertEq(nft.balanceOf(user2, TOKEN_ID_1), 0);
        assertEq(nft.balanceOf(user2, TOKEN_ID_2), 5);
    }

    // --- Tests for CrosschainBurn/CrosschainMint ---
    function test_CrosschainBurn() public {
        uint256 quantity = 10;
        uint256 burnAmount = 5;

        _createSeries(SERIES_ID_1_DAY, 0);
        vm.startPrank(bridger);
        nft.issue(user, quantity, SERIES_ID_1);
        nft.markQualified(SERIES_ID_1);
        nft.crosschainBurn(user, user, TOKEN_ID_1, burnAmount);
        vm.stopPrank();

        assertEq(nft.balanceOf(user, TOKEN_ID_1), quantity - burnAmount);
    }

    function test_CrosschainBurnInCalledState() public {
        uint256 quantity = 10;
        uint256 burnAmount = 5;

        _createSeries(SERIES_ID_1_DAY, 0);
        vm.startPrank(bridger);
        nft.issue(user, quantity, SERIES_ID_1);
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
        nft.crosschainBurn(user, user, TOKEN_ID_1, burnAmount);
        vm.stopPrank();

        assertEq(nft.balanceOf(user, TOKEN_ID_1), quantity - burnAmount);
    }

    function test_OnlyBridgeCanCrosschainBurn() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.prank(bridger);
        nft.issue(user, 10, SERIES_ID_1);

        vm.prank(user);
        vm.expectRevert();
        nft.crosschainBurn(user, user, TOKEN_ID_1, 5);
    }

    function test_CrosschainMint() public {
        uint256 mintAmount = 10;

        _createSeries(SERIES_ID_1_DAY, 0);
        vm.startPrank(bridger);
        nft.markQualified(SERIES_ID_1);
        nft.crosschainMint(user, TOKEN_ID_1, mintAmount);
        vm.stopPrank();

        assertEq(nft.balanceOf(user, TOKEN_ID_1), mintAmount);
    }

    function test_CrosschainMintInCalledState() public {
        uint256 mintAmount = 10;

        _createSeries(SERIES_ID_1_DAY, 0);
        vm.startPrank(bridger);
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
        nft.crosschainMint(user, TOKEN_ID_1, mintAmount);
        vm.stopPrank();

        assertEq(nft.balanceOf(user, TOKEN_ID_1), mintAmount);
    }

    function test_CrosschainBurn_RevertsAfterDeadline() public {
        uint32 callPeriod = uint32(14 days);
        _createSeries(SERIES_ID_1_DAY, callPeriod);
        vm.startPrank(bridger);
        nft.issue(user, 10, SERIES_ID_1);
        uint32 calledAt = uint32(block.timestamp);
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
        uint32 deadline = calledAt + callPeriod;

        // One second past the settlement deadline: the holder is frozen out too.
        vm.warp(uint256(deadline) + 1);
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.BridgeAfterDeadline.selector, TOKEN_ID_1, deadline));
        nft.crosschainBurn(user, user, TOKEN_ID_1, 5);
        vm.stopPrank();
    }

    function test_CrosschainMint_RevertsAfterDeadline() public {
        uint32 callPeriod = uint32(14 days);
        _createSeries(SERIES_ID_1_DAY, callPeriod);
        vm.startPrank(bridger);
        uint32 calledAt = uint32(block.timestamp);
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
        uint32 deadline = calledAt + callPeriod;

        // Mirror of crosschainBurn: crosschainMint cannot re-inflate supply after the window closes.
        vm.warp(uint256(deadline) + 1);
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.BridgeAfterDeadline.selector, TOKEN_ID_1, deadline));
        nft.crosschainMint(user, TOKEN_ID_1, 10);
        vm.stopPrank();
    }

    function test_CrosschainBurn_AllowedAtDeadlineBoundary() public {
        uint32 callPeriod = uint32(14 days);
        _createSeries(SERIES_ID_1_DAY, callPeriod);
        vm.startPrank(bridger);
        nft.issue(user, 10, SERIES_ID_1);
        uint32 calledAt = uint32(block.timestamp);
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
        uint32 deadline = calledAt + callPeriod;

        // Exactly at the deadline is still inside the window (the gate is strict `>`).
        vm.warp(deadline);
        nft.crosschainBurn(user, user, TOKEN_ID_1, 5);
        vm.stopPrank();

        assertEq(nft.balanceOf(user, TOKEN_ID_1), 5);
    }

    function test_OnlyBridgeCanCrosschainMint() public {
        _createSeries(SERIES_ID_1_DAY, 0);

        vm.prank(user);
        vm.expectRevert();
        nft.crosschainMint(user, TOKEN_ID_1, 10);
    }

    function test_CrosschainMintRevertsNonexistentSeries() public {
        vm.prank(bridger);
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.NonexistentToken.selector, TOKEN_ID_1));
        nft.crosschainMint(user, TOKEN_ID_1, 10);
    }

    // --- Tests for two-token model (Issued + Settled) ---

    /// @dev Helper: grant SETTLEMENT_ROLE on the deployed Intex contract to `account`.
    function _grantSettlementRole(address account) internal {
        bytes32 role = nft.SETTLEMENT_ROLE();
        vm.prank(admin);
        nft.grantRole(role, account);
    }

    /// @dev Helper: grant PROMIS_ROLE on the deployed Intex contract to `account`.
    function _grantPromisRole(address account) internal {
        bytes32 role = nft.PROMIS_ROLE();
        vm.prank(admin);
        nft.grantRole(role, account);
    }

    /// @dev Helper: grant GEM_ROLE on the deployed Intex contract to `account`.
    function _grantGemRole(address account) internal {
        bytes32 role = nft.GEM_ROLE();
        vm.prank(admin);
        nft.grantRole(role, account);
    }

    function test_Settle_BurnsIssued_IssuesSettled() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.startPrank(bridger);
        nft.issue(user, 10, SERIES_ID_1);
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
        vm.stopPrank();

        // Grant SETTLEMENT_ROLE to this test for direct settle invocation.
        _grantSettlementRole(address(this));
        nft.settle(SERIES_ID_1, user, user, 4);

        (uint256 issued, uint256 settled) = nft.tokenIds(SERIES_ID_1);
        assertEq(nft.balanceOf(user, issued), 6, "Issued drained by settled amount");
        assertEq(nft.balanceOf(user, settled), 4, "Settled minted to same holder");
        assertEq(nft.totalSupply(issued), 6);
        assertEq(nft.totalSupply(settled), 4);

        IIntexNFT1155.HolderBalances memory bals = nft.holderBalances(SERIES_ID_1, user);
        assertEq(bals.issued, 6);
        assertEq(bals.settled, 4);
    }

    function test_HolderBalances_AboveUint16NoTruncation() public {
        // Drive a single holder above type(uint16).max via two sub-cap mints (each <= 65_535).
        uint32 bigCap = 100_000;
        vm.startPrank(bridger);
        nft.createSeries(CreateSeriesLib.params(SERIES_ID_1_DAY, bigCap, uint32(21 days)));
        nft.issue(user, 40_000, SERIES_ID_1);
        nft.issue(user, 40_000, SERIES_ID_1);
        vm.stopPrank();

        // 80_000 would wrap to 14_464 under the old uint16 field; the widened field must not truncate.
        IIntexNFT1155.HolderBalances memory bals = nft.holderBalances(SERIES_ID_1, user);
        assertEq(bals.issued, 80_000);
        assertEq(bals.settled, 0);
    }

    function test_Settle_RevertsInIssued() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        _grantSettlementRole(address(this));

        vm.expectRevert(
            abi.encodeWithSelector(IIntexNFT1155.InvalidStateForSettle.selector, uint8(IIntexNFT1155.IntexState.Issued))
        );
        nft.settle(SERIES_ID_1, user, user, 1);
    }

    function test_Settle_OnlySettlementRole() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        // Bridger has RELAYER_ROLE only - settle must reject.
        vm.expectRevert();
        vm.prank(bridger);
        nft.settle(SERIES_ID_1, user, user, 1);
    }

    function test_Settle_EmitsIntexSettled() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.startPrank(bridger);
        nft.issue(user, 10, SERIES_ID_1);
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
        vm.stopPrank();
        _grantSettlementRole(address(this));

        vm.expectEmit(true, true, false, true);
        emit IIntexNFT1155.IntexSettled(SERIES_ID_1, user, 4);
        nft.settle(SERIES_ID_1, user, user, 4);
    }

    function test_Settled_IsSoulbound() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.startPrank(bridger);
        nft.issue(user, 10, SERIES_ID_1);
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
        vm.stopPrank();
        _grantSettlementRole(address(this));
        nft.settle(SERIES_ID_1, user, user, 5);

        uint256 sTok = nft.settledTokenId(SERIES_ID_1);
        // Settled cannot be transferred to another holder.
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.SoulboundSettled.selector, sTok));
        nft.safeTransferFrom(user, user2, sTok, 1, "");
    }

    function test_BurnSettled_OnlyPromisRole() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.startPrank(bridger);
        nft.issue(user, 10, SERIES_ID_1);
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
        vm.stopPrank();
        _grantSettlementRole(address(this));
        nft.settle(SERIES_ID_1, user, user, 5);

        // Without PROMIS_ROLE, burnSettled reverts.
        vm.expectRevert();
        nft.burnSettled(user, SERIES_ID_1, 1);

        _grantPromisRole(address(this));

        uint256 sTok = nft.settledTokenId(SERIES_ID_1);
        vm.expectEmit(true, true, false, true);
        emit IIntexNFT1155.IntexCompleted(SERIES_ID_1, user, 3);
        nft.burnSettled(user, SERIES_ID_1, 3);

        assertEq(nft.balanceOf(user, sTok), 2);
        assertEq(nft.totalSupply(sTok), 2);
    }

    function test_Settle_RevertsAfterDeadline() public {
        uint32 callPeriod = uint32(14 days);
        _createSeries(SERIES_ID_1_DAY, callPeriod);
        vm.startPrank(bridger);
        nft.issue(user, 10, SERIES_ID_1);
        uint32 calledAt = uint32(block.timestamp);
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
        vm.stopPrank();
        uint32 deadline = calledAt + callPeriod;

        _grantSettlementRole(address(this));
        // One second past the call window: no new Settled tokens may be minted.
        vm.warp(uint256(deadline) + 1);
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.SettleAfterDeadline.selector, TOKEN_ID_1, deadline));
        nft.settle(SERIES_ID_1, user, user, 4);
    }

    function test_Settle_AllowedAtDeadlineBoundary() public {
        uint32 callPeriod = uint32(14 days);
        _createSeries(SERIES_ID_1_DAY, callPeriod);
        vm.startPrank(bridger);
        nft.issue(user, 10, SERIES_ID_1);
        uint32 calledAt = uint32(block.timestamp);
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
        vm.stopPrank();
        uint32 deadline = calledAt + callPeriod;

        _grantSettlementRole(address(this));
        // Exactly at the deadline is still inside the window (the gate is strict `>`).
        vm.warp(deadline);
        nft.settle(SERIES_ID_1, user, user, 4);

        (uint256 issued, uint256 settled) = nft.tokenIds(SERIES_ID_1);
        assertEq(nft.balanceOf(user, issued), 6);
        assertEq(nft.balanceOf(user, settled), 4);
    }

    function test_Settle_QualifiedNotDeadlineGated() public {
        uint32 callPeriod = uint32(14 days);
        _createSeries(SERIES_ID_1_DAY, callPeriod);
        vm.startPrank(bridger);
        nft.issue(user, 10, SERIES_ID_1);
        nft.markQualified(SERIES_ID_1);
        vm.stopPrank();

        _grantSettlementRole(address(this));
        // Qualified series have no call deadline (`calledAt == 0`), so settle is time-independent.
        vm.warp(block.timestamp + 3650 days);
        nft.settle(SERIES_ID_1, user, user, 4);

        (, uint256 settled) = nft.tokenIds(SERIES_ID_1);
        assertEq(nft.balanceOf(user, settled), 4);
    }

    function test_BurnSettled_AllowedAfterDeadline() public {
        uint32 callPeriod = uint32(14 days);
        _createSeries(SERIES_ID_1_DAY, callPeriod);
        vm.startPrank(bridger);
        nft.issue(user, 10, SERIES_ID_1);
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
        vm.stopPrank();

        _grantSettlementRole(address(this));
        _grantPromisRole(address(this));
        // Redeem after the window: the exit stays open so a settled holder is never trapped.
        uint32 deadline = uint32(block.timestamp) + callPeriod;
        nft.settle(SERIES_ID_1, user, user, 5);

        vm.warp(uint256(deadline) + 1);
        nft.burnSettled(user, SERIES_ID_1, 5);

        assertEq(nft.balanceOf(user, nft.settledTokenId(SERIES_ID_1)), 0);
    }

    // --- Tests for parkIntex (Gem Factory parking) ---

    function test_ParkIntex_BurnsIssued() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.prank(bridger);
        nft.issue(user, 10, SERIES_ID_1);
        _grantGemRole(address(this));

        vm.expectEmit(true, true, false, true);
        emit IIntexNFT1155.IntexParked(SERIES_ID_1, user, 4);
        nft.parkIntex(user, SERIES_ID_1, 4);

        assertEq(nft.balanceOf(user, TOKEN_ID_1), 6);
        assertEq(nft.totalSupply(TOKEN_ID_1), 6);
    }

    function test_ParkIntex_AllowedInQualified() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.startPrank(bridger);
        nft.issue(user, 10, SERIES_ID_1);
        nft.markQualified(SERIES_ID_1);
        vm.stopPrank();
        _grantGemRole(address(this));

        nft.parkIntex(user, SERIES_ID_1, 10);

        assertEq(nft.balanceOf(user, TOKEN_ID_1), 0);
        assertEq(nft.totalSupply(TOKEN_ID_1), 0);
    }

    function test_ParkIntex_OnlyGemRole() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.prank(bridger);
        nft.issue(user, 10, SERIES_ID_1);

        vm.prank(bridger);
        vm.expectRevert();
        nft.parkIntex(user, SERIES_ID_1, 1);
    }

    function test_ParkIntex_RevertsWhenCalled() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.startPrank(bridger);
        nft.issue(user, 10, SERIES_ID_1);
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
        vm.stopPrank();
        _grantGemRole(address(this));

        vm.expectRevert(
            abi.encodeWithSelector(
                IIntexNFT1155.InvalidState.selector,
                uint8(IIntexNFT1155.IntexState.Qualified),
                uint8(IIntexNFT1155.IntexState.Called)
            )
        );
        nft.parkIntex(user, SERIES_ID_1, 1);
    }

    function test_ParkIntex_RevertsOnNonexistentSeries() public {
        _grantGemRole(address(this));
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.NonexistentToken.selector, TOKEN_ID_1));
        nft.parkIntex(user, SERIES_ID_1, 1);
    }

    function test_ParkIntex_RevertsOnZeroAmount() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        _grantGemRole(address(this));
        vm.expectRevert(IIntexNFT1155.ZeroAmount.selector);
        nft.parkIntex(user, SERIES_ID_1, 0);
    }

    function test_ParkIntex_RevertsOnZeroHolder() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        _grantGemRole(address(this));
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.ZeroAddress.selector, "holder", address(0)));
        nft.parkIntex(address(0), SERIES_ID_1, 1);
    }

    function test_ParkIntex_RevertsAboveBalance() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.startPrank(bridger);
        nft.issue(user, 5, SERIES_ID_1);
        nft.issue(user2, 5, SERIES_ID_1);
        vm.stopPrank();
        _grantGemRole(address(this));

        // amount <= totalSupply but > holder balance
        vm.expectRevert();
        nft.parkIntex(user, SERIES_ID_1, 6);
    }

    function test_ParkIntex_DoesNotTouchSettled() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.startPrank(bridger);
        nft.issue(user, 10, SERIES_ID_1);
        nft.markQualified(SERIES_ID_1);
        vm.stopPrank();
        _grantSettlementRole(address(this));
        nft.settle(SERIES_ID_1, user, user, 4);
        _grantGemRole(address(this));

        nft.parkIntex(user, SERIES_ID_1, 6);

        (uint256 issued, uint256 settled) = nft.tokenIds(SERIES_ID_1);
        assertEq(nft.balanceOf(user, issued), 0);
        assertEq(nft.balanceOf(user, settled), 4, "Settled balance is out of parking's reach");
        assertEq(nft.totalSupply(settled), 4);
    }

    function test_ParkIntex_FreesCapRoom() public {
        uint32 cap = 10;
        vm.startPrank(bridger);
        nft.createSeries(CreateSeriesLib.params(SERIES_ID_1_DAY, cap, 0));
        nft.issue(user, 10, SERIES_ID_1);
        vm.stopPrank();
        _grantGemRole(address(this));

        nft.parkIntex(user, SERIES_ID_1, 4);

        // Deliberate: the cap is enforced against live totalSupply, so parking frees mint room.
        vm.prank(bridger);
        nft.issue(user2, 4, SERIES_ID_1);
        assertEq(nft.totalSupply(TOKEN_ID_1), 10);
    }

    function test_BridgeOnSettled_Forbidden() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.startPrank(bridger);
        nft.issue(user, 10, SERIES_ID_1);
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
        vm.stopPrank();
        _grantSettlementRole(address(this));
        nft.settle(SERIES_ID_1, user, user, 5);

        uint256 sTok = nft.settledTokenId(SERIES_ID_1);
        // crosschainBurn is gated by RELAYER_ROLE; bridger has it. Even so, Settled ids are rejected.
        vm.prank(bridger);
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.BridgeOnSettledForbidden.selector, sTok));
        nft.crosschainBurn(user, user, sTok, 1);
    }

    // --- Tests for Enumerable Functions ---

    function test_GetAllSeriesAndTotalSeries() public {
        // Initially empty.
        assertEq(nft.totalSeries(), 0);
        uint256[] memory initialSeries = nft.getAllSeries();
        assertEq(initialSeries.length, 0);

        // Create first series.
        _createSeries(SERIES_ID_1_DAY, 0);
        assertEq(nft.totalSeries(), 1);

        // Create second series.
        _createSeries(SERIES_ID_2_DAY, 0);
        assertEq(nft.totalSeries(), 2);

        // Get all series.
        uint256[] memory allSeries = nft.getAllSeries();
        assertEq(allSeries.length, 2);
        assertEq(allSeries[0], TOKEN_ID_1);
        assertEq(allSeries[1], TOKEN_ID_2);
    }

    function test_GetOwnedSeriesAndOwnedSeriesCount() public {
        // Create two series.
        _createSeries(SERIES_ID_1_DAY, 0);
        _createSeries(SERIES_ID_2_DAY, 0);

        // Initially user has no tokens.
        assertEq(nft.ownedSeriesCount(user), 0);
        uint256[] memory initialOwned = nft.getOwnedSeries(user);
        assertEq(initialOwned.length, 0);

        // Mint first series to user.
        vm.prank(bridger);
        nft.issue(user, 10, SERIES_ID_1);
        assertEq(nft.ownedSeriesCount(user), 1);

        // Mint second series to user.
        vm.prank(bridger);
        nft.issue(user, 5, SERIES_ID_2);
        assertEq(nft.ownedSeriesCount(user), 2);

        // Get owned series.
        uint256[] memory ownedSeries = nft.getOwnedSeries(user);
        assertEq(ownedSeries.length, 2);
    }

    function test_TotalBalance() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        _createSeries(SERIES_ID_2_DAY, 0);

        // Initially zero.
        assertEq(nft.totalBalance(user), 0);

        // Mint to user.
        vm.prank(bridger);
        nft.issue(user, 10, SERIES_ID_1);
        assertEq(nft.totalBalance(user), 10);

        vm.prank(bridger);
        nft.issue(user, 5, SERIES_ID_2);
        assertEq(nft.totalBalance(user), 15);

        // Additional mint to same series should add up.
        vm.prank(bridger);
        nft.issue(user, 3, SERIES_ID_1);
        assertEq(nft.totalBalance(user), 18);
    }

    function test_EnumerableUpdateOnFullTransfer() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.prank(bridger);
        nft.issue(user, 10, SERIES_ID_1);

        // User has 1 series, user2 has 0.
        assertEq(nft.ownedSeriesCount(user), 1);
        assertEq(nft.ownedSeriesCount(user2), 0);

        // Transfer all to user2.
        vm.prank(user);
        nft.safeTransferFrom(user, user2, TOKEN_ID_1, 10, "");

        // User should have 0 series now, user2 should have 1.
        assertEq(nft.ownedSeriesCount(user), 0);
        assertEq(nft.ownedSeriesCount(user2), 1);
        assertEq(nft.totalBalance(user), 0);
        assertEq(nft.totalBalance(user2), 10);

        // Verify getOwnedSeries reflects the change.
        uint256[] memory userOwned = nft.getOwnedSeries(user);
        uint256[] memory user2Owned = nft.getOwnedSeries(user2);
        assertEq(userOwned.length, 0);
        assertEq(user2Owned.length, 1);
        assertEq(user2Owned[0], TOKEN_ID_1);
    }

    function test_EnumerablePartialTransfer() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.prank(bridger);
        nft.issue(user, 10, SERIES_ID_1);

        // Partial transfer.
        vm.prank(user);
        nft.safeTransferFrom(user, user2, TOKEN_ID_1, 5, "");

        // Both users should still own the series.
        assertEq(nft.ownedSeriesCount(user), 1);
        assertEq(nft.ownedSeriesCount(user2), 1);
        assertEq(nft.totalBalance(user), 5);
        assertEq(nft.totalBalance(user2), 5);
    }

    function test_EnumerableBurnTracking() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.startPrank(bridger);
        nft.issue(user, 10, SERIES_ID_1);
        nft.markQualified(SERIES_ID_1);
        vm.stopPrank();

        assertEq(nft.ownedSeriesCount(user), 1);
        assertEq(nft.totalBalance(user), 10);

        // Partial burn - should still own the series.
        vm.prank(bridger);
        nft.crosschainBurn(user, user, TOKEN_ID_1, 5);
        assertEq(nft.ownedSeriesCount(user), 1);
        assertEq(nft.totalBalance(user), 5);

        // Full burn - should no longer own the series.
        vm.prank(bridger);
        nft.crosschainBurn(user, user, TOKEN_ID_1, 5);
        assertEq(nft.ownedSeriesCount(user), 0);
        assertEq(nft.totalBalance(user), 0);

        uint256[] memory ownedAfterBurn = nft.getOwnedSeries(user);
        assertEq(ownedAfterBurn.length, 0);
    }

    function test_GetOwnedSeriesWithBalances() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        _createSeries(SERIES_ID_2_DAY, 0);
        vm.startPrank(bridger);
        nft.issue(user, 10, SERIES_ID_1);
        nft.issue(user, 25, SERIES_ID_2);
        vm.stopPrank();

        (uint256[] memory ownedTokenIds, uint256[] memory balances) = nft.getOwnedSeriesWithBalances(user);

        assertEq(ownedTokenIds.length, 2);
        assertEq(balances.length, 2);

        // Check that TOKEN_ID_1 has balance 10 and TOKEN_ID_2 has balance 25.
        for (uint256 i = 0; i < ownedTokenIds.length; i++) {
            if (ownedTokenIds[i] == TOKEN_ID_1) {
                assertEq(balances[i], 10);
            } else if (ownedTokenIds[i] == TOKEN_ID_2) {
                assertEq(balances[i], 25);
            }
        }
    }

    function test_EnumerableMultiHolderIssue() public {
        _createSeries(SERIES_ID_1_DAY, 0);

        vm.startPrank(bridger);
        nft.issue(user, 5, SERIES_ID_1);
        nft.issue(user2, 10, SERIES_ID_1);
        vm.stopPrank();

        assertEq(nft.ownedSeriesCount(user), 1);
        assertEq(nft.ownedSeriesCount(user2), 1);
        assertEq(nft.totalBalance(user), 5);
        assertEq(nft.totalBalance(user2), 10);
    }

    function test_EnumerableMultipleSeries() public {
        // Create 3 series.
        _createSeries(SERIES_ID_1_DAY, 0);
        _createSeries(SERIES_ID_2_DAY, 0);
        _createSeries(SERIES_ID_3_DAY, 0);

        // Mint all 3 to user.
        vm.startPrank(bridger);
        nft.issue(user, 10, SERIES_ID_1);
        nft.issue(user, 20, SERIES_ID_2);
        nft.issue(user, 30, SERIES_ID_3);
        vm.stopPrank();

        assertEq(nft.ownedSeriesCount(user), 3);
        assertEq(nft.totalBalance(user), 60);

        // Transfer middle one completely.
        vm.prank(user);
        nft.safeTransferFrom(user, user2, TOKEN_ID_2, 20, "");

        assertEq(nft.ownedSeriesCount(user), 2);
        assertEq(nft.totalBalance(user), 40);
        assertEq(nft.ownedSeriesCount(user2), 1);
        assertEq(nft.totalBalance(user2), 20);

        // Verify correct series are owned.
        uint256[] memory userOwned = nft.getOwnedSeries(user);
        assertEq(userOwned.length, 2);

        bool hasToken1 = false;
        bool hasToken3 = false;
        for (uint256 i = 0; i < userOwned.length; i++) {
            if (userOwned[i] == TOKEN_ID_1) hasToken1 = true;
            if (userOwned[i] == TOKEN_ID_3) hasToken3 = true;
        }
        assertTrue(hasToken1);
        assertTrue(hasToken3);
    }

    function test_EnumerableCrosschainMintCrosschainBurn() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.prank(bridger);
        nft.markQualified(SERIES_ID_1);

        // Bridge crosschainMint (like receiving from another chain).
        vm.prank(bridger);
        nft.crosschainMint(user, TOKEN_ID_1, 15);
        assertEq(nft.ownedSeriesCount(user), 1);
        assertEq(nft.totalBalance(user), 15);

        // Bridge crosschainBurn partial.
        vm.prank(bridger);
        nft.crosschainBurn(user, user, TOKEN_ID_1, 5);
        assertEq(nft.ownedSeriesCount(user), 1);
        assertEq(nft.totalBalance(user), 10);

        // Bridge crosschainBurn full.
        vm.prank(bridger);
        nft.crosschainBurn(user, user, TOKEN_ID_1, 10);
        assertEq(nft.ownedSeriesCount(user), 0);
        assertEq(nft.totalBalance(user), 0);
    }

    function test_EnumerableNoDuplicates() public {
        _createSeries(SERIES_ID_1_DAY, 0);

        // Mint multiple times to same user.
        vm.startPrank(bridger);
        nft.issue(user, 5, SERIES_ID_1);
        nft.issue(user, 10, SERIES_ID_1);
        nft.issue(user, 15, SERIES_ID_1);
        vm.stopPrank();

        // Should still only have 1 series entry.
        assertEq(nft.ownedSeriesCount(user), 1);
        assertEq(nft.totalBalance(user), 30);

        uint256[] memory ownedSeries = nft.getOwnedSeries(user);
        assertEq(ownedSeries.length, 1);
        assertEq(ownedSeries[0], TOKEN_ID_1);
    }

    function test_BatchTransferWithDuplicateTokenIds() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.prank(bridger);
        nft.issue(user, 10, SERIES_ID_1);

        assertEq(nft.ownedSeriesCount(user), 1);
        assertEq(nft.ownedSeriesCount(user2), 0);

        // Batch transfer with same tokenId twice: [1, 1] with amounts [5, 5].
        uint256[] memory ids = new uint256[](2);
        ids[0] = TOKEN_ID_1;
        ids[1] = TOKEN_ID_1;

        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 5;
        amounts[1] = 5;

        vm.prank(user);
        nft.safeBatchTransferFrom(user, user2, ids, amounts, "");

        // user should have 0 balance and no owned series.
        assertEq(nft.balanceOf(user, TOKEN_ID_1), 0);
        assertEq(nft.ownedSeriesCount(user), 0);
        assertEq(nft.totalBalance(user), 0);

        // user2 should have 10 balance and 1 owned series.
        assertEq(nft.balanceOf(user2, TOKEN_ID_1), 10);
        assertEq(nft.ownedSeriesCount(user2), 1);
        assertEq(nft.totalBalance(user2), 10);

        uint256[] memory user1Owned = nft.getOwnedSeries(user);
        uint256[] memory user2Owned = nft.getOwnedSeries(user2);
        assertEq(user1Owned.length, 0);
        assertEq(user2Owned.length, 1);
        assertEq(user2Owned[0], TOKEN_ID_1);
    }

    // ============================================================
    // Owner-side pagination windows
    // ============================================================

    function test_PaginatedGetters_WindowClipAndTotal() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.prank(bridger);
        nft.issue(user, 10, SERIES_ID_1);

        (uint256[] memory ids, uint256[] memory obal, uint256 ototal) =
            nft.getOwnedSeriesWithBalancesPaginated(user, 0, 10);
        assertEq(ototal, 1);
        assertEq(ids.length, 1);
        assertEq(ids[0], TOKEN_ID_1);
        assertEq(obal[0], 10);
    }

    // ============================================================
    // totalSupply mid-callback consistency (read-only-reentrancy)
    // ============================================================

    function test_Issue_TotalSupplyConsistentMidCallback() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        MidCallbackSnapshotReceiver receiver = new MidCallbackSnapshotReceiver(nft);

        vm.prank(bridger);
        nft.issue(address(receiver), 7, SERIES_ID_1);

        assertTrue(receiver.observed(), "callback did not fire");
        assertEq(receiver.observedBalance(), 7, "balance updated mid-callback");
        assertEq(
            receiver.observedTotalSupply(), receiver.observedBalance(), "totalSupply must equal balance mid-callback"
        );
    }

    function test_CrosschainMint_TotalSupplyConsistentMidCallback() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.prank(bridger);
        nft.markQualified(SERIES_ID_1);

        MidCallbackSnapshotReceiver receiver = new MidCallbackSnapshotReceiver(nft);

        vm.prank(bridger);
        nft.crosschainMint(address(receiver), TOKEN_ID_1, 9);

        assertTrue(receiver.observed(), "callback did not fire");
        assertEq(receiver.observedBalance(), 9, "balance updated mid-callback");
        assertEq(
            receiver.observedTotalSupply(), receiver.observedBalance(), "totalSupply must equal balance mid-callback"
        );
    }

    function test_Settle_TotalSupplyConsistentMidCallback() public {
        _createSeries(SERIES_ID_1_DAY, 0);
        vm.startPrank(bridger);
        nft.issue(user, 10, SERIES_ID_1);
        nft.markCalled(SERIES_ID_1, uint32(block.timestamp));
        vm.stopPrank();
        _grantSettlementRole(address(this));

        MidCallbackSnapshotReceiver receiver = new MidCallbackSnapshotReceiver(nft);
        uint256 sTok = nft.settledTokenId(SERIES_ID_1);
        uint256 iTokSupplyBefore = nft.totalSupply(TOKEN_ID_1);

        nft.settle(SERIES_ID_1, user, address(receiver), 4);

        // Settled mint callback: settled totalSupply must already reflect the new mint.
        assertTrue(receiver.observed(), "callback did not fire");
        assertEq(receiver.observedBalance(), 4, "settled balance updated mid-callback");
        assertEq(receiver.observedTotalSupply(), 4, "settled totalSupply must equal balance mid-callback");

        // And the Issued burn must have happened before the Settled mint - so the
        // Issued totalSupply read inside the callback would also be consistent.
        assertEq(nft.totalSupply(TOKEN_ID_1), iTokSupplyBefore - 4, "issued totalSupply decreased before settled mint");
        assertEq(nft.totalSupply(sTok), 4);
    }
}
