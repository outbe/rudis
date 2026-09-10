// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {MarkBatchLib} from "../helpers/MarkBatchLib.sol";
import {ReferenceCurrencyPriceLib} from "../helpers/ReferenceCurrencyPriceLib.sol";
import {CrossChainTest} from "../helpers/CrossChainTest.sol";

import {OriginRouter} from "@contracts/origin/OriginRouter.sol";
import {TargetRouter} from "@contracts/target/TargetRouter.sol";
import {IntexNFT1155Bridge} from "@contracts/shared/IntexNFT1155Bridge.sol";
import {IOriginRouter} from "@contracts/origin/interfaces/IOriginRouter.sol";
import {MockDesis} from "@test-mocks/MockDesis.sol";

import {IntexAuction} from "@contracts/target/IntexAuction.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";

/**
 * @title OriginRouterTest
 * @notice Foundry tests for OriginRouter
 * @dev Tests message encoding/decoding and access control.
 *      Auction messages are keyed by `worldwideDay`; series (issuance/mark) by `seriesId`.
 */
contract OriginRouterTest is CrossChainTest {
    uint32 private constant BNB_CHAIN_ID = 1;
    uint32 private constant OUTBE_CHAIN_ID = 2;

    OriginRouter private originRouter;
    TargetRouter private targetRouter;
    IntexNFT1155Bridge private nftBridge;

    // Stand-in Desis recipient that advertises `IDesis` via ERC-165 so that
    // `OriginRouter.wire`'s interface probe accepts it.
    address private desis;

    address private intexFactory;

    // Mock BNB contracts
    IntexAuction private auction;
    IntexNFT1155 private intex;

    address private admin = address(this);
    address private user = address(0x1);

    uint32 private constant WORLDWIDE_DAY = 20250115; // yyyymmdd - the auction day (root)
    bytes14 private constant SERIES_ID = "20250115-USD-U";

    function setUp() public {
        _setUpBridge();
        // Positive quote tests assert a non-zero fee; give the loopback bridge a fixed fee to return.
        bridge.setFee(0.001 ether);

        vm.deal(admin, 1000 ether);
        vm.deal(user, 1000 ether);

        // Stand-in Desis recipient.
        desis = address(new MockDesis());
        vm.deal(desis, 1000 ether);
        intexFactory = makeAddr("factory");
        vm.deal(intexFactory, 1000 ether);

        // Deploy mock BNB contracts
        auction = DeployProxy.intexAuction(admin, admin);
        intex = DeployProxy.intexNFT1155(admin, admin);

        // Deploy Outbe adapter
        originRouter = DeployProxy.originRouter(address(bridge), admin);

        // Deploy BNB adapter (for cross-chain testing)
        targetRouter = DeployProxy.targetRouter(address(bridge), admin, OUTBE_CHAIN_ID);

        // Deploy batch adapter on BNB
        nftBridge = DeployProxy.intexNFT1155Bridge(address(intex), address(bridge), admin);

        // Wire adapters (register remote messengers)
        originRouter.setRemoteMessenger(BNB_CHAIN_ID, _interop(BNB_CHAIN_ID, address(targetRouter)));
        targetRouter.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, address(originRouter)));

        // Register BNB as the single auction target and fund the relay float.
        originRouter.addTarget(BNB_CHAIN_ID);
        vm.deal(address(originRouter), 10 ether);

        // Wire Outbe adapter
        originRouter.wire(desis, intexFactory);

        // Wire BNB adapter
        targetRouter.wire(address(auction), address(intex), admin);
    }

    // --- Helpers ---
    /// @dev Build a baseline AuctionStageStartParams payload keyed by WORLDWIDE_DAY.
    function _baseStageStartParams() internal view returns (IOriginRouter.AuctionStageStartParams memory) {
        return IOriginRouter.AuctionStageStartParams({
            worldwideDay: WORLDWIDE_DAY,
            commitEnd: uint32(block.timestamp + 3600),
            revealEnd: uint32(block.timestamp + 5400),
            issuanceEnd: uint32(block.timestamp + 7200),
            promisLoadMinor: 1000,
            minIntexBidRate: 50e6,
            prices: ReferenceCurrencyPriceLib.one(840, 100e6, 50e6, 25e6),
            callNoticePeriod: 0,
            callWindow: 0,
            callThreshold: 0,
            minIntexBidQuantity: 1,
            commitBondMinor: 0,
            dayState: 1
        });
    }

    function _baseIssuanceParams(address[] memory recipients, uint256[] memory quantities)
        internal
        pure
        returns (IOriginRouter.IssuanceInstructionsParams[] memory batch)
    {
        batch = new IOriginRouter.IssuanceInstructionsParams[](1);
        batch[0] = IOriginRouter.IssuanceInstructionsParams({
            seriesId: SERIES_ID,
            worldwideDay: WORLDWIDE_DAY,
            issuedIntexCount: 10_000,
            promisLoadMinor: 1000,
            entryPriceMinor: 100e6,
            floorPriceMinor: 50e6,
            callNoticePeriod: 0,
            issuanceCurrency: 840,
            referenceCurrency: 840,
            callWindow: 30,
            callThreshold: 5,
            callPriceMinor: 25e6,
            recipients: recipients,
            quantities: quantities
        });
    }

    // --- Constructor / registry Tests ---
    function test_constructor() public view {
        assertTrue(originRouter.isTarget(BNB_CHAIN_ID));
        uint32[] memory t = originRouter.targets();
        assertEq(t.length, 1);
        assertEq(t[0], BNB_CHAIN_ID);
        assertTrue(originRouter.hasRole(originRouter.DEFAULT_ADMIN_ROLE(), admin));
    }

    function test_wire() public view {
        assertEq(originRouter.desis(), desis);
        assertTrue(originRouter.hasRole(originRouter.DESIS_ROLE(), desis));
    }

    function test_wire_revert_zero_address() public {
        OriginRouter newRouter = DeployProxy.originRouter(address(bridge), admin);

        vm.expectRevert(abi.encodeWithSelector(IOriginRouter.ZeroAddress.selector, "desis"));
        newRouter.wire(address(0), intexFactory);
    }

    // --- Access Control Tests ---
    function test_sendAuctionStageStart_revert_unauthorized() public {
        vm.prank(user);
        vm.expectRevert();
        originRouter.sendAuctionStageStart{value: 0.1 ether}(_baseStageStartParams());
    }

    function test_sendMarkCalled_revert_unauthorized() public {
        vm.prank(user);
        vm.expectRevert();
        originRouter.sendMarkCalled{value: 0.1 ether}(
            WORLDWIDE_DAY, uint32(block.timestamp), MarkBatchLib.one(SERIES_ID)
        );
    }

    function test_sendAuctionStageClearing_revert_unauthorized() public {
        vm.prank(user);
        vm.expectRevert();
        originRouter.sendAuctionStageClearing{value: 0.1 ether}(WORLDWIDE_DAY);
    }

    function test_sendAuctionResult_revert_unauthorized() public {
        vm.prank(user);
        vm.expectRevert();
        originRouter.sendAuctionResult{value: 0.1 ether}(BNB_CHAIN_ID, WORLDWIDE_DAY, 10_000, 100e6, 50);
    }

    function test_sendIssuanceInstructions_revert_unauthorized() public {
        address[] memory recipients = new address[](1);
        recipients[0] = address(0x1);
        uint256[] memory quantities = new uint256[](1);
        quantities[0] = 1;

        vm.prank(user);
        vm.expectRevert();
        originRouter.sendIssuanceInstructions{value: 0.1 ether}(
            BNB_CHAIN_ID, WORLDWIDE_DAY, 0, 1, _baseIssuanceParams(recipients, quantities)
        );
    }

    function test_sendRefundInstructions_revert_unauthorized() public {
        address[] memory bidders = new address[](1);
        bidders[0] = address(0x1);
        uint128[] memory refundedAmounts = new uint128[](1);
        refundedAmounts[0] = 100e6;
        uint128[] memory paidAmounts = new uint128[](1);
        paidAmounts[0] = 50e6;

        vm.prank(user);
        vm.expectRevert();
        originRouter.sendRefundInstructions{value: 0.1 ether}(
            BNB_CHAIN_ID, WORLDWIDE_DAY, 0, 1, bidders, refundedAmounts, paidAmounts
        );
    }

    function test_sendMarkQualified_revert_unauthorized() public {
        vm.prank(user);
        vm.expectRevert();
        originRouter.sendMarkQualified{value: 0.1 ether}(WORLDWIDE_DAY, MarkBatchLib.one(SERIES_ID));
    }

    // --- Validation Tests ---
    function test_sendIssuanceInstructions_emptyRecipients_ok() public {
        // Empty recipients is valid: a snapshot chain with no local winners still gets its series created.
        // Fire STAGE_START first so the day's target snapshot exists for the membership check.
        vm.prank(desis);
        originRouter.sendAuctionStageStart(_baseStageStartParams());

        address[] memory recipients = new address[](0);
        uint256[] memory quantities = new uint256[](0);

        vm.prank(intexFactory);
        originRouter.sendIssuanceInstructions(
            BNB_CHAIN_ID, WORLDWIDE_DAY, 0, 1, _baseIssuanceParams(recipients, quantities)
        );
    }

    function test_sendIssuanceInstructions_revert_array_length_mismatch() public {
        vm.prank(desis);
        originRouter.sendAuctionStageStart(_baseStageStartParams());

        address[] memory recipients = new address[](2);
        uint256[] memory quantities = new uint256[](1); // Mismatch

        recipients[0] = address(0x1);
        recipients[1] = address(0x2);
        quantities[0] = 10;

        vm.prank(intexFactory);
        vm.expectRevert(IOriginRouter.ArrayLengthMismatch.selector);
        originRouter.sendIssuanceInstructions{value: 0.1 ether}(
            BNB_CHAIN_ID, WORLDWIDE_DAY, 0, 1, _baseIssuanceParams(recipients, quantities)
        );
    }

    function test_sendRefundInstructions_revert_empty_array() public {
        address[] memory bidders = new address[](0);
        uint128[] memory refundedAmounts = new uint128[](0);
        uint128[] memory paidAmounts = new uint128[](0);

        vm.prank(desis);
        vm.expectRevert(IOriginRouter.EmptyArray.selector);
        originRouter.sendRefundInstructions{value: 0.1 ether}(
            BNB_CHAIN_ID, WORLDWIDE_DAY, 0, 1, bidders, refundedAmounts, paidAmounts
        );
    }

    function test_sendRefundInstructions_revert_array_length_mismatch() public {
        address[] memory bidders = new address[](2);
        uint128[] memory refundedAmounts = new uint128[](2);
        uint128[] memory paidAmounts = new uint128[](1); // Mismatch

        bidders[0] = address(0x1);
        bidders[1] = address(0x2);
        refundedAmounts[0] = 100e6;
        refundedAmounts[1] = 200e6;
        paidAmounts[0] = 50e6;

        vm.prank(desis);
        vm.expectRevert(IOriginRouter.ArrayLengthMismatch.selector);
        originRouter.sendRefundInstructions{value: 0.1 ether}(
            BNB_CHAIN_ID, WORLDWIDE_DAY, 0, 1, bidders, refundedAmounts, paidAmounts
        );
    }

    // --- Role Constants Tests ---
    function test_role_constants() public view {
        assertEq(originRouter.DESIS_ROLE(), keccak256("DESIS_ROLE"));
    }

    // --- Quote Tests ---
    function test_quoteSendAuctionStageStart() public view {
        uint256 fee = originRouter.quoteSendAuctionStageStart(_baseStageStartParams());

        assertEq(fee, 0.001 ether);
    }

    function test_quoteSendAuctionStageClearing() public view {
        uint256 fee = originRouter.quoteSendAuctionStageClearing(WORLDWIDE_DAY);

        assertEq(fee, 0.001 ether);
    }

    function test_quoteSendAuctionResult() public view {
        // (dstChainId, worldwideDay, issuedIntexCount, auctionClearingRate, wonBidsCount)
        uint256 fee = originRouter.quoteSendAuctionResult(BNB_CHAIN_ID, WORLDWIDE_DAY, 500, 75e6, 42);

        assertEq(fee, 0.001 ether);
    }

    function test_quoteSendIssuanceInstructions() public view {
        address[] memory recipients = new address[](2);
        uint256[] memory quantities = new uint256[](2);

        recipients[0] = address(0x1);
        recipients[1] = address(0x2);
        quantities[0] = 10;
        quantities[1] = 20;

        uint256 fee = originRouter.quoteSendIssuanceInstructions(
            BNB_CHAIN_ID, WORLDWIDE_DAY, 0, 1, _baseIssuanceParams(recipients, quantities)
        );

        assertEq(fee, 0.001 ether);
    }

    function test_quoteSendRefundInstructions() public view {
        address[] memory bidders = new address[](2);
        uint128[] memory refundedAmounts = new uint128[](2);
        uint128[] memory paidAmounts = new uint128[](2);

        bidders[0] = address(0x1);
        bidders[1] = address(0x2);
        refundedAmounts[0] = 100e6;
        refundedAmounts[1] = 200e6;
        paidAmounts[0] = 50e6;
        paidAmounts[1] = 75e6;

        uint256 fee = originRouter.quoteSendRefundInstructions(
            BNB_CHAIN_ID, WORLDWIDE_DAY, 0, 1, bidders, refundedAmounts, paidAmounts
        );

        assertEq(fee, 0.001 ether);
    }

    function test_quoteSendMarkCalled() public view {
        uint256 fee =
            originRouter.quoteSendMarkCalled(WORLDWIDE_DAY, uint32(block.timestamp), MarkBatchLib.one(SERIES_ID));

        assertEq(fee, 0.001 ether);
    }

    // --- ERC165 Tests ---
    function test_supportsInterface() public view {
        // IAccessControl interface ID
        bytes4 accessControlId = 0x7965db0b;
        assertTrue(originRouter.supportsInterface(accessControlId));
    }
}
