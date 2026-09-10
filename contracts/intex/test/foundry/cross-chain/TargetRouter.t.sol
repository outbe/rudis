// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {CrossChainTest} from "../helpers/CrossChainTest.sol";

import {TargetRouter} from "@contracts/target/TargetRouter.sol";
import {OriginRouter} from "@contracts/origin/OriginRouter.sol";
import {IntexNFT1155Bridge} from "@contracts/shared/IntexNFT1155Bridge.sol";
import {ITargetRouter} from "@contracts/target/interfaces/ITargetRouter.sol";
import {IIntexNFT1155Bridge} from "@contracts/shared/interfaces/IIntexNFT1155Bridge.sol";
import {RejectingReceiver} from "@test-mocks/RejectingReceiver.sol";
import {MockDesis} from "@test-mocks/MockDesis.sol";

import {IntexAuction} from "@contracts/target/IntexAuction.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";

/**
 * @title TargetRouterTest
 * @notice Foundry tests for TargetRouter
 * @dev Tests message encoding/decoding and cross-chain communication.
 *      All auction/series messages are keyed by `seriesId` (uint32).
 */
contract TargetRouterTest is CrossChainTest {
    uint32 private constant BNB_CHAIN_ID = 1;
    uint32 private constant OUTBE_CHAIN_ID = 2;

    TargetRouter private targetRouter;
    OriginRouter private originRouter;
    IntexNFT1155Bridge private nftBridge;

    // Mock contracts
    IntexAuction private auction;
    IntexNFT1155 private intex;

    address private admin = address(this);
    address private user = address(0x1);

    // Stand-in Desis recipient that advertises `IDesis` via ERC-165 - declared in setUp().
    address private desis;

    uint32 private constant SERIES_ID_DAY = 20250115;
    bytes14 private constant SERIES_ID = "20250115-USD-U"; // yyyymmdd format

    function setUp() public {
        _setUpBridge();
        // The quote test asserts a non-zero fee; give the loopback bridge a fixed fee to return.
        bridge.setFee(0.001 ether);

        vm.deal(admin, 1000 ether);
        vm.deal(user, 1000 ether);

        // Stand-in Desis recipient.
        desis = address(new MockDesis());
        vm.deal(desis, 1000 ether);

        // Deploy mock contracts
        auction = DeployProxy.intexAuction(admin, admin);
        intex = DeployProxy.intexNFT1155(admin, admin);

        // Deploy BNB adapter
        targetRouter = DeployProxy.targetRouter(address(bridge), admin, OUTBE_CHAIN_ID);

        // Deploy Outbe adapter (for cross-chain testing)
        originRouter = DeployProxy.originRouter(address(bridge), admin);

        // Deploy batch adapter on BNB
        nftBridge = DeployProxy.intexNFT1155Bridge(address(intex), address(bridge), admin);

        // Wire adapters (register remote messengers)
        targetRouter.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, address(originRouter)));
        originRouter.setRemoteMessenger(BNB_CHAIN_ID, _interop(BNB_CHAIN_ID, address(targetRouter)));

        // Wire BNB adapter dependencies
        targetRouter.wire(address(auction), address(intex), admin);

        // Wire Outbe adapter dependencies
        originRouter.wire(desis, makeAddr("factory"));

        // Grant RELAYER_ROLE to adapter
        auction.grantRole(auction.RELAYER_ROLE(), address(targetRouter));
        intex.grantRole(intex.RELAYER_ROLE(), address(targetRouter));

        // Grant RELAYER_ROLE to batch adapter on intex (for crosschainBurn)
        intex.grantRole(intex.RELAYER_ROLE(), address(nftBridge));
    }

    // --- Constructor Tests ---
    function test_constructor() public view {
        assertTrue(targetRouter.hasRole(targetRouter.DEFAULT_ADMIN_ROLE(), admin));
    }

    function test_wire() public view {
        assertEq(address(targetRouter.auction()), address(auction));
        assertEq(address(targetRouter.intex()), address(intex));
    }

    function test_wire_revert_zero_address() public {
        TargetRouter newRouter = DeployProxy.targetRouter(address(bridge), admin, OUTBE_CHAIN_ID);

        vm.expectRevert(abi.encodeWithSelector(ITargetRouter.ZeroAddress.selector, "auction"));
        newRouter.wire(address(0), address(intex), admin);
    }

    function test_wire_revert_zero_intex() public {
        TargetRouter newRouter = DeployProxy.targetRouter(address(bridge), admin, OUTBE_CHAIN_ID);

        vm.expectRevert(abi.encodeWithSelector(ITargetRouter.ZeroAddress.selector, "intex"));
        newRouter.wire(address(auction), address(0), admin);
    }

    function test_wire_revert_zero_escrowAdapter() public {
        TargetRouter newRouter = DeployProxy.targetRouter(address(bridge), admin, OUTBE_CHAIN_ID);

        vm.expectRevert(abi.encodeWithSelector(ITargetRouter.ZeroAddress.selector, "escrowAdapter"));
        newRouter.wire(address(auction), address(intex), address(0));
    }

    // --- ERC165 Tests ---
    function test_supportsInterface() public view {
        // IAccessControl interface ID
        bytes4 accessControlId = 0x7965db0b;
        assertTrue(targetRouter.supportsInterface(accessControlId));
    }

    // --- sweepNative Tests (TargetRouter) ---
    function test_sweepNative_bnb_success() public {
        vm.deal(address(targetRouter), 5 ether);
        address payable recipient = payable(address(0xBEEF));
        uint256 before = recipient.balance;

        targetRouter.sweepNative(recipient, 5 ether);

        assertEq(recipient.balance - before, 5 ether);
        assertEq(address(targetRouter).balance, 0);
    }

    function test_sweepNative_bnb_revert_zeroTo() public {
        vm.deal(address(targetRouter), 1 ether);
        vm.expectRevert(abi.encodeWithSelector(ITargetRouter.ZeroAddress.selector, "to"));
        targetRouter.sweepNative(payable(address(0)), 1 ether);
    }

    function test_sweepNative_bnb_revert_insufficientBalance() public {
        vm.deal(address(targetRouter), 1 ether);
        vm.expectRevert(abi.encodeWithSelector(ITargetRouter.NativeBalanceInsufficient.selector, 1 ether, 2 ether));
        targetRouter.sweepNative(payable(address(0xBEEF)), 2 ether);
    }

    function test_sweepNative_bnb_revert_failedCall() public {
        vm.deal(address(targetRouter), 1 ether);
        RejectingReceiver rejector = new RejectingReceiver();
        vm.expectRevert(ITargetRouter.NativeSweepFailed.selector);
        targetRouter.sweepNative(payable(address(rejector)), 1 ether);
    }

    function test_sweepNative_bnb_revert_unauthorized() public {
        vm.deal(address(targetRouter), 1 ether);
        vm.prank(user);
        vm.expectRevert();
        targetRouter.sweepNative(payable(address(0xBEEF)), 1 ether);
    }

    // --- sweepNative Tests (IntexNFT1155Bridge) ---
    function test_sweepNative_batch_success() public {
        vm.deal(address(nftBridge), 3 ether);
        address payable recipient = payable(address(0xCAFE));
        uint256 before = recipient.balance;

        nftBridge.sweepNative(recipient, 3 ether);

        assertEq(recipient.balance - before, 3 ether);
        assertEq(address(nftBridge).balance, 0);
    }

    function test_sweepNative_batch_revert_zeroTo() public {
        vm.deal(address(nftBridge), 1 ether);
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155Bridge.ZeroAddress.selector, "to"));
        nftBridge.sweepNative(payable(address(0)), 1 ether);
    }

    function test_sweepNative_batch_revert_insufficientBalance() public {
        vm.deal(address(nftBridge), 1 ether);
        vm.expectRevert(
            abi.encodeWithSelector(IIntexNFT1155Bridge.NativeBalanceInsufficient.selector, 1 ether, 2 ether)
        );
        nftBridge.sweepNative(payable(address(0xCAFE)), 2 ether);
    }

    function test_sweepNative_batch_revert_failedCall() public {
        vm.deal(address(nftBridge), 1 ether);
        RejectingReceiver rejector = new RejectingReceiver();
        vm.expectRevert(IIntexNFT1155Bridge.NativeSweepFailed.selector);
        nftBridge.sweepNative(payable(address(rejector)), 1 ether);
    }

    function test_sweepNative_batch_revert_unauthorized() public {
        vm.deal(address(nftBridge), 1 ether);
        vm.prank(user);
        vm.expectRevert();
        nftBridge.sweepNative(payable(address(0xCAFE)), 1 ether);
    }
}
