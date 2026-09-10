// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {ReferenceCurrencyPriceLib} from "./helpers/ReferenceCurrencyPriceLib.sol";
import {Test} from "forge-std/Test.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {IIntexAuction} from "@contracts/target/interfaces/IIntexAuction.sol";
import {IntexAuction} from "@contracts/target/IntexAuction.sol";
import {DeployProxy} from "./helpers/DeployProxy.sol";

contract IntexAuctionUupsTest is Test {
    address internal admin = makeAddr("admin");
    address internal bridger = makeAddr("bridger");
    address internal bidder = makeAddr("bidder");
    address internal stranger = makeAddr("stranger");

    IntexAuction internal auction;

    function setUp() public {
        auction = DeployProxy.intexAuction(admin, bridger);
    }

    function _startAuction(uint32 worldwideDay) internal {
        IIntexAuction.AuctionSchedule memory schedule = IIntexAuction.AuctionSchedule({
            commitEnd: uint32(block.timestamp + 1 hours),
            revealEnd: uint32(block.timestamp + 2 hours),
            issuanceEnd: uint32(block.timestamp + 3 hours)
        });
        IIntexAuction.AuctionParams memory params = IIntexAuction.AuctionParams({
            promisLoadMinor: 1000,
            minIntexBidRate: 1,
            prices: ReferenceCurrencyPriceLib.onePriced(840, 1, 1, 1),
            callTrigger: IIntexAuction.IntexCallTrigger({callWindow: 0, callThreshold: 0, callNoticePeriod: 0}),
            minIntexBidQuantity: 1,
            commitBondMinor: 0
        });
        vm.prank(bridger);
        auction.auctionStart(worldwideDay, IIntexAuction.WorldwideDayState.Green, schedule, params);
    }

    function test_Initialize_GrantsRoles() public view {
        assertTrue(auction.hasRole(auction.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(auction.hasRole(auction.RELAYER_ROLE(), bridger));
    }

    function test_RevertWhen_InitializeCalledTwice() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        auction.initialize(stranger);
    }

    function test_RevertWhen_ImplementationInitialized() public {
        IntexAuction impl = new IntexAuction();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(admin);
    }

    function test_RevertWhen_InitializeZeroAdmin() public {
        IntexAuction impl = new IntexAuction();
        vm.expectRevert(abi.encodeWithSelector(IIntexAuction.ZeroAddress.selector, "defaultAdmin"));
        new ERC1967Proxy(address(impl), abi.encodeCall(IntexAuction.initialize, (address(0))));
    }

    function test_RevertWhen_UpgradeByNonAdmin() public {
        IntexAuction newImpl = new IntexAuction();
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, bytes32(0))
        );
        auction.upgradeToAndCall(address(newImpl), "");
    }

    function test_Upgrade_PreservesStateAndSwapsImplementation() public {
        _startAuction(20260612);
        vm.prank(bidder);
        auction.commitBid(20260612, keccak256("commit"));
        vm.prank(admin);
        auction.wire(makeAddr("escrow"));

        IntexAuction newImpl = new IntexAuction();
        vm.prank(admin);
        auction.upgradeToAndCall(address(newImpl), "");

        bytes32 implSlot = vm.load(address(auction), ERC1967Utils.IMPLEMENTATION_SLOT);
        assertEq(address(uint160(uint256(implSlot))), address(newImpl));
        assertEq(auction.committedBidsByHash(20260612, bidder), keccak256("commit"));
        assertEq(address(auction.escrowContract()), makeAddr("escrow"));
        assertEq(uint8(auction.getAuctionStage(20260612)), uint8(IIntexAuction.AuctionStage.CommittingBids));
        assertTrue(auction.hasRole(auction.RELAYER_ROLE(), bridger));
    }
}
