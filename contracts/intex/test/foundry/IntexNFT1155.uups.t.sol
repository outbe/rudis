// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {IIntexNFT1155} from "@contracts/shared/interfaces/IIntexNFT1155.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {DeployProxy} from "./helpers/DeployProxy.sol";
import {CreateSeriesLib} from "./helpers/CreateSeriesLib.sol";

contract IntexNFT1155UupsTest is Test {
    address internal admin = makeAddr("admin");
    address internal bridger = makeAddr("bridger");
    address internal stranger = makeAddr("stranger");

    IntexNFT1155 internal nft;

    function setUp() public {
        nft = DeployProxy.intexNFT1155(admin, bridger);
    }

    function test_Initialize_GrantsRoles() public view {
        assertTrue(nft.hasRole(nft.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(nft.hasRole(nft.RELAYER_ROLE(), bridger));
    }

    function test_RevertWhen_InitializeCalledTwice() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        nft.initialize(stranger);
    }

    function test_RevertWhen_ImplementationInitialized() public {
        IntexNFT1155 impl = new IntexNFT1155();
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(admin);
    }

    function test_RevertWhen_InitializeZeroAdmin() public {
        IntexNFT1155 impl = new IntexNFT1155();
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.ZeroAddress.selector, "defaultAdmin", address(0)));
        new ERC1967Proxy(address(impl), abi.encodeCall(IntexNFT1155.initialize, (address(0))));
    }

    function test_RevertWhen_UpgradeByNonAdmin() public {
        IntexNFT1155 newImpl = new IntexNFT1155();
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, bytes32(0))
        );
        nft.upgradeToAndCall(address(newImpl), "");
    }

    function test_Upgrade_PreservesStateAndSwapsImplementation() public {
        vm.prank(bridger);
        nft.createSeries(CreateSeriesLib.params(7, 100, 0));
        vm.prank(bridger);
        nft.issue(stranger, 3, CreateSeriesLib.seriesId(7));

        IntexNFT1155 newImpl = new IntexNFT1155();
        vm.prank(admin);
        nft.upgradeToAndCall(address(newImpl), "");

        bytes32 implSlot = vm.load(address(nft), ERC1967Utils.IMPLEMENTATION_SLOT);
        assertEq(address(uint160(uint256(implSlot))), address(newImpl));
        uint256 tokenId = nft.issuedTokenId(CreateSeriesLib.seriesId(7));
        assertEq(nft.balanceOf(stranger, tokenId), 3);
        assertEq(nft.totalSupply(tokenId), 3);
        assertTrue(nft.hasRole(nft.RELAYER_ROLE(), bridger));
    }
}
