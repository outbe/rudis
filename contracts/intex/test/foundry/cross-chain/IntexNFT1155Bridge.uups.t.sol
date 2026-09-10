// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {CrossChainTest} from "../helpers/CrossChainTest.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {IntexNFT1155Bridge} from "@contracts/shared/IntexNFT1155Bridge.sol";
import {IntexNFT1155Bridge} from "@contracts/shared/IntexNFT1155Bridge.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";

/// @dev UUPS coverage for both NFT bridge clients - now both are ERC-7786 clients on a {MockERC7786Bridge}.
contract IntexNFT1155BridgeUupsTest is CrossChainTest {
    uint32 internal constant B_CHAIN_ID = 2;

    address internal admin = makeAddr("admin");
    address internal stranger = makeAddr("stranger");
    address internal tokenA = makeAddr("tokenA");

    IntexNFT1155Bridge internal adapter;
    IntexNFT1155Bridge internal batch;

    function setUp() public {
        _setUpBridge();
        adapter = DeployProxy.intexNFT1155Bridge(tokenA, address(bridge), admin);
        batch = DeployProxy.intexNFT1155Bridge(tokenA, address(bridge), admin);
    }

    function test_Initialize_SetsAdmin() public view {
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
        assertTrue(batch.hasRole(batch.DEFAULT_ADMIN_ROLE(), admin));
        assertEq(address(adapter.token()), tokenA);
        assertEq(address(batch.token()), tokenA);
    }

    function test_RevertWhen_InitializeCalledTwice() public {
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        adapter.initialize(stranger);
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        batch.initialize(stranger);
    }

    function test_RevertWhen_ImplementationInitialized() public {
        IntexNFT1155Bridge impl = new IntexNFT1155Bridge(tokenA, address(bridge));
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        impl.initialize(admin);

        IntexNFT1155Bridge batchImpl = new IntexNFT1155Bridge(tokenA, address(bridge));
        vm.expectRevert(Initializable.InvalidInitialization.selector);
        batchImpl.initialize(admin);
    }

    function test_RevertWhen_AdapterUpgradeByNonAdmin() public {
        IntexNFT1155Bridge newImpl = new IntexNFT1155Bridge(tokenA, address(bridge));
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, bytes32(0))
        );
        adapter.upgradeToAndCall(address(newImpl), "");
    }

    function test_RevertWhen_BatchUpgradeByNonAdmin() public {
        IntexNFT1155Bridge newImpl = new IntexNFT1155Bridge(tokenA, address(bridge));
        vm.prank(stranger);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, stranger, bytes32(0))
        );
        batch.upgradeToAndCall(address(newImpl), "");
    }

    function test_Upgrade_PreservesRemoteMessengerAndImmutables() public {
        bytes memory peer = _interop(B_CHAIN_ID, address(0xBEEF));
        vm.prank(admin);
        adapter.setRemoteMessenger(B_CHAIN_ID, peer);

        IntexNFT1155Bridge newImpl = new IntexNFT1155Bridge(tokenA, address(bridge));
        vm.prank(admin);
        adapter.upgradeToAndCall(address(newImpl), "");

        bytes32 implSlot = vm.load(address(adapter), ERC1967Utils.IMPLEMENTATION_SLOT);
        assertEq(address(uint160(uint256(implSlot))), address(newImpl));
        assertEq(adapter.remoteMessenger(B_CHAIN_ID), peer);
        assertEq(address(adapter.token()), tokenA);
        assertTrue(adapter.hasRole(adapter.DEFAULT_ADMIN_ROLE(), admin));
    }
}
