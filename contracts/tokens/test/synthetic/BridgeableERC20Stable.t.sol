// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {IERC7802} from "@openzeppelin/contracts/interfaces/draft-IERC7802.sol";

import {BridgeableERC20} from "../../src/synthetic/BridgeableERC20.sol";
import {ERC7786TokenBridge} from "../../src/ERC7786TokenBridge.sol";
import {IReferenceCurrency} from "../../src/interfaces/IReferenceCurrency.sol";
import {BridgeableERC20Stable} from "../../src/synthetic/BridgeableERC20Stable.sol";
import {BridgeableERC20} from "../../src/synthetic/BridgeableERC20.sol";
import {MockERC7786Bridge} from "../mocks/MockERC7786Bridge.sol";

contract BridgeableERC20StableTest is Test {
    uint16 internal constant USD = 840;

    MockERC7786Bridge internal gateway;
    ERC7786TokenBridge internal tokenBridge;
    BridgeableERC20Stable internal token;

    function setUp() public {
        gateway = new MockERC7786Bridge(block.chainid);
        token = new BridgeableERC20Stable("USDT0", "USDT0", 6, USD, address(this));
        tokenBridge = new ERC7786TokenBridge(
            address(token), address(gateway), address(this), ERC7786TokenBridge.TokenBridgeMode.BurnMint
        );
    }

    function test_Decimals_IsSix() public view {
        assertEq(token.decimals(), 6);
    }

    function test_MetadataAndDecimals_AreConstructorConfigured() public {
        BridgeableERC20 customToken = new BridgeableERC20("Custom Token", "CUSTOM", 18, address(this));

        assertEq(customToken.name(), "Custom Token");
        assertEq(customToken.symbol(), "CUSTOM");
        assertEq(customToken.decimals(), 18);
    }

    function test_SupportsERC7802() public view {
        assertTrue(token.supportsInterface(type(IERC7802).interfaceId));
    }

    /// @dev The Credis Factory reads `isoCode()` on the disbursed asset to pin the
    ///      position's issuance currency; the USD token must report ISO 4217 numeric 840.
    function test_IsoCode_ReportsConstructorValue() public view {
        assertEq(IReferenceCurrency(address(token)).isoCode(), USD);
    }

    /// @dev The code is not hardcoded: a token constructed with a different ISO 4217
    ///      code (978 = EUR) must report that code, so the factory pins the right rate.
    function test_IsoCode_IsConstructorConfigured() public {
        uint16 eur = 978;
        BridgeableERC20Stable eurToken = new BridgeableERC20Stable("EURC", "EURC", 6, eur, address(this));
        assertEq(IReferenceCurrency(address(eurToken)).isoCode(), eur);
    }

    function test_SetTokenBridge_OwnerCanRotate() public {
        token.setTokenBridge(address(tokenBridge));
        ERC7786TokenBridge nextBridge = new ERC7786TokenBridge(
            address(token), address(gateway), address(this), ERC7786TokenBridge.TokenBridgeMode.BurnMint
        );

        vm.expectEmit(true, true, false, true);
        emit BridgeableERC20.TokenBridgeUpdated(address(tokenBridge), address(nextBridge));
        token.setTokenBridge(address(nextBridge));
        assertEq(token.tokenBridge(), address(nextBridge));
    }

    function test_RotatedTokenBridge_ReplacesMintPermission() public {
        address alice = makeAddr("alice");
        ERC7786TokenBridge nextBridge = new ERC7786TokenBridge(
            address(token), address(gateway), address(this), ERC7786TokenBridge.TokenBridgeMode.BurnMint
        );

        token.setTokenBridge(address(tokenBridge));
        token.setTokenBridge(address(nextBridge));

        vm.prank(address(tokenBridge));
        vm.expectRevert(abi.encodeWithSelector(BridgeableERC20.UnauthorizedTokenBridge.selector, address(tokenBridge)));
        token.crosschainMint(alice, 100);

        vm.prank(address(nextBridge));
        token.crosschainMint(alice, 100);
        assertEq(token.balanceOf(alice), 100);
    }

    function test_CrosschainMintAndBurn_OnlyTokenBridge() public {
        address alice = makeAddr("alice");

        vm.expectRevert(abi.encodeWithSelector(BridgeableERC20.UnauthorizedTokenBridge.selector, address(this)));
        token.crosschainMint(alice, 100);

        token.setTokenBridge(address(tokenBridge));

        vm.prank(address(tokenBridge));
        token.crosschainMint(alice, 100);
        assertEq(token.balanceOf(alice), 100);

        vm.prank(address(tokenBridge));
        token.crosschainBurn(alice, 40);
        assertEq(token.balanceOf(alice), 60);
    }
}
