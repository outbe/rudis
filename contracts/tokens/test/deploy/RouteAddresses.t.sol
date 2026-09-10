// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";

import {Create3Factory} from "@shared/Create3Factory.sol";
import {RouteSpec} from "../../script/routes/BaseRoute.sol";
import {DeployAll} from "../../script/DeployAll.s.sol";

contract AddressHarness is DeployAll {
    function exposedSalt(string memory label, string memory salt) external pure returns (bytes32) {
        return _salt(label, salt);
    }

    function exposedTokenAddress(address factory, string memory salt, RouteSpec memory spec)
        external
        view
        returns (address)
    {
        return _tokenAddress(factory, salt, spec);
    }

    function exposedBridgeAddress(address factory, string memory salt, RouteSpec memory spec)
        external
        view
        returns (address)
    {
        return _bridgeAddress(factory, salt, spec);
    }

    function _deployer() internal view override returns (address) {
        return address(this);
    }
}

/// @dev Pins the CREATE3 derivation for every route. Both addresses are live on three chains, so any change to the
///      salt labels or to the hashing formula silently relocates deployed contracts.
contract RouteAddressesTest is Test {
    string internal constant SALT = "TEST_V1";

    AddressHarness internal deploy;
    Create3Factory internal factory;

    function setUp() public {
        vm.setEnv("EXTERNAL_CHAIN_ID", "11155111");
        vm.setEnv("OUTBE_CHAIN_ID", "70860602");
        vm.setEnv("DEPLOYER_PK", "0xA11CE");

        deploy = new AddressHarness();
        factory = new Create3Factory();
    }

    /// @dev A literal snapshot, unlike the per-route checks below: those restate the derivation, so a change made in
    ///      both the code and the expectation would slip through.
    function test_Salts_MatchTheDeployedSnapshot() public view {
        assertEq(
            deploy.exposedSalt("USDT", SALT), 0xf9451e8e547d5972cbb9c2b04172363a165d6eb926fa1cd2fcbb0d059ee466f3, "USDT"
        );
        assertEq(
            deploy.exposedSalt("USDTBridge", SALT),
            0x551ee32ce13d180dc8eae4bf798fe8662f6c6805b5091f5f6050e86892ffaeb2,
            "USDTBridge"
        );
        assertEq(
            deploy.exposedSalt("USDC", SALT), 0x6d74bfda57be563c23b7c04ad6219c867d65d39d546dd38a7f06254bbb27cfe8, "USDC"
        );
        assertEq(
            deploy.exposedSalt("USDCBridge", SALT),
            0xeda038eb609e477939ea07937cd2f3dcb2fb66ca5153595277d27e2e04bc5c0d,
            "USDCBridge"
        );
        assertEq(
            deploy.exposedSalt("WCOEN", SALT),
            0x6da3253d017767bcd0c52763055bea5410fa9932545aa6c8098a56e45b10ee77,
            "WCOEN"
        );
        assertEq(
            deploy.exposedSalt("WCOENBridge", SALT),
            0x74b1f310bb4383041156513e6540f03bfb47af6339c02464f5a4cb912b4f1bdc,
            "WCOENBridge"
        );
    }

    function test_UsdtRoute_DerivesFromItsLabels() public {
        _assertRoute(deploy.routeByLabel("USDT").spec, "USDT");
    }

    function test_UsdcRoute_DerivesFromItsLabels() public {
        _assertRoute(deploy.routeByLabel("USDC").spec, "USDC");
    }

    function test_WcoenRoute_DerivesFromItsLabels() public {
        _assertRoute(deploy.routeByLabel("WCOEN").spec, "WCOEN");
    }

    /// @dev The bridge label is the token label plus `Bridge`; dropping the stored `bridgeLabel` must keep that exact
    ///      string, since it is what the live deployments were salted with.
    function _assertRoute(RouteSpec memory spec, string memory label) internal view {
        assertEq(spec.tokenLabel, label, "token label");

        assertEq(
            deploy.exposedTokenAddress(address(factory), SALT, spec),
            factory.predict(address(deploy), keccak256(abi.encodePacked(label, SALT))),
            "token address"
        );

        assertEq(
            deploy.exposedBridgeAddress(address(factory), SALT, spec),
            factory.predict(address(deploy), keccak256(abi.encodePacked(string.concat(label, "Bridge"), SALT))),
            "bridge address"
        );
    }
}
