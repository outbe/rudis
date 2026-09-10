// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {RouteSpec, BaseRoute, SyntheticSource} from "./BaseRoute.sol";
import {USDC} from "../../src/canonical/USDC.sol";
import {USDT} from "../../src/canonical/USDT.sol";
import {WCOEN} from "../../src/canonical/WCOEN.sol";
import {BridgeableERC20} from "../../src/synthetic/BridgeableERC20.sol";
import {BridgeableERC20Stable} from "../../src/synthetic/BridgeableERC20Stable.sol";

/// @dev One route, ready to deploy on the connected chain.
struct Route {
    RouteSpec spec;
    /// @dev For the side this chain holds. Empty when that side is never placed by this script - the USDC synthetic
    ///      is issued by governance, and `_deployRoute` rejects an unset env var rather than deploying nothing.
    bytes initCode;
    /// @dev The canonical side is a mintable stand-in for a token this repo does not issue, and gets bootstrapped.
    bool mintsCanonicalMock;
}

/// @dev Every route, as data. Adding a token is one entry in `routes()` plus its init code - `BaseRoute` stays
///      route-agnostic, and no caller names a route to deploy it.
///
///      `routes()` cannot be `view`: with `dynamic_test_linking` on, `type(T).creationCode` compiles to a
///      state-modifying `vm.getCode()` cheatcode call.
abstract contract Routes is BaseRoute {
    error UnknownRoute(string label);

    /// @dev Labels are part of the CREATE3 address. Changing one relocates every deployment of that route.
    function routes() public returns (Route[] memory list) {
        list = new Route[](3);

        // Canonical USDT on the external chain, ERC-7802 synthetic on Outbe. Point `CANONICAL_USDT_TOKEN` at the
        // issuer's USDT on a real network; leave it unset on a testnet, where the mock below is deployed instead.
        RouteSpec memory usdt = RouteSpec({
            tokenLabel: "USDT",
            canonicalOnOutbe: false,
            canonicalTokenEnv: "CANONICAL_USDT_TOKEN",
            syntheticTokenEnv: "",
            syntheticSource: SyntheticSource.Erc7802
        });
        list[0] = Route(usdt, _usdtInitCode(_isCanonicalHere(usdt)), true);

        // The same shape as USDT: canonical USDC on the external chain, ERC-7802 synthetic on Outbe.
        RouteSpec memory usdc = RouteSpec({
            tokenLabel: "USDC",
            canonicalOnOutbe: false,
            canonicalTokenEnv: "CANONICAL_USDC_TOKEN",
            syntheticTokenEnv: "",
            syntheticSource: SyntheticSource.Erc7802
        });
        list[1] = Route(usdc, _usdcInitCode(_isCanonicalHere(usdc)), true);

        // The mirror image of USDT: canonical WCOEN on Outbe, ERC-7802 synthetic on the external chain. Its canonical
        // side is the real wrapper over COEN, not a mock, so nothing is minted.
        RouteSpec memory wcoen = RouteSpec({
            tokenLabel: "WCOEN",
            canonicalOnOutbe: true,
            canonicalTokenEnv: "CANONICAL_WCOEN_TOKEN",
            syntheticTokenEnv: "",
            syntheticSource: SyntheticSource.Erc7802
        });
        list[2] = Route(wcoen, _wcoenInitCode(_isCanonicalHere(wcoen)), false);
    }

    function routeByLabel(string memory label) public returns (Route memory) {
        Route[] memory list = routes();
        for (uint256 i = 0; i < list.length; i++) {
            if (keccak256(bytes(list[i].spec.tokenLabel)) == keccak256(bytes(label))) return list[i];
        }
        revert UnknownRoute(label);
    }

    function deployRoutes(address factory, string memory salt) public {
        Route[] memory list = routes();
        for (uint256 i = 0; i < list.length; i++) {
            (address token, address tokenBridge) = deployRoute(factory, salt, list[i]);
            _logRoute(list[i].spec.tokenLabel, token, tokenBridge);
        }
    }

    function deployRoute(address factory, string memory salt, Route memory route)
        public
        returns (address token, address tokenBridge)
    {
        (token, tokenBridge) = _deployRoute(factory, salt, route.spec, route.initCode);

        // Bootstrap the mock on first deploy. Keyed on `totalSupply` rather than on "was just deployed", so a re-run
        // does not mint twice. USDT and USDC share the mock surface, so one cast covers both.
        if (route.mintsCanonicalMock && _isCanonicalHere(route.spec) && USDT(token).totalSupply() == 0) {
            USDT(token).mint(_mintRecipient(), vm.envOr("INITIAL_MINT_AMOUNT", uint256(1_000_000_000e6)));
        }
    }

    // ================================================== Init code ==================================================

    function _usdtInitCode(bool canonical) internal returns (bytes memory) {
        return canonical
            ? type(USDT).creationCode
            : abi.encodePacked(
                type(BridgeableERC20Stable).creationCode, abi.encode("USDT", "USDT", uint8(6), uint16(840), _owner())
            );
    }

    function _usdcInitCode(bool canonical) internal returns (bytes memory) {
        return canonical
            ? type(USDC).creationCode
            : abi.encodePacked(
                type(BridgeableERC20Stable).creationCode, abi.encode("USDC", "USDC", uint8(6), uint16(840), _owner())
            );
    }

    function _wcoenInitCode(bool canonical) internal returns (bytes memory) {
        return canonical
            ? type(WCOEN).creationCode
            : abi.encodePacked(
                type(BridgeableERC20).creationCode, abi.encode("Wrapped Rudis", "wrudis", uint8(18), _owner())
            );
    }
}
