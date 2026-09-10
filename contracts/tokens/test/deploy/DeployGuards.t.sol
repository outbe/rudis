// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";

import {Create3Factory} from "@shared/Create3Factory.sol";
import {RouteSpec, BaseRoute} from "../../script/routes/BaseRoute.sol";
import {Route} from "../../script/routes/Routes.sol";
import {DeployAll} from "../../script/DeployAll.s.sol";
import {BridgeableERC20} from "../../src/synthetic/BridgeableERC20.sol";
import {ERC7786TokenBridge} from "../../src/ERC7786TokenBridge.sol";
import {USDT} from "../../src/canonical/USDT.sol";
import {MockERC7786Bridge} from "../mocks/MockERC7786Bridge.sol";

contract ContractOwnerMock {}

contract DeployHarness is DeployAll {
    function exposedRequireContractOwnerOnGuardedChain(address owner, bool allowEoaOwner) external view {
        _requireContractOwnerOnGuardedChain(owner, allowEoaOwner);
    }

    function exposedRequireDeclaredChain() external view {
        _requireDeclaredChain();
    }

    function exposedDeployRoute(address factory, string memory salt, RouteSpec memory spec, bytes memory tokenInitCode)
        external
        returns (address, address)
    {
        return _deployRoute(factory, salt, spec, tokenInitCode);
    }

    function exposedBridgeAddress(address factory, string memory salt, RouteSpec memory spec)
        external
        view
        returns (address)
    {
        return _bridgeAddress(factory, salt, spec);
    }

    /// @dev The harness is the deployer, so it can make the owner-only `setTokenBridge` call itself. Under a real
    ///      run `vm.startBroadcast` puts the deployer key behind those calls; there is no broadcast in tests.
    function _deployer() internal view override returns (address) {
        return address(this);
    }
}

/// @dev Every test here relies on the constant env values written by `setUp`. That is load-bearing: `vm.setEnv` writes
///      the process environment while forge runs test contracts - and tests within a contract - concurrently, so a
///      test that sets its own env values would race its siblings. Anything computed (a deployed mock's address) is
///      injected with `vm.etch` at a fixed address instead of being written into the environment.
///
///      Sepolia is the declared external chain on purpose: it proves a new network needs env only, no code change.
contract DeployGuardsTest is Test {
    uint256 internal constant EXTERNAL_CHAIN = 11_155_111; // Sepolia
    uint256 internal constant OUTBE_CHAIN = 70_860_602;
    uint256 internal constant UNDECLARED_CHAIN = 97; // BSC testnet - no longer privileged by a hardcoded chain id
    uint256 internal constant LOCAL_CHAIN = 31_337;

    address internal constant HUB = 0x0000000000000000000000000000000000B41D6E;
    /// @dev Stands in for a canonical token that already exists on chain - see the adoption test.
    address internal constant ADOPTED_USDT = address(uint160(0xADD7ED));
    string internal constant SALT = "TEST_V1";

    DeployHarness internal deploy;
    Create3Factory internal factory;

    function setUp() public {
        vm.setEnv("EXTERNAL_CHAIN_ID", "11155111");
        vm.setEnv("OUTBE_CHAIN_ID", "70860602");
        vm.setEnv("DEPLOYER_PK", "0xA11CE");
        vm.setEnv("ALLOW_EOA_OWNER", "true");
        vm.setEnv("BRIDGE_ADDRESS", "0x0000000000000000000000000000000000B41D6E");

        // The hub only needs code for `_requireCode`. Deploying a mock and writing its address into the environment
        // would put a computed value into shared state, which is exactly what the note above forbids.
        vm.setEnv("ADOPTED_USDT_TOKEN", "0x0000000000000000000000000000000000ADD7ED");

        vm.etch(HUB, address(new MockERC7786Bridge(EXTERNAL_CHAIN)).code);
        vm.etch(ADOPTED_USDT, address(new USDT()).code);

        deploy = new DeployHarness();
        factory = new Create3Factory();
    }

    // === Owner guard ===
    // The mint-trust root must sit behind a multisig on every chain the route declares. An undeclared chain (a local
    // node, a scratch fork) stays unguarded so dev flows are not blocked.

    function test_Guards_RevertForEOAOwnerOnDeclaredExternalChain() public {
        vm.chainId(EXTERNAL_CHAIN);
        address owner = makeAddr("owner");

        vm.expectRevert(abi.encodeWithSelector(BaseRoute.OwnerMustBeMultisigContract.selector, owner, EXTERNAL_CHAIN));
        deploy.exposedRequireContractOwnerOnGuardedChain(owner, false);
    }

    function test_Guards_RevertForEOAOwnerOnOutbeChain() public {
        vm.chainId(OUTBE_CHAIN);
        address owner = makeAddr("owner");

        vm.expectRevert(abi.encodeWithSelector(BaseRoute.OwnerMustBeMultisigContract.selector, owner, OUTBE_CHAIN));
        deploy.exposedRequireContractOwnerOnGuardedChain(owner, false);
    }

    function test_Guards_AllowContractOwnerOnGuardedChain() public {
        vm.chainId(EXTERNAL_CHAIN);

        deploy.exposedRequireContractOwnerOnGuardedChain(address(new ContractOwnerMock()), false);
    }

    /// @dev BSC testnet used to be guarded by a hardcoded chain id; once it is not part of the declared route it must
    ///      behave like any other undeclared chain.
    function test_Guards_AllowEOAOwnerOnUndeclaredChain() public {
        vm.chainId(UNDECLARED_CHAIN);

        deploy.exposedRequireContractOwnerOnGuardedChain(makeAddr("owner"), false);
    }

    function test_Guards_AllowEOAOwnerOnLocalChain() public {
        vm.chainId(LOCAL_CHAIN);

        deploy.exposedRequireContractOwnerOnGuardedChain(makeAddr("owner"), false);
    }

    function test_Guards_AllowEOAOwnerOnGuardedChainWithExplicitOverride() public {
        vm.chainId(EXTERNAL_CHAIN);

        deploy.exposedRequireContractOwnerOnGuardedChain(makeAddr("owner"), true);
    }

    // === Declared-chain guard ===
    // A wrong `--rpc-url` must not deploy anything. Without this an unrecognised chain counts as "not Outbe", i.e. as
    // the external end of every route, and a full set of contracts - including the mintable USDT mock - lands on it.

    function test_DeclaredChainGuard_AllowsExternalChain() public {
        vm.chainId(EXTERNAL_CHAIN);

        deploy.exposedRequireDeclaredChain();
    }

    function test_DeclaredChainGuard_AllowsOutbe() public {
        vm.chainId(OUTBE_CHAIN);

        deploy.exposedRequireDeclaredChain();
    }

    function test_DeclaredChainGuard_RevertsOnUndeclaredChain() public {
        vm.chainId(UNDECLARED_CHAIN);

        vm.expectRevert(abi.encodeWithSelector(BaseRoute.UndeclaredChain.selector, UNDECLARED_CHAIN));
        deploy.exposedRequireDeclaredChain();
    }

    function test_DeclaredChainGuard_RevertsOnMainnet() public {
        vm.chainId(1);

        vm.expectRevert(abi.encodeWithSelector(BaseRoute.UndeclaredChain.selector, uint256(1)));
        deploy.exposedRequireDeclaredChain();
    }

    /// @dev The guard has to bite through the deploy entrypoint, not only in isolation - that is where a wrong
    ///      `--rpc-url` actually arrives.
    function test_DeployRoute_RevertsOnUndeclaredChain() public {
        vm.chainId(UNDECLARED_CHAIN);
        // Resolved before `expectRevert`: as a call argument it would run first and consume the expectation.
        Route memory usdt = deploy.routeByLabel("USDT");
        Route memory wcoen = deploy.routeByLabel("WCOEN");

        vm.expectRevert(abi.encodeWithSelector(BaseRoute.UndeclaredChain.selector, UNDECLARED_CHAIN));
        deploy.deployRoute(address(factory), SALT, usdt);

        vm.expectRevert(abi.encodeWithSelector(BaseRoute.UndeclaredChain.selector, UNDECLARED_CHAIN));
        deploy.deployRoute(address(factory), SALT, wcoen);
    }

    // === Deterministic addresses ===

    /// @dev The headline invariant: the same four addresses come out on the external chain and on Outbe, even though
    ///      each side deploys different contracts, with different constructor arguments and a different bridge mode.
    ///      The bytecode assertion keeps the test from passing vacuously.
    function test_Addresses_AreIdenticalInBothRoles() public {
        uint256 snapshot = vm.snapshotState();

        vm.chainId(EXTERNAL_CHAIN);
        (address extUsdt, address extUsdtBridge) =
            deploy.deployRoute(address(factory), SALT, deploy.routeByLabel("USDT"));
        (address extWcoen, address extWcoenBridge) =
            deploy.deployRoute(address(factory), SALT, deploy.routeByLabel("WCOEN"));
        bytes memory extUsdtCode = extUsdt.code;
        uint8 extWcoenDecimals = BridgeableERC20(extWcoen).decimals();
        assertEq(BridgeableERC20(extWcoen).name(), "Wrapped Rudis");
        assertEq(BridgeableERC20(extWcoen).symbol(), "wrudis");
        assertEq(uint8(ERC7786TokenBridge(extUsdtBridge).mode()), uint8(ERC7786TokenBridge.TokenBridgeMode.LockUnlock));

        vm.revertToState(snapshot);

        vm.chainId(OUTBE_CHAIN);
        (address outUsdt, address outUsdtBridge) =
            deploy.deployRoute(address(factory), SALT, deploy.routeByLabel("USDT"));
        (address outWcoen, address outWcoenBridge) =
            deploy.deployRoute(address(factory), SALT, deploy.routeByLabel("WCOEN"));
        assertEq(uint8(ERC7786TokenBridge(outUsdtBridge).mode()), uint8(ERC7786TokenBridge.TokenBridgeMode.BurnMint));

        assertEq(extUsdt, outUsdt, "USDT token address differs between chains");
        assertEq(extUsdtBridge, outUsdtBridge, "USDT bridge address differs between chains");
        assertEq(extWcoen, outWcoen, "WCOEN token address differs between chains");
        assertEq(extWcoenBridge, outWcoenBridge, "WCOEN bridge address differs between chains");
        assertEq(extWcoenDecimals, 18, "external WCOEN decimals differ");
        assertEq(BridgeableERC20(outWcoen).decimals(), 18, "Outbe WCOEN decimals differ");
        assertEq(BridgeableERC20(outWcoen).name(), "Wrapped Rudis");
        assertEq(BridgeableERC20(outWcoen).symbol(), "wrudis");

        assertTrue(keccak256(extUsdtCode) != keccak256(outUsdt.code), "same bytecode: the test proves nothing");
    }

    function test_Routes_AreDistinct() public {
        vm.chainId(EXTERNAL_CHAIN);
        (address usdt, address usdtBridge) = deploy.deployRoute(address(factory), SALT, deploy.routeByLabel("USDT"));
        (address wcoen, address wcoenBridge) = deploy.deployRoute(address(factory), SALT, deploy.routeByLabel("WCOEN"));

        assertTrue(usdt != usdtBridge && usdt != wcoen && usdt != wcoenBridge, "USDT address collides");
        assertTrue(usdtBridge != wcoen && usdtBridge != wcoenBridge, "USDT bridge address collides");
        assertTrue(wcoen != wcoenBridge, "WCOEN address collides");
    }

    function test_Salt_ChangesAddresses() public {
        vm.chainId(EXTERNAL_CHAIN);

        address a = deploy.exposedBridgeAddress(address(factory), "SALT_A", deploy.routeByLabel("USDT").spec);
        address b = deploy.exposedBridgeAddress(address(factory), "SALT_B", deploy.routeByLabel("USDT").spec);

        assertTrue(a != b, "salt does not change the address");
    }

    /// @dev On a real network the canonical USDT already exists at the issuer's address, so the script must adopt it
    ///      instead of deploying a mock next to it - and the bridge address must not move because of that.
    ///      The spec is returned by value, so the test can point it at a fixed env var rather than writing a computed
    ///      address into the shared environment.
    function test_CanonicalToken_AdoptsConfiguredAddress() public {
        vm.chainId(EXTERNAL_CHAIN);

        RouteSpec memory spec = deploy.routeByLabel("USDT").spec;
        address predictedBridge = deploy.exposedBridgeAddress(address(factory), SALT, spec);
        spec.canonicalTokenEnv = "ADOPTED_USDT_TOKEN";

        (address token, address tokenBridge) = deploy.exposedDeployRoute(address(factory), SALT, spec, "");

        assertEq(token, ADOPTED_USDT, "did not adopt the configured canonical token");
        assertEq(tokenBridge, predictedBridge, "bridge address moved because of the adopted token");
        assertEq(address(ERC7786TokenBridge(tokenBridge).token()), ADOPTED_USDT, "bridge points at the wrong token");
    }

    function test_Synthetic_IsWiredToBridge() public {
        vm.chainId(OUTBE_CHAIN);
        (address usdt, address usdtBridge) = deploy.deployRoute(address(factory), SALT, deploy.routeByLabel("USDT"));

        assertEq(BridgeableERC20(usdt).tokenBridge(), usdtBridge, "synthetic not wired to its bridge");
    }

    /// @dev Create3Factory reverts on a re-used salt, so a re-run is only safe because of the code-existence guards.
    function test_Rerun_IsNoop() public {
        vm.chainId(EXTERNAL_CHAIN);
        (address usdt, address usdtBridge) = deploy.deployRoute(address(factory), SALT, deploy.routeByLabel("USDT"));
        (address usdtAgain, address usdtBridgeAgain) =
            deploy.deployRoute(address(factory), SALT, deploy.routeByLabel("USDT"));

        assertEq(usdt, usdtAgain);
        assertEq(usdtBridge, usdtBridgeAgain);
    }
}
