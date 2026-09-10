// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {CrossChainTest} from "../helpers/CrossChainTest.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {Create3Factory} from "@shared/Create3Factory.sol";
import {Create3Deploy} from "../../../deploy/Create3Deploy.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {IntexAuction} from "@contracts/target/IntexAuction.sol";
import {OriginRouter} from "@contracts/origin/OriginRouter.sol";

/// @dev Verifies the CREATE3 proxy deployment path used by the deploy scripts: deterministic
///      addresses, correct implementation pointer, initialization, idempotency, and that the proxy
///      address is independent of the implementation init code.
contract DeployFlowTest is CrossChainTest {
    string internal constant VERSION = "v1.0.0";
    uint32 internal constant B_CHAIN_ID = 2;

    address internal admin = makeAddr("admin");
    address internal bridger = makeAddr("bridger");

    Create3Factory internal factory;

    function setUp() public {
        _setUpBridge();
        factory = new Create3Factory();
    }

    function _implSlot(address proxy) internal view returns (address) {
        return address(uint160(uint256(vm.load(proxy, ERC1967Utils.IMPLEMENTATION_SLOT))));
    }

    function test_DeployPlainProxy_Deterministic() public {
        address predicted = Create3Deploy.predictProxy(factory, address(this), "IntexNFT1155", VERSION);
        address impl = address(new IntexNFT1155());
        address proxy = Create3Deploy.deployProxy(
            factory, address(this), "IntexNFT1155", VERSION, impl, abi.encodeCall(IntexNFT1155.initialize, (admin))
        );

        assertEq(proxy, predicted, "predict != deploy");
        assertEq(_implSlot(proxy), impl, "impl pointer wrong");
        assertTrue(IntexNFT1155(proxy).hasRole(IntexNFT1155(proxy).DEFAULT_ADMIN_ROLE(), admin), "not initialized");
    }

    function test_DeployBridgeClientProxy_Deterministic() public {
        address predicted = Create3Deploy.predictProxy(factory, address(this), "OriginRouter", VERSION);
        address impl = address(new OriginRouter(address(bridge)));
        address proxy = Create3Deploy.deployProxy(
            factory, address(this), "OriginRouter", VERSION, impl, abi.encodeCall(OriginRouter.initialize, (admin))
        );

        assertEq(proxy, predicted, "predict != deploy");
        assertEq(_implSlot(proxy), impl, "impl pointer wrong");
        assertTrue(
            OriginRouter(payable(proxy)).hasRole(OriginRouter(payable(proxy)).DEFAULT_ADMIN_ROLE(), admin),
            "admin not set"
        );
    }

    function test_Idempotent_SkipsRedeploy() public {
        address impl = address(new IntexNFT1155());
        bytes memory initData = abi.encodeCall(IntexNFT1155.initialize, (admin));
        address first = Create3Deploy.deployProxy(factory, address(this), "IntexNFT1155", VERSION, impl, initData);
        // A second call with a DIFFERENT impl must be a no-op: same proxy, original impl left untouched.
        address impl2 = address(new IntexNFT1155());
        address second = Create3Deploy.deployProxy(factory, address(this), "IntexNFT1155", VERSION, impl2, initData);
        assertEq(first, second, "redeploy not idempotent");
        assertEq(_implSlot(second), impl, "idempotent deploy must not re-point impl");
    }

    function test_ProxyAddressIndependentOfImpl() public {
        address predicted = Create3Deploy.predictProxy(factory, address(this), "AddrTest", VERSION);

        uint256 snap = vm.snapshotState();
        // OZ 5.6 `ERC1967Proxy` rejects empty init data; pass each impl's initializer. The CREATE3
        // address depends only on salt + deployer, so it stays independent of impl + init data.
        address a = Create3Deploy.deployProxy(
            factory,
            address(this),
            "AddrTest",
            VERSION,
            address(new IntexNFT1155()),
            abi.encodeCall(IntexNFT1155.initialize, (admin))
        );
        vm.revertToState(snap);
        // Different implementation bytecode, same salt + deployer -> same proxy address.
        address b = Create3Deploy.deployProxy(
            factory,
            address(this),
            "AddrTest",
            VERSION,
            address(new IntexAuction()),
            abi.encodeCall(IntexAuction.initialize, (admin))
        );

        assertEq(a, predicted, "a != predicted");
        assertEq(b, predicted, "b != predicted");
    }

    function test_DistinctDeployersGetDistinctAddresses() public {
        address other = makeAddr("otherDeployer");
        // The factory namespaces the CREATE3 salt by deployer, so the same prefix+version yields
        // disjoint address spaces - one deployer cannot squat another's predicted address.
        address predSelf = Create3Deploy.predictProxy(factory, address(this), "NsTest", VERSION);
        address predOther = Create3Deploy.predictProxy(factory, other, "NsTest", VERSION);
        assertTrue(predSelf != predOther, "deployer must namespace the salt");

        // Deploying as this contract occupies only its own namespaced slot; `other`'s stays free.
        address proxy = Create3Deploy.deployProxy(
            factory,
            address(this),
            "NsTest",
            VERSION,
            address(new IntexNFT1155()),
            abi.encodeCall(IntexNFT1155.initialize, (admin))
        );
        assertEq(proxy, predSelf, "proxy != predicted");
        assertEq(predOther.code.length, 0, "another deployer's address must remain free");
    }
}
