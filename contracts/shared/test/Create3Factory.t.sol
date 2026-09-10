// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {Create3Factory} from "../src/Create3Factory.sol";

/// @dev Minimal contract used as deployment payload; its constructor arg is part of its init code,
///      so two probes with different args have different init code (used to prove the deployed
///      address is independent of init code).
contract Probe {
    uint256 public immutable value;

    constructor(uint256 _value) {
        value = _value;
    }
}

contract Create3FactoryTest is Test {
    Create3Factory internal factory;

    address internal alice = makeAddr("alice");
    address internal bob = makeAddr("bob");
    bytes32 internal constant SALT = keccak256("outbe-intex:test");

    function setUp() public {
        factory = new Create3Factory();
    }

    function _initCode(uint256 v) internal pure returns (bytes memory) {
        return abi.encodePacked(type(Probe).creationCode, abi.encode(v));
    }

    function test_Predict_MatchesDeploy() public {
        address predicted = factory.predict(alice, SALT);
        vm.prank(alice);
        address deployed = factory.deploy(SALT, _initCode(1));
        assertEq(deployed, predicted, "predict != deploy");
        assertEq(Probe(deployed).value(), 1, "deployed probe wrong");
    }

    function test_AddressIndependentOfInitCode() public {
        address predicted = factory.predict(alice, SALT);

        uint256 snap = vm.snapshotState();

        vm.prank(alice);
        address withArg1 = factory.deploy(SALT, _initCode(1));

        vm.revertToState(snap);

        // Same (deployer, salt), different init code -> same address.
        vm.prank(alice);
        address withArg2 = factory.deploy(SALT, _initCode(2));

        assertEq(withArg1, predicted, "arg1 != predicted");
        assertEq(withArg2, predicted, "arg2 != predicted");
        assertEq(withArg1, withArg2, "address depends on init code");
    }

    function test_SaltNamespacedBySender() public {
        assertTrue(factory.predict(alice, SALT) != factory.predict(bob, SALT), "salt not namespaced");

        vm.prank(alice);
        address a = factory.deploy(SALT, _initCode(1));
        // Bob can still deploy with the same salt: no squatting across deployers.
        vm.prank(bob);
        address b = factory.deploy(SALT, _initCode(1));
        assertTrue(a != b, "namespacing failed");
    }

    function test_RevertWhen_Redeploy() public {
        vm.prank(alice);
        address deployed = factory.deploy(SALT, _initCode(1));

        vm.prank(alice);
        vm.expectRevert(abi.encodeWithSelector(Create3Factory.AlreadyDeployed.selector, deployed));
        factory.deploy(SALT, _initCode(1));
    }

    function test_SameAddressAcrossWipe() public {
        // A "wipe" is modeled by reverting all state and redeploying the factory + contract from
        // scratch. As long as the factory lands at the same address (here: same deployer/nonce),
        // the CREATE3 address is identical, since it does not depend on the contract init code.
        address predicted = factory.predict(alice, SALT);

        uint256 snap = vm.snapshotState();
        vm.prank(alice);
        address before = factory.deploy(SALT, _initCode(7));

        // Wipe: undo the deployment, then redeploy with different init code.
        vm.revertToState(snap);

        vm.prank(alice);
        address afterWipe = factory.deploy(SALT, _initCode(9));
        assertEq(afterWipe, before, "address changed across wipe");
        assertEq(afterWipe, predicted, "address != predicted across wipe");
    }
}
