// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {EscrowAdapter} from "@contracts/target/EscrowAdapter.sol";
import {DeployProxy} from "./helpers/DeployProxy.sol";
import {IEscrowAdapter} from "@contracts/target/interfaces/IEscrowAdapter.sol";
import {MockTheCompact} from "@test-mocks/MockTheCompact.sol";
import {MockWCOEN} from "@test-mocks/MockWCOEN.sol";

/// @dev Self-call shim guard on EscrowAdapter. `processFinalizationOne` wraps the per-bidder
///      `_processFinalizationInstruction` for `finalizeAuction`'s try/catch and must reject
///      any external caller so the wrapped logic only runs under the outer entry-point's role
///      gate and reentrancy guard.
contract EscrowAdapterNotSelfTest is Test {
    EscrowAdapter internal escrow;

    address internal admin = address(1);
    address internal bridger = address(2);
    address internal auction = address(3);
    address internal bidder = address(0xB1);

    uint32 internal constant WORLDWIDE_DAY = 1;
    bytes32 internal constant RECEIVE_ID = bytes32(uint256(0xCAFE));

    function setUp() public {
        escrow = DeployProxy.escrowAdapter(admin, bridger);
        MockTheCompact compact = new MockTheCompact();
        MockWCOEN paymentToken = new MockWCOEN();
        vm.prank(admin);
        escrow.wire(auction, address(compact), address(paymentToken));
    }

    function test_processFinalizationOne_externalCallerRevertsNotSelf() public {
        IEscrowAdapter.FinalizationInstruction memory inst =
            IEscrowAdapter.FinalizationInstruction({bidder: bidder, refundedAmount: 1, paidAmount: 0});
        vm.expectRevert(IEscrowAdapter.NotSelf.selector);
        escrow.processFinalizationOne(WORLDWIDE_DAY, RECEIVE_ID, inst);
    }
}
