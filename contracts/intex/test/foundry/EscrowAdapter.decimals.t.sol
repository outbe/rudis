// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {EscrowAdapter} from "@contracts/target/EscrowAdapter.sol";
import {DeployProxy} from "./helpers/DeployProxy.sol";
import {IEscrowAdapter} from "@contracts/target/interfaces/IEscrowAdapter.sol";
import {MockTheCompact} from "@test-mocks/MockTheCompact.sol";
import {MockERC20} from "@test-mocks/MockERC20.sol";
import {MockWCOEN} from "@test-mocks/MockWCOEN.sol";

contract EscrowAdapterDecimalsTest is Test {
    EscrowAdapter internal escrow;
    MockTheCompact internal compact;

    address internal admin = address(1);
    address internal bridger = address(2);
    address internal auction = address(3);

    function setUp() public {
        escrow = DeployProxy.escrowAdapter(admin, bridger);
        compact = new MockTheCompact();
    }

    function test_wire_acceptsEighteenDecimals() public {
        MockWCOEN token = new MockWCOEN();
        vm.prank(admin);
        escrow.wire(auction, address(compact), address(token));
        assertEq(address(escrow.paymentToken()), address(token));
    }

    function test_wire_rejectsNonEighteenDecimals() public {
        MockERC20 token = new MockERC20("Token", "TKN", 6);
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(IEscrowAdapter.PaymentTokenDecimals.selector, uint8(6)));
        escrow.wire(auction, address(compact), address(token));
    }

    function test_wire_rejectsNonEighteenDecimalsOnRotation() public {
        MockWCOEN token = new MockWCOEN();
        vm.prank(admin);
        escrow.wire(auction, address(compact), address(token));

        MockERC20 rotated = new MockERC20("Token", "TKN", 6);
        vm.prank(admin);
        vm.expectRevert(abi.encodeWithSelector(IEscrowAdapter.PaymentTokenDecimals.selector, uint8(6)));
        escrow.wire(auction, address(compact), address(rotated));
    }

    function test_paymentTokenDecimals_isEighteen() public view {
        assertEq(escrow.PAYMENT_TOKEN_DECIMALS(), 18);
    }
}
