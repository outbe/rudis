// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {EscrowAdapter} from "@contracts/target/EscrowAdapter.sol";
import {DeployProxy} from "./helpers/DeployProxy.sol";
import {IEscrowAdapter} from "@contracts/target/interfaces/IEscrowAdapter.sol";
import {MockTheCompact} from "@test-mocks/MockTheCompact.sol";
import {MockWCOEN} from "@test-mocks/MockWCOEN.sol";

/// @dev ERC20 that skims a fee on every move: the sender is crosschainBurned the full amount but the
///      recipient is crosschainMinted amount minus fee. Breaks the "exactly `amount` lands" assumption.
contract FeeOnTransferToken is IERC20 {
    mapping(address => uint256) private _balances;
    mapping(address => mapping(address => uint256)) private _allowances;
    uint256 private _supply;
    uint256 public immutable feeBps;

    string public constant name = "Fee Token";
    string public constant symbol = "FEE";
    uint8 public constant decimals = 18;

    constructor(uint256 _feeBps) {
        feeBps = _feeBps;
    }

    function totalSupply() external view returns (uint256) {
        return _supply;
    }

    function balanceOf(address a) external view returns (uint256) {
        return _balances[a];
    }

    function allowance(address o, address s) external view returns (uint256) {
        return _allowances[o][s];
    }

    function approve(address s, uint256 a) external returns (bool) {
        _allowances[msg.sender][s] = a;
        return true;
    }

    function mint(address to, uint256 a) external {
        _balances[to] += a;
        _supply += a;
    }

    function transfer(address to, uint256 a) external returns (bool) {
        _move(msg.sender, to, a);
        return true;
    }

    function transferFrom(address from, address to, uint256 a) external returns (bool) {
        _allowances[from][msg.sender] -= a;
        _move(from, to, a);
        return true;
    }

    function _move(address from, address to, uint256 a) internal {
        _balances[from] -= a;
        uint256 fee = (a * feeBps) / 10_000;
        _balances[to] += a - fee;
        _supply -= fee;
    }
}

contract EscrowAdapterHardeningTest is Test {
    EscrowAdapter internal escrow;
    MockTheCompact internal compact;
    MockWCOEN internal paymentToken;

    address internal admin = address(1);
    address internal bridger = address(2);
    address internal auction = address(3);
    address internal bidderA = address(0xA);
    address internal bidderB = address(0xB);

    uint32 internal constant SERIES = 20260102;

    function setUp() public {
        escrow = DeployProxy.escrowAdapter(admin, bridger);
        compact = new MockTheCompact();
        paymentToken = new MockWCOEN();

        vm.prank(admin);
        escrow.wire(auction, address(compact), address(paymentToken));
        compact.setResetPeriodSeconds(0);
    }

    function _fund(address bidder, uint256 amount) internal {
        paymentToken.mint(bidder, amount);
        vm.prank(bidder);
        paymentToken.approve(address(escrow), type(uint256).max);
    }

    function test_Boundary_LockFunds_AcceptsUint64Max() public {
        uint128 max = type(uint128).max;
        _fund(bidderA, max);

        vm.prank(auction);
        escrow.lockFunds(SERIES, bidderA, max);

        (,, uint128 totalLocked) = escrow.getAuctionStatus(SERIES);
        assertEq(totalLocked, max, "totalLocked");
        assertEq(escrow.getBidLock(SERIES, bidderA).lockedAmount, max, "lockedAmount");
        assertEq(compact.balanceOf(address(escrow), escrow.lockId()), max, "pooled balance");
    }

    function test_Boundary_TotalLockedOverflow_Reverts() public {
        uint128 max = type(uint128).max;
        _fund(bidderA, max);
        _fund(bidderB, 1);

        vm.prank(auction);
        escrow.lockFunds(SERIES, bidderA, max);

        vm.prank(auction);
        vm.expectRevert(abi.encodeWithSignature("Panic(uint256)", 0x11));
        escrow.lockFunds(SERIES, bidderB, 1);

        (,, uint128 totalLocked) = escrow.getAuctionStatus(SERIES);
        assertEq(totalLocked, max, "totalLocked unchanged after overflow revert");
        assertEq(compact.balanceOf(address(escrow), escrow.lockId()), max, "pooled balance unchanged");
    }

    function test_FeeOnTransferToken_LockFunds_FailsClosed() public {
        EscrowAdapter feeEscrow = DeployProxy.escrowAdapter(admin, bridger);
        MockTheCompact feeCompact = new MockTheCompact();
        FeeOnTransferToken feeToken = new FeeOnTransferToken(100);

        vm.prank(admin);
        feeEscrow.wire(auction, address(feeCompact), address(feeToken));
        feeCompact.setResetPeriodSeconds(0);

        feeToken.mint(bidderA, 1_000e6);
        vm.prank(bidderA);
        feeToken.approve(address(feeEscrow), type(uint256).max);

        vm.prank(auction);
        vm.expectRevert();
        feeEscrow.lockFunds(SERIES, bidderA, 1_000e6);

        (,, uint128 totalLocked) = feeEscrow.getAuctionStatus(SERIES);
        assertEq(totalLocked, 0, "no state written on a fee-token lock");
    }
}
