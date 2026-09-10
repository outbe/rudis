// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {ReferenceCurrencyPriceLib} from "./helpers/ReferenceCurrencyPriceLib.sol";
import {Test} from "forge-std/Test.sol";
import {IERC6909} from "@openzeppelin/contracts/interfaces/IERC6909.sol";
import {IntexAuction} from "@contracts/target/IntexAuction.sol";
import {EscrowAdapter} from "@contracts/target/EscrowAdapter.sol";
import {DeployProxy} from "./helpers/DeployProxy.sol";
import {IIntexAuction} from "@contracts/target/interfaces/IIntexAuction.sol";
import {IEscrowAdapter} from "@contracts/target/interfaces/IEscrowAdapter.sol";
import {MockTheCompact} from "@test-mocks/MockTheCompact.sol";
import {MockWCOEN} from "@test-mocks/MockWCOEN.sol";

/// @dev Commit-bond lifecycle through the real IntexAuction + EscrowAdapter pair:
///      commit takes the bond, reveal/cancel return it, and a no-reveal waits out
///      `UNREVEALED_BOND_LOCK_PERIOD`.
contract IntexAuctionBondTest is Test {
    uint16 internal constant ISSUANCE_CCY = 840;
    uint16 internal constant REFERENCE_CCY = 840;

    IntexAuction auction;
    EscrowAdapter escrow;
    MockTheCompact compact;
    MockWCOEN paymentToken;

    address admin = address(1);
    address bridger = address(2);
    address outsider = address(7);

    uint256 iba1PrivateKey;
    address iba1;

    bytes32 internal constant REVEAL_BID_TYPEHASH = keccak256(
        "RevealBid(uint32 worldwideDay,address bidder,uint16 quantity,uint32 bidRate,uint16 issuanceCurrency,uint16 referenceCurrency)"
    );

    uint128 internal constant PROMIS_LOAD_MINOR = 100_000 * 1e6;
    uint64 internal constant ENTRY_PRICE = 1e6;
    uint128 internal constant BOND = 100e18;
    // Protocol-scale basis/rate cross into 18-decimal WCOEN, well below BOND.
    uint16 internal constant QTY = 1;
    uint32 internal constant RATE = 1;
    uint128 internal constant LOCK_AMOUNT = uint128(uint256(QTY) * PROMIS_LOAD_MINOR * RATE / 1_000_000 * 1e12);

    uint32 constant COMMIT_OFFSET = 100;
    uint32 constant REVEAL_OFFSET = 200;
    uint32 constant ISSUANCE_OFFSET = 300;

    uint32 worldwideDay = 20260706;
    uint256 startTs;

    function setUp() public {
        (iba1, iba1PrivateKey) = makeAddrAndKey("iba1");

        auction = DeployProxy.intexAuction(admin, bridger);
        escrow = DeployProxy.escrowAdapter(admin, bridger);
        compact = new MockTheCompact();
        paymentToken = new MockWCOEN();

        vm.startPrank(admin);
        auction.grantRole(auction.RELAYER_ROLE(), bridger);
        auction.wire(address(escrow));
        escrow.wire(address(auction), address(compact), address(paymentToken));
        vm.stopPrank();
        compact.setResetPeriodSeconds(0);

        paymentToken.mint(iba1, 1000e18);
        vm.prank(iba1);
        paymentToken.approve(address(escrow), type(uint256).max);

        startTs = block.timestamp;
        vm.prank(bridger);
        auction.auctionStart(worldwideDay, IIntexAuction.WorldwideDayState.Green, _schedule(), _params(BOND));
    }

    // --- Helpers ---

    function _schedule() internal view returns (IIntexAuction.AuctionSchedule memory) {
        return IIntexAuction.AuctionSchedule({
            commitEnd: uint32(block.timestamp + COMMIT_OFFSET),
            revealEnd: uint32(block.timestamp + REVEAL_OFFSET),
            issuanceEnd: uint32(block.timestamp + ISSUANCE_OFFSET)
        });
    }

    function _params(uint128 bond) internal pure returns (IIntexAuction.AuctionParams memory) {
        return IIntexAuction.AuctionParams({
            promisLoadMinor: PROMIS_LOAD_MINOR,
            minIntexBidRate: 1,
            prices: ReferenceCurrencyPriceLib.onePriced(840, ENTRY_PRICE, 100, 200),
            callTrigger: IIntexAuction.IntexCallTrigger({callWindow: 0, callThreshold: 0, callNoticePeriod: 0}),
            minIntexBidQuantity: 1,
            commitBondMinor: bond
        });
    }

    function _signature() internal view returns (bytes memory) {
        bytes32 structHash =
            keccak256(abi.encode(REVEAL_BID_TYPEHASH, worldwideDay, iba1, QTY, RATE, ISSUANCE_CCY, REFERENCE_CCY));
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("IntexAuction")),
                keccak256(bytes("1")),
                block.chainid,
                address(auction)
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(iba1PrivateKey, digest);
        return abi.encodePacked(r, s, v);
    }

    function _commit() internal {
        vm.prank(iba1);
        auction.commitBid(worldwideDay, keccak256(_signature()));
    }

    function _enterRevealStage() internal {
        vm.warp(startTs + COMMIT_OFFSET + 1);
    }

    function _liveCompactBalance() internal view returns (uint256) {
        return IERC6909(address(compact)).balanceOf(address(escrow), escrow.lockId());
    }

    // --- commitBid ---

    function test_CommitBid_TakesBond() public {
        _commit();

        assertEq(paymentToken.balanceOf(iba1), 1000e18 - BOND, "bidder debited the bond");
        assertEq(_liveCompactBalance(), BOND, "bond custodied in The Compact");
        IEscrowAdapter.CommitBond memory bond = escrow.getCommitBond(worldwideDay, iba1);
        assertEq(bond.amount, BOND, "bond recorded");
    }

    function test_CommitBid_RevertsWithoutApproval() public {
        vm.prank(iba1);
        paymentToken.approve(address(escrow), 0);

        vm.prank(iba1);
        vm.expectRevert();
        auction.commitBid(worldwideDay, keccak256(_signature()));
    }

    function test_CommitBid_ZeroBond_SkipsEscrow() public {
        uint32 freeSeries = worldwideDay + 1;
        vm.prank(bridger);
        auction.auctionStart(freeSeries, IIntexAuction.WorldwideDayState.Green, _schedule(), _params(0));

        // No approval needed when the series carries no bond.
        address pauper = address(0xF00D);
        vm.prank(pauper);
        auction.commitBid(freeSeries, keccak256("sealed"));

        assertEq(escrow.getCommitBond(freeSeries, pauper).amount, 0, "no bond taken");
        assertEq(auction.committedBidsByHash(freeSeries, pauper), keccak256("sealed"), "commit recorded");
    }

    // --- cancelCommit / revealBid return paths ---

    function test_CancelCommit_ReturnsBondAndAllowsRecommit() public {
        _commit();
        vm.prank(iba1);
        auction.cancelCommit(worldwideDay);

        assertEq(paymentToken.balanceOf(iba1), 1000e18, "bond returned in full");
        assertEq(escrow.getCommitBond(worldwideDay, iba1).amount, 0, "bond deleted");

        // The freed slot re-locks a fresh bond on re-commit.
        _commit();
        assertEq(escrow.getCommitBond(worldwideDay, iba1).amount, BOND, "re-committed bond");
    }

    function test_RevealBid_ReturnsBondAndLocksEscrow() public {
        _commit();
        _enterRevealStage();

        vm.prank(iba1);
        auction.revealBid(worldwideDay, QTY, RATE, ISSUANCE_CCY, REFERENCE_CCY, uint64(block.chainid), _signature());

        // Bond came back, the bid escrow went out - net position is just the bid lock.
        assertEq(paymentToken.balanceOf(iba1), 1000e18 - LOCK_AMOUNT, "net = bid lock only");
        assertEq(escrow.getCommitBond(worldwideDay, iba1).amount, 0, "bond deleted");
        assertEq(escrow.getBidLock(worldwideDay, iba1).lockedAmount, LOCK_AMOUNT, "bid lock recorded");
        assertEq(_liveCompactBalance(), LOCK_AMOUNT, "Compact holds only the bid lock");
    }

    /// @dev The bond is released before the bid lock is taken, so it can fund the bid: a bidder
    ///      whose entire balance sits in the bond still reveals successfully.
    function test_RevealBid_BondFundsTheBid() public {
        // Burn everything beyond the bond, then commit (bond consumes the full balance).
        vm.prank(iba1);
        paymentToken.transfer(outsider, 1000e18 - BOND);
        _commit();
        assertEq(paymentToken.balanceOf(iba1), 0, "everything is in the bond");

        _enterRevealStage();
        vm.prank(iba1);
        auction.revealBid(worldwideDay, QTY, RATE, ISSUANCE_CCY, REFERENCE_CCY, uint64(block.chainid), _signature());

        assertEq(paymentToken.balanceOf(iba1), BOND - LOCK_AMOUNT, "bond funded the bid");
        assertEq(escrow.getBidLock(worldwideDay, iba1).lockedAmount, LOCK_AMOUNT, "bid lock recorded");
    }

    // --- claimCommitBond ---

    function test_ClaimCommitBond_RedDay_SkipsTimeGate() public {
        uint32 redSeries = worldwideDay + 7;
        vm.prank(bridger);
        auction.auctionStart(redSeries, IIntexAuction.WorldwideDayState.Red, _schedule(), _params(BOND));

        // Cancelled short-circuits the penalty window; with no bond the escrow reverts NotFound
        // instead of CommitBondNotYetClaimable.
        vm.prank(outsider);
        vm.expectRevert(IEscrowAdapter.CommitBondNotFound.selector);
        auction.claimCommitBond(redSeries, iba1);
    }

    function test_ClaimCommitBond_NoReveal_RevertsBeforeWindow() public {
        _commit();
        _enterRevealStage();

        uint32 claimableAt = uint32(startTs) + REVEAL_OFFSET + auction.UNREVEALED_BOND_LOCK_PERIOD();
        vm.warp(claimableAt - 1);
        vm.prank(outsider);
        vm.expectRevert(
            abi.encodeWithSelector(IIntexAuction.CommitBondNotYetClaimable.selector, claimableAt, claimableAt - 1)
        );
        auction.claimCommitBond(worldwideDay, iba1);
    }

    function test_ClaimCommitBond_NoReveal_ReleasesAfterWindow() public {
        _commit();
        _enterRevealStage();

        vm.warp(uint256(startTs) + REVEAL_OFFSET + auction.UNREVEALED_BOND_LOCK_PERIOD());
        vm.prank(outsider);
        auction.claimCommitBond(worldwideDay, iba1);

        assertEq(paymentToken.balanceOf(iba1), 1000e18, "bond returned after the penalty window");
        assertEq(paymentToken.balanceOf(outsider), 0, "caller gets nothing");
    }

    function test_ClaimCommitBond_RevertsForRevealedBidder() public {
        _commit();
        _enterRevealStage();
        vm.prank(iba1);
        auction.revealBid(worldwideDay, QTY, RATE, ISSUANCE_CCY, REFERENCE_CCY, uint64(block.chainid), _signature());

        vm.warp(uint256(startTs) + REVEAL_OFFSET + auction.UNREVEALED_BOND_LOCK_PERIOD());
        vm.prank(outsider);
        vm.expectRevert(IEscrowAdapter.CommitBondNotFound.selector);
        auction.claimCommitBond(worldwideDay, iba1);
    }

    function test_ClaimCommitBond_RevertsOnUnknownSeries() public {
        vm.expectRevert(IIntexAuction.AuctionNotFound.selector);
        auction.claimCommitBond(worldwideDay + 42, iba1);
    }
}
