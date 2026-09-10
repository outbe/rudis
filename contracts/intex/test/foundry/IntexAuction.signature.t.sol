// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {ReferenceCurrencyPriceLib} from "./helpers/ReferenceCurrencyPriceLib.sol";
import {Test, Vm} from "forge-std/Test.sol";
import {IntexAuction} from "@contracts/target/IntexAuction.sol";
import {DeployProxy} from "./helpers/DeployProxy.sol";
import {IIntexAuction} from "@contracts/target/interfaces/IIntexAuction.sol";
import {MockAuctionEscrow} from "@test-mocks/MockAuctionEscrow.sol";

/// @notice Focused suite for the EIP-712 reveal signature scheme: cross-chain and
///         cross-instance replay protection, malleability rejection, the new commit-side
///         and chainId guards, the golden typed-data digest, and the indexer events.
contract AuctionSignatureTest is Test {
    uint16 internal constant ISSUANCE_CCY = 840;
    uint16 internal constant REFERENCE_CCY = 840;

    IntexAuction internal auction;
    MockAuctionEscrow internal escrow;

    address internal admin = address(1);
    address internal bridger = address(2);

    uint256 internal iba1Pk = 0x100;
    uint256 internal iba2Pk = 0x200;
    address internal iba1;
    address internal iba2;

    bytes32 internal constant REVEAL_BID_TYPEHASH = keccak256(
        "RevealBid(uint32 worldwideDay,address bidder,uint16 quantity,uint32 bidRate,uint16 issuanceCurrency,uint16 referenceCurrency)"
    );
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    /// @dev secp256k1 half-order. ECDSA.recover rejects signatures with `s > HALF_N` as malleable.
    bytes32 internal constant SECP256K1_HALF_N = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0;
    bytes32 internal constant SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;

    uint32 internal constant COMMIT_OFFSET = 100;
    uint32 internal constant REVEAL_OFFSET = 200;
    uint32 internal constant ISSUANCE_OFFSET = 300;

    function setUp() public {
        iba1 = vm.addr(iba1Pk);
        iba2 = vm.addr(iba2Pk);

        auction = DeployProxy.intexAuction(admin, bridger);
        escrow = new MockAuctionEscrow();

        vm.startPrank(admin);
        auction.grantRole(auction.RELAYER_ROLE(), bridger);
        auction.wire(address(escrow));
        vm.stopPrank();
    }

    // --- Helpers ---

    function _domainSeparator(address verifyingContract, uint256 chainid) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes("IntexAuction")),
                keccak256(bytes("1")),
                chainid,
                verifyingContract
            )
        );
    }

    function _structHash(uint32 worldwideDay, address bidder, uint16 qty, uint32 rate) internal pure returns (bytes32) {
        return keccak256(abi.encode(REVEAL_BID_TYPEHASH, worldwideDay, bidder, qty, rate, ISSUANCE_CCY, REFERENCE_CCY));
    }

    function _digest(
        address verifyingContract,
        uint256 chainid,
        uint32 worldwideDay,
        address bidder,
        uint16 qty,
        uint32 rate
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01", _domainSeparator(verifyingContract, chainid), _structHash(worldwideDay, bidder, qty, rate)
            )
        );
    }

    function _signFor(
        uint256 pk,
        address verifyingContract,
        uint256 chainid,
        uint32 worldwideDay,
        address bidder,
        uint16 qty,
        uint32 rate
    ) internal pure returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(pk, _digest(verifyingContract, chainid, worldwideDay, bidder, qty, rate));
        return abi.encodePacked(r, s, v);
    }

    function _start(uint32 worldwideDay) internal {
        IIntexAuction.AuctionSchedule memory schedule = IIntexAuction.AuctionSchedule({
            commitEnd: uint32(block.timestamp + COMMIT_OFFSET),
            revealEnd: uint32(block.timestamp + REVEAL_OFFSET),
            issuanceEnd: uint32(block.timestamp + ISSUANCE_OFFSET)
        });
        IIntexAuction.AuctionParams memory params = IIntexAuction.AuctionParams({
            promisLoadMinor: 1000,
            minIntexBidRate: 10,
            prices: ReferenceCurrencyPriceLib.onePriced(840, 100, 100, 100),
            callTrigger: IIntexAuction.IntexCallTrigger({callWindow: 0, callThreshold: 0, callNoticePeriod: 0}),
            minIntexBidQuantity: 1,
            commitBondMinor: 0
        });
        vm.prank(bridger);
        auction.auctionStart(worldwideDay, IIntexAuction.WorldwideDayState.Green, schedule, params);
    }

    function _enterReveal(uint32) internal {
        vm.warp(block.timestamp + COMMIT_OFFSET + 1);
    }

    function _commit(IntexAuction target, uint32 worldwideDay, address bidder, bytes memory sig) internal {
        vm.prank(bidder);
        target.commitBid(worldwideDay, keccak256(sig));
    }

    // --- commitBid: zero-hash guard (B1.3) ---

    function test_commitBid_revertsOnZeroHash() public {
        uint32 worldwideDay = 20260101;
        _start(worldwideDay);

        vm.expectRevert(IIntexAuction.InvalidCommitHash.selector);
        vm.prank(iba1);
        auction.commitBid(worldwideDay, bytes32(0));
    }

    // --- revealBid: WrongChain guard (B1.4) ---

    function test_revealBid_revertsOnWrongChain_paramMismatch() public {
        uint32 worldwideDay = 20260102;
        _start(worldwideDay);

        bytes memory sig = _signFor(iba1Pk, address(auction), block.chainid, worldwideDay, iba1, 5, 50);
        _commit(auction, worldwideDay, iba1, sig);
        _enterReveal(worldwideDay);

        uint64 wrongChain = uint64(block.chainid + 1);
        vm.expectRevert(abi.encodeWithSelector(IIntexAuction.WrongChain.selector, block.chainid, uint256(wrongChain)));
        vm.prank(iba1);
        auction.revealBid(worldwideDay, 5, 50, ISSUANCE_CCY, REFERENCE_CCY, wrongChain, sig);
    }

    function test_revealBid_revertsAfterChainidFlip() public {
        uint32 worldwideDay = 20260103;
        _start(worldwideDay);

        // Sign for the chain we deployed on.
        uint256 origChain = block.chainid;
        bytes memory sig = _signFor(iba1Pk, address(auction), origChain, worldwideDay, iba1, 5, 50);
        _commit(auction, worldwideDay, iba1, sig);
        _enterReveal(worldwideDay);

        // Simulate the EVM moving to a different chain (e.g. fork). Caller passes the new chainid
        // - guard is fine - but the EIP-712 domain rebuilds with the new chainid, so the signature
        // recovers the wrong signer and `RevealHashMismatch` fires.
        uint256 newChain = origChain + 1;
        vm.chainId(newChain);
        vm.expectRevert(IIntexAuction.RevealHashMismatch.selector);
        vm.prank(iba1);
        auction.revealBid(worldwideDay, 5, 50, ISSUANCE_CCY, REFERENCE_CCY, uint64(newChain), sig);
    }

    // --- Cross-chain replay (B1.5) ---

    function test_replay_revertsAcrossChains() public {
        uint32 worldwideDay = 20260104;
        _start(worldwideDay);

        // Bidder A signs for chain X (some other chain that is NOT the current one) - replay attacker
        // captures it and tries to use against the contract running on the current chain.
        uint256 attackChain = block.chainid + 17;
        bytes memory crossChainSig = _signFor(iba1Pk, address(auction), attackChain, worldwideDay, iba1, 5, 50);
        _commit(auction, worldwideDay, iba1, crossChainSig);
        _enterReveal(worldwideDay);

        // Caller passes block.chainid in the param so the WrongChain guard is silent, but the domain
        // separator on this chain differs from the one used to sign - recovery fails.
        vm.expectRevert(IIntexAuction.RevealHashMismatch.selector);
        vm.prank(iba1);
        auction.revealBid(worldwideDay, 5, 50, ISSUANCE_CCY, REFERENCE_CCY, uint64(block.chainid), crossChainSig);
    }

    // --- Cross-instance replay (B1.5) ---

    function test_replay_revertsAcrossInstances() public {
        uint32 worldwideDay = 20260105;

        // Deploy a second IntexAuction on the same chain.
        IntexAuction other = DeployProxy.intexAuction(admin, bridger);
        MockAuctionEscrow otherEscrow = new MockAuctionEscrow();
        vm.startPrank(admin);
        other.grantRole(other.RELAYER_ROLE(), bridger);
        other.wire(address(otherEscrow));
        vm.stopPrank();

        // Start an identical auction on both instances.
        IIntexAuction.AuctionSchedule memory schedule = IIntexAuction.AuctionSchedule({
            commitEnd: uint32(block.timestamp + COMMIT_OFFSET),
            revealEnd: uint32(block.timestamp + REVEAL_OFFSET),
            issuanceEnd: uint32(block.timestamp + ISSUANCE_OFFSET)
        });
        IIntexAuction.AuctionParams memory params = IIntexAuction.AuctionParams({
            promisLoadMinor: 1000,
            minIntexBidRate: 10,
            prices: ReferenceCurrencyPriceLib.onePriced(840, 100, 100, 100),
            callTrigger: IIntexAuction.IntexCallTrigger({callWindow: 0, callThreshold: 0, callNoticePeriod: 0}),
            minIntexBidQuantity: 1,
            commitBondMinor: 0
        });
        vm.startPrank(bridger);
        auction.auctionStart(worldwideDay, IIntexAuction.WorldwideDayState.Green, schedule, params);
        other.auctionStart(worldwideDay, IIntexAuction.WorldwideDayState.Green, schedule, params);
        vm.stopPrank();

        // Bidder signs for `auction` (verifyingContract=auction). Attacker tries to replay on `other`.
        bytes memory sigForAuction = _signFor(iba1Pk, address(auction), block.chainid, worldwideDay, iba1, 5, 50);
        _commit(other, worldwideDay, iba1, sigForAuction);

        // Move to reveal stage on `other`.
        vm.warp(block.timestamp + COMMIT_OFFSET + 1);

        // Reveal on `other` - domain separator binds verifyingContract=other; recovery yields a
        // wrong signer.
        vm.expectRevert(IIntexAuction.RevealHashMismatch.selector);
        vm.prank(iba1);
        other.revealBid(worldwideDay, 5, 50, ISSUANCE_CCY, REFERENCE_CCY, uint64(block.chainid), sigForAuction);
    }

    // --- Signature malleability (B1.5) ---

    function test_revealBid_revertsOnMalleableSignature() public {
        uint32 worldwideDay = 20260106;
        _start(worldwideDay);

        // Build a canonical signature.
        bytes32 digest = _digest(address(auction), block.chainid, worldwideDay, iba1, 5, 50);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(iba1Pk, digest);
        bytes memory canonical = abi.encodePacked(r, s, v);
        _commit(auction, worldwideDay, iba1, canonical);
        _enterReveal(worldwideDay);

        // Construct the malleable counterpart: s' = n - s, v' = v ^ 1.
        bytes32 mallS = bytes32(uint256(SECP256K1_N) - uint256(s));
        require(uint256(mallS) > uint256(SECP256K1_HALF_N), "test: precondition; mallS must be > half-n");
        uint8 mallV = v == 27 ? 28 : 27;
        bytes memory malleable = abi.encodePacked(r, mallS, mallV);

        // OZ ECDSA rejects high-s signatures with ECDSAInvalidSignatureS(s).
        bytes4 invalidS = bytes4(keccak256("ECDSAInvalidSignatureS(bytes32)"));
        vm.expectRevert(abi.encodeWithSelector(invalidS, mallS));
        vm.prank(iba1);
        auction.revealBid(worldwideDay, 5, 50, ISSUANCE_CCY, REFERENCE_CCY, uint64(block.chainid), malleable);
    }

    // --- Garbage signature (zero-address recovery) (B1.5) ---

    function test_revealBid_revertsOnWrongLengthSignature() public {
        uint32 worldwideDay = 20260107;
        _start(worldwideDay);

        // Commit with a real signature first so the bid is bookable.
        bytes memory realSig = _signFor(iba1Pk, address(auction), block.chainid, worldwideDay, iba1, 5, 50);
        _commit(auction, worldwideDay, iba1, realSig);
        _enterReveal(worldwideDay);

        // Submit a 64-byte signature (truncated). OZ ECDSA reverts ECDSAInvalidSignatureLength.
        bytes memory truncated = new bytes(64);
        bytes4 invalidLen = bytes4(keccak256("ECDSAInvalidSignatureLength(uint256)"));
        vm.expectRevert(abi.encodeWithSelector(invalidLen, uint256(64)));
        vm.prank(iba1);
        auction.revealBid(worldwideDay, 5, 50, ISSUANCE_CCY, REFERENCE_CCY, uint64(block.chainid), truncated);
    }

    function test_revealBid_revertsOnAllZeroSignature() public {
        uint32 worldwideDay = 20260108;
        _start(worldwideDay);

        bytes memory realSig = _signFor(iba1Pk, address(auction), block.chainid, worldwideDay, iba1, 5, 50);
        _commit(auction, worldwideDay, iba1, realSig);
        _enterReveal(worldwideDay);

        // 65 zero bytes - recovers to a zero/garbage address, fails malleability or signer check.
        bytes memory zeroes = new bytes(65);
        // OZ ECDSA either reverts ECDSAInvalidSignature (v not 27/28) or treats r/s/v as a
        // garbage but valid-length input that recovers a non-msg.sender address. Either way the
        // call must revert; we only assert it does.
        vm.expectRevert();
        vm.prank(iba1);
        auction.revealBid(worldwideDay, 5, 50, ISSUANCE_CCY, REFERENCE_CCY, uint64(block.chainid), zeroes);
    }

    // --- Golden digest snapshot (B1.5) ---

    /// @dev Lock the EIP-712 typed-data shape: any change to the domain (`name`, `version`,
    ///      chainid mixing) or the `RevealBid` struct (field order/types) flips the digest.
    ///      Inputs:
    ///        chainid           = 56          (BSC mainnet)
    ///        verifyingContract = 0x..00cafe
    ///        worldwideDay          = 20260108
    ///        bidder            = 0x..00abcd
    ///        quantity          = 5
    ///        bidRate           = 1100
    ///        issuanceCurrency  = 840
    ///        referenceCurrency = 840
    function test_eip712_goldenDigest() public pure {
        address vc = 0x000000000000000000000000000000000000cafE;
        address bidder = 0x000000000000000000000000000000000000ABcD;
        bytes32 expected = 0xdcb1a612bff25a4e281245ff212f41aa908bc240455f7ef28044d81c65d41d69;

        bytes32 domain = keccak256(
            abi.encode(EIP712_DOMAIN_TYPEHASH, keccak256(bytes("IntexAuction")), keccak256(bytes("1")), uint256(56), vc)
        );
        bytes32 structH = keccak256(
            abi.encode(
                REVEAL_BID_TYPEHASH, uint32(20260108), bidder, uint16(5), uint32(1100), ISSUANCE_CCY, REFERENCE_CCY
            )
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domain, structH));

        assertEq(digest, expected, "typed-data digest drift");
    }

    // --- Indexer events ---

    function test_emit_BidCommitted() public {
        uint32 worldwideDay = 20260109;
        _start(worldwideDay);

        bytes memory sig = _signFor(iba1Pk, address(auction), block.chainid, worldwideDay, iba1, 5, 50);
        bytes32 commitHash = keccak256(sig);

        vm.expectEmit(true, true, false, true);
        emit IIntexAuction.BidCommitted(worldwideDay, iba1, commitHash);
        vm.prank(iba1);
        auction.commitBid(worldwideDay, commitHash);
    }

    function test_emit_CommitCancelled() public {
        uint32 worldwideDay = 20260110;
        _start(worldwideDay);

        bytes memory sig = _signFor(iba1Pk, address(auction), block.chainid, worldwideDay, iba1, 5, 50);
        _commit(auction, worldwideDay, iba1, sig);

        vm.expectEmit(true, true, false, false);
        emit IIntexAuction.CommitCancelled(worldwideDay, iba1);
        vm.prank(iba1);
        auction.cancelCommit(worldwideDay);
    }

    function test_emit_BidRevealed() public {
        uint32 worldwideDay = 20260111;
        _start(worldwideDay);

        bytes memory sig = _signFor(iba1Pk, address(auction), block.chainid, worldwideDay, iba1, 5, 50);
        _commit(auction, worldwideDay, iba1, sig);
        _enterReveal(worldwideDay);

        vm.expectEmit(true, true, false, true);
        emit IIntexAuction.BidRevealed(worldwideDay, iba1, 5, 50, ISSUANCE_CCY, REFERENCE_CCY);
        vm.prank(iba1);
        auction.revealBid(worldwideDay, 5, 50, ISSUANCE_CCY, REFERENCE_CCY, uint64(block.chainid), sig);
    }
}
