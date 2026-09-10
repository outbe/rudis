// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {CrossChainTest} from "../helpers/CrossChainTest.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";
import {CreateSeriesLib} from "../helpers/CreateSeriesLib.sol";
import {IntexNFT1155Bridge} from "@contracts/shared/IntexNFT1155Bridge.sol";
import {BatchSendParam, IIntexNFT1155Bridge} from "@contracts/shared/interfaces/IIntexNFT1155Bridge.sol";

/// @dev Cross-chain conservation invariants for the IntexNFT1155 + IntexNFT1155Bridge pair:
///
///   - SI-08: `sum totalSupply(issuedId)` across chains is never larger than the on-chain
///     `issuedIntexCount` cap of the underlying series. Mint+bridge+round-trip moves balances
///     between chains but cannot inflate the global pool.
///   - SI-09: a `crosschainBurn` of `amount` on the source mints exactly `amount` on the destination,
///     even when the inbound crosschainMint fails: the parked-amount `failedCrosschainMints[receiveId][idx].amount`
///     holds the in-flight units until retry, so the source-burned amount equals
///     `destination-minted + destination-parked` at every step.
contract CrossChainSupplyConservationTest is CrossChainTest {
    uint32 private constant A_CHAIN_ID = 1;
    uint32 private constant B_CHAIN_ID = 2;

    uint32 private constant SERIES_ID_DAY = 20260401;
    bytes14 private constant SERIES_ID = "20260401-USD-U";
    uint256 private constant TOKEN_ID = uint256(uint112(SERIES_ID));
    uint32 private constant ISSUED_INTEX_COUNT = 10_000;

    IntexNFT1155 private tokenA;
    IntexNFT1155 private tokenB;
    IntexNFT1155Bridge private adapterA;
    IntexNFT1155Bridge private adapterB;

    address private user = address(0x1);

    function setUp() public {
        vm.deal(user, 1000 ether);

        _setUpBridge();

        tokenA = DeployProxy.intexNFT1155(address(this), address(this));
        tokenB = DeployProxy.intexNFT1155(address(this), address(this));

        adapterA = DeployProxy.intexNFT1155Bridge(address(tokenA), address(bridge), address(this));
        adapterB = DeployProxy.intexNFT1155Bridge(address(tokenB), address(bridge), address(this));

        tokenA.grantRole(tokenA.RELAYER_ROLE(), address(adapterA));
        tokenB.grantRole(tokenB.RELAYER_ROLE(), address(adapterB));

        adapterA.setRemoteMessenger(B_CHAIN_ID, _interop(B_CHAIN_ID, address(adapterB)));
        adapterB.setRemoteMessenger(A_CHAIN_ID, _interop(A_CHAIN_ID, address(adapterA)));

        tokenA.createSeries(CreateSeriesLib.params(SERIES_ID_DAY, ISSUED_INTEX_COUNT, 0));
        tokenB.createSeries(CreateSeriesLib.params(SERIES_ID_DAY, ISSUED_INTEX_COUNT, 0));

        tokenA.markQualified(SERIES_ID);
        tokenB.markQualified(SERIES_ID);
    }

    function test_HopAToB_TotalSupplyPreservedAndBelowCap() public {
        uint256 minted = 100;
        tokenA.issue(user, minted, SERIES_ID);

        uint256 bridged = 60;
        _send(adapterA, adapterB, A_CHAIN_ID, user, TOKEN_ID, bridged);

        // Source burns exactly `bridged`; destination mints exactly `bridged`.
        assertEq(tokenA.totalSupply(TOKEN_ID), minted - bridged, "A.totalSupply -= bridged");
        assertEq(tokenB.totalSupply(TOKEN_ID), bridged, "B.totalSupply += bridged");

        // SI-08: the global pool stays within the issuance cap and equals the original mint.
        uint256 totalAcrossChains = tokenA.totalSupply(TOKEN_ID) + tokenB.totalSupply(TOKEN_ID);
        assertEq(totalAcrossChains, minted, "SI-08: sum preserved");
        assertLe(totalAcrossChains, ISSUED_INTEX_COUNT, "SI-08: sum <= issuedIntexCount");
    }

    function test_RoundTripAToBToA_TotalSupplyPreserved() public {
        uint256 minted = 100;
        tokenA.issue(user, minted, SERIES_ID);

        _send(adapterA, adapterB, A_CHAIN_ID, user, TOKEN_ID, minted);
        assertEq(tokenA.totalSupply(TOKEN_ID), 0, "A drained after outbound");
        assertEq(tokenB.totalSupply(TOKEN_ID), minted, "B holds the bridged units");

        _send(adapterB, adapterA, B_CHAIN_ID, user, TOKEN_ID, minted);
        assertEq(tokenA.totalSupply(TOKEN_ID), minted, "A restored after return");
        assertEq(tokenB.totalSupply(TOKEN_ID), 0, "B drained after return");

        uint256 totalAcrossChains = tokenA.totalSupply(TOKEN_ID) + tokenB.totalSupply(TOKEN_ID);
        assertEq(totalAcrossChains, minted, "SI-08: sum preserved end-to-end");
        assertLe(totalAcrossChains, ISSUED_INTEX_COUNT, "SI-08: sum <= issuedIntexCount");
    }

    function test_ParkBranch_ConservesAcrossCrosschainBurnAndPark() public {
        // Pick a fresh series that exists on A but not on B: the inbound crosschainMint reverts
        // NonexistentToken and the transfer parks on B. Tokens are burned on A but not yet
        // minted on B - the missing amount lives in failedCrosschainMints.
        uint32 parkDay = 20260601;
        bytes14 parkSeries = "20260601-USD-U";
        uint256 parkTokenId = uint256(uint112(parkSeries));
        tokenA.createSeries(CreateSeriesLib.params(parkDay, ISSUED_INTEX_COUNT, 0));
        tokenA.markQualified(parkSeries);

        uint256 minted = 100;
        uint256 bridged = 100;
        tokenA.issue(user, minted, parkSeries);

        bytes32 receiveId = _send(adapterA, adapterB, A_CHAIN_ID, user, parkTokenId, bridged);

        // Source-side: the source intex burned the bridged amount; the cap-respecting supply on A
        // is the remainder.
        assertEq(tokenA.totalSupply(parkTokenId), minted - bridged, "A.totalSupply -= bridged");
        assertEq(tokenB.totalSupply(parkTokenId), 0, "B not minted (series missing)");

        // Park entry holds the in-flight amount, so the global accounting still adds up.
        (,, uint256 parkedAmount,, bool exists) = adapterB.failedCrosschainMints(receiveId, 0);
        assertTrue(exists, "park entry present");
        assertEq(parkedAmount, bridged, "park amount == bridged");

        uint256 total = tokenA.totalSupply(parkTokenId) + tokenB.totalSupply(parkTokenId) + parkedAmount;
        assertEq(total, minted, "SI-09: source-burned == dest-minted + dest-parked");

        // Fix the destination cause and retry - parked moves into B.totalSupply with no
        // change to the global sum.
        tokenB.createSeries(CreateSeriesLib.params(parkDay, ISSUED_INTEX_COUNT, 0));
        tokenB.markQualified(parkSeries);
        adapterB.retryCrosschainMint(receiveId, 0);

        assertEq(tokenB.totalSupply(parkTokenId), bridged, "B.totalSupply == bridged after retry");
        (,,,, bool stillExists) = adapterB.failedCrosschainMints(receiveId, 0);
        assertFalse(stillExists, "park entry cleared on retry");

        uint256 totalAfterRetry = tokenA.totalSupply(parkTokenId) + tokenB.totalSupply(parkTokenId);
        assertEq(totalAfterRetry, minted, "SI-09: sum preserved after retry");
    }

    function test_ReclaimToSource_ReMintsHolderOnOriginAndConservesSupply() public {
        // A series that exists on A but not B: bridging A->B parks on B (crosschainMint reverts).
        uint32 parkDay = 20260601;
        bytes14 parkSeries = "20260601-USD-U";
        uint256 parkTokenId = uint256(uint112(parkSeries));
        tokenA.createSeries(CreateSeriesLib.params(parkDay, ISSUED_INTEX_COUNT, 0));
        tokenA.markQualified(parkSeries);

        uint256 minted = 100;
        tokenA.issue(user, minted, parkSeries);

        bytes32 receiveId = _send(adapterA, adapterB, A_CHAIN_ID, user, parkTokenId, minted);

        (,, uint256 parkedAmount,, bool exists) = adapterB.failedCrosschainMints(receiveId, 0);
        assertTrue(exists, "parked on B");
        assertEq(parkedAmount, minted, "park holds the in-flight units");
        assertEq(tokenA.totalSupply(parkTokenId), 0, "A burned the bridged units");

        // Retry can never clear it while B lacks the series; reclaim to the origin is the only exit.
        adapterB.reclaimToSource(receiveId, 0);

        (,,,, bool stillExists) = adapterB.failedCrosschainMints(receiveId, 0);
        assertFalse(stillExists, "entry consumed on reclaim");

        // Deliver the reverse SEND_MULTI on A -> holder re-minted, global supply conserved end-to-end.
        _deliver(B_CHAIN_ID, address(adapterB), address(adapterA), bridge.lastPayload());
        assertEq(tokenA.totalSupply(parkTokenId), minted, "A restored via reclaim");
        assertEq(tokenB.totalSupply(parkTokenId), 0, "B holds nothing");
        assertEq(tokenA.balanceOf(user, parkTokenId), minted, "holder whole on origin");

        // A second reclaim reverts - the entry is gone.
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155Bridge.NoSuchFailedCrosschainMint.selector, receiveId, 0));
        adapterB.reclaimToSource(receiveId, 0);
    }

    function testFuzz_Hop_TotalSupplyAlwaysAtCap(uint256 issuedSeed, uint256 bridgedSeed) public {
        uint256 minted = bound(issuedSeed, 1, ISSUED_INTEX_COUNT);
        uint256 bridged = bound(bridgedSeed, 0, minted);

        tokenA.issue(user, minted, SERIES_ID);
        if (bridged > 0) {
            _send(adapterA, adapterB, A_CHAIN_ID, user, TOKEN_ID, bridged);
        }

        uint256 totalAcrossChains = tokenA.totalSupply(TOKEN_ID) + tokenB.totalSupply(TOKEN_ID);
        assertEq(totalAcrossChains, minted, "SI-08: sum preserved");
        assertLe(totalAcrossChains, ISSUED_INTEX_COUNT, "SI-08: sum <= issuedIntexCount");
    }

    /// @dev Bridge a single tokenId to `recipient` on the destination and deliver the packet.
    ///      Returns the destination `receiveId` (matching `MockERC7786Bridge._deliver`) so a parked
    ///      inbound can be retried.
    function _send(
        IntexNFT1155Bridge from,
        IntexNFT1155Bridge to,
        uint32 srcChainId,
        address recipient,
        uint256 tokenId,
        uint256 amount
    ) internal returns (bytes32 receiveId) {
        uint32 dstChainId = srcChainId == A_CHAIN_ID ? B_CHAIN_ID : A_CHAIN_ID;

        uint256[] memory tokenIds = new uint256[](1);
        tokenIds[0] = tokenId;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = amount;

        BatchSendParam memory params = BatchSendParam({
            dstChainId: dstChainId, to: bytes32(uint256(uint160(recipient))), tokenIds: tokenIds, amounts: amounts
        });

        uint256 fee = from.quoteBatchSend(params);
        vm.prank(recipient);
        from.batchSend{value: fee}(params);

        bytes memory packet = bridge.lastPayload();
        receiveId = keccak256(abi.encode(_interop(srcChainId, address(from)), packet));
        _deliver(srcChainId, address(from), address(to), packet);
    }
}
