// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {ReferenceCurrencyPriceLib} from "../helpers/ReferenceCurrencyPriceLib.sol";
import {CrossChainTest} from "../helpers/CrossChainTest.sol";
import {ERC1967Utils} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Utils.sol";
import {IIntexAuction} from "@contracts/target/interfaces/IIntexAuction.sol";
import {IIntexNFT1155} from "@contracts/shared/interfaces/IIntexNFT1155.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {IntexAuction} from "@contracts/target/IntexAuction.sol";
import {EscrowAdapter} from "@contracts/target/EscrowAdapter.sol";
import {OriginRouter} from "@contracts/origin/OriginRouter.sol";
import {IOriginRouter} from "@contracts/origin/interfaces/IOriginRouter.sol";
import {TargetRouter} from "@contracts/target/TargetRouter.sol";
import {IntexNFT1155Bridge} from "@contracts/shared/IntexNFT1155Bridge.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";
import {CreateSeriesLib} from "../helpers/CreateSeriesLib.sol";
import {
    UPGRADE_PROBE,
    IntexNFT1155V2,
    IntexNFT1155V2Reinit,
    IntexAuctionV2,
    EscrowAdapterV2,
    OriginRouterV2,
    TargetRouterV2,
    IntexNFT1155BridgeV2
} from "./UpgradeStubs.sol";
import {MockDesis} from "@test-mocks/MockDesis.sol";
import {MockWCOEN} from "@test-mocks/MockWCOEN.sol";
import {MockTheCompact} from "@test-mocks/MockTheCompact.sol";

interface IUpgradeProbe {
    function upgradeProbe() external pure returns (uint256);
}

/// @dev End-to-end upgrade rehearsal: deploy v1 behind a proxy, populate real state, upgrade the
///      implementation to a v1.1 stub that adds a new view, then assert that persisted state
///      survived the upgrade, the implementation pointer moved, and the new view is callable.
///      Covers one upgrade per impl contract. All four bridge clients (OriginRouter, TargetRouter, both
///      NFT bridge clients) run against a standalone {MockERC7786Bridge}.
contract UpgradeDrillTest is CrossChainTest {
    uint32 internal constant A_CHAIN_ID = 1;
    uint32 internal constant B_CHAIN_ID = 2;

    address internal admin = makeAddr("admin");

    function setUp() public {
        _setUpBridge();
    }

    function _assertUpgraded(address proxy, address newImpl) internal view {
        bytes32 implSlot = vm.load(proxy, ERC1967Utils.IMPLEMENTATION_SLOT);
        assertEq(address(uint160(uint256(implSlot))), newImpl, "implementation not swapped");
        assertEq(IUpgradeProbe(proxy).upgradeProbe(), UPGRADE_PROBE, "new view unreachable");
    }

    function test_Drill_IntexNFT1155() public {
        IntexNFT1155 nft = DeployProxy.intexNFT1155(admin, admin);
        address holder = makeAddr("holder");

        vm.startPrank(admin);
        nft.createSeries(CreateSeriesLib.params(7, 100, 0));
        nft.issue(holder, 3, CreateSeriesLib.seriesId(7));
        vm.stopPrank();

        IntexNFT1155V2 newImpl = new IntexNFT1155V2();
        vm.prank(admin);
        nft.upgradeToAndCall(address(newImpl), "");

        _assertUpgraded(address(nft), address(newImpl));
        assertEq(nft.balanceOf(holder, nft.issuedTokenId(CreateSeriesLib.seriesId(7))), 3, "balance lost");
        assertEq(nft.totalSupply(nft.issuedTokenId(CreateSeriesLib.seriesId(7))), 3, "supply lost");
        (,,,,,,,, uint32 issuedAt,,,, IIntexNFT1155.IntexState state) =
            nft.seriesData(nft.issuedTokenId(CreateSeriesLib.seriesId(7)));
        assertGt(issuedAt, 0, "series record lost");
        assertEq(uint8(state), uint8(IIntexNFT1155.IntexState.Issued), "state lost");
        assertTrue(nft.hasRole(nft.RELAYER_ROLE(), admin), "role lost");
    }

    // keccak256(abi.encode(uint256(keccak256("outbe.intex.IntexNFT1155V2Reinit")) - 1)) & ~bytes32(uint256(0xff))
    // Mirrors IntexNFT1155V2Reinit's private storage slot (UpgradeStubs.sol) so the migrated
    // field can be read via vm.load without a dedicated getter on the stub.
    bytes32 private constant _V2_REINIT_SLOT = 0xa6131e184e5aae318840a83507194e5ed64c56b50a1ac526e8c519cdd8bb2200;

    /// @dev Exercises the `upgradeToAndCall` init-data path: upgrade runs a `reinitializer(2)`
    ///      migration that sets a new v2 field, while pre-upgrade state survives.
    function test_Drill_IntexNFT1155_ReinitializerPath() public {
        IntexNFT1155 nft = DeployProxy.intexNFT1155(admin, admin);
        address holder = makeAddr("holder");

        vm.startPrank(admin);
        nft.createSeries(CreateSeriesLib.params(7, 100, 0));
        nft.issue(holder, 3, CreateSeriesLib.seriesId(7));
        vm.stopPrank();

        IntexNFT1155V2Reinit newImpl = new IntexNFT1155V2Reinit();
        vm.prank(admin);
        nft.upgradeToAndCall(address(newImpl), abi.encodeCall(IntexNFT1155V2Reinit.initializeV2, (UPGRADE_PROBE)));

        bytes32 implSlot = vm.load(address(nft), ERC1967Utils.IMPLEMENTATION_SLOT);
        assertEq(address(uint160(uint256(implSlot))), address(newImpl), "implementation not swapped");
        uint256 migratedFlag = uint256(vm.load(address(nft), _V2_REINIT_SLOT));
        assertEq(migratedFlag, UPGRADE_PROBE, "reinitializer did not run");
        assertEq(nft.balanceOf(holder, nft.issuedTokenId(CreateSeriesLib.seriesId(7))), 3, "balance lost across reinit");
        assertEq(nft.totalSupply(nft.issuedTokenId(CreateSeriesLib.seriesId(7))), 3, "supply lost across reinit");
    }

    function test_Drill_IntexAuction() public {
        IntexAuction auction = DeployProxy.intexAuction(admin, admin);
        address escrow = makeAddr("escrow");
        address bidder = makeAddr("bidder");

        IIntexAuction.AuctionSchedule memory schedule = IIntexAuction.AuctionSchedule({
            commitEnd: uint32(block.timestamp + 1 hours),
            revealEnd: uint32(block.timestamp + 2 hours),
            issuanceEnd: uint32(block.timestamp + 3 hours)
        });
        IIntexAuction.AuctionParams memory params = IIntexAuction.AuctionParams({
            promisLoadMinor: 1000,
            minIntexBidRate: 1,
            prices: ReferenceCurrencyPriceLib.onePriced(840, 1, 1, 1),
            callTrigger: IIntexAuction.IntexCallTrigger({callWindow: 0, callThreshold: 0, callNoticePeriod: 0}),
            minIntexBidQuantity: 1,
            commitBondMinor: 0
        });

        vm.startPrank(admin);
        auction.wire(escrow);
        auction.auctionStart(20260614, IIntexAuction.WorldwideDayState.Green, schedule, params);
        vm.stopPrank();
        vm.prank(bidder);
        auction.commitBid(20260614, keccak256("commit"));

        IntexAuctionV2 newImpl = new IntexAuctionV2();
        vm.prank(admin);
        auction.upgradeToAndCall(address(newImpl), "");

        _assertUpgraded(address(auction), address(newImpl));
        assertEq(address(auction.escrowContract()), escrow, "escrow wiring lost");
        assertEq(auction.committedBidsByHash(20260614, bidder), keccak256("commit"), "commit lost");
        assertEq(
            uint8(auction.getAuctionStage(20260614)), uint8(IIntexAuction.AuctionStage.CommittingBids), "stage lost"
        );
    }

    function test_Drill_EscrowAdapter() public {
        EscrowAdapter escrow = DeployProxy.escrowAdapter(admin, admin);
        MockWCOEN token = new MockWCOEN();
        MockTheCompact compactMock = new MockTheCompact();
        address auction = makeAddr("auction");

        vm.prank(admin);
        escrow.wire(auction, address(compactMock), address(token));
        uint96 allocatorId = escrow.allocatorId();
        bytes12 lockTag = escrow.lockTag();

        EscrowAdapterV2 newImpl = new EscrowAdapterV2();
        vm.prank(admin);
        escrow.upgradeToAndCall(address(newImpl), "");

        _assertUpgraded(address(escrow), address(newImpl));
        assertEq(escrow.intexAuctionContract(), auction, "auction wiring lost");
        assertEq(address(escrow.paymentToken()), address(token), "token wiring lost");
        assertEq(escrow.allocatorId(), allocatorId, "allocatorId lost");
        assertEq(escrow.lockTag(), lockTag, "lockTag lost");
        assertTrue(escrow.hasRole(escrow.AUCTION_ROLE(), auction), "auction role lost");
    }

    function test_Drill_OriginRouter() public {
        OriginRouter origin = DeployProxy.originRouter(address(bridge), admin);
        MockDesis desisMock = new MockDesis();
        address factory = makeAddr("factory");
        bytes memory remote = _interop(B_CHAIN_ID, address(0xBEEF));
        uint32 day = 20260614;

        vm.startPrank(admin);
        origin.wire(address(desisMock), factory);
        origin.setRemoteMessenger(B_CHAIN_ID, remote);
        origin.addTarget(B_CHAIN_ID);
        vm.stopPrank();

        // Freeze the day's target snapshot, then drop the peer so the clearing leg parks.
        IOriginRouter.AuctionStageStartParams memory p;
        p.prices = ReferenceCurrencyPriceLib.one(840, 1, 2, 3);
        p.worldwideDay = day;
        p.dayState = 1;
        vm.prank(address(desisMock));
        origin.sendAuctionStageStart(p);
        vm.prank(admin);
        origin.setRemoteMessenger(B_CHAIN_ID, "");
        vm.prank(address(desisMock));
        origin.sendAuctionStageClearing(day);

        OriginRouterV2 newImpl = new OriginRouterV2(address(bridge));
        vm.prank(admin);
        origin.upgradeToAndCall(address(newImpl), "");

        _assertUpgraded(address(origin), address(newImpl));
        assertEq(origin.desis(), address(desisMock), "desis wiring lost");
        assertEq(origin.intexFactory(), factory, "factory wiring lost");
        // Appended multi-target storage must survive the upgrade (tail-appended erc7201 fields).
        assertTrue(origin.isTarget(B_CHAIN_ID), "target registry lost");
        uint32[] memory snapshot = origin.targetsOf(day);
        assertEq(snapshot.length, 1, "day snapshot lost");
        assertEq(snapshot[0], B_CHAIN_ID, "day snapshot chain lost");
        IOriginRouter.ParkedSend memory parked = origin.parkedSend(0);
        assertEq(parked.dstChainId, B_CHAIN_ID, "parked send lost");
        assertFalse(parked.sent, "parked send flag lost");

        // The park queue stays functional: restore the peer and flush post-upgrade.
        vm.prank(admin);
        origin.setRemoteMessenger(B_CHAIN_ID, remote);
        assertEq(origin.remoteMessenger(B_CHAIN_ID), remote, "remote messenger lost");
        origin.flushPendingSend(0);
        assertTrue(origin.parkedSend(0).sent, "flush broken after upgrade");
    }

    function test_Drill_TargetRouter() public {
        TargetRouter target = DeployProxy.targetRouter(address(bridge), admin, A_CHAIN_ID);
        address auction = makeAddr("auction");
        address intex = makeAddr("intex");
        address escrow = makeAddr("escrow");
        bytes memory remote = _interop(A_CHAIN_ID, address(0xCAFE));

        vm.startPrank(admin);
        target.wire(auction, intex, escrow);
        target.setRemoteMessenger(A_CHAIN_ID, remote);
        vm.stopPrank();

        TargetRouterV2 newImpl = new TargetRouterV2(address(bridge), A_CHAIN_ID);
        vm.prank(admin);
        target.upgradeToAndCall(address(newImpl), "");

        _assertUpgraded(address(target), address(newImpl));
        assertEq(address(target.auction()), auction, "auction wiring lost");
        assertEq(address(target.escrowAdapter()), escrow, "escrow wiring lost");
        assertEq(target.remoteMessenger(A_CHAIN_ID), remote, "remote messenger lost");
    }

    function test_Drill_IntexNFT1155Bridge() public {
        address tokenAddr = makeAddr("token");
        IntexNFT1155Bridge batch = DeployProxy.intexNFT1155Bridge(tokenAddr, address(bridge), admin);
        address relayer = makeAddr("relayer");
        bytes memory remote = _interop(B_CHAIN_ID, address(0xBEEF));

        vm.startPrank(admin);
        batch.setRemoteMessenger(B_CHAIN_ID, remote);
        batch.grantRole(batch.DEFAULT_ADMIN_ROLE(), relayer);
        vm.stopPrank();

        IntexNFT1155BridgeV2 newImpl = new IntexNFT1155BridgeV2(tokenAddr, address(bridge));
        vm.prank(admin);
        batch.upgradeToAndCall(address(newImpl), "");

        _assertUpgraded(address(batch), address(newImpl));
        assertEq(batch.remoteMessenger(B_CHAIN_ID), remote, "remote messenger lost");
        assertEq(address(batch.token()), tokenAddr, "token immutable lost");
        assertTrue(batch.hasRole(batch.DEFAULT_ADMIN_ROLE(), relayer), "role lost");
    }
}
