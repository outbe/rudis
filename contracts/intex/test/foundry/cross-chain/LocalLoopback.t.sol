// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {BridgeMsgCodec} from "@contracts/shared/libs/BridgeMsgCodec.sol";
import {ReferenceCurrencyPriceLib} from "../helpers/ReferenceCurrencyPriceLib.sol";
import {Test} from "forge-std/Test.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";

import {OriginRouter} from "@contracts/origin/OriginRouter.sol";
import {IOriginRouter} from "@contracts/origin/interfaces/IOriginRouter.sol";
import {IDesis} from "@contracts/origin/interfaces/IDesis.sol";
import {IERC7786TokenReceiver} from "@contracts/origin/interfaces/IERC7786TokenReceiver.sol";
import {TargetRouter} from "@contracts/target/TargetRouter.sol";
import {IntexAuction} from "@contracts/target/IntexAuction.sol";
import {CreateSeriesLib} from "../helpers/CreateSeriesLib.sol";
import {IIntexAuction} from "@contracts/target/interfaces/IIntexAuction.sol";
import {EscrowAdapter} from "@contracts/target/EscrowAdapter.sol";
import {IEscrowAdapter} from "@contracts/target/interfaces/IEscrowAdapter.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {IntexNFT1155Bridge} from "@contracts/shared/IntexNFT1155Bridge.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";
import {MockERC7786Bridge} from "@test-mocks/MockERC7786Bridge.sol";
import {MockERC20} from "@test-mocks/MockERC20.sol";
import {MockTheCompact} from "@test-mocks/MockTheCompact.sol";

/// @dev Desis precompile stand-in that records the relayed bid intake.
uint16 constant ISSUANCE_CCY = 840;
uint16 constant REFERENCE_CCY = 840;

contract RecordingDesis {
    uint32 public lastDay;
    uint32 public lastSrcChainId;
    uint32 public lastGeneration;
    uint16 public lastTotalBatches;
    address[] public bidders;
    uint16[] public quantities;
    uint32[] public rates;

    uint32 public doneSrcChainId;
    uint16 public doneTotalBatches;
    uint32 public doneTotalBids;

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IDesis).interfaceId || interfaceId == type(IERC165).interfaceId;
    }

    function processBidsBatch(
        uint32 worldwideDay,
        uint32 srcChainId,
        uint32 relayGeneration,
        uint16, /* batchIndex */
        uint16 totalBatches,
        address[] calldata bidderAddresses,
        uint256[] calldata packedBids
    ) external {
        lastDay = worldwideDay;
        lastSrcChainId = srcChainId;
        lastGeneration = relayGeneration;
        lastTotalBatches = totalBatches;
        for (uint256 i = 0; i < bidderAddresses.length; i++) {
            (uint16 q, uint32 r,,,) = BridgeMsgCodec.unpackBid(packedBids[i]);
            bidders.push(bidderAddresses[i]);
            quantities.push(q);
            rates.push(r);
        }
    }

    function processBidsDone(uint32, uint32 srcChainId, uint32, uint16 totalBatches, uint32 totalBids) external {
        doneSrcChainId = srcChainId;
        doneTotalBatches = totalBatches;
        doneTotalBids = totalBids;
    }

    function bidsCount() external view returns (uint256) {
        return bidders.length;
    }
}

/// @dev IntexFactory precompile stand-in: records the native proceeds hand-off.
contract RecordingFactory {
    uint32 public lastDay;
    uint32 public lastSrcChainId;
    uint256 public lastValue;
    uint256 public calls;

    function distribute(uint32 worldwideDay, uint32 srcChainId) external payable {
        lastDay = worldwideDay;
        lastSrcChainId = srcChainId;
        lastValue = msg.value;
        calls++;
    }
}

/// @dev WETH-style wCOEN: ERC20 for the escrow plus a native `withdraw` (paid from its own
///      pre-funded balance) for the origin unwrap.
contract WCOEN is MockERC20 {
    constructor() MockERC20("Wrapped Rudis", "wrudis", 18) {}

    function withdraw(uint256 wad) external {
        (bool ok,) = payable(msg.sender).call{value: wad}("");
        require(ok, "withdraw failed");
    }

    receive() external payable {}
}

/// @dev Same-chain token bridge: delivers the wCOEN and invokes the receiver hook in the same tx,
///      mirroring the composed loopback token leg.
contract SyncTokenBridge {
    IERC20 internal immutable TOKEN;

    constructor(IERC20 token) {
        TOKEN = token;
    }

    function quoteSend(uint32, address, uint256, bytes calldata, uint256) external pure returns (uint256) {
        return 0;
    }

    function sendAndCall(uint32, address to, uint256 amount, bytes calldata extraData, uint256)
        external
        payable
        returns (bytes32)
    {
        TOKEN.transferFrom(msg.sender, to, amount);
        IERC7786TokenReceiver(to)
            .onCrosschainTokensReceived(
                uint32(block.chainid), InteroperableAddress.formatEvmV1(block.chainid, msg.sender), amount, extraData
            );
        return bytes32(0);
    }
}

/// @dev Origin==target on one chain: both routers, the auction, the escrow and the canonical NFT
///      are wired to a synchronous in-process bridge, so every protocol message - including the
///      nested bids relay fired from inside the CLEARING delivery - executes in the sending
///      transaction, mirroring the loopback transport. Each delivery runs under its exact IntexGas
///      executionGasLimit attribute, so an undersized budget out-of-gases the delivery and fails
///      the walk: the test doubles as the budget check.
contract LocalLoopbackTest is Test {
    uint32 internal constant DAY = 20260714;
    uint128 internal constant PROMIS_LOAD_MINOR = 1e6;
    uint256 internal constant INITIAL_WCOEN_BALANCE = 100e18;

    bytes32 internal constant REVEAL_BID_TYPEHASH = keccak256(
        "RevealBid(uint32 worldwideDay,address bidder,uint16 quantity,uint32 bidRate,uint16 issuanceCurrency,uint16 referenceCurrency)"
    );

    MockERC7786Bridge internal bridge;
    OriginRouter internal origin;
    TargetRouter internal target;
    IntexAuction internal auction;
    EscrowAdapter internal escrow;
    IntexNFT1155 internal intex;
    IntexNFT1155Bridge internal nftBridge;
    RecordingDesis internal desis;
    RecordingFactory internal factory;
    WCOEN internal wcoen;
    SyncTokenBridge internal tokenBridge;
    MockTheCompact internal compact;

    uint32 internal local;
    uint256 internal startTs;

    uint256 internal iba1Pk = 0x100;
    uint256 internal iba2Pk = 0x200;
    address internal iba1;
    address internal iba2;

    function setUp() public {
        vm.warp(1_760_000_000);
        startTs = block.timestamp;
        local = uint32(block.chainid);
        iba1 = vm.addr(iba1Pk);
        iba2 = vm.addr(iba2Pk);

        // Synchronous delivery under the exact per-message gas attribute, like the loopback transport.
        bridge = new MockERC7786Bridge();
        bridge.setEnforceGasAttribute(true);

        intex = DeployProxy.intexNFT1155(address(this), address(this));
        auction = DeployProxy.intexAuction(address(this), address(this));
        origin = DeployProxy.originRouter(address(bridge), address(this));
        target = DeployProxy.targetRouter(address(bridge), address(this), local);
        nftBridge = DeployProxy.intexNFT1155Bridge(address(intex), address(bridge), address(this));

        desis = new RecordingDesis();
        factory = new RecordingFactory();
        wcoen = new WCOEN();
        tokenBridge = new SyncTokenBridge(IERC20(address(wcoen)));
        vm.deal(address(wcoen), INITIAL_WCOEN_BALANCE * 2); // native backing for both unwrap paths

        escrow = DeployProxy.escrowAdapter(address(this), address(this));
        compact = new MockTheCompact();
        escrow.wire(address(auction), address(compact), address(wcoen));
        escrow.setProceedsRecipient(address(target));
        compact.setResetPeriodSeconds(0);

        // Peers: each router's remote on the local chainId is the other router.
        origin.setRemoteMessenger(local, InteroperableAddress.formatEvmV1(local, address(target)));
        target.setRemoteMessenger(local, InteroperableAddress.formatEvmV1(local, address(origin)));

        origin.wire(address(desis), address(factory));
        origin.addTarget(local);
        origin.setProceedsRoute(address(tokenBridge), address(wcoen));

        target.wire(address(auction), address(intex), address(escrow));
        target.setProceedsRoute(address(tokenBridge), address(origin));

        auction.wire(address(escrow));
        auction.grantRole(auction.RELAYER_ROLE(), address(target));
        intex.grantRole(intex.RELAYER_ROLE(), address(target));
        escrow.grantRole(escrow.RELAYER_ROLE(), address(target));

        wcoen.mint(iba1, INITIAL_WCOEN_BALANCE);
        wcoen.mint(iba2, INITIAL_WCOEN_BALANCE);
        vm.prank(iba1);
        wcoen.approve(address(escrow), type(uint256).max);
        vm.prank(iba2);
        wcoen.approve(address(escrow), type(uint256).max);
    }

    function _stageStartParams() internal view returns (IOriginRouter.AuctionStageStartParams memory p) {
        p.worldwideDay = DAY;
        p.commitEnd = uint32(startTs + 100);
        p.revealEnd = uint32(startTs + 200);
        p.issuanceEnd = uint32(startTs + 300);
        p.promisLoadMinor = PROMIS_LOAD_MINOR;
        p.minIntexBidRate = 600_000;
        p.prices = ReferenceCurrencyPriceLib.one(840, 1e6, 100, 200);
        p.minIntexBidQuantity = 1;
        p.dayState = 1;
    }

    function _sig(address bidder, uint16 qty, uint32 rate, uint256 pk) internal view returns (bytes memory) {
        bytes32 structHash =
            keccak256(abi.encode(REVEAL_BID_TYPEHASH, DAY, bidder, qty, rate, ISSUANCE_CCY, REFERENCE_CCY));
        bytes32 domainSeparator = keccak256(
            abi.encode(
                keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
                keccak256(bytes("IntexAuction")),
                keccak256(bytes("1")),
                block.chainid,
                address(auction)
            )
        );
        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(pk, keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash)));
        return abi.encodePacked(r, s, v);
    }

    function _commitAndReveal(address bidder, uint16 qty, uint32 rate, uint256 pk) internal {
        bytes memory signature = _sig(bidder, qty, rate, pk);
        vm.prank(bidder);
        auction.revealBid(DAY, qty, rate, ISSUANCE_CCY, REFERENCE_CCY, uint64(block.chainid), signature);
    }

    function test_FullWalk_OriginAsTarget() public {
        // 1. STAGE_START broadcast lands synchronously: hub -> loopback -> hub -> TargetRouter -> auction.
        vm.prank(address(desis));
        origin.sendAuctionStageStart(_stageStartParams());
        assertEq(uint8(auction.getAuctionStage(DAY)), uint8(IIntexAuction.AuctionStage.CommittingBids), "not started");
        uint32[] memory snapshot = origin.targetsOf(DAY);
        assertEq(snapshot.length, 1, "snapshot size");
        assertEq(snapshot[0], local, "snapshot chain");

        // 2. Commits during the commit window.
        vm.prank(iba1);
        auction.commitBid(DAY, keccak256(_sig(iba1, 30, 800_000, iba1Pk)));
        vm.prank(iba2);
        auction.commitBid(DAY, keccak256(_sig(iba2, 40, 700_000, iba2Pk)));

        // 3. Past commitEnd the stage computes to RevealingBids; reveals lock escrow
        //    (qty * load * rate / 1e6), converted to 18-decimal WCOEN.
        vm.warp(startTs + 101);
        assertEq(uint8(auction.getAuctionStage(DAY)), uint8(IIntexAuction.AuctionStage.RevealingBids), "not revealing");
        _commitAndReveal(iba1, 30, 800_000, iba1Pk);
        _commitAndReveal(iba2, 40, 700_000, iba2Pk);
        assertEq(uint256(escrow.getBidLock(DAY, iba1).lockedAmount), 24e18, "iba1 lock");
        assertEq(uint256(escrow.getBidLock(DAY, iba2).lockedAmount), 28e18, "iba2 lock");

        // 4. CLEARING: the delivery itself fires the nested bids relay (BIDS_BATCH + BIDS_DONE)
        //    back through the loopback to the origin - three chained same-tx deliveries.
        vm.warp(startTs + 201);
        vm.prank(address(desis));
        origin.sendAuctionStageClearing(DAY);
        assertEq(desis.bidsCount(), 2, "bids not relayed");
        assertEq(desis.lastDay(), DAY, "relay day");
        assertEq(desis.lastSrcChainId(), local, "relay source chain");
        assertEq(desis.lastGeneration(), 1, "relay generation");
        assertEq(desis.lastTotalBatches(), 1, "relay batches");
        assertEq(desis.doneSrcChainId(), local, "marker source chain");
        assertEq(desis.doneTotalBatches(), 1, "marker batches");
        assertEq(desis.doneTotalBids(), 2, "marker bids");

        // 5. AUCTION_RESULT: supply 50 -> iba1 wins 30, iba2 wins 20 at the uniform rate 700k.
        vm.prank(address(desis));
        origin.sendAuctionResult(local, DAY, 50, 700_000, 2);
        IIntexAuction.AuctionResult memory result = auction.getAuctionInfo(DAY).result;
        assertEq(result.issuedIntexCount, 50, "issued");
        assertEq(result.auctionClearingRate, 700_000, "clearing rate");

        // 6. REFUND_INSTRUCTIONS: the delivery finalizes the escrow AND routes the paid wCOEN to
        //    the origin (sync token leg + unwrap + factory hand-off), all inside the refund budget.
        address[] memory bidders = new address[](2);
        bidders[0] = iba1;
        bidders[1] = iba2;
        uint128[] memory refunded = new uint128[](2);
        refunded[0] = 3e18; // lock 24 WCOEN - paid 30*1*0.7
        refunded[1] = 14e18; // lock 28 WCOEN - paid 20*1*0.7
        uint128[] memory paid = new uint128[](2);
        paid[0] = 21e18;
        paid[1] = 14e18;
        vm.prank(address(desis));
        origin.sendRefundInstructions(local, DAY, 0, 1, bidders, refunded, paid);

        assertEq(
            uint8(escrow.getBidLock(DAY, iba1).status), uint8(IEscrowAdapter.LockStatus.Finalized), "iba1 not final"
        );
        assertEq(wcoen.balanceOf(iba1), INITIAL_WCOEN_BALANCE - 24e18 + 3e18, "iba1 refund");
        assertEq(wcoen.balanceOf(iba2), INITIAL_WCOEN_BALANCE - 28e18 + 14e18, "iba2 refund");
        assertEq(factory.calls(), 1, "proceeds not distributed");
        assertEq(factory.lastValue(), 35e18, "proceeds amount");
        assertEq(factory.lastSrcChainId(), local, "proceeds source chain");
        assertEq(factory.lastDay(), DAY, "proceeds day");
        assertEq(address(origin).balance, 0, "native stranded on origin");

        // 7. ISSUANCE_INSTRUCTIONS: winners minted on the canonical NFT via the loopback leg.
        address[] memory winners = new address[](2);
        winners[0] = iba1;
        winners[1] = iba2;
        uint256[] memory amounts = new uint256[](2);
        amounts[0] = 30;
        amounts[1] = 20;
        IOriginRouter.IssuanceInstructionsParams[] memory issuance = new IOriginRouter.IssuanceInstructionsParams[](1);
        issuance[0] = IOriginRouter.IssuanceInstructionsParams({
            seriesId: CreateSeriesLib.seriesId(DAY),
            worldwideDay: DAY,
            issuedIntexCount: 50,
            promisLoadMinor: PROMIS_LOAD_MINOR,
            entryPriceMinor: 1e6,
            floorPriceMinor: 100,
            callNoticePeriod: 0,
            issuanceCurrency: 840,
            referenceCurrency: 840,
            callWindow: 30,
            callThreshold: 21,
            callPriceMinor: 200,
            recipients: winners,
            quantities: amounts
        });
        vm.prank(address(factory));
        origin.sendIssuanceInstructions(local, DAY, 0, 1, issuance);
        uint256 tokenId = intex.issuedTokenId(CreateSeriesLib.seriesId(DAY));
        assertEq(intex.balanceOf(iba1, tokenId), 30, "iba1 mint");
        assertEq(intex.balanceOf(iba2, tokenId), 20, "iba2 mint");

        // 8. Every leg executed within its IntexGas budget: nothing parked anywhere.
        assertEq(target.nextPendingBidsRelayIdx(), 0, "bids relay parked");
        (,, bool proceedsParked,) = target.pendingProceedsRoutes(0);
        assertFalse(proceedsParked, "proceeds route parked");
        assertEq(target.nextPendingIssuanceIdx(), 0, "issuance mint parked");
        assertEq(origin.parkedSend(0).payload.length, 0, "origin leg parked");
    }
}
