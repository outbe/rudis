// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {CrossChainTest} from "../helpers/CrossChainTest.sol";

import {TargetRouter} from "@contracts/target/TargetRouter.sol";
import {OriginRouter} from "@contracts/origin/OriginRouter.sol";
import {IOriginRouter} from "@contracts/origin/interfaces/IOriginRouter.sol";
import {IDesis} from "@contracts/origin/interfaces/IDesis.sol";
import {IntexAuction} from "@contracts/target/IntexAuction.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {IIntexNFT1155} from "@contracts/shared/interfaces/IIntexNFT1155.sol";
import {BridgeMsgCodec} from "@contracts/shared/libs/BridgeMsgCodec.sol";
import {IntexGas} from "@contracts/shared/libs/IntexGas.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";
import {CreateSeriesLib} from "../helpers/CreateSeriesLib.sol";
import {MarkBatchLib} from "../helpers/MarkBatchLib.sol";
import {ReferenceCurrencyPriceLib} from "../helpers/ReferenceCurrencyPriceLib.sol";
import {MockDesis} from "@test-mocks/MockDesis.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";

/// @dev One day's series in one reference currency travel as a single mark message: the origin
///      broadcasts one payload per target, and the target applies every series it carries.
contract MarkBatchWireTest is CrossChainTest {
    uint32 internal constant BNB_CHAIN_ID = 1;
    uint32 internal constant OUTBE_CHAIN_ID = 2;

    uint32 internal constant WORLDWIDE_DAY = 20250101;
    bytes4 internal constant GAS_SELECTOR = bytes4(keccak256("executionGasLimit(uint256)"));
    bytes14 internal constant USD_SERIES = "20250101-USD-U";
    bytes14 internal constant EUR_SERIES = "20250101-EUR-U";

    TargetRouter internal bnbRouter;
    OriginRouter internal outbeRouter;
    IntexAuction internal auction;
    IntexNFT1155 internal intex;
    MockDesis internal desis;

    address internal admin = address(this);
    address internal intexFactory = makeAddr("factory");

    function setUp() public {
        _setUpBridge();

        desis = new MockDesis();
        auction = DeployProxy.intexAuction(admin, admin);
        intex = DeployProxy.intexNFT1155(admin, admin);
        bnbRouter = DeployProxy.targetRouter(address(bridge), admin, OUTBE_CHAIN_ID);
        outbeRouter = DeployProxy.originRouter(address(bridge), admin);

        bnbRouter.setRemoteMessenger(OUTBE_CHAIN_ID, _interop(OUTBE_CHAIN_ID, address(outbeRouter)));
        outbeRouter.setRemoteMessenger(BNB_CHAIN_ID, _interop(BNB_CHAIN_ID, address(bnbRouter)));

        bnbRouter.wire(address(auction), address(intex), admin);
        intex.grantRole(intex.RELAYER_ROLE(), address(bnbRouter));

        outbeRouter.wire(address(desis), intexFactory);
        outbeRouter.addTarget(BNB_CHAIN_ID);
        _freezeSnapshot();
    }

    /// @dev Freeze the day's target snapshot, which every mark broadcast goes out over.
    function _freezeSnapshot() internal {
        IOriginRouter.AuctionStageStartParams memory p;
        p.prices = ReferenceCurrencyPriceLib.one(840, 1, 2, 3);
        p.worldwideDay = WORLDWIDE_DAY;
        p.dayState = 1;
        vm.prank(address(desis));
        outbeRouter.sendAuctionStageStart(p);
    }

    function _createBoth() internal {
        intex.createSeries(CreateSeriesLib.params(WORLDWIDE_DAY, 10_000, 0));
        IIntexNFT1155.CreateSeriesParams memory eur = CreateSeriesLib.params(WORLDWIDE_DAY, 10_000, 0);
        eur.seriesId = EUR_SERIES;
        intex.createSeries(eur);
    }

    function _state(bytes14 seriesId) internal view returns (uint8) {
        return uint8(intex.readData(seriesId).state);
    }

    function test_oneSendCarriesTheWholeGroupToTheTarget() public {
        _createBoth();
        bytes14[] memory batch = MarkBatchLib.two(USD_SERIES, EUR_SERIES);

        uint256 fee = outbeRouter.quoteSendMarkQualified(WORLDWIDE_DAY, batch);
        vm.deal(intexFactory, fee);
        vm.prank(intexFactory);
        outbeRouter.sendMarkQualified{value: fee}(WORLDWIDE_DAY, batch);

        _deliver(OUTBE_CHAIN_ID, address(outbeRouter), address(bnbRouter), bridge.lastPayload());

        assertEq(_state(USD_SERIES), uint8(IIntexNFT1155.IntexState.Qualified), "USD series marked");
        assertEq(_state(EUR_SERIES), uint8(IIntexNFT1155.IntexState.Qualified), "EUR series marked");
    }

    /// @notice One series missing on the target must not cost the rest of its batch.
    function test_aMissingSeriesParksAloneWhileTheRestApply() public {
        intex.createSeries(CreateSeriesLib.params(WORLDWIDE_DAY, 10_000, 0));

        _deliver(
            OUTBE_CHAIN_ID,
            address(outbeRouter),
            address(bnbRouter),
            BridgeMsgCodec.encodeMarkQualified(WORLDWIDE_DAY, MarkBatchLib.two(USD_SERIES, EUR_SERIES))
        );

        assertEq(_state(USD_SERIES), uint8(IIntexNFT1155.IntexState.Qualified), "the known series applied");
        assertEq(bnbRouter.pendingMark(EUR_SERIES), BridgeMsgCodec.MSG_MARK_QUALIFIED, "only the missing one waits");
        assertEq(bnbRouter.pendingMark(USD_SERIES), 0, "the applied one has no slot");
    }

    /// @dev The destination gas the router buys has to follow the batch it is sending, not the
    ///      message type: a batch relayed on a single series' budget runs out on arrival.
    function test_theSendBuysDestinationGasForTheWholeBatch() public {
        vm.startPrank(intexFactory);
        outbeRouter.sendMarkQualified(WORLDWIDE_DAY, MarkBatchLib.one(USD_SERIES));
        _assertLastGas(IntexGas.markQualified(1));

        outbeRouter.sendMarkQualified(WORLDWIDE_DAY, MarkBatchLib.two(USD_SERIES, EUR_SERIES));
        _assertLastGas(IntexGas.markQualified(2));

        outbeRouter.sendMarkCalled(WORLDWIDE_DAY, uint32(block.timestamp), MarkBatchLib.two(USD_SERIES, EUR_SERIES));
        _assertLastGas(IntexGas.markCalled(2));
        vm.stopPrank();
    }

    /// @dev The last recorded send carries exactly one executionGasLimit attribute equal to `expectedGas`.
    function _assertLastGas(uint256 expectedGas) internal view {
        bytes[] memory attrs = bridge.getLastAttributes();
        assertEq(attrs.length, 1, "expected one attribute");
        assertEq(attrs[0], abi.encodeWithSelector(GAS_SELECTOR, expectedGas), "gas attribute mismatch");
    }

    function test_anOverSizedBatchIsRefusedAtTheSend() public {
        bytes14[] memory batch = MarkBatchLib.sized(USD_SERIES, BridgeMsgCodec.MAX_SERIES_PER_MARK + 1);
        vm.prank(intexFactory);
        vm.expectRevert(
            abi.encodeWithSelector(
                BridgeMsgCodec.MarkBatchTooLarge.selector,
                BridgeMsgCodec.MAX_SERIES_PER_MARK + 1,
                BridgeMsgCodec.MAX_SERIES_PER_MARK
            )
        );
        outbeRouter.sendMarkCalled(WORLDWIDE_DAY, uint32(block.timestamp), batch);
    }

    function test_onlyTheFactoryMaySendAMarkBatch() public {
        bytes14[] memory batch = MarkBatchLib.one(USD_SERIES);
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector,
                address(this),
                outbeRouter.INTEX_FACTORY_ROLE()
            )
        );
        outbeRouter.sendMarkQualified(WORLDWIDE_DAY, batch);
    }
}
