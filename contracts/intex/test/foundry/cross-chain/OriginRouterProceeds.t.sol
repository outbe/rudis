// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {ReferenceCurrencyPriceLib} from "../helpers/ReferenceCurrencyPriceLib.sol";
import {CrossChainTest} from "../helpers/CrossChainTest.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";
import {OriginRouter} from "@contracts/origin/OriginRouter.sol";
import {IOriginRouter} from "@contracts/origin/interfaces/IOriginRouter.sol";
import {IERC7786TokenReceiver} from "@contracts/origin/interfaces/IERC7786TokenReceiver.sol";
import {MockDesis} from "@test-mocks/MockDesis.sol";

/// @dev WETH-style stub: `withdraw` pays native from its own pre-funded balance, standing in for WCOEN unwrap.
contract MockWCOEN {
    function withdraw(uint256 wad) external {
        (bool ok,) = payable(msg.sender).call{value: wad}("");
        require(ok, "withdraw failed");
    }

    receive() external payable {}
}

/// @dev IntexFactory precompile stub: records the value/series/source of each `distribute`; can be toggled to revert.
contract MockIntexFactory {
    bool public shouldRevert;
    uint32 public lastWorldwideDay;
    uint32 public lastSrcChainId;
    uint256 public lastValue;
    uint256 public calls;

    function setShouldRevert(bool v) external {
        shouldRevert = v;
    }

    function distribute(uint32 worldwideDay, uint32 srcChainId) external payable {
        require(!shouldRevert, "distribute failed");
        calls++;
        lastWorldwideDay = worldwideDay;
        lastSrcChainId = srcChainId;
        lastValue = msg.value;
    }
}

contract OriginRouterProceedsTest is CrossChainTest {
    uint32 internal constant BNB_CHAIN_ID = 2;
    uint32 internal constant WORLDWIDE_DAY = 20_260_713;
    uint256 internal constant AMOUNT = 100e6;

    OriginRouter internal origin;
    MockWCOEN internal wcoen;
    MockIntexFactory internal factory;
    MockDesis internal desis;

    address internal tokenBridge = makeAddr("tokenBridge");
    address internal stranger = makeAddr("stranger");
    address internal targetRouter = makeAddr("targetRouter");
    // Legit source sender = the registered BNB peer (TargetRouter).
    bytes internal from;

    function setUp() public {
        _setUpBridge();
        origin = DeployProxy.originRouter(address(bridge), address(this));

        desis = new MockDesis();
        factory = new MockIntexFactory();
        wcoen = new MockWCOEN();
        vm.deal(address(wcoen), 1_000e6); // native backing for unwrap

        origin.wire(address(desis), address(factory));
        origin.setProceedsRoute(tokenBridge, address(wcoen));
        // Peer the proceeds hook authenticates `from` against.
        origin.setRemoteMessenger(BNB_CHAIN_ID, _interop(BNB_CHAIN_ID, targetRouter));
        from = _interop(BNB_CHAIN_ID, targetRouter);

        // Register BNB and seed the day's target snapshot: proceeds authenticate the source against it.
        // No float needed - the mock bridge fee defaults to 0, so the seed STAGE_START costs nothing.
        origin.addTarget(BNB_CHAIN_ID);
        _seedDaySnapshot(WORLDWIDE_DAY);
    }

    /// @dev Fire a minimal STAGE_START (as the DESIS_ROLE holder) so `seriesTargets[day]` is populated.
    function _seedDaySnapshot(uint32 day) internal {
        IOriginRouter.AuctionStageStartParams memory p;
        p.prices = ReferenceCurrencyPriceLib.one(840, 1, 2, 3);
        p.worldwideDay = day;
        p.dayState = 1;
        vm.prank(address(desis));
        origin.sendAuctionStageStart(p);
    }

    function _receive(uint32 sourceDomain, uint256 amount, uint32 worldwideDay) internal returns (bytes4) {
        vm.prank(tokenBridge);
        return origin.onCrosschainTokensReceived(sourceDomain, from, amount, abi.encode(worldwideDay));
    }

    function test_OnReceive_DistributesToFactory() public {
        bytes4 magic = _receive(BNB_CHAIN_ID, AMOUNT, WORLDWIDE_DAY);

        assertEq(magic, IERC7786TokenReceiver.onCrosschainTokensReceived.selector);
        assertEq(factory.calls(), 1);
        assertEq(factory.lastWorldwideDay(), WORLDWIDE_DAY);
        assertEq(factory.lastSrcChainId(), BNB_CHAIN_ID);
        assertEq(factory.lastValue(), AMOUNT);
        // Fully routed: nothing parked, no native stranded on the router.
        assertEq(origin.parkedProceeds(0).amount, 0);
        assertEq(address(origin).balance, 0);
    }

    function test_PublicWrappedTokenGetterUsesRudis() public view {
        assertEq(origin.wrudis(), address(wcoen));
        (bool ok,) = address(origin).staticcall(abi.encodeWithSignature("wcoen()"));
        assertFalse(ok, "old getter must not remain in the public ABI");
    }

    function test_OnReceive_ParksOnDistributeFailure() public {
        factory.setShouldRevert(true);

        vm.expectEmit(true, true, false, true, address(origin));
        emit IOriginRouter.ProceedsParked(0, WORLDWIDE_DAY, AMOUNT);
        bytes4 magic = _receive(BNB_CHAIN_ID, AMOUNT, WORLDWIDE_DAY);

        // The transfer still settles (magic returned) and the native is held for retry.
        assertEq(magic, IERC7786TokenReceiver.onCrosschainTokensReceived.selector);
        assertEq(factory.calls(), 0);
        IOriginRouter.ParkedProceeds memory p = origin.parkedProceeds(0);
        assertEq(p.worldwideDay, WORLDWIDE_DAY);
        assertEq(p.amount, AMOUNT);
        assertEq(p.settled, false);
        assertEq(address(origin).balance, AMOUNT);
    }

    function test_RetryProceeds_DistributesParked() public {
        factory.setShouldRevert(true);
        _receive(BNB_CHAIN_ID, AMOUNT, WORLDWIDE_DAY);

        factory.setShouldRevert(false);
        vm.expectEmit(true, true, false, true, address(origin));
        emit IOriginRouter.ProceedsRetried(0, WORLDWIDE_DAY, AMOUNT);
        origin.retryProceeds(0);

        assertEq(factory.calls(), 1);
        assertEq(factory.lastValue(), AMOUNT);
        assertEq(origin.parkedProceeds(0).settled, true);
        assertEq(address(origin).balance, 0);
    }

    function test_RevertWhen_RetryAlreadySettled() public {
        factory.setShouldRevert(true);
        _receive(BNB_CHAIN_ID, AMOUNT, WORLDWIDE_DAY);
        factory.setShouldRevert(false);
        origin.retryProceeds(0);

        vm.expectRevert(abi.encodeWithSelector(IOriginRouter.NoParkedProceeds.selector, uint256(0)));
        origin.retryProceeds(0);
    }

    function test_RevertWhen_RetryUnknownIdx() public {
        vm.expectRevert(abi.encodeWithSelector(IOriginRouter.NoParkedProceeds.selector, uint256(99)));
        origin.retryProceeds(99);
    }

    function test_RevertWhen_CallerNotTokenBridge() public {
        vm.prank(stranger);
        vm.expectRevert(abi.encodeWithSelector(IOriginRouter.UnauthorizedProceedsCaller.selector, stranger));
        origin.onCrosschainTokensReceived(BNB_CHAIN_ID, from, AMOUNT, abi.encode(WORLDWIDE_DAY));
    }

    function test_RevertWhen_WrongSourceDomain() public {
        vm.prank(tokenBridge);
        vm.expectRevert(abi.encodeWithSelector(IOriginRouter.UnexpectedProceedsSource.selector, uint32(999)));
        origin.onCrosschainTokensReceived(999, from, AMOUNT, abi.encode(WORLDWIDE_DAY));
    }

    function test_RevertWhen_ProceedsSenderSpoofed() public {
        // Permissionless bridge: a sender other than the registered BNB peer must be rejected.
        bytes memory spoofed = _interop(BNB_CHAIN_ID, stranger);
        vm.prank(tokenBridge);
        vm.expectRevert(abi.encodeWithSelector(IOriginRouter.UnauthorizedProceedsSender.selector, spoofed));
        origin.onCrosschainTokensReceived(BNB_CHAIN_ID, spoofed, AMOUNT, abi.encode(WORLDWIDE_DAY));
    }
}
