// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {CrossChainTest} from "../helpers/CrossChainTest.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";
import {CreateSeriesLib} from "../helpers/CreateSeriesLib.sol";
import {IIntexNFT1155} from "@contracts/shared/interfaces/IIntexNFT1155.sol";
import {IntexNFT1155Bridge} from "@contracts/shared/IntexNFT1155Bridge.sol";
import {IIntexNFT1155Bridge, SendParam} from "@contracts/shared/interfaces/IIntexNFT1155Bridge.sol";
import {ERC7786MessengerBase} from "@contracts/shared/ERC7786MessengerBase.sol";
import {RejectingReceiver} from "@test-mocks/RejectingReceiver.sol";

/// @title IntexNFT1155BridgeSingleTest
/// @notice Foundry tests for IntexNFT1155Bridge with IntexNFT1155 token.
/// @dev Tests cross-chain transfers over the {MockERC7786Bridge} loopback via {CrossChainTest}. Series are keyed by
///      `seriesId` (uint32); the issued token id is `uint256(seriesId)`. Delivery is manual: a send records the
///      packet on the bridge and {_deliver} hands it to the destination adapter as the bridge.
contract IntexNFT1155BridgeSingleTest is CrossChainTest {
    uint32 private constant A_CHAIN_ID = 1;
    uint32 private constant B_CHAIN_ID = 2;

    uint256 private constant FEE = 0.001 ether;

    IntexNFT1155 private tokenA;
    IntexNFT1155 private tokenB;
    IntexNFT1155Bridge private adapterA;
    IntexNFT1155Bridge private adapterB;

    address private admin = address(this);
    address private user = address(0x1);
    uint32 private constant SERIES_ID_DAY = 20260401;
    bytes14 private constant SERIES_ID = "20260401-USD-U";
    uint256 private constant TOKEN_ID = uint256(uint112(SERIES_ID));
    uint256 private constant AMOUNT = 100;
    uint32 private constant ISSUED_INTEX_COUNT = 10_000;

    function setUp() public {
        vm.deal(user, 1000 ether);

        _setUpBridge();
        bridge.setFee(FEE);

        // Deploy IntexNFT1155 tokens on both chains
        tokenA = DeployProxy.intexNFT1155(admin, admin);
        tokenB = DeployProxy.intexNFT1155(admin, admin);

        adapterA = DeployProxy.intexNFT1155Bridge(address(tokenA), address(bridge), admin);
        adapterB = DeployProxy.intexNFT1155Bridge(address(tokenB), address(bridge), admin);

        // Grant RELAYER_ROLE to adapters
        tokenA.grantRole(tokenA.RELAYER_ROLE(), address(adapterA));
        tokenB.grantRole(tokenB.RELAYER_ROLE(), address(adapterB));

        // Wire adapters (register each as the other's remote messenger)
        adapterA.setRemoteMessenger(B_CHAIN_ID, _interop(B_CHAIN_ID, address(adapterB)));
        adapterB.setRemoteMessenger(A_CHAIN_ID, _interop(A_CHAIN_ID, address(adapterA)));

        // Create series on both chains
        tokenA.createSeries(CreateSeriesLib.params(SERIES_ID_DAY, ISSUED_INTEX_COUNT, 0));
        tokenB.createSeries(CreateSeriesLib.params(SERIES_ID_DAY, ISSUED_INTEX_COUNT, 0));

        // Bridge is only allowed in Qualified state for the user-driven adapter.
        tokenA.markQualified(SERIES_ID);
        tokenB.markQualified(SERIES_ID);

        // Mint initial tokens to user on chain A
        tokenA.issue(user, AMOUNT, SERIES_ID);
    }

    /// @dev Deliver the packet the source adapter just handed the bridge to `dst` as if from `src` on A.
    function _deliverAToB() internal {
        _deliver(A_CHAIN_ID, address(adapterA), address(adapterB), bridge.lastPayload());
    }

    function _deliverBToA() internal {
        _deliver(B_CHAIN_ID, address(adapterB), address(adapterA), bridge.lastPayload());
    }

    function test_constructor() public view {
        assertTrue(adapterA.hasRole(adapterA.DEFAULT_ADMIN_ROLE(), admin));
        assertEq(address(adapterA.token()), address(tokenA));
        assertEq(address(adapterA.BRIDGE()), address(bridge));
    }

    /// @notice `token` is immutable, so a zero address would permanently brick the
    ///         adapter (every `crosschainBurn`/`crosschainMint` reverts on a non-contract). Reject at construction.
    function test_constructor_revertsZeroToken() public {
        // Property of the implementation constructor - the token immutable is set there.
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155Bridge.ZeroAddress.selector, "token"));
        new IntexNFT1155Bridge(address(0), address(bridge));
    }

    /// @notice A zero bridge address is caught by the `ERC7786MessengerBase` constructor guard.
    function test_constructor_revertsZeroBridge() public {
        vm.expectRevert(ERC7786MessengerBase.InvalidBridge.selector);
        new IntexNFT1155Bridge(address(tokenA), address(0));
    }

    function test_send() public {
        SendParam memory sendParam =
            SendParam({dstChainId: B_CHAIN_ID, to: bytes32(uint256(uint160(user))), tokenId: TOKEN_ID, amount: AMOUNT});

        uint256 fee = adapterA.quoteSend(sendParam);

        // Check initial balances
        assertEq(tokenA.balanceOf(user, TOKEN_ID), AMOUNT);
        assertEq(tokenB.balanceOf(user, TOKEN_ID), 0);

        // Send tokens
        vm.prank(user);
        adapterA.send{value: fee}(sendParam);

        // Process cross-chain message
        _deliverAToB();

        // Check final balances
        assertEq(tokenA.balanceOf(user, TOKEN_ID), 0);
        assertEq(tokenB.balanceOf(user, TOKEN_ID), AMOUNT);
    }

    function test_send_partial_amount() public {
        uint256 sendAmount = AMOUNT / 2;

        SendParam memory sendParam = SendParam({
            dstChainId: B_CHAIN_ID, to: bytes32(uint256(uint160(user))), tokenId: TOKEN_ID, amount: sendAmount
        });

        uint256 fee = adapterA.quoteSend(sendParam);

        vm.prank(user);
        adapterA.send{value: fee}(sendParam);
        _deliverAToB();

        assertEq(tokenA.balanceOf(user, TOKEN_ID), AMOUNT - sendAmount);
        assertEq(tokenB.balanceOf(user, TOKEN_ID), sendAmount);
    }

    function test_send_to_different_address() public {
        address recipient = address(0x2);

        SendParam memory sendParam = SendParam({
            dstChainId: B_CHAIN_ID, to: bytes32(uint256(uint160(recipient))), tokenId: TOKEN_ID, amount: AMOUNT
        });

        uint256 fee = adapterA.quoteSend(sendParam);

        vm.prank(user);
        adapterA.send{value: fee}(sendParam);
        _deliverAToB();

        assertEq(tokenA.balanceOf(user, TOKEN_ID), 0);
        assertEq(tokenB.balanceOf(recipient, TOKEN_ID), AMOUNT);
    }

    function test_roundtrip() public {
        // Send A -> B
        SendParam memory sendParamAB =
            SendParam({dstChainId: B_CHAIN_ID, to: bytes32(uint256(uint160(user))), tokenId: TOKEN_ID, amount: AMOUNT});

        uint256 feeAB = adapterA.quoteSend(sendParamAB);
        vm.prank(user);
        adapterA.send{value: feeAB}(sendParamAB);
        _deliverAToB();

        assertEq(tokenB.balanceOf(user, TOKEN_ID), AMOUNT);

        // Send B -> A
        SendParam memory sendParamBToA =
            SendParam({dstChainId: A_CHAIN_ID, to: bytes32(uint256(uint160(user))), tokenId: TOKEN_ID, amount: AMOUNT});

        uint256 feeBToA = adapterB.quoteSend(sendParamBToA);
        vm.prank(user);
        adapterB.send{value: feeBToA}(sendParamBToA);
        _deliverBToA();

        assertEq(tokenA.balanceOf(user, TOKEN_ID), AMOUNT);
        assertEq(tokenB.balanceOf(user, TOKEN_ID), 0);
    }

    function test_revert_invalid_receiver() public {
        SendParam memory sendParam =
            SendParam({dstChainId: B_CHAIN_ID, to: bytes32(0), tokenId: TOKEN_ID, amount: AMOUNT});

        vm.expectRevert(IIntexNFT1155Bridge.InvalidReceiver.selector);
        adapterA.quoteSend(sendParam);
    }

    function test_revert_insufficient_balance() public {
        SendParam memory sendParam = SendParam({
            dstChainId: B_CHAIN_ID,
            to: bytes32(uint256(uint160(user))),
            tokenId: TOKEN_ID,
            amount: AMOUNT + 1 // More than balance
        });

        uint256 fee = adapterA.quoteSend(sendParam);

        vm.prank(user);
        vm.expectRevert();
        adapterA.send{value: fee}(sendParam);
    }

    function test_intex_state_preserved_after_bridge() public {
        // Get initial state on chain A (setUp marked the series Qualified for bridging).
        IIntexNFT1155.SeriesData memory dataA = tokenA.readData(SERIES_ID);
        assertEq(uint8(dataA.state), uint8(IIntexNFT1155.IntexState.Qualified));

        // Send tokens A -> B
        SendParam memory sendParam =
            SendParam({dstChainId: B_CHAIN_ID, to: bytes32(uint256(uint160(user))), tokenId: TOKEN_ID, amount: AMOUNT});

        uint256 fee = adapterA.quoteSend(sendParam);
        vm.prank(user);
        adapterA.send{value: fee}(sendParam);
        _deliverAToB();

        // Verify state is identical on chain B
        IIntexNFT1155.SeriesData memory dataB = tokenB.readData(SERIES_ID);
        assertEq(uint8(dataB.state), uint8(IIntexNFT1155.IntexState.Qualified));
    }

    // --- sweepNative Tests ---
    function test_sweepNative_success() public {
        vm.deal(address(adapterA), 4 ether);
        address payable recipient = payable(address(0xBEEF));
        uint256 before = recipient.balance;

        adapterA.sweepNative(recipient, 4 ether);

        assertEq(recipient.balance - before, 4 ether);
        assertEq(address(adapterA).balance, 0);
    }

    function test_sweepNative_revert_zeroTo() public {
        vm.deal(address(adapterA), 1 ether);
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155Bridge.ZeroAddress.selector, "to"));
        adapterA.sweepNative(payable(address(0)), 1 ether);
    }

    function test_sweepNative_revert_insufficientBalance() public {
        vm.deal(address(adapterA), 1 ether);
        vm.expectRevert(
            abi.encodeWithSelector(IIntexNFT1155Bridge.NativeBalanceInsufficient.selector, 1 ether, 2 ether)
        );
        adapterA.sweepNative(payable(address(0xBEEF)), 2 ether);
    }

    function test_sweepNative_revert_failedCall() public {
        vm.deal(address(adapterA), 1 ether);
        RejectingReceiver rejector = new RejectingReceiver();
        vm.expectRevert(IIntexNFT1155Bridge.NativeSweepFailed.selector);
        adapterA.sweepNative(payable(address(rejector)), 1 ether);
    }

    function test_sweepNative_revert_unauthorized() public {
        vm.deal(address(adapterA), 1 ether);
        vm.prank(user);
        vm.expectRevert();
        adapterA.sweepNative(payable(address(0xBEEF)), 1 ether);
    }

    // --- Inbound crosschainMint isolation ---

    function test_inboundCrosschainMintFailure_parksAndRetries() public {
        // A series that exists on A only: the destination crosschainMint reverts NonexistentToken, which
        // must park the transfer (not unwind the packet and strand the burned tokens).
        uint32 failDay = 20260402;
        bytes14 failSeries = "20260402-USD-U";
        uint256 failTokenId = uint256(uint112(failSeries));
        tokenA.createSeries(CreateSeriesLib.params(failDay, ISSUED_INTEX_COUNT, 0));
        tokenA.markQualified(failSeries);
        tokenA.issue(user, AMOUNT, failSeries);

        SendParam memory sendParam = SendParam({
            dstChainId: B_CHAIN_ID, to: bytes32(uint256(uint160(user))), tokenId: failTokenId, amount: AMOUNT
        });
        uint256 fee = adapterA.quoteSend(sendParam);
        vm.prank(user);
        adapterA.send{value: fee}(sendParam);

        // The bridge derives the receiveId from (sender interop, payload); recompute it to key the parked entry.
        bytes memory packet = bridge.lastPayload();
        bytes32 receiveId = keccak256(abi.encode(_interop(A_CHAIN_ID, address(adapterA)), packet));

        // Delivery must succeed (crosschainMint parked), not revert.
        _deliverAToB();

        // Source burned; destination not minted; transfer parked under the bridge receiveId.
        assertEq(tokenA.balanceOf(user, failTokenId), 0, "source burned");
        assertEq(tokenB.balanceOf(user, failTokenId), 0, "not minted yet");
        (address to,, uint256 amount,, bool exists) = adapterB.failedCrosschainMints(receiveId, 0);
        assertTrue(exists, "crosschainMint parked");
        assertEq(to, user);
        assertEq(amount, AMOUNT);

        // Fix the cause on B, then retry -> minted and entry cleared.
        tokenB.createSeries(CreateSeriesLib.params(failDay, ISSUED_INTEX_COUNT, 0));
        tokenB.markQualified(failSeries);
        adapterB.retryCrosschainMint(receiveId, 0);
        assertEq(tokenB.balanceOf(user, failTokenId), AMOUNT, "minted on retry");

        (,,,, bool existsAfter) = adapterB.failedCrosschainMints(receiveId, 0);
        assertFalse(existsAfter, "entry cleared");

        // A re-retry reverts.
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155Bridge.NoSuchFailedCrosschainMint.selector, receiveId, 0));
        adapterB.retryCrosschainMint(receiveId, 0);
    }

    function test_inboundCrosschainMintFailure_reclaimToSourceRestoresOrigin() public {
        // Park an inbound on B for a series that exists on A only.
        uint32 failDay = 20260402;
        bytes14 failSeries = "20260402-USD-U";
        uint256 failTokenId = uint256(uint112(failSeries));
        tokenA.createSeries(CreateSeriesLib.params(failDay, ISSUED_INTEX_COUNT, 0));
        tokenA.markQualified(failSeries);
        tokenA.issue(user, AMOUNT, failSeries);

        SendParam memory sendParam = SendParam({
            dstChainId: B_CHAIN_ID, to: bytes32(uint256(uint160(user))), tokenId: failTokenId, amount: AMOUNT
        });
        uint256 fee = adapterA.quoteSend(sendParam);
        vm.prank(user);
        adapterA.send{value: fee}(sendParam);

        bytes memory packet = bridge.lastPayload();
        bytes32 receiveId = keccak256(abi.encode(_interop(A_CHAIN_ID, address(adapterA)), packet));
        _deliverAToB();

        assertEq(tokenA.balanceOf(user, failTokenId), 0, "source burned");
        (,,,, bool parked) = adapterB.failedCrosschainMints(receiveId, 0);
        assertTrue(parked, "parked on B");

        // Reclaim: B sends the transfer back to its origin A - the only exit that skips B's gate.
        vm.prank(user);
        adapterB.reclaimToSource{value: FEE}(receiveId, 0);

        (,,,, bool stillParked) = adapterB.failedCrosschainMints(receiveId, 0);
        assertFalse(stillParked, "entry consumed");

        // Deliver the reverse packet on A -> holder re-minted, cross-chain supply conserved.
        _deliverBToA();
        assertEq(tokenA.balanceOf(user, failTokenId), AMOUNT, "holder re-minted on origin");
        assertEq(tokenB.balanceOf(user, failTokenId), 0, "nothing on destination");

        // A second reclaim reverts - the entry is gone.
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155Bridge.NoSuchFailedCrosschainMint.selector, receiveId, 0));
        adapterB.reclaimToSource(receiveId, 0);
    }

    function test_retryCrosschainMint_revertsForUnknownReceiveId() public {
        bytes32 unknown = bytes32(uint256(0xABCD));
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155Bridge.NoSuchFailedCrosschainMint.selector, unknown, 0));
        adapterB.retryCrosschainMint(unknown, 0);
    }

    function test_crosschainMintOne_externalCallerRevertsNotSelf() public {
        vm.expectRevert(IIntexNFT1155Bridge.NotSelf.selector);
        adapterB.crosschainMintOne(address(0xCAFE), TOKEN_ID, 1);
    }
}
