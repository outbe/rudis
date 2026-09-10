// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {CrossChainTest} from "../helpers/CrossChainTest.sol";

import {IntexNFT1155Bridge} from "@contracts/shared/IntexNFT1155Bridge.sol";
import {IIntexNFT1155Bridge, BatchSendParam} from "@contracts/shared/interfaces/IIntexNFT1155Bridge.sol";

import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";
import {CreateSeriesLib} from "../helpers/CreateSeriesLib.sol";

/// @title DuplicateProtectionTest
/// @notice Duplicate-execution protection on the NFT batch adapter.
/// @dev Under ERC-7786 the routers have NO message-level dedup - the hub deduplicates and rolls back, so the old
///      ERC-7786 ORDERED `nextNonce` premise no longer exists at the router. The NFT batch adapter, which
///      carries independent transfers, keeps its OWN defence-in-depth dedup keyed by the bridge `receiveId`
///      (`processed[receiveId]`), rejecting a replay of the same message with `AlreadyProcessed(receiveId)`. A
///      `deliverLast()` replay reuses the same `receiveId`, so it exercises exactly this guard.
contract DuplicateProtectionTest is CrossChainTest {
    uint32 internal constant SRC_CHAIN_ID = 1;
    uint32 internal constant DST_CHAIN_ID = 2;

    IntexNFT1155Bridge internal batchSrc;
    IntexNFT1155Bridge internal batchDst;
    IntexNFT1155 internal intexSrc;
    IntexNFT1155 internal intexDst;

    address internal admin = address(this);
    address internal sender = address(0xA11CE);
    address internal recipient = address(0xBEEF);

    uint32 internal constant SERIES_ID_DAY = 20260101;
    bytes14 internal constant SERIES_ID = "20260101-USD-U";
    uint256 internal constant TOKEN_ID = uint256(uint112(SERIES_ID));

    function setUp() public {
        _setUpBridge();
        // A genuine send auto-delivers (records lastPayload) so `deliverLast()` can replay it.
        bridge.setAutoDeliver(true);

        intexSrc = DeployProxy.intexNFT1155(admin, admin);
        intexDst = DeployProxy.intexNFT1155(admin, admin);
        batchSrc = DeployProxy.intexNFT1155Bridge(address(intexSrc), address(bridge), admin);
        batchDst = DeployProxy.intexNFT1155Bridge(address(intexDst), address(bridge), admin);

        // Outbound recipient for the send.
        batchSrc.setRemoteMessenger(DST_CHAIN_ID, _interop(DST_CHAIN_ID, address(batchDst)));
        // Inbound peer authentication: the loopback bridge stamps the sender chainId as `block.chainid`, so the
        // destination must recognize the source adapter under that chainId.
        batchDst.setRemoteMessenger(uint32(block.chainid), _interop(uint32(block.chainid), address(batchSrc)));

        // Series in a bridgeable (Qualified) state on both chains, with the adapters granted RELAYER_ROLE so
        // crosschainBurn/crosschainMint succeed.
        _seedSeries(intexSrc);
        _seedSeries(intexDst);
        intexSrc.grantRole(intexSrc.RELAYER_ROLE(), address(batchSrc));
        intexDst.grantRole(intexDst.RELAYER_ROLE(), address(batchDst));

        // Mint on the source so the caller (an EOA that can receive/hold ERC1155) has a balance to bridge.
        intexSrc.issue(sender, 1, SERIES_ID);
    }

    function _seedSeries(IntexNFT1155 intex) internal {
        intex.createSeries(CreateSeriesLib.params(SERIES_ID_DAY, 10_000, 0));
        intex.markQualified(SERIES_ID);
    }

    function _batchSendParam(address to) internal view returns (BatchSendParam memory) {
        uint256[] memory tokenIds = new uint256[](1);
        tokenIds[0] = TOKEN_ID;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1;
        return BatchSendParam({
            dstChainId: DST_CHAIN_ID, to: bytes32(uint256(uint160(to))), tokenIds: tokenIds, amounts: amounts
        });
    }

    /// @notice A genuine batch send burns on the source and mints on the destination on first delivery. Replaying
    ///         the same message (`deliverLast`, same `receiveId`) is rejected with `AlreadyProcessed(receiveId)`.
    function test_NFTBatch_ReplayedMessage_RevertsAlreadyProcessed() public {
        // First delivery: auto-delivered by the send, mints on the destination.
        vm.prank(sender);
        batchSrc.batchSend(_batchSendParam(recipient));
        assertEq(intexDst.balanceOf(recipient, TOKEN_ID), 1, "first delivery minted");

        // The mock's receiveId binds (sender, payload); a `deliverLast()` replay reuses it.
        bytes32 receiveId = keccak256(abi.encode(bridge.lastSender(), bridge.lastPayload()));

        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155Bridge.AlreadyProcessed.selector, receiveId));
        bridge.deliverLast();
    }

    /// @notice Two sends carrying distinct payloads -> distinct receiveIds, so both land. Proves the guard keys on
    ///         the message id, not merely on the source. (Different recipients keep the payloads distinct, which the
    ///         loopback bridge needs since it binds the receiveId to the payload bytes.)
    function test_NFTBatch_DistinctMessages_BothSucceed() public {
        address other = address(0xCAFE);

        vm.prank(sender);
        batchSrc.batchSend(_batchSendParam(recipient));
        assertEq(intexDst.balanceOf(recipient, TOKEN_ID), 1, "first send minted");

        // Mint another unit and send to a different recipient - a fresh payload/receiveId, not a duplicate.
        intexSrc.issue(sender, 1, SERIES_ID);
        vm.prank(sender);
        batchSrc.batchSend(_batchSendParam(other));
        assertEq(intexDst.balanceOf(other, TOKEN_ID), 1, "second distinct send minted");
    }
}
