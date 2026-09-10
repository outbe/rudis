// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {CrossChainTest} from "../helpers/CrossChainTest.sol";

import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {IIntexNFT1155} from "@contracts/shared/interfaces/IIntexNFT1155.sol";
import {IntexNFT1155Bridge} from "@contracts/shared/IntexNFT1155Bridge.sol";
import {SendParam, MultiRecipientSendParam} from "@contracts/shared/interfaces/IIntexNFT1155Bridge.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";
import {CreateSeriesLib} from "../helpers/CreateSeriesLib.sol";

/// @dev Called freezes who owns a series. The bridge stays open so a holder can reach the chain that
///      settles, but only for their own balance.
contract CalledOwnershipFreezeTest is CrossChainTest {
    uint32 internal constant DST_CHAIN_ID = 2;
    uint32 internal constant WORLDWIDE_DAY = 20260501;
    bytes14 internal constant SERIES_ID = "20260501-USD-U";

    IntexNFT1155 internal intex;
    IntexNFT1155Bridge internal nftBridge;
    address internal admin = address(this);
    address internal holder = address(0xCAFE);
    address internal stranger = address(0xBEEF);
    uint256 internal tokenId;

    function setUp() public {
        _setUpBridge();
        intex = DeployProxy.intexNFT1155(admin, admin);
        nftBridge = DeployProxy.intexNFT1155Bridge(address(intex), address(bridge), admin);
        nftBridge.setRemoteMessenger(DST_CHAIN_ID, _interop(DST_CHAIN_ID, address(0xD57)));

        intex.grantRole(intex.RELAYER_ROLE(), address(nftBridge));

        intex.createSeries(CreateSeriesLib.params(WORLDWIDE_DAY, 10_000, 1 days));
        intex.issue(holder, 10, SERIES_ID);
        tokenId = intex.issuedTokenId(SERIES_ID);
        intex.markCalled(SERIES_ID, uint32(block.timestamp));
    }

    function _param(address to, uint256 amount) internal view returns (SendParam memory) {
        return
            SendParam({dstChainId: DST_CHAIN_ID, to: bytes32(uint256(uint160(to))), tokenId: tokenId, amount: amount});
    }

    function test_AHolderMayCarryTheirOwnBalanceOut() public {
        vm.prank(holder);
        nftBridge.send(_param(holder, 4));

        assertEq(intex.balanceOf(holder, tokenId), 6, "burned on the source, bound for the same holder");
    }

    function test_ABridgeHopToAnotherAddressIsRefused() public {
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.TransferOnCalledForbidden.selector, tokenId));
        vm.prank(holder);
        nftBridge.send(_param(stranger, 4));
    }

    function test_AMultiSendCannotFanOutToOthers() public {
        bytes32[] memory to = new bytes32[](1);
        to[0] = bytes32(uint256(uint160(stranger)));
        uint256[] memory ids = new uint256[](1);
        ids[0] = tokenId;
        uint256[] memory amounts = new uint256[](1);
        amounts[0] = 1;

        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.TransferOnCalledForbidden.selector, tokenId));
        vm.prank(holder);
        nftBridge.multiSend(
            MultiRecipientSendParam({dstChainId: DST_CHAIN_ID, recipients: to, tokenIds: ids, amounts: amounts})
        );
    }

    function test_APlainTransferStaysRefused() public {
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.TransferOnCalledForbidden.selector, tokenId));
        vm.prank(holder);
        intex.safeTransferFrom(holder, stranger, tokenId, 1, "");
    }

    function test_BeforeTheCallTheBridgeStillCarriesToAnyone() public {
        intex.createSeries(CreateSeriesLib.params(20260502, 10_000, 1 days));
        bytes14 open = "20260502-USD-U";
        intex.issue(holder, 5, open);
        intex.markQualified(open);

        uint256 openTokenId = intex.issuedTokenId(open);
        vm.prank(holder);
        nftBridge.send(
            SendParam({
                dstChainId: DST_CHAIN_ID, to: bytes32(uint256(uint160(stranger))), tokenId: openTokenId, amount: 2
            })
        );

        assertEq(intex.balanceOf(holder, openTokenId), 3, "qualified stays freely bridgeable");
    }
}
