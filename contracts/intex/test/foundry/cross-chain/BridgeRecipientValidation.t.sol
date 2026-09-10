// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {CrossChainTest} from "../helpers/CrossChainTest.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {DeployProxy} from "../helpers/DeployProxy.sol";
import {CreateSeriesLib} from "../helpers/CreateSeriesLib.sol";
import {IntexNFT1155Bridge} from "@contracts/shared/IntexNFT1155Bridge.sol";
import {SendParam, BatchSendParam, MultiRecipientSendParam} from "@contracts/shared/interfaces/IIntexNFT1155Bridge.sol";
import {IntexNFT1155BridgeCodec} from "@contracts/shared/libs/IntexNFT1155BridgeCodec.sol";

/// @notice A non-canonical recipient (dirty high bits) is rejected on the send path before any burn, matching the
///         receive path - otherwise the burn would have no mint counterpart and the message would wedge.
contract BridgeRecipientValidationTest is CrossChainTest {
    uint32 private constant B_CHAIN_ID = 2;
    uint256 private constant FEE = 0.001 ether;

    IntexNFT1155 private token;
    IntexNFT1155Bridge private adapter;

    address private admin = address(this);
    address private user = address(0x1);
    uint32 private constant SERIES_ID_DAY = 20260401;
    bytes14 private constant SERIES_ID = "20260401-USD-U";
    uint256 private constant TOKEN_ID = uint256(uint112(SERIES_ID));
    uint256 private constant AMOUNT = 100;

    /// @dev A bytes32 with a bit set above the low 160 - not a canonical left-padded address.
    bytes32 private constant DIRTY = bytes32(uint256(1) << 160);

    function setUp() public {
        vm.deal(user, 100 ether);
        _setUpBridge();
        bridge.setFee(FEE);

        token = DeployProxy.intexNFT1155(admin, admin);
        adapter = DeployProxy.intexNFT1155Bridge(address(token), address(bridge), admin);
        token.grantRole(token.RELAYER_ROLE(), address(adapter));
        adapter.setRemoteMessenger(B_CHAIN_ID, _interop(B_CHAIN_ID, address(adapter)));

        token.createSeries(CreateSeriesLib.params(SERIES_ID_DAY, 10_000, 0));
        token.markQualified(SERIES_ID);
        token.issue(user, AMOUNT, SERIES_ID);
    }

    function _expectMalformed() internal {
        vm.expectRevert(abi.encodeWithSelector(IntexNFT1155BridgeCodec.MalformedAddress.selector, DIRTY));
    }

    function _ids() private pure returns (uint256[] memory ids) {
        ids = new uint256[](1);
        ids[0] = TOKEN_ID;
    }

    function _amounts() private pure returns (uint256[] memory amts) {
        amts = new uint256[](1);
        amts[0] = AMOUNT;
    }

    function test_send_rejectsMalformedRecipientBeforeBurn() public {
        _expectMalformed();
        vm.prank(user);
        adapter.send{value: FEE}(SendParam({dstChainId: B_CHAIN_ID, to: DIRTY, tokenId: TOKEN_ID, amount: AMOUNT}));
        assertEq(token.balanceOf(user, TOKEN_ID), AMOUNT, "no burn on malformed recipient");
    }

    function test_batchSend_rejectsMalformedRecipientBeforeBurn() public {
        _expectMalformed();
        vm.prank(user);
        adapter.batchSend{value: FEE}(
            BatchSendParam({dstChainId: B_CHAIN_ID, to: DIRTY, tokenIds: _ids(), amounts: _amounts()})
        );
        assertEq(token.balanceOf(user, TOKEN_ID), AMOUNT, "no burn on malformed recipient");
    }

    function test_multiSend_rejectsMalformedRecipientBeforeBurn() public {
        bytes32[] memory recipients = new bytes32[](1);
        recipients[0] = DIRTY;
        _expectMalformed();
        vm.prank(user);
        adapter.multiSend{value: FEE}(
            MultiRecipientSendParam({
                dstChainId: B_CHAIN_ID, recipients: recipients, tokenIds: _ids(), amounts: _amounts()
            })
        );
        assertEq(token.balanceOf(user, TOKEN_ID), AMOUNT, "no burn on malformed recipient");
    }

    /// @notice A canonical recipient still passes the guard and burns on the source.
    function test_send_canonicalRecipientStillSends() public {
        SendParam memory p =
            SendParam({dstChainId: B_CHAIN_ID, to: bytes32(uint256(uint160(user))), tokenId: TOKEN_ID, amount: AMOUNT});
        uint256 fee = adapter.quoteSend(p);
        vm.prank(user);
        adapter.send{value: fee}(p);
        assertEq(token.balanceOf(user, TOKEN_ID), 0, "burned on valid send");
    }
}
