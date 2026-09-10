// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {IIntexNFT1155} from "@contracts/shared/interfaces/IIntexNFT1155.sol";
import {DeployProxy} from "./helpers/DeployProxy.sol";
import {CreateSeriesLib} from "./helpers/CreateSeriesLib.sol";

/// @dev `createSeries` must copy the full immutable series identity into the Settled record;
///      the record has no public reader, so slots are compared raw via `vm.load`.
contract IntexNFT1155SettledRecordTest is Test {
    uint32 internal constant SERIES_ID_DAY = 20260622;
    bytes14 internal constant SERIES_ID = "20260622-USD-U";
    uint32 internal constant CAP = 10_000;
    uint32 internal constant CALL_PERIOD = 14 days;

    // keccak256(abi.encode(uint256(keccak256("outbe.intex.IntexNFT1155")) - 1)) & ~bytes32(uint256(0xff))
    uint256 internal constant _NFT_STORAGE_SLOT = 0xe941cbaf65abb9f7003c3006add9c5d12ba7e339abdf88d4afd5defeb8932900;
    // `seriesData` mapping is member 1 of the ERC-7201 struct; SeriesData spans 4 slots.
    uint256 internal constant _SERIES_DATA_OFFSET = 1;
    uint256 internal constant _SERIES_DATA_SLOTS = 4;
    // `status` sits at bit 96 of slot 3 (after issuedAt, calledAt, totalSupply).
    uint256 internal constant _STATUS_BIT = 96;

    address internal admin = makeAddr("admin");
    address internal bridger = makeAddr("bridger");
    address internal holder = makeAddr("holder");

    IntexNFT1155 internal nft;
    uint256 internal iTok;
    uint256 internal sTok;

    function setUp() public {
        nft = DeployProxy.intexNFT1155(admin, bridger);
        vm.prank(bridger);
        nft.createSeries(CreateSeriesLib.params(SERIES_ID_DAY, CAP, CALL_PERIOD));
        (iTok, sTok) = nft.tokenIds(SERIES_ID);
    }

    function _recordSlot(uint256 tokenId, uint256 i) internal view returns (bytes32) {
        uint256 base = uint256(keccak256(abi.encode(tokenId, _NFT_STORAGE_SLOT + _SERIES_DATA_OFFSET)));
        return vm.load(address(nft), bytes32(base + i));
    }

    function test_CreateSeries_CopiesIdentityIntoSettledRecord() public view {
        for (uint256 i = 0; i < _SERIES_DATA_SLOTS; i++) {
            bytes32 issued = _recordSlot(iTok, i);
            bytes32 settled = _recordSlot(sTok, i);
            if (i < _SERIES_DATA_SLOTS - 1) {
                assertEq(settled, issued, "identity slot must match the Issued record");
            } else {
                // Last slot: identical except the status byte flipped Issued -> Settled.
                assertEq(settled, issued | bytes32(uint256(1) << _STATUS_BIT), "only status may differ");
            }
        }
        // issuedAt (low 4 bytes of slot 3) doubles as the existence sentinel for both classes.
        assertTrue(uint32(uint256(_recordSlot(sTok, 3))) != 0, "settled record must carry issuedAt");
        assertEq(uint8(nft.statusOf(sTok)), uint8(IIntexNFT1155.IntexStatus.Settled));
    }

    function test_MarkCalled_DoesNotTouchSettledRecord() public {
        bytes32[_SERIES_DATA_SLOTS] memory before;
        for (uint256 i = 0; i < _SERIES_DATA_SLOTS; i++) {
            before[i] = _recordSlot(sTok, i);
        }

        vm.prank(bridger);
        nft.markQualified(SERIES_ID);
        vm.prank(bridger);
        nft.markCalled(SERIES_ID, uint32(block.timestamp));

        for (uint256 i = 0; i < _SERIES_DATA_SLOTS; i++) {
            assertEq(_recordSlot(sTok, i), before[i], "lifecycle transitions must not write the Settled record");
        }
        assertEq(uint8(nft.readData(SERIES_ID).state), uint8(IIntexNFT1155.IntexState.Called));
    }

    function test_SettledRecord_BridgeGuardsUnchanged() public {
        vm.prank(bridger);
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.BridgeOnSettledForbidden.selector, sTok));
        nft.crosschainMint(holder, sTok, 1);

        vm.prank(bridger);
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.BridgeOnSettledForbidden.selector, sTok));
        nft.crosschainBurn(holder, holder, sTok, 1);
    }
}
