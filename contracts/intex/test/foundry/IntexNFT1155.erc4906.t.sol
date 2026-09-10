// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test, Vm} from "forge-std/Test.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {IIntexNFT1155} from "@contracts/shared/interfaces/IIntexNFT1155.sol";
import {IERC1155Bridgeable} from "@contracts/shared/interfaces/IERC1155Bridgeable.sol";
import {DeployProxy} from "./helpers/DeployProxy.sol";
import {CreateSeriesLib} from "./helpers/CreateSeriesLib.sol";

/// @dev ERC-4906 discipline: `MetadataUpdate` fires exactly when the rendered document changes
///      (series birth, lifecycle transitions) and never on supply moves.
contract IntexNFT1155Erc4906Test is Test {
    bytes32 internal constant METADATA_UPDATE_TOPIC = keccak256("MetadataUpdate(uint256)");
    uint32 internal constant SERIES_ID_DAY = 20260622;
    bytes14 internal constant SERIES_ID = "20260622-USD-U";
    uint32 internal constant CAP = 10_000;
    uint32 internal constant CALL_PERIOD = 14 days;

    address internal admin = makeAddr("admin");
    address internal bridger = makeAddr("bridger");
    address internal user = makeAddr("user");
    address internal user2 = makeAddr("user2");
    address internal user3 = makeAddr("user3");

    IntexNFT1155 internal nft;
    uint256 internal iTok;
    uint256 internal sTok;

    function setUp() public {
        nft = DeployProxy.intexNFT1155(admin, bridger);
        vm.startPrank(admin);
        nft.grantRole(nft.SETTLEMENT_ROLE(), bridger);
        nft.grantRole(nft.PROMIS_ROLE(), bridger);
        nft.grantRole(nft.GEM_ROLE(), bridger);
        vm.stopPrank();
        (iTok, sTok) = nft.tokenIds(SERIES_ID);
    }

    /// @dev Drains recorded logs; counts MetadataUpdate emits and checks the de-indexed shape.
    function _metadataUpdates() internal returns (uint256 count, uint256 lastTokenId) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i = 0; i < logs.length; i++) {
            if (logs[i].emitter != address(nft) || logs[i].topics[0] != METADATA_UPDATE_TOPIC) continue;
            count++;
            assertEq(logs[i].topics.length, 1, "tokenId must be non-indexed");
            lastTokenId = abi.decode(logs[i].data, (uint256));
        }
    }

    function test_SupportsInterface_Erc4906() public view {
        assertTrue(nft.supportsInterface(bytes4(0x49064906)), "ERC-4906");
        assertTrue(nft.supportsInterface(type(IIntexNFT1155).interfaceId));
        assertTrue(nft.supportsInterface(type(IERC1155Bridgeable).interfaceId));
        assertFalse(nft.supportsInterface(0xffffffff));
    }

    function test_MetadataUpdate_OnlyOnRenderedChanges() public {
        vm.recordLogs();
        vm.startPrank(bridger);

        nft.createSeries(CreateSeriesLib.params(SERIES_ID_DAY, CAP, CALL_PERIOD));
        (uint256 count, uint256 tokenId) = _metadataUpdates();
        assertEq(count, 1, "createSeries emits once");
        assertEq(tokenId, iTok);

        nft.issue(user, 10, SERIES_ID);
        (count,) = _metadataUpdates();
        assertEq(count, 0, "mint is supply-only");

        nft.markQualified(SERIES_ID);
        (count, tokenId) = _metadataUpdates();
        assertEq(count, 1, "markQualified changes the document");
        assertEq(tokenId, iTok);

        nft.parkIntex(user, SERIES_ID, 1);
        (count,) = _metadataUpdates();
        assertEq(count, 0, "parkIntex is supply-only");

        nft.markCalled(SERIES_ID, uint32(block.timestamp));
        (count, tokenId) = _metadataUpdates();
        assertEq(count, 1, "markCalled changes the document");
        assertEq(tokenId, iTok);

        nft.settle(SERIES_ID, user, user2, 2);
        (count,) = _metadataUpdates();
        assertEq(count, 0, "settle is supply-only");

        nft.burnSettled(user2, SERIES_ID, 1);
        (count,) = _metadataUpdates();
        assertEq(count, 0, "burnSettled is supply-only");

        nft.crosschainBurn(user, user, iTok, 1);
        nft.crosschainMint(user3, iTok, 1);
        (count,) = _metadataUpdates();
        assertEq(count, 0, "bridge moves are supply-only");

        vm.stopPrank();
    }
}
