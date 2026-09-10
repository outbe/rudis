// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {IIntexNFT1155} from "@contracts/shared/interfaces/IIntexNFT1155.sol";
import {DeployProxy} from "./helpers/DeployProxy.sol";
import {CreateSeriesLib} from "./helpers/CreateSeriesLib.sol";

/// @notice A called series past its notice period reads as `Expired`, while storage
///         keeps `Called` so every freeze written against the stored field still bites.
contract IntexNFT1155ExpiredTest is Test {
    uint32 internal constant SERIES_ID_DAY = 20260622;
    bytes14 internal constant SERIES_ID = "20260622-USD-U";
    uint32 internal constant CAP = 10_000;
    uint32 internal constant CALL_PERIOD = 21 days;

    /// erc7201:outbe.intex.IntexNFT1155; `seriesData` is the namespace's second member.
    bytes32 internal constant STORAGE_SLOT = 0xe941cbaf65abb9f7003c3006add9c5d12ba7e339abdf88d4afd5defeb8932900;

    address internal admin = makeAddr("admin");
    address internal relayer = makeAddr("relayer");
    address internal user = makeAddr("user");

    IntexNFT1155 internal token;
    uint256 internal iTok;
    uint256 internal sTok;
    uint256 internal deadline;

    function setUp() public {
        token = DeployProxy.intexNFT1155(admin, relayer);
        vm.startPrank(relayer);
        token.createSeries(CreateSeriesLib.params(SERIES_ID_DAY, CAP, CALL_PERIOD));
        token.issue(user, 10, SERIES_ID);
        token.markQualified(SERIES_ID);
        token.markCalled(SERIES_ID, uint32(block.timestamp));
        vm.stopPrank();
        (iTok, sTok) = token.tokenIds(SERIES_ID);
        deadline = block.timestamp + CALL_PERIOD;
    }

    /// The stored `state` word: `SeriesData` packs `issuedAt`, `calledAt`, `totalSupply`,
    /// `status` and `state` into the record's fourth slot, `state` at byte 13.
    function _storedState() internal view returns (uint8) {
        bytes32 base = keccak256(abi.encode(iTok, bytes32(uint256(STORAGE_SLOT) + 1)));
        return uint8(uint256(vm.load(address(token), bytes32(uint256(base) + 3))) >> 104);
    }

    function test_ReadsCalledUpToTheDeadlineAndExpiredAfterIt() public {
        vm.warp(deadline);
        assertEq(uint8(token.readData(SERIES_ID).state), uint8(IIntexNFT1155.IntexState.Called));

        vm.warp(deadline + 1);
        assertEq(uint8(token.readData(SERIES_ID).state), uint8(IIntexNFT1155.IntexState.Expired));
    }

    function test_SeriesDataAgreesWithReadData() public {
        vm.warp(deadline + 1);
        (,,,,,,,,,,,, IIntexNFT1155.IntexState state) = token.seriesData(iTok);
        assertEq(uint8(state), uint8(IIntexNFT1155.IntexState.Expired));
    }

    /// The whole point of deriving: storage still says `Called`, so `_update`,
    /// `crosschainBurn` and `crosschainMint` keep refusing an expired series.
    function test_StorageStillHoldsCalled() public {
        assertEq(_storedState(), uint8(IIntexNFT1155.IntexState.Called), "before");
        vm.warp(deadline + 1);
        assertEq(_storedState(), uint8(IIntexNFT1155.IntexState.Called), "after");
    }

    function test_TransferStaysFrozenAfterExpiry() public {
        vm.warp(deadline + 1);
        vm.prank(user);
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.TransferOnCalledForbidden.selector, iTok));
        token.safeTransferFrom(user, makeAddr("other"), iTok, 1, "");
    }

    function test_BridgeStaysClosedAfterExpiry() public {
        vm.warp(deadline + 1);
        vm.prank(relayer);
        vm.expectRevert(abi.encodeWithSelector(IIntexNFT1155.BridgeAfterDeadline.selector, iTok, uint32(deadline)));
        token.crosschainBurn(user, user, iTok, 1);
    }

    /// `statusOf` answers which of the two token ids this is, not where the series
    /// stands, so expiry must leave it alone - a settled unit is paid for and alive.
    function test_StatusOfIsUntouched() public {
        vm.warp(deadline + 1);
        assertEq(uint8(token.statusOf(iTok)), uint8(IIntexNFT1155.IntexStatus.Issued));
        assertEq(uint8(token.statusOf(sTok)), uint8(IIntexNFT1155.IntexStatus.Settled));
    }
}
