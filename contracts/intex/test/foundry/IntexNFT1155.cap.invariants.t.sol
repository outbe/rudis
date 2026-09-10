// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {Test} from "forge-std/Test.sol";
import {StdInvariant} from "forge-std/StdInvariant.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {DeployProxy} from "./helpers/DeployProxy.sol";
import {CreateSeriesLib} from "./helpers/CreateSeriesLib.sol";
import {IIntexNFT1155} from "@contracts/shared/interfaces/IIntexNFT1155.sol";

/// @dev Randomized mints and burns into a fixed series; the cap and parity invariants must always
///      hold. A burn frees cap room, so totalSupply moves both ways while staying `<= cap`.
contract NFT1155CapHandler is Test {
    IntexNFT1155 internal intex;
    bytes14 internal seriesId;
    uint256 internal tokenId;
    address[] internal bidders;

    constructor(IntexNFT1155 _intex, bytes14 _seriesId, address[] memory _bidders) {
        intex = _intex;
        seriesId = _seriesId;
        tokenId = _intex.issuedTokenId(_seriesId);
        bidders = _bidders;
    }

    function mint(uint256 bidderSeed, uint256 qtySeed) external {
        address to = bidders[bound(bidderSeed, 0, bidders.length - 1)];
        uint256 qty = bound(qtySeed, 1, 1_000);
        try intex.issue(to, qty, seriesId) {} catch {}
    }

    /// @dev Burning Issued frees cap room: totalSupply must drop and the cap stays reusable.
    function burn(uint256 bidderSeed, uint256 qtySeed) external {
        address from = bidders[bound(bidderSeed, 0, bidders.length - 1)];
        uint256 bal = intex.balanceOf(from, tokenId);
        if (bal == 0) return;
        uint256 qty = bound(qtySeed, 1, bal);
        try intex.crosschainBurn(from, from, tokenId, qty) {} catch {}
    }
}

contract IntexNFT1155CapInvariantTest is StdInvariant, Test {
    IntexNFT1155 internal intex;
    NFT1155CapHandler internal handler;
    address internal admin = address(this);
    address[] internal bidders;

    uint32 internal constant SERIES_ID_DAY = 20250101;
    bytes14 internal constant SERIES_ID = "20250101-USD-U";
    uint32 internal constant CAP = 10_000;

    function setUp() public {
        intex = DeployProxy.intexNFT1155(admin, admin);
        intex.createSeries(CreateSeriesLib.params(SERIES_ID_DAY, CAP, 0));

        bidders.push(address(0xB1));
        bidders.push(address(0xB2));
        bidders.push(address(0xB3));

        handler = new NFT1155CapHandler(intex, SERIES_ID, bidders);
        // Handler drives mint/crosschainBurn directly; both are RELAYER_ROLE-gated.
        intex.grantRole(intex.RELAYER_ROLE(), address(handler));
        // crosschainBurn is rejected while a series is Issued; Qualified opens the bridge path so the
        // burn action can actually free cap room during the run.
        intex.markQualified(SERIES_ID);

        bytes4[] memory selectors = new bytes4[](2);
        selectors[0] = NFT1155CapHandler.mint.selector;
        selectors[1] = NFT1155CapHandler.burn.selector;
        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
    }

    /// @dev Cap is on LIVE supply: `totalSupply <= issuedIntexCount` at every step, and a burn frees
    ///      room rather than permanently consuming the cap. Parity (sum balanceOf == totalSupply) holds.
    function invariant_supplyCapAndParity() public view {
        uint256 iTok = intex.issuedTokenId(SERIES_ID);
        IIntexNFT1155.SeriesData memory d = intex.readData(SERIES_ID);
        assertLe(d.totalSupply, d.issuedIntexCount, "totalSupply exceeds cap");
        assertEq(d.issuedIntexCount, CAP, "cap is immutable");
        uint256 sum;
        for (uint256 i = 0; i < bidders.length; i++) {
            sum += intex.balanceOf(bidders[i], iTok);
        }
        assertEq(sum, d.totalSupply, "sum(balanceOf) != totalSupply");
    }
}
