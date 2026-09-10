// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {IntexNFT1155} from "@contracts/shared/IntexNFT1155.sol";
import {IntexAuction} from "@contracts/target/IntexAuction.sol";
import {EscrowAdapter} from "@contracts/target/EscrowAdapter.sol";
import {OriginRouter} from "@contracts/origin/OriginRouter.sol";
import {TargetRouter} from "@contracts/target/TargetRouter.sol";
import {IntexNFT1155Bridge} from "@contracts/shared/IntexNFT1155Bridge.sol";
import {Vm} from "forge-std/Vm.sol";

/// @dev Deploys implementation + ERC1967 proxy pairs for the UUPS contracts under test.
///      Returned handles point at the proxy; `bridger` receives RELAYER_ROLE.
library DeployProxy {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function intexNFT1155(address defaultAdmin, address bridger) internal returns (IntexNFT1155) {
        IntexNFT1155 impl = new IntexNFT1155();
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), abi.encodeCall(IntexNFT1155.initialize, (defaultAdmin)));
        IntexNFT1155 nft = IntexNFT1155(address(proxy));
        bytes32 role = nft.RELAYER_ROLE();
        vm.prank(defaultAdmin);
        nft.grantRole(role, bridger);
        return nft;
    }

    function intexAuction(address defaultAdmin, address bridger) internal returns (IntexAuction) {
        IntexAuction impl = new IntexAuction();
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), abi.encodeCall(IntexAuction.initialize, (defaultAdmin)));
        IntexAuction auction = IntexAuction(address(proxy));
        bytes32 role = auction.RELAYER_ROLE();
        vm.prank(defaultAdmin);
        auction.grantRole(role, bridger);
        return auction;
    }

    function escrowAdapter(address defaultAdmin, address bridger) internal returns (EscrowAdapter) {
        EscrowAdapter impl = new EscrowAdapter();
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), abi.encodeCall(EscrowAdapter.initialize, (defaultAdmin)));
        EscrowAdapter escrow = EscrowAdapter(address(proxy));
        bytes32 role = escrow.RELAYER_ROLE();
        vm.prank(defaultAdmin);
        escrow.grantRole(role, bridger);
        return escrow;
    }

    /// @dev The router is not chain-pinned; targets are a runtime registry. Callers register
    ///      targets via `addTarget` after wiring the peer.
    function originRouter(address bridge, address delegate) internal returns (OriginRouter) {
        OriginRouter impl = new OriginRouter(bridge);
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), abi.encodeCall(OriginRouter.initialize, (delegate)));
        return OriginRouter(payable(address(proxy)));
    }

    function targetRouter(address bridge, address delegate, uint32 outbeChainId) internal returns (TargetRouter) {
        TargetRouter impl = new TargetRouter(bridge, outbeChainId);
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), abi.encodeCall(TargetRouter.initialize, (delegate)));
        return TargetRouter(payable(address(proxy)));
    }

    function intexNFT1155Bridge(address tokenAddr, address bridge, address delegate)
        internal
        returns (IntexNFT1155Bridge)
    {
        IntexNFT1155Bridge impl = new IntexNFT1155Bridge(tokenAddr, bridge);
        ERC1967Proxy proxy = new ERC1967Proxy(address(impl), abi.encodeCall(IntexNFT1155Bridge.initialize, (delegate)));
        return IntexNFT1155Bridge(payable(address(proxy)));
    }
}
