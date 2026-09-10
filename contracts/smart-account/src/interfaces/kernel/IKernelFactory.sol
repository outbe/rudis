// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

import {Install} from "@zerodev/kernel/types/Structs.sol";

/// @dev Minimal interface for the Kernel v4 KernelFactory (ERC-1967 UUPS proxies).
///      `deploy` returns the `Kernel` account; declared as `address` (identical ABI encoding).
interface IKernelFactory {
    function deploy(Install[] calldata initialPackages, uint256 nonce) external payable returns (address);
    function getAddress(Install[] calldata initialPackages, uint256 nonce) external view returns (address);
}
