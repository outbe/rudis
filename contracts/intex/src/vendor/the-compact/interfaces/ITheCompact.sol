// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {Scope} from "../types/Scope.sol";
import {ResetPeriod} from "../types/ResetPeriod.sol";

/**
 * @title The Compact - Minimal Interface
 * @notice Minimal interface for The Compact protocol, compatible with Uniswap The Compact.
 * @dev This is a minimal subset of the full ITheCompact interface. Full interface available at:
 *      https://github.com/Uniswap/the-compact/blob/main/src/interfaces/ITheCompact.sol
 * @custom:source https://github.com/Uniswap/the-compact
 */
interface ITheCompact {
    /**
     * @notice External function for depositing ERC20 tokens into a resource lock.
     * @param token     The address of the ERC20 token to deposit.
     * @param lockTag   The lock tag containing allocator ID, reset period, and scope.
     * @param amount    The amount of tokens to deposit.
     * @param recipient The address that will receive the corresponding ERC6909 tokens.
     * @return id       The ERC6909 token identifier of the associated resource lock.
     */
    function depositERC20(address token, bytes12 lockTag, uint256 amount, address recipient)
        external
        returns (uint256 id);

    /**
     * @notice External function to initiate a forced withdrawal for a resource lock.
     * @param id              The ERC6909 token identifier for the resource lock.
     * @return withdrawableAt The timestamp at which tokens become withdrawable.
     */
    function enableForcedWithdrawal(uint256 id) external returns (uint256 withdrawableAt);

    /**
     * @notice External function to execute a forced withdrawal from a resource lock.
     * @param id        The ERC6909 token identifier for the resource lock.
     * @param recipient The account that will receive the withdrawn tokens.
     * @param amount    The amount of tokens to withdraw.
     * @return          Boolean indicating whether the forced withdrawal was successfully executed.
     */
    function forcedWithdrawal(uint256 id, address recipient, uint256 amount) external returns (bool);

    /**
     * @notice External function for registering an allocator.
     * @param allocator    The address to register as an allocator.
     * @param proof        An 85-byte value containing create2 address derivation parameters.
     * @return allocatorId A unique identifier assigned to the registered allocator.
     */
    function __registerAllocator(address allocator, bytes calldata proof) external returns (uint96 allocatorId);

    /**
     * @notice External view function for retrieving the details of a resource lock.
     * @param id           The ERC6909 token identifier of the resource lock.
     * @return token       The address of the underlying token (or address(0) for native tokens).
     * @return allocator   The account of the allocator mediating the resource lock.
     * @return resetPeriod The duration after which the resource lock can be reset.
     * @return scope       The scope of the resource lock (multichain or single chain).
     * @return lockTag     The lock tag containing the allocator ID, the reset period, and the scope.
     */
    function getLockDetails(uint256 id)
        external
        view
        returns (address token, address allocator, ResetPeriod resetPeriod, Scope scope, bytes12 lockTag);
}
