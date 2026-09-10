// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {ITheCompact} from "the-compact/src/interfaces/ITheCompact.sol";
import {IAuction} from "../../interfaces/IAuction.sol";
import {ISolverEscrow} from "../../interfaces/ISolverEscrow.sol";

/**
 * @title RouterAccessors
 * @notice Shared virtual accessors for Origin and Destination settlers
 * @dev Prevents diamond inheritance conflicts - BaseRouter provides single override for all.
 */
abstract contract RouterAccessors {
    function _compact() internal view virtual returns (ITheCompact);
    function _lockTag() internal view virtual returns (bytes12);
    function _auction() internal view virtual returns (IAuction);
    function _solverEscrow() internal view virtual returns (ISolverEscrow);
    function _localDomain() internal view virtual returns (uint32);
}
