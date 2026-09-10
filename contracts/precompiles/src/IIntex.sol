// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

/// @title IIntex
/// @notice Read-only view surface for the Intex runtime module: the
///         canonical, cross-chain Intex series ledger (identity + lifecycle).
/// @dev Writes are Rust-to-Rust only (IntexFactory); this interface exposes
///      reads for off-chain observability. `promisLoadMinor` is returned as uint256
///      (its storage representation); it is bounded by the Origin `uint128`.
interface IIntex {
    /// @notice Constant-size owner event for one certified contributor root.
    ///         There is deliberately no matching public installation selector.
    event CertifiedContributorRootInstalled(
        bytes32 indexed activationCallId,
        uint32 indexed worldwideDay,
        uint64 seriesVersionBefore,
        uint64 seriesVersionAfter,
        uint32 contributorCount,
        bytes32 contributorRoot,
        uint256 eligibleNominalTotal,
        bytes32 stateEventDigest
    );

    struct SeriesData {
        bytes14 seriesId;
        uint256 promisLoadMinor;
        uint256 entryPriceMinor;
        uint256 floorPriceMinor;
        uint32 issuedIntexCount;
        uint32 callWindow;
        uint32 callThreshold;
        uint256 callPriceMinor;
        uint8 state;
        uint32 issuedAt;
        uint32 calledAt;
        uint32 callNoticePeriod;
        uint16 issuanceCurrency;
        uint16 referenceCurrency;
        uint32 worldwideDay;
        /// @notice Units settled so far; their load belongs to the settler.
        uint32 settledUnits;
        /// @notice Units parked into Gem positions; their load moved with them.
        uint32 parkedUnits;
    }

    /// @notice Full identity + lifecycle record for a series. Reverts if the
    ///         series does not exist.
    function seriesData(bytes14 seriesId) external view returns (SeriesData memory);

    /// @notice Whether a series exists.
    function seriesExists(bytes14 seriesId) external view returns (bool);

    /// @notice Number of series ever created (dense-enumeration length).
    function totalSeries() external view returns (uint64);

    /// @notice The series id at a dense-enumeration index.
    function seriesAt(uint64 index) external view returns (bytes14);

    /// @notice Certified contributor authority for one day, as quorum installed it.
    ///         All fields are zero when no generation exists.
    struct CertifiedContributorGeneration {
        uint64 seriesVersion;
        bytes32 contributorRoot;
        uint32 contributorCount;
        uint256 eligibleNominalTotal;
    }

    /// @notice Read the certified contributor authority for `worldwideDay`. An
    ///         off-chain payout sender compares its local records against this
    ///         before building a proof.
    function certifiedContributorGeneration(uint32 worldwideDay)
        external
        view
        returns (CertifiedContributorGeneration memory);
}
