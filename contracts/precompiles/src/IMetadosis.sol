// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

interface IMetadosis {
    error OcompActivationRejected(uint16 code);
    error OcompResultVoteRejected(uint16 code);

    event MetadosisAccumulation(
        uint32 indexed date, uint256 dayMetadosisLimitAmount, uint256 totalAccumulated, uint64 blockNumber
    );

    event OcompDayLimitFormed(
        uint32 indexed worldwideDay,
        uint256 baseLimit,
        uint256 carryOverBefore,
        uint256 carryOverTaken,
        uint256 carryOverAfter,
        uint256 formedDayLimit,
        uint64 blockNumber
    );

    event WorldwideDayStarted(
        uint32 indexed worldwideDay,
        uint64 formingStart,
        uint64 formingEnd,
        uint64 offeringStart,
        uint64 offeringEnd,
        uint64 scheduledTime
    );

    event WorldwideDayStatusChange(uint32 indexed worldwideDay, uint8 oldStatus, uint8 newStatus, uint64 blockNumber);

    /// @notice A reference currency was left out of a day's auction because the
    ///         oracle could price neither its previous closed UTC day nor the
    ///         worldwide day itself.
    event ReferenceCurrencyUnpriced(uint32 indexed worldwideDay, uint16 indexed isoCode);

    event WorldwideDayMissedOffering(
        uint32 indexed worldwideDay,
        uint256 dayMetadosisLimit,
        uint256 carryOverBefore,
        uint256 carryOverAfter,
        uint8 retirementOutcome,
        uint64 blockNumber
    );

    event WorldwideDayCapacityForfeited(
        uint32 indexed worldwideDay,
        uint32 maxRetainedWorldwideDays,
        uint32 retainedCountBefore,
        uint256 dayMetadosisLimit,
        uint256 carryOverBefore,
        uint256 carryOverAfter,
        bytes32 sealedCollectionRoot,
        uint32 forfeitedTributeCount,
        uint256 forfeitedTributeNominal,
        uint64 sourceGeneration,
        uint64 retiredGeneration,
        uint8 retirementOutcome,
        uint64 blockNumber
    );

    event MetadosisSkipped(uint32 indexed worldwideDay, string reason, string status, uint64 blockNumber);

    event MetadosisExecuted(
        uint32 indexed worldwideDay,
        uint256 tributeTotals,
        uint256 dayGratisDemand,
        uint256 dayGratisLimit,
        uint256 dayGratisAllocation,
        uint256 dayGratisAllocationRemainder,
        uint256 netDayGratisAllocation,
        uint256 dayMetadosisLimitRemainder,
        string status,
        uint64 blockNumber
    );

    event MetadosisWorldwideDayProcessed(
        uint32 indexed worldwideDay,
        uint256 dayMetadosisLimit,
        uint256 dayMetadosisLimitRemainder,
        string status,
        string dayState,
        string action
    );

    /// @notice Emitted when a terminal WorldwideDay record is evicted from the
    /// bounded delete-queue (oldest-first, once terminal records exceed the cap).
    /// `finalStatus` is the day's terminal status (COMPLETED or FAILED).
    event WorldwideDayCleanedUp(uint32 indexed worldwideDay, uint8 finalStatus);

    event OffchainJobRequested(
        bytes32 indexed intentId,
        uint32 indexed wwd,
        uint64 pendingNonce,
        uint32 attempt,
        bytes32 activationPreconditionsHash
    );

    event OffchainJobExpired(bytes32 indexed intentId, uint32 indexed wwd, uint64 expiredAtHeight);

    event OcompVoteMissed(
        address indexed validator,
        bytes32 indexed jobId,
        uint64 missCount,
        uint256 slashedBonded,
        uint64 recoveryDeadline,
        bool firstInWindow
    );

    event LysisActivated(
        bytes32 indexed intentId,
        bytes32 indexed jobId,
        bytes32 activationCallId,
        bytes32 resultDigest,
        bytes32 terminalReceiptHash,
        uint32 wwd
    );

    function getWorldwideDay(uint32 wwd)
        external
        view
        returns (
            uint8 status,
            uint8 dayType,
            uint64 formingStart,
            uint64 formingEnd,
            uint64 lookbackEnd,
            uint64 offeringEnd,
            uint64 scheduledProcessTime,
            uint256 previousVwap,
            uint256 currentVwap
        );

    function getActiveWorldwideDays() external view returns (uint32[] memory wwds);
    /// @notice Returns days for a closed WwdStatus discriminant.
    /// @dev Unknown status bytes revert; they are never interpreted as empty.
    function getWorldwideDaysByStatus(uint8 status) external view returns (uint32[] memory wwds);
    function getBootstrapEndTime() external view returns (uint64 endTime);

    function getWorldwideDayTerminalReceipt(uint32 wwd)
        external
        view
        returns (
            uint8 outcome,
            uint256 valueRouted,
            uint256 carryOverBefore,
            uint256 carryOverAfter,
            uint8 retirementOutcome,
            uint64 blockNumber
        );

    function getCapacityForfeitureReceipt(uint32 wwd)
        external
        view
        returns (
            uint8 outcome,
            uint32 maxRetainedWorldwideDays,
            uint32 retainedCountBefore,
            uint256 valueRouted,
            uint256 carryOverBefore,
            uint256 carryOverAfter,
            bytes32 sealedCollectionRoot,
            uint32 forfeitedTributeCount,
            uint256 forfeitedTributeNominal,
            uint64 sourceGeneration,
            uint64 retiredGeneration,
            uint8 retirementOutcome,
            uint64 blockNumber
        );

    /// @notice Return the canonical OCB1 record for one off-chain computation job.
    /// @param intentId Canonical JobIntent identifier.
    /// @return ocompJobRecordV1 Canonically encoded OcompJobRecordV1 bytes.
    function getOffchainJob(bytes32 intentId) external view returns (bytes memory ocompJobRecordV1);

    /// @notice Submit one canonical node-attested ResultVoteV1.
    function submitLysisResult(bytes calldata resultVoteV1) external;

    /// @notice Return the pinned ValidatorSet vote slots, immutable quorum and
    /// optional closed accountability summary for one finalized JobId.
    function getOffchainVoteAccountability(bytes32 jobId) external view returns (bytes memory ocompVoteAccountabilityV1);

    /// @notice Return the canonical active generation selected by Metadosis state.
    function getActiveLysisGeneration(uint32 wwd) external view returns (bytes memory activeGenerationV1);

    /// @notice Return the canonical aggregate terminal receipt for an activation attempt.
    function getLysisTerminalReceipt(bytes32 intentId) external view returns (bytes memory aggregateActivationReceiptV1);
}
