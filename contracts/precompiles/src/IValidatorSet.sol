// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

/// @title IValidatorSet
/// @notice Validator set management precompile at 0x000000000000000000000000000000000000EE00
interface IValidatorSet {
    /// Emitted when a new validator is registered.
    event ValidatorRegistered(address indexed validator, uint64 index);

    /// Emitted when a validator is activated.
    event ValidatorActivated(address indexed validator);

    /// Emitted when a validator begins exiting.
    event ValidatorDeactivated(address indexed validator, uint64 atHeight);

    /// Emitted when a validator is forced to exit because of a severe fault.
    event ValidatorForcedExit(address indexed validator, uint64 atHeight);

    /// Emitted when a validator is JAILED (slashed + frozen) on a felony, instead
    /// of being force-exited. It is dropped from the next reshare and may later
    /// unjail (-> PENDING -> ACTIVE) or unstake out.
    event ValidatorJailed(address indexed validator, uint64 atHeight);

    /// Emitted when a JAILED validator calls unjailValidator() and returns to
    /// PENDING (then ACTIVE via the next reshare).
    event ValidatorUnjailed(address indexed validator, uint64 atHeight);

    /// Emitted when an OCOMP recovery deadline is resolved. outcome:
    /// 1 = restored, 2 = jailed, 3 = lifecycle already non-active.
    event OcompRecoveryResolved(address indexed validator, uint64 recoveryDeadline, uint256 bondedStake, uint8 outcome);

    /// Emitted on epoch transition.
    event EpochTransition(uint256 indexed newEpochNumber, uint64 timestamp, uint32 activeValidatorCount);

    /// Emitted when DKG reshare updates the active consensus set.
    event ConsensusSetUpdated(uint32 activeCount);

    /// Emitted when a validator assigns a role-scoped operational key.
    event ValidatorDelegateSet(address indexed validator, uint8 indexed role, address indexed delegate);

    /// Emitted when a validator revokes a role-scoped operational key.
    event ValidatorDelegateRevoked(address indexed validator, uint8 indexed role, address indexed delegate);

    function getValidators() external view returns (address[] memory);
    function getActiveValidators() external view returns (address[] memory);
    function getActiveConsensusSet() external view returns (address[] memory);
    function validatorByAddress(address addr)
        external
        view
        returns (
            address validatorAddress,
            bytes memory consensusPubkey,
            uint256 stake,
            uint8 status,
            uint64 slashCount,
            uint64 missedBlocks,
            uint64 missedVotes,
            uint64 blocksProposed,
            uint64 joinedAtHeight,
            uint64 deactivatedAtHeight,
            uint64 unbondingEnd,
            bool hasBLSShare
        );
    function validatorByIndex(uint64 index)
        external
        view
        returns (
            address validatorAddress,
            bytes memory consensusPubkey,
            uint256 stake,
            uint8 status,
            uint64 slashCount,
            uint64 missedBlocks,
            uint64 missedVotes,
            uint64 blocksProposed,
            uint64 joinedAtHeight,
            uint64 deactivatedAtHeight,
            uint64 unbondingEnd,
            bool hasBLSShare
        );
    function validatorCount() external view returns (uint32);
    function activeValidatorCount() external view returns (uint32);
    function activeConsensusCount() external view returns (uint32);
    function isValidator(address addr) external view returns (bool);
    function isConsensusParticipant(address addr) external view returns (bool);
    function hasPendingSetChange() external view returns (bool);
    function getEpochNumber() external view returns (uint256);
    function getEpochStartTimestamp() external view returns (uint64);
    function getEpochStartBlock() external view returns (uint64);
    /// Stable role ids: 1 = ORACLE, 2 = OCOMP. Unknown ids revert.
    function setDelegate(uint8 role, address delegate) external;
    function revokeDelegate(uint8 role) external;
    function getDelegate(address validator, uint8 role) external view returns (address);
    function resolveValidator(uint8 role, address signer) external view returns (address);
    function registerValidator(
        address validatorAddress,
        bytes calldata consensusPubkey,
        bytes32 radicleNodeId,
        bytes calldata blsRegistrationSignature
    ) external;
    function getRadicleNodeId(address validator) external view returns (bytes32);
    function validatorByRadicleNodeId(bytes32 nodeId) external view returns (address);
    function setP2pAddress(address validatorAddress, uint8 version, bytes calldata encoded) external;
    function getP2pAddress(address validatorAddress) external view returns (uint8 version, bytes memory encoded);
    function deactivateValidator(address validatorAddress) external;
    /// Stale-join guard: a PENDING joiner confirms on-chain that its node has
    /// caught up to head and may be frozen into the next DKG reshare target.
    /// Caller must be the validator itself and currently PENDING. Until called,
    /// a staked joiner stays PENDING and is excluded from the reshare target.
    function confirmValidatorReady(bytes calldata registration) external;
}
