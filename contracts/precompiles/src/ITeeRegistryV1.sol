// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

/// @notice Flattened view of a node-enclave binding.
struct NodeEnclaveBindingV1View {
    bool exists;
    bytes32 nodeIdHash;
    bytes32 enclaveId;
    bytes32 bindingId;
    bytes32 intentHash;
    bytes32 evidenceHash;
    bytes32 policyHash;
    uint64 bindingVersion;
    uint64 registrationVersion;
    uint64 renewalNonce;
    uint64 transitionNonce;
    uint64 leaseStartedAt;
    uint64 validUntil;
    uint64 collateralValidUntil;
    bytes32 recipientX25519;
    bytes32 attestationEd25519;
    bytes32 noiseResponderX25519;
    bytes32 mrenclave;
    bytes32 mrsigner;
    uint16 isvProdId;
    uint16 isvSvn;
    uint8 platformTcbStatus;
    bytes32 verdictHash;
    bytes32 nodeHostAuthorizationHash;
}

/// @title ITeeRegistryV1
/// @notice TeeRegistry V1 node-enclave registration surface at
///         0x000000000000000000000000000000000000EE0A.
/// @dev One interface pins selectors, event topics and tuple layout across the
///      consensus precompile, the operator tooling and the CLI.
interface ITeeRegistryV1 {
    /// @notice Fixed-size consensus event. Evidence, collateral, advisories and
    ///         signatures are deliberately excluded so a registration cannot
    ///         create an unbounded log.
    event EnclaveRegisteredV1(
        bytes32 indexed nodeIdHash,
        bytes32 indexed enclaveId,
        bytes32 indexed bindingId,
        uint64 validUntil,
        uint64 bindingVersion
    );

    event EnclaveRenewedV1(
        bytes32 indexed nodeIdHash,
        bytes32 indexed enclaveId,
        bytes32 indexed bindingId,
        uint64 validUntil,
        uint64 registrationVersion,
        uint64 renewalNonce
    );

    event EnclaveBindingReplacedV1(
        bytes32 indexed nodeIdHash,
        bytes32 indexed enclaveId,
        bytes32 indexed bindingId,
        uint64 validUntil,
        uint64 bindingVersion
    );

    event EnclaveMeasurementTransitionedV1(
        bytes32 indexed nodeIdHash,
        bytes32 indexed enclaveId,
        bytes32 indexed bindingId,
        bytes32 policyHash,
        uint64 validUntil,
        uint64 bindingVersion,
        uint64 transitionNonce
    );

    event ValidatorNodeHostBoundV1(address indexed validator, bytes32 indexed nodeIdHash);

    /// @notice One-time permanent offer-key onboarding artifact for a newly
    ///         created V1 binding. Renewal, replacement and idempotent replay
    ///         never emit it.
    event OfferKeySealedForRegistryV1(bytes32 indexed nodeIdHash, bytes sealedOfferKey);

    event TeePolicyActivatedV1(
        uint256 indexed proposalId, bytes32 indexed policyHash, uint64 policyVersion, uint64 activationHeight
    );

    function isBootstrapped() external view returns (bool);
    function tributeOfferPublicKey() external view returns (uint256);
    function policyHash() external view returns (uint256);
    function keyEpoch() external view returns (uint256);
    function tributeOfferEpoch() external view returns (uint256);
    function activePolicyV1() external view returns (bytes memory);
    function stagedSuccessorPolicyV1() external view returns (bool exists, uint256 proposalId, bytes memory policy);

    function registerEnclave(
        bytes calldata evidence,
        bytes calldata nodeSignature,
        bytes calldata enclaveSignature,
        bytes calldata validatorNodeBinding,
        bytes calldata validatorSignature,
        bytes calldata nodeBindingSignature
    ) external returns (bool);

    function renewEnclave(bytes calldata evidence, bytes calldata nodeSignature, bytes calldata enclaveSignature)
        external
        returns (bool);

    function replaceEnclaveBinding(
        bytes calldata evidence,
        bytes calldata nodeSignature,
        bytes calldata enclaveSignature
    ) external returns (bool);

    function transitionEnclaveMeasurement(
        bytes calldata evidence,
        bytes calldata nodeSignature,
        bytes calldata enclaveSignature
    ) external returns (bool);

    function validatorEnclaveBinding(address validator) external view returns (NodeEnclaveBindingV1View memory);

    function nodeHostEnclaveBinding(uint8 rethP2pPrefix, bytes32 rethP2pX)
        external
        view
        returns (NodeEnclaveBindingV1View memory);

    function isValidatorEnclaveReady(address validator) external view returns (bool);

    function isNodeHostEnclaveReady(uint8 rethP2pPrefix, bytes32 rethP2pX) external view returns (bool);
}
