// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

/// @title IStablecoinPolicyRegistry
/// @notice Shared bounded account-eligibility policy registry for Rust-native stablecoins.
interface IStablecoinPolicyRegistry {
    /// @dev policyType is one of DenyAll=0, AllowAll=1, Whitelist=2, Blacklist=3,
    ///      Directional=4. Only Whitelist and Blacklist may be created through this selector.
    event PolicyCreated(
        uint256 indexed policyId,
        address indexed actor,
        address indexed admin,
        uint8 policyType,
        uint256 sendPolicyId,
        uint256 receivePolicyId,
        uint256 mintPolicyId
    );
    event PolicyMemberAdded(uint256 indexed policyId, address indexed account, address indexed actor);
    event PolicyMemberRemoved(uint256 indexed policyId, address indexed account, address indexed actor);
    event PolicyAdminTransferStarted(
        uint256 indexed policyId, address indexed currentAdmin, address indexed pendingAdmin
    );
    event PolicyAdminTransferCancelled(
        uint256 indexed policyId, address indexed admin, address indexed cancelledPendingAdmin
    );
    event PolicyAdminTransferred(uint256 indexed policyId, address indexed previousAdmin, address indexed newAdmin);

    error UnexpectedValue(uint256 value);
    error InvalidPolicyType(uint8 policyType);
    error UnknownPolicy(uint256 policyId);
    error ImmutablePolicy(uint256 policyId);
    error InvalidPolicyAdmin(address admin);
    error UnauthorizedPolicyAdmin(uint256 policyId, address caller);
    error InvalidDirectionalChild(uint256 policyId);
    error DirectionalMembershipUnsupported(uint256 policyId);
    error InvalidMember(address account);
    error EmptyMemberBatch();
    error MemberBatchTooLarge(uint256 length, uint256 maximum);
    error DuplicateMember(address account);
    error MembershipUnchanged(uint256 policyId, address account, bool member);
    error InvalidPendingPolicyAdmin(address candidate);
    error NotPendingPolicyAdmin(uint256 policyId, address caller);
    error PolicyIdExhausted();
    error InvalidListLimit(uint256 limit, uint256 maximum);
    error PolicyMemberEnumerationUnsupported(uint256 policyId, uint8 policyType);

    /// @notice Creates a Whitelist or Blacklist policy. Reverts for all other descriptors.
    function createPolicy(uint8 policyType, address admin) external returns (uint256 policyId);

    /// @notice Creates a non-recursive Directional policy with immutable child policies.
    function createDirectionalPolicy(address admin, uint256 sendPolicyId, uint256 receivePolicyId, uint256 mintPolicyId)
        external
        returns (uint256 policyId);

    /// @notice Atomically adds unique nonzero accounts. Re-adding a member reverts.
    function addMembers(uint256 policyId, address[] calldata accounts) external;

    /// @notice Atomically removes unique nonzero accounts. Removing a non-member reverts.
    function removeMembers(uint256 policyId, address[] calldata accounts) external;

    function beginPolicyAdminTransfer(uint256 policyId, address candidate) external;

    function cancelPolicyAdminTransfer(uint256 policyId) external;

    function acceptPolicyAdminTransfer(uint256 policyId) external;

    function policyExists(uint256 policyId) external view returns (bool);

    function policyType(uint256 policyId) external view returns (uint8);

    function policyAdmin(uint256 policyId) external view returns (address);

    function pendingPolicyAdmin(uint256 policyId) external view returns (address);

    /// @notice Returns raw stored membership only for Whitelist and Blacklist policies.
    function isMember(uint256 policyId, address account) external view returns (bool);

    /// @notice Returns the current member count for a Whitelist or Blacklist policy.
    function policyMemberCount(uint256 policyId) external view returns (uint256);

    /// @notice Returns up to `limit` current members starting at `offset`.
    /// @dev Valid only for Whitelist and Blacklist. `limit` must be between 1 and
    ///      100. `offset >= policyMemberCount(policyId)` returns an empty array; the
    ///      final page is clamped to the current count. No ordering guarantee is
    ///      provided.
    function listPolicyMembers(uint256 policyId, uint256 offset, uint256 limit) external view returns (address[] memory);

    /// @notice Unknown policies return false rather than reverting.
    function canSend(uint256 policyId, address account) external view returns (bool);

    /// @notice Unknown policies return false rather than reverting.
    function canReceive(uint256 policyId, address account) external view returns (bool);

    /// @notice Unknown policies return false rather than reverting.
    function canMint(uint256 policyId, address account) external view returns (bool);
}
