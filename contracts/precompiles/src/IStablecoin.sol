// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.30;

/// @title IStablecoin
/// @notice ERC-20-compatible issuer ledger executed by the shared Rust stablecoin runtime.
interface IStablecoin {
    /// @dev Stable uint8 encoding used by PolicyDenied: Send=0, Receive=1, Mint=2.
    enum PolicyOperation {
        Send,
        Receive,
        Mint
    }

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event TransferWithMemo(address indexed from, address indexed to, uint256 amount, bytes32 indexed memo);
    event Frozen(address indexed account, uint256 amount);
    event ForcedTransfer(address indexed from, address indexed to, uint256 amount);
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed actor);
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed actor);
    event SupplyCapChanged(uint256 previousCap, uint256 newCap, address indexed actor);
    event PolicyChanged(uint256 previousPolicyId, uint256 newPolicyId, address indexed actor);
    event Paused(address indexed actor);
    event Unpaused(address indexed actor);
    event AdminTransferStarted(address indexed currentAdmin, address indexed pendingAdmin);
    event AdminTransferCancelled(address indexed admin, address indexed cancelledPendingAdmin);
    event AdminTransferred(address indexed previousAdmin, address indexed newAdmin);

    error UnexpectedValue(uint256 value);
    error Unauthorized(bytes32 role, address caller);
    error UnsupportedRole(bytes32 role);
    error InvalidAddress(address account);
    error InvalidAmount();
    error TokenPaused();
    error TokenNotPaused();
    error InsufficientBalance(address account, uint256 available, uint256 required);
    error InsufficientAllowance(address owner, address spender, uint256 available, uint256 required);
    error ERC7943CannotSend(address account);
    error ERC7943CannotReceive(address account);
    error ERC7943CannotTransfer(address from, address to, uint256 amount);
    error ERC7943InsufficientUnfrozenBalance(address account, uint256 amount, uint256 unfrozen);
    error FrozenAllowanceIncrease(address owner, uint256 currentAllowance, uint256 requestedAllowance);
    error SupplyCapExceeded(uint256 supplyCap, uint256 requestedSupply);
    error SupplyCapBelowSupply(uint256 requestedCap, uint256 totalSupply);
    error UnknownPolicy(uint256 policyId);
    error PolicyDenied(uint256 policyId, address account, PolicyOperation operation);
    error ForcedSelfTransfer();
    error InvalidPendingAdmin(address candidate);
    error NotPendingAdmin(address caller);
    error PermitExpired(uint256 deadline);
    error InvalidPermitSignature();
    error MigrationRequired(uint64 storedSchemaVersion, uint64 activeSchemaVersion);

    function name() external view returns (string memory);

    function symbol() external view returns (string memory);

    function decimals() external view returns (uint8);

    function totalSupply() external view returns (uint256);

    function balanceOf(address account) external view returns (uint256);

    function allowance(address owner, address spender) external view returns (uint256);

    function approve(address spender, uint256 value) external returns (bool);

    function transfer(address to, uint256 value) external returns (bool);

    function transferFrom(address from, address to, uint256 value) external returns (bool);

    function nonces(address owner) external view returns (uint256);

    function DOMAIN_SEPARATOR() external view returns (bytes32);

    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s)
        external;

    function supportsInterface(bytes4 interfaceId) external view returns (bool);

    function currency() external view returns (uint16);

    function supplyCap() external view returns (uint256);

    function policyId() external view returns (uint256);

    function issuer() external view returns (address);

    function paused() external view returns (bool);

    /// @notice ADMIN and all five operational roles are queryable.
    function hasRole(bytes32 role, address account) external view returns (bool);

    function pendingAdmin() external view returns (address);

    function creationProtocolVersion() external view returns (uint64);

    function canSend(address account) external view returns (bool status);

    function canReceive(address account) external view returns (bool status);

    function canTransfer(address from, address to, uint256 value) external view returns (bool status);

    function forcedTransfer(address from, address to, uint256 value) external returns (bool result);

    function getFrozenTokens(address account) external view returns (uint256 amount);

    function setFrozenTokens(address account, uint256 amount) external returns (bool result);

    function mint(address to, uint256 amount) external returns (bool);

    function burn(uint256 amount) external returns (bool);

    function burnFrom(address from, uint256 amount) external returns (bool);

    function transferWithMemo(address to, uint256 amount, bytes32 memo) external returns (bool);

    function transferFromWithMemo(address from, address to, uint256 amount, bytes32 memo) external returns (bool);

    function mintWithMemo(address to, uint256 amount, bytes32 memo) external returns (bool);

    function burnWithMemo(uint256 amount, bytes32 memo) external returns (bool);

    function burnFromWithMemo(address from, uint256 amount, bytes32 memo) external returns (bool);

    function forcedTransferWithMemo(address from, address to, uint256 amount, bytes32 memo) external returns (bool);

    /// @notice Grants one of ISSUER, CAP_MANAGER, GUARDIAN, COMPLIANCE, or ENFORCER.
    /// @dev ADMIN is rejected with UnsupportedRole and changes only through two-step transfer.
    function grantRole(bytes32 role, address account) external;

    /// @notice Revokes one of ISSUER, CAP_MANAGER, GUARDIAN, COMPLIANCE, or ENFORCER.
    /// @dev ADMIN is rejected with UnsupportedRole and changes only through two-step transfer.
    function revokeRole(bytes32 role, address account) external;

    function setSupplyCap(uint256 newCap) external;

    function setPolicyId(uint256 newPolicyId) external;

    function pause() external;

    function unpause() external;

    function beginAdminTransfer(address candidate) external;

    function cancelAdminTransfer() external;

    function acceptAdminTransfer() external;
}
