// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity ^0.8.0;

/// @notice Standalone cross-chain vault-routing capability.
/// @dev A concrete implementation may compose this interface with {IVaultRouter}
///      without forcing every cross-chain implementation to implement local routing.
interface IVaultRouterCrosschainExtention {
    enum CrosschainOperationKind {
        Unknown,
        Deposit,
        Withdraw
    }

    enum CrosschainOperationStatus {
        Unknown,
        Pending,
        Completed
    }

    error InvalidDestinationChain();
    error CrosschainBridgeNotConfigured();
    error CrosschainAssetNotConfigured();
    error CrosschainTokenBridgeNotConfigured();
    error RemoteVaultRouterNotConfigured(uint256 chainId);
    error CrosschainFeeMismatch(uint256 provided, uint256 required);
    error CrosschainOperationNotFound(bytes32 operationId);
    error CrosschainOperationAlreadyCompleted(bytes32 operationId);
    error CrosschainOperationsPending(uint256 count);
    error InvalidCrosschainSender();
    error InvalidCrosschainCallback();
    error InsufficientCrosschainShares(uint256 availableShares, uint256 requiredShares);

    event CrosschainBridgeUpdated(address indexed oldBridge, address indexed newBridge);
    event RemoteVaultRouterUpdated(uint256 indexed chainId, address indexed oldRouter, address indexed newRouter);
    event CrosschainAssetUpdated(
        address indexed oldAsset, address indexed newAsset, address indexed tokenBridge, uint256 destinationChainId
    );
    event CrosschainDepositSent(
        bytes32 indexed operationId,
        address indexed user,
        uint256 assetsAmount,
        uint256 destinationChainId,
        bytes32 sendId
    );
    event CrosschainDepositFinalized(
        bytes32 indexed operationId, address indexed user, uint256 assetsAmount, uint256 receiptShares
    );
    event CrosschainWithdrawalSent(
        bytes32 indexed operationId,
        address indexed user,
        uint256 receiptShares,
        uint256 destinationChainId,
        bytes32 sendId
    );
    event CrosschainWithdrawalFinalized(
        bytes32 indexed operationId, address indexed user, uint256 receiptShares, uint256 assetsAmount
    );

    /// @notice Returns the generic ERC-7786 bridge used for crosschain vault messages.
    function crosschainBridge() external view returns (address);

    /// @notice Returns the configured remote vault router for `chainId`.
    function remoteVaultRouter(uint256 chainId) external view returns (address);

    /// @notice Sets the generic ERC-7786 bridge used for crosschain vault messages.
    function setCrosschainBridge(address bridge) external;

    /// @notice Sets the remote vault router for `chainId`.
    function setRemoteVaultRouter(uint256 chainId, address router) external;

    /// @notice Returns the Outbe asset used by the crosschain vault flow.
    function crosschainAsset() external view returns (address);

    /// @notice Returns the Outbe token bridge used to send and receive the crosschain asset.
    function crosschainTokenBridge() external view returns (address);

    /// @notice Returns the fixed destination chain hosting the remote vault.
    function crosschainDestinationChainId() external view returns (uint256);

    /// @notice Configures the Outbe asset, token bridge and fixed destination chain.
    function setCrosschainAsset(address asset, address tokenBridge, uint256 destinationChainId) external;

    /// @notice Returns the nonce used to derive crosschain operation identifiers.
    function crosschainOperationNonce() external view returns (uint256);

    /// @notice Returns the number of crosschain operations awaiting authenticated completion.
    function pendingCrosschainOperations() external view returns (uint256);

    /// @notice Returns the finalized 1:1 remote-vault receipt shares owned by `user`.
    function crosschainShares(address user) external view returns (uint256);

    /// @notice Returns the total finalized 1:1 remote-vault receipt shares.
    function totalCrosschainShares() external view returns (uint256);

    /// @notice Returns the stored details and lifecycle state of `operationId`.
    function crosschainOperation(bytes32 operationId)
        external
        view
        returns (address user, uint256 amount, CrosschainOperationKind kind, CrosschainOperationStatus status);

    /// @notice Quotes a crosschain WCOEN deposit and previews its operation identifier.
    function quoteCrosschainDeposit(uint256 assetsAmount, uint256 destinationGasLimit, uint256 acknowledgementGasLimit)
        external
        view
        returns (uint256 nativeFee, bytes32 operationId);

    /// @notice Locks Outbe WCOEN and starts a deposit into the fixed remote 1:1 vault.
    function crosschainDeposit(uint256 assetsAmount, uint256 destinationGasLimit, uint256 acknowledgementGasLimit)
        external
        payable
        returns (bytes32 operationId, bytes32 sendId);

    /// @notice Quotes a crosschain receipt-share withdrawal and previews its operation identifier.
    function quoteCrosschainWithdraw(uint256 sharesAmount, uint256 requestGasLimit, uint256 returnGasLimit)
        external
        view
        returns (uint256 nativeFee, bytes32 operationId);

    /// @notice Removes 1:1 receipt shares and requests the corresponding WCOEN from the remote vault.
    function crosschainWithdraw(uint256 sharesAmount, uint256 requestGasLimit, uint256 returnGasLimit)
        external
        payable
        returns (bytes32 operationId, bytes32 sendId);

    /// @notice Receives the BNB deposit acknowledgement through the generic ERC-7786 bridge.
    function receiveMessage(bytes32 receiveId, bytes calldata sender, bytes calldata payload)
        external
        payable
        returns (bytes4);

    /// @notice Receives returned WCOEN after the Outbe token bridge credits this router.
    function onCrosschainTokensReceived(
        uint32 sourceDomain,
        bytes calldata from,
        uint256 amount,
        bytes calldata extraData
    ) external returns (bytes4);
}
