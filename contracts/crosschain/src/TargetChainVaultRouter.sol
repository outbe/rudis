// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";

import {IERC7786GatewaySource, IERC7786Recipient, IGatewayQuote} from "./interfaces/IERC7786.sol";
import {IERC7786TokenReceiver} from "./interfaces/IERC7786TokenReceiver.sol";

interface IOneToOneVault {
    function asset() external view returns (address);
    function deposit(uint256 assets, address onBehalf) external returns (uint256 shares);
    function withdraw(uint256 assets, address receiver, address onBehalf) external returns (uint256 burnedShares);
    function balanceOf(address account) external view returns (uint256);
}

interface IERC7786TokenBridge {
    function token() external view returns (IERC20);

    function quoteSend(uint32 destinationDomain, address to, uint256 amount, bytes calldata extraData, uint256 gasLimit)
        external
        view
        returns (uint256 nativeFee);

    function sendAndCall(
        uint32 destinationDomain,
        address to,
        uint256 amount,
        bytes calldata extraData,
        uint256 gasLimit
    ) external payable returns (bytes32 sendId);
}

/// @title TargetChainVaultRouter
/// @notice Fixed target-chain adapter for the Outbe cross-chain WCOEN vault.
/// @dev Tokens arrive through ERC7786TokenBridge.sendAndCall, are deposited into one immutable
///      1:1 vault, and the resulting real vault shares remain in this contract. Outbe stores only
///      the mirrored receipt balance. This contract has no vault/source/target management registry.
contract TargetChainVaultRouter is IERC7786Recipient, IERC7786TokenReceiver, Ownable, ReentrancyGuard {
    using SafeERC20 for IERC20;

    uint256 public constant DEPOSIT_REQUEST = 1;
    uint256 public constant DEPOSIT_ACKNOWLEDGEMENT = 2;
    uint256 public constant WITHDRAW_REQUEST = 3;
    uint256 public constant WITHDRAW_RETURN = 4;

    enum OperationKind {
        None,
        Deposit,
        Withdraw
    }

    struct Operation {
        OperationKind kind;
        address user;
        uint256 amount;
    }

    error ZeroAddress();
    error InvalidContract(address target);
    error InvalidVaultAsset(address expected, address actual);
    error InvalidTokenBridgeAsset(address expected, address actual);
    error UnauthorizedTokenBridge(address caller);
    error UnauthorizedMessageBridge(address caller);
    error UnauthorizedCrosschainSender();
    error UnexpectedMessageValue(uint256 value);
    error InvalidSourceDomain(uint32 sourceDomain);
    error InvalidMessageKind(uint256 kind);
    error InvalidOperationData();
    error OperationAlreadyExecuted(bytes32 operationId);
    error InvalidShareAmount(uint256 assets, uint256 shares);
    error InsufficientManagedShares(uint256 available, uint256 required);
    error InsufficientNativeGas(uint256 available, uint256 required);
    error NativeTransferFailed();

    event CrosschainDepositExecuted(
        bytes32 indexed operationId, address indexed user, uint256 amount, uint256 shares, bytes32 acknowledgementSendId
    );
    event CrosschainWithdrawalExecuted(
        bytes32 indexed operationId, address indexed user, uint256 shares, uint256 amount, bytes32 returnSendId
    );

    IERC20 public immutable asset;
    IOneToOneVault public immutable vault;
    IERC7786TokenBridge public immutable tokenBridge;
    IERC7786GatewaySource public immutable messageBridge;
    uint32 public immutable outbeDomain;
    address public immutable outbeRouter;

    uint256 public totalManagedShares;
    mapping(bytes32 operationId => Operation operation) public operations;

    constructor(
        address asset_,
        address vault_,
        address tokenBridge_,
        address messageBridge_,
        uint32 outbeDomain_,
        address outbeRouter_,
        address owner_
    ) Ownable(owner_) {
        _requireContract(asset_);
        _requireContract(vault_);
        _requireContract(tokenBridge_);
        _requireContract(messageBridge_);
        if (outbeDomain_ == 0) revert InvalidSourceDomain(0);
        if (outbeRouter_ == address(0)) revert ZeroAddress();

        address vaultAsset = IOneToOneVault(vault_).asset();
        if (vaultAsset != asset_) revert InvalidVaultAsset(asset_, vaultAsset);
        address bridgeAsset = address(IERC7786TokenBridge(tokenBridge_).token());
        if (bridgeAsset != asset_) revert InvalidTokenBridgeAsset(asset_, bridgeAsset);

        asset = IERC20(asset_);
        vault = IOneToOneVault(vault_);
        tokenBridge = IERC7786TokenBridge(tokenBridge_);
        messageBridge = IERC7786GatewaySource(messageBridge_);
        outbeDomain = outbeDomain_;
        outbeRouter = outbeRouter_;

        IERC20(asset_).forceApprove(vault_, type(uint256).max);
    }

    receive() external payable {}

    function expectedOutbeSender() public view returns (bytes memory) {
        return InteroperableAddress.formatEvmV1(outbeDomain, outbeRouter);
    }

    /// @notice Called by the BNB WCOEN token bridge after synthetic WCOEN is minted to this adapter.
    /// @dev A revert rolls back both the mint and the vault deposit, leaving the transport delivery retryable.
    function onCrosschainTokensReceived(
        uint32 sourceDomain,
        bytes calldata from,
        uint256 amount,
        bytes calldata extraData
    ) external nonReentrant returns (bytes4) {
        if (msg.sender != address(tokenBridge)) revert UnauthorizedTokenBridge(msg.sender);
        if (sourceDomain != outbeDomain) revert InvalidSourceDomain(sourceDomain);
        if (keccak256(from) != keccak256(expectedOutbeSender())) revert UnauthorizedCrosschainSender();

        (uint256 kind, bytes32 operationId, address user, uint256 declaredAmount, uint256 acknowledgementGasLimit) =
            abi.decode(extraData, (uint256, bytes32, address, uint256, uint256));
        if (kind != DEPOSIT_REQUEST) revert InvalidMessageKind(kind);
        if (operationId == bytes32(0) || user == address(0) || amount == 0 || declaredAmount != amount) {
            revert InvalidOperationData();
        }
        _recordOperation(operationId, OperationKind.Deposit, user, amount);

        uint256 shares = vault.deposit(amount, address(this));
        if (shares != amount) revert InvalidShareAmount(amount, shares);
        totalManagedShares += shares;

        bytes memory acknowledgement = abi.encode(DEPOSIT_ACKNOWLEDGEMENT, operationId, user, amount);
        bytes memory recipient = InteroperableAddress.formatEvmV1(outbeDomain, outbeRouter);
        bytes[] memory attributes = _gasAttributes(acknowledgementGasLimit);
        uint256 nativeFee = IGatewayQuote(address(messageBridge)).quote(recipient, acknowledgement, attributes);
        _requireNativeGas(nativeFee);
        bytes32 sendId = messageBridge.sendMessage{value: nativeFee}(recipient, acknowledgement, attributes);

        emit CrosschainDepositExecuted(operationId, user, amount, shares, sendId);
        return IERC7786TokenReceiver.onCrosschainTokensReceived.selector;
    }

    /// @notice Receives an authenticated withdrawal request from the Outbe VaultRouter.
    /// @dev Withdrawn BNB WCOEN is burned by the token bridge and returned to Outbe with a completion hook.
    function receiveMessage(bytes32, bytes calldata sender, bytes calldata payload)
        external
        payable
        nonReentrant
        returns (bytes4)
    {
        if (msg.sender != address(messageBridge)) revert UnauthorizedMessageBridge(msg.sender);
        if (msg.value != 0) revert UnexpectedMessageValue(msg.value);
        if (keccak256(sender) != keccak256(expectedOutbeSender())) revert UnauthorizedCrosschainSender();

        (uint256 kind, bytes32 operationId, address user, uint256 amount, uint256 returnGasLimit) =
            abi.decode(payload, (uint256, bytes32, address, uint256, uint256));
        if (kind != WITHDRAW_REQUEST) revert InvalidMessageKind(kind);
        if (operationId == bytes32(0) || user == address(0) || amount == 0) revert InvalidOperationData();
        _recordOperation(operationId, OperationKind.Withdraw, user, amount);

        uint256 available = vault.balanceOf(address(this));
        if (available < amount || totalManagedShares < amount) {
            revert InsufficientManagedShares(available < totalManagedShares ? available : totalManagedShares, amount);
        }

        uint256 burnedShares = vault.withdraw(amount, address(this), address(this));
        if (burnedShares != amount) revert InvalidShareAmount(amount, burnedShares);
        totalManagedShares -= amount;

        bytes memory returnData = abi.encode(WITHDRAW_RETURN, operationId, user, amount);
        uint256 nativeFee = tokenBridge.quoteSend(outbeDomain, outbeRouter, amount, returnData, returnGasLimit);
        _requireNativeGas(nativeFee);

        asset.forceApprove(address(tokenBridge), amount);
        bytes32 sendId =
            tokenBridge.sendAndCall{value: nativeFee}(outbeDomain, outbeRouter, amount, returnData, returnGasLimit);
        asset.forceApprove(address(tokenBridge), 0);

        emit CrosschainWithdrawalExecuted(operationId, user, amount, amount, sendId);
        return IERC7786Recipient.receiveMessage.selector;
    }

    /// @notice Withdraws unused native gas-tank funds. It cannot withdraw WCOEN or vault shares.
    function withdrawNative(address payable receiver, uint256 amount) external onlyOwner nonReentrant {
        if (receiver == address(0)) revert ZeroAddress();
        (bool success,) = receiver.call{value: amount}("");
        if (!success) revert NativeTransferFailed();
    }

    function _recordOperation(bytes32 operationId, OperationKind kind, address user, uint256 amount) private {
        if (operations[operationId].kind != OperationKind.None) revert OperationAlreadyExecuted(operationId);
        operations[operationId] = Operation({kind: kind, user: user, amount: amount});
    }

    function _requireNativeGas(uint256 required) private view {
        if (address(this).balance < required) revert InsufficientNativeGas(address(this).balance, required);
    }

    function _requireContract(address target) private view {
        if (target == address(0)) revert ZeroAddress();
        if (target.code.length == 0) revert InvalidContract(target);
    }

    function _gasAttributes(uint256 gasLimit) private pure returns (bytes[] memory attributes) {
        if (gasLimit == 0) return new bytes[](0);
        attributes = new bytes[](1);
        attributes[0] = abi.encodeWithSelector(bytes4(keccak256("executionGasLimit(uint256)")), gasLimit);
    }
}
