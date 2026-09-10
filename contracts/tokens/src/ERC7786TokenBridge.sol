// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuardTransient} from "@openzeppelin/contracts/utils/ReentrancyGuardTransient.sol";
import {IERC7786GatewaySource, IERC7786Recipient} from "@openzeppelin/contracts/interfaces/draft-IERC7786.sol";
import {IERC7802} from "@openzeppelin/contracts/interfaces/draft-IERC7802.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";

import {IStablecoin} from "@precompiles/IStablecoin.sol";

import {IGatewayQuote} from "./interfaces/IGatewayQuote.sol";
import {IERC7786TokenReceiver} from "./interfaces/IERC7786TokenReceiver.sol";

/// @title ERC7786TokenBridge
/// @notice ERC-7786 fungible token bridge supporting lock/unlock, ERC-7802 burn/mint, and
///         issuer-gated mint/burn sides. Composed transfers (`sendAndCall`) additionally invoke an
///         ERC-1363-style receiver hook on the destination after the tokens are credited.
contract ERC7786TokenBridge is Ownable, ReentrancyGuardTransient, IERC7786Recipient {
    using SafeERC20 for IERC20;
    using InteroperableAddress for bytes;

    enum TokenBridgeMode {
        LockUnlock,
        BurnMint,
        IssuerBurnMint
    }

    IERC20 public immutable token;
    IERC7786GatewaySource public immutable bridge;
    TokenBridgeMode public immutable mode;

    mapping(uint32 domain => bytes recipient) public remoteBridges;

    event RemoteBridgeRegistered(uint32 indexed domain, bytes recipient);
    event CrosschainTransferSent(
        bytes32 indexed sendId, uint32 indexed destinationDomain, address indexed from, address to, uint256 amount
    );
    event CrosschainTransferReceived(
        bytes32 indexed receiveId, uint32 indexed sourceDomain, bytes from, address indexed to, uint256 amount
    );
    event EmergencyWithdrawn(address indexed to, uint256 amount);

    error InvalidToken();
    error InvalidBridge();
    error InvalidAmount();
    error InvalidRecipient(address to);
    error EmptyExtraData();
    error InvalidTokenReceiver(address to);
    error RemoteBridgeNotSet(uint32 domain);
    error DomainTooLarge(uint256 chainId);
    error UnauthorizedBridge(address caller);
    error UnauthorizedRemoteBridge(bytes sender);
    error NothingToWithdraw();

    /// @dev `executionGasLimit(uint256)` ERC-7786 attribute understood by the bridge hub's gateways.
    bytes4 private constant GAS_LIMIT_ATTR = bytes4(keccak256("executionGasLimit(uint256)"));

    constructor(address token_, address bridge_, address owner_, TokenBridgeMode mode_) Ownable(owner_) {
        if (token_ == address(0)) revert InvalidToken();
        if (bridge_ == address(0)) revert InvalidBridge();

        token = IERC20(token_);
        bridge = IERC7786GatewaySource(bridge_);
        mode = mode_;
    }

    /// @notice TEMPORARY: recovers everything this bridge holds when a remote chain is down and no delivery can
    ///         release it. Only `LockUnlock` custodies tokens, so only that mode has anything to recover.
    /// @dev TODO: remove before production.
    function emergencyWithdraw() external onlyOwner {
        if (mode != TokenBridgeMode.LockUnlock) revert NothingToWithdraw();

        address to = owner();
        uint256 amount = token.balanceOf(address(this));
        token.safeTransfer(to, amount);
        emit EmergencyWithdrawn(to, amount);
    }

    function setRemoteBridge(uint32 domain, bytes calldata recipient) external onlyOwner {
        remoteBridges[domain] = recipient;
        emit RemoteBridgeRegistered(domain, recipient);
    }

    function quoteSend(uint32 destinationDomain, address to, uint256 amount, bytes calldata extraData, uint256 gasLimit)
        external
        view
        returns (uint256)
    {
        _requireRecipient(to);
        return IGatewayQuote(address(bridge))
            .quote(
                _remoteBridge(destinationDomain),
                _encodePayload(msg.sender, to, amount, extraData),
                _gasAttributes(gasLimit)
            );
    }

    function send(uint32 destinationDomain, address to, uint256 amount) external payable returns (bytes32 sendId) {
        if (amount == 0) revert InvalidAmount();
        _requireRecipient(to);

        _onSend(msg.sender, amount);

        bytes memory payload = _encodePayload(msg.sender, to, amount, "");
        sendId = bridge.sendMessage{value: msg.value}(_remoteBridge(destinationDomain), payload, new bytes[](0));

        emit CrosschainTransferSent(sendId, destinationDomain, msg.sender, to, amount);
    }

    /// @notice Composed transfer: deliver `amount` to `to` and invoke its receiver hook with `extraData`.
    /// @param gasLimit Destination execution gas (0 = gateway default), carried as the
    ///        `executionGasLimit` ERC-7786 attribute to cover the hook.
    function sendAndCall(
        uint32 destinationDomain,
        address to,
        uint256 amount,
        bytes calldata extraData,
        uint256 gasLimit
    ) external payable returns (bytes32 sendId) {
        if (amount == 0) revert InvalidAmount();
        _requireRecipient(to);
        if (extraData.length == 0) revert EmptyExtraData();

        _onSend(msg.sender, amount);

        bytes memory payload = _encodePayload(msg.sender, to, amount, extraData);
        sendId =
            bridge.sendMessage{value: msg.value}(_remoteBridge(destinationDomain), payload, _gasAttributes(gasLimit));

        emit CrosschainTransferSent(sendId, destinationDomain, msg.sender, to, amount);
    }

    function receiveMessage(bytes32 receiveId, bytes calldata sender, bytes calldata payload)
        external
        payable
        nonReentrant
        returns (bytes4)
    {
        if (msg.sender != address(bridge)) revert UnauthorizedBridge(msg.sender);

        (uint256 srcChainId,) = sender.parseEvmV1Calldata();
        if (srcChainId > type(uint32).max) revert DomainTooLarge(srcChainId);

        uint32 sourceDomain = uint32(srcChainId);
        bytes memory expectedSender = _remoteBridge(sourceDomain);
        if (keccak256(sender) != keccak256(expectedSender)) revert UnauthorizedRemoteBridge(sender);

        (bytes memory from, address to, uint256 amount, bytes memory extraData) =
            abi.decode(payload, (bytes, address, uint256, bytes));
        _requireRecipient(to);
        _onReceive(to, amount);

        if (extraData.length > 0) {
            // Composed transfer: tokens are credited before the receiver hook runs; a hook
            // revert rolls back the whole delivery, which the transport then redelivers.
            bytes4 magic = IERC7786TokenReceiver(to).onCrosschainTokensReceived(sourceDomain, from, amount, extraData);
            if (magic != IERC7786TokenReceiver.onCrosschainTokensReceived.selector) revert InvalidTokenReceiver(to);
        }

        emit CrosschainTransferReceived(receiveId, sourceDomain, from, to, amount);
        return IERC7786Recipient.receiveMessage.selector;
    }

    function _remoteBridge(uint32 domain) internal view returns (bytes memory recipient) {
        recipient = remoteBridges[domain];
        if (recipient.length == 0) revert RemoteBridgeNotSet(domain);
    }

    function _requireRecipient(address to) internal pure {
        if (to == address(0)) revert InvalidRecipient(to);
    }

    function _encodePayload(address from, address to, uint256 amount, bytes memory extraData)
        internal
        view
        returns (bytes memory)
    {
        return abi.encode(InteroperableAddress.formatEvmV1(block.chainid, from), to, amount, extraData);
    }

    function _gasAttributes(uint256 gasLimit) internal pure returns (bytes[] memory attrs) {
        if (gasLimit == 0) return new bytes[](0);
        attrs = new bytes[](1);
        attrs[0] = abi.encodeWithSelector(GAS_LIMIT_ATTR, gasLimit);
    }

    function _onSend(address from, uint256 amount) internal {
        if (mode == TokenBridgeMode.LockUnlock) {
            token.safeTransferFrom(from, address(this), amount);
        } else if (mode == TokenBridgeMode.IssuerBurnMint) {
            IStablecoin(address(token)).burnFrom(from, amount);
        } else {
            IERC7802(address(token)).crosschainBurn(from, amount);
        }
    }

    function _onReceive(address to, uint256 amount) internal {
        if (mode == TokenBridgeMode.LockUnlock) {
            token.safeTransfer(to, amount);
        } else if (mode == TokenBridgeMode.IssuerBurnMint) {
            IStablecoin(address(token)).mint(to, amount);
        } else {
            IERC7802(address(token)).crosschainMint(to, amount);
        }
    }
}
