// SPDX-License-Identifier: MIT

pragma solidity ^0.8.30;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {InteroperableAddress} from "@openzeppelin/contracts/utils/draft-InteroperableAddress.sol";
import {IERC7786GatewaySource, IERC7786Recipient, IGatewayQuote} from "../interfaces/IERC7786.sol";
import {GasLimitAttribute} from "../libs/GasLimitAttribute.sol";

/**
 * @dev ERC-7786 gateway adapter for same-chain delivery.
 *
 * When the destination chain is the local chain no external transport is needed: {sendMessage} hands the wrapped
 * package straight back to the hub's {IERC7786Recipient-receiveMessage} in the same transaction, for zero fee.
 * Delivery is bounded by the executionGasLimit attribute and isolated with try/catch, mirroring a real transport:
 * a revert on the receiving side parks the delivery for a permissionless {retryDelivery} instead of rolling back
 * the send.
 *
 * Wiring: the hub registers itself as the remote bridge for the local chain and sets this adapter as the local
 * chain's gateway. Rotating the local gateway strands parked deliveries (the hub stops trusting this adapter), so
 * parked entries must be drained first.
 */
contract LoopbackGatewayAdapter is Ownable, IERC7786GatewaySource, IGatewayQuote {
    using InteroperableAddress for bytes;

    struct ParkedDelivery {
        address target;
        bool done;
        bytes sender;
        bytes payload;
    }

    /// @dev The ERC7786Bridge hub: the only allowed caller and the delivery target of every message.
    address public immutable HUB;

    /// @dev Gas granted to the delivery when the executionGasLimit attribute is absent.
    uint128 public defaultGasLimit;

    /// @dev Failed deliveries awaiting {retryDelivery}.
    mapping(uint256 idx => ParkedDelivery delivery) public parked;
    uint256 public nextParkedIdx;

    /// @dev Distinguishes receive ids of otherwise identical messages (the hub deduplicates on its own nonce).
    uint256 private _nonce;

    event DefaultGasLimitUpdated(uint128 gasLimit);
    event DeliveryParked(uint256 indexed idx, bytes reason);
    event DeliveryRetried(uint256 indexed idx);

    error OnlyHub(address caller);
    error NonZeroValue();
    error NotLocalChain(uint256 chainId);
    error InsufficientForwardGas(uint256 gasLimit);
    error NoParkedDelivery(uint256 idx);
    error AlreadyDelivered(uint256 idx);
    error RecipientExecutionFailed();

    constructor(address hub_, address owner_) Ownable(owner_) {
        HUB = hub_;
        defaultGasLimit = 200_000;
    }

    // =================================================== Config ====================================================

    function setDefaultGasLimit(uint128 gasLimit) public virtual onlyOwner {
        defaultGasLimit = gasLimit;
        emit DefaultGasLimitUpdated(gasLimit);
    }

    // ============================================ IERC7786GatewaySource ============================================

    /// @inheritdoc IERC7786GatewaySource
    function supportsAttribute(bytes4 selector) public pure virtual returns (bool) {
        return selector == GasLimitAttribute.SELECTOR;
    }

    /// @inheritdoc IERC7786GatewaySource
    /// @dev Delivers immediately with the attribute-resolved gas; on a delivery revert the message is parked and the
    /// send still succeeds (failure isolation, like an asynchronous transport).
    function sendMessage(bytes calldata recipient, bytes calldata payload, bytes[] calldata attributes)
        public
        payable
        virtual
        returns (bytes32)
    {
        require(msg.sender == HUB, OnlyHub(msg.sender));
        require(msg.value == 0, NonZeroValue());

        (uint256 chainId, address target) = recipient.parseEvmV1Calldata();
        require(chainId == block.chainid, NotLocalChain(chainId));

        uint128 gasLimit = GasLimitAttribute.resolve(attributes, defaultGasLimit);
        bytes memory sender = InteroperableAddress.formatEvmV1(block.chainid, msg.sender);
        bytes32 receiveId = keccak256(abi.encode(address(this), ++_nonce));

        uint256 gasBefore = gasleft();
        try IERC7786Recipient(target).receiveMessage{gas: gasLimit}(receiveId, sender, payload) returns (bytes4 magic) {
            // The target is the hub, which returns the magic value or reverts; never park a non-reverting call.
            require(magic == IERC7786Recipient.receiveMessage.selector, RecipientExecutionFailed());
        } catch (bytes memory reason) {
            // Park only a delivery that provably received the full gas limit - EIP-150 headroom plus the call's
            // argument encoding, which scales with the payload. An under-gassed send reverts outright so a delivery
            // can never be falsely parked.
            require(
                gasBefore >= uint256(gasLimit) + uint256(gasLimit) / 63 + 5_000 + payload.length / 4,
                InsufficientForwardGas(gasLimit)
            );
            uint256 idx = nextParkedIdx++;
            parked[idx] = ParkedDelivery({target: target, done: false, sender: sender, payload: payload});
            emit DeliveryParked(idx, reason);
        }

        emit MessageSent(bytes32(0), sender, recipient, payload, 0, attributes);
        return bytes32(0);
    }

    // ============================================== IGatewayQuote ==================================================

    /// @inheritdoc IGatewayQuote
    function quote(bytes calldata, bytes calldata) public pure virtual returns (uint256) {
        return 0;
    }

    /// @inheritdoc IGatewayQuote
    function quote(bytes calldata, bytes calldata, bytes[] calldata) public pure virtual returns (uint256) {
        return 0;
    }

    // ================================================== Retry ======================================================

    /// @dev Re-attempts a parked delivery with the transaction's full gas. Permissionless; a revert rolls the whole
    /// call back, leaving the delivery parked and retryable.
    function retryDelivery(uint256 idx) public virtual {
        ParkedDelivery storage delivery = parked[idx];
        require(delivery.target != address(0), NoParkedDelivery(idx));
        require(!delivery.done, AlreadyDelivered(idx));
        delivery.done = true;

        bytes4 magic = IERC7786Recipient(delivery.target)
            .receiveMessage(keccak256(abi.encode(address(this), idx)), delivery.sender, delivery.payload);
        require(magic == IERC7786Recipient.receiveMessage.selector, RecipientExecutionFailed());
        emit DeliveryRetried(idx);
    }
}
