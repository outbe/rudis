// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.30;

/// @title OrderData
/// @notice Internal order data structure used in the settlement system
struct OrderData {
    bytes32 sender;
    bytes32 recipient;
    bytes32 inputToken;
    bytes32 outputToken;
    uint256 amountIn;
    uint256 amountOut;
    uint256 senderNonce;
    uint32 originDomain;
    uint32 destinationDomain;
    bytes32 destinationSettler;
    uint32 fillDeadline;
    bytes data;
}

/// @title OnchainCrossChainOrder
/// @notice Standard order struct for user-opened orders
struct OnchainCrossChainOrder {
    /// @dev The timestamp by which the order must be filled on the destination chain
    uint32 fillDeadline;
    /// @dev Type identifier for the order data. This is an EIP-712 typehash.
    bytes32 orderDataType;
    /// @dev Arbitrary implementation-specific data
    bytes orderData;
}

/// @title ResolvedCrossChainOrder
/// @notice An implementation-generic representation of an order intended for filler consumption
struct ResolvedCrossChainOrder {
    /// @dev The address of the user who is initiating the transfer
    address user;
    /// @dev The chainId of the origin chain
    uint256 originChainId;
    /// @dev The timestamp by which the order must be filled on the destination chain(s)
    uint32 fillDeadline;
    /// @dev The unique identifier for this order within this settlement system
    bytes32 orderId;
    /// @dev The max outputs that the filler will send
    Output[] maxSpent;
    /// @dev The minimum outputs that must be given to the filler as part of order settlement
    Output[] minReceived;
    /// @dev Each instruction parameterizes a single leg of the fill
    FillInstruction[] fillInstructions;
}

/// @notice Tokens that must be received for a valid order fulfillment
struct Output {
    /// @dev The address of the ERC20 token on the destination chain (address(0) for native token)
    bytes32 token;
    /// @dev The amount of the token to be sent
    uint256 amount;
    /// @dev The address to receive the output tokens
    bytes32 recipient;
    /// @dev The destination chain for this output
    uint256 chainId;
}

/// @title FillInstruction
/// @notice Instructions to parameterize each leg of the fill
struct FillInstruction {
    /// @dev The chain that this instruction is intended to be filled on
    uint256 destinationChainId;
    /// @dev The contract address that the instruction is intended to be filled on
    bytes32 destinationSettler;
    /// @dev The data generated on the origin chain needed by the destinationSettler to process the fill
    bytes originData;
}
