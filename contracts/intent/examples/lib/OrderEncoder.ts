import { keccak256, toUtf8Bytes, AbiCoder, zeroPadValue } from 'ethers';

/**
 * OrderData structure matching Solidity struct in libs/OrderEncoder.sol
 */
export interface OrderData {
  sender: string;              // bytes32
  recipient: string;           // bytes32
  inputToken: string;          // bytes32
  outputToken: string;         // bytes32
  amountIn: bigint;            // uint256
  amountOut: bigint;           // uint256
  senderNonce: bigint;         // uint256
  originDomain: number;        // uint32
  destinationDomain: number;   // uint32
  destinationSettler: string;  // bytes32
  fillDeadline: number;        // uint32
  data: string;                // bytes
}

/**
 * ORDER_DATA_TYPE constant from OrderEncoder.sol
 */
export const ORDER_DATA_TYPE =
  'OrderData(' +
  'bytes32 sender,' +
  'bytes32 recipient,' +
  'bytes32 inputToken,' +
  'bytes32 outputToken,' +
  'uint256 amountIn,' +
  'uint256 amountOut,' +
  'uint256 senderNonce,' +
  'uint32 originDomain,' +
  'uint32 destinationDomain,' +
  'bytes32 destinationSettler,' +
  'uint32 fillDeadline,' +
  'bytes data)';

/**
 * ORDER_DATA_TYPE_HASH constant from OrderEncoder.sol
 * keccak256(ORDER_DATA_TYPE)
 */
export const ORDER_DATA_TYPE_HASH = keccak256(toUtf8Bytes(ORDER_DATA_TYPE));

/**
 * Returns the OrderData type hash
 * Matches OrderEncoder.orderDataType() in Solidity
 */
export function orderDataType(): string {
  return ORDER_DATA_TYPE_HASH;
}

/**
 * Encodes OrderData to bytes
 * Matches OrderEncoder.encode() in Solidity
 */
export function encode(order: OrderData): string {
  const abiCoder = AbiCoder.defaultAbiCoder();

  return abiCoder.encode(
    ['tuple(bytes32,bytes32,bytes32,bytes32,uint256,uint256,uint256,uint32,uint32,bytes32,uint32,bytes)'],
    [[
      order.sender,
      order.recipient,
      order.inputToken,
      order.outputToken,
      order.amountIn,
      order.amountOut,
      order.senderNonce,
      order.originDomain,
      order.destinationDomain,
      order.destinationSettler,
      order.fillDeadline,
      order.data,
    ]]
  );
}

/**
 * Decodes bytes to OrderData
 * Matches OrderEncoder.decode() in Solidity
 */
export function decode(orderBytes: string): OrderData {
  const abiCoder = AbiCoder.defaultAbiCoder();

  const decoded = abiCoder.decode(
    ['tuple(bytes32,bytes32,bytes32,bytes32,uint256,uint256,uint256,uint32,uint32,bytes32,uint32,bytes)'],
    orderBytes
  )[0];

  return {
    sender: decoded[0],
    recipient: decoded[1],
    inputToken: decoded[2],
    outputToken: decoded[3],
    amountIn: decoded[4],
    amountOut: decoded[5],
    senderNonce: decoded[6],
    originDomain: decoded[7],
    destinationDomain: decoded[8],
    destinationSettler: decoded[9],
    fillDeadline: decoded[10],
    data: decoded[11],
  };
}

/**
 * Calculates the order ID (keccak256 hash of encoded order)
 * Matches OrderEncoder.id() in Solidity
 */
export function id(order: OrderData): string {
  return keccak256(encode(order));
}

/**
 * Helper to create OrderData with address padding
 */
export function createOrderData(params: {
  sender: string;              // address (will be padded to bytes32)
  recipient: string;           // address (will be padded to bytes32)
  inputToken: string;          // address (will be padded to bytes32)
  outputToken: string;         // address (will be padded to bytes32)
  amountIn: bigint;
  amountOut: bigint;
  senderNonce: bigint;
  originDomain: number;
  destinationDomain: number;
  destinationSettler: string;  // address (will be padded to bytes32)
  fillDeadline: number;
  data?: string;
}): OrderData {
  return {
    sender: zeroPadValue(params.sender, 32),
    recipient: zeroPadValue(params.recipient, 32),
    inputToken: zeroPadValue(params.inputToken, 32),
    outputToken: zeroPadValue(params.outputToken, 32),
    amountIn: params.amountIn,
    amountOut: params.amountOut,
    senderNonce: params.senderNonce,
    originDomain: params.originDomain,
    destinationDomain: params.destinationDomain,
    destinationSettler: zeroPadValue(params.destinationSettler, 32),
    fillDeadline: params.fillDeadline,
    data: params.data || '0x',
  };
}