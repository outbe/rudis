import {
  type Address,
  type Hex,
  decodeAbiParameters,
  encodeAbiParameters,
  formatUnits,
  getAddress,
  hexToString,
  keccak256,
  parseAbiParameters,
  stringToBytes,
  zeroAddress,
} from "viem";
import { symbolForAddress } from "./tokens.js";

// OrderData ABI tuple (mirrors libs/OrderEncoder.sol).
export const ORDER_DATA_TUPLE = parseAbiParameters(
  "(bytes32 sender, bytes32 recipient, bytes32 inputToken, bytes32 outputToken, uint256 amountIn, uint256 amountOut, uint256 senderNonce, uint32 originDomain, uint32 destinationDomain, bytes32 destinationSettler, uint32 fillDeadline, bytes data)",
);

// keccak256 of the OrderData type string - matches OrderEncoder.orderDataType().
export const ORDER_DATA_TYPE_HASH = keccak256(
  stringToBytes(
    "OrderData(bytes32 sender,bytes32 recipient,bytes32 inputToken,bytes32 outputToken,uint256 amountIn,uint256 amountOut,uint256 senderNonce,uint32 originDomain,uint32 destinationDomain,bytes32 destinationSettler,uint32 fillDeadline,bytes data)",
  ),
);

/** OrderData record (mirrors libs/OrderEncoder.sol). */
export interface OrderData {
  sender: Hex;
  recipient: Hex;
  inputToken: Hex;
  outputToken: Hex;
  amountIn: bigint;
  amountOut: bigint;
  senderNonce: bigint;
  originDomain: number;
  destinationDomain: number;
  destinationSettler: Hex;
  fillDeadline: number;
  data: Hex;
}

export const isNative = (token: string): boolean => getAddress(token) === zeroAddress;
export const bytes32ToAddress = (b32: Hex): Address => getAddress(`0x${b32.slice(-40)}`);

export function encodeOrderData(o: OrderData): Hex {
  return encodeAbiParameters(ORDER_DATA_TUPLE, [o]);
}
export function decodeOrderData(bytes: Hex): OrderData {
  const [d] = decodeAbiParameters(ORDER_DATA_TUPLE, bytes);
  return d as OrderData;
}
/** Order id = keccak256(abi.encode(OrderData)) - matches OrderEncoder.id(). */
export function computeOrderId(o: OrderData): Hex {
  return keccak256(encodeOrderData(o));
}
/** bytes32 status -> readable label ("OPENED", "", ...). */
export function statusLabel(b32: Hex): string {
  try {
    return hexToString(b32, { size: 32 }).replace(/\0+$/, "").trim();
  } catch {
    return b32;
  }
}

/** Decode addresses + resolve token symbols by their per-domain chain ids. */
export function humanizeOrder(o: OrderData) {
  const inAddr = bytes32ToAddress(o.inputToken);
  const outAddr = bytes32ToAddress(o.outputToken);
  return {
    sender: bytes32ToAddress(o.sender),
    recipient: bytes32ToAddress(o.recipient),
    inputToken: { address: inAddr, symbol: symbolForAddress(inAddr, o.originDomain) ?? null },
    outputToken: { address: outAddr, symbol: symbolForAddress(outAddr, o.destinationDomain) ?? null },
    amountIn: { raw: o.amountIn.toString(), value1e18: formatUnits(o.amountIn, 18) },
    amountOut: { raw: o.amountOut.toString(), value1e18: formatUnits(o.amountOut, 18) },
    senderNonce: o.senderNonce.toString(),
    originDomain: o.originDomain,
    destinationDomain: o.destinationDomain,
    destinationSettler: bytes32ToAddress(o.destinationSettler),
    fillDeadline: { epoch: o.fillDeadline, iso: new Date(Number(o.fillDeadline) * 1000).toISOString() },
  };
}
