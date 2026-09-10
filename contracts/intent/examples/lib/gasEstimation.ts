/**
 * Gas estimation utilities
 */

import { ethers } from 'ethers';
import type { Router } from '../typechain';

/**
 * Estimates gas for a contract call and adds a buffer
 * @param estimateGasFn - Function that estimates gas (e.g., contract.method.estimateGas)
 * @param bufferPercent - Buffer percentage to add (default: 20%)
 * @returns Gas limit with buffer applied
 */
export async function estimateGasWithBuffer(
  estimateGasFn: () => Promise<bigint>,
  bufferPercent: number = 20
): Promise<bigint> {
  try {
    const estimatedGas = await estimateGasFn();
    console.log(`  Estimated gas: ${estimatedGas.toString()}`);

    // Add buffer to estimated gas
    const gasLimit = (estimatedGas * BigInt(100 + bufferPercent)) / 100n;
    console.log(`  Gas limit: ${gasLimit.toString()}`);

    return gasLimit;
  } catch (error: any) {
    console.error('  [FAIL] Gas estimation failed:', error.message);
    if (error.data) {
      console.error('  Error data:', error.data);
    }
    throw error;
  }
}

/**
 * Calculates LayerZero messaging fee for refund operation
 * @param router - Router contract instance
 * @param originChainId - Origin chain domain ID
 * @param orderIds - Array of order IDs to refund
 * @returns native messaging fee in wei
 */
export async function calculateRefundFee(
  router: Router,
  originChainId: number,
  orderIds: string[]
): Promise<bigint> {
  // Create payload for quote (same as RouterMessage.encodeRefund)
  const payload = ethers.AbiCoder.defaultAbiCoder().encode(
    ['bool', 'bytes32[]', 'bytes[]'],
    [false, orderIds, []]
  );

  // Bridge messaging fee, native (wei)
  return await router.quote(originChainId, payload);
}

/**
 * Calculates LayerZero messaging fee for settle operation
 * @param router - Router contract instance
 * @param originChainId - Origin chain domain ID
 * @param orderIds - Array of order IDs to settle
 * @param ordersFillerData - Array of filler data for each order
 * @returns native messaging fee in wei
 */
export async function calculateSettleFee(
  router: Router,
  originChainId: number,
  orderIds: string[],
  ordersFillerData: string[]
): Promise<bigint> {
  // Create payload for quote (same as RouterMessage.encodeSettle)
  const payload = ethers.AbiCoder.defaultAbiCoder().encode(
    ['bool', 'bytes32[]', 'bytes[]'],
    [true, orderIds, ordersFillerData]
  );

  // Bridge messaging fee, native (wei)
  return await router.quote(originChainId, payload);
}
