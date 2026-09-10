import { ethers, Provider, JsonRpcProvider } from 'ethers';
import { ERC20__factory, Router__factory } from '../typechain';
import type { Router } from '../typechain';
import { chains, nativeDecimalsByChainId, ROUTER } from '../config';
import * as OrderEncoder from './OrderEncoder';

/**
 * Get decimals for a token (native or ERC20)
 * @param tokenAddress Token address (use 0x0 or ZeroAddress for native token)
 * @param provider Ethers provider for the chain the token lives on
 * @returns Number of decimals
 * @throws If the chain's native decimals are not configured, or `decimals()` fails
 */
export async function getTokenDecimals(
  tokenAddress: string,
  provider: Provider
): Promise<number> {
  // Native decimals are not discoverable over RPC and are not the same on every
  // chain, so they come from the chain config rather than token metadata.
  if (isNativeToken(tokenAddress)) {
    const { chainId } = await provider.getNetwork();
    const decimals = nativeDecimalsByChainId[Number(chainId)];
    if (decimals === undefined) {
      throw new Error(`nativeDecimals not configured for chain ${chainId}`);
    }
    return decimals;
  }

  const token = ERC20__factory.connect(tokenAddress, provider);
  const result = await token.decimals();
  return Number(result);
}

/**
 * Get symbol for a token (native or ERC20)
 * @param tokenAddress Token address (use 0x0 or ZeroAddress for native token)
 * @param provider Ethers provider
 * @returns Token symbol (defaults to 'Native' for native token or 'UNKNOWN' if call fails)
 */
export async function getTokenSymbol(
  tokenAddress: string,
  provider: Provider
): Promise<string> {
  // Native token
  if (isNativeToken(tokenAddress)) {
    return 'Native';
  }

  // Try to get symbol from ERC20 contract
  try {
    const token = ERC20__factory.connect(tokenAddress, provider);
    return await token.symbol();
  } catch {
    return 'UNKNOWN';
  }
}

/**
 * Check if address is a native token address
 * @param tokenAddress Token address to check
 * @returns True if native token
 */
export function isNativeToken(tokenAddress: string): boolean {
  return (
    tokenAddress === ethers.ZeroAddress ||
    tokenAddress === '0x0000000000000000000000000000000000000000' ||
    tokenAddress === '0x0'
  );
}

/**
 * Get provider for a chain by domain ID
 * @param domain Domain ID from order data (e.g., orderData.destinationDomain)
 * @returns JsonRpcProvider for the chain
 */
export function getProviderByDomain(domain: number | bigint): JsonRpcProvider {
  const domainNum = Number(domain);
  const chainEntry = Object.entries(chains).find(
    ([_, chain]) => chain.chainId === domainNum
  );

  if (!chainEntry) {
    console.error('[FAIL] Chain not found for domain:', domainNum);
    console.error('   Available chains:', Object.keys(chains).join(', '));
    process.exit(1);
  }

  const [_, chainConfig] = chainEntry;
  return new JsonRpcProvider(chainConfig.rpc);
}

/**
 * Sleep for a given number of milliseconds
 * @param ms Duration in milliseconds
 */
export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Read order data directly from on-chain storage (openOrders mapping).
 * No event scanning needed - works regardless of block depth.
 *
 * @param orderId The order ID to look up
 * @param router Router contract instance (connected to origin chain)
 * @returns { originData, orderData } - raw bytes and decoded OrderData
 */
export async function getOrderData(
  orderId: string,
  router: Router
): Promise<{ originData: string; orderData: OrderEncoder.OrderData }> {
  const raw = await router.openOrders(orderId);
  if (!raw || raw === '0x') {
    throw new Error(`Order not found: ${orderId}`);
  }

  // openOrders stores abi.encode(bytes32 orderDataType, bytes orderData)
  const [, orderDataBytes] = ethers.AbiCoder.defaultAbiCoder().decode(
    ['bytes32', 'bytes'],
    raw
  );

  return {
    originData: orderDataBytes,
    orderData: OrderEncoder.decode(orderDataBytes),
  };
}
