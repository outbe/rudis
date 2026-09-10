// Shared Types
// Type definitions for Hardhat runtime and viem clients.

// =============================================================================
// Task Arguments
// =============================================================================

export type TaskArgValue = string | boolean | undefined;

export interface TaskArgs {
  readonly [key: string]: TaskArgValue;
}

// =============================================================================
// Hardhat Runtime
// =============================================================================

export interface HardhatRuntimeEnvironmentLike {
  readonly network: {
    connect(): Promise<{
      readonly viem: ViemNetworkLike;
    }>;
  };
}

export interface ViemNetworkLike {
  getPublicClient(): Promise<PublicClientLike>;
  getContractAt(contractName: string, address: `0x${string}`): Promise<unknown>;
  getWalletClients(): Promise<readonly WalletClientLike[]>;
}

export interface PublicClientLike {
  getChainId(): Promise<bigint>;
  waitForTransactionReceipt(args: { hash: `0x${string}` }): Promise<void>;
}

export interface WalletClientLike {
  readonly account: {
    readonly address: `0x${string}`;
  };
}

// =============================================================================
// Type Guards
// =============================================================================

export function isHardhatRuntimeEnvironment(
  value: unknown,
): value is HardhatRuntimeEnvironmentLike {
  return (
    typeof value === "object" &&
    value !== null &&
    "network" in value &&
    typeof (value as { network: unknown }).network === "object" &&
    (value as { network: { connect?: unknown } }).network !== null &&
    typeof (value as { network: { connect?: unknown } }).network.connect === "function"
  );
}
