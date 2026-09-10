// Shared chain definitions and RPC helpers (transport-agnostic).
// Chain definitions, chain IDs, and env-driven RPC/key resolution used by the deploy-wiring task.

import { createPublicClient, defineChain, http } from "viem";

// =============================================================================
// Outbe Chain Definitions (hardhat-viem doesn't know chain IDs 424242/512512)
// =============================================================================

export const OUTBE_CHAINS = {
  outbeDevnet: defineChain({
    id: 424242,
    name: "Outbe Dev",
    nativeCurrency: { decimals: 18, name: "rudis", symbol: "rudis" },
    rpcUrls: { default: { http: ["https://eth.d.outbe.net"] } },
  }),
  outbePrivnet: defineChain({
    id: 512512,
    name: "Outbe Priv",
    nativeCurrency: { decimals: 18, name: "rudis", symbol: "rudis" },
    rpcUrls: { default: { http: ["https://eth.p.outbe.net"] } },
  }),
  outbeTestnet: defineChain({
    id: 512215,
    name: "Outbe Testnet",
    nativeCurrency: { decimals: 18, name: "rudis", symbol: "rudis" },
    rpcUrls: { default: { http: ["https://eth.testnet.outbe.net"] } },
  }),
  outbeTestnetNew: defineChain({
    id: 70860602,
    name: "Rehearsal Network",
    nativeCurrency: { decimals: 18, name: "rudis", symbol: "rudis" },
    rpcUrls: { default: { http: process.env.OUTBE_RPC_URL ? [process.env.OUTBE_RPC_URL] : [] } },
  }),
} as const;

export const NETWORK_CHAIN_IDS: Record<string, number> = {
  bscTestnet: 97,
  bsc: 56,
  outbePrivnet: 512512,
  outbeDevnet: 424242,
  outbeTestnet: 512215,
  outbeTestnetNew: 70860602,
};

// =============================================================================
// Environment Helpers
// =============================================================================

export function getEnvRpcAndPk(networkName: string): { rpc: string; pk: string } {
  // Data-driven override: the deploy workflow exports the current target's RPC/key as
  // WIRE_* per targets.json entry, so adding a target needs no per-network case here.
  // Gated on the network name so stray WIRE_* env cannot redirect an unrelated run.
  if (process.env.WIRE_RPC_URL && networkName === process.env.WIRE_NETWORK) {
    return { rpc: process.env.WIRE_RPC_URL, pk: process.env.WIRE_PRIVATE_KEY ?? "" };
  }
  switch (networkName) {
    case "outbeDevnet":
      return { rpc: process.env.OUTBE_RPC_URL ?? "https://eth.d.outbe.net", pk: process.env.OUTBE_PRIVATE_KEY ?? "" };
    case "outbePrivnet":
      return { rpc: process.env.OUTBE_RPC_URL ?? "https://eth.p.outbe.net", pk: process.env.OUTBE_PRIVATE_KEY ?? "" };
    case "outbeTestnet":
      return { rpc: process.env.OUTBE_RPC_URL ?? "https://eth.testnet.outbe.net", pk: process.env.OUTBE_PRIVATE_KEY ?? "" };
    case "outbeTestnetNew":
      if (!process.env.OUTBE_RPC_URL) throw new Error("OUTBE_RPC_URL is required for Rehearsal Network");
      return { rpc: process.env.OUTBE_RPC_URL, pk: process.env.OUTBE_PRIVATE_KEY ?? "" };
    case "bscTestnet":
      return { rpc: process.env.BSC_TESTNET_RPC_URL ?? "https://bsc-testnet.publicnode.com", pk: process.env.BSC_TESTNET_PRIVATE_KEY ?? "" };
    case "bsc":
      return { rpc: process.env.BSC_MAINNET_RPC_URL ?? "https://bsc-dataseed1.binance.org", pk: process.env.BSC_MAINNET_PRIVATE_KEY ?? "" };
    default:
      throw new Error(`Unknown network: ${networkName}`);
  }
}

export function makeChain(networkName: string, rpc?: string) {
  if (networkName in OUTBE_CHAINS) return OUTBE_CHAINS[networkName as keyof typeof OUTBE_CHAINS];
  const chainId = NETWORK_CHAIN_IDS[networkName]
    ?? (networkName === process.env.WIRE_NETWORK ? Number(process.env.WIRE_CHAIN_ID ?? 0) : 0);
  if (!chainId) throw new Error(`Unknown network: ${networkName}`);
  const effectiveRpc = rpc ?? getEnvRpcAndPk(networkName).rpc;
  return defineChain({
    id: chainId,
    name: networkName,
    nativeCurrency: { decimals: 18, name: "ETH", symbol: "ETH" },
    rpcUrls: { default: { http: [effectiveRpc] } },
  });
}

export function makePublicClient(networkName: string) {
  const { rpc } = getEnvRpcAndPk(networkName);
  const chain = makeChain(networkName, rpc);
  return createPublicClient({ chain, transport: http(rpc) });
}
