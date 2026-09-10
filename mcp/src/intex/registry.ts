import { type Abi, type Address, getAddress } from "viem";
import IDesisJson from "../../../contracts/precompiles/abi-export/IDesis.json";
import IIntexJson from "../../../contracts/precompiles/abi-export/IIntex.json";
import IIntexFactoryJson from "../../../contracts/precompiles/abi-export/IIntexFactory.json";
import IVaultRouterJson from "../../../contracts/precompiles/abi-export/IVaultRouter.json";
import EscrowAdapterJson from "../../../contracts/intex/abi-export/EscrowAdapter.json";
import IntexAuctionJson from "../../../contracts/intex/abi-export/IntexAuction.json";
import IIntexNFT1155Json from "../../../contracts/intex/abi-export/IIntexNFT1155.json";
import IIntexNFT1155BridgeJson from "../../../contracts/intex/abi-export/IIntexNFT1155Bridge.json";
import IOriginRouterJson from "../../../contracts/intex/abi-export/IOriginRouter.json";
import IERC20Json from "../../../contracts/tokens/abi-export/IERC20.json";

/** contracts/intex exports as `{ contractName, abi }`; the others as a bare array. */
const abiOf = (json: unknown): Abi =>
  (Array.isArray(json) ? json : (json as { abi: unknown }).abi) as Abi;

/**
 * Addresses + ABIs for the Intex tools (auction commit/reveal, escrow, NFT,
 * series registry, cross-chain bridge, settlement/Promis).
 *
 * Intex is cross-chain: the auction + escrow + NFT run on target chains (BSC
 * today, more later); the series ledger (Intex), settlement
 * (IntexFactory) and Promis live on Rehearsal Network as runtime precompiles.
 * Precompile addresses are fixed; application addresses are supplied by the
 * operator. The ABI JSON is inlined at build time, never read at runtime.
 *
 * ABIs are generated from Solidity (contracts/{intex,precompiles,tokens}), never
 * hand-written - matching the convention in src/registry.ts. Where a method is
 * only on the concrete contract and not its interface, the concrete artifact is
 * used.
 */

export interface NetworkDef {
  name: string;
  chainId: number;
  rpc?: string;
}

/** Supported networks. `rudis-rehearsal` reuses the connected ctx when ids match. */
export const NETWORKS: NetworkDef[] = [
  { name: "bsc-testnet", chainId: 97, rpc: "https://bsc-testnet-rpc.publicnode.com" },
  { name: "rudis-rehearsal", chainId: 70860602, rpc: process.env.OUTBE_RPC },
];

/** Per-network Intex contract addresses. Empty until deployed on that network. */
export interface IntexAddresses {
  auction?: Address;
  escrow?: Address;
  paymentToken?: Address;
  nft?: Address;
  nftBridge?: Address;
  intex?: Address;
  factory?: Address;
  promis?: Address;
  desis?: Address;
  vaultRouter?: Address;
  originRouter?: Address;
}

const a = (s: string): Address => getAddress(s);

const OUTBE = "rudis-rehearsal";

/** Fixed runtime precompiles. Deployed application contracts are operator configuration. */
const OUTBE_ONLY: IntexAddresses = {
  intex: a("0x0000000000000000000000000000000000001014"),
  factory: a("0x0000000000000000000000000000000000001015"),
  promis: a("0x0000000000000000000000000000000000001337"),
  desis: a("0x0000000000000000000000000000000000001016"),
  vaultRouter: a("0x0000000000000000000000000000000000001017"),
};

/**
 * OUTBE_INTEX_ADDRESSES is JSON keyed by network then contract key.
 * Existing deployments are never assumed to be configured for a new chain ID.
 */
export function intexAddress(network: string, key: keyof IntexAddresses): Address {
  const fixed = network === OUTBE ? OUTBE_ONLY[key] : undefined;
  if (fixed) return fixed;
  const deployments = JSON.parse(process.env.OUTBE_INTEX_ADDRESSES ?? "{}");
  const value = deployments[network]?.[key];
  if (typeof value !== "string") {
    throw new Error(`Intex "${key}" is not configured on "${network}"; set OUTBE_INTEX_ADDRESSES`);
  }
  return getAddress(value);
}

/** Destination EVM chain id of each network's bridge counterpart (NFT destination). */
export const BRIDGE_DST_CHAIN_ID: Record<string, number> = {
  "bsc-testnet": 70860602, // -> rudis-rehearsal
  "rudis-rehearsal": 97, // -> bsc-testnet
};

/** Destination chain id for bridging an NFT out of a network, or throw. */
export function bridgeDstChainId(network: string): number {
  const chainId = BRIDGE_DST_CHAIN_ID[network];
  if (chainId === undefined) {
    throw new Error(`Intex bridge destination chain id is not configured on "${network}"`);
  }
  return chainId;
}

// --- ABIs ------------------------------------------------------------------

/** IntexAuction (BSC): commit/reveal + auction views. */
export const AUCTION_ABI: Abi = abiOf(IntexAuctionJson);

/** IntexNFT1155 (BSC + outbe): holder-facing reads. */
export const NFT_ABI: Abi = abiOf(IIntexNFT1155Json);

/** Intex (outbe precompile): canonical cross-chain series ledger. */
export const INTEX_ABI: Abi = abiOf(IIntexJson);

/** IntexNFT1155Bridge: the cross-chain NFT bridge (BSC <-> outbe) over ERC-7786. */
export const NFT_BRIDGE_ABI: Abi = abiOf(IIntexNFT1155BridgeJson);

/** IntexFactory (outbe precompile): holder-facing settlement + Promis mining. */
export const FACTORY_ABI: Abi = abiOf(IIntexFactoryJson);

/** Desis (outbe precompile): auction stage + per-chain bid fan-in views. */
export const DESIS_ABI: Abi = abiOf(IDesisJson);

/** OriginRouter (outbe): the auction's target-chain registry + per-day snapshot. */
export const ORIGIN_ROUTER_ABI: Abi = abiOf(IOriginRouterJson);

/** EscrowAdapter (target chains): bid locks, commit bonds and refunds. */
export const ESCROW_ABI: Abi = abiOf(EscrowAdapterJson);

/** VaultRouter (outbe precompile): the reserve asset registry. */
export const VAULT_ROUTER_ABI: Abi = abiOf(IVaultRouterJson);

/** ERC20 (BSC payment token; outbe Promis balance). */
export const ERC20_ABI: Abi = abiOf(IERC20Json);
