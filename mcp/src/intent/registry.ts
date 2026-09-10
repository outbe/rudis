import { type Abi, type Address, getAddress } from "viem";
import RouterJson from "../../../contracts/intent/abi-export/Router.json";
import IERC20Json from "../../../contracts/tokens/abi-export/IERC20.json";

/**
 * ABI + constants for the intent (ERC-7683 LayerZeroRouter) tools.
 *
 * ABIs are generated, not hand-written - see `src/abi.ts`. Source of truth:
 *  - contracts/intent/src/router/... via contracts/intent/abi-export/Router.json
 *  - contracts/tokens/src/interfaces/IERC20.sol
 */

/** Same-address router deployment on both chains, explicitly supplied by the operator. */
export function intentRouter(): Address {
  const value = process.env.OUTBE_INTENT_ROUTER;
  if (!value) throw new Error("Set OUTBE_INTENT_ROUTER to the deployed Rudis intent router");
  return getAddress(value);
}
export const DEFAULT_FILL_DEADLINE_SECONDS = 120; // 120s

/**
 * Supported networks besides `outbe` (always the connected ctx). Resolved by
 * name or chain id - no RPC URLs, no aliases; the model normalizes natural
 * language ("bsc" typed in Cyrillic, "BSC testnet") to `bsc`. Add a row to support another chain.
 */
export interface NetworkDef {
  name: string;
  chainId: number;
  rpc?: string;
}

export const NETWORKS: NetworkDef[] = [
  { name: "bsc-testnet", chainId: 97, rpc: "https://bsc-testnet-rpc.publicnode.com" },
  { name: "rudis-rehearsal", chainId: 70860602, rpc: process.env.OUTBE_RPC },
];

export const ROUTER_ABI: Abi = RouterJson as Abi;

export const ERC20_ABI: Abi = IERC20Json as Abi;
