import { type Abi, type Address, getAddress } from "viem";
import { PRECOMPILE_ABI as ABI } from "./abi.js";

/**
 * Precompile registry for outbe-chain.
 *
 * Addresses: crates/blockchain/primitives/src/addresses.rs
 * Dispatch:  crates/blockchain/evm/src/precompiles.rs::outbe_dispatch_fn
 * ABIs:      generated from contracts/precompiles/src/I*.sol - see ./abi.ts.
 *
 * Each entry pairs an address with the whole generated ABI of its interface, so
 * the signatures - and the output parameter names `humanize()` in format.ts
 * keys off - always come from the Solidity, never from a hand-written string.
 */

export interface ContractEntry {
  address: Address;
  abi: Abi;
  /** short human description shown in tool output / errors */
  note: string;
}

const A = (hex: string): Address => getAddress(hex);

export const CONTRACTS: Record<string, ContractEntry> = {
  tribute: {
    address: A("0x0000000000000000000000000000000000001101"),
    note: "Tribute NFT",
    abi: ABI.ITribute,
  },

  tributefactory: {
    address: A("0x0000000000000000000000000000000000001100"),
    note: "TributeFactory (offerTribute, enclave decrypt)",
    abi: ABI.ITributeFactory,
  },

  nod: {
    address: A("0x0000000000000000000000000000000000001006"),
    note: "Nod NFT",
    abi: ABI.INod,
  },

  gratis: {
    address: A("0x0000000000000000000000000000000000001003"),
    note: "Gratis - confidential (TEE-encrypted) balances; balanceOf/pledgedOf return the account's ciphertext blob (decrypt off-chain with the account's view key from rudis_deriveGratisKeys).",
    abi: ABI.IGratis,
  },

  promis: {
    address: A("0x0000000000000000000000000000000000001337"),
    note: "Promis - confidential (TEE-encrypted) balances; balanceOf returns the account's ciphertext blob (decrypt off-chain with the account's view key from rudis_deriveKeys(Promis, ...)). opNonceOf is the modify-auth replay counter a write's mac/opNonce must bind.",
    abi: ABI.IPromis,
  },

  promislimit: {
    address: A("0x000000000000000000000000000000000000100F"),
    note: "Promis limit",
    abi: ABI.IPromisLimit,
  },

  gem: {
    address: A("0x0000000000000000000000000000000000001013"),
    note: "Gem NFT",
    abi: ABI.IGem,
  },

  gemfactory: {
    address: A("0x0000000000000000000000000000000000002013"),
    note: "Gem factory",
    abi: ABI.IGemFactory,
  },

  credis: {
    address: A("0x000000000000000000000000000000000000100A"),
    note: "Credis positions",
    abi: ABI.ICredis,
  },

  agentreward: {
    address: A("0x000000000000000000000000000000000000100B"),
    note: "Agent reward",
    abi: ABI.IAgentReward,
  },

  fidelity: {
    address: A("0x000000000000000000000000000000000000100C"),
    note: "Fidelity RCFI (per-account index is owner-signature-gated; only the public scalars are callable here)",
    abi: ABI.IFidelity,
  },

  metadosis: {
    address: A("0x000000000000000000000000000000000000100E"),
    note: "Metadosis (WorldwideDay lifecycle)",
    abi: ABI.IMetadosis,
  },

  oracle: {
    address: A("0x000000000000000000000000000000000000EE05"),
    note: "Oracle (rates, VWAP, pairs)",
    abi: ABI.IOracle,
  },

  staking: {
    address: A("0x000000000000000000000000000000000000EE02"),
    note: "Staking",
    abi: ABI.IStaking,
  },

  validatorset: {
    address: A("0x000000000000000000000000000000000000EE00"),
    note: "Validator set / epoch",
    abi: ABI.IValidatorSet,
  },

  slashindicator: {
    address: A("0x000000000000000000000000000000000000EE01"),
    note: "Slash indicator",
    abi: ABI.ISlashIndicator,
  },

  zerofee: {
    address: A("0x000000000000000000000000000000000000EE09"),
    note: "ZeroFee paymaster",
    abi: ABI.IZeroFee,
  },

  teeregistry: {
    address: A("0x000000000000000000000000000000000000EE0A"),
    note: "TEE registry (offer key)",
    abi: ABI.ITeeRegistryV1,
  },

  governance: {
    address: A("0x0000000000000000000000000000000000001018"),
    note: "Governance (canon, meta-canon, OIP, GIP)",
    abi: ABI.IGovernance,
  },

  paynote: {
    address: A("0x0000000000000000000000000000000000001019"),
    note: "PayNote shielded ERC20 note pool (deposit + tree queries; spending is a Rust-only API)",
    abi: ABI.IPayNote,
  },
};

/** Resolve a contract by registry name or raw 0x address. */
export function resolveContract(nameOrAddr: string): ContractEntry {
  const key = nameOrAddr.toLowerCase();
  if (CONTRACTS[key]) return CONTRACTS[key];
  if (/^0x[0-9a-fA-F]{40}$/.test(nameOrAddr)) {
    const addr = getAddress(nameOrAddr);
    for (const entry of Object.values(CONTRACTS)) {
      if (entry.address === addr) return entry;
    }
    throw new Error(
      `address ${addr} is not a known precompile; use a contract name (${Object.keys(
        CONTRACTS,
      ).join(", ")})`,
    );
  }
  throw new Error(
    `unknown contract "${nameOrAddr}"; known: ${Object.keys(CONTRACTS).join(", ")}`,
  );
}

// --- Enum / code maps (crates/core/metadosis/src/schema.rs) ------------------
export const WWD_STATUS = [
  "FORMING",
  "LOOKBACK_DELAY",
  "OFFERING",
  "WAITING",
  "READY",
  "IN_PROGRESS",
  "COMPLETED",
  "FAILED",
] as const;

export const DAY_TYPE = ["UNKNOWN", "GREEN", "RED"] as const;

// Governance proposal status (crates/core/governance/src/status.rs).
export const PROPOSAL_STATUS = [
  "Draft",
  "Approved",
  "Rejected",
  "Rework",
  "Implemented",
] as const;

export type ProposalStatusName = (typeof PROPOSAL_STATUS)[number];

export function proposalStatusName(v: number): string {
  return PROPOSAL_STATUS[v] ?? `UNKNOWN(${v})`;
}

/** Status name -> on-chain `uint8` code accepted by `get{Oip,Gip}sByStatus`. */
export function proposalStatusCode(name: ProposalStatusName): number {
  return PROPOSAL_STATUS.indexOf(name);
}

// Gem lifecycle state (crates/core/gem/src/schema.rs::GemState).
export const GEM_STATE = ["Issued", "Qualified", "Called", "Settled"] as const;

// ISO 4217 numeric -> symbol. Chain currently accepts 840 (USD) only; the rest
// are convenience labels for display.
export const ISO_4217: Record<number, string> = {
  840: "USD",
  978: "EUR",
  826: "GBP",
  392: "JPY",
  756: "CHF",
  156: "CNY",
};

export function statusName(v: number): string {
  return WWD_STATUS[v] ?? `UNKNOWN(${v})`;
}
export function dayTypeName(v: number): string {
  return DAY_TYPE[v] ?? `UNKNOWN(${v})`;
}
export function gemStateName(v: number): string {
  return GEM_STATE[v] ?? `UNKNOWN(${v})`;
}
export function currencyLabel(code: number): { code: number; symbol: string } {
  return { code, symbol: ISO_4217[code] ?? `#${code}` };
}
