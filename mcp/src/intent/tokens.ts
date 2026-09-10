import { type Address, getAddress, zeroAddress } from "viem";

/**
 * Token registry for intent tools. A logical symbol maps to a per-chain token
 * address (addresses are network-specific, so the key is the chain id):
 *
 *   USD  -> configured token (Rudis) / USDT (BSC)
 *   rudis -> native (Rudis) / configured wrudis (BSC)
 *
 * A raw 0x address is always accepted too. Decimals are read on-chain elsewhere.
 */

/** Symbol -> { chainId -> address }. Chain ids match the NETWORKS table. */
const TOKENS: Record<string, Record<number, Address>> = {
  USD: {
    97: getAddress("0x78366397b72D0c283658DA5A38C450455A97e595"), // external USDT
  },
  rudis: {
    70860602: zeroAddress,
  },
};

const TOKEN_ALIASES: Record<string, string> = {
  USDT: "USD",
  USDT0: "USD",
  RUDIS: "rudis",
  WRUDIS: "rudis",
};

/** Operator-confirmed token deployments: symbol -> chain ID -> address. */
function tokenRegistry(): Record<string, Record<number, Address>> {
  const configured = JSON.parse(process.env.OUTBE_INTENT_TOKENS ?? "{}");
  const tokens = Object.fromEntries(Object.entries(TOKENS).map(([symbol, chains]) => [symbol, { ...chains }]));
  for (const [input, chains] of Object.entries(configured)) {
    const symbol = TOKEN_ALIASES[input.toUpperCase()] ?? input.toUpperCase();
    if (!chains || typeof chains !== "object" || Array.isArray(chains)) {
      throw new Error(`OUTBE_INTENT_TOKENS.${input} must map chain IDs to addresses`);
    }
    for (const [chainId, address] of Object.entries(chains)) {
      if (typeof address !== "string") throw new Error(`Invalid token address for ${input}/${chainId}`);
      const value = getAddress(address);
      if (symbol === "rudis" && Number(chainId) === 70860602 && value !== zeroAddress) {
        throw new Error("rudis on Rehearsal Network is the native asset");
      }
      (tokens[symbol] ??= {})[Number(chainId)] = value;
    }
  }
  return tokens;
}

export interface TokenRef {
  address: Address;
  /** logical symbol when resolved from the registry, else the raw address */
  symbol: string;
}

/** Logical symbol for a known token address on a chain, or undefined. */
export function symbolForAddress(addr: Address, chainId: number): string | undefined {
  for (const [sym, perChain] of Object.entries(tokenRegistry())) {
    const a = perChain[chainId];
    if (a !== undefined && getAddress(a) === addr) return sym;
  }
  return undefined;
}

/** Resolve a token spec (symbol or 0x address) to an address on a network. */
export function resolveToken(spec: string, net: { chainId: number; name: string }): TokenRef {
  const s = spec.trim();
  if (/^0x[0-9a-fA-F]{40}$/.test(s)) {
    const address = getAddress(s);
    return { address, symbol: symbolForAddress(address, net.chainId) ?? address };
  }
  const key = TOKEN_ALIASES[s.toUpperCase()] ?? s.toUpperCase();
  const tokens = tokenRegistry();
  const entry = tokens[key];
  if (!entry) {
    const known = [...Object.keys(tokens), ...Object.keys(TOKEN_ALIASES)].join(", ");
    throw new Error(`unknown token "${spec}"; known: ${known}, or a 0x address`);
  }
  const address = entry[net.chainId];
  if (address === undefined) {
    throw new Error(`token ${key} is not available on ${net.name} (chainId ${net.chainId})`);
  }
  return { address, symbol: key };
}
