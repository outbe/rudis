import { getAddress } from "viem";

export type Market = { base: string; quote: string; baseScale: number; quoteScale: number };
export type PairRow = readonly [string, string, number | bigint, number | bigint];

const cache = new Map<number, Map<string, Market>>();

function key(base: string, quote: string): string {
  return [getAddress(base), getAddress(quote)].sort().join(":");
}

/** Index the registry's rows by market, keeping the orientation each was registered in. */
export function marketMap(rows: readonly PairRow[]): Map<string, Market> {
  const markets = new Map<string, Market>();
  for (const [base, quote, baseScale, quoteScale] of rows) {
    markets.set(key(base, quote), {
      base: getAddress(base),
      quote: getAddress(quote),
      baseScale: Number(baseScale),
      quoteScale: Number(quoteScale),
    });
  }
  return markets;
}

/** Remember what the registry reported, so later reads render in the scale it named. */
export function rememberMarkets(chainId: number, rows: readonly PairRow[]): void {
  cache.set(chainId, marketMap(rows));
}

export function knownMarkets(chainId: number): Map<string, Market> {
  return cache.get(chainId) ?? new Map();
}

/** Decimals a rate is expressed in, for the direction it was asked in. */
export function scaleOf(
  markets: Map<string, Market>,
  base: unknown,
  quote: unknown,
): number | undefined {
  if (typeof base !== "string" || typeof quote !== "string") return undefined;
  try {
    const market = markets.get(key(base, quote));
    if (!market) return undefined;
    return getAddress(quote) === market.quote ? market.quoteScale : market.baseScale;
  } catch {
    return undefined;
  }
}
