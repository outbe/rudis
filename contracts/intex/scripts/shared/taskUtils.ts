// Task Utilities
// Helper functions for Hardhat task definitions.

import type { TaskArgs } from "./types.js";

// =============================================================================
// HRE Helpers
// =============================================================================

/** Extract network name from Hardhat v3 globalOptions or NETWORK env var. */
export function getNetworkName(hre: unknown, fallback = ""): string {
  return (hre as { globalOptions?: { network?: string } }).globalOptions?.network
    ?? process.env.NETWORK
    ?? fallback;
}

// =============================================================================
// Lazy Loading
// =============================================================================

/** Wrap task action for lazy loading */
export const lazy =
  <T extends (args: TaskArgs, hre: unknown) => Promise<void>>(fn: T) =>
  async () => ({ default: fn });

// =============================================================================
// Value Parsing
// =============================================================================

/** Convert empty string to undefined */
export function toOptional(value?: string): string | undefined {
  return value ? value : undefined;
}

/** Parse boolean from string/boolean with default */
export function parseBoolean(value?: string | boolean, defaultValue = true): boolean {
  if (typeof value === "boolean") return value;
  if (value === undefined || value === "") return defaultValue;
  return ["true", "1", "yes"].includes(String(value).toLowerCase());
}

/** Parse floor price with default */
export function parseFloor(floor?: string): bigint {
  return floor ? BigInt(floor) : 1080n;
}

// =============================================================================
// BigInt Conversion
// =============================================================================

export type BigIntInput = string | number | bigint | undefined;

/** Convert input to bigint, return undefined for empty/undefined */
export function toOptionalBigInt(input: BigIntInput): bigint | undefined {
  if (input === undefined) return undefined;
  if (typeof input === "bigint") return input;
  if (typeof input === "number") return BigInt(input);
  const trimmed = String(input).trim();
  return trimmed === "" ? undefined : BigInt(trimmed);
}
