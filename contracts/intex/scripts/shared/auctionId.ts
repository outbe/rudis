// Worldwide-day utilities
// Functions for working with the auction worldwide day.
//
// Conventions
// - worldwideDay: 8-digit numeric in yyyymmdd format (uint32 on-chain), e.g. 20250924.
//   A plain TypeScript `number` keys every auction; the series id is derived from it.

// =============================================================================
// Parsing
// =============================================================================

/** Parse yyyymmdd format to ISO components */
export function yyyymmddToIso(worldwideDay: string): { y: string; m: string; d: string } {
  if (!/^\d{8}$/.test(worldwideDay)) {
    throw new Error("worldwide day must be yyyymmdd, e.g. 20250924");
  }
  return {
    y: worldwideDay.slice(0, 4),
    m: worldwideDay.slice(4, 6),
    d: worldwideDay.slice(6, 8),
  };
}

// =============================================================================
// Worldwide-day generation
// =============================================================================

/**
 * Normalize a worldwide day to yyyymmdd format.
 * Returns today's date if not provided or invalid.
 */
export function normalizeWorldwideDay(worldwideDay?: string): string {
  if (worldwideDay && /^\d{8}$/.test(worldwideDay)) {
    return worldwideDay;
  }
  const now = new Date();
  const y = String(now.getFullYear());
  const m = String(now.getMonth() + 1).padStart(2, "0");
  const d = String(now.getDate()).padStart(2, "0");
  return `${y}${m}${d}`;
}

/**
 * Parse range string in format "min-max" to tuple.
 * Returns undefined if invalid.
 */
export function parseRange(rangeStr?: string): [number, number] | undefined {
  if (!rangeStr || !rangeStr.includes("-")) return undefined;

  const [min, max] = rangeStr.split("-").map((v) => parseFloat(v.trim()));
  if (isNaN(min) || isNaN(max) || min >= max) {
    throw new Error(`Invalid range: ${rangeStr}`);
  }
  return [min, max];
}

/**
 * Convert a worldwide day (yyyymmdd) to UNIX timestamp at noon UTC.
 */
export function worldwideDayToNoonTimestamp(worldwideDay: string): bigint {
  const { y, m, d } = yyyymmddToIso(worldwideDay);
  const date = new Date(`${y}-${m}-${d}T12:00:00Z`);
  return BigInt(Math.floor(date.getTime() / 1000));
}

/**
 * Convert a worldwide day string (yyyymmdd) to uint32 number.
 * Example: "20260212" -> 20260212
 */
export function worldwideDayToUint32(worldwideDay: string): number {
  if (!/^\d{8}$/.test(worldwideDay)) {
    throw new Error("worldwide day must be yyyymmdd, e.g. 20250924");
  }
  return parseInt(worldwideDay, 10);
}

/**
 * Convert a uint32 worldwide day to string format (yyyymmdd).
 * Example: 20260212 -> "20260212"
 */
export function uint32ToWorldwideDay(worldwideDay: number): string {
  const str = String(worldwideDay).padStart(8, "0");
  if (str.length !== 8) {
    throw new Error("worldwide day must be a valid 8-digit number (yyyymmdd)");
  }
  return str;
}

/**
 * Resolve a uint32 worldwide day from an explicit yyyymmdd string or fall back to today.
 * Throws if an explicit string is malformed.
 */
export function resolveWorldwideDay(worldwideDay?: string): number {
  return worldwideDayToUint32(normalizeWorldwideDay(worldwideDay));
}
