import {
  type AbiFunction,
  type AbiParameter,
  formatUnits,
  getAddress,
  zeroAddress,
} from "viem";
import {
  currencyLabel,
  dayTypeName,
  gemStateName,
  proposalStatusName,
  statusName,
} from "./registry.js";

/**
 * Turn viem-decoded contract return values into human-readable JSON, driven by
 * the ABI output parameter names (registry.ts keeps them verbatim).
 *
 * Formatting sources:
 *  - WorldwideDay u32 YYYYMMDD .......... crates/core/common/src/worldwideday.rs
 *  - native COEN amounts at 1e18 ........ explicit contract/function boundaries
 *  - protocol monetary amounts at 1e6 ... crates/blockchain/primitives/src/units.rs
 *  - Credis annual currency rate at 1e6 . Oracle/Credis contract
 *  - generic prices/ratios at 1e18 ...... their owning protocol modules
 *  - status / day_type enums ............ crates/core/metadosis/src/schema.rs
 */

const DATE_RE = /(worldwideday|^wwd$|^wwds$|^date$|^day$)/i;
const SIX_DECIMAL_AMOUNT_RE = /(minor$|amount|stake|balance|pledged|reward)/i;
const SIX_DECIMAL_RATE_RE = /currencyrate/i;
const DIMENSIONLESS_FP18_RE = /(rewardband|minvalidperwindow|slashfraction)/i;
const GENERIC_FP18_RE = /(vwap|twap|rate|price|volume|peakprice|currentvalue|nominalprice|maxscurve)/i;
/// Gem prices and loads are six-decimal like every other Gem amount. Scoped to
/// Gem's own structs: the same field names on other instruments are 1e18.
const GEM_SIX_DECIMAL_RE =
  /^(entryPrice|floorPrice|callPrice|sourceEntryPrice|sourceFloorPrice|promisLoad|remainingCapacity)$/;
const GEM_STRUCT_RE = /^struct IGem(Factory)?\./;
const TIME_RE = /(at$|time$|timestamp$|start$|end$|date$|duedate$|paidat$)/i;

function isIsoCurrencyAddress(value: unknown): boolean {
  if (typeof value !== "string") return false;
  try {
    const raw = BigInt(getAddress(value));
    if (raw < 0xcc000n || raw > 0xcc999n) return false;
    const packed = Number(raw - 0xcc000n);
    return [0, 4, 8].every((shift) => ((packed >> shift) & 0xf) <= 9);
  } catch {
    return false;
  }
}

/** Decimal scale override for a stablecoin-backed COEN/ISO Oracle market. */
function coenIsoMarketDecimals(base: unknown, quote: unknown): 6 | undefined {
  const isCoen = (value: unknown) => {
    if (typeof value !== "string") return false;
    try {
      return getAddress(value) === zeroAddress;
    } catch {
      return false;
    }
  };
  return (isCoen(base) && isIsoCurrencyAddress(quote)) ||
    (isIsoCurrencyAddress(base) && isCoen(quote))
    ? 6
    : undefined;
}

type DecimalScale = number | (number | undefined)[];

export interface ReturnFormatContext {
  /** Canonical registry key of the precompile whose result is being formatted. */
  contractName?: string;
  /** Raw ABI arguments for a call resolved to the Oracle precompile. */
  oracleArgs?: readonly unknown[];
  /** The registry's own answer for a market; the local rule is the fallback. */
  scaleFor?: (base: unknown, quote: unknown) => number | undefined;
}

function oraclePresentationScale(
  fn: AbiFunction,
  result: unknown,
  context: ReturnFormatContext | undefined,
): DecimalScale | undefined {
  if (!context) return undefined;

  if (fn.name === "getRudisExchangeRateFor" || fn.name === "getPolicyRate") {
    return 6;
  }

  const scaleFor = (base: unknown, quote: unknown) =>
    context.scaleFor?.(base, quote) ?? coenIsoMarketDecimals(base, quote);

  const inputs = fn.inputs ?? [];
  if (inputs[0]?.name === "base" && inputs[1]?.name === "quote") {
    return scaleFor(context.oracleArgs?.[0], context.oracleArgs?.[1]);
  }

  const outputs = fn.outputs ?? [];
  const basesIndex = outputs.findIndex((output) => output.name === "bases");
  const quotesIndex = outputs.findIndex((output) => output.name === "quotes");
  if (basesIndex < 0 || quotesIndex < 0 || !Array.isArray(result)) return undefined;

  const bases = result[basesIndex];
  const quotes = result[quotesIndex];
  if (!Array.isArray(bases) || !Array.isArray(quotes) || bases.length !== quotes.length) {
    return undefined;
  }
  return bases.map((base, index) => scaleFor(base, quotes[index]));
}

function formatWwd(v: number): string {
  const y = Math.floor(v / 10_000);
  const m = Math.floor((v / 100) % 100);
  const d = v % 100;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${y}-${pad(m)}-${pad(d)}`;
}

function toIso(epoch: bigint | number): string {
  const sec = Number(epoch);
  if (!Number.isFinite(sec) || sec <= 0) return "n/a";
  return new Date(sec * 1000).toISOString();
}

function parseDataUri(s: string): unknown {
  const marker = "data:application/json";
  if (!s.startsWith(marker)) return s;
  const comma = s.indexOf(",");
  if (comma < 0) return s;
  const meta = s.slice(0, comma);
  let payload = s.slice(comma + 1);
  try {
    if (meta.includes(";base64")) {
      payload = Buffer.from(payload, "base64").toString("utf8");
    }
    return JSON.parse(payload);
  } catch {
    return s;
  }
}

function isUint(type: string, bits?: number): boolean {
  if (bits) return type === `uint${bits}`;
  return type.startsWith("uint");
}

/**
 * Format a single (non-array, non-tuple) scalar value by name + type.
 *
 * `enclosingTupleType` is the enclosing tuple's `internalType` (e.g. `struct
 * IGovernance.Proposal`) when there is one. A bare `status` byte means the
 * WorldwideDay lifecycle everywhere except inside a governance proposal, which
 * uses its own enum - so the enclosing struct disambiguates them.
 */
interface ScalarFormatContext {
  contractName?: string;
  functionName?: string;
  enclosingTupleType?: string;
  marketDecimals?: number;
}

function isNativeCoenAmount(name: string, context: ScalarFormatContext): boolean {
  const contract = context.contractName;
  const fn = context.functionName;
  if (contract === "staking" && (fn === "getStake" || fn === "getTotalStaked")) return true;
  // `claimReward` is not here: it returns a Gem id, not an amount.
  if (
    contract === "agentreward" &&
    (fn === "getClaimableBalance" || fn === "getPoolClaimableBalance")
  ) {
    return true;
  }
  return (
    contract === "validatorset" &&
    (fn === "validatorByAddress" || fn === "validatorByIndex") &&
    name === "stake"
  );
}

function formatScalar(
  name: string,
  type: string,
  value: unknown,
  context: ScalarFormatContext = {},
): unknown {
  const n = name ?? "";

  if (isUint(type, 32) && DATE_RE.test(n)) {
    const v = Number(value);
    return { wwd: v, date: formatWwd(v) };
  }
  if (isUint(type, 8) && n === "status") {
    const v = Number(value);
    const inProposal =
      context.enclosingTupleType !== undefined &&
      /\bIGovernance\./.test(context.enclosingTupleType);
    return { code: v, name: inProposal ? proposalStatusName(v) : statusName(v) };
  }
  if (isUint(type, 8) && n === "dayType") {
    const v = Number(value);
    return { code: v, name: dayTypeName(v) };
  }
  if (isUint(type, 8) && n === "state") {
    const v = Number(value);
    return { code: v, name: gemStateName(v) };
  }
  if (isUint(type, 16) && /currency/i.test(n)) {
    return currencyLabel(Number(value));
  }
  if (type === "uint256" && DIMENSIONLESS_FP18_RE.test(n)) {
    const v = value as bigint;
    return { raw: v.toString(), value: formatUnits(v, 18) };
  }
  if (type === "uint256" && isNativeCoenAmount(n, context)) {
    const v = value as bigint;
    return { raw: v.toString(), value: formatUnits(v, 18) };
  }
  if (
    type === "uint256" &&
    (SIX_DECIMAL_RATE_RE.test(n) || context.functionName === "getPolicyRate")
  ) {
    const v = value as bigint;
    return { raw: v.toString(), value: formatUnits(v, 6) };
  }
  if (type === "uint256" && SIX_DECIMAL_AMOUNT_RE.test(n)) {
    const v = value as bigint;
    return { raw: v.toString(), value: formatUnits(v, 6) };
  }
  if (
    type === "uint256" &&
    GEM_SIX_DECIMAL_RE.test(n) &&
    GEM_STRUCT_RE.test(context.enclosingTupleType ?? "")
  ) {
    const v = value as bigint;
    return { raw: v.toString(), value: formatUnits(v, 6) };
  }
  if (type === "uint256" && GENERIC_FP18_RE.test(n)) {
    const v = value as bigint;
    return {
      raw: v.toString(),
      value: formatUnits(v, context.marketDecimals ?? 18),
    };
  }
  if (isUint(type, 64) && TIME_RE.test(n) && !/height$|block$/i.test(n)) {
    return { epoch: Number(value), iso: toIso(value as bigint) };
  }
  if (type === "string" && typeof value === "string") {
    return parseDataUri(value);
  }
  if (typeof value === "bigint") return value.toString();
  return value;
}

interface ParamFormatContext {
  contractName?: string;
  functionName?: string;
  enclosingTupleType?: string;
  marketDecimals?: DecimalScale;
}

/** Recursively format a value against its ABI parameter metadata. */
export function formatParam(
  param: AbiParameter,
  value: unknown,
  context: ParamFormatContext = {},
): unknown {
  const { type } = param;

  if (type.endsWith("[]")) {
    const base = { ...param, type: type.slice(0, -2) } as AbiParameter;
    return Array.isArray(value)
      ? value.map((v, index) =>
          formatParam(
            base,
            v,
            {
              ...context,
              marketDecimals: Array.isArray(context.marketDecimals)
                ? context.marketDecimals[index]
                : context.marketDecimals,
            },
          ),
        )
      : value;
  }

  if (type === "tuple" && "components" in param && param.components) {
    const enclosingTupleType =
      "internalType" in param && typeof param.internalType === "string"
        ? param.internalType
        : context.enclosingTupleType;
    const out: Record<string, unknown> = {};
    param.components.forEach((c, i) => {
      const sub =
        value && typeof value === "object" && c.name && c.name in (value as object)
          ? (value as Record<string, unknown>)[c.name]
          : (value as unknown[])[i];
      out[c.name || String(i)] = formatParam(
        c,
        sub,
        {
          ...context,
          enclosingTupleType,
          marketDecimals: Array.isArray(context.marketDecimals)
            ? undefined
            : context.marketDecimals,
        },
      );
    });
    return out;
  }

  return formatScalar(param.name ?? "", type, value, {
    contractName: context.contractName,
    functionName: context.functionName,
    enclosingTupleType: context.enclosingTupleType,
    marketDecimals: Array.isArray(context.marketDecimals)
      ? undefined
      : context.marketDecimals,
  });
}

/**
 * Humanize a decoded function result. `result` is what viem returns from
 * `readContract`/`decodeFunctionResult`: a scalar for a single output, an array
 * for multiple outputs.
 */
export function humanizeReturn(
  fn: AbiFunction,
  result: unknown,
  context?: ReturnFormatContext,
): unknown {
  const outputs = fn.outputs ?? [];
  const marketDecimals = oraclePresentationScale(fn, result, context);
  if (outputs.length === 0) return null;
  if (outputs.length === 1) {
    const p = outputs[0];
    const formatted = formatParam(p, result, {
      contractName: context?.contractName,
      functionName: fn.name,
      marketDecimals,
    });
    return p.name ? { [p.name]: formatted } : formatted;
  }
  const arr = result as unknown[];
  const out: Record<string, unknown> = {};
  outputs.forEach((p, i) => {
    out[p.name || String(i)] = formatParam(p, arr[i], {
      contractName: context?.contractName,
      functionName: fn.name,
      marketDecimals,
    });
  });
  return out;
}

/** JSON.stringify replacer that renders bigint as a decimal string. */
export function bigintReplacer(_key: string, value: unknown): unknown {
  return typeof value === "bigint" ? value.toString() : value;
}

/** Stringify any value for MCP text content, bigint-safe and pretty. */
export function toJson(value: unknown): string {
  return JSON.stringify(value, bigintReplacer, 2);
}
