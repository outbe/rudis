import { config } from "dotenv";
import { dirname, resolve } from "path";
import { ethers } from "ethers";
import { fileURLToPath } from "url";

export const DEFAULT_ENV = "local-reth";

export const DEFAULT_GRATIS_ADDRESS = "0x0000000000000000000000000000000000001003";
export const DEFAULT_GRATIS_FACTORY_ADDRESS = "0x0000000000000000000000000000000000002003";
export const DEFAULT_PROMIS_ADDRESS = "0x0000000000000000000000000000000000001337";
export const DEFAULT_PROMIS_FACTORY_ADDRESS = "0x0000000000000000000000000000000000002337";
export const DEFAULT_GEM_ADDRESS = "0x0000000000000000000000000000000000001013";
export const DEFAULT_GEM_FACTORY_ADDRESS = "0x0000000000000000000000000000000000002013";
export const DEFAULT_CREDIS_FACTORY_ADDRESS = "0x0000000000000000000000000000000000001009";
export const DEFAULT_CREDIS_ADDRESS = "0x000000000000000000000000000000000000100A";
export const DEFAULT_FIDELITY_ADDRESS = "0x000000000000000000000000000000000000100C";

// Native COEN uses the standard 18-decimal EVM boundary. Protocol-side Gratis
// accounting remains six-decimal; mineRudis performs that conversion on-chain.
export const COEN_DECIMALS = 18;
export const NATIVE_UNITS_PER_PROTOCOL_UNIT = 1_000_000_000_000n;

/** Six-decimal protocol amount -> native COEN atomic units. */
export function protocolAmountToNativeCoen(value: bigint): bigint {
  return value * NATIVE_UNITS_PER_PROTOCOL_UNIT;
}

/** Whole COEN -> base units. `coen("1.5")` === 1_500_000_000_000_000_000n. */
export function coen(whole: string): bigint {
  return ethers.parseUnits(whole, COEN_DECIMALS);
}

/** Base units -> a human string, without a symbol. */
export function formatCoen(value: bigint): string {
  return ethers.formatUnits(value, COEN_DECIMALS);
}

// ERC-4337 prefund. EntryPoint requires
//   (verificationGasLimit + callGasLimit + preVerificationGas) * maxFeePerGas
// to be on deposit before validation. The UserOps here use [2e6, 2e6] account gas
// limits, 1e6 preVerificationGas and maxFeePerGas = 1, so that floor is 5e6 base
// units. At the fixture's maxFeePerGas = 1 that is 0.000000000005 COEN; this
// constant intentionally follows the raw gas reservation, not a whole-COEN amount.
export const ENTRYPOINT_MIN_DEPOSIT = 5_000_000n;
export const ENTRYPOINT_TOPUP = 20_000_000n;

export interface TokenMeta {
  decimals: number;
  symbol: string;
}

export function formatToken(value: bigint, decimals: number, symbol: string): string {
  return `${ethers.formatUnits(value, decimals)} ${symbol}`;
}

export function formatTokenMeta(value: bigint, meta: TokenMeta): string {
  return formatToken(value, meta.decimals, meta.symbol);
}

export function formatTokenMeta2(value: bigint, meta: TokenMeta): string {
  return `${ethers.formatUnits(value, meta.decimals)}`;
}

export function formatTokenDiff(value: bigint, decimals: number, symbol: string): string {
  return `${value >= 0n ? "+" : ""}${formatToken(value, decimals, symbol)}`;
}

export async function fetchTokenMeta(
  contract: { decimals(): Promise<bigint>; symbol(): Promise<string> },
): Promise<TokenMeta> {
  const [decimalsBig, symbol] = await Promise.all([
    contract.decimals(),
    contract.symbol(),
  ]);
  return { decimals: Number(decimalsBig), symbol };
}

export function loadEnv(importMetaUrl: string, envName: string, opts?: { deploymentEnv?: boolean }): {
  envPath: string;
  deploymentEnvPath?: string;
} {
  const callerFilename = fileURLToPath(importMetaUrl);
  const callerDirname = dirname(callerFilename);
  const envPath = resolve(callerDirname, `../.${envName}.env`);
  config({ path: envPath, override: true });

  let deploymentEnvPath: string | undefined;
  if (opts?.deploymentEnv) {
    deploymentEnvPath = resolve(callerDirname, `../.${envName}.deployment.env`);
    config({ path: deploymentEnvPath, override: true });
    config({ path: envPath, override: true });
  }

  return { envPath, deploymentEnvPath };
}

export function requireEnv(name: string, context?: string): string {
  const val = process.env[name];
  if (!val) throw new Error(`${name} is not set${context ? ` in ${context}` : ""}`);
  return val;
}

// -- Kernel v4 permission-based UserOp helpers -----------------------------
//
// After the Kernel v4 migration every validation on the smart account is a
// permission (the owner is `SudoPolicy + ECDSASigner`, each CCA is
// `WithdrawalLimitPolicy + ECDSASigner`). UserOps therefore use the permission
// nonce type (0x02) and the Kernel v4 `PermissionSignature` = `abi.encode(bytes[])`:
// one slice per policy (empty here - our policies read from calldata, not the
// signature) followed by the signer's ECDSA signature.

/** bytes4 owner permission id = `bytes4(keccak256("credis.owner"))`. */
export function ownerPermissionId(): string {
  return ethers.keccak256(ethers.toUtf8Bytes("credis.owner")).slice(0, 10);
}

/** bytes4 per-token CCA permission id = `bytes4(keccak256(abi.encode("credis.cca", token)))`. */
export function ccaPermissionId(token: string): string {
  return ethers
    .keccak256(ethers.AbiCoder.defaultAbiCoder().encode(["string", "address"], ["credis.cca", token]))
    .slice(0, 10);
}

/**
 * EntryPoint nonce key for a permission validation.
 * Layout (top 24 bytes of userOp.nonce): `[vMode(1)=0x00 | vType(1)=0x02 | vId(20) | parallel(2)=0]`.
 * The permission id (bytes4) occupies the high 4 bytes of the 20-byte vId.
 */
export function permissionNonceKey(permId4: string): bigint {
  const permHex = permId4.replace(/^0x/, "").toLowerCase().padStart(8, "0");
  const vId = permHex + "0".repeat(32); // bytes4 permId + 16 zero bytes = 20 bytes
  return BigInt("0x" + "0002" + vId + "0000");
}

/**
 * Kernel v4 `PermissionSignature` for a permission with a single policy + signer:
 * `abi.encode(bytes[]{ "" (policy slice), ecdsaSig (signer) })`. The ECDSA signature
 * is an eth-signed (EIP-191) signature over the userOpHash, which the ECDSASigner accepts.
 */
export function encodePermissionSignature(ecdsaSig: string): string {
  return ethers.AbiCoder.defaultAbiCoder().encode(["bytes[]"], [["0x", ecdsaSig]]);
}
