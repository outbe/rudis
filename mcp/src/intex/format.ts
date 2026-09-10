/**
 * Decoders for Intex enum codes into human-readable names, plus small shaping
 * helpers for tool output. Enum orderings are verbatim from the contracts:
 *  - AuctionStage ... contracts/intex/src/target/interfaces/IIntexAuction.sol
 *  - IntexState / IntexStatus ... contracts/intex/src/shared/interfaces/IIntexNFT1155.sol
 *  - Desis AuctionStage / escrow LockStatus ... IDesis.sol / IEscrowAdapter.sol
 */

import { type Hex, hexToString, stringToHex } from "viem";

const AUCTION_STAGE = ["CommittingBids", "RevealingBids", "Issuance", "Completed", "Cancelled"];
const INTEX_STATE = ["Issued", "Qualified", "Called", "Expired"];
const INTEX_STATUS = ["Issued", "Settled"];
const DESIS_STAGE = ["None", "Briefed", "Started", "Revealing", "Clearing", "Cleared", "Cancelled"];
const LOCK_STATUS = ["None", "Locked", "Finalized"];

function label(table: string[], code: number | bigint): { code: number; name: string } {
  const c = Number(code);
  return { code: c, name: table[c] ?? `unknown(${c})` };
}

// Short clarifications for non-obvious auction stages. The name stays exactly as
// the contract enum; the note only explains it.
const AUCTION_STAGE_NOTE: Record<number, string> = {
  2: "reveal window ended, awaiting clearing", // Issuance
};

export const auctionStage = (code: number | bigint) => {
  const base = label(AUCTION_STAGE, code);
  const note = AUCTION_STAGE_NOTE[base.code];
  return note ? { ...base, note } : base;
};
export const intexState = (code: number | bigint) => label(INTEX_STATE, code);
export const intexStatus = (code: number | bigint) => label(INTEX_STATUS, code);
export const desisStage = (code: number | bigint) => label(DESIS_STAGE, code);
export const lockStatus = (code: number | bigint) => label(LOCK_STATUS, code);

/** Auction stages a participant can still act in (commit or reveal). */
export function isActiveStage(code: number | bigint): boolean {
  const c = Number(code);
  return c === 0 || c === 1; // CommittingBids | RevealingBids
}

/** A unix-seconds u32 as { epoch, iso }, or null when zero/unset. */
export function epochIso(v: number | bigint): { epoch: number; iso: string } | null {
  const sec = Number(v);
  if (!Number.isFinite(sec) || sec <= 0) return null;
  return { epoch: sec, iso: new Date(sec * 1000).toISOString() };
}

/** Series ids are the 14 ASCII bytes of `20260212-TRY-U`. */
export function toSeriesId(value: string): Hex {
  const id = value.trim().toUpperCase();
  if (!/^\d{8}-[A-Z0-9]{3}-[A-Z0-9]$/.test(id)) {
    throw new Error(`series id ${value} must look like 20260212-TRY-U`);
  }
  return stringToHex(id) as Hex;
}

export const fromSeriesId = (id: Hex) => hexToString(id);
