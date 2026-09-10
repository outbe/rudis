// Local ticket persistence for the confidential Gratis/Credis demo.
//
// Pledge writes a ticket so requestCredis (and a direct unpledge) know the
// pledge handle + the spend secret; in production a wallet would store the same
// fields. The `tickets/` directory is gitignored so demo secrets never leave the
// developer machine.
//
// The `pledgeSecret` is the bearer secret the user hands to the CCA off-chain:
// the CCA computes `spendAuth(pledgeSecret, smartAccount)` to bind the pledge to
// its smart account at `requestCredis`. It is `HMAC(modifyKey, handle)` - the
// modify key never leaves the user's machine.

import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, unlinkSync, writeFileSync } from "fs";
import { dirname, resolve } from "path";
import { fileURLToPath } from "url";

export interface Ticket {
  pledgeHandle: string; // 0x-prefixed 32-byte hex - the public pledge record id
  pledgeSecret: string; // 0x-prefixed 32-byte hex - HMAC(modifyKey, handle), hand to the CCA
  stablesAmount: string; // credit the pledge was quoted for, in stablecoin minor units
  asset: string; // the stablecoin the credis will be disbursed in
  amount: string; // gratis collateral the quote cost (decimal string)
  opNonce: number; // the account op-nonce used for this pledge
  blockNumber: number;
  txHash: string;
  chainId: string;
  createdAt: string;
  // Filled by `request-credis` so `user-settles` can address the position.
  positionId?: string; // decimal string (uint256)
  smartAccount?: string; // the smart account the pledge was bound to
}

const TICKETS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "../tickets");

function ensureDir() {
  if (!existsSync(TICKETS_DIR)) mkdirSync(TICKETS_DIR, { recursive: true });
}

function ticketName(t: Pick<Ticket, "pledgeHandle">): string {
  const short = t.pledgeHandle.replace(/^0x/, "").slice(0, 12);
  return `pledge-${short}.json`;
}

export function writeTicket(t: Ticket): string {
  ensureDir();
  const path = resolve(TICKETS_DIR, ticketName(t));
  writeFileSync(path, JSON.stringify(t, null, 2) + "\n");
  return path;
}

export function readTicket(path: string): Ticket {
  return JSON.parse(readFileSync(path, "utf-8")) as Ticket;
}

export function deleteTicket(path: string): void {
  if (existsSync(path)) unlinkSync(path);
}

/** All ticket files, newest first. */
export function listTickets(): { path: string; ticket: Ticket }[] {
  if (!existsSync(TICKETS_DIR)) return [];
  return readdirSync(TICKETS_DIR)
    .filter((f) => f.endsWith(".json"))
    .map((f) => resolve(TICKETS_DIR, f))
    .map((path) => ({ path, ticket: readTicket(path), mtime: statSync(path).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime)
    .map(({ path, ticket }) => ({ path, ticket }));
}

/** Most recently modified ticket file, or null if the directory is empty. */
export function findLatestTicket(): { path: string; ticket: Ticket } | null {
  return listTickets()[0] ?? null;
}

export { TICKETS_DIR };
