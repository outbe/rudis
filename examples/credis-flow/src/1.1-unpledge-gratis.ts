import { ethers, Wallet } from "ethers";
import { IGratis__factory, IGratisFactory__factory } from "./contracts/index.js";
import {
  DEFAULT_GRATIS_ADDRESS,
  DEFAULT_GRATIS_FACTORY_ADDRESS,
  formatToken,
  formatTokenDiff,
  fetchTokenMeta,
  DEFAULT_ENV,
  loadEnv,
  requireEnv,
} from "./utils.js";
import { deriveGratisKeys, decryptBalance, decryptPledged, modifyMac, GratisOp } from "./confidential.js";
import { deleteTicket, findLatestTicket, readTicket, type Ticket } from "./ticket.js";

// Direct reclaim of an UNSPENT pledge (e.g. the user decided not to take credis).
// Consumes the pledge record and returns the full collateral to the pledger.
//
// CLI: [ticketPath?] [envName?]
let ticketPath: string | undefined;
let envName = DEFAULT_ENV;
for (const a of process.argv.slice(2)) {
  if (a.endsWith(".json")) ticketPath = a;
  else envName = a;
}

const { envPath } = loadEnv(import.meta.url, envName);
const rpcUrl = requireEnv("RPC_URL", envPath);
const userPrivateKey = requireEnv("USER_PRIVATE_KEY", envPath);
const userAddress = requireEnv("USER_ADDRESS", envPath);
const gratisAddress = process.env["GRATIS_ADDRESS"] || DEFAULT_GRATIS_ADDRESS;
const gratisFactoryAddress = process.env["GRATIS_FACTORY_ADDRESS"] || DEFAULT_GRATIS_FACTORY_ADDRESS;

async function main() {
  const found = ticketPath ? { path: ticketPath, ticket: readTicket(ticketPath) } : findLatestTicket();
  if (!found) throw new Error("No pledge ticket found - run `npm run pledge-gratis` first.");
  const ticket: Ticket = found.ticket;

  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const wallet = new Wallet(userPrivateKey, provider);
  const gratis = IGratis__factory.connect(gratisAddress, wallet);
  const gratisFactory = IGratisFactory__factory.connect(gratisFactoryAddress, wallet);

  const gratisMeta = await fetchTokenMeta(gratis);
  // Unpledge is quoted in the same unit the pledge was - the stables figure sealed in
  // the ticket. `ticket.amount` is the gratis collateral that comes back.
  const stablesAmount = BigInt(ticket.stablesAmount);
  const amount = BigInt(ticket.amount);
  const { chainId } = await provider.getNetwork();

  const keys = await deriveGratisKeys(wallet);
  const opNonce = await gratis.opNonceOf(userAddress);
  const balanceBefore = decryptBalance(keys.viewKey, userAddress, await gratis.balanceOf(userAddress));
  const pledgedBefore = decryptPledged(keys.viewKey, userAddress, await gratis.pledgedOf(userAddress));

  console.log("=== Unpledge Gratis (direct reclaim) ===");
  console.log(`Ticket:       ${found.path}`);
  console.log(`Pledge handle:${ticket.pledgeHandle}`);
  console.log(`Amount:       ${formatToken(amount, gratisMeta.decimals, gratisMeta.symbol)}`);
  console.log(`Op-nonce:     ${opNonce}`);
  console.log(`Balance:        ${formatToken(balanceBefore, gratisMeta.decimals, gratisMeta.symbol)}`);
  console.log(`Active pledged: ${formatToken(pledgedBefore, gratisMeta.decimals, gratisMeta.symbol)} (credited only at requestCredis)`);
  console.log(`Pending pledge: ${formatToken(amount, gratisMeta.decimals, gratisMeta.symbol)} (this ticket, being reclaimed)`);

  const mac = modifyMac(keys.modifyKey, userAddress, GratisOp.Unpledge, stablesAmount, opNonce, chainId);

  console.log("\nSending unpledgeGratis(amountStables, handle, mac, opNonce)...");
  const tx = await gratisFactory.unpledgeGratis(stablesAmount, ticket.pledgeHandle, mac, opNonce);
  console.log(`  TX hash: ${tx.hash}`);
  const receipt = await tx.wait();
  if (!receipt) throw new Error("unpledgeGratis tx receipt missing");
  console.log(`  Block:   ${receipt.blockNumber}`);

  const balanceAfter = decryptBalance(keys.viewKey, userAddress, await gratis.balanceOf(userAddress));
  const pledgedAfter = decryptPledged(keys.viewKey, userAddress, await gratis.pledgedOf(userAddress));

  // Unpledge refunds the pending ticket back to the liquid balance and deletes it;
  // the active pledged ledger (`pledgedOf`) was never credited, so it stays flat.
  console.log("\n=== CHANGES (decrypted) ===");
  console.log(`  Balance:         ${formatTokenDiff(balanceAfter - balanceBefore, gratisMeta.decimals, gratisMeta.symbol)}`);
  console.log(`  Active pledged:  ${formatTokenDiff(pledgedAfter - pledgedBefore, gratisMeta.decimals, gratisMeta.symbol)} (unchanged)`);
  console.log(`  Pending pledge:  ${formatTokenDiff(-amount, gratisMeta.decimals, gratisMeta.symbol)}`);

  deleteTicket(found.path);
  console.log(`\nTicket consumed: ${found.path}`);
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
