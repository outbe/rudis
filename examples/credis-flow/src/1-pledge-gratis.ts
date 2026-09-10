import { ethers, Wallet } from "ethers";
import { IGratis__factory, IGratisFactory__factory, IERC20__factory } from "./contracts/index.js";
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
import {
  deriveGratisKeys,
  decryptBalance,
  decryptPledged,
  modifyMac,
  pledgeSecret,
  GratisOp,
} from "./confidential.js";
import { writeTicket } from "./ticket.js";

// The user names the CREDIT they want, not the collateral: `pledgeGratis` converts
// `amountStables` of `asset` into the gratis it costs at the current oracle rate and
// seals both into the pledge ticket, so `requestCredis` disburses exactly this amount
// without re-pricing.
//
// CLI: [amountStables] [envName]. Defaults to "1" unit of the stablecoin.
const amountArg = process.argv[2] || "1";
const envName = process.argv[3] || DEFAULT_ENV;

const { envPath } = loadEnv(import.meta.url, envName);

const rpcUrl = requireEnv("RPC_URL", envPath);
const userPrivateKey = requireEnv("USER_PRIVATE_KEY", envPath);
const userAddress = requireEnv("USER_ADDRESS", envPath);
const erc20Address = requireEnv("ERC20_ADDRESS", envPath);
const gratisAddress = process.env["GRATIS_ADDRESS"] || DEFAULT_GRATIS_ADDRESS;
const gratisFactoryAddress = process.env["GRATIS_FACTORY_ADDRESS"] || DEFAULT_GRATIS_FACTORY_ADDRESS;

async function main() {
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const wallet = new Wallet(userPrivateKey, provider);
  const gratis = IGratis__factory.connect(gratisAddress, wallet);
  const gratisFactory = IGratisFactory__factory.connect(gratisFactoryAddress, wallet);
  const asset = IERC20__factory.connect(erc20Address, provider);

  const [gratisMeta, assetMeta] = await Promise.all([fetchTokenMeta(gratis), fetchTokenMeta(asset)]);
  const amountStables = ethers.parseUnits(amountArg, assetMeta.decimals);
  const { chainId } = await provider.getNetwork();

  // Fetch the user's enclave-derived confidential keys (view + modify) so we can
  // read the encrypted balance and authorize the write. Signs an ownership proof.
  const keys = await deriveGratisKeys(wallet);

  const opNonce = await gratis.opNonceOf(userAddress);
  const balanceBefore = decryptBalance(keys.viewKey, userAddress, await gratis.balanceOf(userAddress));
  const pledgedBefore = decryptPledged(keys.viewKey, userAddress, await gratis.pledgedOf(userAddress));

  // The gratis cost is unknown until the chain applies the oracle rate, so cap it at
  // the whole balance: the pledge cannot cost more than the user holds anyway, and a
  // rate move that makes the credit unaffordable reverts instead of draining extra.
  const maxGratis = balanceBefore;

  console.log("=== Pledge Gratis (confidential / TEE) ===");
  console.log(`Env:        ${envName} (${envPath})`);
  console.log(`RPC:        ${rpcUrl}`);
  console.log(`User:       ${userAddress}`);
  console.log(`Gratis:     ${gratisAddress} (${gratisMeta.symbol})`);
  console.log(`Factory:    ${gratisFactoryAddress}`);
  console.log(`Credit:     ${formatToken(amountStables, assetMeta.decimals, assetMeta.symbol)}`);
  console.log(`Asset:      ${erc20Address}`);
  console.log(`Max gratis: ${formatToken(maxGratis, gratisMeta.decimals, gratisMeta.symbol)}`);
  console.log(`Op-nonce:   ${opNonce}`);

  console.log("\n=== State BEFORE (decrypted with the view key) ===");
  console.log(`  Balance:  ${formatToken(balanceBefore, gratisMeta.decimals, gratisMeta.symbol)}`);
  console.log(`  Pledged:  ${formatToken(pledgedBefore, gratisMeta.decimals, gratisMeta.symbol)}`);

  if (balanceBefore === 0n) {
    console.error("No Gratis balance to pledge - run `npm run setup-gratis` first.");
    process.exit(1);
  }

  // Authorize the pledge with the modify key. The MAC binds the STABLES figure - the
  // one the user chose; `asset` and `maxGratis` are covered by the tx signature.
  const mac = modifyMac(keys.modifyKey, userAddress, GratisOp.Pledge, amountStables, opNonce, chainId);

  console.log("\nSending pledgeGratis(amountStables, asset, maxGratis, mac, opNonce)...");
  const tx = await gratisFactory.pledgeGratis(amountStables, erc20Address, maxGratis, mac, opNonce);
  console.log(`  TX hash: ${tx.hash}`);
  const receipt = await tx.wait();
  if (!receipt) throw new Error("pledgeGratis tx receipt missing");
  console.log(`  Block:   ${receipt.blockNumber}`);

  // Capture the confidential pledge handle from the GratisPledged event.
  const factoryIface = IGratisFactory__factory.createInterface();
  const pledged = receipt.logs
    .filter((l) => l.address.toLowerCase() === gratisFactoryAddress.toLowerCase())
    .map((l) => {
      try {
        return factoryIface.parseLog({ topics: l.topics as string[], data: l.data });
      } catch {
        return null;
      }
    })
    .find((p) => p?.name === "GratisPledged");
  if (!pledged) throw new Error("GratisPledged event not found in receipt");
  const handle = pledged.args.pledgeHandle as string;
  // The gratis the quote actually cost - derived on-chain, so read it back off the event.
  const gratisAmount = pledged.args.gratisAmount as bigint;

  // The bearer secret the user hands to the CCA to request credis later.
  const secret = pledgeSecret(keys.modifyKey, handle);

  const balanceAfter = decryptBalance(keys.viewKey, userAddress, await gratis.balanceOf(userAddress));
  const pledgedAfter = decryptPledged(keys.viewKey, userAddress, await gratis.pledgedOf(userAddress));

  console.log("\n=== State AFTER (decrypted with the view key) ===");
  console.log(`  Balance:         ${formatToken(balanceAfter, gratisMeta.decimals, gratisMeta.symbol)}`);
  console.log(`  Active pledged:  ${formatToken(pledgedAfter, gratisMeta.decimals, gratisMeta.symbol)} (credited to the pledged ledger only at requestCredis)`);
  console.log(`  Pending pledge:  ${formatToken(gratisAmount, gratisMeta.decimals, gratisMeta.symbol)} (parked in this ticket)`);
  console.log(`  Quoted credit:   ${formatToken(amountStables, assetMeta.decimals, assetMeta.symbol)} (sealed in the ticket)`);
  console.log(`  Pledge handle:   ${handle}`);

  // A pledge moves the derived gratis from the liquid balance into a new pending
  // ticket; the active pledged ledger (`pledgedOf`) stays flat until requestCredis
  // consumes the ticket. So the pending line - not the pledged-ledger diff - is where
  // a fresh pledge shows up.
  console.log("\n=== CHANGES ===");
  console.log(`  Balance:         ${formatTokenDiff(balanceAfter - balanceBefore, gratisMeta.decimals, gratisMeta.symbol)}`);
  console.log(`  Active pledged:  ${formatTokenDiff(pledgedAfter - pledgedBefore, gratisMeta.decimals, gratisMeta.symbol)} (unchanged until requestCredis)`);
  console.log(`  Pending pledge:  ${formatTokenDiff(gratisAmount, gratisMeta.decimals, gratisMeta.symbol)}`);

  const ticketPath = writeTicket({
    pledgeHandle: handle,
    pledgeSecret: ethers.hexlify(secret),
    stablesAmount: amountStables.toString(),
    asset: erc20Address,
    amount: gratisAmount.toString(),
    opNonce: Number(opNonce),
    blockNumber: receipt.blockNumber,
    txHash: receipt.hash,
    chainId: chainId.toString(),
    createdAt: new Date().toISOString(),
  });

  console.log(`\nTicket written: ${ticketPath}`);
  console.log("Hand the pledgeSecret to the CCA, then run `npm run request-credis`.");
  console.log("(Or `npm run unpledge-gratis-fast` to directly reclaim this unspent pledge.)");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
