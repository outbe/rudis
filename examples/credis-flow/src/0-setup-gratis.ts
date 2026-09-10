import { ethers, Wallet } from "ethers";
import {
  IGem__factory,
  IGemFactory__factory,
  IGratis__factory,
  IPromis__factory,
  IPromisFactory__factory,
} from "./contracts/index.js";
import {
  DEFAULT_GEM_ADDRESS,
  DEFAULT_GEM_FACTORY_ADDRESS,
  DEFAULT_GRATIS_ADDRESS,
  DEFAULT_PROMIS_FACTORY_ADDRESS,
  DEFAULT_PROMIS_ADDRESS,
  formatToken,
  formatTokenDiff,
  fetchTokenMeta,
  DEFAULT_ENV,
  loadEnv,
  requireEnv,
} from "./utils.js";
import {
  deriveKeys,
  decryptBalance,
  modifyMac,
  findPowNonce,
  GratisOp,
  PromisOp,
} from "./confidential.js";

// CLI: [amount] [envName]. `amount` (token units) is how much confidential Gratis
// to bootstrap; it defaults to the full gem load. Neither Gratis nor Promis can be
// plaintext-seeded at genesis anymore (both are TEE-encrypted at rest), so genesis
// seeds the user a Settled *gem* instead. This script burns that gem for confidential
// Promis (`minePromis`), then converts the Promis 1:1 into confidential Gratis
// (`mineGratis`) - leaving the user real, enclave-encrypted Gratis to pledge.
const amountArg = process.argv[2];
const envName = process.argv[3] || DEFAULT_ENV;

const { envPath } = loadEnv(import.meta.url, envName);

const rpcUrl = requireEnv("RPC_URL", envPath);
const userPrivateKey = requireEnv("USER_PRIVATE_KEY", envPath);
const userAddress = requireEnv("USER_ADDRESS", envPath);
const gemAddress = process.env["GEM_ADDRESS"] || DEFAULT_GEM_ADDRESS;
const gemFactoryAddress = process.env["GEM_FACTORY_ADDRESS"] || DEFAULT_GEM_FACTORY_ADDRESS;
const gratisAddress = process.env["GRATIS_ADDRESS"] || DEFAULT_GRATIS_ADDRESS;
const promisAddress = process.env["PROMIS_ADDRESS"] || DEFAULT_PROMIS_ADDRESS;
const promisFactoryAddress = process.env["PROMIS_FACTORY_ADDRESS"] || DEFAULT_PROMIS_FACTORY_ADDRESS;

const GEM_STATE_SETTLED = 3;

async function main() {
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const wallet = new Wallet(userPrivateKey, provider);
  const gem = IGem__factory.connect(gemAddress, wallet);
  const gemFactory = IGemFactory__factory.connect(gemFactoryAddress, wallet);
  const gratis = IGratis__factory.connect(gratisAddress, wallet);
  const promis = IPromis__factory.connect(promisAddress, wallet);
  const promisFactory = IPromisFactory__factory.connect(promisFactoryAddress, wallet);

  const gratisMeta = await fetchTokenMeta(gratis);
  const promisMeta = await fetchTokenMeta(promis);
  const { chainId } = await provider.getNetwork();

  // Both tokens are confidential: fetch the user's per-ledger enclave keys so we
  // can decrypt balances (view key) and authorize the enclave-routed mint/burn
  // (modify key). Each derivation signs its own ownership proof.
  const promisKeys = await deriveKeys(wallet, "Promis");
  const gratisKeys = await deriveKeys(wallet, "Gratis");

  // Discover the genesis-seeded gem: one gem per demo user, at owner index 0.
  const gemCount = await gem.balanceOf(userAddress);
  if (gemCount === 0n) {
    console.error(
      `No gem found for ${userAddress}. Genesis must seed a Settled gem for this ` +
        `account (see scripts/seed-testnet.json "gems"). Re-bootstrap the localnet.`,
    );
    process.exit(1);
  }
  const gemId = await gem.tokenOfOwnerByIndex(userAddress, 0);
  const gemStatus = await gem.getGemStatus(gemId);
  const promisLoad = gemStatus.promisLoad;
  if (Number(gemStatus.state) !== GEM_STATE_SETTLED) {
    console.error(
      `Gem ${gemId} is in state ${gemStatus.state}, not Settled (${GEM_STATE_SETTLED}); ` +
        `minePromis requires a Settled gem.`,
    );
    process.exit(1);
  }

  // Amount of Promis to convert to Gratis (defaults to the whole gem load).
  const amount = amountArg ? ethers.parseUnits(amountArg, promisMeta.decimals) : promisLoad;
  if (amount > promisLoad) {
    console.error(
      `Requested ${formatToken(amount, promisMeta.decimals, promisMeta.symbol)} exceeds the ` +
        `gem load ${formatToken(promisLoad, promisMeta.decimals, promisMeta.symbol)}.`,
    );
    process.exit(1);
  }

  const promisBefore = decryptBalance(
    promisKeys.viewKey,
    userAddress,
    await promis.balanceOf(userAddress),
    "Promis",
  );
  const gratisBefore = decryptBalance(gratisKeys.viewKey, userAddress, await gratis.balanceOf(userAddress));

  console.log("=== Setup Gratis via Gem -> Promis -> Gratis (confidential / TEE) ===");
  console.log(`Env:            ${envName} (${envPath})`);
  console.log(`RPC:            ${rpcUrl}`);
  console.log(`User:           ${userAddress}`);
  console.log(`Gem:            ${gemAddress} (id ${gemId})`);
  console.log(`GemFactory:     ${gemFactoryAddress}`);
  console.log(`Promis:         ${promisAddress} (${promisMeta.symbol})`);
  console.log(`PromisFactory:  ${promisFactoryAddress}`);
  console.log(`Gratis:         ${gratisAddress} (${gratisMeta.symbol})`);
  console.log(`Gem load:       ${formatToken(promisLoad, promisMeta.decimals, promisMeta.symbol)}`);
  console.log(`Convert amount: ${formatToken(amount, promisMeta.decimals, promisMeta.symbol)}`);

  console.log("\n=== State BEFORE ===");
  console.log(`  Promis:   ${formatToken(promisBefore, promisMeta.decimals, promisMeta.symbol)} (decrypted)`);
  console.log(`  Gratis:   ${formatToken(gratisBefore, gratisMeta.decimals, gratisMeta.symbol)} (decrypted)`);

  // Step 1 - Gem -> Promis: burn the gem, minting `promisLoad` confidential Promis to
  // the owner. The Promis mint MAC binds the minted amount (= promisLoad) and the
  // caller's current Promis op-nonce. PoW gates the burn (difficulty 1).
  const powNonce = findPowNonce(gemId);
  const promisMintNonce = await promis.opNonceOf(userAddress);
  const promisMintMac = modifyMac(
    promisKeys.modifyKey,
    userAddress,
    PromisOp.Mint,
    promisLoad,
    promisMintNonce,
    chainId,
    "Promis",
  );
  console.log("\nStep 1: minePromis(gemId, powNonce, mac, opNonce)...");
  const tx1 = await gemFactory.minePromis(gemId, powNonce, promisMintMac, promisMintNonce);
  console.log(`  TX hash: ${tx1.hash}`);
  const receipt1 = await tx1.wait();
  if (!receipt1) throw new Error("minePromis tx receipt missing");
  console.log(`  Block:   ${receipt1.blockNumber} - minted ${formatToken(promisLoad, promisMeta.decimals, promisMeta.symbol)}`);

  // Step 2 - Promis -> Gratis: burn `amount` Promis and mint `amount` Gratis. Both
  // ledgers are confidential, so mineGratis takes TWO modify authorizations, each
  // bound to its own ledger's current op-nonce: the Promis BURN auth (PromisOp.Burn)
  // and the Gratis MINT auth (GratisOp.Mint). The Promis op-nonce has advanced to 1
  // after the mint above.
  const gratisMintNonce = await gratis.opNonceOf(userAddress);
  const gratisMintMac = modifyMac(
    gratisKeys.modifyKey,
    userAddress,
    GratisOp.Mint,
    amount,
    gratisMintNonce,
    chainId,
    "Gratis",
  );
  const promisBurnNonce = await promis.opNonceOf(userAddress);
  const promisBurnMac = modifyMac(
    promisKeys.modifyKey,
    userAddress,
    PromisOp.Burn,
    amount,
    promisBurnNonce,
    chainId,
    "Promis",
  );
  console.log("\nStep 2: mineGratis(amount, promisMac, promisOpNonce, gratisMac, gratisOpNonce)...");
  const tx2 = await promisFactory.mineGratis(
    amount,
    promisBurnMac,
    promisBurnNonce,
    gratisMintMac,
    gratisMintNonce,
  );
  console.log(`  TX hash: ${tx2.hash}`);
  const receipt2 = await tx2.wait();
  if (!receipt2) throw new Error("mineGratis tx receipt missing");
  console.log(`  Block:   ${receipt2.blockNumber}`);

  const promisAfter = decryptBalance(
    promisKeys.viewKey,
    userAddress,
    await promis.balanceOf(userAddress),
    "Promis",
  );
  const gratisAfter = decryptBalance(gratisKeys.viewKey, userAddress, await gratis.balanceOf(userAddress));

  console.log("\n=== State AFTER (both decrypted with the view keys) ===");
  console.log(`  Promis:   ${formatToken(promisAfter, promisMeta.decimals, promisMeta.symbol)}`);
  console.log(`  Gratis:   ${formatToken(gratisAfter, gratisMeta.decimals, gratisMeta.symbol)}`);

  console.log("\n=== CHANGES ===");
  console.log(`  Promis:   ${formatTokenDiff(promisAfter - promisBefore, promisMeta.decimals, promisMeta.symbol)}`);
  console.log(`  Gratis:   ${formatTokenDiff(gratisAfter - gratisBefore, gratisMeta.decimals, gratisMeta.symbol)}`);

  console.log("\nDone. Run `npm run pledge-gratis` to pledge some of this Gratis.");
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
